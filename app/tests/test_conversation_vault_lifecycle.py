from __future__ import annotations

import asyncio

import pytest

from app.masking.anonymizer import MaskingSession
from app.masking.detector import RegexDetector
from app.policies.policy_engine import PolicyEngine
from app.storage.conversation_store import (
    ConversationMemoryCapacityExceeded,
    InMemoryConversationStore,
)


def test_idle_cleanup_does_not_detach_an_active_writer(settings) -> None:
    now = [0.0]
    policy = PolicyEngine(settings.policy_file)
    store = InMemoryConversationStore(ttl_seconds=1, clock=lambda: now[0])
    state = store.get_or_create(
        "conversation-active-writer",
        "tenant-a",
        lambda: MaskingSession("placeholder", policy),
    )
    asyncio.run(state.lock.acquire())
    try:
        now[0] = 2.0

        assert store.cleanup() == 0
        assert (
            store.get_or_create(
                "conversation-active-writer",
                "tenant-a",
                lambda: MaskingSession("placeholder", policy),
            )
            is state
        )
    finally:
        state.lock.release()


def test_detached_state_commit_fails_explicitly(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    store = InMemoryConversationStore(ttl_seconds=60)
    state = store.get_or_create(
        "conversation-stale-commit",
        "tenant-a",
        lambda: MaskingSession("placeholder", policy),
    )
    staged = state.session.clone()
    store.delete(state.conversation_id, state.owner_id)
    replacement = store.get_or_create(
        state.conversation_id,
        state.owner_id,
        lambda: MaskingSession("placeholder", policy),
    )

    with pytest.raises(RuntimeError):
        store.commit(state, staged, [{"role": "assistant", "content": "stale"}])

    assert replacement.messages == []


def test_waiting_writer_keeps_generation_alive_across_idle_expiry(settings) -> None:
    async def exercise() -> None:
        now = [0.0]
        policy = PolicyEngine(settings.policy_file)
        store = InMemoryConversationStore(ttl_seconds=1, clock=lambda: now[0])

        def factory() -> MaskingSession:
            return MaskingSession("placeholder", policy)

        first = await store.begin_turn(
            "conversation-waiting-writer",
            "tenant-a",
            factory,
            requested_mode="placeholder",
        )
        waiter = asyncio.create_task(
            store.begin_turn(
                "conversation-waiting-writer",
                "tenant-a",
                factory,
                requested_mode="placeholder",
            )
        )
        await asyncio.sleep(0)
        now[0] = 2.0

        assert store.cleanup() == 0
        assert not waiter.done()
        first.close()
        second = await waiter
        try:
            assert second.state is first.state
            assert second.generation == first.generation
        finally:
            second.close()

    asyncio.run(exercise())


def test_delete_revokes_old_lease_and_recreate_uses_new_generation(settings) -> None:
    async def exercise() -> None:
        policy = PolicyEngine(settings.policy_file)
        store = InMemoryConversationStore(ttl_seconds=60)

        def factory() -> MaskingSession:
            return MaskingSession("placeholder", policy)

        old = await store.begin_turn(
            "conversation-delete-race",
            "tenant-a",
            factory,
            requested_mode="placeholder",
        )
        staged = old.state.session.clone()
        store.delete(old.state.conversation_id, old.state.owner_id)
        fresh = await store.begin_turn(
            "conversation-delete-race",
            "tenant-a",
            factory,
            requested_mode="placeholder",
        )
        try:
            assert fresh.generation != old.generation
            with pytest.raises(RuntimeError):
                old.require_active()
            with pytest.raises(RuntimeError):
                old.commit(staged, [{"role": "assistant", "content": "stale"}])
            assert fresh.state.messages == []
        finally:
            old.close()
            fresh.close()

    asyncio.run(exercise())


def test_cancelled_waiter_releases_reservation_exactly_once(settings) -> None:
    async def exercise() -> None:
        policy = PolicyEngine(settings.policy_file)
        store = InMemoryConversationStore(ttl_seconds=60)

        def factory() -> MaskingSession:
            return MaskingSession("placeholder", policy)

        first = await store.begin_turn(
            "conversation-cancelled-waiter",
            "tenant-a",
            factory,
            requested_mode="placeholder",
        )
        waiter = asyncio.create_task(
            store.begin_turn(
                "conversation-cancelled-waiter",
                "tenant-a",
                factory,
                requested_mode="placeholder",
            )
        )
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter

        assert first.state.lease_count == 1
        first.close()
        first.close()
        assert first.state.lease_count == 0
        assert not first.state.lock.locked()

    asyncio.run(exercise())


def test_aggregate_retained_state_budget_rejects_without_partial_publish(settings) -> None:
    async def exercise() -> None:
        policy = PolicyEngine(settings.policy_file)
        store = InMemoryConversationStore(
            ttl_seconds=60,
            max_chars=10_000,
            max_total_bytes=1_024,
            max_owner_bytes=1_024,
        )
        lease = await store.begin_turn(
            "conversation-memory-budget",
            "tenant-a",
            lambda: MaskingSession("placeholder", policy),
            requested_mode="placeholder",
        )
        try:
            with pytest.raises(ConversationMemoryCapacityExceeded):
                lease.commit(
                    lease.state.session.clone(),
                    [{"role": "user", "content": "x" * 2_000}],
                )
            assert lease.state.messages == []
            assert lease.state.accounted_bytes == 0
        finally:
            lease.close()

    asyncio.run(exercise())


def test_trimmed_conversation_messages_release_unreferenced_originals(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("placeholder", policy)
    detector = RegexDetector()
    old_text = "old.owner@example.com"
    current_text = "current.owner@example.com"
    old_masked = session.mask_text(old_text, detector.detect(old_text))
    current_masked = session.mask_text(current_text, detector.detect(current_text))
    old_token = session.items[0].replacement
    current_token = session.items[1].replacement
    store = InMemoryConversationStore(ttl_seconds=60, max_messages=4, max_chars=10_000)
    lease = asyncio.run(
        store.begin_turn(
            "conversation-123",
            "tenant-a",
            lambda: session,
            requested_mode="placeholder",
        )
    )
    state = lease.state

    lease.commit(
        session,
        [
            {"role": "user", "content": old_masked},
            {"role": "assistant", "content": "old reply"},
            {"role": "user", "content": "filler"},
            {"role": "assistant", "content": "filler reply"},
            {"role": "user", "content": current_masked},
            {"role": "assistant", "content": current_token},
        ],
    )
    lease.close()

    assert old_token not in str(state.messages)
    assert current_token in str(state.messages)
    assert [item.original for item in state.session.items] == [current_text]


def test_irreversible_redactions_are_not_retained_after_commit(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("redact", policy)
    detector = RegexDetector()
    masked = session.mask_text("owner@example.com", detector.detect("owner@example.com"))
    store = InMemoryConversationStore(ttl_seconds=60)
    lease = asyncio.run(
        store.begin_turn(
            "conversation-456",
            "tenant-a",
            lambda: session,
            requested_mode="redact",
        )
    )
    state = lease.state

    lease.commit(session, [{"role": "user", "content": masked}])
    lease.close()

    assert state.session.items == []


def test_conversation_cleanup_physically_removes_expired_vaults(settings) -> None:
    now = [0.0]
    policy = PolicyEngine(settings.policy_file)
    store = InMemoryConversationStore(ttl_seconds=1, clock=lambda: now[0])
    store.get_or_create(
        "conversation-789",
        "tenant-a",
        lambda: MaskingSession("placeholder", policy),
    )
    now[0] = 2.0

    assert store.cleanup() == 1
    assert store.size() == 0


def test_tenant_delete_removes_only_that_tenants_conversation_vaults(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    store = InMemoryConversationStore(ttl_seconds=60)

    def session_factory() -> MaskingSession:
        return MaskingSession("placeholder", policy)

    store.get_or_create("conversation-a1", "tenant-a", session_factory)
    store.get_or_create("conversation-a2", "tenant-a", session_factory)
    tenant_b_state = store.get_or_create("conversation-b1", "tenant-b", session_factory)

    removed = store.delete_owner("tenant-a")

    assert removed == 2
    assert store.size() == 1
    assert store.get_or_create("conversation-b1", "tenant-b", session_factory) is tenant_b_state
    assert store.delete_owner("tenant-missing") == 0
    assert store.size() == 1


def test_mapping_survives_until_every_repeated_active_reference_is_trimmed(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("placeholder", policy)
    detector = RegexDetector()
    original = "repeated.owner@example.com"
    first = session.mask_text(original, detector.detect(original))
    second = session.mask_text(f"Again {original}", detector.detect(f"Again {original}"))
    token = session.items[0].replacement
    assert len(session.items) == 1
    assert first == token
    assert second == f"Again {token}"
    store = InMemoryConversationStore(ttl_seconds=60)
    lease = asyncio.run(
        store.begin_turn(
            "conversation-repeat",
            "tenant-a",
            lambda: session,
            requested_mode="placeholder",
        )
    )
    state = lease.state

    lease.commit(
        session,
        [
            {"role": "user", "content": first},
            {"role": "assistant", "content": second},
        ],
    )
    assert [item.original for item in state.session.items] == [original]

    lease.commit(session, [{"role": "assistant", "content": second}])
    assert [item.original for item in state.session.items] == [original]

    lease.commit(session, [{"role": "assistant", "content": "no references"}])
    lease.close()
    assert state.session.items == []
