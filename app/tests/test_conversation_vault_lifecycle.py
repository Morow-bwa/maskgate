from __future__ import annotations

from app.masking.anonymizer import MaskingSession
from app.masking.detector import RegexDetector
from app.policies.policy_engine import PolicyEngine
from app.storage.conversation_store import InMemoryConversationStore


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
    state = store.get_or_create("conversation-123", "tenant-a", lambda: session)

    store.commit(
        state,
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

    assert old_token not in str(state.messages)
    assert current_token in str(state.messages)
    assert [item.original for item in state.session.items] == [current_text]


def test_irreversible_redactions_are_not_retained_after_commit(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("redact", policy)
    detector = RegexDetector()
    masked = session.mask_text("owner@example.com", detector.detect("owner@example.com"))
    store = InMemoryConversationStore(ttl_seconds=60)
    state = store.get_or_create("conversation-456", "tenant-a", lambda: session)

    store.commit(state, session, [{"role": "user", "content": masked}])

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
    state = store.get_or_create("conversation-repeat", "tenant-a", lambda: session)

    store.commit(
        state,
        session,
        [
            {"role": "user", "content": first},
            {"role": "assistant", "content": second},
        ],
    )
    assert [item.original for item in state.session.items] == [original]

    store.commit(state, session, [{"role": "assistant", "content": second}])
    assert [item.original for item in state.session.items] == [original]

    store.commit(state, session, [{"role": "assistant", "content": "no references"}])
    assert state.session.items == []
