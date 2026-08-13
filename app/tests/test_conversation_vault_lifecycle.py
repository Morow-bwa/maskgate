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
