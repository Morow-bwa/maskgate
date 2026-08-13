from app.masking.anonymizer import MappingItem
from app.storage.mapping_store import InMemoryMappingStore


def test_mapping_cleanup_after_delete() -> None:
    store = InMemoryMappingStore(ttl_seconds=60)
    store.put("req_1", [MappingItem("EMAIL", "a@example.com", "<EMAIL_1>")])
    assert store.size() == 1
    store.delete("req_1")
    assert store.size() == 0


def test_mapping_ttl_expires() -> None:
    now = [0.0]
    store = InMemoryMappingStore(ttl_seconds=1, clock=lambda: now[0])
    store.put("req_1", [])
    now[0] = 1.05
    assert store.get("req_1") is None


def test_mapping_cleanup_physically_removes_expired_entries() -> None:
    now = [0.0]
    store = InMemoryMappingStore(ttl_seconds=1, clock=lambda: now[0])
    store.put("req_1", [])
    now[0] = 2.0

    assert store.cleanup() == 1
    assert store.size() == 0
