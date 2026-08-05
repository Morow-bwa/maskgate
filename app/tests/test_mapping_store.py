import time

from app.masking.anonymizer import MappingItem
from app.storage.mapping_store import InMemoryMappingStore


def test_mapping_cleanup_after_delete() -> None:
    store = InMemoryMappingStore(ttl_seconds=60)
    store.put("req_1", [MappingItem("EMAIL", "a@example.com", "<EMAIL_1>")])
    assert store.size() == 1
    store.delete("req_1")
    assert store.size() == 0


def test_mapping_ttl_expires() -> None:
    store = InMemoryMappingStore(ttl_seconds=1)
    store.put("req_1", [])
    time.sleep(1.05)
    assert store.get("req_1") is None
