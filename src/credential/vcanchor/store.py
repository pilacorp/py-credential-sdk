from __future__ import annotations

from typing import Protocol

from credential.vcanchor.batch import StoredBatch

ERR_BATCH_NOT_FOUND = "vcanchor: batch not found"
ERR_BATCH_CONFLICT = "vcanchor: batch already exists with different content"


class Store(Protocol):
    def save_batch(self, batch: StoredBatch) -> None: ...
    def get_batch(self, issuer_did: str, external_tree_id: str) -> StoredBatch | None: ...
    def mark_anchored(self, issuer_did: str, external_tree_id: str, tx_hash: str) -> None: ...


def same_batch_content(a: StoredBatch, b: StoredBatch) -> bool:
    return (
        a.issuer_did == b.issuer_did
        and a.external_tree_id == b.external_tree_id
        and a.root == b.root
        and a.leaf_count == b.leaf_count
        and a.hash_scheme == b.hash_scheme
        and a.leaves_digest == b.leaves_digest
    )


class MemoryStore:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str], StoredBatch] = {}

    def save_batch(self, batch: StoredBatch) -> None:
        key = (batch.issuer_did, batch.external_tree_id)
        existing = self._items.get(key)
        if existing is not None and not same_batch_content(existing, batch):
            raise ValueError(ERR_BATCH_CONFLICT)
        if existing is None:
            self._items[key] = batch

    def get_batch(self, issuer_did: str, external_tree_id: str) -> StoredBatch | None:
        return self._items.get((issuer_did, external_tree_id))

    def mark_anchored(self, issuer_did: str, external_tree_id: str, tx_hash: str) -> None:
        stored = self.get_batch(issuer_did, external_tree_id)
        if stored is None:
            raise ValueError(ERR_BATCH_NOT_FOUND)
        stored.tx_hash = tx_hash
        stored.status = "anchored"
