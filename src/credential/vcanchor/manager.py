from credential.vcanchor.batch import Batch, BatchInput, Receipt, StoredBatch, batch_to_stored, build_batch
from credential.vcanchor.store import ERR_BATCH_NOT_FOUND, Store


class Manager:
    def __init__(self, store: Store) -> None:
        self.store = store

    def create_batch(self, input: BatchInput) -> Batch:
        if self.store is None:
            raise ValueError("store is required")
        batch = build_batch(input)
        self.store.save_batch(batch_to_stored(batch))
        return batch

    def _get(self, issuer_did: str, external_tree_id: str) -> StoredBatch:
        stored = self.store.get_batch(issuer_did, external_tree_id)
        if stored is None:
            raise ValueError(f"vcanchor: store returned no batch for {issuer_did}/{external_tree_id}: {ERR_BATCH_NOT_FOUND}")
        return stored

    def mark_anchored(self, issuer_did: str, external_tree_id: str, tx_hash: str) -> None:
        if not tx_hash:
            raise ValueError("tx hash is required")
        stored = self._get(issuer_did, external_tree_id)
        self.store.mark_anchored(stored.issuer_did, stored.external_tree_id, tx_hash)

    def generate_receipt(self, issuer_did: str, external_tree_id: str, vc_hash: str) -> Receipt:
        stored = self._get(issuer_did, external_tree_id)
        if not stored.tx_hash:
            raise ValueError(f"batch {external_tree_id} is not anchored")
        batch = build_batch(
            BatchInput(stored.issuer_did, stored.external_tree_id, stored.ordered_vc_hashes)
        )
        _ensure_matches(batch, stored)
        return batch.receipt(vc_hash, stored.tx_hash)

    def validate_stored_batch(self, issuer_did: str, external_tree_id: str) -> None:
        stored = self._get(issuer_did, external_tree_id)
        batch = build_batch(
            BatchInput(stored.issuer_did, stored.external_tree_id, stored.ordered_vc_hashes)
        )
        _ensure_matches(batch, stored)


def _ensure_matches(batch: Batch, stored: StoredBatch) -> None:
    if batch.root != stored.root:
        raise ValueError(f"stored batch root mismatch: got {batch.root} want {stored.root}")
    if batch.leaf_count != stored.leaf_count:
        raise ValueError("stored batch leaf_count mismatch")
    if batch.hash_scheme != stored.hash_scheme:
        raise ValueError("stored batch hash_scheme mismatch")
    if batch.leaves_digest != stored.leaves_digest:
        raise ValueError("stored batch leaves_digest mismatch")
