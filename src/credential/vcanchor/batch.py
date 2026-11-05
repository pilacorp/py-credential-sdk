from __future__ import annotations

from dataclasses import dataclass, field

from credential.vcanchor.hash import hex_hash, normalize_hash32
from credential.vcanchor.merkle import digest_leaves, merkle_proof, merkle_root

HASH_SCHEME = "keccak256-sorted-pairs-no-leaf-hash-v1"
MAX_LEAVES_PER_BATCH = 10000


@dataclass
class BatchInput:
    issuer_did: str
    external_tree_id: str
    vc_hashes: list[str]


@dataclass
class Receipt:
    issuer_did: str
    external_tree_id: str
    vc_hash: str
    leaf_index: int
    leaf_count: int
    root: str
    proof: list[str]
    hash_scheme: str
    tx_hash: str = ""


def _drop_empty(d: dict, *keys: str) -> dict:
    for k in keys:
        if not d[k]:
            del d[k]
    return d


@dataclass
class StoredBatch:
    issuer_did: str
    external_tree_id: str
    root: str
    leaf_count: int
    hash_scheme: str
    leaves_digest: str
    ordered_vc_hashes: list[str]
    status: str = "created"
    tx_hash: str = ""
    anchored_at_unix: int = 0
    created_at_unix: int = 0
    last_modified_unix: int = 0

    def to_dict(self) -> dict:
        """Go json tags (tx_hash / anchored_at_unix are omitempty)."""
        return _drop_empty(dict(self.__dict__), "tx_hash", "anchored_at_unix")

    @classmethod
    def from_dict(cls, d: dict) -> "StoredBatch":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


@dataclass
class Batch:
    issuer_did: str
    external_tree_id: str
    root: str
    leaf_count: int
    hash_scheme: str
    leaves_digest: str
    leaves: list[bytes] = field(repr=False)
    leaves_by_hash: dict[bytes, int] = field(repr=False)

    def to_dict(self) -> dict:
        return {
            "issuer_did": self.issuer_did,
            "external_tree_id": self.external_tree_id,
            "root": self.root,
            "leaf_count": self.leaf_count,
            "hash_scheme": self.hash_scheme,
            "leaves_digest": self.leaves_digest,
        }

    def receipt(self, vc_hash: str, tx_hash: str = "") -> Receipt:
        normalized, raw = normalize_hash32(vc_hash)
        if raw not in self.leaves_by_hash:
            raise ValueError(f"vc_hash {normalized} is not in batch")
        idx = self.leaves_by_hash[raw]
        proof = [hex_hash(p) for p in merkle_proof(self.leaves, idx)]
        return Receipt(
            issuer_did=self.issuer_did,
            external_tree_id=self.external_tree_id,
            vc_hash=normalized,
            leaf_index=idx,
            leaf_count=self.leaf_count,
            root=self.root,
            proof=proof,
            hash_scheme=self.hash_scheme,
            tx_hash=tx_hash,
        )


def build_batch(input: BatchInput) -> Batch:
    if not input.issuer_did:
        raise ValueError("issuer_did is required")
    if not input.external_tree_id:
        raise ValueError("external_tree_id is required")
    if not input.vc_hashes:
        raise ValueError("vc_hashes is required")
    if len(input.vc_hashes) > MAX_LEAVES_PER_BATCH:
        raise ValueError(
            f"too many vc_hashes: {len(input.vc_hashes)} exceeds max {MAX_LEAVES_PER_BATCH} per batch"
        )
    leaves: list[bytes] = []
    leaves_by_hash: dict[bytes, int] = {}
    for h in input.vc_hashes:
        normalized, raw = normalize_hash32(h)
        if raw in leaves_by_hash:
            raise ValueError(f"duplicate vc_hash {normalized}")
        leaves_by_hash[raw] = len(leaves)
        leaves.append(raw)
    root = merkle_root(leaves)
    return Batch(
        issuer_did=input.issuer_did,
        external_tree_id=input.external_tree_id,
        root=hex_hash(root),
        leaf_count=len(leaves),
        hash_scheme=HASH_SCHEME,
        leaves_digest=hex_hash(digest_leaves(leaves)),
        leaves=leaves,
        leaves_by_hash=leaves_by_hash,
    )


def batch_to_stored(batch: Batch) -> StoredBatch:
    return StoredBatch(
        issuer_did=batch.issuer_did,
        external_tree_id=batch.external_tree_id,
        root=batch.root,
        leaf_count=batch.leaf_count,
        hash_scheme=batch.hash_scheme,
        leaves_digest=batch.leaves_digest,
        ordered_vc_hashes=[hex_hash(leaf) for leaf in batch.leaves],
        status="created",
    )
