from credential.vcanchor.batch import HASH_SCHEME, Receipt
from credential.vcanchor.hash import normalize_hash32
from credential.vcanchor.merkle import proof_len, verify_proof


def verify_receipt_local(receipt: Receipt, anchored_root: str, anchored_leaf_count: int) -> bool:
    if receipt.hash_scheme != HASH_SCHEME:
        raise ValueError(f"unsupported hash_scheme {receipt.hash_scheme!r}")
    _, leaf = normalize_hash32(receipt.vc_hash)
    receipt_root, _ = normalize_hash32(receipt.root)
    anchored, root = normalize_hash32(anchored_root)
    if receipt_root != anchored:
        return False
    if anchored_leaf_count <= 0:
        raise ValueError("anchored leaf_count is required")
    if receipt.leaf_count != anchored_leaf_count:
        return False
    if len(receipt.proof) != proof_len(anchored_leaf_count):
        return False
    proof = [normalize_hash32(p)[1] for p in receipt.proof]
    return verify_proof(leaf, proof, root)
