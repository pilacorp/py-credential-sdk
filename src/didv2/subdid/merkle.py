from didv2.hexutil import hex_to_bytes, with_0x
from didv2.keccak import keccak256_hex

MAX_LEAVES = 8192
MAX_PROOF_LEN = 13
REVOKED_LEAF_TAG = b"revoked"


def merkle_root(leaves: list[str]) -> str:
    _check_leaf_count(len(leaves))
    level = [_norm32(x) for x in leaves]
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[str]:
    _check_leaf_count(len(leaves))
    if index < 0 or index >= len(leaves):
        raise ValueError(f"subdid: leaf index {index} out of range [0, {len(leaves)})")
    proof: list[str] = []
    level = [_norm32(x) for x in leaves]
    i = index
    while len(level) > 1:
        sibling = i ^ 1
        if sibling < len(level):
            proof.append(level[sibling])
        level = _next_level(level)
        i //= 2
    return proof


def verify_proof(leaf: str, path: list[str], root: str) -> bool:
    if len(path) > MAX_PROOF_LEN:
        return False
    h = _norm32(leaf)
    for sibling in path:
        h = _hash_pair(h, sibling)
    return h == _norm32(root)


def revoked_leaf(addr: str) -> str:
    raw = hex_to_bytes(addr)
    if len(raw) != 20:
        raw = bytes.fromhex(addr[-40:])
    return keccak256_hex(REVOKED_LEAF_TAG + raw)


def _check_leaf_count(n: int) -> None:
    if n == 0:
        raise ValueError("subdid: a tree needs at least one leaf")
    if n > MAX_LEAVES:
        raise ValueError(f"subdid: {n} leaves exceed the maximum of {MAX_LEAVES}")


def _next_level(level: list[str]) -> list[str]:
    nxt: list[str] = []
    i = 0
    while i + 1 < len(level):
        nxt.append(_hash_pair(level[i], level[i + 1]))
        i += 2
    if len(level) % 2 == 1:
        nxt.append(level[-1])
    return nxt


def _hash_pair(a: str, b: str) -> str:
    left, right = hex_to_bytes(a), hex_to_bytes(b)
    if left > right:
        left, right = right, left
    return keccak256_hex(left + right)


def _norm32(h: str) -> str:
    hexv = with_0x(h)
    if len(hexv) != 66:
        raise ValueError(f"hash is not 32 bytes: {h}")
    return hexv
