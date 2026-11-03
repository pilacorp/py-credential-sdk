from didv2.keccak import keccak256


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise ValueError("leaves is empty")
    if len(leaves) == 1:
        return leaves[0]
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            right = level[i] if i + 1 >= len(level) else level[i + 1]
            nxt.append(merge_sorted(level[i], right))
        level = nxt
    return level[0]


def merkle_proof(leaves: list[bytes], leaf_index: int) -> list[bytes]:
    if not leaves:
        raise ValueError("leaves is empty")
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise ValueError(f"leaf index {leaf_index} out of range")
    if len(leaves) == 1:
        return []
    proof: list[bytes] = []
    index = leaf_index
    level = list(leaves)
    while len(level) > 1:
        sibling = index ^ 1
        if sibling >= len(level):
            sibling = index
        proof.append(level[sibling])
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            right = level[i] if i + 1 >= len(level) else level[i + 1]
            nxt.append(merge_sorted(level[i], right))
        index //= 2
        level = nxt
    return proof


def verify_proof(leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    current = leaf
    for sibling in proof:
        current = merge_sorted(current, sibling)
    return current == root


def merge_sorted(left: bytes, right: bytes) -> bytes:
    if left < right:
        return keccak256(left + right)
    return keccak256(right + left)


def digest_leaves(leaves: list[bytes]) -> bytes:
    return keccak256(b"".join(leaves))


def proof_len(leaf_count: int) -> int:
    if leaf_count <= 1:
        return 0
    return (leaf_count - 1).bit_length()
