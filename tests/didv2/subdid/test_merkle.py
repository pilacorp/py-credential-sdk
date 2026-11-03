from didv2.subdid.merkle import merkle_proof, merkle_root, revoked_leaf, verify_proof


def fixture_leaves(n: int) -> list[str]:
    return ["0x" + bytes([i + 1] * 32).hex() for i in range(n)]


def test_root_vectors() -> None:
    vectors = [
        (1, "0x0101010101010101010101010101010101010101010101010101010101010101"),
        (2, "0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0"),
        (3, "0x1d614fa3c8de62938b0948972494f9a3858575db69ce1d34c77926f30732c981"),
        (5, "0x55d458ff264cc10cb4ef71d27a18db86f587999b2355cfa5eb5fccf8c973bced"),
    ]
    for n, root in vectors:
        assert merkle_root(fixture_leaves(n)) == root


def test_proof_vectors() -> None:
    assert merkle_proof(fixture_leaves(5), 4) == [
        "0x0b242b9a6559f2d9f8563485a0697b746ec58ce879e0e5ac94d4c8a250723121",
    ]
    leaves = fixture_leaves(5)
    proof = merkle_proof(leaves, 2)
    assert proof == [
        "0x0404040404040404040404040404040404040404040404040404040404040404",
        "0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0",
        "0x0505050505050505050505050505050505050505050505050505050505050505",
    ]
    assert verify_proof(leaves[2], proof, merkle_root(leaves))


def test_revoked_leaf() -> None:
    assert revoked_leaf("0x86b2efd244acb31eb238a65ca05476ab42558071") == (
        "0x83c91d2020210e4924defde940dcb4e63ec3f20bbad4229da6019faba05cc206"
    )
    leaves = fixture_leaves(3)
    leaves[2] = revoked_leaf("0x86b2efd244acb31eb238a65ca05476ab42558071")
    assert merkle_root(leaves) == "0x934b02ce8ddedb479ffc1fad0eaf40f0cd0d75e853f9d28e9b1273fd49004993"
