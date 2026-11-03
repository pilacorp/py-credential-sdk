from credential.vcanchor import BatchInput, MemoryStore, Manager, build_batch, verify_receipt_local
from credential.vcanchor.merkle import merkle_proof, proof_len


def test_build_batch_and_receipt() -> None:
    hashes = [
        "0x" + "00" * 31 + "01",
        "0x" + "00" * 31 + "02",
        "0x" + "00" * 31 + "03",
        "0x" + "00" * 31 + "04",
    ]
    batch = build_batch(BatchInput("did:pila:testnet:0xissuer", "app-tree-001", hashes))
    assert batch.leaf_count == 4
    assert batch.root.startswith("0x") and len(batch.root) == 66
    receipt = batch.receipt(hashes[2], "0xtx")
    assert receipt.leaf_index == 2
    assert len(receipt.proof) == 2
    assert verify_receipt_local(receipt, batch.root, 4)


def test_rejects_duplicate() -> None:
    try:
        build_batch(
            BatchInput(
                "did:pila:testnet:0xissuer",
                "app-tree-001",
                ["0x" + "00" * 31 + "01", "00" * 31 + "01"],
            )
        )
        raise AssertionError("expected duplicate")
    except ValueError:
        pass


def test_proof_len() -> None:
    for n in range(1, 41):
        leaves = [(i).to_bytes(32, "big") for i in range(n)]
        for idx in {0, n // 2, n - 1}:
            assert proof_len(n) == len(merkle_proof(leaves, idx))


def test_manager_receipt() -> None:
    store = MemoryStore()
    mgr = Manager(store)
    hashes = ["0x" + "00" * 31 + "01", "0x" + "00" * 31 + "02"]
    batch = mgr.create_batch(BatchInput("did:pila:x", "t1", hashes))
    try:
        mgr.generate_receipt("did:pila:x", "t1", hashes[0])
        raise AssertionError("expected not anchored")
    except ValueError:
        pass
    mgr.mark_anchored("did:pila:x", "t1", "0xabc")
    receipt = mgr.generate_receipt("did:pila:x", "t1", hashes[0])
    assert verify_receipt_local(receipt, batch.root, 2)
