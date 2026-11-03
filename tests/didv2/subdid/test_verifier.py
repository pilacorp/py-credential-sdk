from didv2.subdid.proof import ProofResponse
from didv2.subdid.verifier import Chain, Verifier, VerifyRequest


def test_verifier_rejects_mismatched_proof_did():
    class _Client:
        def chain_id(self) -> int:
            return 704

        def transaction_receipt(self, tx_hash: str):
            return None

        def call_contract(self, to: str, data: bytes) -> bytes:
            return b""

    v = Verifier(
        [
            Chain(
                code="did",
                evm_chain_id=704,
                did_registry="0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a",
                client=_Client(),
            )
        ]
    )
    proof: ProofResponse = {
        "did": "did:nda:0x1111111111111111111111111111111111111111",
        "root_did": "did:nda:0x2222222222222222222222222222222222222222",
        "tree_index": "",
        "chains": [],
    }
    result = v.verify_sub_did(
        VerifyRequest(
            sub_did="did:nda:0x3333333333333333333333333333333333333333",
            document=None,
            proof=proof,
            chain="did",
        )
    )
    assert result.status.name == "INVALID"
