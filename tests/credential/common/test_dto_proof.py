from credential.common.dto.proof import proof_from_map


def test_proof_from_map_keeps_extra_fields():
    p = proof_from_map({"type": "DataIntegrityProof", "custom": {"x": 1}})
    m = p.to_map()
    assert m["type"] == "DataIntegrityProof"
    assert m["custom"] == {"x": 1}
