from did.helper import generate_ecdsa_did
from did.model import CreateDID, DIDType
from did.did_generator import DIDGenerator


def test_generate_ecdsa_did_identifier():
    kp = generate_ecdsa_did("did:nda")
    assert kp.identifier.startswith("did:nda:0x")
    assert kp.address in kp.identifier


def test_did_generator_builds_signed_tx():
    gen = DIDGenerator()
    out = gen.generate_did(CreateDID(type=DIDType.PEOPLE))
    assert out.did == out.document.id
    assert out.transaction.tx_hex
    assert out.transaction.tx_hash.startswith("0x")
