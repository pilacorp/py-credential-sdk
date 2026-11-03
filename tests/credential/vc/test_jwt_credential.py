from credential.vc.helper import serialize_credential_contents
from credential.vc.jwt_credential import JWTCredential
from didv2.signer import DefaultProvider

PRIV = "11" * 32
DID = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"


def test_jwt_roundtrip() -> None:
    vcc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "credentialSubject": {"id": "did:nda:0xabc"},
    }
    data = serialize_credential_contents(vcc)
    cred = JWTCredential.create(vcc)
    signed = cred.add_proof(DefaultProvider(PRIV))
    parsed = JWTCredential.parse(signed.serialize())
    assert parsed.payload()["iss"] == DID
    assert parsed.vc()["issuer"] == DID
    parsed.verify(DefaultProvider(PRIV).get_address())
    assert data["id"] == "urn:uuid:1"
