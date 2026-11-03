from credential.vp import JWTPresentation
from didv2.signer import DefaultProvider

PRIV = "11" * 32
HOLDER = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"


def test_jwt_presentation_roundtrip() -> None:
    pres = JWTPresentation.create(
        {
            "holder": HOLDER,
            "verifiableCredential": ["eyJhbGciOiJFUzI1NksifQ.e30.sig"],
            "domain": "https://rp.example",
            "challenge": "abc",
        }
    ).add_proof(DefaultProvider(PRIV))
    parsed_addr = DefaultProvider(PRIV).get_address()
    JWTPresentation(
        pres.signing_input,
        pres.payload,
        pres.signature,
    ).verify(parsed_addr, audience="https://rp.example", challenge="abc")
    assert pres.credentials()
