from datetime import datetime, timezone

from credential.common.signer.p256 import P256Provider
from digitalcredential.issue import issue
from digitalcredential.issuerkey import PublicKey, SigningKey, StaticResolver
from digitalcredential.present import present_credential
from digitalcredential.verify import verify_credential


def test_issue_present_verify() -> None:
    issuer = P256Provider()
    holder = P256Provider()
    key = SigningKey(signer=issuer, public_key=issuer.public_key_uncompressed(), kid="iss-1")
    cred = issue(
        {
            "issuer": "https://issuer.example",
            "vct": "https://example.com/vct",
            "claims": {"given_name": "Ada", "family_name": "Lovelace"},
            "disclose": [["given_name"], ["family_name"]],
            "holder_key": holder.public_key_uncompressed(),
        },
        key,
    )
    presented = present_credential(
        cred,
        {
            "reveal": [["given_name"]],
            "key_binding": {
                "signer": holder,
                "audience": "https://verifier.example",
                "nonce": "n1",
                "issued_at": datetime.now(timezone.utc),
            },
        },
    )
    result = verify_credential(
        presented,
        StaticResolver("https://issuer.example", [PublicKey(issuer.public_key_uncompressed(), "iss-1")]),
        {"audience": "https://verifier.example", "nonce": "n1", "skip_status": True},
    )
    assert result["vct"] == "https://example.com/vct"
    assert result["claims"]["given_name"] == "Ada"
    assert result["key_bound"] is True
    assert "family_name" not in result["claims"]
