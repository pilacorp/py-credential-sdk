from datetime import datetime, timezone

from credential.common.signer.p256 import P256Provider
from digitalcredential.issuerkey import SigningKey
from digitalcredential.jws_compact import verify_compact_jws
from digitalcredential.statuslist.statuslist import List
from digitalcredential.statuslist.token import TokenClaims, decode_token_claims_unverified, issue_token


def test_issue_token_draft21_bits1() -> None:
    want = bytes([0xB9, 0xA3])
    lst = List.from_bytes(want, 1)
    signer = P256Provider()
    key = SigningKey(signer=signer, public_key=signer.public_key_uncompressed(), kid="12")
    token = issue_token(
        lst,
        TokenClaims(
            sub="https://example.com/statuslists/1",
            issued_at=datetime.fromtimestamp(1686920170, tz=timezone.utc),
            expiry=datetime.fromtimestamp(2291720170, tz=timezone.utc),
            ttl_seconds=43200,
        ),
        key,
    )
    claims = verify_compact_jws(token, key.public_key, ["ES256"])
    assert claims["sub"] == "https://example.com/statuslists/1"
    assert claims["iat"] == 1686920170
    assert claims["exp"] == 2291720170
    assert claims["ttl"] == 43200
    sl = claims["status_list"]
    assert sl["bits"] == 1
    back = List.decode(sl["lst"], 1)
    assert back.bytes() == want
    header_claims = decode_token_claims_unverified(token)
    assert header_claims["sub"] == claims["sub"]


def test_issue_token_rejects_reserved_in_other() -> None:
    lst = List.new(16, 1)
    signer = P256Provider()
    key = SigningKey(signer=signer, public_key=signer.public_key_uncompressed())
    try:
        issue_token(
            lst,
            TokenClaims(
                sub="https://example.com/statuslists/1",
                issued_at=datetime.fromtimestamp(1686920170, tz=timezone.utc),
                other={"ttl": 60},
            ),
            key,
        )
        raise AssertionError("expected error")
    except ValueError:
        pass
