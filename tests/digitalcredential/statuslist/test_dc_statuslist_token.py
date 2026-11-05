import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from digitalcredential import statuslist as sl
from digitalcredential.issuerkey import SigningKey
from jose import json as jj
from jose import jws
from jose.errors import ErrInvalidArgument


def new_signing_key(kid=""):
    priv = ec.generate_private_key(ec.SECP256R1())
    return SigningKey(jws.private_key_signer(priv), priv.public_key(), kid)


def ts(n):
    return datetime.fromtimestamp(n, tz=timezone.utc)


# The non-normative Status List Token of draft 21 §5.1: header kid "12" and its claims, with the bits=1 list
# of §4.2 it carries, then the same claims with the bits=2 list.
@pytest.mark.parametrize("bits,data", [(1, bytes([0xB9, 0xA3])), (2, bytes([0xC9, 0x44, 0xF9]))])
def test_issue_token_draft21_example(bits, data):
    key = new_signing_key("12")
    l = sl.List.from_bytes(data, bits)
    token = l.issue_token(sl.TokenClaims(sub="https://example.com/statuslists/1", issued_at=ts(1686920170), expiry=ts(2291720170), ttl_seconds=43200), key)
    header, payload = jws.verify(token, key.public, None)
    assert dict(header) == {"alg": "ES256", "typ": "statuslist+jwt", "kid": "12"}
    claims = jj.decode_json_object(payload)
    assert {k: str(v) for k, v in claims.items() if k != "status_list"} == {
        "sub": "https://example.com/statuslists/1", "iat": "1686920170", "exp": "2291720170", "ttl": "43200"}
    st = claims["status_list"]
    assert set(st) == {"bits", "lst"} and str(st["bits"]) == str(bits)
    assert sl.decode(st["lst"], bits).bytes() == data


def test_ttl_number_forms():
    key = new_signing_key()
    l = sl.List.new(16, 1)
    for ttl, want in [(60, "60"), (1.5, "1.5"), (0.000000001, "0.000000001"), (timedelta(seconds=90, microseconds=500), "90.0005")]:
        token = sl.issue_token(l, sl.TokenClaims(sub="https://example.com/s/1", issued_at=ts(1686920170), ttl_seconds=ttl), key)
        raw = jws.unverified_payload(token).decode()
        assert f'"ttl":{want}' in raw, raw
    # no ttl, no exp when unset
    raw = jws.unverified_payload(l.issue_token(sl.TokenClaims(sub="https://example.com/s/1", issued_at=ts(1)), key)).decode()
    assert "ttl" not in raw and "exp" not in raw


# TC-29: Other carries the claims §5.1 lets the token hold, and never one of those issue_token writes itself.
def test_issue_token_other():
    key = new_signing_key()
    l = sl.List.new(16, 1)
    base = dict(sub="https://example.com/statuslists/1", issued_at=ts(1686920170))
    token = l.issue_token(sl.TokenClaims(**base, other={"iss": "https://example.com"}), key)
    got = jj.decode_json_object(jws.verify(token, key.public, None)[1])
    assert got["iss"] == "https://example.com"
    for name, other in {
        "ttl in Other": {"ttl": 60},
        "status_list in Other": {"status_list": {"bits": 1, "lst": "eNoDAAAAAAE"}},
        "sub in Other": {"sub": "x"},
        "nbf as datetime": {"nbf": ts(1686920170)},
        "nbf a string": {"nbf": "yesterday"},
        "value JSON cannot hold": {"x": lambda: 1},
    }.items():
        with pytest.raises(ErrInvalidArgument):
            l.issue_token(sl.TokenClaims(**base, other=other), key)
    # nbf as a number passes
    l.issue_token(sl.TokenClaims(**base, other={"nbf": 1686920170}), key)


def test_issue_token_argument_checks():
    key = new_signing_key()
    l = sl.List.new(16, 1)
    ok = dict(sub="https://example.com/statuslists/1", issued_at=ts(1686920170))
    for kw in ({"sub": "not a uri"}, {"sub": "https:///x"}, {"ttl_seconds": -1}, {"issued_at": None}):
        with pytest.raises(ErrInvalidArgument):
            l.issue_token(sl.TokenClaims(**{**ok, **kw}), key)
    with pytest.raises(ErrInvalidArgument):
        sl.List().issue_token(sl.TokenClaims(**ok), key)
    # any scheme is a valid sub (the scheme a verifier fetches is the Relying Party's choice)
    l.issue_token(sl.TokenClaims(**{**ok, "sub": "urn:example:list:1"}), key)


# A token is verified with key.public before it is returned, so a signer holding another key never yields a token.
def test_issue_token_self_check():
    key = new_signing_key()
    key.public = new_signing_key().public
    with pytest.raises(jws.ErrSelfCheck):
        sl.List.new(16, 1).issue_token(sl.TokenClaims(sub="https://example.com/statuslists/1", issued_at=ts(1686920170)), key)
