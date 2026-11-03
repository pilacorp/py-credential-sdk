from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from digitalcredential.internal import uri
from digitalcredential.issuerkey import SigningKey
from digitalcredential.jws_compact import sign_compact_jws
from digitalcredential.statuslist.statuslist import List

TYP_STATUS_LIST = "statuslist+jwt"
_RESERVED = frozenset({"sub", "iat", "exp", "ttl", "status_list"})


@dataclass
class TokenClaims:
    sub: str
    issued_at: datetime
    expiry: datetime | None = None
    ttl_seconds: float | None = None
    other: dict[str, Any] = field(default_factory=dict)


def _ttl_number(seconds: float) -> int | float:
    whole = int(seconds)
    if whole == seconds:
        return whole
    return seconds


def _payload_from_claims(c: TokenClaims) -> dict[str, Any]:
    uri.check(c.sub)
    if c.issued_at.tzinfo is None:
        c.issued_at = c.issued_at.replace(tzinfo=timezone.utc)
    if c.ttl_seconds is not None and c.ttl_seconds < 0:
        raise ValueError("statuslist: TTL is negative")
    claims = _other_claims(c.other)
    claims["sub"] = c.sub
    claims["iat"] = int(c.issued_at.timestamp())
    if c.expiry is not None:
        if c.expiry.tzinfo is None:
            c.expiry = c.expiry.replace(tzinfo=timezone.utc)
        claims["exp"] = int(c.expiry.timestamp())
    if c.ttl_seconds is not None and c.ttl_seconds != 0:
        claims["ttl"] = _ttl_number(c.ttl_seconds)
    return claims


def _other_claims(other: dict[str, Any]) -> dict[str, Any]:
    if not other:
        return {}
    raw = json.dumps(other, separators=(",", ":"))
    claims = json.loads(raw)
    if not isinstance(claims, dict):
        raise ValueError("statuslist: Other is not an object")
    for name in _RESERVED:
        if name in claims:
            raise ValueError(f"statuslist: Other holds {name!r}, which TokenClaims writes")
    if "nbf" in claims and not isinstance(claims["nbf"], (int, float)):
        raise ValueError("statuslist: Other nbf is not a NumericDate")
    return claims


def issue_token(lst: List, claims: TokenClaims, key: SigningKey) -> str:
    payload = _payload_from_claims(claims)
    payload["status_list"] = {"bits": lst.bits(), "lst": lst.encode()}
    header: dict[str, Any] = {"alg": "ES256", "typ": TYP_STATUS_LIST}
    if key.kid:
        header["kid"] = key.kid

    class _Adapter:
        def sign(self, digest: bytes) -> bytes:
            return key.signer.sign(digest)

    token = sign_compact_jws(header, payload, _Adapter())
    from digitalcredential.jws_compact import verify_compact_jws

    verify_compact_jws(token, key.public_key, ["ES256"])
    return token


def decode_token_claims_unverified(token: str) -> dict[str, Any]:
    from credential.common.sdjwt.helper import b64url_decode
    from digitalcredential.jws_compact import peek_header
    from digitalcredential.statuslist.errors import ErrTokenType

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("statuslist: token is not compact JWS")
    if peek_header(token).get("typ") != TYP_STATUS_LIST:
        raise ErrTokenType
    return json.loads(b64url_decode(parts[1]))
