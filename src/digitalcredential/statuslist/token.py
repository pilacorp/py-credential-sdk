"""The Status List Token in JWT format: draft-ietf-oauth-status-list-21 §5.1."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from digitalcredential.internal import uri
from digitalcredential.issuerkey import SigningKey
from digitalcredential.statuslist.statuslist import List
from jose import json as jose_json
from jose.errors import ErrInvalidArgument
from jose.json import JsonNumber
from jose.jwt import numeric_date

TYP_STATUS_LIST = "statuslist+jwt"  # draft 21 §5.1: typ MUST be statuslist+jwt
# The claims issue_token writes from TokenClaims and the list, so `other` must not hold them.
_RESERVED = ("sub", "iat", "exp", "ttl", "status_list")


@dataclass
class TokenClaims:
    """The claims of a new Status List Token (§5.1).

    sub: the URI of the token, the uri the Referenced Tokens carry (§6.2); a URI (RFC 3986), with a
    host when http or https. issued_at: iat, required, written in whole seconds. expiry: exp
    (RECOMMENDED), None writes none. ttl_seconds: ttl in seconds (RECOMMENDED, positive); None or 0
    writes none, a negative one is refused; a timedelta is accepted too. Whole seconds are written as
    a JSON integer, a fraction as a JSON number with up to nine decimals. other: the other claims
    (§5.1), never sub, iat, exp, ttl or status_list; an nbf in it must be a NumericDate.
    """

    sub: str
    issued_at: datetime
    expiry: datetime | None = None
    ttl_seconds: float | timedelta | None = None
    other: dict[str, Any] = field(default_factory=dict)

    @property
    def ttl(self) -> float | timedelta | None:
        return self.ttl_seconds


def _unix(t: datetime) -> int:
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return math.floor(t.timestamp())


def _ttl_number(ttl: float | timedelta) -> JsonNumber:
    """ttl in seconds as a JSON number: exact in decimal, an integer when whole seconds."""
    ns = (
        (ttl.days * 86400 + ttl.seconds) * 10**9 + ttl.microseconds * 1000
        if isinstance(ttl, timedelta)
        else round(ttl * 10**9)
    )
    s = str(ns // 10**9)
    frac = ns % 10**9
    if frac:
        s += "." + f"{frac:09d}".rstrip("0")
    return JsonNumber(s)


def _payload(c: TokenClaims) -> dict[str, Any]:
    # §5.1: sub is the uri of the Referenced Tokens, so it meets the rule of Ref.validate.
    try:
        uri.check(c.sub)
    except ValueError as e:
        raise ErrInvalidArgument(f"statuslist: Sub {e}") from e
    if c.issued_at is None:
        raise ErrInvalidArgument("statuslist: IssuedAt is required")
    ttl = c.ttl_seconds
    secs = ttl.total_seconds() if isinstance(ttl, timedelta) else (ttl or 0)
    if secs < 0:  # §5.1: ttl MUST be a positive number; zero writes none
        raise ErrInvalidArgument(f"statuslist: TTL {ttl} is negative")
    claims = _other_claims(c.other)
    claims["sub"] = c.sub
    claims["iat"] = _unix(c.issued_at)
    if c.expiry is not None:
        claims["exp"] = _unix(c.expiry)
    if secs != 0:
        claims["ttl"] = _ttl_number(ttl)
    return claims


def _other_claims(other: dict[str, Any] | None) -> dict[str, Any]:
    """`other` as decode_json_object reads it from its JSON, so later steps see JSON types whatever
    Python types the caller used, and `other` is never modified."""
    if not other:
        return {}
    try:
        claims = jose_json.decode_json_object(jose_json.encode_json(other))
    except Exception as e:  # noqa: BLE001
        raise ErrInvalidArgument(f"statuslist: Other: {e}") from e
    for name in _RESERVED:
        if name in claims:
            raise ErrInvalidArgument(f"statuslist: Other holds {name!r}, which TokenClaims or the list writes")
    # RFC 7519 §4.1.5: nbf is a NumericDate. A datetime in Other encodes as a string at best.
    if "nbf" in claims:
        try:
            numeric_date(claims["nbf"])
        except Exception as e:  # noqa: BLE001
            raise ErrInvalidArgument(f"statuslist: Other nbf: {e}") from e
    return claims


def issue_token(lst: List, claims: TokenClaims, key: SigningKey, ctx: Any = None) -> str:
    """Sign lst as a Status List Token in JWT format (§5.1): header {"alg", "typ": "statuslist+jwt",
    "kid"} (alg the one of key.signer, which jws.sign checks against key.public; kid only when set);
    payload {"sub", "iat", "exp", "ttl", "status_list": {"bits", "lst"}} (exp and ttl only when set)
    plus the claims of `other`. A zero list or claims breaking the rules of TokenClaims are
    jose.ErrInvalidArgument, checked before the signer is called; jws.sign errors are passed on
    unchanged (ErrBadKey for a nil key, ErrSelfCheck when the signer holds another key)."""
    from jose.jws import sign

    if lst is None or not lst.valid():
        raise ErrInvalidArgument("statuslist: list not made by New, FromBytes or Decode")
    payload_claims = _payload(claims)
    payload_claims["status_list"] = {"bits": lst.bits(), "lst": lst.encode()}
    payload = jose_json.encode_json(payload_claims)
    header: dict[str, Any] = {"typ": TYP_STATUS_LIST}
    if key.kid:
        header["kid"] = key.kid
    return sign(ctx if ctx is not None else _NoContext(), key.signer, key.public, header, payload)


class _NoContext:
    """Stands in for Go's context.Background() where jose.jws.sign asks for a ctx."""


def _issue_token_method(self: List, claims: TokenClaims, key: SigningKey, ctx: Any = None) -> str:
    return issue_token(self, claims, key, ctx)


List.issue_token = _issue_token_method  # type: ignore[attr-defined]


def decode_token_claims_unverified(token: str) -> dict[str, Any]:
    """The claims of token without verifying it (typ is checked)."""
    from digitalcredential.statuslist.errors import ErrTokenType
    from jose.jws import header_typ_is, unverified_header, unverified_payload

    if not header_typ_is(unverified_header(token), TYP_STATUS_LIST):
        raise ErrTokenType("statuslist: token typ is not statuslist+jwt")
    return jose_json.decode_json_object(unverified_payload(token))
