"""Key Binding JWT (RFC 9901 §4.3)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
from eth_keys import keys as eth_keys

from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrUnsupportedKey
from jose.internal.ec import from_public_key
from jose.jws import errors as jws_errors
from jose.jws.jws import header_typ_is, sign, verify
from jose.jwt import jwt as jwt_mod
from jose.sdjwt.disclosure import digest_of

TYP_KB = "kb+jwt"


class ErrKBInvalid(Exception):
    pass


class ErrKBAudience(Exception):
    pass


class ErrKBNonce(Exception):
    pass


class ErrKBSDHash(Exception):
    pass


def sd_hash(sd_jwt: str) -> str:
    return digest_of(sd_jwt)


@dataclass
class KBClaims:
    audience: str
    nonce: str
    issued_at: datetime
    sd_hash: str
    extra: dict[str, Any] | None = None


def new_kb_jwt(ctx: Any, signer: Any, holder: Any, claims: KBClaims) -> str:
    if signer is None or _is_nil_key(holder):
        raise ErrInvalidArgument("sdjwt: NewKBJWT needs a signer and the holder key")
    if not claims.audience or not claims.nonce or not claims.sd_hash or claims.issued_at.timestamp() == 0:
        raise ErrInvalidArgument("sdjwt: KBClaims needs Audience, Nonce, IssuedAt and SDHash")
    extra = dict(claims.extra or {})
    for name in ("iat", "aud", "nonce", "sd_hash"):
        if name in extra:
            raise ErrInvalidArgument(f"sdjwt: KBClaims.Extra holds {name}, which NewKBJWT writes from its own field")
    try:
        body = jose_json.decode_json_object(jose_json.encode_json(extra))
    except Exception as e:
        raise ErrInvalidArgument(f"sdjwt: KBClaims.Extra: {e}") from e
    body["iat"] = int(claims.issued_at.timestamp())
    body["aud"] = claims.audience
    body["nonce"] = claims.nonce
    body["sd_hash"] = claims.sd_hash
    payload = jose_json.encode_json(body)
    return sign(ctx, signer, holder, {"typ": TYP_KB}, payload)


@dataclass
class KBVerifyParams:
    audience: str
    nonce: str
    sd_hash: str
    now: datetime | None = None
    max_age_seconds: float = 300.0
    clock_skew_seconds: float = 0.0
    allowed_algs: list[str] | None = None


def verify_kb_jwt(kb: str, holder: Any, params: KBVerifyParams) -> dict[str, Any]:
    if _is_nil_key(holder):
        raise ErrInvalidArgument("sdjwt: VerifyKBJWT needs the holder key")
    if not params.audience or not params.nonce or not params.sd_hash:
        raise ErrInvalidArgument("sdjwt: KBVerifyParams needs Audience, Nonce and SDHash")
    if params.max_age_seconds <= 0 or params.clock_skew_seconds < 0:
        raise ErrInvalidArgument("sdjwt: KBVerifyParams needs a positive MaxAge and a ClockSkew that is not negative")
    try:
        from_public_key(holder)
    except ErrUnsupportedKey as e:
        raise ErrUnsupportedKey(f"sdjwt: key binding JWT: holder key: {e}") from e
    except ValueError as e:
        raise jws_errors.ErrBadKey(f"sdjwt: key binding JWT: holder key: {e}") from e
    now = params.now or datetime.now(timezone.utc)
    try:
        header, raw = verify(kb, holder, params.allowed_algs)
    except ErrUnsupportedKey as e:
        raise e
    except Exception as e:
        if type(e).__name__ == "ErrUnsupportedAlg":
            raise
        raise ErrKBInvalid(str(e)) from e
    if not header_typ_is(header, TYP_KB):
        raise ErrKBInvalid(f"typ is not {TYP_KB}")
    try:
        body = jose_json.decode_json_object(raw)
    except Exception as e:
        raise ErrKBInvalid(f"payload: {e}") from e
    iat, ok, err = _date_claim(body, "iat")
    if err:
        raise ErrKBInvalid(str(err)) from err
    if not ok:
        raise ErrKBInvalid("iat is missing")
    earliest = now.timestamp() - params.max_age_seconds - params.clock_skew_seconds
    latest = now.timestamp() + params.clock_skew_seconds
    if iat.timestamp() < earliest or iat.timestamp() > latest:
        raise ErrKBInvalid(f"iat {iat} is outside window")
    _string_claim(body, "aud", params.audience, ErrKBAudience)
    _string_claim(body, "nonce", params.nonce, ErrKBNonce)
    _string_claim(body, "sd_hash", params.sd_hash, ErrKBSDHash)
    try:
        jwt_mod.check_exp_nbf(body, now, params.clock_skew_seconds)
    except Exception as e:
        raise ErrKBInvalid(str(e)) from e
    return body


def _string_claim(claims: dict[str, Any], name: str, want: str, sentinel: type[Exception]) -> None:
    if name not in claims:
        raise ErrKBInvalid(f"{name} is missing")
    v = claims[name]
    if not isinstance(v, str):
        raise ErrKBInvalid(f"{name} is {type(v).__name__}, not a string")
    if v != want:
        raise sentinel(f"{name} differs from the expected value")


def _date_claim(claims: dict[str, Any], name: str) -> tuple[datetime, bool, Exception | None]:
    if name not in claims:
        return datetime.fromtimestamp(0, tz=timezone.utc), False, None
    try:
        return jwt_mod.numeric_date(claims[name]), True, None
    except Exception as e:
        return datetime.fromtimestamp(0, tz=timezone.utc), True, e


def _is_nil_key(k: Any) -> bool:
    if k is None:
        return True
    if isinstance(k, crypto_ec.EllipticCurvePublicKey):
        return False
    if isinstance(k, eth_keys.PublicKey):
        return False
    return False
