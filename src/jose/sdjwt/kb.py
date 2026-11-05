"""Key Binding JWT (RFC 9901 §4.3, §7.3 step 5), after go-credential-sdk/jose/sdjwt/kb.go."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrUnsupportedAlg, ErrUnsupportedKey, wrap
from jose.internal.ec import from_public_key
from jose.jws import errors as jws_errors
from jose.jws.jws import header_typ_is, sign, verify
from jose.jwt import jwt as jwt_mod
from jose.sdjwt.disclosure import digest_of

TYP_KB = "kb+jwt"

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ErrKBInvalid(Exception):
    """Not a compact JWS, wrong alg/typ/signature, bad payload or iat, missing/non-string aud, nonce, sd_hash, failed exp/nbf."""


class ErrKBAudience(Exception):
    """aud is a string that differs from KBVerifyParams.audience."""


class ErrKBNonce(Exception):
    """nonce is a string that differs from KBVerifyParams.nonce."""


class ErrKBSDHash(Exception):
    """sd_hash is a string that differs from KBVerifyParams.sd_hash."""


def sd_hash(sd_jwt: str) -> str:
    """base64url(SHA-256(US-ASCII of sd_jwt)); sd_jwt is <issuer-jwt>~<D.1>~...~<D.N>~ (RFC 9901 §4.3.1)."""
    return digest_of(sd_jwt)


@dataclass
class KBClaims:
    """Claims of a new Key Binding JWT. All but `extra` are required; `extra` must not hold iat/aud/nonce/sd_hash."""

    audience: str
    nonce: str
    issued_at: datetime
    sd_hash: str
    extra: dict[str, Any] | None = None


def _unix(t: datetime) -> int:
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return (t - _EPOCH) // timedelta(seconds=1)


def new_kb_jwt(ctx: Any, signer: Any, holder: Any, claims: KBClaims) -> str:
    if signer is None or _is_nil_key(holder):
        raise ErrInvalidArgument("sdjwt: NewKBJWT needs a signer and the holder key")
    if (
        not claims.audience
        or not claims.nonce
        or not claims.sd_hash
        or claims.issued_at is None
        or claims.issued_at == datetime.min
    ):
        raise ErrInvalidArgument("sdjwt: KBClaims needs Audience, Nonce, IssuedAt and SDHash")
    extra = claims.extra or {}
    for name in ("iat", "aud", "nonce", "sd_hash"):
        if name in extra:
            raise ErrInvalidArgument(f"sdjwt: KBClaims.Extra holds {name}, which NewKBJWT writes from its own field")
    # A copy read back as verify_kb_jwt reads it, so Extra holds only JSON that it can decode.
    try:
        body = jose_json.decode_json_object(jose_json.encode_json(extra))
    except Exception as e:
        raise ErrInvalidArgument(f"sdjwt: KBClaims.Extra: {e}") from e
    body["iat"] = _unix(claims.issued_at)
    body["aud"] = claims.audience
    body["nonce"] = claims.nonce
    body["sd_hash"] = claims.sd_hash
    payload = jose_json.encode_json(body)
    return sign(ctx, signer, holder, {"typ": TYP_KB}, payload)


@dataclass
class KBVerifyParams:
    """What verify_kb_jwt checks a KB-JWT against. audience, nonce, sd_hash are required; max_age_seconds must be
    positive (no default window) and clock_skew_seconds not negative. now None means the current time."""

    audience: str
    nonce: str
    sd_hash: str
    now: datetime | None = None
    max_age_seconds: float = 0.0
    clock_skew_seconds: float = 0.0
    allowed_algs: list[str] | None = None


def verify_kb_jwt(kb: str, holder: Any, params: KBVerifyParams) -> dict[str, Any]:
    """Check kb in the order of RFC 9901 §7.3 step 5 and return its claims (all of them) on success."""
    if _is_nil_key(holder):
        raise ErrInvalidArgument("sdjwt: VerifyKBJWT needs the holder key")
    if not params.audience or not params.nonce or not params.sd_hash:
        raise ErrInvalidArgument("sdjwt: KBVerifyParams needs Audience, Nonce and SDHash")
    if params.max_age_seconds <= 0 or params.clock_skew_seconds < 0:
        raise ErrInvalidArgument("sdjwt: KBVerifyParams needs a positive MaxAge and a ClockSkew that is not negative")
    # Checked before kb is read, so the class of a bad holder key never depends on what the holder sends.
    try:
        from_public_key(holder)
    except ErrUnsupportedKey as e:
        raise ErrUnsupportedKey(f"sdjwt: key binding JWT: holder key: {e}") from e
    except ValueError as e:
        raise jws_errors.ErrBadKey(f"sdjwt: key binding JWT: holder key: {e}") from e
    now = params.now if params.now is not None else datetime.now(timezone.utc)
    now_ns = jwt_mod._now_ns(now)
    skew = round(params.clock_skew_seconds * 1e9)
    max_age = round(params.max_age_seconds * 1e9)

    try:
        header, raw = verify(kb, holder, params.allowed_algs)
    except ErrUnsupportedAlg as e:
        # The caller's allowed_algs, refused before kb is read.
        raise ErrUnsupportedAlg(f"sdjwt: key binding JWT: {e}") from e
    except Exception as e:
        raise wrap(ErrKBInvalid, e) from e
    if not header_typ_is(header, TYP_KB):
        raise ErrKBInvalid(f"typ is not {TYP_KB}")
    try:
        body = jose_json.decode_json_object(raw)
    except Exception as e:
        raise wrap(ErrKBInvalid, e, f"payload: {e}") from e

    try:
        iat = jwt_mod._date_claim_ns(body, "iat")
    except Exception as e:
        raise wrap(ErrKBInvalid, e) from e
    if iat is None:
        raise ErrKBInvalid("iat is missing")
    earliest, latest = now_ns - max_age - skew, now_ns + skew
    if iat < earliest or iat > latest:
        raise ErrKBInvalid("iat is outside the accepted window")

    # RFC 9901 §4.3: aud MUST be a single string; an array is refused (one KB-JWT, one Verifier).
    _string_claim(body, "aud", params.audience, ErrKBAudience)
    _string_claim(body, "nonce", params.nonce, ErrKBNonce)
    _string_claim(body, "sd_hash", params.sd_hash, ErrKBSDHash)

    try:
        jwt_mod.check_exp_nbf(body, now, params.clock_skew_seconds)
    except Exception as e:
        raise wrap(ErrKBInvalid, e) from e
    return body


def _string_claim(claims: dict[str, Any], name: str, want: str, sentinel: type[Exception]) -> None:
    if name not in claims:
        raise ErrKBInvalid(f"{name} is missing")
    v = claims[name]
    if not isinstance(v, str):
        raise ErrKBInvalid(f"{name} is {type(v).__name__}, not a string")
    if v != want:
        raise sentinel(f"{name} differs from the expected value")


def _is_nil_key(k: Any) -> bool:
    return k is None
