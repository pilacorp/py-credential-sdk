"""JSON Web Key (RFC 7517) for EC P-256 and secp256k1."""

from __future__ import annotations

from typing import Any

from jose import base64 as jose_b64
from jose.errors import ErrUnsupportedKey
from jose.internal.ec import Kind, Point, from_public_key as ec_from_public_key

class ErrBadKey(Exception):
    """JWK is not a valid public key of a supported type."""

_CRV_P256 = "P-256"
_CRV_SECP256K1 = "secp256k1"
_ALG_ES256K = "ES256K"


def to_public_key(m: dict[str, Any] | None) -> Any:
    if m is None:
        raise ErrBadKey("nil JWK")
    if "d" in m:
        raise ErrBadKey("JWK carries a private key (d)")
    kty = m.get("kty")
    if not isinstance(kty, str):
        raise ErrBadKey("kty is missing or not a string")
    if kty != "EC":
        raise ErrUnsupportedKey(f"kty {kty[:16]!r}; the SDK supports kty EC on P-256 and secp256k1")
    crv = m.get("crv")
    if not isinstance(crv, str):
        raise ErrBadKey("crv is missing or not a string")
    kind = _kind_for_crv(crv)
    if kind is None:
        raise ErrUnsupportedKey(f"crv {crv[:16]!r}; the SDK supports P-256 and secp256k1")
    if kind is Kind.SECP256K1:
        _check_es256k_members(m)
    x = _coordinate(m, "x")
    y = _coordinate(m, "y")
    pt = Point(kind=kind, x=x, y=y)
    try:
        pt.check_on_curve()
    except ValueError as e:
        raise ErrBadKey(str(e)) from e
    return _point_to_crypto_key(pt)


def from_public_key(key: Any) -> dict[str, Any]:
    try:
        pt = ec_from_public_key(key)
    except ErrUnsupportedKey:
        raise
    except ValueError as e:
        raise ErrBadKey(str(e)) from e
    return {
        "kty": "EC",
        "crv": _crv_of(pt.kind),
        "x": jose_b64.encode_segment(pt.x),
        "y": jose_b64.encode_segment(pt.y),
    }


def _coordinate(m: dict[str, Any], name: str) -> bytes:
    s = m.get(name)
    if not isinstance(s, str):
        raise ErrBadKey(f"{name} must be a string")
    try:
        b = jose_b64.decode_segment(s)
    except Exception as e:
        raise ErrBadKey(f"{name}: {e}") from e
    if len(b) != 32:
        raise ErrBadKey(f"{name} must be 32 bytes, got {len(b)}")
    return int.from_bytes(b, "big").to_bytes(32, "big")


def _check_es256k_members(m: dict[str, Any]) -> None:
    if "alg" in m:
        alg = m["alg"]
        if not isinstance(alg, str) or alg != _ALG_ES256K:
            raise ErrBadKey("alg of a secp256k1 key must be ES256K (RFC 8812 §3.2)")
    if "use" in m:
        use = m["use"]
        if not isinstance(use, str) or use != "sig":
            raise ErrBadKey("use of a secp256k1 key must be sig (RFC 8812 §3.2)")
    if "key_ops" in m:
        if not _includes_verify(m["key_ops"]):
            raise ErrBadKey(
                "key_ops of a secp256k1 key must be a JSON array including verify (RFC 7517 §4.3, RFC 8812 §3.2)"
            )


def _includes_verify(key_ops: Any) -> bool:
    if not isinstance(key_ops, list):
        return False
    return "verify" in key_ops


def _crv_of(kind: Kind) -> str:
    if kind is Kind.P256:
        return _CRV_P256
    if kind is Kind.SECP256K1:
        return _CRV_SECP256K1
    raise ValueError(f"jose: invalid curve kind {kind}")


def _kind_for_crv(crv: str) -> Kind | None:
    if crv == _CRV_P256:
        return Kind.P256
    if crv == _CRV_SECP256K1:
        return Kind.SECP256K1
    return None


def _point_to_crypto_key(pt: Point) -> Any:
    # A cryptography EC public key on either curve (Go: *ecdsa.PublicKey, on secp256k1.S256() for secp256k1).
    return pt.public_key()
