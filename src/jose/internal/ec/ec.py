"""P-256 and secp256k1 ECDSA (r||s) for JOSE (Go jose/internal/ec)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
from eth_keys import keys as eth_keys

from jose.errors import ErrUnsupportedKey
from jose.internal.errtext import quote

_SUPPORTED = "the SDK supports ECDSA keys on P-256 and secp256k1"

_P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
_SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


class Kind(Enum):
    P256 = 1
    SECP256K1 = 2

    def name(self) -> str:  # noqa: D102 - shadows Enum.name on purpose (Go Kind.Name)
        if self is Kind.P256:
            return "P-256"
        if self is Kind.SECP256K1:
            return "secp256k1"
        raise ValueError(f"jose: invalid curve kind {self}")

    def curve(self) -> crypto_ec.EllipticCurve:
        if self is Kind.P256:
            return crypto_ec.SECP256R1()
        if self is Kind.SECP256K1:
            return crypto_ec.SECP256K1()
        raise ValueError(f"jose: invalid curve kind {self}")

    def order(self) -> int:
        if self is Kind.P256:
            return _P256_N
        if self is Kind.SECP256K1:
            return _SECP256K1_N
        raise ValueError(f"jose: invalid curve kind {self}")


P256 = Kind.P256
Secp256k1 = Kind.SECP256K1

_KIND_BY_CURVE = {"secp256r1": Kind.P256, "secp256k1": Kind.SECP256K1}


def _kind_of_curve(curve: Any) -> Kind:
    kind = _KIND_BY_CURVE.get(getattr(curve, "name", None))
    if kind is None:
        raise ErrUnsupportedKey(f"curve {quote(str(getattr(curve, 'name', curve)))}; {_SUPPORTED}")
    return kind


@dataclass
class Point:
    kind: Kind
    x: bytes  # 32 bytes
    y: bytes  # 32 bytes

    def uncompressed(self) -> bytes:
        return b"\x04" + self.x + self.y

    def public_key(self) -> crypto_ec.EllipticCurvePublicKey:
        """Build a cryptography public key; raises ValueError when the point is off the curve."""
        curve = self.kind.curve()
        return crypto_ec.EllipticCurvePublicNumbers(
            int.from_bytes(self.x, "big"), int.from_bytes(self.y, "big"), curve
        ).public_key()

    def check_on_curve(self) -> None:
        """Partial public-key validation (SP 800-186 App. D.1.1.1): coordinates in [0, p-1] and on the curve."""
        Kind.curve(self.kind)  # an invalid kind is a bug in this module, not bad input
        if len(self.x) != 32 or len(self.y) != 32:
            raise ValueError("coordinate out of range")
        try:
            self.public_key()
        except Exception as e:
            raise ValueError(f"point is not on {self.kind.name()}: {e}") from e


@dataclass
class PrivateKey:
    point: Point
    d: bytes  # 32 bytes

    def _public_bytes(self) -> bytes:
        priv = crypto_ec.derive_private_key(int.from_bytes(self.d, "big"), self.point.kind.curve())
        nums = priv.public_key().public_numbers()
        return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def sign_rs(self, digest: bytes) -> bytes:
        """ECDSA over digest as 64-byte r||s. secp256k1 is RFC 6979 low-S (as decred); P-256 is not normalised."""
        if self.point.kind is Kind.P256:
            priv = crypto_ec.derive_private_key(int.from_bytes(self.d, "big"), crypto_ec.SECP256R1())
            r, s = decode_dss_signature(priv.sign(digest, crypto_ec.ECDSA(Prehashed(hashes.SHA256()))))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if self.point.kind is Kind.SECP256K1:
            sig = eth_keys.PrivateKey(self.d).sign_msg_hash(digest)
            return sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
        raise ValueError(f"jose: invalid curve kind {self.point.kind}")


def from_public_key(key: Any) -> Point:
    """Curve + affine coordinates of key, checked on its curve.

    Unsupported key type or curve: ErrUnsupportedKey; any other fault is a plain ValueError
    (the caller wraps it in its own ErrBadKey).
    """
    if key is None:
        raise ValueError("nil key")
    if isinstance(key, crypto_ec.EllipticCurvePublicKey):
        kind = _kind_of_curve(key.curve)
        nums = key.public_numbers()
        if nums.x < 0 or nums.y < 0 or nums.x.bit_length() > 256 or nums.y.bit_length() > 256:
            raise ValueError("coordinate out of range")
        pt = Point(kind=kind, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))
    elif isinstance(key, eth_keys.PublicKey):
        unc = key.to_bytes()
        pt = Point(kind=Kind.SECP256K1, x=unc[:32], y=unc[32:])
    else:
        raise ErrUnsupportedKey(f"key type {type(key).__name__}; the SDK supports cryptography EC public keys or eth_keys.PublicKey on P-256 or secp256k1")
    pt.check_on_curve()
    return pt


def from_private_key(key: Any) -> PrivateKey:
    """Copy of key after the checks of from_public_key plus d in [1, n-1] and d*G == public key."""
    if key is None:
        raise ValueError("nil key")
    if isinstance(key, crypto_ec.EllipticCurvePrivateKey):
        kind = _kind_of_curve(key.curve)
        try:
            pub_pt = from_public_key(key.public_key())
        except ErrUnsupportedKey:
            raise
        except ValueError as e:
            raise ValueError(f"public key: {e}") from e
        d = key.private_numbers().private_value
    elif isinstance(key, eth_keys.PrivateKey):
        kind = Kind.SECP256K1
        pub_pt = from_public_key(key.public_key)
        d = int.from_bytes(key.to_bytes(), "big")
    else:
        raise ErrUnsupportedKey(f"key type {type(key).__name__}; the SDK supports cryptography EC private keys or eth_keys.PrivateKey on P-256 or secp256k1")
    if not _in_scalar_range(d, kind.order()):
        raise ValueError("d outside [1, n-1]")
    k = PrivateKey(point=pub_pt, d=d.to_bytes(32, "big"))
    if k._public_bytes() != pub_pt.uncompressed():
        raise ValueError("public key does not match d")
    return k


def verify_rs(point: Point, digest: bytes, sig: bytes) -> None:
    """ECDSA verification (FIPS 186-5 §6.4.2) of 64-byte r||s over digest; any s in [1, n-1] verifies (low or high)."""
    if len(sig) != 64:
        raise ValueError("signature must be 64 bytes")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    n = Kind.order(point.kind)
    if not _in_scalar_range(r, n) or not _in_scalar_range(s, n):
        raise ValueError("r or s outside [1, n-1]")
    try:
        point.public_key().verify(encode_dss_signature(r, s), digest, crypto_ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature as e:
        raise ValueError("signature does not verify") from e
    except Exception as e:
        raise ValueError(f"signature does not verify: {e}") from e


def _in_scalar_range(v: int, n: int) -> bool:
    return v is not None and n is not None and 0 < v < n
