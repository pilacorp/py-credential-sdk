"""P-256 and secp256k1 ECDSA (r||s) for JOSE."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from eth_keys import keys as eth_keys

from credential.common.signer.p256 import verify_p256
from jose.errors import ErrUnsupportedKey
from jose.internal.errtext import quote

_SUPPORTED = "the SDK supports ECDSA keys on P-256 and secp256k1"

# secp256k1 domain parameters (identify curve by p and n)
_SECP256K1_P = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
_SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
_P256_P = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
_P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


class Kind(Enum):
    P256 = 1
    SECP256K1 = 2

    def name(self) -> str:
        if self is Kind.P256:
            return "P-256"
        if self is Kind.SECP256K1:
            return "secp256k1"
        raise ValueError(f"jose: invalid curve kind {self}")


P256 = Kind.P256
Secp256k1 = Kind.SECP256K1


@dataclass
class Point:
    kind: Kind
    x: bytes  # 32 bytes
    y: bytes  # 32 bytes

    def uncompressed(self) -> bytes:
        return b"\x04" + self.x + self.y

    def check_on_curve(self) -> None:
        if self.kind is Kind.P256:
            nums = crypto_ec.EllipticCurvePublicNumbers(
                int.from_bytes(self.x, "big"),
                int.from_bytes(self.y, "big"),
                crypto_ec.SECP256R1(),
            )
            try:
                nums.public_key()
            except Exception as e:
                raise ValueError(f"point is not on P-256: {e}") from e
            return
        if self.kind is Kind.SECP256K1:
            try:
                eth_keys.PublicKey(self.x + self.y)
            except Exception as e:
                raise ValueError(f"point is not on secp256k1: {e}") from e
            return
        raise ValueError(f"jose: invalid curve kind {self.kind}")


@dataclass
class PrivateKey:
    point: Point
    d: bytes  # 32 bytes

    def sign_rs(self, digest: bytes) -> bytes:
        if self.point.kind is Kind.P256:
            priv_int = int.from_bytes(self.d, "big")
            priv = crypto_ec.derive_private_key(priv_int, crypto_ec.SECP256R1())
            der = priv.sign(digest, crypto_ec.ECDSA(Prehashed(hashes.SHA256())))
            r, s = decode_dss_signature(der)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if self.point.kind is Kind.SECP256K1:
            sig = eth_keys.PrivateKey(self.d).sign_msg_hash(digest)
            return sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
        raise ValueError(f"jose: invalid curve kind {self.point.kind}")


def from_public_key(key: Any) -> Point:
    if key is None:
        raise ValueError("nil key")
    if isinstance(key, crypto_ec.EllipticCurvePublicKey):
        if key.curve.name != "secp256r1":
            raise ErrUnsupportedKey(f"curve {quote(key.curve.name)}; {_SUPPORTED}")
        nums = key.public_numbers()
        if nums.x < 0 or nums.y < 0 or nums.x.bit_length() > 256 or nums.y.bit_length() > 256:
            raise ValueError("coordinate out of range")
        pt = Point(kind=Kind.P256, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))
        pt.check_on_curve()
        return pt
    if isinstance(key, eth_keys.PublicKey):
        unc = key.to_bytes()
        if len(unc) != 64:
            raise ValueError("coordinate out of range")
        pt = Point(kind=Kind.SECP256K1, x=unc[:32], y=unc[32:])
        pt.check_on_curve()
        return pt
    raise ErrUnsupportedKey(f"key type {type(key).__name__}; {_SUPPORTED}")


def from_private_key(key: Any) -> PrivateKey:
    if key is None:
        raise ValueError("nil key")
    if isinstance(key, crypto_ec.EllipticCurvePrivateKey):
        if key.curve.name != "secp256r1":
            raise ErrUnsupportedKey(f"curve {quote(key.curve.name)}; {_SUPPORTED}")
        pub_pt = from_public_key(key.public_key())
        d = key.private_numbers().private_value
        n = _P256_N
        if not _in_scalar_range(d, n):
            raise ValueError("d outside [1, n-1]")
        d_bytes = d.to_bytes(32, "big")
        k = PrivateKey(point=pub_pt, d=d_bytes)
        if k._public_bytes() != pub_pt.uncompressed():
            raise ValueError("public key does not match d")
        return k
    if isinstance(key, eth_keys.PrivateKey):
        pub_pt = from_public_key(key.public_key)
        d_bytes = key.to_bytes()
        if not _in_scalar_range(int.from_bytes(d_bytes, "big"), _SECP256K1_N):
            raise ValueError("d outside [1, n-1]")
        k = PrivateKey(point=pub_pt, d=d_bytes)
        if k._public_bytes() != pub_pt.uncompressed():
            raise ValueError("public key does not match d")
        return k
    raise ErrUnsupportedKey(f"key type {type(key).__name__}; {_SUPPORTED}")


def verify_rs(point: Point, digest: bytes, sig: bytes) -> None:
    if len(sig) != 64:
        raise ValueError("signature must be 64 bytes")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    n = _P256_N if point.kind is Kind.P256 else _SECP256K1_N
    if not _in_scalar_range(r, n) or not _in_scalar_range(s, n):
        raise ValueError("r or s outside [1, n-1]")
    if point.kind is Kind.P256:
        if not verify_p256(point.uncompressed(), digest, sig):
            raise ValueError("signature does not verify")
        return
    if point.kind is Kind.SECP256K1:
        pub = eth_keys.PublicKey(point.x + point.y)
        for rec_id in (0, 1):
            try:
                trial = eth_keys.Signature(sig + bytes([rec_id]))
                pub.verify_msg_hash(digest, trial)
                return
            except Exception:
                continue
        raise ValueError("signature does not verify")
    raise ValueError(f"jose: invalid curve kind {point.kind}")


def _in_scalar_range(v: int, n: int) -> bool:
    return v > 0 and v < n


def _kind_of_crypto_curve(curve: crypto_ec.EllipticCurve) -> Kind | None:
    params = curve
    if isinstance(curve, crypto_ec.EllipticCurve):
        if curve.name == "secp256r1":
            return Kind.P256
    return None


# Attach helper to PrivateKey
def _public_bytes(self: PrivateKey) -> bytes:
    if self.point.kind is Kind.P256:
        priv_int = int.from_bytes(self.d, "big")
        priv = crypto_ec.derive_private_key(priv_int, crypto_ec.SECP256R1())
        nums = priv.public_key().public_numbers()
        return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    pub = eth_keys.PrivateKey(self.d).public_key
    return b"\x04" + pub.to_bytes()


PrivateKey._public_bytes = _public_bytes  # type: ignore[attr-defined]
