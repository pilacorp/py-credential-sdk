from __future__ import annotations

from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature

from didv2.hexutil import with_0x

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def normalize_low_s(order: int, s: int) -> int:
    """Go signer.NormalizeLowS: s if s <= n/2 else n-s."""
    return order - s if s > order >> 1 else s


class P256Provider:
    """P-256 signer of a 32-byte digest -> 64-byte low-S r||s (Go signer.P256Provider).

    Construct from an in-memory scalar (``P256Provider(priv_bytes)``), ``from_hex``,
    ``from_private_key`` or a callback (``from_func``; HSM/KMS) that returns r||s.
    """

    def __init__(self, private_key: bytes | None = None, *, sign_func: Callable[[bytes], bytes] | None = None) -> None:
        self._sign_func = sign_func
        if sign_func is not None:
            self._key = None
        elif private_key is None:
            self._key = ec.generate_private_key(ec.SECP256R1())
        else:
            self._key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())

    @classmethod
    def from_private_key(cls, priv: ec.EllipticCurvePrivateKey) -> "P256Provider":
        if priv is None:
            raise ValueError("p256 private key is nil")
        if not isinstance(priv.curve, ec.SECP256R1):
            raise ValueError("private key is not P-256")
        self = cls.__new__(cls)
        self._sign_func = None
        self._key = priv
        return self

    @classmethod
    def from_hex(cls, priv_hex: str) -> "P256Provider":
        h = priv_hex[2:] if priv_hex[:2] in ("0x", "0X") else priv_hex
        try:
            raw = bytes.fromhex(h)
        except ValueError as exc:
            raise ValueError(f"decode p256 private key hex: {exc}") from exc
        if 0 < len(raw) < 32:
            raw = b"\x00" * (32 - len(raw)) + raw
        try:
            return cls(raw)
        except ValueError as exc:
            raise ValueError(f"invalid p256 private key: {exc}") from exc

    @classmethod
    def from_func(cls, sign_func: Callable[[bytes], bytes]) -> "P256Provider":
        if sign_func is None:
            raise ValueError("sign function is nil")
        return cls(sign_func=sign_func)

    def sign(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise ValueError(f"hash payload must be 32 bytes, got {len(digest)}")
        if self._sign_func is not None:
            return self._sign_func(digest)
        der = self._key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        s = normalize_low_s(P256_ORDER, s)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public(self) -> ec.EllipticCurvePublicKey | None:
        return None if self._key is None else self._key.public_key()

    def algorithm(self) -> str:
        return "ES256"

    # kept for existing callers (jose_algorithm is what jsonmap asks for)
    jose_algorithm = algorithm

    def public_key_uncompressed(self) -> bytes:
        nums = self._key.public_key().public_numbers()
        return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def private_key_bytes(self) -> bytes:
        return self._key.private_numbers().private_value.to_bytes(32, "big")

    def get_address(self) -> str:
        return with_0x(self.public_key_uncompressed()[-20:])


def verify_p256(pub_uncompressed: bytes, digest: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(pub_uncompressed) != 65 or pub_uncompressed[0] != 4:
        return False
    try:
        nums = ec.EllipticCurvePublicNumbers(
            int.from_bytes(pub_uncompressed[1:33], "big"),
            int.from_bytes(pub_uncompressed[33:65], "big"),
            ec.SECP256R1(),
        )
        pub = nums.public_key()
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:64], "big")
        pub.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False
