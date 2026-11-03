from __future__ import annotations

from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from credential.common.ecdsasd.crypto_util import encode_rs_p256
from didv2.did.multikey import (
    P256_PUB_MULTICODEC,
    _b58encode,
    decode_multibase_key,
    ec_pub_from_multikey_bytes as _ec_pub_from_multikey_bytes,
)

P256_PRIV_MULTICODEC = bytes([0x86, 0x26])


def pub_to_multikey_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    if not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("multikey: unsupported curve (want P-256)")
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    prefix = b"\x02" if (nums.y % 2) == 0 else b"\x03"
    return P256_PUB_MULTICODEC + prefix + x


def encode_multibase_key(raw: bytes) -> str:
    return "z" + _b58encode(raw)


def ec_pub_from_multikey_bytes(raw: bytes) -> ec.EllipticCurvePublicKey:
    return _ec_pub_from_multikey_bytes(raw)


def decode_p256_priv_multibase(s: str) -> ec.EllipticCurvePrivateKey:
    raw = decode_multibase_key(s)
    if not raw.startswith(P256_PRIV_MULTICODEC):
        raise ValueError("multikey: not a p256-priv multikey")
    d = raw[len(P256_PRIV_MULTICODEC) :]
    if len(d) != 32:
        raise ValueError(f"multikey: p256 secret key must be 32 bytes, got {len(d)}")
    return ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())


class EphemeralKey:
    def __init__(self, priv: ec.EllipticCurvePrivateKey | None = None) -> None:
        self.priv = priv or ec.generate_private_key(ec.SECP256R1())

    def sign_statement(self, statement: str) -> bytes:
        digest = sha256(statement.encode("utf-8")).digest()
        der = self.priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        return encode_rs_p256(r, s)


def new_ephemeral_key() -> EphemeralKey:
    return EphemeralKey()
