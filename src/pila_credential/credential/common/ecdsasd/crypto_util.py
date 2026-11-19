from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

# secp256r1 group order n
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def normalize_low_s_p256(s: int) -> int:
    if s >= _P256_N:
        return s
    half = _P256_N >> 1
    if s > half:
        return _P256_N - s
    return s


def encode_rs_p256(r: int, s: int) -> bytes:
    s = normalize_low_s_p256(s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_p256(pub: ec.EllipticCurvePublicKey, digest: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    try:
        pub.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        pass
    if s >= _P256_N:
        return False
    s_alt = _P256_N - s
    try:
        pub.verify(encode_dss_signature(r, s_alt), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


def verify_ecdsa(pub: ec.EllipticCurvePublicKey, digest: bytes, signature: bytes) -> bool:
    if len(signature) == 65:
        signature = signature[:64]
    return verify_p256(pub, digest, signature)
