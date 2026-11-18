"""ECDSA verification helpers (Go credential/common/crypto/ecdsa-rdfc-2019.go, ecdsa-sd-2023.go)."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from eth_keys import keys as eth_keys_mod

_PREHASHED = ec.ECDSA(Prehashed(hashes.SHA256()))


def _verify_rs(pub: ec.EllipticCurvePublicKey | eth_keys_mod.PublicKey, digest: bytes, sig64: bytes) -> bool:
    if len(digest) != 32:
        return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if isinstance(pub, eth_keys_mod.PublicKey):
        try:
            return bool(eth_keys_mod.Signature(vrs=(0, r, s)).verify_msg_hash(digest, pub))
        except Exception:
            return False
    try:
        pub.verify(encode_dss_signature(r, s), digest, _PREHASHED)
        return True
    except Exception:
        return False


def verify_p256(pub: ec.EllipticCurvePublicKey, digest: bytes, sig: bytes) -> bool:
    """Go VerifyP256: 64-byte r||s over a 32-byte digest; high-S accepted."""
    if pub is None or len(sig) != 64:
        return False
    return _verify_rs(pub, digest, sig)


def verify_ecdsa(pub: ec.EllipticCurvePublicKey | eth_keys_mod.PublicKey, digest: bytes, sig: bytes) -> bool:
    """Go VerifyECDSA: verifies with the key's own curve; a trailing recovery byte (65 bytes) is dropped."""
    if pub is None:
        return False
    if len(sig) == 65:
        sig = sig[:64]
    if len(sig) != 64:
        return False
    return _verify_rs(pub, digest, sig)


def ecdsa_verify_signature(pub: ec.EllipticCurvePublicKey, signature_hex: str, msg: bytes) -> bool:
    """Go ECDSAVerifySignature: hex r||s[||v] over ``msg`` taken as the digest itself (legacy hex proofs)."""
    if pub is None:
        raise ValueError("public key is nil")
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ValueError(f"failed to decode signature: {exc}") from exc
    if len(sig_bytes) == 65:
        sig_bytes = sig_bytes[:64]
    elif len(sig_bytes) != 64:
        raise ValueError(f"invalid signature length: got {len(sig_bytes)}, want 64 or 65 bytes")
    return _verify_rs(pub, msg, sig_bytes)
