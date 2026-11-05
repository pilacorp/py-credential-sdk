from __future__ import annotations

import hashlib

from eth_keys import keys

from credential.common.verification_method.key_material import verify_rs
from credential.common.verification_method.selector import KeyKind

ALG_ES256K = "ES256K"  # secp256k1
ALG_ES256 = "ES256"  # P-256


def alg_for_key_kind(kind: KeyKind) -> str:
    """JOSE algorithm for the key a VM holds. RSA is rejected: the JWT path signs 64-byte r||s."""
    if kind == KeyKind.SECP256K1:
        return ALG_ES256K
    if kind == KeyKind.P256:
        return ALG_ES256
    raise ValueError(f"key kind {kind} is not supported for JWT")


def sign_es256k(signing_string: str, priv_key_hex: str) -> bytes:
    """ES256K signature (r||s) of SHA-256(signing_string)."""
    from credential.common.verification_method.key_material import strip_hex_prefix

    try:
        priv = keys.PrivateKey(bytes.fromhex(strip_hex_prefix(priv_key_hex)))
    except Exception as exc:
        raise ValueError(f"invalid private key: {exc}") from exc
    sig = priv.sign_msg_hash(hashlib.sha256(signing_string.encode("utf-8")).digest())
    return sig.to_bytes()[:64]


def verify_ecdsa(signing_string: str, signature: bytes, public_key) -> None:
    """Verify a 64-byte r||s signature over SHA-256(signing_string) on whatever curve the key is on."""
    if public_key is None:
        raise ValueError("public key is nil")
    if len(signature) != 64:
        raise ValueError("invalid signature length")
    if not verify_rs(public_key, hashlib.sha256(signing_string.encode("utf-8")).digest(), bytes(signature)):
        raise ValueError("signature verification failed")
