"""secp256k1 helpers (Go credential/common/crypto/crypto.go and ecdsa-rdfc-2019.go key-pair checks)."""

from __future__ import annotations

from hashlib import sha256

from eth_keys import keys
from eth_keys.exceptions import BadSignature

from credential.common.jsoncanonicalizer import transform as _jcs_transform


def key_to_bytes(key: str) -> bytes:
    if not key.startswith("0x"):
        raise ValueError("key is not in hex format")
    return bytes.fromhex(key[2:])


def parse_private_key(private_key: bytes) -> keys.PrivateKey:
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    return keys.PrivateKey(private_key)


def sign_message(private_key: bytes, message: bytes) -> str:
    """sha256(message) signed with secp256k1; returns hex r||s||v (v in {0,1}, low-S)."""
    priv = parse_private_key(private_key)
    return priv.sign_msg_hash(sha256(message).digest()).to_bytes().hex()


def _verify_without_v(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 33 or len(message) == 0:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if s > keys.constants.SECPK1_N // 2:  # libsecp256k1 VerifySignature rejects malleable (high-S)
        return False
    try:
        pub = keys.PublicKey.from_compressed_bytes(public_key)
        return bool(keys.Signature(vrs=(0, r, s)).verify_msg_hash(sha256(message).digest(), pub))
    except Exception:
        return False


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """secp256k1 verify: 65-byte r||s||v recovers and compares the key; 64-byte r||s verifies directly."""
    if len(signature) != 65 or len(public_key) != 33 or len(message) == 0:
        return _verify_without_v(public_key, message, signature)
    try:
        sig = keys.Signature(signature_bytes=signature)
        recovered = sig.recover_public_key_from_msg_hash(sha256(message).digest())
    except (BadSignature, ValueError, Exception):
        return False
    return recovered.to_compressed_bytes() == public_key


def verify_json_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        canonical = _jcs_transform(message)
    except Exception:
        return False
    return verify_signature(public_key, canonical, signature)


def verify_key_pair_from_hex(private_key_hex: str, public_key_hex: str) -> bool:
    try:
        priv = keys.PrivateKey(bytes.fromhex(private_key_hex.removeprefix("0x")))
    except Exception as exc:
        raise ValueError(f"failed to convert private key hex: {exc}") from exc
    try:
        raw = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise ValueError(f"failed to decode public key hex: {exc}") from exc
    try:
        if len(raw) == 33 and raw[0] in (2, 3):
            pub = keys.PublicKey.from_compressed_bytes(raw)
        elif len(raw) == 65 and raw[0] == 4:
            pub = keys.PublicKey(raw[1:])
        else:
            raise ValueError(f"bad length {len(raw)}")
    except Exception as exc:
        raise ValueError(f"failed to unmarshal public key: {exc}") from exc
    return priv.public_key == pub
