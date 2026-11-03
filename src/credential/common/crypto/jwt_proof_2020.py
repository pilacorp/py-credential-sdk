from __future__ import annotations

import base64
from hashlib import sha256
from typing import Any

from eth_keys import keys
from eth_keys.exceptions import BadSignature


def verify_jwt_proof(document: dict[str, Any], pub_compressed: bytes) -> bool:
    proof = document.get("proof")
    if not isinstance(proof, dict):
        return False
    jwt_token = proof.get("jwt")
    if not jwt_token:
        return False
    try:
        signature, message = _signature_and_message(jwt_token)
    except ValueError:
        return False
    return _verify_signature(pub_compressed, message, signature)


def _signature_and_message(jwt_token: str) -> tuple[bytes, bytes]:
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT format")
    signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    message = (parts[0] + "." + parts[1]).encode("ascii")
    return signature, message


def _verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    digest = sha256(message).digest()
    pub = keys.PublicKey(public_key)
    if len(signature) == 65:
        try:
            return keys.Signature(signature_bytes=signature).verify_msg_hash(digest, pub)
        except BadSignature:
            return False
    if len(signature) == 64:
        return _verify_signature_without_v(public_key, message, signature)
    return False


def _verify_signature_without_v(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 33 or not message:
        return False
    digest = sha256(message).digest()
    pub = keys.PublicKey(public_key)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    for v in (0, 1):
        try:
            sig = keys.Signature(vrs=(v, r, s))
            if sig.verify_msg_hash(digest, pub):
                return True
        except BadSignature:
            continue
    return False
