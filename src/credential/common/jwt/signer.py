from __future__ import annotations

import base64
import hashlib

from didv2.signer import DefaultProvider


class JWTSigner:
    def __init__(self, signer: DefaultProvider) -> None:
        self._signer = signer

    def sign_string(self, signing_string: str) -> str:
        digest = hashlib.sha256(signing_string.encode("utf-8")).digest()
        sig = normalize_jwt_signature(self._signer.sign(digest))
        return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def normalize_jwt_signature(signature: bytes) -> bytes:
    if len(signature) == 64:
        return signature
    if len(signature) == 65:
        return signature[:64]
    raise ValueError("signature length must be 64 or 65")
