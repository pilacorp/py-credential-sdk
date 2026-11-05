from __future__ import annotations

import hashlib
from typing import Any

from credential.common.jwt.jwtutil import b64url_encode, trim_recovery_byte


class JWTSigner:
    """Signs JWT signing strings with a SignerProvider (``sign(digest32) -> bytes``)."""

    def __init__(self, signer: Any) -> None:
        self._signer = signer

    def sign_string(self, signing_string: str) -> str:
        if self._signer is None:
            raise ValueError("jwt signer: signer cannot be nil")
        digest = hashlib.sha256(signing_string.encode("utf-8")).digest()
        try:
            signature = self._signer.sign(digest)
        except Exception as exc:
            raise ValueError(f"jwt signer: failed to sign digest: {exc}") from exc
        return b64url_encode(trim_recovery_byte(signature))


def normalize_jwt_signature(signature: bytes) -> bytes:
    """Trim a 65-byte r||s||v to r||s; only 64/65-byte signatures are JWS-shaped."""
    if len(signature) in (64, 65):
        return trim_recovery_byte(signature)
    raise ValueError("signature length must be 64 or 65")
