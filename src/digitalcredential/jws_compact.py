from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol

from credential.common.sdjwt.helper import b64url, b64url_decode
from credential.common.signer.p256 import verify_p256


class Signer(Protocol):
    def sign(self, digest: bytes) -> bytes: ...


def encode_jwk_from_p256(pub: bytes) -> dict[str, str]:
    raw = pub if len(pub) == 65 else pub
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(raw[1:33]),
        "y": b64url(raw[33:65]),
    }


def p256_from_jwk(jwk: dict[str, str]) -> bytes:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "x" not in jwk or "y" not in jwk:
        raise ValueError("cnf.jwk must be a P-256 EC key")
    return b"\x04" + b64url_decode(jwk["x"]) + b64url_decode(jwk["y"])


def sign_compact_jws(header: dict[str, Any], payload: dict[str, Any], signer: Signer) -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing = f"{h}.{p}"
    digest = hashlib.sha256(signing.encode("utf-8")).digest()
    sig = signer.sign(digest)
    if len(sig) == 65:
        sig = sig[:64]
    return f"{signing}.{b64url(sig)}"


def verify_compact_jws(token: str, pub: bytes, allowed_algs: list[str] | None = None) -> dict[str, Any]:
    allowed = allowed_algs or ["ES256"]
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWS")
    header = json.loads(b64url_decode(parts[0]))
    if header.get("alg") not in allowed:
        raise ValueError(f"alg not allowed: {header.get('alg')}")
    digest = hashlib.sha256(f"{parts[0]}.{parts[1]}".encode("utf-8")).digest()
    sig = b64url_decode(parts[2])[:64]
    if not verify_p256(pub, digest, sig):
        raise ValueError("signature verification failed")
    return json.loads(b64url_decode(parts[1]))


def peek_header(token: str) -> dict[str, Any]:
    return json.loads(b64url_decode(token.split(".")[0]))
