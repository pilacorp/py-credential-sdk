from __future__ import annotations

import base64
import json
from typing import Any

from credential.common.jwt.signer import JWTSigner
from credential.vp.jwt_presentation import JWTPresentation


def _b64url_json(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class JOSEPresentation:
    """W3C vc-jose-cose presentation (typ: vp+jwt)."""

    def __init__(self, signing_input: str, payload: dict[str, Any], signature: str = "") -> None:
        self.signing_input = signing_input
        self._payload = payload
        self.signature = signature

    @classmethod
    def create(cls, vpc: dict[str, Any], kid: str = "key-1") -> JOSEPresentation:
        if not vpc.get("@context"):
            vpc = {**vpc, "@context": ["https://www.w3.org/ns/credentials/v2"]}
        payload = dict(vpc)
        holder = payload.get("holder") or ""
        header = {"typ": "vp+jwt", "alg": "ES256K", "kid": f"{holder}#{kid}" if holder else kid}
        signing_input = _b64url_json(header) + "." + _b64url_json(payload)
        return cls(signing_input, payload)

    @classmethod
    def parse(cls, token: str) -> JOSEPresentation:
        legacy = JWTPresentation.parse(token)
        return cls(legacy.signing_input, legacy.payload, legacy.signature)

    def sign(self, signer: JWTSigner) -> None:
        self.signature = signer.sign_string(self.signing_input)

    def serialize(self) -> str:
        if not self.signature:
            raise ValueError("presentation is not signed")
        return self.signing_input + "." + self.signature
