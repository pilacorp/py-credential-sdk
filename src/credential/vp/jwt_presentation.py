from __future__ import annotations

import json
from typing import Any

from credential.common.jwt.signer import JWTSigner
from credential.common.jwt.verifier import verify_es256k
from credential.vc.jwt_credential import _b64url_json
from didv2.signer import DefaultProvider


class JWTPresentation:
    def __init__(self, signing_input: str, payload: dict[str, Any], signature: str = "") -> None:
        self.signing_input = signing_input
        self.payload = payload
        self.signature = signature

    @classmethod
    def create(cls, vpc: dict[str, Any], kid: str = "key-1") -> JWTPresentation:
        holder = vpc.get("holder") or ""
        vp = {
            "@context": vpc.get("@context") or ["https://www.w3.org/2018/credentials/v1"],
            "type": vpc.get("type") or ["VerifiablePresentation"],
            "holder": holder,
            "verifiableCredential": vpc.get("verifiableCredential") or [],
        }
        claims: dict[str, Any] = {"vp": vp}
        if holder:
            claims["iss"] = holder
            claims["sub"] = holder
        if vpc.get("id"):
            claims["jti"] = vpc["id"]
        if vpc.get("challenge"):
            claims["nonce"] = vpc["challenge"]
        if vpc.get("domain"):
            claims["aud"] = vpc["domain"]
        header = {"typ": "JWT", "alg": "ES256K", "kid": f"{holder}#{kid}"}
        return cls(_b64url_json(header) + "." + _b64url_json(claims), claims)

    def add_proof(self, signer: DefaultProvider) -> JWTPresentation:
        self.signature = JWTSigner(signer).sign_string(self.signing_input)
        return self

    def serialize(self) -> str:
        if not self.signature:
            raise ValueError("presentation is not signed")
        return self.signing_input + "." + self.signature

    def verify(self, expected_address: str, audience: str | None = None, challenge: str | None = None) -> None:
        verify_es256k(self.signing_input, self.signature, expected_address)
        if audience and self.payload.get("aud") != audience:
            raise ValueError("audience mismatch")
        if challenge and self.payload.get("nonce") != challenge:
            raise ValueError("challenge mismatch")

    def credentials(self) -> list[Any]:
        return list((self.payload.get("vp") or {}).get("verifiableCredential") or [])
