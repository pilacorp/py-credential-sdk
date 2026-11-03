from __future__ import annotations

import base64
import json
from typing import Any

from credential.common.jwt.signer import JWTSigner
from credential.common.jwt.verifier import verify_es256k
from credential.vc.helper import serialize_credential_contents
from didv2.signer import DefaultProvider

DEFAULT_KID = "key-1"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_json(obj: dict[str, Any]) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


class JWTCredential:
    def __init__(self, signing_input: str, payload: dict[str, Any], signature: str = "") -> None:
        self.signing_input = signing_input
        self._payload = payload
        self.signature = signature

    @classmethod
    def create(cls, vcc: dict[str, Any], kid: str = DEFAULT_KID) -> JWTCredential:
        vc = serialize_credential_contents(vcc)
        claims: dict[str, Any] = {"vc": vc}
        issuer = vcc.get("issuer") or ""
        if issuer:
            claims["iss"] = issuer
        subject = vcc.get("credentialSubject")
        if isinstance(subject, dict) and subject.get("id"):
            claims["sub"] = subject["id"]
        elif isinstance(subject, list) and subject and subject[0].get("id"):
            claims["sub"] = subject[0]["id"]
        if vcc.get("id"):
            claims["jti"] = vcc["id"]
        header = {"typ": "JWT", "alg": "ES256K", "kid": f"{issuer}#{kid}"}
        signing_input = _b64url_json(header) + "." + _b64url_json(claims)
        return cls(signing_input, claims)

    @classmethod
    def parse(cls, raw: str) -> JWTCredential:
        parts = raw.split(".")
        if len(parts) != 3 or not all(parts):
            raise ValueError("invalid JWT format")
        pad = "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        return cls(parts[0] + "." + parts[1], payload, parts[2])

    def add_proof(self, signer: DefaultProvider) -> JWTCredential:
        self.signature = JWTSigner(signer).sign_string(self.signing_input)
        return self

    def serialize(self) -> str:
        if not self.signature:
            raise ValueError("JWT is not signed")
        return self.signing_input + "." + self.signature

    def payload(self) -> dict[str, Any]:
        return self._payload

    def vc(self) -> dict[str, Any]:
        vc = self._payload.get("vc")
        return vc if isinstance(vc, dict) else self._payload

    def verify(self, expected_address: str) -> None:
        if not self.signature:
            raise ValueError("JWT is not signed")
        verify_es256k(self.signing_input, self.signature, expected_address)
