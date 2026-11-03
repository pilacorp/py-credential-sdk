from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from credential.vc.helper import serialize_credential_contents
from didv2.did.jsoncanonicalizer import transform
from didv2.hexutil import with_0x
from didv2.signer import DefaultProvider


class JSONCredential:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    @classmethod
    def create(cls, vcc: dict[str, Any]) -> JSONCredential:
        return cls(serialize_credential_contents(vcc))

    @classmethod
    def parse(cls, raw: str | bytes) -> JSONCredential:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not raw:
            raise ValueError("JSON string is empty")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("invalid JSON format")
        return cls(data)

    def add_proof(self, signer: DefaultProvider, verification_method: str, purpose: str = "assertionMethod") -> None:
        body = {k: v for k, v in self.data.items() if k != "proof"}
        digest = sha256(transform(body)).digest()
        sig = signer.sign(digest)
        self.data["proof"] = {
            "type": "EcdsaSecp256k1Signature2019",
            "verificationMethod": verification_method,
            "proofPurpose": purpose,
            "proofValue": with_0x(sig[:64]),
        }

    def serialize(self) -> str:
        return json.dumps(self.data, separators=(",", ":"), ensure_ascii=True)
