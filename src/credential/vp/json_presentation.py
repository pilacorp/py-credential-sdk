from __future__ import annotations

import json
from typing import Any

from credential.common.jsonmap import add_ecdsa_rdfc_proof
from credential.common.signer.p256 import P256Provider


class JSONPresentation:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    @classmethod
    def create(cls, vpc: dict[str, Any]) -> JSONPresentation:
        if not vpc.get("type"):
            vpc = {**vpc, "type": ["VerifiablePresentation"]}
        if not vpc.get("@context"):
            vpc = {**vpc, "@context": ["https://www.w3.org/ns/credentials/v2"]}
        return cls(dict(vpc))

    @classmethod
    def parse(cls, raw: str | bytes) -> JSONPresentation:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not raw:
            raise ValueError("JSON string is empty")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("invalid JSON format")
        return cls(data)

    def add_proof_by_provider(
        self,
        signer: P256Provider,
        verification_method: str,
        purpose: str = "authentication",
    ) -> None:
        add_ecdsa_rdfc_proof(self.data, signer, verification_method, purpose)

    def serialize(self) -> str:
        return json.dumps(self.data, separators=(",", ":"), ensure_ascii=True)
