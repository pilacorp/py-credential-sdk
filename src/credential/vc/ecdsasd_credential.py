from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from credential.common.ecdsasd.api import create_base_proof
from credential.common.jsonmap._constants import DATA_INTEGRITY_V2_CONTEXT
from credential.common.signer.p256 import P256Provider
from credential.vc.json_credential import JSONCredential


class ECDSASDCredential:
    def __init__(self, base: JSONCredential) -> None:
        self._base = base

    @classmethod
    def create(cls, vcc: dict[str, Any]) -> ECDSASDCredential:
        return cls(JSONCredential.create(vcc))

    @classmethod
    def parse(cls, raw: str | bytes) -> ECDSASDCredential:
        return cls(JSONCredential.parse(raw))

    @property
    def data(self) -> dict[str, Any]:
        return self._base.data

    def add_proof_by_provider(
        self,
        signer: P256Provider,
        verification_method: str,
        mandatory_paths: list[str] | None = None,
    ) -> None:
        doc = self._base.data
        proof_config = {
            "@context": DATA_INTEGRITY_V2_CONTEXT,
            "type": "DataIntegrityProof",
            "cryptosuite": "ecdsa-sd-2023",
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod",
        }
        proof_value = create_base_proof(doc, proof_config, mandatory_paths or [], signer)
        self._base.data["proof"] = {
            **proof_config,
            "proofValue": proof_value,
        }

    def serialize(self) -> str:
        return self._base.serialize()
