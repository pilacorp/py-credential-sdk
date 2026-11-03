from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from didv2.did.jsoncanonicalizer import transform
from didv2.keccak import keccak256_hex

DID_TYPE_PEOPLE = 0
DID_TYPE_ITEM = 1
DID_TYPE_LOCATION = 2
DID_TYPE_ACTIVITY = 3

SECP256K1_VM_TYPE = "EcdsaSecp256k1VerificationKey2019"


@dataclass
class VerificationMethod:
    id: str
    type: str
    controller: str
    public_key_hex: str = ""
    public_key_jwk: dict[str, Any] | None = None
    public_key_multibase: str = ""
    revoked: datetime | None = None
    revocation_reason: str = ""


@dataclass
class DIDDocument:
    context: list[str] = field(default_factory=list)
    id: str = ""
    controller: str = ""
    verification_method: list[VerificationMethod] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    assertion_method: list[str] = field(default_factory=list)
    document_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "@context": self.context,
            "id": self.id,
            "controller": self.controller,
            "verificationMethod": [_vm_to_dict(vm) for vm in self.verification_method],
            "authentication": self.authentication,
            "assertionMethod": self.assertion_method,
            "didDocumentMetadata": self.document_metadata,
        }
        return out

    def hash(self) -> str:
        if not self.id:
            raise ValueError("DID document is nil")
        raw = json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return keccak256_hex(transform(raw)).lower()


def _vm_to_dict(vm: VerificationMethod) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": vm.id,
        "type": vm.type,
        "controller": vm.controller,
    }
    if vm.public_key_hex:
        out["publicKeyHex"] = vm.public_key_hex
    if vm.public_key_jwk:
        out["publicKeyJwk"] = vm.public_key_jwk
    if vm.public_key_multibase:
        out["publicKeyMultibase"] = vm.public_key_multibase
    if vm.revoked is not None:
        out["revoked"] = vm.revoked.isoformat().replace("+00:00", "Z")
    if vm.revocation_reason:
        out["revocationReason"] = vm.revocation_reason
    return out


def did_type_string(did_type: int) -> str:
    return {
        DID_TYPE_PEOPLE: "people",
        DID_TYPE_ITEM: "item",
        DID_TYPE_LOCATION: "location",
        DID_TYPE_ACTIVITY: "activity",
    }.get(did_type, "unknown")
