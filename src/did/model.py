from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DIDType(str, Enum):
    ITEM = "item"
    PEOPLE = "people"
    LOCATION = "location"
    ACTIVITY = "activity"


@dataclass
class KeyPair:
    address: str
    public_key: str
    private_key: str
    identifier: str


@dataclass
class CreateDID:
    type: DIDType
    metadata: dict[str, Any] = field(default_factory=dict)
    hash: str = ""


@dataclass
class VerificationMethod:
    id: str
    type: str
    controller: str
    public_key_hex: str = ""


@dataclass
class DIDDocument:
    context: list[str]
    id: str
    controller: str
    verification_method: list[VerificationMethod]
    authentication: list[str]
    assertion_method: list[str]
    document_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "@context": self.context,
            "id": self.id,
            "controller": self.controller,
            "verificationMethod": [
                {
                    "id": vm.id,
                    "type": vm.type,
                    "controller": vm.controller,
                    **({"publicKeyHex": vm.public_key_hex} if vm.public_key_hex else {}),
                }
                for vm in self.verification_method
            ],
            "authentication": self.authentication,
            "assertionMethod": self.assertion_method,
            "didDocumentMetadata": self.document_metadata,
        }


@dataclass
class Secret:
    private_key_hex: str


@dataclass
class SubmitDIDTX:
    tx_hex: str
    tx_hash: str


@dataclass
class DID:
    did: str
    secret: Secret
    document: DIDDocument
    transaction: SubmitDIDTX


def to_blockchain_type(did_type: str) -> DIDType:
    return DIDType(did_type)
