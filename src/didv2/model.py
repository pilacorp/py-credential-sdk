from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from didv2.did.verification_method_ops import canonical_vm_id
from didv2.config import DEFAULT_CHAIN_ID, DEFAULT_DID_SMC_ADDRESS, DEFAULT_METHOD, DEFAULT_RPC
from didv2.signer import DefaultProvider

DID_TYPE_PEOPLE = 0
DID_TYPE_ITEM = 1
DID_TYPE_LOCATION = 2
DID_TYPE_ACTIVITY = 3

SECP256K1_VM_TYPE = "EcdsaSecp256k1VerificationKey2019"


def did_type_string(did_type: int) -> str:
    return {0: "people", 1: "item", 2: "location", 3: "activity"}.get(did_type, "unknown")


def to_did(method: str, address: str) -> str:
    return f"{method}:{address}".lower()


def new_secp256k1_vm(did: str, fragment: str, public_key_hex: str) -> dict[str, Any]:
    return {
        "id": canonical_vm_id(did, fragment),
        "type": SECP256K1_VM_TYPE,
        "controller": did,
        "publicKeyHex": public_key_hex,
    }


@dataclass
class DIDConfig:
    rpc: str = DEFAULT_RPC
    chain_id: int = DEFAULT_CHAIN_ID
    did_smc_addr: str = DEFAULT_DID_SMC_ADDRESS
    method: str = DEFAULT_METHOD
    issuer_signer: DefaultProvider | None = None
    did_signer: DefaultProvider | None = None
    nonce: int = 0
    epoch: int = 0
    cap_id: str = ""
    extra_vms: list[dict[str, Any]] = field(default_factory=list)


class DIDGenerator:
    def __init__(self, cfg: DIDConfig | None = None) -> None:
        from didv2.did_generator import DIDGenerator as Impl

        self._impl = Impl(cfg or DIDConfig())

    def generate_did_tx(self, did_type: int, public_key_hex: str, hash_: str = "", metadata: dict | None = None):
        return self._impl.generate_did_tx(did_type, public_key_hex, hash_, metadata)
