from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from didv2.config import DEFAULT_CHAIN_ID, DEFAULT_DID_SMC_ADDRESS, DEFAULT_METHOD, DEFAULT_RPC
from didv2.did.did import (  # noqa: F401  (re-exported for callers of the old location)
    DID_TYPE_ACTIVITY,
    DID_TYPE_ITEM,
    DID_TYPE_LOCATION,
    DID_TYPE_PEOPLE,
    SECP256K1_VM_TYPE,
    did_type_string,
    new_secp256k1_vm,
    to_did,
)
from didv2.signer import DefaultProvider


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
    sync_epoch: bool = False
    sync_nonce: bool = False
    extra_vms: list[Any] = field(default_factory=list)
    enable_p256_vm: bool = False


class DIDGenerator:
    """Thin facade kept for backwards compatibility; see didv2.did_generator.DIDGenerator."""

    def __init__(self, cfg: DIDConfig | None = None) -> None:
        from didv2.did_generator import DIDGenerator as Impl

        self._impl = Impl(cfg or DIDConfig())

    def __getattr__(self, name: str) -> Any:
        return getattr(self._impl, name)

    def generate_did_tx(self, did_type: int, public_key_hex: str, hash_: str = "", metadata: dict | None = None):
        return self._impl.generate_did_tx(did_type, public_key_hex, hash_, metadata)
