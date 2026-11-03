from __future__ import annotations

from typing import Any

from did.blockchain.helper import parse_private_key
from did.blockchain.smartcontract import EthereumDIDRegistry
from did.config.config import Config, new_config
from did.helper import generate_did_document, generate_ecdsa_did
from did.model import CreateDID, DID, Secret, SubmitDIDTX
from didv2.hexutil import with_0x


class DIDGenerator:
    def __init__(self, config: Config | None = None) -> None:
        self.config = new_config(config or Config())

    def generate_did(self, new_did: CreateDID, *, nonce: int = 0) -> DID:
        key_pair = generate_ecdsa_did(self.config.method)
        doc = generate_did_document(
            key_pair,
            new_did.type,
            new_did.hash,
            new_did.metadata,
            key_pair.identifier,
        )
        registry = EthereumDIDRegistry(
            self.config.rpc, self.config.did_address, self.config.chain_id
        )
        tx = registry.generate_set_attribute_tx(
            key_pair.private_key,
            key_pair.address,
            str(new_did.type.value if hasattr(new_did.type, "value") else new_did.type),
            nonce=nonce,
        )
        return DID(
            did=key_pair.identifier,
            secret=Secret(private_key_hex=key_pair.private_key),
            document=doc,
            transaction=SubmitDIDTX(tx_hex=tx.tx_hex, tx_hash=tx.tx_hash),
        )

    def regenerate_did_tx(
        self,
        priv_key: str,
        did_metadata: dict[str, Any],
        *,
        nonce: int = 0,
    ) -> SubmitDIDTX:
        private_key = parse_private_key(priv_key)
        address = with_0x(bytes(private_key.public_key.to_canonical_address())).lower()
        did_type = did_metadata.get("type")
        if not did_type:
            raise ValueError("did type is required")
        registry = EthereumDIDRegistry(
            self.config.rpc, self.config.did_address, self.config.chain_id
        )
        tx = registry.generate_set_attribute_tx(
            priv_key, address, str(did_type), nonce=nonce
        )
        return SubmitDIDTX(tx_hex=tx.tx_hex, tx_hash=tx.tx_hash)
