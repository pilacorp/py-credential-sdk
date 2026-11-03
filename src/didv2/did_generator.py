from __future__ import annotations

from typing import Any

from didv2.config import DEFAULT_DID_SMC_ADDRESS
from didv2.didcontract import create_did_tx
from didv2.did.did import generate_did_document, hash_did_document
from didv2.ethereum import address_from_public_key_hex
from didv2.issuer import generate_cap_id, generate_issue_did_signature
from didv2.model import DIDConfig, to_did


class DIDGenerator:
    def __init__(self, cfg: DIDConfig) -> None:
        self.cfg = cfg

    def generate_did_tx(
        self,
        did_type: int,
        public_key_hex: str,
        hash_: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.cfg.issuer_signer:
            raise ValueError("issuer signer is required")
        if not self.cfg.did_signer:
            raise ValueError("did signer is required")
        cap_id = self.cfg.cap_id or generate_cap_id()
        issuer_addr = self.cfg.issuer_signer.get_address()
        did_addr = address_from_public_key_hex(public_key_hex)
        sig = generate_issue_did_signature(
            self.cfg.did_smc_addr or DEFAULT_DID_SMC_ADDRESS,
            issuer_addr,
            did_addr,
            did_type,
            self.cfg.epoch,
            cap_id,
            self.cfg.issuer_signer,
        )
        did_id = to_did(self.cfg.method, did_addr)
        issuer_did = to_did(self.cfg.method, issuer_addr)
        doc = generate_did_document(public_key_hex, did_id, hash_, issuer_did, did_type, metadata)
        doc_hash = hash_did_document(doc)
        tx = create_did_tx(
            issuer_addr,
            sig,
            doc_hash,
            cap_id,
            did_type,
            self.cfg.nonce,
            self.cfg.did_signer,
            self.cfg.did_smc_addr,
            self.cfg.chain_id,
        )
        return {"did": did_id, "document": doc, "transaction": tx, "capId": cap_id}
