"""DID issuance workflow (port of Go didv2/did_generator.go).  Never submits; blockchain reads
(epoch/nonce sync) go through an injectable ``DIDChain``."""

from __future__ import annotations

import dataclasses
from typing import Any

from didv2.didcontract import (
    Config,
    create_did_tx,
    set_document_hash_by_issuer_tx,
    set_document_hash_tx,
)
from didv2.did.did import (
    generate_dual_curve_key_pair,
    generate_did_document,
    hash_did_document,
    new_p256_multikey_vm,
    new_spec,
    validate_did_document,
)
from didv2.ethereum import address_from_public_key_hex
from didv2.issuer import generate_cap_id, generate_issue_did_signature
from didv2.model import DIDConfig, to_did
from didv2.signer import DefaultProvider


class DIDGenerator:
    def __init__(self, cfg: DIDConfig | None = None, *, chain: Any = None, **overrides: Any) -> None:
        cfg = dataclasses.replace(cfg or DIDConfig(), **overrides)
        # Go NewContract validates the contract address and chain id up front
        Config(rpc_url=cfg.rpc, contract_address=cfg.did_smc_addr, chain_id=cfg.chain_id).validate()
        self.cfg = cfg
        self._chain = chain

    # ------------------------------------------------------------------ config / chain

    def _resolve(self, overrides: dict[str, Any]) -> DIDConfig:
        ov = dict(overrides)
        # Go WithVerificationMethods appends to the base list; ``extra_vms=`` replaces it (WithDIDConfig)
        extra = list(ov.pop("extra_vms", self.cfg.extra_vms)) + list(ov.pop("add_vms", []))
        cfg = dataclasses.replace(self.cfg, extra_vms=extra, **ov)
        if not cfg.cap_id:
            cfg.cap_id = generate_cap_id()
        return cfg

    def _get_chain(self, cfg: DIDConfig) -> Any:
        if self._chain is None:
            from didv2.rpc import DIDChain

            self._chain = DIDChain(cfg.rpc, cfg.did_smc_addr)
        return self._chain

    # ------------------------------------------------------------------ workflows

    def generate_did(
        self,
        did_type: int,
        hash_: str = "",
        metadata: dict[str, Any] | None = None,
        **overrides: Any,
    ) -> dict[str, Any]:
        """New dual-curve key pair -> full issuance.  The private key is returned under ``secret``."""
        cfg = self._resolve(overrides)
        key_pair = generate_dual_curve_key_pair()
        did_signer = DefaultProvider(key_pair.get_private_key_hex())
        overrides = {**overrides, "did_signer": did_signer, "cap_id": cfg.cap_id}
        if cfg.enable_p256_vm:
            did_addr = address_from_public_key_hex(key_pair.get_public_key_hex())
            vm = new_p256_multikey_vm(to_did(cfg.method, did_addr), "#key-2", key_pair.p256_public_key)
            overrides["extra_vms"] = [*cfg.extra_vms, new_spec(vm)]
        res = self.generate_did_tx(did_type, key_pair.get_public_key_hex(), hash_, metadata, **overrides)
        res["secret"] = {"privateKeyHex": key_pair.get_private_key_hex()}
        return res

    def generate_did_tx(
        self,
        did_type: int,
        public_key_hex: str,
        hash_: str = "",
        metadata: dict[str, Any] | None = None,
        **overrides: Any,
    ) -> dict[str, Any]:
        cfg = self._resolve(overrides)
        if cfg.issuer_signer is None:
            raise ValueError("issuer signer is required")
        issuer_addr = cfg.issuer_signer.get_address()
        try:
            did_addr = address_from_public_key_hex(public_key_hex)
        except ValueError as exc:
            raise ValueError(f"failed to convert public key hex to address: {exc}") from exc
        sig = self.generate_issuer_signature(did_type, did_addr, issuer_addr, **_carry(cfg))
        issuer_did = to_did(cfg.method, issuer_addr)
        did_id = to_did(cfg.method, did_addr)
        doc = generate_did_document(public_key_hex, did_id, hash_, issuer_did, did_type, metadata, cfg.extra_vms)
        try:
            validate_did_document(doc)
        except ValueError as exc:
            raise ValueError(f"invalid DID document: {exc}") from exc
        doc_hash = hash_did_document(doc)
        tx = self.generate_did_create_transaction(
            did_type, doc_hash, did_addr, issuer_addr, sig, **_carry(cfg)
        )
        return {"did": did_id, "document": doc, "transaction": tx, "capId": cfg.cap_id}

    def generate_issuer_signature(
        self, did_type: int, did_addr: str, issuer_addr: str, **overrides: Any
    ) -> dict[str, int]:
        cfg = self._resolve(overrides)
        if cfg.sync_epoch:
            try:
                cfg.epoch = self._get_chain(cfg).get_capability_epoch(issuer_addr)
            except Exception as exc:
                raise ValueError(f"failed to get capability epoch: {exc}") from exc
        # Go signs for the generator's base contract address, not a per-call override
        return generate_issue_did_signature(
            self.cfg.did_smc_addr, issuer_addr, did_addr, did_type, cfg.epoch, cfg.cap_id, cfg.issuer_signer
        )

    def generate_did_create_transaction(
        self,
        did_type: int,
        doc_hash: str,
        did_addr: str,
        issuer_addr: str,
        issuer_sig: dict[str, int],
        **overrides: Any,
    ):
        cfg = self._resolve(overrides)
        if cfg.sync_nonce:
            cfg.nonce = self._sync_nonce(cfg, did_addr)
        return create_did_tx(
            issuer_addr, issuer_sig, doc_hash, cfg.cap_id, did_type, cfg.nonce, cfg.did_signer,
            cfg.did_smc_addr, cfg.chain_id,
        )

    def generate_set_document_hash_transaction(
        self, doc_hash: str, did_addr: str, issuer_sig: dict[str, int] | None, **overrides: Any
    ):
        cfg = self._resolve(overrides)
        if cfg.did_signer is None:
            raise ValueError("did signer is required")
        if issuer_sig is None:
            raise ValueError("issuer signature is required")
        if cfg.sync_nonce:
            cfg.nonce = self._sync_nonce(cfg, did_addr)
        return set_document_hash_tx(
            did_addr, doc_hash, cfg.cap_id, issuer_sig, cfg.nonce, cfg.did_signer, cfg.did_smc_addr, cfg.chain_id
        )

    def generate_set_document_hash_by_issuer_transaction(self, doc_hash: str, did_addr: str, **overrides: Any):
        cfg = self._resolve(overrides)
        if cfg.issuer_signer is None:
            raise ValueError("issuer signer is required")
        if cfg.sync_nonce:
            cfg.nonce = self._sync_nonce(cfg, cfg.issuer_signer.get_address())
        return set_document_hash_by_issuer_tx(
            did_addr, doc_hash, cfg.nonce, cfg.issuer_signer, cfg.did_smc_addr, cfg.chain_id
        )

    def _sync_nonce(self, cfg: DIDConfig, address: str) -> int:
        try:
            return self._get_chain(cfg).get_nonce(address)
        except Exception as exc:
            raise ValueError(f"failed to get nonce: {exc}") from exc


def _carry(cfg: DIDConfig) -> dict[str, Any]:
    """Options handed down to the sub-steps (Go: WithDIDConfig(cfg)); the resolved cap id is kept."""
    return {f.name: getattr(cfg, f.name) for f in dataclasses.fields(cfg)}
