from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from didv2.hexutil import is_hex_address

DEFAULT_GAS_LIMIT = 200_000
DOC_HASH_HEX_LENGTH = 64
CAP_ID_HEX_LENGTH = 64


@dataclass
class Config:
    rpc_url: str = ""
    contract_address: str = ""
    chain_id: int = 0
    gas_price: int | None = None
    gas_limit: int = 0

    def validate(self) -> None:
        if not is_hex_address(self.contract_address):
            raise ValueError("contract address is required")
        if self.chain_id <= 0:
            raise ValueError("chain ID must be greater than 0, it's required")

    def standardize(self) -> None:
        if self.gas_limit == 0:
            self.gas_limit = DEFAULT_GAS_LIMIT
        if self.gas_price is None:
            self.gas_price = 0


@dataclass
class Transaction:
    tx_hex: str
    tx_hash: str

    def __getitem__(self, key: str) -> str:  # dict-style access kept for the older {"txHex","txHash"} shape
        return {"txHex": self.tx_hex, "txHash": self.tx_hash}[key]


def _hex_body_len(value: str) -> int:
    n = len(value)
    if value.startswith("0x"):
        n -= 2
    return n


def validate_doc_hash(doc_hash: str) -> None:
    if _hex_body_len(doc_hash) != DOC_HASH_HEX_LENGTH:
        raise ValueError(
            f"invalid docHash length: expected {DOC_HASH_HEX_LENGTH} hex chars (32 bytes), got {_hex_body_len(doc_hash)}"
        )


def validate_cap_id(cap_id: str) -> None:
    if _hex_body_len(cap_id) != CAP_ID_HEX_LENGTH:
        raise ValueError(
            f"invalid capID length: expected {CAP_ID_HEX_LENGTH} hex chars (32 bytes), got {_hex_body_len(cap_id)}"
        )


def validate_issuer_sig(sig: dict[str, Any] | None) -> None:
    if sig is None:
        raise ValueError("issuer signature is required")
    for key in ("v", "r", "s"):
        if sig.get(key) is None:
            raise ValueError("issuer signature V, R, S are required")


@dataclass
class CreateDIDRequest:
    issuer_address: str
    issuer_sig: dict[str, int] | None
    doc_hash: str
    cap_id: str
    did_type: int = 0
    nonce: int = 0

    def validate(self) -> None:
        if not is_hex_address(self.issuer_address):
            raise ValueError(f"invalid issuer address: {self.issuer_address}")
        validate_issuer_sig(self.issuer_sig)
        validate_doc_hash(self.doc_hash)
        validate_cap_id(self.cap_id)


@dataclass
class SetDocumentHashRequest:
    did_address: str
    doc_hash: str
    cap_id: str
    issuer_sig: dict[str, int] | None
    nonce: int = 0

    def validate(self) -> None:
        if not is_hex_address(self.did_address):
            raise ValueError(f"invalid did address: {self.did_address}")
        if self.issuer_sig is None or any(self.issuer_sig.get(k) is None for k in ("v", "r", "s")):
            raise ValueError("issuer signature V, R, S are required")
        validate_doc_hash(self.doc_hash)
        validate_cap_id(self.cap_id)


@dataclass
class SetDocumentHashByIssuerRequest:
    did_address: str
    doc_hash: str
    nonce: int = 0

    def validate(self) -> None:
        if not is_hex_address(self.did_address):
            raise ValueError(f"invalid did address: {self.did_address}")
        validate_doc_hash(self.doc_hash)
