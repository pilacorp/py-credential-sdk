from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eth_utils import is_address

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
        if not is_address(self.contract_address):
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
