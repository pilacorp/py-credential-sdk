from __future__ import annotations

from dataclasses import dataclass, field

from eth_utils import is_address

from credential.vcanchor.hash import normalize_hash32

HASH32_HEX_LEN = 64


def validate_hash32(value: str) -> None:
    trimmed = value.strip().removeprefix("0x")
    if len(trimmed) != HASH32_HEX_LEN:
        raise ValueError(f"expected {HASH32_HEX_LEN} hex chars (32 bytes), got {len(trimmed)}")


def validate_proof_fields(issuer_address: str, leaf: str, proof: list[str]) -> None:
    if not is_address(issuer_address):
        raise ValueError(f"invalid issuer address: {issuer_address!r}")
    try:
        normalize_hash32(leaf)
    except ValueError as exc:
        raise ValueError(f"invalid leaf: {exc}") from exc
    for i, item in enumerate(proof):
        try:
            normalize_hash32(item)
        except ValueError as exc:
            raise ValueError(f"invalid proof element at index {i}: {exc}") from exc


@dataclass
class VerifyRequest:
    issuer_address: str
    tree_index: int
    leaf: str
    proof: list[str] = field(default_factory=list)

    def validate(self) -> None:
        validate_proof_fields(self.issuer_address, self.leaf, self.proof)


@dataclass
class VerifyByTxRequest:
    issuer_address: str
    leaf: str
    proof: list[str]
    tx_hash: str
    tree_index: int = 0
    contract_address: str = ""

    def validate(self) -> None:
        validate_proof_fields(self.issuer_address, self.leaf, self.proof)
        try:
            normalize_hash32(self.tx_hash)
        except ValueError as exc:
            raise ValueError(f"invalid tx hash: {exc}") from exc
        if self.contract_address and not is_address(self.contract_address):
            raise ValueError(f"invalid contract address: {self.contract_address!r}")
