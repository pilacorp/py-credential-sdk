from __future__ import annotations

import re
from dataclasses import dataclass, field

from didv2.hexutil import is_hex_address

HASH32_HEX_LEN = 64
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2})*$")


def validate_hash32(value: str) -> None:
    """32 bytes of hex with an optional lowercase "0x" prefix (length only, as Go validateHash32)."""
    trimmed = value.removeprefix("0x")
    if len(trimmed) != HASH32_HEX_LEN:
        raise ValueError(f"expected {HASH32_HEX_LEN} hex chars (32 bytes), got {len(trimmed)}")


def hex_to_bytes32(value: str) -> bytes:
    """Go hexToBytes32: strict hex (no whitespace, no 0X), exactly 32 bytes."""
    trimmed = value.removeprefix("0x")
    if not _HEX.match(trimmed):
        raise ValueError("invalid hex")
    raw = bytes.fromhex(trimmed)
    if len(raw) != 32:
        raise ValueError(f"length must be 32 bytes, got {len(raw)}")
    return raw


def validate_proof_fields(issuer_address: str, leaf: str, proof: list[str]) -> None:
    if not is_hex_address(issuer_address):
        raise ValueError(f"invalid issuer address: {issuer_address!r}")
    try:
        validate_hash32(leaf)
    except ValueError as exc:
        raise ValueError(f"invalid leaf: {exc}") from exc
    for i, item in enumerate(proof):
        try:
            validate_hash32(item)
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
    """Merkle proof plus the tx that anchored the root.  ``tree_index`` is deprecated and ignored.
    Derive ``issuer_address`` and ``leaf`` from the credential itself, never from the proof bundle."""

    issuer_address: str
    leaf: str
    proof: list[str]
    tx_hash: str
    tree_index: int = 0
    contract_address: str = ""

    def validate(self) -> None:
        validate_proof_fields(self.issuer_address, self.leaf, self.proof)
        try:
            validate_hash32(self.tx_hash)
        except ValueError as exc:
            raise ValueError(f"invalid tx hash: {exc}") from exc
        if self.contract_address and not is_hex_address(self.contract_address):
            raise ValueError(f"invalid contract address: {self.contract_address!r}")
