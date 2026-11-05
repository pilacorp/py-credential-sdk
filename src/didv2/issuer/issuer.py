from __future__ import annotations

import os

from eth_abi.packed import encode_packed

from didv2.hexutil import address_bytes, is_hex_address, with_0x
from didv2.keccak import keccak256
from didv2.signer import SignerProvider

CAP_CREATE_ACTION = "CAP_CREATE"
CAP_ID_LENGTH = 32
DEFAULT_EPOCH = 0


def generate_cap_id() -> str:
    return with_0x(os.urandom(CAP_ID_LENGTH))


def validate_issue_did_payload(contract_address: str, issuer_address: str, did_address: str, cap_id: str) -> None:
    if not is_hex_address(contract_address):
        raise ValueError(f"invalid contract address: {contract_address}")
    if not is_hex_address(issuer_address):
        raise ValueError(f"invalid issuer address: {issuer_address}")
    if not is_hex_address(did_address):
        raise ValueError(f"invalid did address: {did_address}")
    if len(cap_id) != CAP_ID_LENGTH * 2 + 2:  # +2 for "0x"
        raise ValueError(f"invalid cap id length: expected {CAP_ID_LENGTH}, got {len(cap_id)}")


def build_issue_did_payload(
    contract_address: str,
    issuer_address: str,
    did_address: str,
    did_type: int,
    epoch: int,
    cap_id: str,
) -> bytes:
    """0x19 0x00 | contract | abi.encodePacked("CAP_CREATE", issuer, did, uint8 type, uint64 epoch, bytes32 capId)."""
    validate_issue_did_payload(contract_address, issuer_address, did_address, cap_id)
    cap = cap_id[2:] if cap_id.startswith("0x") else cap_id
    try:
        cap_raw = bytes.fromhex(cap)
    except ValueError as exc:
        raise ValueError(f"failed to encode payload to issue DID payload: invalid bytes32 {cap_id}: {exc}") from exc
    if len(cap_raw) != 32:
        raise ValueError(
            f"failed to encode payload to issue DID payload: bytes32 must be 32 bytes, got {len(cap_raw)}"
        )
    packed = encode_packed(
        ["string", "address", "address", "uint8", "uint64", "bytes32"],
        [
            CAP_CREATE_ACTION,
            "0x" + address_bytes(issuer_address).hex(),
            "0x" + address_bytes(did_address).hex(),
            did_type,
            epoch,
            cap_raw,
        ],
    )
    return b"\x19\x00" + address_bytes(contract_address) + packed


def signature_from_bytes(sig: bytes) -> dict[str, int]:
    """Parse r||s||v and normalise v from the 0/1 recovery id to 27/28."""
    if len(sig) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(sig)}")
    v = sig[64]
    if v < 27:
        v += 27
    return {"r": int.from_bytes(sig[:32], "big"), "s": int.from_bytes(sig[32:64], "big"), "v": v}


def sign_payload(payload: bytes, issuer_signer: SignerProvider) -> dict[str, int]:
    try:
        return signature_from_bytes(issuer_signer.sign(payload))
    except ValueError as exc:
        raise ValueError(f"invalid signature format: {exc}") from exc


def generate_issue_did_signature(
    contract_address: str,
    issuer_address: str,
    did_address: str,
    did_type: int,
    epoch: int,
    cap_id: str,
    issuer_signer: SignerProvider | None,
) -> dict[str, int]:
    if issuer_signer is None:
        raise ValueError("issuer signer is required")
    payload = build_issue_did_payload(contract_address, issuer_address, did_address, did_type, epoch, cap_id)
    return sign_payload(keccak256(payload), issuer_signer)
