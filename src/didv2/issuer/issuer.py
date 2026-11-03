from __future__ import annotations

import os
from eth_abi.packed import encode_packed
from eth_utils import is_address, to_canonical_address

from didv2.signer import DefaultProvider
from didv2.hexutil import with_0x
from didv2.keccak import keccak256

CAP_CREATE_ACTION = "CAP_CREATE"
CAP_ID_LENGTH = 32


def generate_cap_id() -> str:
    return with_0x(os.urandom(CAP_ID_LENGTH))


def build_issue_did_payload(
    contract_address: str,
    issuer_address: str,
    did_address: str,
    did_type: int,
    epoch: int,
    cap_id: str,
) -> bytes:
    if not is_address(contract_address):
        raise ValueError(f"invalid contract address: {contract_address}")
    if not is_address(issuer_address):
        raise ValueError(f"invalid issuer address: {issuer_address}")
    if not is_address(did_address):
        raise ValueError(f"invalid did address: {did_address}")
    if len(cap_id) != 66:
        raise ValueError(f"invalid cap id length: expected {CAP_ID_LENGTH}, got {len(cap_id)}")
    packed = encode_packed(
        ["string", "address", "address", "uint8", "uint64", "bytes32"],
        [
            CAP_CREATE_ACTION,
            issuer_address,
            did_address,
            did_type,
            epoch,
            bytes.fromhex(cap_id[2:] if cap_id.startswith("0x") else cap_id),
        ],
    )
    return b"\x19\x00" + to_canonical_address(contract_address) + packed


def generate_issue_did_signature(
    contract_address: str,
    issuer_address: str,
    did_address: str,
    did_type: int,
    epoch: int,
    cap_id: str,
    issuer_signer: DefaultProvider,
) -> dict[str, int]:
    payload = build_issue_did_payload(contract_address, issuer_address, did_address, did_type, epoch, cap_id)
    digest = keccak256(payload)
    sig = issuer_signer.sign(digest)
    v = sig[64]
    if v < 27:
        v += 27
    return {
        "r": int.from_bytes(sig[:32], "big"),
        "s": int.from_bytes(sig[32:64], "big"),
        "v": v,
    }
