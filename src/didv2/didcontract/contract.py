from __future__ import annotations

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from didv2.config import DEFAULT_CHAIN_ID, DEFAULT_DID_SMC_ADDRESS
from didv2.signer import DefaultProvider
from didv2.hexutil import hex_to_bytes, with_0x

CREATE_DID_SELECTOR = keccak(text="createDID(address,uint8,bytes32,bytes32,uint8,bytes32,bytes32)")[:4]
SET_HASH_SELECTOR = keccak(text="setDocumentHash(address,bytes32,bytes32,uint8,bytes32,bytes32)")[:4]
SET_HASH_ISSUER_SELECTOR = keccak(text="setDocumentHashByIssuer(address,bytes32)")[:4]
HAS_ROLE_SELECTOR = keccak(text="hasRole(bytes32,address)")[:4]
WRITER_ANCHOR_TOPIC0 = keccak(
    text="BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])"
)
SUBTREE_WRITER_ROLE = keccak(text="SUBTREE_WRITER_ROLE")


def create_did_tx(
    issuer_address: str,
    issuer_sig: dict[str, int],
    doc_hash: str,
    cap_id: str,
    did_type: int,
    nonce: int,
    signer: DefaultProvider,
    contract_address: str = DEFAULT_DID_SMC_ADDRESS,
    chain_id: int = DEFAULT_CHAIN_ID,
) -> dict[str, str]:
    data = CREATE_DID_SELECTOR + encode(
        ["address", "uint8", "bytes32", "bytes32", "uint8", "bytes32", "bytes32"],
        [
            issuer_address,
            did_type,
            hex_to_bytes(doc_hash),
            hex_to_bytes(cap_id),
            issuer_sig["v"],
            issuer_sig["r"].to_bytes(32, "big"),
            issuer_sig["s"].to_bytes(32, "big"),
        ],
    )
    signed = Account.sign_transaction(
        {
            "nonce": nonce,
            "gasPrice": 0,
            "gas": 200000,
            "to": to_checksum_address(contract_address),
            "value": 0,
            "data": data,
            "chainId": chain_id,
        },
        signer.private_key_hex(),
    )
    raw = signed.raw_transaction.hex()
    if raw.startswith("0x"):
        raw = raw[2:]
    return {"txHex": raw, "txHash": with_0x(signed.hash)}


def writer_anchor_topic0() -> str:
    return with_0x(WRITER_ANCHOR_TOPIC0)


def subtree_writer_role() -> str:
    return with_0x(SUBTREE_WRITER_ROLE)


def has_role_selector() -> str:
    return with_0x(HAS_ROLE_SELECTOR)
