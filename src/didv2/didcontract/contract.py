"""Raw transaction builders for the DID Registry (port of Go didcontract/contract.go).

The SDK never submits: it ABI-encodes the call, signs the EIP-155 legacy transaction through a
``SignerProvider`` (so HSM / remote signers work) and returns the RLP hex + hash.
"""

from __future__ import annotations

import re

from eth_abi import encode
from eth_utils import keccak

from didv2.config import DEFAULT_CHAIN_ID, DEFAULT_DID_SMC_ADDRESS
from didv2.didcontract.model import (
    DEFAULT_GAS_LIMIT,
    Config,
    CreateDIDRequest,
    SetDocumentHashByIssuerRequest,
    SetDocumentHashRequest,
    Transaction,
)
from didv2.hexutil import address_bytes, with_0x
from didv2.keccak import keccak256
from didv2.signer import SignerProvider

CREATE_DID_SELECTOR = keccak(text="createDID(address,uint8,bytes32,bytes32,uint8,bytes32,bytes32)")[:4]
SET_HASH_SELECTOR = keccak(text="setDocumentHash(address,bytes32,bytes32,uint8,bytes32,bytes32)")[:4]
SET_HASH_ISSUER_SELECTOR = keccak(text="setDocumentHashByIssuer(address,bytes32)")[:4]
HAS_ROLE_SELECTOR = keccak(text="hasRole(bytes32,address)")[:4]
WRITER_ANCHOR_TOPIC0 = keccak(
    text="BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])"
)
SUBTREE_WRITER_ROLE = keccak(text="SUBTREE_WRITER_ROLE")


# --------------------------------------------------------------------------- minimal RLP


def _rlp_int(n: int) -> bytes:
    return b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def _rlp(item: int | bytes | list) -> bytes:
    if isinstance(item, int):
        item = _rlp_int(item)
    if isinstance(item, list):
        payload = b"".join(_rlp(i) for i in item)
        return _rlp_len(len(payload), 0xC0) + payload
    if len(item) == 1 and item[0] < 0x80:
        return item
    return _rlp_len(len(item), 0x80) + item


def _rlp_len(n: int, offset: int) -> bytes:
    if n < 56:
        return bytes([offset + n])
    b = _rlp_int(n)
    return bytes([offset + 55 + len(b)]) + b


def sign_legacy_tx(
    signer: SignerProvider,
    *,
    nonce: int,
    to: str,
    data: bytes,
    chain_id: int,
    gas_limit: int = DEFAULT_GAS_LIMIT,
    gas_price: int = 0,
    value: int = 0,
) -> Transaction:
    """EIP-155 legacy transaction signed through ``signer`` (RLP hex without 0x + keccak hash)."""
    if nonce < 0:
        raise ValueError("nonce must not be negative")
    to_raw = address_bytes(to)
    body = [nonce, gas_price, gas_limit, to_raw, value, data]
    sig = signer.sign(keccak256(_rlp(body + [chain_id, 0, 0])))
    if len(sig) != 65:
        raise ValueError("wrong size for signature: got %d, want 65" % len(sig))
    v = sig[64] + 35 + 2 * chain_id
    raw = _rlp(body + [v, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")])
    return Transaction(tx_hex=raw.hex(), tx_hash=with_0x(keccak256(raw)))


_HEXRE = re.compile(r"^(?:[0-9a-fA-F]{2})*$")


def _hex_to_bytes32(s: str, what: str) -> bytes:
    h = s[2:] if s.startswith("0x") else s
    if not _HEXRE.match(h):
        raise ValueError(f"invalid {what}: invalid hex")
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise ValueError(f"invalid {what}: length must be 32 bytes, got {len(b)}")
    return b


def _sig_parts(sig: dict[str, int]) -> tuple[int, bytes, bytes]:
    v, r, s = sig["v"], sig["r"], sig["s"]
    if not (0 <= v <= 0xFF):
        raise ValueError("issuer signature v does not fit uint8")
    if not (0 <= r < 1 << 256 and 0 <= s < 1 << 256):
        raise ValueError("issuer signature r/s do not fit 32 bytes")
    return v, r.to_bytes(32, "big"), s.to_bytes(32, "big")


def _config(contract_address: str, chain_id: int, gas_limit: int, gas_price: int | None) -> Config:
    cfg = Config(contract_address=contract_address, chain_id=chain_id, gas_limit=gas_limit, gas_price=gas_price)
    cfg.validate()
    cfg.standardize()
    return cfg


def _send(signer: SignerProvider, cfg: Config, nonce: int, data: bytes) -> Transaction:
    return sign_legacy_tx(
        signer,
        nonce=nonce,
        to=cfg.contract_address,
        data=data,
        chain_id=cfg.chain_id,
        gas_limit=cfg.gas_limit,
        gas_price=cfg.gas_price or 0,
    )


def create_did_tx(
    issuer_address: str,
    issuer_sig: dict[str, int] | None,
    doc_hash: str,
    cap_id: str,
    did_type: int,
    nonce: int,
    signer: SignerProvider | None,
    contract_address: str = DEFAULT_DID_SMC_ADDRESS,
    chain_id: int = DEFAULT_CHAIN_ID,
    *,
    gas_limit: int = 0,
    gas_price: int | None = None,
) -> Transaction:
    """createDID(address,uint8,bytes32,bytes32,uint8,bytes32,bytes32)."""
    if signer is None:
        raise ValueError("tx signer is required")
    req = CreateDIDRequest(issuer_address, issuer_sig, doc_hash, cap_id, did_type, nonce)
    try:
        req.validate()
    except ValueError as exc:
        raise ValueError(f"invalid request: {exc}") from exc
    cfg = _config(contract_address, chain_id, gas_limit, gas_price)
    doc = _hex_to_bytes32(doc_hash, "docHash")
    cap = _hex_to_bytes32(cap_id, "capId")
    v, r, s = _sig_parts(issuer_sig)  # type: ignore[arg-type]
    data = CREATE_DID_SELECTOR + encode(
        ["address", "uint8", "bytes32", "bytes32", "uint8", "bytes32", "bytes32"],
        ["0x" + address_bytes(issuer_address).hex(), did_type, doc, cap, v, r, s],
    )
    return _send(signer, cfg, nonce, data)


def set_document_hash_tx(
    did_address: str,
    doc_hash: str,
    cap_id: str,
    issuer_sig: dict[str, int] | None,
    nonce: int,
    signer: SignerProvider | None,
    contract_address: str = DEFAULT_DID_SMC_ADDRESS,
    chain_id: int = DEFAULT_CHAIN_ID,
    *,
    gas_limit: int = 0,
    gas_price: int | None = None,
) -> Transaction:
    """setDocumentHash(address,bytes32,bytes32,uint8,bytes32,bytes32), signed by the DID."""
    if signer is None:
        raise ValueError("tx signer is required")
    try:
        SetDocumentHashRequest(did_address, doc_hash, cap_id, issuer_sig, nonce).validate()
    except ValueError as exc:
        raise ValueError(f"invalid request: {exc}") from exc
    cfg = _config(contract_address, chain_id, gas_limit, gas_price)
    doc = _hex_to_bytes32(doc_hash, "docHash")
    cap = _hex_to_bytes32(cap_id, "capId")
    v, r, s = _sig_parts(issuer_sig)  # type: ignore[arg-type]
    data = SET_HASH_SELECTOR + encode(
        ["address", "bytes32", "bytes32", "uint8", "bytes32", "bytes32"],
        ["0x" + address_bytes(did_address).hex(), doc, cap, v, r, s],
    )
    return _send(signer, cfg, nonce, data)


def set_document_hash_by_issuer_tx(
    did_address: str,
    doc_hash: str,
    nonce: int,
    signer: SignerProvider | None,
    contract_address: str = DEFAULT_DID_SMC_ADDRESS,
    chain_id: int = DEFAULT_CHAIN_ID,
    *,
    gas_limit: int = 0,
    gas_price: int | None = None,
) -> Transaction:
    """setDocumentHashByIssuer(address,bytes32), signed by the issuer."""
    if signer is None:
        raise ValueError("tx signer is required")
    try:
        SetDocumentHashByIssuerRequest(did_address, doc_hash, nonce).validate()
    except ValueError as exc:
        raise ValueError(f"invalid request: {exc}") from exc
    cfg = _config(contract_address, chain_id, gas_limit, gas_price)
    doc = _hex_to_bytes32(doc_hash, "docHash")
    data = SET_HASH_ISSUER_SELECTOR + encode(
        ["address", "bytes32"], ["0x" + address_bytes(did_address).hex(), doc]
    )
    return _send(signer, cfg, nonce, data)


def writer_anchor_topic0() -> str:
    return with_0x(WRITER_ANCHOR_TOPIC0)


def subtree_writer_role() -> str:
    return with_0x(SUBTREE_WRITER_ROLE)


def has_role_selector() -> str:
    return with_0x(HAS_ROLE_SELECTOR)
