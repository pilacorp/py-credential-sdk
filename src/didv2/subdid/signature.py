from __future__ import annotations

import re
from typing import Any

from eth_keys import keys

from didv2.ethereum import eip191_hash
from didv2.signer import DefaultProvider
from didv2.subdid.document import check_did, did_address, doc_hash
from didv2.hexutil import hex_to_bytes, with_0x

ROOT_CONSENT_PREFIX = "Sub-DID "
STORED_SIG = re.compile(r"^0x[0-9a-f]{130}$")
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def normalize_signature(sig: bytes) -> bytes:
    if len(sig) != 65:
        raise ValueError(f"subdid: signature is {len(sig)} bytes, want 65")
    out = bytearray(sig)
    v = out[64]
    if v in (0, 1):
        out[64] = v + 27
    elif v not in (27, 28):
        raise ValueError(f"subdid: signature v = {v}, want 0, 1, 27 or 28")
    s = int.from_bytes(out[32:64], "big")
    if s > SECP_N // 2:
        raise ValueError("subdid: signature s is above n/2")
    return bytes(out)


def root_consent_digest(sub_did: str) -> bytes:
    return eip191_hash((ROOT_CONSENT_PREFIX + sub_did).encode("utf-8"))


def sign_root_consent(sub_did: str, root: DefaultProvider) -> bytes:
    check_did(sub_did)
    return normalize_signature(root.sign(root_consent_digest(sub_did)))


def set_root_consent(doc: dict[str, Any], sig: bytes) -> None:
    normalized = normalize_signature(sig)
    meta = dict(doc.get("didDocumentMetadata") or {})
    meta["rootConsent"] = with_0x(normalized)
    doc["didDocumentMetadata"] = {k: meta[k] for k in sorted(meta)}


def get_root_consent(doc: dict[str, Any]) -> bytes:
    value = (doc.get("didDocumentMetadata") or {}).get("rootConsent")
    if not isinstance(value, str) or not STORED_SIG.fullmatch(value):
        raise ValueError("subdid: root consent invalid: rootConsent must be 0x followed by 130 lowercase hex characters")
    sig = hex_to_bytes(value)
    if sig[64] not in (27, 28):
        raise ValueError(f"subdid: root consent invalid: rootConsent v = {sig[64]}, want 27 or 28")
    normalize_signature(sig)
    return sig


def verify_root_consent(sub_doc: dict[str, Any], root_did: str) -> None:
    sig = get_root_consent(sub_doc)
    check_did(root_did)
    check_did(sub_doc["id"])
    _check_signer(root_consent_digest(sub_doc["id"]), sig, did_address(root_did))


def signature_digest(document_hash: str) -> bytes:
    return eip191_hash(hex_to_bytes(document_hash))


def sign_document(doc: dict[str, Any], sub: DefaultProvider) -> bytes:
    return normalize_signature(sub.sign(signature_digest(doc_hash(doc))))


def verify_document_signature(doc: dict[str, Any], sig: bytes) -> None:
    normalized = normalize_signature(sig)
    _check_signer(signature_digest(doc_hash(doc)), normalized, did_address(doc["id"]))


def _check_signer(digest: bytes, stored_sig: bytes, address: str) -> None:
    rec = bytearray(stored_sig)
    rec[64] = rec[64] - 27
    sig = keys.Signature(bytes(rec))
    pub = sig.recover_public_key_from_msg_hash(digest)
    recovered = with_0x(bytes(pub.to_canonical_address()))
    if recovered != address.lower():
        raise ValueError(f"signed by {recovered}, not by {address}")
