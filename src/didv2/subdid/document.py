from __future__ import annotations

import re
from typing import Any

from didv2.did.verification_method_ops import find_verification_method
from didv2.did.did import hash_did_document, validate_did_document
from didv2.ethereum import address_from_public_key_hex

SUB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
DID_RE = re.compile(r"^did:[a-z]{1,16}(:[a-z]{1,16}){0,2}:0x[0-9a-f]{40}$")
COMPRESSED_KEY_RE = re.compile(r"^0x0[23][0-9a-f]{64}$")
SECP256K1_VM_TYPE = "EcdsaSecp256k1VerificationKey2019"


def parse_sub_id(s: str) -> str:
    if not SUB_ID_RE.fullmatch(s):
        raise ValueError(f"subdid: subId must match {SUB_ID_RE.pattern}")
    return s


def check_did(s: str) -> None:
    if not DID_RE.fullmatch(s):
        raise ValueError(f"{s!r} does not match {DID_RE.pattern}")


def did_prefix(s: str) -> str:
    return s[: s.rfind(":") + 1]


def did_address(s: str) -> str:
    return s[s.rfind(":") + 1 :]


def sub_did_for(root_did: str, public_key_hex: str) -> str:
    check_did(root_did)
    addr = address_from_public_key_hex(public_key_hex)
    return did_prefix(root_did) + addr


def validate_sub_did(doc: dict[str, Any], root_did: str) -> None:
    if not doc:
        raise ValueError("subdid: document is nil")
    try:
        validate_did_document(doc)
    except ValueError as exc:
        raise ValueError(f"subdid: {exc}") from exc
    check_did(doc["id"])
    check_did(root_did)
    if did_prefix(doc["id"]) != did_prefix(root_did):
        raise ValueError(f"subdid: {doc['id']} and root {root_did} have different prefixes")
    if doc["id"] == root_did:
        raise ValueError("subdid: a Sub-DID cannot be its own root")
    if doc.get("controller") != root_did:
        raise ValueError(f"subdid: controller {doc.get('controller')!r} is not the root DID {root_did}")
    for vm in doc.get("verificationMethod") or []:
        if not vm["id"].startswith(doc["id"] + "#"):
            raise ValueError(f"subdid: verification method id {vm['id']!r} must start with {doc['id']}#")
    _check_primary(doc)
    if doc.get("didDocumentMetadata") is None:
        raise ValueError("subdid: didDocumentMetadata is missing")


def _check_primary(doc: dict[str, Any]) -> None:
    vm = find_verification_method(doc, "#key-1")
    if not vm:
        raise ValueError("subdid: #key-1 is missing")
    if vm.get("type") != SECP256K1_VM_TYPE:
        raise ValueError(f"subdid: #key-1 has type {vm.get('type')!r}, want {SECP256K1_VM_TYPE}")
    if not vm.get("publicKeyHex") or not COMPRESSED_KEY_RE.fullmatch(vm["publicKeyHex"]):
        raise ValueError("subdid: #key-1 publicKeyHex must be a lowercase compressed secp256k1 key")
    address = address_from_public_key_hex(vm["publicKeyHex"])
    if address != did_address(doc["id"]):
        raise ValueError(f"subdid: #key-1 belongs to {address}, not to {doc['id']}")


def doc_hash(doc: dict[str, Any]) -> str:
    h = hash_did_document(doc)
    if not re.fullmatch(r"0x[0-9a-f]{64}", h):
        raise ValueError(f"subdid: document hash {h!r} is not 32 bytes")
    return h
