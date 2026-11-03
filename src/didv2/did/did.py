from __future__ import annotations

import json
from typing import Any

from didv2.model import DID_TYPE_PEOPLE, did_type_string, new_secp256k1_vm
from didv2.keccak import keccak256_hex
from didv2.did.jsoncanonicalizer import transform


def generate_did_document(
    did_public_key: str,
    did: str,
    hash_: str,
    issuer_did: str,
    did_type: int = DID_TYPE_PEOPLE,
    metadata: dict[str, Any] | None = None,
    extra_vms: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    meta = dict(metadata or {})
    name = did_type_string(did_type)
    if name:
        meta["type"] = name
    if hash_:
        meta["hash"] = hash_
    vms = [new_secp256k1_vm(did, "#key-1", did_public_key)]
    vms.extend(extra_vms or [])
    authentication = [vm["id"] for vm in vms]
    assertion = [vm["id"] for vm in vms]
    ctx = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1"]
    if any(vm.get("type") == "Multikey" for vm in vms):
        ctx.append("https://www.w3.org/ns/cid/v1")
    return {
        "@context": ctx,
        "id": did,
        "controller": issuer_did,
        "verificationMethod": vms,
        "authentication": authentication,
        "assertionMethod": assertion,
        "didDocumentMetadata": _sorted_meta(meta),
    }


def did_document_json(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "@context": doc["@context"],
        "id": doc["id"],
        "controller": doc.get("controller") or "",
        "verificationMethod": [_vm_json(vm) for vm in doc.get("verificationMethod") or []],
        "authentication": doc.get("authentication") or [],
        "assertionMethod": doc.get("assertionMethod") or [],
        "didDocumentMetadata": _sorted_meta(doc.get("didDocumentMetadata") or {}),
    }


def marshal_did_document(doc: dict[str, Any]) -> str:
    return json.dumps(did_document_json(doc), separators=(",", ":"), ensure_ascii=True)


def hash_did_document(doc: dict[str, Any]) -> str:
    marshaled = marshal_did_document(doc)
    return keccak256_hex(transform(marshaled))


def _vm_json(vm: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"id": vm["id"], "type": vm["type"], "controller": vm["controller"]}
    if vm.get("publicKeyHex"):
        out["publicKeyHex"] = vm["publicKeyHex"]
    if vm.get("publicKeyJwk"):
        out["publicKeyJwk"] = vm["publicKeyJwk"]
    if vm.get("publicKeyMultibase"):
        out["publicKeyMultibase"] = vm["publicKeyMultibase"]
    if vm.get("revoked"):
        out["revoked"] = vm["revoked"].isoformat() if hasattr(vm["revoked"], "isoformat") else vm["revoked"]
    if vm.get("revocationReason"):
        out["revocationReason"] = vm["revocationReason"]
    return out


def _sorted_meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {k: meta[k] for k in sorted(meta)}
