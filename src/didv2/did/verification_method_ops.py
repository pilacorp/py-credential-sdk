from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from didv2.ethereum import compress_secp256k1, secp256k1_point
from didv2.did.did import (
    CID_CONTEXT,
    MULTIKEY_VM_TYPE,
    SECP256K1_VM_TYPE,
    SUPPORTED_PURPOSES as SUPPORTED,
    canonical_vm_id,
    rfc3339_nano,
    vm_type_for as _vm_type_for,
)


def find_verification_method(doc: dict[str, Any] | None, id_or_fragment: str) -> dict[str, Any] | None:
    if not doc:
        return None
    did = doc.get("id") or ""
    target = canonical_vm_id(did, id_or_fragment)
    for vm in doc.get("verificationMethod") or []:
        if canonical_vm_id(did, vm.get("id") or "") == target:
            return vm
    return None


def add_verification_method(
    doc: dict[str, Any],
    vm: dict[str, Any],
    purposes: list[str] | None = None,
) -> str:
    if doc is None:
        raise ValueError("document is nil")
    if not doc.get("id"):
        raise ValueError("document.id is required")
    purposes = purposes or []
    expected = _vm_type_for(vm)
    # validate purposes before touching the document: a later failure must not leave a half-added VM
    _validate_purposes(purposes)
    next_vm = {
        "id": canonical_vm_id(doc["id"], vm["id"]) if vm.get("id") else _next_sequential_kid(doc),
        "type": vm.get("type") or expected,
        "controller": vm.get("controller") or doc["id"],
    }
    for key in ("publicKeyHex", "publicKeyMultibase", "publicKeyJwk", "revoked", "revocationReason"):
        if key in vm and vm[key] is not None:
            next_vm[key] = vm[key]
    if next_vm["type"] != expected:
        raise ValueError(
            f"verification method type {next_vm['type']!r} does not match its key material: expected {expected}"
        )
    if find_verification_method(doc, next_vm["id"]):
        raise ValueError(f"verification method already exists: {next_vm['id']}")
    existing = _find_by_fingerprint(doc, _key_fingerprint(next_vm))
    if existing:
        raise ValueError(f"verification method with the same public key already exists: {existing}")
    if doc.get("verificationMethod") is None:
        doc["verificationMethod"] = []
    doc["verificationMethod"].append(next_vm)
    if next_vm["type"] == MULTIKEY_VM_TYPE:
        _ensure_context(doc, CID_CONTEXT)
    for p in purposes:
        _add_purpose(doc, p, next_vm["id"])
    return next_vm["id"]


def rotate_verification_method(
    doc: dict[str, Any],
    old_kid: str,
    new_vm: dict[str, Any],
    reason: str = "superseded",
    revoked_at: datetime | None = None,
) -> str:
    if doc is None:
        raise ValueError("document is nil")
    if not old_kid:
        raise ValueError("old_kid is required")
    revoked_at = revoked_at or datetime.now(timezone.utc)
    reason = reason or "superseded"
    old = find_verification_method(doc, old_kid)
    if not old:
        raise ValueError(f"verification method not found: {old_kid}")
    if old.get("revoked") is not None:
        raise ValueError(f"verification method {old['id']!r} is already revoked")
    old_id = old["id"]
    purposes = _purposes_of_kid(doc, old_id)
    new_id = add_verification_method(doc, new_vm, purposes)
    old["revoked"] = revoked_at
    old["revocationReason"] = reason
    _ensure_context(doc, CID_CONTEXT)
    return new_id


def revoke_verification_method(
    doc: dict[str, Any],
    kid: str,
    reason: str,
    revoked_at: datetime | None = None,
) -> None:
    """Mark a VM revoked.  It stays in the relationship arrays on purpose: verifiers compare
    proof.created with the revoked timestamp."""
    if doc is None:
        raise ValueError("document is nil")
    if not kid:
        raise ValueError("kid is required")
    if not reason:
        raise ValueError("reason is required")
    revoked_at = revoked_at or datetime.now(timezone.utc)
    vm = find_verification_method(doc, kid)
    if not vm:
        raise ValueError(f"verification method not found: {kid}")
    if vm.get("revoked") is not None:
        at = rfc3339_nano(vm["revoked"])
        raise ValueError(
            f"verification method {vm['id']!r} is already revoked at {at} (reason: {vm.get('revocationReason', '')})"
        )
    vm["revoked"] = revoked_at
    vm["revocationReason"] = reason
    _ensure_context(doc, CID_CONTEXT)


def add_verification_method_purposes(doc: dict[str, Any], kid: str, purposes: list[str]) -> None:
    if doc is None:
        raise ValueError("document is nil")
    if not kid:
        raise ValueError("kid is required")
    if not purposes:
        raise ValueError("purposes is required")
    vm = find_verification_method(doc, kid)
    if not vm:
        raise ValueError(f"verification method not found: {kid}")
    if vm.get("revoked") is not None:
        raise ValueError(f"verification method {vm['id']!r} is revoked")
    _validate_purposes(purposes)
    for p in purposes:
        _add_purpose(doc, p, kid)


def remove_verification_method_purposes(doc: dict[str, Any], kid: str, purposes: list[str]) -> None:
    if doc is None:
        raise ValueError("document is nil")
    if not kid:
        raise ValueError("kid is required")
    if not purposes:
        raise ValueError("purposes is required")
    if not find_verification_method(doc, kid):
        raise ValueError(f"verification method not found: {kid}")
    _validate_purposes(purposes)
    for p in purposes:
        _remove_purpose(doc, p, kid)


def _ensure_context(doc: dict[str, Any], ctx: str) -> None:
    ctxs = list(doc.get("@context") or [])
    if ctx not in ctxs:
        ctxs.append(ctx)
        doc["@context"] = ctxs


def _find_by_fingerprint(doc: dict[str, Any], fp: str) -> str:
    if not fp:
        return ""
    for vm in doc.get("verificationMethod") or []:
        if _key_fingerprint(vm) == fp:
            return vm["id"]
    return ""


def _key_fingerprint(vm: dict[str, Any]) -> str:
    if vm.get("publicKeyHex"):
        return "publicKeyHex:" + _normalize_secp(vm["publicKeyHex"])
    if vm.get("publicKeyMultibase"):
        return "publicKeyMultibase:" + vm["publicKeyMultibase"]
    return ""


def _normalize_secp(h: str) -> str:
    """Reduce a hex key to its compressed point; anything else compares as lowercase hex w/o 0x."""
    trimmed = h.lower().removeprefix("0x")
    try:
        return compress_secp256k1(*secp256k1_point(bytes.fromhex(trimmed))).hex()
    except ValueError:
        return trimmed


def _validate_purposes(purposes: list[str]) -> None:
    for p in purposes:
        if p not in SUPPORTED:
            raise ValueError(f"unsupported purpose: {p}")


def _add_purpose(doc: dict[str, Any], p: str, kid: str) -> None:
    key = "authentication" if p == "authentication" else "assertionMethod"
    doc[key] = _add_ref(doc.get(key) or [], kid, doc["id"])


def _remove_purpose(doc: dict[str, Any], p: str, kid: str) -> None:
    key = "authentication" if p == "authentication" else "assertionMethod"
    doc[key] = _remove_ref(doc.get(key) or [], kid, doc["id"])


def _add_ref(arr: list[str], kid: str, did: str) -> list[str]:
    target = canonical_vm_id(did, kid)
    seen: set[str] = set()
    out: list[str] = []
    for x in arr:
        c = canonical_vm_id(did, x)
        if c in seen:
            continue
        seen.add(c)
        out.append(c)
    if target not in seen:
        out.append(target)
    return out


def _remove_ref(arr: list[str], kid: str, did: str) -> list[str]:
    target = canonical_vm_id(did, kid)
    seen: set[str] = set()
    out: list[str] = []
    for x in arr:
        c = canonical_vm_id(did, x)
        if c == target or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _purposes_of_kid(doc: dict[str, Any], kid: str) -> list[str]:
    out: list[str] = []
    if _contains(doc.get("authentication") or [], kid, doc["id"]):
        out.append("authentication")
    if _contains(doc.get("assertionMethod") or [], kid, doc["id"]):
        out.append("assertionMethod")
    return out


def _contains(arr: list[str], kid: str, did: str) -> bool:
    target = canonical_vm_id(did, kid)
    return any(canonical_vm_id(did, x) == target for x in arr)


def _next_sequential_kid(doc: dict[str, Any]) -> str:
    max_n = 0
    did = doc["id"]
    for vm in doc.get("verificationMethod") or []:
        frag = vm["id"][len(did) :] if vm["id"].startswith(did) else vm["id"]
        if not frag.startswith("#key-"):
            continue
        try:
            n = int(frag[len("#key-") :])
        except ValueError:
            continue
        if n > max_n:
            max_n = n
    return f"{did}#key-{max_n + 1}"
