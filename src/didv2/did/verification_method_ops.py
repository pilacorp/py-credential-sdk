from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from eth_keys import keys

from didv2.hexutil import hex_to_bytes, normalize_hex

SECP256K1_VM_TYPE = "EcdsaSecp256k1VerificationKey2019"
MULTIKEY_VM_TYPE = "Multikey"
CID_CONTEXT = "https://www.w3.org/ns/cid/v1"
SUPPORTED = ("authentication", "assertionMethod")


def canonical_vm_id(did: str, id_or_fragment: str) -> str:
    if id_or_fragment.startswith("#"):
        return did + id_or_fragment
    return id_or_fragment


def find_verification_method(doc: dict[str, Any] | None, id_or_fragment: str) -> dict[str, Any] | None:
    if not doc:
        return None
    target = canonical_vm_id(doc["id"], id_or_fragment)
    for vm in doc.get("verificationMethod") or []:
        if canonical_vm_id(doc["id"], vm["id"]) == target:
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
    doc.setdefault("verificationMethod", []).append(next_vm)
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
    if not old_kid:
        raise ValueError("old_kid is required")
    old = find_verification_method(doc, old_kid)
    if not old:
        raise ValueError(f"verification method not found: {old_kid}")
    if old.get("revoked"):
        raise ValueError(f"verification method {old['id']!r} is already revoked")
    purposes = _purposes_of_kid(doc, old["id"])
    new_id = add_verification_method(doc, new_vm, purposes)
    after = find_verification_method(doc, old_kid)
    if after is None:
        raise ValueError(f"verification method index mismatch after append: {old_kid}")
    after["revoked"] = revoked_at or datetime.now(timezone.utc)
    after["revocationReason"] = reason or "superseded"
    _ensure_context(doc, CID_CONTEXT)
    return new_id


def revoke_verification_method(
    doc: dict[str, Any],
    kid: str,
    reason: str,
    revoked_at: datetime | None = None,
) -> None:
    if not kid:
        raise ValueError("kid is required")
    if not reason:
        raise ValueError("reason is required")
    vm = find_verification_method(doc, kid)
    if not vm:
        raise ValueError(f"verification method not found: {kid}")
    if vm.get("revoked"):
        raise ValueError(f"verification method {vm['id']!r} is already revoked")
    vm["revoked"] = revoked_at or datetime.now(timezone.utc)
    vm["revocationReason"] = reason
    _ensure_context(doc, CID_CONTEXT)


def add_verification_method_purposes(doc: dict[str, Any], kid: str, purposes: list[str]) -> None:
    if not kid:
        raise ValueError("kid is required")
    if not purposes:
        raise ValueError("purposes is required")
    vm = find_verification_method(doc, kid)
    if not vm:
        raise ValueError(f"verification method not found: {kid}")
    if vm.get("revoked"):
        raise ValueError(f"verification method {vm['id']!r} is revoked")
    _validate_purposes(purposes)
    for p in purposes:
        _add_purpose(doc, p, kid)


def remove_verification_method_purposes(doc: dict[str, Any], kid: str, purposes: list[str]) -> None:
    if not kid:
        raise ValueError("kid is required")
    if not purposes:
        raise ValueError("purposes is required")
    if not find_verification_method(doc, kid):
        raise ValueError(f"verification method not found: {kid}")
    _validate_purposes(purposes)
    for p in purposes:
        _remove_purpose(doc, p, kid)


def _vm_type_for(vm: dict[str, Any]) -> str:
    if vm.get("publicKeyJwk"):
        raise ValueError(
            "publicKeyJwk is not supported: publish secp256k1 as publicKeyHex or P-256 as publicKeyMultibase"
        )
    has_hex = bool(vm.get("publicKeyHex"))
    has_mb = bool(vm.get("publicKeyMultibase"))
    if has_hex and has_mb:
        raise ValueError("verification method must have publicKeyHex or publicKeyMultibase, not both")
    if has_hex:
        return SECP256K1_VM_TYPE
    if has_mb:
        return MULTIKEY_VM_TYPE
    raise ValueError("verification method must have either publicKeyHex or publicKeyMultibase")


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
    trimmed = normalize_hex(h)
    try:
        raw = hex_to_bytes(trimmed)
        pub = keys.PublicKey.from_compressed_bytes(raw) if len(raw) == 33 else keys.PublicKey.from_bytes(raw[1:])
        return pub.to_compressed_bytes().hex()
    except Exception:
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
