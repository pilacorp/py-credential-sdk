from __future__ import annotations

from typing import Any, Callable

from didv2.did.verification_method_ops import canonical_vm_id


def select_default_signing_vm(doc: dict[str, Any] | None, purpose: str) -> dict[str, Any]:
    if not doc:
        raise ValueError("did document is nil")
    vms = doc.get("verificationMethod") or []
    if len(vms) == 1:
        return vms[0]
    return select_latest_active_vm_for_purpose(doc, purpose)


def ensure_vm_authorized_for_purpose(doc: dict[str, Any] | None, vm_id: str, purpose: str) -> None:
    if not doc:
        raise ValueError("did document is nil")
    arr = _purpose_array(doc, purpose)
    if not _id_in_purpose_array(vm_id, doc["id"], arr):
        raise ValueError(
            f"verification method '{vm_id}' is not granted purpose '{purpose}' on DID '{doc['id']}'"
        )


def select_latest_active_vm_for_purpose(
    doc: dict[str, Any] | None,
    purpose: str,
    match: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    if not doc:
        raise ValueError("did document is nil")
    purpose_arr = _purpose_array(doc, purpose)
    if not purpose_arr:
        raise ValueError(f"no verification methods listed for purpose '{purpose}' on DID '{doc['id']}'")
    best: dict[str, Any] | None = None
    best_n = -1
    for vm in doc.get("verificationMethod") or []:
        if vm.get("revoked"):
            continue
        if not _id_in_purpose_array(vm["id"], doc["id"], purpose_arr):
            continue
        if match is not None and not match(vm):
            continue
        n = _parse_sequential_fragment(vm["id"], doc["id"])
        if n is None:
            n = 0
        if n > best_n or (n == best_n and best is not None and vm["id"] > best["id"]):
            best_n = n
            best = vm
    if best is None:
        raise ValueError(f"no active verification method for purpose '{purpose}' on DID '{doc['id']}'")
    return best


def _purpose_array(doc: dict[str, Any], purpose: str) -> list[str]:
    if purpose == "authentication":
        return list(doc.get("authentication") or [])
    if purpose == "assertionMethod":
        return list(doc.get("assertionMethod") or [])
    raise ValueError(f"unsupported purpose: {purpose}")


def _id_in_purpose_array(vm_id: str, did: str, arr: list[str]) -> bool:
    frag = vm_id[len(did) :] if vm_id.startswith(did + "#") else vm_id
    return any(ref == vm_id or ref == frag or canonical_vm_id(did, ref) == canonical_vm_id(did, vm_id) for ref in arr)


def _parse_sequential_fragment(vm_id: str, did: str) -> int | None:
    prefix = f"{did}#key-"
    if not vm_id.startswith(prefix):
        return None
    tail = vm_id[len(prefix) :]
    if not tail.isdigit() or str(int(tail)) != tail:
        return None
    return int(tail)
