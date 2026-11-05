from __future__ import annotations

from datetime import timezone
from typing import Any

from credential.common.verification_method.selector import (
    KeyKind,
    ensure_vm_authorized_for_purpose,
    select_default_signing_vm,
    select_latest_active_vm_for_key,
)
from credential.common.verification_method.verification_method import (
    DIDDocument,
    VerificationMethodEntry,
    coerce_document,
)


def format_rfc3339(dt: Any) -> str:
    """UTC, whole seconds, 'Z' suffix (Go's time.RFC3339 on a UTC time)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_verification_method_url(did: str, kid: str) -> str:
    """'did:x#k' stays; '#k' -> '<did>#k'; 'k' -> '<did>#k'; '' -> ''."""
    if not kid:
        return ""
    if kid.startswith("did:"):
        return kid
    if kid.startswith("#"):
        return did + kid
    return did + "#" + kid


def did_from_vm_url(url: str) -> str:
    """DID prefix of a VM URL ('did:x:y#key-1' -> 'did:x:y'); '' when not a DID URL."""
    if not url.startswith("did:"):
        return ""
    i = url.find("#")
    return url[:i] if i > 0 else url


def did_from_verification_method_url(vm_url: str) -> str:
    """Split at the first '#'; the URL must start with 'did:'."""
    if not vm_url:
        raise ValueError("verification method is empty")
    did_part, sep, _ = vm_url.partition("#")
    if not sep or did_part == "":
        raise ValueError(f"invalid verification method URL, could not extract DID: {vm_url}")
    if not did_part.startswith("did:"):
        raise ValueError(f"extracted DID '{did_part}' is invalid, must start with 'did:'")
    return did_part


def find_verification_method(doc: Any, vm_url: str) -> VerificationMethodEntry:
    """Exact full-URL match; normalise first for fragment forms."""
    if doc is None:
        raise ValueError("did document is nil")
    d = coerce_document(doc)
    if vm_url == "":
        raise ValueError("verification method is empty")
    for vm in d.verification_method:
        if vm.id == vm_url:
            return vm
    raise ValueError(f"verification method '{vm_url}' not found in DID '{d.id}' document")


def _resolve(resolver: Any, did: str) -> DIDDocument:
    if resolver is None:
        raise ValueError("document resolver is not configured")
    if hasattr(resolver, "resolve_document"):
        return coerce_document(resolver.resolve_document(did))
    return coerce_document(resolver)  # an already-resolved document


def resolve_verification_method_url_for_key(did: str, purpose: str, kind: KeyKind, resolver: Any) -> str:
    """Like the default selector but picks the latest active VM whose key matches kind."""
    if resolver is None:
        raise ValueError("document resolver is not configured")
    try:
        doc = _resolve(resolver, did)
    except Exception as exc:
        raise ValueError(f"failed to resolve DID '{did}': {exc}") from exc
    return select_latest_active_vm_for_key(doc, purpose, kind).id


def resolve_signing_vm(did: str, purpose: str, pinned_kid: str, resolver: Any) -> VerificationMethodEntry:
    """The VM to sign with: the pinned kid, else the only/latest active one for purpose.

    ``resolver`` is a ResolverProvider (``resolve_document(did)``) or an already
    resolved document. The result is rejected if revoked or not granted purpose.
    """
    if resolver is None:
        raise ValueError("document resolver is not configured")
    url = normalize_verification_method_url(did, pinned_kid)
    vm_did = did_from_vm_url(url) or did
    try:
        doc = _resolve(resolver, vm_did)
    except Exception as exc:
        raise ValueError(f"failed to resolve DID '{vm_did}': {exc}") from exc
    if not pinned_kid:
        vm = select_default_signing_vm(doc, purpose)
    else:
        vm = find_verification_method(doc, url)
    if vm.revoked is not None:
        raise ValueError(f"verification method '{vm.id}' was revoked at {format_rfc3339(vm.revoked)}")
    ensure_vm_authorized_for_purpose(doc, vm.id, purpose)
    return vm
