from __future__ import annotations

from datetime import datetime
from typing import Any

from credential.common.verification_method.selector import (
    ensure_vm_authorized_for_purpose,
    select_default_signing_vm,
)
from didv2.did.verification_method_ops import find_verification_method

HARD_REASONS = {"keyCompromise"}


def normalize_verification_method_url(did: str, kid: str) -> str:
    if not kid:
        return ""
    if kid.startswith("did:"):
        return kid
    if kid.startswith("#"):
        return did + kid
    return did + "#" + kid


def resolve_signing_vm(
    did: str,
    purpose: str,
    pinned_kid: str,
    document: dict[str, Any],
) -> dict[str, Any]:
    url = normalize_verification_method_url(did, pinned_kid)
    if pinned_kid:
        vm = find_verification_method(document, url)
        if vm is None:
            raise ValueError(f"verification method '{url}' not found")
    else:
        vm = select_default_signing_vm(document, purpose)
    if vm.get("revocationReason") in HARD_REASONS:
        raise ValueError(
            f"verification method '{vm['id']}' revoked with hard reason '{vm['revocationReason']}'"
        )
    if vm.get("revoked"):
        revoked = vm["revoked"]
        stamp = revoked.isoformat().replace("+00:00", "Z") if isinstance(revoked, datetime) else str(revoked)
        raise ValueError(f"verification method '{vm['id']}' was revoked at {stamp}")
    ensure_vm_authorized_for_purpose(document, vm["id"], purpose)
    return vm
