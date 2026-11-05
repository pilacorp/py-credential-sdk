from __future__ import annotations

import re
from enum import Enum
from typing import Any, Callable

from credential.common.verification_method.key_material import curve_name, ec_pub_from_multibase
from credential.common.verification_method.verification_method import (
    DIDDocument,
    VerificationMethodEntry,
    coerce_document,
)


class KeyKind(Enum):
    """Key type a verification method holds, so VM selection can match the signer's key."""

    SECP256K1 = "secp256k1"
    RSA = "RSA"
    P256 = "P-256"

    def __str__(self) -> str:
        return self.value


def vm_is_rsa(vm: VerificationMethodEntry | None) -> bool:
    return vm is not None and vm.public_key_jwk is not None and vm.public_key_jwk.kty == "RSA"


def vm_is_p256(vm: VerificationMethodEntry | None) -> bool:
    """EC P-256 JWK or a P-256 Multikey."""
    if vm is None:
        return False
    if vm.public_key_jwk is not None:
        return vm.public_key_jwk.kty == "EC" and vm.public_key_jwk.crv == "P-256"
    if vm.public_key_multibase:
        try:
            return curve_name(ec_pub_from_multibase(vm.public_key_multibase)) == "P-256"
        except ValueError:
            return False
    return False


def vm_is_secp256k1(vm: VerificationMethodEntry | None) -> bool:
    """EC secp256k1 JWK or a publicKeyHex (P-256 keys never use publicKeyHex)."""
    if vm is None:
        return False
    if vm.public_key_jwk is not None:
        return vm.public_key_jwk.kty == "EC" and vm.public_key_jwk.crv == "secp256k1"
    return vm.public_key_hex != ""


def vm_key_kind(vm: VerificationMethodEntry | None) -> tuple[KeyKind, bool]:
    """(kind, recognized). A None vm is reported as unrecognized."""
    if vm is None:
        return KeyKind.SECP256K1, False
    if vm_is_secp256k1(vm):
        return KeyKind.SECP256K1, True
    if vm_is_p256(vm):
        return KeyKind.P256, True
    if vm_is_rsa(vm):
        return KeyKind.RSA, True
    return KeyKind.SECP256K1, False


def _vm_matches_kind(vm: VerificationMethodEntry, kind: KeyKind) -> bool:
    return {KeyKind.RSA: vm_is_rsa, KeyKind.P256: vm_is_p256, KeyKind.SECP256K1: vm_is_secp256k1}[kind](vm)


def _doc(doc: Any) -> DIDDocument:
    if doc is None or doc == {}:
        raise ValueError("did document is nil")
    return coerce_document(doc)


def _purpose_array(doc: DIDDocument, purpose: str) -> list[str]:
    if purpose == "authentication":
        return doc.authentication
    if purpose == "assertionMethod":
        return doc.assertion_method
    raise ValueError(f"unsupported purpose: {purpose}")


def id_in_purpose_array(vm_id: str, did: str, arr: list[str]) -> bool:
    """vm_id (full URL or fragment) appears in the relationship array in either form."""
    frag = vm_id[len(did):] if vm_id.startswith(did + "#") else vm_id
    return any(ref == vm_id or ref == frag for ref in arr)


def parse_sequential_fragment(vm_id: str, did: str) -> int | None:
    """N from '<did>#key-N' (Go fmt.Sscanf %d reads the leading integer), else None."""
    prefix = did + "#key-"
    if not vm_id.startswith(prefix):
        return None
    m = re.match(r"[+-]?\d+", vm_id[len(prefix):])
    return int(m.group()) if m else None


def _select_latest_active_vm(
    doc: DIDDocument, purpose: str, match: Callable[[VerificationMethodEntry], bool] | None
) -> VerificationMethodEntry | None:
    purpose_arr = _purpose_array(doc, purpose)
    if not purpose_arr:
        raise ValueError(f"no verification methods listed for purpose '{purpose}' on DID '{doc.id}'")
    best: VerificationMethodEntry | None = None
    best_n = -1
    for vm in doc.verification_method:
        if vm.revoked is not None:
            continue
        if not id_in_purpose_array(vm.id, doc.id, purpose_arr):
            continue
        if match is not None and not match(vm):
            continue
        n = parse_sequential_fragment(vm.id, doc.id)
        if n is None:
            n = 0
        # Higher #key-N wins; ties break on the lexicographically larger ID so the
        # choice does not depend on the resolver's ordering.
        if n > best_n or (n == best_n and best is not None and vm.id > best.id):
            best_n = n
            best = vm
    return best


def select_latest_active_vm_for_purpose(doc: Any, purpose: str) -> VerificationMethodEntry:
    d = _doc(doc)
    vm = _select_latest_active_vm(d, purpose, None)
    if vm is None:
        raise ValueError(f"no active verification method for purpose '{purpose}' on DID '{d.id}'")
    return vm


def select_latest_active_vm_for_key(doc: Any, purpose: str, kind: KeyKind) -> VerificationMethodEntry:
    d = _doc(doc)
    vm = _select_latest_active_vm(d, purpose, lambda v: _vm_matches_kind(v, kind))
    if vm is None:
        raise ValueError(f"no active {kind} verification method for purpose '{purpose}' on DID '{d.id}'")
    return vm


def select_default_signing_vm(doc: Any, purpose: str) -> VerificationMethodEntry:
    """The only VM when the document has exactly one, else the latest active one for purpose."""
    d = _doc(doc)
    if len(d.verification_method) == 1:
        return d.verification_method[0]
    return select_latest_active_vm_for_purpose(d, purpose)


def select_vm_for_purpose(doc: Any, purpose: str, kid: str) -> VerificationMethodEntry:
    """Prefer an explicit kid (full URL, '#frag' or bare 'frag'); the VM may be revoked."""
    if kid == "":
        return select_latest_active_vm_for_purpose(doc, purpose)
    d = _doc(doc)
    from credential.common.verification_method.resolve import normalize_verification_method_url

    canonical = normalize_verification_method_url(d.id, kid)
    for vm in d.verification_method:
        if vm.id == canonical:
            return vm
    raise ValueError(f"verification method '{kid}' not found in DID '{d.id}' document")


def ensure_vm_authorized_for_purpose(doc: Any, vm_id: str, purpose: str) -> None:
    d = _doc(doc)
    if purpose == "authentication":
        arr = d.authentication
    elif purpose == "assertionMethod":
        arr = d.assertion_method
    else:
        raise ValueError(f"unsupported purpose '{purpose}'")
    if not id_in_purpose_array(vm_id, d.id, arr):
        raise ValueError(f"verification method '{vm_id}' is not granted purpose '{purpose}' on DID '{d.id}'")
