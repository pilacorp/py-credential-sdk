"""DID document construction, validation and hashing (port of Go didv2/did/did.go + model.go).

Documents are plain dicts with the JSON field names of the Go struct.  A key that is absent or
``None`` marshals as JSON ``null`` (Go nil slice / nil map) exactly like Go; ``revoked`` may be a
``datetime`` or an RFC 3339 string and is always hashed as Go's RFC3339Nano.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys

from didv2.did.jsoncanonicalizer import number_to_json, serialize
from didv2.did.multikey import encode_pub_multibase
from didv2.keccak import keccak256_hex

DID_TYPE_PEOPLE = 0
DID_TYPE_ITEM = 1
DID_TYPE_LOCATION = 2
DID_TYPE_ACTIVITY = 3

SECP256K1_VM_TYPE = "EcdsaSecp256k1VerificationKey2019"
MULTIKEY_VM_TYPE = "Multikey"
CID_CONTEXT = "https://www.w3.org/ns/cid/v1"
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
SECURITY_CONTEXT = "https://w3id.org/security/v1"

PURPOSE_AUTHENTICATION = "authentication"
PURPOSE_ASSERTION_METHOD = "assertionMethod"
SUPPORTED_PURPOSES = (PURPOSE_AUTHENTICATION, PURPOSE_ASSERTION_METHOD)


def did_type_string(did_type: int) -> str:
    return {0: "people", 1: "item", 2: "location", 3: "activity"}.get(did_type, "unknown")


def to_did(method: str, address: str) -> str:
    return f"{method}:{address}".lower()


def canonical_vm_id(did: str, id_or_fragment: str) -> str:
    """Expand a "#fragment" reference into a full DID URL."""
    if id_or_fragment.startswith("#"):
        return did + id_or_fragment
    return id_or_fragment


# --------------------------------------------------------------------------- verification methods


def new_secp256k1_vm(did: str, fragment: str, public_key_hex: str) -> dict[str, Any]:
    return {
        "id": canonical_vm_id(did, fragment),
        "type": SECP256K1_VM_TYPE,
        "controller": did,
        "publicKeyHex": public_key_hex,
    }


def new_p256_multikey_vm(did: str, fragment: str, pub: ec.EllipticCurvePublicKey | None) -> dict[str, Any]:
    if pub is None or not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("NewP256MultikeyVM requires a P-256 public key")
    return {
        "id": canonical_vm_id(did, fragment),
        "type": MULTIKEY_VM_TYPE,
        "controller": did,
        "publicKeyMultibase": encode_pub_multibase(pub),
    }


@dataclass
class VerificationMethodSpec:
    """A verification method plus the relationship arrays it joins (empty purposes means both)."""

    vm: dict[str, Any]
    purposes: list[str] = field(default_factory=list)

    def effective_purposes(self) -> list[str]:
        return list(self.purposes) or [PURPOSE_AUTHENTICATION, PURPOSE_ASSERTION_METHOD]


def new_spec(vm: dict[str, Any], *purposes: str) -> VerificationMethodSpec:
    return VerificationMethodSpec(vm=vm, purposes=list(purposes))


def new_verification_methods(
    *specs: VerificationMethodSpec | dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Split specs into (verificationMethod, authentication, assertionMethod); rejects other purposes."""
    vms: list[dict[str, Any]] = []
    authentication: list[str] = []
    assertion: list[str] = []
    for s in specs:
        if not isinstance(s, VerificationMethodSpec):
            s = VerificationMethodSpec(vm=s)
        vms.append(s.vm)
        for p in s.effective_purposes():
            if p == PURPOSE_AUTHENTICATION:
                authentication.append(s.vm["id"])
            elif p == PURPOSE_ASSERTION_METHOD:
                assertion.append(s.vm["id"])
            else:
                raise ValueError(f"verification method {s.vm['id']}: unsupported purpose: {p!r}")
    return vms, authentication, assertion


def document_context(vms: list[dict[str, Any]]) -> list[str]:
    """DID Core 1.0 section 6.1: did/v1 first, then security; plus CID when a Multikey VM is published."""
    ctx = [DID_CONTEXT, SECURITY_CONTEXT]
    if any(vm.get("type") == MULTIKEY_VM_TYPE for vm in vms):
        ctx.append(CID_CONTEXT)
    return ctx


def generate_did_document(
    did_public_key: str,
    did: str,
    hash_: str,
    issuer_did: str,
    did_type: int = DID_TYPE_PEOPLE,
    metadata: dict[str, Any] | None = None,
    extra_vms: list[VerificationMethodSpec | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the document.  ``extra_vms`` entries are specs (or bare VM dicts = both purposes);
    "#key-1" is reserved for ``did_public_key``.  Raises ValueError where Go returns nil."""
    meta = dict(metadata or {})
    name = did_type_string(did_type)
    if name:
        meta["type"] = name
    if hash_:
        meta["hash"] = hash_
    specs: list[Any] = [new_spec(new_secp256k1_vm(did, "#key-1", did_public_key))]
    specs.extend(extra_vms or [])
    vms, authentication, assertion = new_verification_methods(*specs)
    return {
        "@context": document_context(vms),
        "id": did,
        "controller": issuer_did,
        "verificationMethod": vms,
        "authentication": authentication,
        "assertionMethod": assertion,
        "didDocumentMetadata": meta,
    }


def vm_type_for(vm: dict[str, Any]) -> str:
    """The suite a VM must be published under, derived from its key material field."""
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


def validate_did_document(doc: dict[str, Any] | None) -> None:
    """Go DIDDocument.Validate: empty/duplicate VM ids, key material vs type, dangling relationships."""
    if doc is None:
        raise ValueError("DID document is nil")
    doc_id = doc.get("id") or ""
    seen: set[str] = set()
    for i, vm in enumerate(doc.get("verificationMethod") or []):
        vm_id = vm.get("id") or ""
        if vm_id == "":
            raise ValueError(f"verificationMethod[{i}]: id is empty")
        if vm_id in seen:
            raise ValueError(
                f"verificationMethod: duplicate id {vm_id} (#key-1 and #key-2 are reserved by GenerateDID)"
            )
        seen.add(vm_id)
        try:
            expected = vm_type_for(vm)
        except ValueError as exc:
            raise ValueError(f"verificationMethod[{i}] ({vm_id}): {exc}") from exc
        if (vm.get("type") or "") != expected:
            raise ValueError(
                f"verificationMethod[{i}] ({vm_id}): type {vm.get('type') or ''!r} does not match its key "
                f"material: expected {expected}"
            )
    for name in ("authentication", "assertionMethod"):
        for ref in doc.get(name) or []:
            if canonical_vm_id(doc_id, ref) not in seen:
                raise ValueError(f"{name} references unknown verification method {ref!r}")


# --------------------------------------------------------------------------- RFC 3339 (Go RFC3339Nano)

_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$", re.ASCII
)


def _leap(y: int) -> bool:
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def rfc3339_nano(value: Any) -> str:
    """Normalise ``revoked`` to what Go's ``time.Time`` marshals: RFC3339Nano, trailing fractional zeros
    trimmed, ``Z`` for a zero offset.  Raises ValueError for anything Go's UnmarshalJSON would refuse."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        off = dt.utcoffset() or timedelta(0)
        secs = int(off.total_seconds())
        frac = f"{dt.microsecond:06d}".rstrip("0")
        base = f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        zone = "Z" if secs == 0 else f"{'+' if secs > 0 else '-'}{abs(secs) // 3600:02d}:{abs(secs) % 3600 // 60:02d}"
        return base + ("." + frac if frac else "") + zone
    if not isinstance(value, str):
        raise ValueError(f"revoked: cannot parse {value!r} as RFC 3339 time")
    m = _RFC3339.match(value)
    if not m:
        raise ValueError(f"revoked: cannot parse {value!r} as RFC 3339 time")
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    dim = [31, 29 if _leap(y) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not (1 <= mo <= 12 and 1 <= d <= dim[mo - 1] and h < 24 and mi < 60 and s < 60):
        raise ValueError(f"revoked: {value!r} is out of range")
    zone = m.group(8)
    if zone != "Z":
        zh, zm = int(zone[1:3]), int(zone[4:6])
        if zh >= 24 or zm >= 60:
            raise ValueError(f"revoked: {value!r} has an out-of-range zone")
        if zh == 0 and zm == 0:
            zone = "Z"
    frac = (m.group(7) or "")[:9].rstrip("0")
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}" + (
        "." + frac if frac else ""
    ) + zone


# --------------------------------------------------------------------------- marshal / hash


def _vm_json(vm: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": vm.get("id") or "",
        "type": vm.get("type") or "",
        "controller": vm.get("controller") or "",
    }
    if vm.get("publicKeyHex"):
        out["publicKeyHex"] = vm["publicKeyHex"]
    if vm.get("publicKeyJwk"):
        out["publicKeyJwk"] = vm["publicKeyJwk"]
    if vm.get("publicKeyMultibase"):
        out["publicKeyMultibase"] = vm["publicKeyMultibase"]
    if vm.get("revoked") is not None:
        out["revoked"] = rfc3339_nano(vm["revoked"])
    if vm.get("revocationReason"):
        out["revocationReason"] = vm["revocationReason"]
    return out


def did_document_json(doc: dict[str, Any]) -> dict[str, Any]:
    """The wire form of Go json.Marshal(*DIDDocument): known fields only, absent slices/maps -> null."""
    vms = doc.get("verificationMethod")
    return {
        "@context": doc.get("@context"),
        "id": doc.get("id") or "",
        "controller": doc.get("controller") or "",
        "verificationMethod": None if vms is None else [_vm_json(vm) for vm in vms],
        "authentication": doc.get("authentication"),
        "assertionMethod": doc.get("assertionMethod"),
        "didDocumentMetadata": doc.get("didDocumentMetadata"),
    }


def _go_marshal(value: Any) -> str:
    """encoding/json style output: struct (dict) order kept, but metadata maps sorted by key."""
    if isinstance(value, float):
        return number_to_json(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _go_marshal(v) for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_go_marshal(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False)


def _sort_maps(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sort_maps(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_sort_maps(v) for v in value]
    return value


def marshal_did_document(doc: dict[str, Any]) -> str:
    j = did_document_json(doc)
    j["didDocumentMetadata"] = _sort_maps(j["didDocumentMetadata"])
    for vm in j["verificationMethod"] or []:
        if "publicKeyJwk" in vm:
            vm["publicKeyJwk"] = _sort_maps(vm["publicKeyJwk"])
    out = _go_marshal(j)
    # Go escapes these in json.Marshal output
    return out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace(
        " ", "\\u2028"
    ).replace(" ", "\\u2029")


def hash_did_document(doc: dict[str, Any] | None) -> str:
    """keccak256 of the RFC 8785 canonical form of the document; lowercase 0x hex."""
    if doc is None:
        raise ValueError("DID document is nil")
    return keccak256_hex(serialize(did_document_json(doc)).encode("utf-8"))


# --------------------------------------------------------------------------- key pairs


@dataclass
class KeyPair:
    """secp256k1 key pair of a DID; ``p256_public_key`` is set only by generate_dual_curve_key_pair."""

    private_key: keys.PrivateKey
    p256_public_key: ec.EllipticCurvePublicKey | None = None

    @property
    def public_key(self) -> keys.PublicKey:
        return self.private_key.public_key

    def get_address(self) -> str:
        return "0x" + self.public_key.to_canonical_address().hex()

    def get_did(self, method: str) -> str:
        if not method:
            return ""
        return f"{method}:{self.get_address()}".lower()

    def get_public_key_hex(self) -> str:
        return "0x" + self.public_key.to_compressed_bytes().hex()

    def get_private_key_hex(self) -> str:
        return "0x" + self.private_key.to_bytes().hex()


def generate_ecdsa_key_pair() -> KeyPair:
    import os

    return KeyPair(keys.PrivateKey(os.urandom(32)))


def generate_dual_curve_key_pair() -> KeyPair:
    """One scalar published on both curves.  P-256 first: n(P-256) < n(secp256k1)."""
    p256 = ec.generate_private_key(ec.SECP256R1())
    scalar = p256.private_numbers().private_value
    return KeyPair(keys.PrivateKey(scalar.to_bytes(32, "big")), p256.public_key())
