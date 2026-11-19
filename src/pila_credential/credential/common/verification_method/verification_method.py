from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass
class JWK:
    kty: str
    crv: str = ""
    x: str = ""
    y: str = ""
    n: str = ""
    e: str = ""


@dataclass
class VerificationMethodEntry:
    id: str
    type: str
    controller: str
    public_key_hex: str = ""
    public_key_jwk: JWK | None = None
    public_key_multibase: str = ""
    revoked: datetime | None = None
    revocation_reason: str = ""


@dataclass
class DIDDocument:
    id: str
    context: list[str] = field(default_factory=list)
    verification_method: list[VerificationMethodEntry] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    assertion_method: list[str] = field(default_factory=list)
    controller: Any = ""
    did_document_metadata: dict[str, Any] = field(default_factory=dict)


# Go's time.Time JSON decoding: RFC 3339 with an explicit offset, fraction of any length.
_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$"
)


def parse_rfc3339(value: str) -> datetime:
    """Parse an RFC 3339 / RFC3339Nano timestamp (offset required) into an aware datetime.

    Sub-microsecond digits are truncated (datetime keeps microseconds).
    """
    m = _RFC3339.match(value) if isinstance(value, str) else None
    if not m:
        raise ValueError(f"invalid RFC 3339 timestamp: {value!r}")
    y, mo, d, h, mi, s, frac, off = m.groups()
    micro = int((frac + "000000")[:6]) if frac else 0
    if off in ("Z", "z"):
        tz = timezone.utc
    else:
        sign = 1 if off[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[4:6])))
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=tz)


def _str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError("expected an array")
    return [x for x in v if isinstance(x, str)]


def vm_from_dict(raw: dict[str, Any]) -> VerificationMethodEntry:
    jwk_raw = raw.get("publicKeyJwk")
    jwk = None
    if jwk_raw is not None:
        if not isinstance(jwk_raw, dict):
            raise ValueError("publicKeyJwk must be an object")
        jwk = JWK(
            kty=str(jwk_raw.get("kty") or ""),
            crv=str(jwk_raw.get("crv") or ""),
            x=str(jwk_raw.get("x") or ""),
            y=str(jwk_raw.get("y") or ""),
            n=str(jwk_raw.get("n") or ""),
            e=str(jwk_raw.get("e") or ""),
        )
    revoked = raw.get("revoked")
    if isinstance(revoked, str):
        revoked = parse_rfc3339(revoked)
    elif revoked is not None and not isinstance(revoked, datetime):
        raise ValueError("revoked must be an RFC 3339 string")
    return VerificationMethodEntry(
        id=str(raw.get("id") or ""),
        type=str(raw.get("type") or ""),
        controller=str(raw.get("controller") or ""),
        public_key_hex=str(raw.get("publicKeyHex") or ""),
        public_key_jwk=jwk,
        public_key_multibase=str(raw.get("publicKeyMultibase") or ""),
        revoked=revoked,
        revocation_reason=str(raw.get("revocationReason") or ""),
    )


def did_document_from_dict(raw: dict[str, Any]) -> DIDDocument:
    """Build a DIDDocument from its JSON form (what an HTTP DID resolver returns)."""
    if not isinstance(raw, dict):
        raise ValueError("DID document must be a JSON object")
    ctx = raw.get("@context")
    return DIDDocument(
        id=str(raw.get("id") or ""),
        context=[ctx] if isinstance(ctx, str) else _str_list(ctx),
        verification_method=[vm_from_dict(v) for v in (raw.get("verificationMethod") or [])],
        authentication=_str_list(raw.get("authentication")),
        assertion_method=_str_list(raw.get("assertionMethod")),
        controller=raw.get("controller") or "",
        did_document_metadata=raw.get("didDocumentMetadata") or {},
    )


def coerce_document(doc: Any) -> DIDDocument:
    """Accept a DIDDocument or its JSON dict form."""
    if isinstance(doc, DIDDocument):
        return doc
    if isinstance(doc, dict):
        return did_document_from_dict(doc)
    raise ValueError("did document is nil")


def coerce_vm(vm: Any) -> VerificationMethodEntry | None:
    if vm is None or isinstance(vm, VerificationMethodEntry):
        return vm
    if isinstance(vm, dict):
        return vm_from_dict(vm)
    raise TypeError(f"unsupported verification method type: {type(vm).__name__}")
