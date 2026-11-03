from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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
