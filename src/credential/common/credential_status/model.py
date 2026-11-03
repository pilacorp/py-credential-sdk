from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StatusListCredentialSubject:
    encoded_list: str
    id: str
    status_purpose: str
    type: str


@dataclass
class StatusListCredential:
    context: list[str] = field(default_factory=list)
    credential_subject: StatusListCredentialSubject | None = None
    id: str = ""
    issuer: str = ""
    proof: dict[str, Any] = field(default_factory=dict)
    type: list[str] = field(default_factory=list)
    valid_from: str = ""
    valid_until: str = ""


@dataclass
class StatusListCredentialResponse:
    data: StatusListCredential
