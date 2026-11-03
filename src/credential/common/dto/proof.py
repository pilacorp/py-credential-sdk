from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StringOrStrings:
    values: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Any) -> StringOrStrings:
        if data is None:
            return cls([])
        if isinstance(data, str):
            return cls([data])
        if isinstance(data, list):
            return cls([str(x) for x in data])
        raise TypeError("domain/previousProof must be string or list of strings")

    def to_json(self) -> Any:
        if len(self.values) == 1:
            return self.values[0]
        return list(self.values)


@dataclass
class Proof:
    id: str = ""
    type: str = ""
    created: str = ""
    expires: str = ""
    verification_method: str = ""
    proof_purpose: str = ""
    cryptosuite: str = ""
    challenge: str = ""
    domain: StringOrStrings = field(default_factory=StringOrStrings)
    nonce: str = ""
    previous_proof: StringOrStrings = field(default_factory=StringOrStrings)
    proof_value: str = ""
    jws: str = ""
    signature: bytes = field(default_factory=bytes, repr=False)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_map(self) -> dict[str, Any]:
        out = dict(self.extra)
        typed = {
            "id": self.id,
            "type": self.type,
            "created": self.created,
            "expires": self.expires,
            "verificationMethod": self.verification_method,
            "proofPurpose": self.proof_purpose,
            "cryptosuite": self.cryptosuite,
            "challenge": self.challenge,
            "nonce": self.nonce,
            "proofValue": self.proof_value,
            "jws": self.jws,
        }
        if self.domain.values:
            typed["domain"] = self.domain.to_json()
        if self.previous_proof.values:
            typed["previousProof"] = self.previous_proof.to_json()
        for key, value in typed.items():
            if value not in ("", None, [], {}):
                out[key] = value
        return out


def proof_from_map(m: dict[str, Any]) -> Proof:
    p = Proof()
    known = {
        "id",
        "type",
        "created",
        "expires",
        "verificationMethod",
        "proofPurpose",
        "cryptosuite",
        "challenge",
        "domain",
        "nonce",
        "previousProof",
        "proofValue",
        "jws",
    }
    for key, value in m.items():
        raw = json.dumps({key: value})
        try:
            obj = json.loads(raw)
            if key in known:
                _apply_field(p, key, obj[key])
            else:
                p.extra[key] = value
        except Exception:
            p.extra[key] = value
    return p


def _apply_field(p: Proof, key: str, value: Any) -> None:
    if key == "id":
        p.id = str(value)
    elif key == "type":
        p.type = str(value)
    elif key == "created":
        p.created = str(value)
    elif key == "expires":
        p.expires = str(value)
    elif key == "verificationMethod":
        p.verification_method = str(value)
    elif key == "proofPurpose":
        p.proof_purpose = str(value)
    elif key == "cryptosuite":
        p.cryptosuite = str(value)
    elif key == "challenge":
        p.challenge = str(value)
    elif key == "domain":
        p.domain = StringOrStrings.from_json(value)
    elif key == "nonce":
        p.nonce = str(value)
    elif key == "previousProof":
        p.previous_proof = StringOrStrings.from_json(value)
    elif key == "proofValue":
        p.proof_value = str(value)
    elif key == "jws":
        p.jws = str(value)
