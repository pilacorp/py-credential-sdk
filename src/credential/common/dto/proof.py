from __future__ import annotations

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
        if isinstance(data, list) and all(isinstance(x, str) for x in data):
            return cls(list(data))
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


_STRING_FIELDS = {
    "id": "id",
    "type": "type",
    "created": "created",
    "expires": "expires",
    "verificationMethod": "verification_method",
    "proofPurpose": "proof_purpose",
    "cryptosuite": "cryptosuite",
    "challenge": "challenge",
    "nonce": "nonce",
    "proofValue": "proof_value",
    "jws": "jws",
}
_SET_FIELDS = {"domain": "domain", "previousProof": "previous_proof"}


def proof_from_map(m: dict[str, Any]) -> Proof:
    """Build a Proof; a property lands in its typed field only when the value fits the
    field's type (string / string-or-set-of-strings), else it is kept verbatim in
    ``extra`` so the proof configuration hashed at verification still matches the signer's.
    JSON null for a typed field means "not set" and is dropped (Go json semantics)."""
    p = Proof()
    for key, value in m.items():
        if key in _STRING_FIELDS:
            if value is None:
                continue
            if isinstance(value, str):
                setattr(p, _STRING_FIELDS[key], value)
                continue
        elif key in _SET_FIELDS:
            if value is None:
                continue
            if isinstance(value, str):
                setattr(p, _SET_FIELDS[key], StringOrStrings([value]))
                continue
            if isinstance(value, list) and all(isinstance(x, str) for x in value):
                setattr(p, _SET_FIELDS[key], StringOrStrings(list(value)))
                continue
        p.extra[key] = value
    return p
