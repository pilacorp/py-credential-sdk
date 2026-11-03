from __future__ import annotations

from typing import Any


def serialize_credential_contents(vcc: dict[str, Any] | None) -> dict[str, Any]:
    if not vcc:
        raise ValueError("credential contents is nil")
    if not (vcc.get("@context") or vcc.get("id") or vcc.get("issuer")):
        raise ValueError("credential contents must have at least one of: context, ID, or issuer")
    out: dict[str, Any] = {}
    if vcc.get("@context"):
        out["@context"] = vcc["@context"]
    if vcc.get("id"):
        out["id"] = vcc["id"]
    if vcc.get("type"):
        out["type"] = vcc["type"]
    if vcc.get("credentialSubject"):
        out["credentialSubject"] = vcc["credentialSubject"]
    if vcc.get("issuer"):
        out["issuer"] = vcc["issuer"]
    if vcc.get("credentialSchema"):
        out["credentialSchema"] = vcc["credentialSchema"]
    if vcc.get("credentialStatus"):
        out["credentialStatus"] = vcc["credentialStatus"]
    if vcc.get("validFrom"):
        out["validFrom"] = vcc["validFrom"]
    if vcc.get("validUntil"):
        out["validUntil"] = vcc["validUntil"]
    return out
