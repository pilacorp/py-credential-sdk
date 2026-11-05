from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from credential.common.jwt.jwtutil import b64url_decode, json_loads, numeric_claim
from credential.common.jwt.signing_method import alg_for_key_kind, verify_ecdsa, ALG_ES256, ALG_ES256K
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.common.verification_method.resolve import find_verification_method, format_rfc3339
from credential.common.verification_method.revocation import is_hard_revocation_reason
from credential.common.verification_method.selector import id_in_purpose_array, vm_key_kind
from credential.common.verification_method.verification_method import (
    DIDDocument,
    VerificationMethodEntry,
    coerce_document,
)

ASSERTION_METHOD = "assertionMethod"
AUTHENTICATION = "authentication"


class JWTVerifier:
    """Verifies compact JWS credentials/presentations. Always enforces the strict
    purpose + revocation check after crypto verification."""

    def __init__(self, doc_resolver: Any) -> None:
        self._resolver = doc_resolver

    def verify_jwt(self, token: str) -> None:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("invalid JWT format")

        try:
            header = json_loads(b64url_decode(parts[0]))
        except ValueError as exc:
            raise ValueError(f"invalid header: {exc}") from exc
        if not isinstance(header, dict):
            raise ValueError("invalid header: not a JSON object")

        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in (ALG_ES256K, ALG_ES256):
            raise ValueError(f"unsupported algorithm: {alg}")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise ValueError("kid not found in header")
        if self._resolver is None:
            raise ValueError("document resolver is not configured")

        # The payload decides the purpose (assertionMethod for a credential,
        # authentication for a presentation), which names the signer property;
        # both are read before any key is resolved.
        purpose = jwt_proof_purpose(header, parts[1])
        issuer = jwt_signer(parts[1], purpose)

        # Resolve the document of the signer the body names, not the DID prefix of
        # kid; find_verification_method rejects a kid that is not in that document.
        try:
            doc = coerce_document(self._resolver.resolve_document(issuer))
        except Exception as exc:
            raise ValueError(f"failed to resolve DID document for issuer '{issuer}': {exc}") from exc
        try:
            vm = find_verification_method(doc, kid)
        except ValueError as exc:
            raise ValueError(f"failed to resolve verification method: {exc}") from exc

        kind, ok = vm_key_kind(vm)
        if not ok:
            raise ValueError(f"verification method '{vm.id}' has an unrecognized key type")
        try:
            want_alg = alg_for_key_kind(kind)
        except ValueError as exc:
            raise ValueError(f"verification method '{vm.id}': {exc}") from exc
        if alg != want_alg:
            raise ValueError(
                f'JWT alg "{alg}" does not match verification method \'{vm.id}\', which holds a {kind} key'
            )
        try:
            public_key = ec_pub_from_vm(vm)
        except ValueError as exc:
            raise ValueError(f"invalid public key: {exc}") from exc

        signing_string = parts[0] + "." + parts[1]
        try:
            signature = b64url_decode(parts[2])
        except ValueError as exc:
            raise ValueError(f"invalid signature: {exc}") from exc
        verify_ecdsa(signing_string, signature, public_key)

        issued_at = jwt_issued_at(parts[1])
        strict_purpose_check(doc, vm, purpose, issued_at)


def _payload_object(payload_b64: str) -> dict[str, Any]:
    try:
        raw = b64url_decode(payload_b64)
    except ValueError as exc:
        raise ValueError(f"invalid payload encoding: {exc}") from exc
    try:
        body = json_loads(raw)
    except ValueError as exc:
        raise ValueError(f"invalid payload JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise ValueError("invalid payload JSON: not a JSON object")
    return body


def jwt_proof_purpose(header: dict[str, Any], payload_b64: str) -> str:
    """The proofPurpose to enforce. The payload decides, not the header: a typ that
    contradicts the payload is refused; when only one speaks, that one answers."""
    body = _payload_object(payload_b64)
    carried = purpose_from_body(body)
    declared = purpose_from_typ(header)
    if carried and declared and carried != declared:
        raise ValueError(
            f'JWT typ "{header.get("typ")}" implies proofPurpose "{declared}" but its payload is a {document_kind(carried)}'
        )
    if carried:
        return carried
    if declared:
        return declared
    raise ValueError("JWT has neither vc/vp claims nor vc+jwt/vp+jwt typ; cannot determine proofPurpose")


def purpose_from_typ(header: dict[str, Any]) -> str:
    """Media types vc-jose-cose gives the two kinds. Must cover every typ the
    parsers accept (vc.is_jose_credential_typ / vp.is_jose_presentation_typ)."""
    typ = header.get("typ")
    if typ in ("vc+jwt", "application/vc+jwt", "vc+sd-jwt", "application/vc+sd-jwt"):
        return ASSERTION_METHOD
    if typ in ("vp+jwt", "application/vp+jwt"):
        return AUTHENTICATION
    return ""


def purpose_from_body(body: dict[str, Any]) -> str:
    has_vc, has_vp = "vc" in body, "vp" in body
    if has_vc and has_vp:
        raise ValueError("JWT carries both vc and vp claims; its kind is ambiguous")
    if has_vc:
        return ASSERTION_METHOD
    if has_vp:
        return AUTHENTICATION
    t = body.get("type")
    if isinstance(t, list):
        # Every entry has to agree; the order of the array must not pick the purpose.
        found = ""
        for v in t:
            p = purpose_from_type(v if isinstance(v, str) else "")
            if not p:
                continue
            if found and found != p:
                raise ValueError("JWT type names both a credential and a presentation; its kind is ambiguous")
            found = p
        return found
    if isinstance(t, str):
        return purpose_from_type(t)
    return ""


def purpose_from_type(t: str) -> str:
    if t == "VerifiableCredential":
        return ASSERTION_METHOD
    if t == "VerifiablePresentation":
        return AUTHENTICATION
    return ""


def document_kind(purpose: str) -> str:
    return "credential" if purpose == ASSERTION_METHOD else "presentation"


def did_from_claim(v: Any) -> str:
    """A DID out of a property that is either a string or an object with a string id."""
    if isinstance(v, str):
        return v
    if isinstance(v, dict) and isinstance(v.get("id"), str):
        return v["id"]
    return ""


def jwt_signer(payload_b64: str, purpose: str) -> str:
    """The DID whose key signed the JWT; refuses an iss that disagrees with the
    issuer (VC) / holder (VP) property, also when nested under vc/vp."""
    body = _payload_object(payload_b64)
    field = "issuer" if purpose == ASSERTION_METHOD else "holder"

    doc: dict[str, Any] = body
    if isinstance(body.get("vc"), dict):
        doc = body["vc"]
    elif isinstance(body.get("vp"), dict):
        doc = body["vp"]

    # Go's encoding/json matches struct fields case-insensitively, so "Holder" is
    # absent to an exact-key read yet lands in the holder field downstream.
    for k in doc:
        if k != field and k.casefold() == field.casefold():
            raise ValueError(f'JWT carries "{k}", which differs from {field} only by case')

    present = field in doc
    claimed = did_from_claim(doc.get(field))
    if present and claimed == "":
        raise ValueError(
            f"JWT {field} must be a string or an object with a string id, got {_go_type(doc.get(field))}"
        )

    iss = body.get("iss")
    iss = iss if isinstance(iss, str) else ""
    if iss and claimed and iss != claimed:
        raise ValueError(f'JWT iss "{iss}" does not match {field} "{claimed}"')
    if iss:
        return iss
    if claimed:
        return claimed
    raise ValueError(f"JWT names no signer: both iss and {field} are absent")


def _go_type(v: Any) -> str:
    return {type(None): "<nil>", bool: "bool", int: "float64", float: "float64", list: "[]interface {}",
            dict: "map[string]interface {}", str: "string"}.get(type(v), type(v).__name__)


def jwt_issued_at(payload_b64: str) -> datetime | None:
    """iat as a UTC datetime, or None when absent. No fallback to validFrom: iat is
    when the token was signed, validFrom when the document starts being true."""
    body = _payload_object(payload_b64)
    sec = numeric_claim(body, "iat")
    if sec is None:
        return None
    try:
        return datetime.fromtimestamp(sec, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"invalid iat value: {sec}") from exc


def strict_purpose_check(
    doc: DIDDocument, vm: VerificationMethodEntry, proof_purpose: str, issued_at: datetime | None
) -> None:
    """Post-crypto checks mirroring jsonmap.VerifyProof for embedded ECDSA proofs; the
    timestamp is iat since a JWT has no proof.created."""
    if is_hard_revocation_reason(vm.revocation_reason):
        raise ValueError(f"verification method '{vm.id}' revoked with hard reason '{vm.revocation_reason}'")
    if vm.revoked is not None:
        revoked = vm.revoked if vm.revoked.tzinfo else vm.revoked.replace(tzinfo=timezone.utc)
        if issued_at is None:
            raise ValueError(
                f"verification method '{vm.id}' was revoked at {format_rfc3339(revoked)} "
                "(missing iat for time-based revocation check)"
            )
        if not issued_at < revoked:
            raise ValueError(
                f"verification method '{vm.id}' was revoked at {format_rfc3339(revoked)}; "
                f"iat {format_rfc3339(issued_at)} is not earlier"
            )
    if proof_purpose == AUTHENTICATION:
        arr = doc.authentication
    elif proof_purpose == ASSERTION_METHOD:
        arr = doc.assertion_method
    else:
        raise ValueError(f"unsupported proofPurpose '{proof_purpose}'")
    if not id_in_purpose_array(vm.id, doc.id, arr):
        raise ValueError(f"verification method '{vm.id}' is not granted purpose '{proof_purpose}' on DID '{doc.id}'")
