"""Checks shared by the JWT (VC 1.1) and JOSE (vc-jose-cose) credentials: ports of the
unexported helpers in Go credential/vc (json_credential.go, credential.go)."""
from __future__ import annotations

import re
from typing import Any

from credential.common.sdjwt import carries_sd_machinery
from credential.vc import credential_helper as helper

CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
CREDENTIAL_SUBJECT_PROPERTY = "credentialSubject"
SDJWT_REQUIRES_JOSE_MSG = (
    "selective disclosure is supported only as vc+sd-jwt; use NewJOSECredential / ParseJOSECredential"
)

_JWT_RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$")

# Properties a verifier decides on; they must come out of the signed payload.
SECURED_CLAIMS = (
    "@context", "type", "issuer", "validFrom", "validUntil", "issuanceDate", "expirationDate", "credentialStatus",
)


def is_jwt_credential(val: str) -> bool:
    # Go: strings.Trim(val, "\"") then regexp `$` (no trailing-newline allowance)
    return _JWT_RE.fullmatch(val.strip('"')) is not None


def carries_sdjwt(m: dict[str, Any]) -> bool:
    """_sd_alg (root or under vc), an _sd array, or an array element {"...": digest}, at any depth."""
    if "_sd_alg" in m:
        return True
    vc = m.get("vc")
    if isinstance(vc, dict) and "_sd_alg" in vc:
        return True
    return carries_sd_machinery(m)


def require_v2_context(v: Any) -> None:
    first = ""
    if isinstance(v, str):
        first = v
    elif isinstance(v, list) and v and isinstance(v[0], str):
        first = v[0]
    if first != CREDENTIALS_V2_CONTEXT:
        raise ValueError(f'credential must name "{CREDENTIALS_V2_CONTEXT}" first in @context, got "{first}"')


def require_credential_type(v: Any) -> None:
    if helper.has_type(v, "VerifiableCredential"):
        return
    raise ValueError(f"credential type must include VerifiableCredential, got {v}")


def require_jose_credential(m: dict[str, Any]) -> None:
    helper.require_credential_properties(m)
    require_v2_context(m.get("@context"))
    require_credential_type(m.get("type"))


def require_secured_claims_signed(signed: dict[str, Any], reconstructed: dict[str, Any]) -> None:
    for claim in SECURED_CLAIMS:
        if claim in signed:
            continue
        if claim in reconstructed:
            raise ValueError(
                f'"{claim}" was selectively disclosed; a verifier decides on it, so it must be part of the signed payload'
            )
    if "_sd" in signed:
        raise ValueError(
            "the signed payload hides top-level properties behind _sd; selective disclosure is for claims inside credentialSubject"
        )


def require_disclosable_at_top_level(m: dict[str, Any], subject_may_disclose: bool) -> None:
    if "_sd" in m:
        raise ValueError(
            "the payload carries _sd at the root; selective disclosure — and the decoy digests that pad it — "
            "belong to claims inside credentialSubject, because nothing at the top level may be withheld"
        )
    for name, value in m.items():
        if name == CREDENTIAL_SUBJECT_PROPERTY and subject_may_disclose:
            continue
        if carries_sd_machinery(value):
            raise ValueError(
                f'selective disclosure is not permitted in "{name}"; only claims inside {CREDENTIAL_SUBJECT_PROPERTY} may be withheld'
            )


def refuse_overwrite(current: str, options: Any) -> None:
    if current == "" or options.replace_proof:
        return
    raise ValueError(
        "credential is already signed; signing again would replace that signature — "
        "pass WithReplaceProof to do so deliberately"
    )


def reject_build_time_options(o: Any) -> None:
    if o.verification_method_key != "":
        raise ValueError(
            "WithVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when the "
            "token was built — pass the option to NewJWTCredential or NewJOSECredential"
        )
    if o.has_sd_options():
        raise ValueError(
            "SD-JWT options cannot be applied when signing: the disclosures were fixed when the token was built — "
            "pass them to NewJOSECredential"
        )


def execute_common_options(payload_data: dict[str, Any], options: Any) -> None:
    """Schema + revocation checks (Go runs them in an errgroup; first error wins)."""
    if options.is_validate_schema:
        try:
            helper.validate_credential(payload_data, options)
        except Exception as exc:
            raise ValueError(f"credential verification failed: validate credential: {exc}") from exc
    if options.is_check_revocation:
        try:
            helper.check_revocation(payload_data)
        except Exception as exc:
            raise ValueError(f"credential verification failed: check revocation: {exc}") from exc
