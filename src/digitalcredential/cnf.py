from __future__ import annotations

from typing import Any

from digitalcredential.errors import DigitalCredentialError
from digitalcredential.jws_compact import p256_from_jwk

err_no_cnf = ValueError("dc: the credential has no cnf claim")


def cnf_key(cnf: Any) -> bytes:
    if not isinstance(cnf, dict):
        raise DigitalCredentialError("MALFORMED", "dc: cnf or cnf.jwk is not a JSON object")
    present = sum(1 for k in ("jwk", "jwe", "jku") if k in cnf)
    if present > 1:
        raise DigitalCredentialError("MALFORMED", "dc: cnf has more than one of jwk, jwe and jku")
    if "jwk" not in cnf:
        raise DigitalCredentialError("KB_UNSUPPORTED", "cnf has no jwk member")
    jwk = cnf["jwk"]
    if not isinstance(jwk, dict):
        raise DigitalCredentialError("MALFORMED", "dc: cnf.jwk is not a JSON object")
    if jwk.get("kty") == "oct":
        raise DigitalCredentialError("MALFORMED", "dc: cnf.jwk is a symmetric key in a JWT that is not encrypted")
    try:
        return p256_from_jwk({k: str(v) for k, v in jwk.items() if isinstance(v, str)})
    except ValueError as exc:
        msg = str(exc)
        if "P-256" in msg or "must be" in msg:
            raise DigitalCredentialError("KB_UNSUPPORTED", f"cnf.jwk holds an unsupported key: {exc}") from exc
        raise DigitalCredentialError("MALFORMED", f"dc: cnf.jwk is not a usable key: {exc}") from exc


def holder_key(payload: dict[str, Any], disclosed_paths: set[tuple[str, ...]] | None = None) -> bytes:
    if disclosed_paths and ("cnf",) in disclosed_paths or any(p and p[0] == "cnf" for p in disclosed_paths):
        raise DigitalCredentialError(
            "MALFORMED",
            "dc: cnf or a claim inside it is in a disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids",
        )
    cnf = payload.get("cnf")
    if cnf is None:
        raise err_no_cnf
    return cnf_key(cnf)
