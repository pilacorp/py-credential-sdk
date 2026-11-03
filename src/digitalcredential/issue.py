from __future__ import annotations

from datetime import datetime
from typing import Any

from credential.common.sdjwt.disclosure import build_disclosures
from digitalcredential.credential import Credential
from digitalcredential.errors import DigitalCredentialError
from digitalcredential.issuerkey import SigningKey
from digitalcredential.jws_compact import encode_jwk_from_p256, sign_compact_jws

TYP_DC_SD_JWT = "dc+sd-jwt"
NEVER_DISCLOSABLE = {"iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"}


def issue(
    req: dict[str, Any],
    key: SigningKey,
) -> Credential:
    vct = req.get("vct")
    if not vct:
        raise ValueError("VCT is required")
    disclose = req.get("disclose") or []
    for path in disclose:
        first = path[0] if path else None
        if isinstance(first, str) and first in NEVER_DISCLOSABLE:
            raise ValueError(f"claim {first} MUST NOT be concealed")
    concealable = dict(req.get("claims") or {})
    if req.get("issued_at"):
        concealable["iat"] = int(req["issued_at"].timestamp())
    paths = [".".join(str(s) for s in p if isinstance(s, str)) for p in disclose]
    built = build_disclosures(concealable, paths)
    payload = dict(built["processed_vc"])
    if req.get("issuer"):
        payload["iss"] = req["issuer"]
    payload["vct"] = vct
    if req.get("not_before"):
        payload["nbf"] = int(req["not_before"].timestamp())
    if req.get("expiry"):
        payload["exp"] = int(req["expiry"].timestamp())
    if req.get("holder_key"):
        payload["cnf"] = {"jwk": encode_jwk_from_p256(req["holder_key"])}
    if req.get("status"):
        st = req["status"]
        if st["idx"] < 0 or not st.get("uri"):
            raise ValueError("status ref is invalid")
        payload["status"] = {"status_list": {"idx": st["idx"], "uri": st["uri"]}}
    if payload.get("cnf") and not payload.get("iss") and not payload.get("sub"):
        raise ValueError("a credential with cnf needs iss or sub")
    header: dict[str, Any] = {"alg": "ES256", "typ": TYP_DC_SD_JWT}
    if key.kid:
        header["kid"] = key.kid
    issuer_jwt = sign_compact_jws(header, payload, key.signer)
    compact = issuer_jwt + "~"
    for d in built["disclosures"]:
        compact += d + "~"
    return Credential(compact)
