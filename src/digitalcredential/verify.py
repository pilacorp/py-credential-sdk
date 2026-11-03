from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from credential.common.sdjwt.helper import b64url_decode
from credential.common.sdjwt.reconstruct import reconstruct
from digitalcredential.credential import Credential
from digitalcredential.errors import DigitalCredentialError, MALFORMED
from digitalcredential.issue import NEVER_DISCLOSABLE, TYP_DC_SD_JWT
from digitalcredential.issuerkey import Resolver, select_key
from digitalcredential.jws_compact import p256_from_jwk, peek_header, verify_compact_jws
from digitalcredential.present import TYP_KB_JWT
from digitalcredential.split import sd_hash, split_sd_jwt


def verify_credential(c: Credential, resolver: Resolver, opts: dict[str, Any] | None = None) -> dict[str, Any]:
    opts = opts or {}
    algs = opts.get("allowed_algs") or ["ES256"]
    parts = split_sd_jwt(c.compact)
    header = peek_header(str(parts["issuer_jwt"]))
    if header.get("typ") != TYP_DC_SD_JWT:
        raise DigitalCredentialError("TYP_INVALID", f"typ {header.get('typ')!r} is not {TYP_DC_SD_JWT}")
    if header.get("alg") and header["alg"] not in algs:
        raise DigitalCredentialError("ALG_NOT_ALLOWED", f"alg {header['alg']} is not allowed")
    payload = json.loads(b64url_decode(str(parts["issuer_jwt"]).split(".")[1]))
    iss = payload.get("iss") if isinstance(payload.get("iss"), str) else ""
    accepted = opts.get("accepted_issuers")
    if accepted and iss not in accepted:
        raise DigitalCredentialError("ISSUER_NOT_ACCEPTED", "iss is not an issuer in WithAcceptedIssuers")
    try:
        keys = resolver.keys(iss)
    except Exception as exc:
        raise DigitalCredentialError("ISSUER_NOT_SUPPORTED", str(exc)) from exc
    pub = select_key(keys, header.get("kid") if isinstance(header.get("kid"), str) else None)
    try:
        verify_compact_jws(str(parts["issuer_jwt"]), pub.public_key, algs)
    except Exception as exc:
        raise DigitalCredentialError("SIGNATURE_INVALID", "Issuer-signed JWT signature invalid") from exc
    try:
        claims = reconstruct(payload, list(parts["disclosures"]), True)
    except Exception as exc:
        raise DigitalCredentialError("DISCLOSURE_INVALID", str(exc)) from exc
    for name in NEVER_DISCLOSABLE:
        if name not in payload and name in claims:
            raise DigitalCredentialError("DISCLOSURE_INVALID", f"claim {name} came in a Disclosure")
    now = int((opts.get("now") or datetime.now(timezone.utc)).timestamp())
    skew = opts.get("clock_skew_seconds", 60)
    if isinstance(claims.get("exp"), int) and now >= claims["exp"] + skew:
        raise DigitalCredentialError("EXPIRED", "credential is expired")
    if isinstance(claims.get("nbf"), int) and now < claims["nbf"] - skew:
        raise DigitalCredentialError("NOT_YET_VALID", "credential is not yet valid")
    vct = claims.get("vct")
    if not isinstance(vct, str) or not vct:
        raise DigitalCredentialError(MALFORMED, "vct is absent or not a non-empty string")
    kb = str(parts["kb_jwt"])
    key_bound = False
    has_cnf = bool(payload.get("cnf"))
    if kb:
        cnf = payload.get("cnf") or {}
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not jwk:
            raise DigitalCredentialError("KB_UNSUPPORTED", "no cnf.jwk to check Key Binding")
        kb_payload = verify_compact_jws(kb, p256_from_jwk(jwk), algs)
        if peek_header(kb).get("typ") != TYP_KB_JWT:
            raise DigitalCredentialError("KB_INVALID", "KB JWT typ must be kb+jwt")
        presented = c.compact[: -len(kb)] if c.compact.endswith(kb) else f"{parts['issuer_jwt']}~"
        if kb_payload.get("sd_hash") != sd_hash(presented):
            raise DigitalCredentialError("KB_SD_HASH_MISMATCH", "sd_hash mismatch")
        if opts.get("audience") and kb_payload.get("aud") != opts["audience"]:
            raise DigitalCredentialError("KB_AUDIENCE_MISMATCH", "KB aud mismatch")
        if opts.get("nonce") and kb_payload.get("nonce") != opts["nonce"]:
            raise DigitalCredentialError("KB_NONCE_MISMATCH", "KB nonce mismatch")
        key_bound = True
    elif has_cnf or opts.get("require_key_binding"):
        raise DigitalCredentialError("KB_MISSING", "Key Binding JWT is required")
    if claims.get("status") is not None and not opts.get("skip_status") and not opts.get("status"):
        raise ValueError("the credential has a status_list: pass status or skipStatus")
    return {"issuer": iss or None, "vct": vct, "claims": claims, "key_bound": key_bound}
