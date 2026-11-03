from __future__ import annotations

import json
from typing import Any

from credential.common.sdjwt.helper import b64url_decode, parse_disclosure
from credential.common.sdjwt.reconstruct import reconstruct
from digitalcredential.credential import Credential
from digitalcredential.errors import DigitalCredentialError
from digitalcredential.jws_compact import p256_from_jwk, sign_compact_jws
from digitalcredential.split import sd_hash, split_sd_jwt

TYP_KB_JWT = "kb+jwt"


def present_credential(c: Credential, req: dict[str, Any]) -> Credential:
    if not c.compact:
        raise ValueError("Present on a nil or zero Credential")
    parts = split_sd_jwt(c.compact)
    if parts["kb_jwt"]:
        raise ValueError("Present takes an SD-JWT, not an SD-JWT+KB")
    issuer_jwt = str(parts["issuer_jwt"])
    disclosures = list(parts["disclosures"])
    payload = json.loads(b64url_decode(issuer_jwt.split(".")[1]))
    names = {p[0] for p in (req.get("reveal") or []) if p and isinstance(p[0], str)}
    selected: list[str] = []
    if names:
        for item in disclosures:
            decoded = parse_disclosure(item)
            if decoded.object_field in names:
                selected.append(decoded.raw)
    compact = issuer_jwt + "~"
    for d in selected:
        compact += d + "~"
    kb = req.get("key_binding")
    if kb:
        reconstruct(payload, disclosures, True)
        cnf = payload.get("cnf") or {}
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not jwk:
            raise ValueError("credential has no cnf.jwk for Key Binding")
        p256_from_jwk(jwk)
        if not kb.get("audience") or not kb.get("nonce"):
            raise ValueError("KeyBinding audience and nonce are required")
        extra = dict(kb.get("claims") or {})
        for forbidden in ("iat", "aud", "nonce", "sd_hash"):
            if forbidden in extra:
                raise ValueError(f"KeyBinding claims must not hold {forbidden}")
        kb_payload = {
            **extra,
            "iat": int(kb["issued_at"].timestamp()),
            "aud": kb["audience"],
            "nonce": kb["nonce"],
            "sd_hash": sd_hash(compact),
        }
        compact += sign_compact_jws({"alg": "ES256", "typ": TYP_KB_JWT}, kb_payload, kb["signer"])
    return Credential(compact)
