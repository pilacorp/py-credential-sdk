from __future__ import annotations

from hashlib import sha256

from digitalcredential.errors import MALFORMED, DigitalCredentialError

MAX_BYTES = 1 << 20
MAX_DISCLOSURES = 1000


def split_sd_jwt(compact: str) -> dict[str, object]:
    if len(compact) > MAX_BYTES:
        raise DigitalCredentialError(MALFORMED, f"SD-JWT of {len(compact)} bytes, at most {MAX_BYTES}")
    parts = compact.split("~")
    tildes = len(parts) - 1
    if tildes == 0:
        raise DigitalCredentialError(MALFORMED, "sdjwt: no ~ separator")
    if tildes - 1 > MAX_DISCLOSURES:
        raise DigitalCredentialError(MALFORMED, "too many disclosures")
    issuer_jwt, kb_jwt = parts[0], parts[-1]
    if not _is_compact_jws(issuer_jwt):
        raise DigitalCredentialError(MALFORMED, "Issuer-signed JWT is not three non-empty dot-separated parts")
    if kb_jwt != "" and not _is_compact_jws(kb_jwt):
        raise DigitalCredentialError(MALFORMED, "the part after the last ~ is not a JWT (missing trailing ~?)")
    disclosures = parts[1:-1]
    seen: set[str] = set()
    for i, item in enumerate(disclosures):
        if not item:
            raise DigitalCredentialError(MALFORMED, f"empty disclosure at position {i + 1}")
        if item in seen:
            raise DigitalCredentialError(MALFORMED, "disclosure given twice")
        seen.add(item)
    return {"issuer_jwt": issuer_jwt, "disclosures": disclosures, "kb_jwt": kb_jwt}


def sd_hash(sd_jwt: str) -> str:
    import base64

    digest = sha256(sd_jwt.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _is_compact_jws(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 3 and all(parts)
