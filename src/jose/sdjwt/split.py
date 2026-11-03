"""Split compact SD-JWT presentations (RFC 9901 §4)."""

from __future__ import annotations

from jose.errors import ErrMalformed
from jose.sdjwt.limits import MAX_BYTES, MAX_DISCLOSURES


def split(compact: str) -> tuple[str, list[str], str]:
    if len(compact) > MAX_BYTES:
        raise ErrMalformed(f"sdjwt: SD-JWT of {len(compact)} bytes, at most {MAX_BYTES}")
    tildes = compact.count("~")
    if tildes == 0:
        raise ErrMalformed("sdjwt: no ~ separator")
    if tildes - 1 > MAX_DISCLOSURES:
        raise ErrMalformed(f"sdjwt: {tildes - 1} disclosures, at most {MAX_DISCLOSURES}")
    parts = compact.split("~")
    issuer_jwt, kb_jwt = parts[0], parts[-1]
    if not _is_compact_jws(issuer_jwt):
        raise ErrMalformed("sdjwt: the Issuer-signed JWT is not three non-empty dot-separated parts")
    if kb_jwt and not _is_compact_jws(kb_jwt):
        raise ErrMalformed("sdjwt: the part after the last ~ is not a JWT (missing trailing ~?)")
    disclosures = parts[1:-1]
    seen: set[str] = set()
    for i, d in enumerate(disclosures):
        if d == "":
            raise ErrMalformed(f"sdjwt: empty disclosure at position {i + 1} (~~)")
        if d in seen:
            raise ErrMalformed(f"sdjwt: disclosure at position {i + 1} given twice")
        seen.add(d)
    return issuer_jwt, disclosures, kb_jwt


def _is_compact_jws(s: str) -> bool:
    header, _, rest = s.partition(".")
    payload, _, sig = rest.partition(".")
    return bool(header and payload and sig and "." not in sig)
