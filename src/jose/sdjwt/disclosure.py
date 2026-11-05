"""SD-JWT disclosures (RFC 9901 §4.2)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from jose import base64 as jose_b64
from jose import json as jose_json
from jose.errors import ErrMalformed

KEY_SD = "_sd"
KEY_SD_ALG = "_sd_alg"
KEY_ELLIPSIS = "..."
SD_ALG_SHA256 = "sha-256"


@dataclass
class Disclosure:
    salt: str = ""
    name: str = ""
    value: Any = None
    array_element: bool = False
    encoded: str = ""
    digest: str = ""


def parse_disclosure(encoded: str) -> Disclosure:
    try:
        raw = jose_b64.decode_segment(encoded)
    except ErrMalformed as e:
        raise ErrMalformed(f"sdjwt: disclosure: {e}") from e
    try:
        v = jose_json.decode_json(raw)
    except ErrMalformed as e:
        raise ErrMalformed(f"sdjwt: disclosure: {e}") from e
    if not isinstance(v, list) or len(v) not in (2, 3):
        raise ErrMalformed("sdjwt: a disclosure is a JSON array of 2 or 3 items")
    if not isinstance(v[0], str):
        raise ErrMalformed("sdjwt: disclosure salt is not a string")
    d = Disclosure(salt=v[0], encoded=encoded, digest=digest_of(encoded))
    if len(v) == 2:
        d.array_element = True
        d.value = v[1]
        return d
    if not isinstance(v[1], str):
        raise ErrMalformed("sdjwt: disclosure claim name is not a string")
    if reserved(v[1]):
        raise ErrMalformed(f"sdjwt: disclosure claim name {v[1]!r} is reserved")
    d.name = v[1]
    d.value = v[2]
    return d


def reserved(name: str) -> bool:
    return name in (KEY_SD, KEY_SD_ALG, KEY_ELLIPSIS)


def digest_of(s: str) -> str:
    return jose_b64.encode_segment(hashlib.sha256(s.encode("utf-8", "surrogatepass")).digest())
