from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any

ALG_SHA256 = "sha-256"
DEFAULT_HASH_ALGORITHM = ALG_SHA256
SUPPORTED = {ALG_SHA256: True, "sha-384": True, "sha-512": True}
JWT_RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def is_jwt(s: str) -> bool:
    trimmed = s.strip().rstrip(".")
    return bool(JWT_RE.match(trimmed))


def is_sd_jwt(raw: str) -> bool:
    if not raw:
        return False
    s = raw.strip().strip('"')
    if "~" not in s:
        return False
    return is_jwt(s[: s.index("~")])


def hash_disclosure(sd_alg: str, disclosure: str) -> str:
    data = disclosure.encode("utf-8")
    if sd_alg == ALG_SHA256:
        digest = hashlib.sha256(data).digest()
    elif sd_alg == "sha-384":
        digest = hashlib.sha384(data).digest()
    elif sd_alg == "sha-512":
        digest = hashlib.sha512(data).digest()
    else:
        raise ValueError(f'unsupported sd_alg "{sd_alg}"')
    return b64url(digest)


def random_salt() -> str:
    return b64url(os.urandom(16))


@dataclass
class DisclosureInfo:
    raw: str
    salt: str
    object_field: str
    value: Any
    is_array_elem: bool


def parse_disclosure(disc: str) -> DisclosureInfo:
    arr = json.loads(b64url_decode(disc).decode("utf-8"))
    if not isinstance(arr, list) or len(arr) not in (2, 3):
        raise ValueError("invalid disclosure structure")
    if not isinstance(arr[0], str):
        raise ValueError("disclosure salt must be a string")
    if len(arr) == 3:
        if not isinstance(arr[1], str):
            raise ValueError("disclosure field name must be a string")
        return DisclosureInfo(disc, arr[0], arr[1], arr[2], False)
    return DisclosureInfo(disc, arr[0], "", arr[1], True)
