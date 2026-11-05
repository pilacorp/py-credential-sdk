from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

ALG_SHA256 = "sha-256"
ALG_SHA384 = "sha-384"
ALG_SHA512 = "sha-512"
DEFAULT_HASH_ALGORITHM = ALG_SHA256
SUPPORTED = {ALG_SHA256: True, ALG_SHA384: True, ALG_SHA512: True}
JWT_RE = re.compile(r"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?")
_B64URL_RE = re.compile(r"[A-Za-z0-9\-_]*")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    """Strict base64url without padding, like Go's base64.RawURLEncoding.

    Rejects '=' padding, characters outside the alphabet (Python's default decoder
    silently discards them) and impossible lengths.
    """
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise ValueError("illegal base64url data")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def is_jwt(s: str) -> bool:
    """Regex check for header.payload[.signature] (Go isJWT)."""
    s = s.strip()
    if s.endswith("."):
        s = s[:-1]
    return JWT_RE.fullmatch(s) is not None


def is_sd_jwt(raw: str) -> bool:
    if not raw:
        return False
    s = raw.strip('"').strip()
    if "~" not in s:
        return False
    return is_jwt(s.split("~", 1)[0])


def hash_disclosure(sd_alg: str, disclosure: str) -> str:
    data = disclosure.encode("utf-8")
    if sd_alg == ALG_SHA256:
        digest = hashlib.sha256(data).digest()
    elif sd_alg == ALG_SHA384:
        digest = hashlib.sha384(data).digest()
    elif sd_alg == ALG_SHA512:
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


@dataclass
class DecodedDisclosure:
    """A decoded disclosure a holder can inspect (Go sdjwt.DecodedDisclosure)."""

    disclosure: str
    salt: str
    field_name: str
    value: Any
    is_array_elem: bool


@dataclass
class ParsedSDJWT:
    base_jwt: str
    disclosures: list[str] = field(default_factory=list)
    decoded_disclosures: list[DecodedDisclosure] = field(default_factory=list)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


def parse_disclosure(disc: str) -> DisclosureInfo:
    try:
        decoded = b64url_decode(disc)
    except ValueError as exc:
        raise ValueError(f"failed to decode disclosure {disc!r}: {exc}") from exc
    try:
        arr = json.loads(decoded.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"failed to unmarshal disclosure: {exc}") from exc
    if not isinstance(arr, list):
        raise ValueError("failed to unmarshal disclosure: not a JSON array")
    if len(arr) not in (2, 3):
        raise ValueError(f"invalid disclosure structure: expected 2 or 3 elements, got {len(arr)}")
    if not isinstance(arr[0], str):
        raise ValueError("disclosure salt must be a string")
    if len(arr) == 3:
        if not isinstance(arr[1], str):
            raise ValueError("disclosure field name must be a string")
        return DisclosureInfo(disc, arr[0], arr[1], arr[2], False)
    return DisclosureInfo(disc, arr[0], "", arr[1], True)


def decode_disclosures(disclosures: list[str]) -> list[DecodedDisclosure]:
    out: list[DecodedDisclosure] = []
    for disc in disclosures:
        if disc == "":
            continue
        info = parse_disclosure(disc)
        out.append(DecodedDisclosure(disc, info.salt, info.object_field, info.value, info.is_array_elem))
    return out


def parse(raw: str) -> ParsedSDJWT:
    """Split an SD-JWT into the issuer-signed JWT and its disclosures (Go sdjwt.Parse)."""
    if not is_sd_jwt(raw):
        raise ValueError("invalid SD-JWT format")
    s = raw.strip('"').strip()
    parts = s.split("~")
    if len(parts) < 2:
        raise ValueError("invalid SD-JWT: missing disclosures or terminator")
    disclosures: list[str] = []
    for i in range(1, len(parts)):
        seg = parts[i].strip()
        if seg == "":
            continue
        # A trailing JWT after the disclosures is a key binding JWT, which nothing
        # here verifies: refuse it rather than skip it silently.
        if i == len(parts) - 1 and is_jwt(seg) and i > 1:
            raise ValueError(
                "SD-JWT carries a key binding JWT, which this SDK does not verify yet; "
                "present the credential without it"
            )
        disclosures.append(seg)
    try:
        decoded = decode_disclosures(disclosures)
    except ValueError as exc:
        raise ValueError(f"failed to decode disclosures: {exc}") from exc
    return ParsedSDJWT(parts[0], disclosures, decoded)


def build_sd_jwt_presentation(issuer_signed_jwt: str, selected_disclosures: list[str] | None) -> str:
    """issuer-JWT~d1~d2~ ; the trailing '~' is always written (SD-JWT §4)."""
    out = [issuer_signed_jwt]
    for sel in selected_disclosures or []:
        if sel:
            out.append("~" + sel)
    out.append("~")
    return "".join(out)


def carries_sd_machinery(value: Any) -> bool:
    """True when value holds an `_sd` key or an array element {"...": digest}, at any depth."""
    if isinstance(value, dict):
        if "_sd" in value:
            return True
        return any(carries_sd_machinery(c) for c in value.values())
    if isinstance(value, list):
        for child in value:
            if isinstance(child, dict) and len(child) == 1 and "..." in child:
                return True
            if carries_sd_machinery(child):
                return True
    return False
