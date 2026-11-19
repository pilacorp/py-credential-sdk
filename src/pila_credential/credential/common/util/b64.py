"""Strict base64 helpers matching Go's encoding/base64 RawURLEncoding / StdEncoding."""

from __future__ import annotations

import base64
import binascii
import re

_URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_decode(s: str, *, strict: bool = False) -> bytes:
    """Go ``base64.RawURLEncoding.DecodeString``: no padding, URL alphabet only.

    ``strict=True`` is Go's ``.Strict()``: the unused trailing bits must be zero."""
    if not _URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("illegal base64url data")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if strict and b64url_encode(raw) != s:
        raise ValueError("illegal base64url data: non-zero trailing bits")
    return raw


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64std_decode(s: str) -> bytes:
    """Go ``base64.StdEncoding.DecodeString`` (padding required, no stray characters)."""
    try:
        return base64.b64decode(s, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"illegal base64 data: {exc}") from exc
