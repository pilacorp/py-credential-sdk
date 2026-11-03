"""Strict base64url (RFC 7515 §2)."""

from __future__ import annotations

import base64
import binascii
import re

from jose.errors import ErrMalformed

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def encode_segment(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def decode_segment(s: str) -> bytes:
    if "\r" in s or "\n" in s:
        raise ErrMalformed("base64url contains a line break")
    if "=" in s:
        raise ErrMalformed(f"base64url: Invalid base64-encoded string: number of data characters ({len(s)}) cannot be 1 more than a multiple of 4")
    if not _B64URL_RE.match(s):
        raise ErrMalformed("base64url: character outside alphabet")
    pad = (-len(s)) % 4
    try:
        return base64.urlsafe_b64decode(s + ("=" * pad))
    except binascii.Error as e:
        raise ErrMalformed(f"base64url: {e}") from e
