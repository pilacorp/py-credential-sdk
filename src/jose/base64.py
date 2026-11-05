"""Strict base64url (RFC 7515 §2, RFC 4648 §3.3 and §3.5)."""

from __future__ import annotations

import base64
import re

from jose.errors import ErrMalformed

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")


def encode_segment(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def decode_segment(s: str) -> bytes:
    """Decode unpadded base64url; every alternative spelling of the same bytes is ErrMalformed."""
    if "\r" in s or "\n" in s:
        raise ErrMalformed("base64url contains a line break")
    # '=' (padding), the standard alphabet and any other character are outside the alphabet.
    if not _B64URL_RE.fullmatch(s):
        raise ErrMalformed("base64url: illegal character")
    if len(s) % 4 == 1:
        raise ErrMalformed(f"base64url: number of data characters ({len(s)}) cannot be 1 more than a multiple of 4")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    # RFC 4648 §3.5: non-zero pad bits would give a second spelling ("QQ" and "QR" both -> "A").
    if encode_segment(b) != s:
        raise ErrMalformed("base64url: non-zero trailing bits")
    return b
