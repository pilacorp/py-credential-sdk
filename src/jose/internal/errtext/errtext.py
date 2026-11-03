"""Bounded quoting for error messages."""

from __future__ import annotations

import json

_MAX_BYTES = 32


def quote(s: str) -> str:
    if len(s) <= _MAX_BYTES:
        return json.dumps(s)
    cut = _MAX_BYTES
    while cut > 0 and (s[cut] & 0xC0) == 0x80:
        cut -= 1
    return json.dumps(s[:cut]) + "..."
