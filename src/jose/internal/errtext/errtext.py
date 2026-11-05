"""Bounded quoting for error messages (Go internal/errtext)."""

from __future__ import annotations

_MAX_BYTES = 32
_SHORT = {7: "\\a", 8: "\\b", 12: "\\f", 10: "\\n", 13: "\\r", 9: "\\t", 11: "\\v", 34: '\\"', 92: "\\\\"}


def _go_quote(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if o in _SHORT:
            out.append(_SHORT[o])
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\x{o:02x}")
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\ufffd")
        elif ch.isprintable():
            out.append(ch)
        elif o < 0x10000:
            out.append(f"\\u{o:04x}")
        else:
            out.append(f"\\U{o:08x}")
    out.append('"')
    return "".join(out)


def quote(s: str) -> str:
    """strconv.Quote of s, cut to its first 32 UTF-8 bytes at a rune boundary, plus "..." when cut."""
    b = s.encode("utf-8", "replace")
    if len(b) <= _MAX_BYTES:
        return _go_quote(s)
    cut = _MAX_BYTES
    while cut > 0 and (b[cut] & 0xC0) == 0x80:
        cut -= 1
    return _go_quote(b[:cut].decode("utf-8", "replace")) + "..."
