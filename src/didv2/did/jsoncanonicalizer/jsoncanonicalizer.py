"""RFC 8785 JSON Canonicalization Scheme, byte-compatible with Go didv2/did/jsoncanonicalizer.

Parity notes (Go -> Python):
- numbers are IEEE-754 doubles formatted by the ES6 rules (``number_to_json``); integers go through
  float64 too (so 2**63 hashes the same as in Go), NaN/Infinity are rejected;
- object members are sorted by UTF-16 code units; duplicate keys are rejected (Go: "Duplicate key");
- the top level must be an object or an array;
- strings are emitted as raw UTF-8 with only ``\\ " \\b \\f \\n \\r \\t`` and ``\\u00xx`` (lowercase) escapes.

ponytail: nesting depth is capped (Go has no cap); Go's lenient number grammar (``01``, ``+1``,
``.5``) is rejected here because ``json`` is strict.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

MAX_DEPTH = 200

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _reject_constant(name: str) -> Any:
    raise ValueError(f"canonicalizer: invalid number {name}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"canonicalizer: Duplicate key: {k}")
        out[k] = v
    return out


def transform(value: Any) -> bytes:
    """Canonicalize JSON text (str/bytes) or an already-parsed JSON value."""
    if isinstance(value, (bytes, bytearray)):
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("canonicalizer: input is not valid UTF-8") from exc
        parsed = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    elif isinstance(value, str):
        parsed = json.loads(value, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    else:
        parsed = value
    if not isinstance(parsed, (dict, list)):
        raise ValueError("canonicalizer: top-level value must be an object or an array")
    return serialize(parsed).encode("utf-8")


def serialize(value: Any, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise ValueError("canonicalizer: nesting exceeds maximum depth")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        try:
            return number_to_json(float(value))
        except OverflowError as exc:
            raise ValueError("canonicalizer: invalid number") from exc
    if isinstance(value, float):
        return number_to_json(value)
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(serialize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"canonicalizer: object key must be a string, got {type(k)}")
        keys = sorted(value, key=_utf16_key)
        return "{" + ",".join(_quote(k) + ":" + serialize(value[k], depth + 1) for k in keys) + "}"
    raise TypeError(f"canonicalizer: unsupported value type {type(value)}")


def _utf16_key(key: str) -> bytes:
    # big-endian UTF-16 compares bytewise exactly like the code-unit sequence
    return key.encode("utf-16-be", "surrogatepass")


def _quote(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def number_to_json(n: float) -> str:
    """ES6 Number.prototype.toString as used by Go NumberToJSON (-0 -> "0"; NaN/Inf rejected)."""
    if math.isnan(n) or math.isinf(n):
        raise ValueError("canonicalizer: Invalid JSON number")
    if n == 0:
        return "0"
    sign = "-" if n < 0 else ""
    n = abs(n)
    # repr() is the shortest round-trip digit string, as is Go's FormatFloat(.., -1, 64)
    _, digits_t, exp = Decimal(repr(n)).as_tuple()
    digits = "".join(map(str, digits_t)).rstrip("0") or "0"
    # value = 0.d1d2... * 10**point
    point = len(digits_t) + exp
    # strip leading zeros of the digit string (Decimal never has them for repr, but be safe)
    k = len(digits)
    if 1e-6 <= n < 1e21:
        if point <= 0:
            body = "0." + "0" * (-point) + digits
        elif point >= k:
            body = digits + "0" * (point - k)
        else:
            body = digits[:point] + "." + digits[point:]
    else:
        e = point - 1
        mant = digits[0] + ("." + digits[1:] if k > 1 else "")
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body
