"""RFC 8785 JSON Canonicalization Scheme (Go jsoncanonicalizer / TS transform)."""

from __future__ import annotations

import json
import math
import re
from typing import Any

MAX_DEPTH = 64


def transform(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        parsed = json.loads(bytes(value).decode("utf-8"))
    elif isinstance(value, str):
        parsed = json.loads(value)
    else:
        parsed = value
    return serialize(parsed).encode("utf-8")


def serialize(value: Any, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise ValueError("canonicalizer: nesting exceeds maximum depth")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return _number_to_json(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(serialize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_key)
        parts = [json.dumps(k, ensure_ascii=False) + ":" + serialize(value[k], depth + 1) for k in keys]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"canonicalizer: unsupported value type {type(value)}")


def _utf16_key(key: str) -> list[int]:
    return [ord(c) for c in key]


def _number_to_json(n: float) -> str:
    if math.isnan(n) or math.isinf(n):
        raise ValueError("canonicalizer: invalid number")
    if n == 0:
        return "0"
    text = format(n, ".16e")
    m = re.match(r"^(-?)(\d)\.(\d+)e([+-]\d+)$", text)
    if not m:
        return json.dumps(n)
    sign, d0, frac, exp = m.group(1), m.group(2), m.group(3), int(m.group(4))
    frac = frac.rstrip("0")
    if not frac:
        return f"{sign}{d0}e{exp}" if abs(n) >= 1e21 or (abs(n) < 1e-6 and n != 0) else f"{sign}{d0}"
    return json.dumps(n)
