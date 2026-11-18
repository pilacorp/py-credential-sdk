from __future__ import annotations

import json
from typing import Any


def _no_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON number {name}")


def _strict_float(s: str) -> float:
    v = float(s)
    if v in (float("inf"), float("-inf")):
        raise ValueError(f"JSON number {s[:20]!r} is out of range")
    return v


def strict_loads(raw: str | bytes | bytearray) -> Any:
    """json.loads that refuses NaN, Infinity and numbers like 1e400, which json.dumps would write back as
    invalid JSON."""
    return json.loads(raw, parse_constant=_no_constant, parse_float=_strict_float)


def to_map(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = json.dumps(value).encode("utf-8")
    obj = strict_loads(raw)
    if not isinstance(obj, dict):
        raise TypeError("value is not a JSON object")
    return obj


def merge_custom_fields(value: Any, custom: dict[str, Any]) -> dict[str, Any]:
    out = to_map(value)
    for key, val in (custom or {}).items():
        if key not in out:
            out[key] = val
    return out


def shallow_copy_obj(obj: dict[str, Any]) -> dict[str, Any]:
    return dict(obj)


def deep_copy_map(src: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(src))


def copy_except(obj: dict[str, Any], *fields: str) -> dict[str, Any]:
    out = shallow_copy_obj(obj)
    for fld in fields:
        out.pop(fld, None)
    return out


def select(obj: dict[str, Any], *fields: str) -> dict[str, Any]:
    return {fld: obj[fld] for fld in fields if fld in obj}
