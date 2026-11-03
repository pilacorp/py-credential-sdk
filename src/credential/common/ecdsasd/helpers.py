from __future__ import annotations

from typing import Any


def deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return deep_copy_map(value)
    if isinstance(value, list):
        return [deep_copy(v) for v in value]
    return value


def deep_copy_map(m: dict[str, Any]) -> dict[str, Any]:
    return {k: deep_copy(v) for k, v in m.items()}
