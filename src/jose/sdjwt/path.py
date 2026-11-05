"""Claim paths for SD-JWT."""

from __future__ import annotations

from typing import Any

from jose.errors import ErrInvalidArgument
from jose.internal.errtext.errtext import _go_quote

Path = list[Any]


def validate_path(p: Path) -> None:
    if len(p) == 0:
        raise ErrInvalidArgument("sdjwt: empty path")
    for el in p:
        if isinstance(el, str):
            continue
        if isinstance(el, int) and not isinstance(el, bool):
            if el < 0:
                raise ErrInvalidArgument(f"sdjwt: path {format_path(p)} has a negative index")
            continue
        raise ErrInvalidArgument(f"sdjwt: path {format_path(p)} has an element of type {type(el).__name__}, want string or int")


def format_path(p: Path, quote=_go_quote) -> str:
    parts: list[str] = []
    for el in p:
        if isinstance(el, str):
            parts.append(quote(el))
        elif isinstance(el, int) and not isinstance(el, bool):
            parts.append(str(el))
        else:
            parts.append(type(el).__name__)
    return "[" + ",".join(parts) + "]"


def compare_paths(a: Path, b: Path) -> int:
    if len(a) != len(b):
        return len(b) - len(a)
    for i in range(len(a)):
        ae, be = a[i], b[i]
        if isinstance(ae, str) and isinstance(be, str):
            if ae != be:
                return -1 if ae < be else 1
        elif isinstance(ae, str):
            return -1
        elif isinstance(be, str):
            return 1
        else:
            if ae != be:
                return -1 if ae < be else 1
    return 0


def child_path(p: Path, el: Any) -> Path:
    return p + [el]


def lookup(v: Any, p: Path) -> tuple[Any, bool]:
    cur = v
    for el in p:
        if isinstance(el, str):
            if not isinstance(cur, dict) or el not in cur:
                return None, False
            cur = cur[el]
        elif isinstance(el, int) and not isinstance(el, bool):
            if not isinstance(cur, list) or el < 0 or el >= len(cur):
                return None, False
            cur = cur[el]
        else:
            return None, False
    return cur, True
