"""Strict JSON for JOSE headers and claims (RFC 8259, RFC 7515 §10.12)."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

from jose.errors import ErrInvalidArgument, ErrMalformed
from jose.internal.errtext import quote

MAX_JSON_DEPTH = 64


class JsonNumber(str):
    """JSON number kept as decimal digits (like Go json.Number)."""

    def as_float(self) -> float:
        return float(self)

    def as_int(self) -> int:
        return int(Decimal(self))


def decode_json(data: bytes) -> Any:
    if not _valid_utf8(data):
        raise ErrMalformed("JSON is not valid UTF-8")
    try:
        text = data.decode("utf-8")
        dec = json.JSONDecoder(
            object_pairs_hook=lambda p: _object_hook(p, _depth=0),
            parse_float=JsonNumber,
            parse_int=JsonNumber,
        )
        v, end = dec.raw_decode(text, 0)
        v = _normalize_numbers(v)
        _check_depth(v, 0)
    except json.JSONDecodeError as e:
        raise ErrMalformed(f"JSON: {e.msg}") from e
    except _JSONStrictError as e:
        raise ErrMalformed(f"JSON: {e}") from e
    rest = text[end:]
    if rest.strip():
        raise ErrMalformed("JSON: data after the value")
    return v


def decode_json_object(data: bytes) -> dict[str, Any]:
    v = decode_json(data)
    if not isinstance(v, dict):
        raise ErrMalformed("JSON value is not an object")
    return v


def decode_json_string_member(data: bytes, name: str) -> tuple[str, bool]:
    if not _valid_utf8(data):
        raise ErrMalformed("JSON is not valid UTF-8")
    try:
        text = data.decode("utf-8")
        json.loads(text)
    except json.JSONDecodeError as e:
        raise ErrMalformed(f"JSON: {e.msg}") from e
    i = _skip_json_space(text, 0)
    if i >= len(text) or text[i] != "{":
        raise ErrMalformed("JSON value is not an object")
    member: str | None = None
    found = False
    i = _skip_json_space(text, i + 1)
    while text[i] != "}":
        key_end = _end_json_string(text, i)
        key_body = text[i + 1 : key_end - 1]
        is_name = _json_string_is(key_body, name)
        i = _skip_json_space(text, _skip_json_space(text, key_end) + 1)
        val_end = _end_json_value(text, i)
        if is_name:
            if found:
                raise ErrMalformed(f"JSON: duplicate key {quote(name)}")
            member = text[i:val_end]
            found = True
        i = _skip_json_space(text, val_end)
        if text[i] == ",":
            i = _skip_json_space(text, i + 1)
    if not found:
        return "", False
    assert member is not None
    if not member.startswith('"'):
        raise ErrMalformed(f"JSON: member {quote(name)} is {_json_kind(member[0])}, not a string")
    s = decode_json(member.encode("utf-8"))
    return s, True


def encode_json(v: Any) -> bytes:
    try:
        out = json.dumps(
            v,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            default=_encode_default,
        ).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ErrInvalidArgument(f"encode JSON: {e}") from e
    if not _valid_utf8(out):
        raise ErrInvalidArgument(
            "encode JSON: a value gave bytes that are not UTF-8, and JSON must be UTF-8 (RFC 8259 §8.1); make it write UTF-8"
        )
    return out


class _JSONStrictError(Exception):
    pass


def _encode_default(obj: Any) -> Any:
    if isinstance(obj, JsonNumber):
        return str(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _object_hook(pairs: list[tuple[str, Any]], *, _depth: int = 0) -> dict[str, Any]:
    if _depth >= MAX_JSON_DEPTH:
        raise _JSONStrictError(f"nesting deeper than {MAX_JSON_DEPTH}")
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise _JSONStrictError(f"duplicate key {quote(key)}")
        obj[key] = val
    return obj


def _check_depth(v: Any, depth: int) -> None:
    if depth >= MAX_JSON_DEPTH and isinstance(v, (dict, list)):
        raise _JSONStrictError(f"nesting deeper than {MAX_JSON_DEPTH}")
    if isinstance(v, dict):
        for child in v.values():
            _check_depth(child, depth + 1)
    elif isinstance(v, list):
        for child in v:
            _check_depth(child, depth + 1)


def _normalize_numbers(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _normalize_numbers(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_normalize_numbers(x) for x in v]
    return v


def _valid_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _skip_json_space(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t\n\r":
        i += 1
    return i


def _end_json_string(text: str, i: int) -> int:
    j = i + 1
    while True:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1


def _end_json_value(text: str, i: int) -> int:
    c = text[i]
    if c == '"':
        return _end_json_string(text, i)
    if c in "{[":
        depth = 0
        for j in range(i, len(text)):
            ch = text[j]
            if ch == '"':
                j = _end_json_string(text, j) - 1
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 0:
                    return j + 1
        raise IndexError("unclosed composite")
    j = i
    while j < len(text) and text[j] not in ",}]" and text[j] not in " \t\n\r":
        j += 1
    return j


def _json_string_is(body: str, name: str) -> bool:
    try:
        decoded = json.loads(f'"{body}"')
    except json.JSONDecodeError:
        return False
    return decoded == name


def _json_kind(c: str) -> str:
    if c == "{":
        return "an object"
    if c == "[":
        return "an array"
    if c in "tf":
        return "a boolean"
    if c == "n":
        return "null"
    return "a number"


