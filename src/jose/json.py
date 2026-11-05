"""Strict JSON for JOSE headers and claims (RFC 8259, RFC 7515 §10.12).

Mirrors go-credential-sdk/jose/json.go: duplicate keys rejected at any depth
(after unescaping), numbers kept as JsonNumber (every digit), nothing after the
value, valid UTF-8 only, nesting capped at MAX_JSON_DEPTH while reading.
"""

from __future__ import annotations

import re
from decimal import Decimal
from json.decoder import scanstring
from typing import Any

from jose.errors import ErrInvalidArgument, ErrMalformed
from jose.internal.errtext import quote

MAX_JSON_DEPTH = 64
# encoding/json's json.Valid limit, used by decode_json_string_member.
_MAX_VALID_DEPTH = 10000

_WS = " \t\n\r"
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_STRING_RE = re.compile(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')
_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")


class JsonNumber:
    """A JSON number kept as its literal text (Go json.Number).

    Deliberately not a str: a JSON number must never pass an isinstance(x, str) check.
    """

    __slots__ = ("_s",)

    def __init__(self, text: str) -> None:
        self._s = str(text)

    def __str__(self) -> str:
        return self._s

    def __repr__(self) -> str:
        return f"JsonNumber({self._s!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, JsonNumber) and other._s == self._s

    def __hash__(self) -> int:
        return hash(("JsonNumber", self._s))

    def as_float(self) -> float:
        return float(self._s)

    def as_int(self) -> int:
        return int(Decimal(self._s))


class _Strict(Exception):
    pass


def _fix_surrogates(s: str) -> str:
    # encoding/json reads an escaped surrogate that is not half of a pair as U+FFFD.
    return _LONE_SURROGATE_RE.sub("�", s) if s else s


def _valid_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _ws(t: str, i: int) -> int:
    n = len(t)
    while i < n and t[i] in _WS:
        i += 1
    return i


def decode_json(data: bytes) -> Any:
    """Parse data as exactly one JSON value under the strict rules above."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not _valid_utf8(data):
        raise ErrMalformed("JSON is not valid UTF-8")
    text = data.decode("utf-8")
    try:
        i = _ws(text, 0)
        v, i = _value(text, i, 0)
    except (_Strict, ValueError) as e:
        raise ErrMalformed(f"JSON: {e}") from e
    if _ws(text, i) != len(text):
        raise ErrMalformed("JSON: data after the value")
    return v


def _string(t: str, i: int) -> tuple[str, int]:
    s, end = scanstring(t, i + 1, True)
    return _fix_surrogates(s), end


def _value(t: str, i: int, depth: int) -> tuple[Any, int]:
    if i >= len(t):
        raise _Strict("unexpected end of JSON input")
    c = t[i]
    if c == '"':
        return _string(t, i)
    if c == "{":
        if depth >= MAX_JSON_DEPTH:
            raise _Strict(f"nesting deeper than {MAX_JSON_DEPTH}")
        obj: dict[str, Any] = {}
        i = _ws(t, i + 1)
        if i < len(t) and t[i] == "}":
            return obj, i + 1
        while True:
            if i >= len(t) or t[i] != '"':
                raise _Strict("object key is not a string")
            key, i = _string(t, i)
            i = _ws(t, i)
            if i >= len(t) or t[i] != ":":
                raise _Strict("expected ':' after object key")
            if key in obj:
                raise _Strict(f"duplicate key {quote(key)}")
            val, i = _value(t, _ws(t, i + 1), depth + 1)
            obj[key] = val
            i = _ws(t, i)
            if i < len(t) and t[i] == ",":
                i = _ws(t, i + 1)
                continue
            if i < len(t) and t[i] == "}":
                return obj, i + 1
            raise _Strict("expected ',' or '}' in object")
    if c == "[":
        if depth >= MAX_JSON_DEPTH:
            raise _Strict(f"nesting deeper than {MAX_JSON_DEPTH}")
        arr: list[Any] = []
        i = _ws(t, i + 1)
        if i < len(t) and t[i] == "]":
            return arr, i + 1
        while True:
            val, i = _value(t, i, depth + 1)
            arr.append(val)
            i = _ws(t, i)
            if i < len(t) and t[i] == ",":
                i = _ws(t, i + 1)
                continue
            if i < len(t) and t[i] == "]":
                return arr, i + 1
            raise _Strict("expected ',' or ']' in array")
    for lit, val in (("true", True), ("false", False), ("null", None)):
        if t.startswith(lit, i):
            return val, i + len(lit)
    m = _NUMBER_RE.match(t, i)
    if m:
        return JsonNumber(m.group()), m.end()
    raise _Strict(f"invalid character {c!r}")


def decode_json_object(data: bytes) -> dict[str, Any]:
    v = decode_json(data)
    if not isinstance(v, dict):
        raise ErrMalformed("JSON value is not an object")
    return v


# --- decode_json_string_member -------------------------------------------------


def _check_syntax(t: str) -> None:
    """Iterative RFC 8259 syntax check (no values built); nesting over 10000 is refused as encoding/json does."""
    n = len(t)
    stack: list[str] = []

    def key(i: int) -> int:
        m = _STRING_RE.match(t, i)
        if not m:
            raise _Strict("object key is not a string")
        i = _ws(t, m.end())
        if i >= n or t[i] != ":":
            raise _Strict("expected ':' after object key")
        return _ws(t, i + 1)

    i = _ws(t, 0)
    want_value = True
    while True:
        if want_value:
            if i >= n:
                raise _Strict("unexpected end of JSON input")
            c = t[i]
            if c in "{[":
                if len(stack) >= _MAX_VALID_DEPTH:
                    raise _Strict("exceeded max depth")
                close = "}" if c == "{" else "]"
                j = _ws(t, i + 1)
                if j < n and t[j] == close:
                    i, want_value = j + 1, False
                else:
                    stack.append(c)
                    i = key(j) if c == "{" else j
                continue
            m = _STRING_RE.match(t, i)
            if not m:
                m = _NUMBER_RE.match(t, i)
            if m:
                i = m.end()
            else:
                for lit in ("true", "false", "null"):
                    if t.startswith(lit, i):
                        i += len(lit)
                        break
                else:
                    raise _Strict(f"invalid character {c!r}")
            want_value = False
        else:
            i = _ws(t, i)
            if not stack:
                if i != n:
                    raise _Strict("data after the value")
                return
            if i >= n:
                raise _Strict("unexpected end of JSON input")
            c, top = t[i], stack[-1]
            if c == ",":
                i = _ws(t, i + 1)
                if top == "{":
                    i = key(i)
                want_value = True
            elif (c == "}" and top == "{") or (c == "]" and top == "["):
                stack.pop()
                i += 1
            else:
                raise _Strict(f"unexpected {c!r}")


def _end_string(t: str, i: int) -> int:
    j = i + 1
    while True:
        c = t[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1
        else:
            j += 1


def _end_value(t: str, i: int) -> int:
    c = t[i]
    if c == '"':
        return _end_string(t, i)
    if c in "{[":
        depth = 0
        j = i
        while True:
            ch = t[j]
            if ch == '"':
                j = _end_string(t, j)
                continue
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
    j = i
    while j < len(t) and t[j] not in ",}]" and t[j] not in _WS:
        j += 1
    return j


def _json_kind(c: str) -> str:
    return {"{": "an object", "[": "an array", "t": "a boolean", "f": "a boolean", "n": "null"}.get(c, "a number")


def decode_json_string_member(data: bytes, name: str) -> tuple[str, bool]:
    """Return (value, found) of the top-level string member `name` without building any other value.

    Follows decode_json on what it reads: valid UTF-8, one object, keys compared after
    unescaping (a name present twice is ErrMalformed), a non-string member is ErrMalformed.
    Duplicate keys inside other members and MAX_JSON_DEPTH are left to decode_json.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not _valid_utf8(data):
        raise ErrMalformed("JSON is not valid UTF-8")
    t = data.decode("utf-8")
    try:
        _check_syntax(t)
    except (_Strict, ValueError) as e:
        raise ErrMalformed(f"JSON: {e}") from e
    i = _ws(t, 0)
    if t[i] != "{":
        raise ErrMalformed("JSON value is not an object")
    member = None
    i = _ws(t, i + 1)
    while t[i] != "}":
        key_end = _end_string(t, i)
        is_name = _string(t, i)[0] == name if "\\" in t[i:key_end] else t[i + 1 : key_end - 1] == name
        i = _ws(t, _ws(t, key_end) + 1)
        end = _end_value(t, i)
        if is_name:
            if member is not None:
                raise ErrMalformed(f"JSON: duplicate key {quote(name)}")
            member = t[i:end]
        i = _ws(t, end)
        if t[i] == ",":
            i = _ws(t, i + 1)
    if member is None:
        return "", False
    if member[0] != '"':
        raise ErrMalformed(f"JSON: member {quote(name)} is {_json_kind(member[0])}, not a string")
    return decode_json(member.encode("utf-8")), True


# --- encode_json ---------------------------------------------------------------

_ESC = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f", " ": "\\u2028", " ": "\\u2029"}
_NEEDS_ESC_RE = re.compile('[\x00-\x1f"\\\\  \ud800-\udfff]')


def _esc(m: re.Match[str]) -> str:
    c = m.group()
    if c in _ESC:
        return _ESC[c]
    if "\ud800" <= c <= "\udfff":
        return "\\ufffd"
    return f"\\u{ord(c):04x}"


def _enc_str(s: str) -> str:
    return '"' + _NEEDS_ESC_RE.sub(_esc, s) + '"'


def _enc_float(f: float) -> str:
    if f != f or f in (float("inf"), float("-inf")):
        raise ErrInvalidArgument(f"encode JSON: unsupported value: {f}")
    if f == 0:
        return "-0" if str(f).startswith("-") else "0"
    d = Decimal(repr(f))
    a = abs(f)
    if a < 1e-6 or a >= 1e21:
        sign, digits, exp = d.as_tuple()
        ds = "".join(map(str, digits))
        e = len(ds) - 1 + int(exp)
        mant = ds[0] + ("." + ds[1:] if len(ds) > 1 else "")
        return f"{'-' if sign else ''}{mant}e{'+' if e >= 0 else '-'}{abs(e):02d}".replace("e-0", "e-")
    s = format(d, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def _enc(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_enc_str(v))
    elif isinstance(v, int):
        out.append(str(int(v)))
    elif isinstance(v, float):
        out.append(_enc_float(v))
    elif isinstance(v, JsonNumber):
        if not _NUMBER_RE.fullmatch(str(v)):
            raise ErrInvalidArgument(f"encode JSON: invalid number literal {quote(str(v))}")
        out.append(str(v))
    elif isinstance(v, dict):
        items = []
        for k, x in v.items():
            if not isinstance(k, str):
                raise ErrInvalidArgument(f"encode JSON: unsupported map key type {type(k).__name__}")
            items.append((_fix_surrogates(k), x))
        items.sort(key=lambda kv: kv[0])
        out.append("{")
        for n, (k, x) in enumerate(items):
            if n:
                out.append(",")
            out.append(_enc_str(k))
            out.append(":")
            _enc(x, out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for n, x in enumerate(v):
            if n:
                out.append(",")
            _enc(x, out)
        out.append("]")
    else:
        raise ErrInvalidArgument(f"encode JSON: unsupported type: {type(v).__name__}")


def encode_json(v: Any) -> bytes:
    """Encode v compactly: sorted keys, no HTML escaping, UTF-8 kept (U+2028/U+2029 escaped), numbers by JsonNumber text."""
    out: list[str] = []
    try:
        _enc(v, out)
    except RecursionError as e:
        raise ErrInvalidArgument("encode JSON: nesting too deep") from e
    return "".join(out).encode("utf-8")
