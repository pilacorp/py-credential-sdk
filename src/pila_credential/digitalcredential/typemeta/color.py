from __future__ import annotations

_CSS_SPACE = " \t\n\r\f"


def rgb_color(s: str) -> bool:
    if s.startswith("#"):
        h = s[1:].lower()
        return (len(h) in (3, 6)) and all(c in "0123456789abcdef" for c in h)
    if len(s) < len("rgb()") or s[:4].lower() != "rgb(" or s[-1] != ")":
        return False
    vals = s[4:-1].split(",")
    if len(vals) != 3:
        return False
    pct = vals[0].strip(_CSS_SPACE).endswith("%")
    for v in vals:
        v = v.strip(_CSS_SPACE)
        if v.endswith("%") != pct:
            return False
        n = v[:-1] if pct else v
        if pct and not _css_number(n):
            return False
        if not pct and not _css_integer(n):
            return False
    return True


def _css_integer(s: str) -> bool:
    if s and s[0] in "+-":
        s = s[1:]
    return bool(s) and all("0" <= c <= "9" for c in s)


def _css_number(s: str) -> bool:
    if s and s[0] in "+-":
        s = s[1:]
    if "." in s:
        a, b = s.split(".", 1)
        return _digits(a) and bool(b) and _digits(b)
    return bool(s) and _digits(s)


def _digits(s: str) -> bool:
    return all("0" <= c <= "9" for c in s)
