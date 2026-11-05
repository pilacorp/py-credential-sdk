from __future__ import annotations

from jose.json import JsonNumber

_MAX_INT = 2**63 - 1  # Go math.MaxInt on 64-bit


class ErrNotInteger(ValueError):
    """Not a JSON number, or one whose value is negative or has a fraction."""


class ErrTooLarge(ValueError):
    """A non-negative integer larger than an int holds."""

_MAX_EXP = 1 << 40


def _digits(s: str, i: int) -> int:
    while i < len(s) and "0" <= s[i] <= "9":
        i += 1
    return i


def non_negative(n: str | int | float) -> int:
    if isinstance(n, bool):
        raise ErrNotInteger("not a non-negative integer")
    if isinstance(n, int):
        if n < 0:
            raise ErrNotInteger("not a non-negative integer")
        if n > _MAX_INT:
            raise ErrTooLarge("integer too large")
        return n
    if isinstance(n, float):
        if n != n or n in (float("inf"), float("-inf")) or n < 0 or not n.is_integer():
            raise ErrNotInteger("not a non-negative integer")
        return non_negative(int(n))
    if isinstance(n, JsonNumber):
        n = str(n)
    if not isinstance(n, str):
        raise ErrNotInteger("not a non-negative integer")
    s = n
    neg = False
    if s.startswith("-"):
        s, neg = s[1:], True
    i = _digits(s, 0)
    if i == 0 or (s[0] == "0" and i > 1):
        raise ErrNotInteger("not a non-negative integer")
    whole, frac = s[:i], ""
    if i < len(s) and s[i] == ".":
        j = _digits(s, i + 1)
        if j == i + 1:
            raise ErrNotInteger("not a non-negative integer")
        frac, i = s[i + 1 : j], j
    exp = 0
    if i < len(s) and s[i] in "eE":
        i += 1
        exp_neg = i < len(s) and s[i] == "-"
        if i < len(s) and s[i] in "+-":
            i += 1
        j = _digits(s, i)
        if j == i:
            raise ErrNotInteger("not a non-negative integer")
        for c in s[i:j]:
            if exp < _MAX_EXP:
                exp = exp * 10 + (ord(c) - ord("0"))
        if exp_neg:
            exp = -exp
        i = j
    if i != len(s):
        raise ErrNotInteger("not a non-negative integer")
    all_len = len(whole) + len(frac)

    def at(k: int) -> str:
        return whole[k] if k < len(whole) else frac[k - len(whole)]

    lo, hi = 0, all_len
    while lo < hi and at(lo) == "0":
        lo += 1
    if lo == hi:
        return 0
    while at(hi - 1) == "0":
        hi -= 1
    if neg:
        raise ErrNotInteger("not a non-negative integer")
    shift = exp - len(frac) + (all_len - hi)
    if shift < 0:
        raise ErrNotInteger("not a non-negative integer")
    if (hi - lo) + shift > 19:
        raise ErrTooLarge("integer too large")
    v = 0
    for k in range(lo, hi):
        v = v * 10 + (ord(at(k)) - ord("0"))
    for _ in range(int(shift)):
        v *= 10
    if v > _MAX_INT:
        raise ErrTooLarge("integer too large")
    return int(v)
