from __future__ import annotations

ErrNotInteger = ValueError("not a non-negative integer")
ErrTooLarge = ValueError("integer too large")

_MAX_EXP = 1 << 40


def _digits(s: str, i: int) -> int:
    while i < len(s) and "0" <= s[i] <= "9":
        i += 1
    return i


def non_negative(n: str | int | float) -> int:
    if isinstance(n, bool):
        raise ErrNotInteger
    if isinstance(n, int):
        if n < 0:
            raise ErrNotInteger
        return n
    if isinstance(n, float):
        if n < 0 or not n.is_integer():
            raise ErrNotInteger
        return int(n)
    s = str(n).strip()
    neg = False
    if s.startswith("-"):
        s, neg = s[1:], True
    i = _digits(s, 0)
    if i == 0 or (s[0] == "0" and i > 1):
        raise ErrNotInteger
    whole, frac = s[:i], ""
    if i < len(s) and s[i] == ".":
        j = _digits(s, i + 1)
        if j == i + 1:
            raise ErrNotInteger
        frac, i = s[i + 1 : j], j
    exp = 0
    if i < len(s) and s[i] in "eE":
        i += 1
        exp_neg = i < len(s) and s[i] == "-"
        if i < len(s) and s[i] in "+-":
            i += 1
        j = _digits(s, i)
        if j == i:
            raise ErrNotInteger
        for c in s[i:j]:
            if exp < _MAX_EXP:
                exp = exp * 10 + (ord(c) - ord("0"))
        if exp_neg:
            exp = -exp
        i = j
    if i != len(s):
        raise ErrNotInteger
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
        raise ErrNotInteger
    shift = exp - len(frac) + (all_len - hi)
    if shift < 0:
        raise ErrNotInteger
    if (hi - lo) + shift > 19:
        raise ErrTooLarge
    v = 0
    for k in range(lo, hi):
        v = v * 10 + (ord(at(k)) - ord("0"))
    for _ in range(int(shift)):
        v *= 10
    if v > 2**31 - 1:
        raise ErrTooLarge
    return int(v)
