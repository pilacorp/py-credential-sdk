from __future__ import annotations

_IRREGULAR = {
    "en-gb-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "sgn-be-fr",
    "sgn-be-nl",
    "sgn-ch-de",
}


def well_formed_lang_tag(s: str) -> bool:
    allowed = set("-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    if any(c not in allowed for c in s):
        return False
    s = s.lower()
    if s in _IRREGULAR:
        return True
    subs = s.split("-")
    for t in subs:
        if not t or len(t) > 8 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789" for c in t):
            return False
    i = 0

    def next_ok(pred) -> bool:
        nonlocal i
        if i < len(subs) and pred(subs[i]):
            i += 1
            return True
        return False

    if subs[0] != "x":
        if not next_ok(lambda t: len(t) >= 2 and _alpha(t)):
            return False
        if len(subs[0]) <= 3:
            for _ in range(3):
                if not next_ok(lambda t: len(t) == 3 and _alpha(t)):
                    break
        next_ok(lambda t: len(t) == 4 and _alpha(t))
        next_ok(lambda t: (len(t) == 2 and _alpha(t)) or (len(t) == 3 and _digit(t)))
        while next_ok(lambda t: len(t) >= 5 or (len(t) == 4 and _digit(t[0]))):
            pass
        while i < len(subs) and len(subs[i]) == 1 and subs[i] != "x":
            i += 1
            if not next_ok(lambda t: len(t) >= 2):
                return False
            while next_ok(lambda t: len(t) >= 2):
                pass
    if next_ok(lambda t: t == "x"):
        if i == len(subs):
            return False
        i = len(subs)
    return i == len(subs)


def _alpha(s: str) -> bool:
    return all("a" <= c <= "z" for c in s)


def _digit(s: str) -> bool:
    return all(c.isdigit() for c in s)
