from __future__ import annotations

import base64
import hashlib
from typing import Callable

_ALGS: list[tuple[str, Callable[[bytes], bytes]]] = [
    ("sha512", lambda b: hashlib.sha512(b).digest()),
    ("sha384", lambda b: hashlib.sha512(b, usedforsecurity=True).digest() if False else hashlib.new("sha384", b).digest()),
    ("sha256", lambda b: hashlib.sha256(b).digest()),
]


def _sha384(data: bytes) -> bytes:
    return hashlib.new("sha384", data).digest()


_ALGS[1] = ("sha384", _sha384)


def well_formed(integrity: str) -> bool:
    for tok in integrity.split():
        if not _parse_token(tok)[2]:
            return False
    return True


def check(data: bytes, integrity: str) -> None:
    if not well_formed(integrity):
        raise ValueError(
            "integrity metadata is not well formed: each token is sha256-, sha384- or sha512- and base64, "
            "tokens separated by spaces (W3C SRI §3.5)"
        )
    alg, digests = _strongest(integrity)
    if alg < 0:
        raise ValueError("integrity metadata holds no sha256, sha384 or sha512 hash expression")
    digest = _ALGS[alg][1](data)
    for d in digests:
        if d is not None and digest == d:
            return
    raise ValueError(f"the document does not match its {_ALGS[alg][0]} integrity metadata")


def _strongest(integrity: str) -> tuple[int, list[bytes | None]]:
    alg = -1
    digests: list[bytes | None] = []
    for tok in integrity.split():
        i, value, ok = _parse_token(tok)
        if not ok:
            continue
        if alg >= 0 and i > alg:
            continue
        try:
            d = base64.b64decode(value + "=" * ((4 - len(value) % 4) % 4))
        except Exception:
            d = None
        if i < alg or alg < 0:
            alg, digests = i, []
        digests.append(d)
    return alg, digests


def _parse_token(tok: str) -> tuple[int, str, bool]:
    tok, _, opts = tok.partition("?")
    for c in opts:
        if ord(c) < 0x21 or ord(c) > 0x7E:
            return -1, "", False
    if "-" not in tok:
        return -1, "", False
    name, value = tok.split("-", 1)
    if not _base64_value(value):
        return -1, "", False
    for j, (aname, _) in enumerate(_ALGS):
        if len(name) == len(aname) and name.lower() == aname:
            return j, value, True
    return -1, "", False


def _base64_value(s: str) -> bool:
    body = s.rstrip("=")
    if not body or len(s) - len(body) > 2:
        return False
    for c in body:
        if not (c.isalnum() or c in "+/"):
            return False
    return True
