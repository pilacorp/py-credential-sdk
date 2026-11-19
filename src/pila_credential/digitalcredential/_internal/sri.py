"""Integrity metadata (draft-ietf-oauth-sd-jwt-vc-19 §6, W3C SRI §3.5): the value of vct#integrity,
extends#integrity and uri#integrity, and the check of a document against it."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Callable

# CSP Level 2 §4.2 hash-algo, strongest first (draft 19 §6 asks the strongest supported to be used).
_ALGS: list[tuple[str, Callable[[bytes], bytes]]] = [
    ("sha512", lambda b: hashlib.sha512(b).digest()),
    ("sha384", lambda b: hashlib.sha384(b).digest()),
    ("sha256", lambda b: hashlib.sha256(b).digest()),
]

# SRI splits on ASCII whitespace only, never on other Unicode spaces.
_ASCII_SPACE = re.compile(r"[ \t\n\f\r]+")


def _tokens(integrity: str) -> list[str]:
    return [t for t in _ASCII_SPACE.split(integrity) if t]


def well_formed(integrity: str) -> bool:
    """Every token is hash-algo "-" base64-value with options of VCHAR only. A token of another
    algorithm makes the whole value malformed. No token at all is well formed; `check` refuses it."""
    return all(_parse_token(t)[2] for t in _tokens(integrity))


def check(data: bytes, integrity: str) -> None:
    """Raise ValueError unless data matches integrity: the digest of exactly data under the
    strongest algorithm integrity uses, compared with each digest of that algorithm."""
    if not well_formed(integrity):
        raise ValueError(
            "integrity metadata is not well formed: each token is sha256-, sha384- or sha512- and base64, "
            "tokens separated by spaces (W3C SRI §3.5)"
        )
    alg, digests = _strongest(integrity)
    if alg < 0:
        raise ValueError("integrity metadata holds no sha256, sha384 or sha512 hash expression")
    digest = _ALGS[alg][1](bytes(data))
    for d in digests:
        if d is not None and digest == d:
            return
    raise ValueError(f"the document does not match its {_ALGS[alg][0]} integrity metadata")


def _strongest(integrity: str) -> tuple[int, list[bytes | None]]:
    alg = -1
    digests: list[bytes | None] = []
    for tok in _tokens(integrity):
        i, value, _ = _parse_token(tok)
        if alg >= 0 and i > alg:
            continue
        # base64-value allows any padding up to "==", so it is decoded unpadded. A value that does
        # not decode is still a well-formed token of its algorithm and matches no document.
        v = value.rstrip("=")
        try:
            d: bytes | None = base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
        except (binascii.Error, ValueError):
            d = None
        if alg < 0 or i < alg:
            alg, digests = i, []
        digests.append(d)
    return alg, digests


def _parse_token(tok: str) -> tuple[int, str, bool]:
    tok, _, opts = tok.partition("?")
    for c in opts:
        if ord(c) < 0x21 or ord(c) > 0x7E:
            return -1, "", False
    name, sep, value = tok.partition("-")
    if not sep or not _base64_value(value):
        return -1, "", False
    # hash-algo matches in ASCII case only (ABNF, RFC 5234 §2.3).
    if name.isascii():
        for j, (aname, _) in enumerate(_ALGS):
            if name.lower() == aname:
                return j, value, True
    return -1, "", False


def _base64_value(s: str) -> bool:
    """CSP Level 2 §4.2: 1*( ALPHA / DIGIT / "+" / "/" ) *2( "=" )."""
    body = s.rstrip("=")
    if not body or len(s) - len(body) > 2:
        return False
    return all("A" <= c <= "Z" or "a" <= c <= "z" or "0" <= c <= "9" or c in "+/" for c in body)
