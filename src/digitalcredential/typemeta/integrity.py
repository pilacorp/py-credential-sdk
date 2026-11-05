"""Integrity of referenced documents: draft-ietf-oauth-sd-jwt-vc-19 §6, the "integrity metadata" string of
W3C Subresource Integrity (REC 2016-06-23) §3.5."""

from __future__ import annotations

import base64
import hashlib

from digitalcredential.internal import sri
from digitalcredential.typemeta.errors import ErrInvalid


def integrity(doc: bytes) -> str:
    """"sha256-" and the base64 SHA-256 of doc: the integrity metadata an issuer writes as vct#integrity,
    and a publisher as extends#integrity or uri#integrity, over exactly the bytes served."""
    return "sha256-" + base64.standard_b64encode(hashlib.sha256(bytes(doc)).digest()).decode("ascii")


Integrity = integrity


def check_integrity(data: bytes, value: str) -> None:
    """Check data against value as draft 19 §6 says, reading the string per SRI §3.5: tokens split on
    ASCII whitespace, the options after "?" dropped; every token is sha256, sha384 or sha512 in any case,
    "-", and base64 of the standard alphabet. Only the tokens of the strongest algorithm count, and data
    passes when its digest equals one of them. Raises ErrInvalid: value is not integrity metadata,
    holds no token, or no token matches."""
    try:
        sri.check(data, value)
    except ValueError as exc:
        raise ErrInvalid(f"typemeta: {exc} (draft-ietf-oauth-sd-jwt-vc-19 §6)") from exc


CheckIntegrity = check_integrity
