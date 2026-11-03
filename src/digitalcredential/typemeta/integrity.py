from __future__ import annotations

import base64
import hashlib

from digitalcredential.internal import sri
from digitalcredential.typemeta.errors import ErrInvalid


def integrity(doc: bytes) -> str:
    digest = hashlib.sha256(doc).digest()
    return "sha256-" + base64.standard_b64encode(digest).decode("ascii")


Integrity = integrity


def check_integrity(data: bytes, value: str) -> None:
    try:
        sri.check(data, value)
    except ValueError as exc:
        raise ErrInvalid(f"{exc} (draft-ietf-oauth-sd-jwt-vc-19 §6)") from exc


CheckIntegrity = check_integrity
