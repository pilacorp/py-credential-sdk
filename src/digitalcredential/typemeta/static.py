"""Preloaded documents: draft-ietf-oauth-sd-jwt-vc-19 §5.3.4 and §7.5."""

from __future__ import annotations

from typing import Protocol

from jose import json as jose_json
from jose.errors import ErrInvalidArgument
from digitalcredential.typemeta.errors import ErrNotFound
from digitalcredential.typemeta.ref import Ref


class Resolver(Protocol):
    def metadata(self, ref: Ref) -> bytes: ...


class StaticResolver:
    def __init__(self, by_vct: dict[str, bytes]) -> None:
        self._docs = {k: bytes(v) for k, v in by_vct.items()}

    def metadata(self, ref: Ref) -> bytes:
        doc = self._docs.get(ref.vct)
        if doc is None:
            raise ErrNotFound("typemeta: no preloaded document for the vct")
        return bytes(doc)


def Static(*docs: bytes) -> StaticResolver:
    """A Resolver over docs, documents the application ships or fetched ahead (§5.3.4, §7.5), each found
    by the vct it holds. It copies docs and reads only each vct; Load checks the rest. No document, one
    that is not a JSON object or has no non-empty string vct, or two with the same vct, is
    jose.ErrInvalidArgument. metadata returns ErrNotFound for any other vct and the document for its
    own, whatever ref.integrity, which Load checks."""
    if not docs:
        raise ErrInvalidArgument("typemeta: Static needs at least one document")
    by_vct: dict[str, bytes] = {}
    for i, d in enumerate(docs):
        try:
            vct, _ = jose_json.decode_json_string_member(bytes(d), "vct")
        except Exception as exc:  # noqa: BLE001
            vct = ""
            err: Exception | None = exc
        else:
            err = None
        if err is not None or vct == "":
            raise ErrInvalidArgument(
                f"typemeta: Static document {i} is not a JSON object with a non-empty string vct "
                "(draft-ietf-oauth-sd-jwt-vc-19 §5.2)"
            ) from err
        if vct in by_vct:
            raise ErrInvalidArgument(f"typemeta: Static document {i} has the vct of an earlier one")
        by_vct[vct] = bytes(d)
    return StaticResolver(by_vct)
