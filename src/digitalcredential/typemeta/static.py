from __future__ import annotations

import json
from typing import Protocol

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
            raise ErrNotFound("typemeta: no preloaded document for the vct") from None
        return bytes(doc)


def Static(*docs: bytes) -> StaticResolver:
    if not docs:
        raise ValueError("typemeta: Static needs at least one document")
    by_vct: dict[str, bytes] = {}
    for i, d in enumerate(docs):
        try:
            obj = json.loads(d)
        except json.JSONDecodeError as exc:
            raise ValueError(f"typemeta: Static document {i} is not JSON") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"typemeta: Static document {i} is not a JSON object with vct")
        vct = obj.get("vct")
        if not isinstance(vct, str) or not vct:
            raise ValueError(f"typemeta: Static document {i} has no non-empty string vct")
        if vct in by_vct:
            raise ValueError(f"typemeta: Static document {i} duplicates vct")
        by_vct[vct] = bytes(d)
    return StaticResolver(by_vct)
