from __future__ import annotations

from dataclasses import dataclass, field

from digitalcredential.typemeta.document import Claim, Display
from digitalcredential.typemeta.errors import ErrClaims, ErrCycle, ErrInvalid, ErrNotFound
from digitalcredential.typemeta.format import (
    MAX_CHAIN,
    SD_ALLOWED,
    _ClaimMeta,
    _check_svg_ids,
    merge_claims_impl,
    path_key,
    read_document,
)
from digitalcredential.typemeta.integrity import check_integrity
from digitalcredential.typemeta.ref import Ref
from digitalcredential.typemeta.static import Resolver


@dataclass
class Metadata:
    vct: str
    chain: list[str] = field(default_factory=list)
    name: str = ""
    description: str = ""
    display: list[Display] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    docs: list[bytes] = field(default_factory=list)

    def claims_list(self) -> list[Claim]:
        return list(self.claims)

    def display_list(self) -> list[Display]:
        return list(self.display)

    def documents(self) -> list[bytes]:
        return [bytes(d) for d in self.docs]


def Load(r: Resolver, ref: Ref) -> Metadata:
    if not ref.vct:
        raise ErrInvalid("typemeta: Load of an empty vct")
    docs = []
    raws: list[bytes] = []
    seen: set[str] = set()
    next_ref = ref
    while True:
        try:
            raw = r.metadata(next_ref)
        except ErrNotFound:
            if docs:
                raise ErrInvalid(
                    f"typemeta: document {len(docs)} of the extends chain is not found"
                ) from None
            raise
        if len(raw) > 256 << 10:
            raise ErrInvalid(f"typemeta: document {len(docs)} of the chain is over size limit")
        if next_ref.integrity:
            check_integrity(raw, next_ref.integrity)
        d = read_document(raw)
        if d.vct != next_ref.vct:
            raise ErrInvalid(f"typemeta: document {len(docs)} has wrong vct")
        docs.append(d)
        raws.append(bytes(raw))
        seen.add(d.vct)
        if not d.has_extends:
            break
        if d.extends in seen:
            raise ErrCycle(f"typemeta: document {len(docs) - 1} extends a type already in the chain")
        if len(docs) == MAX_CHAIN:
            raise ErrInvalid(f"typemeta: extends chain over {MAX_CHAIN} documents")
        next_ref = Ref(vct=d.extends, integrity=d.extends_integrity if d.has_extends_integrity else "")

    m = Metadata(vct=ref.vct, name=docs[0].name, description=docs[0].description, docs=raws)
    merged: list[_ClaimMeta] = []
    for i in range(len(docs) - 1, -1, -1):
        d = docs[i]
        m.chain.append(d.vct)
        if d.has_display:
            m.display = d.display
        claims, err = d.read_claims()
        if err:
            raise err
        if claims:
            svg_err = _check_svg_ids(claims)
            if svg_err:
                raise svg_err
            try:
                merged = merge_claims_impl(merged, claims)
            except ErrClaims as exc:
                raise exc
            svg_err = _check_svg_ids(merged)
            if svg_err:
                raise ErrClaims(f"typemeta: document {i} duplicate svg_id in merged claims")
    m.chain.reverse()
    for cm in merged:
        if not cm.has_sd:
            cm.claim.sd = SD_ALLOWED
        m.claims.append(cm.claim)
    return m
