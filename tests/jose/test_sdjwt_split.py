from __future__ import annotations

import pytest

from jose.errors import ErrMalformed
from jose.sdjwt.limits import MAX_BYTES, MAX_DISCLOSURES
from jose.sdjwt.split import split

JWT = "eyJh.eyJw.c2ln"


def _sized(n: int) -> str:
    return JWT + "~" + ("A" * (n - len(JWT) - 2)) + "~"


def test_split_accepts_one_mib() -> None:
    split(_sized(1 << 20))


def test_split_rejects_oversized() -> None:
    with pytest.raises(ErrMalformed):
        split(_sized((1 << 20) + 1))


def test_split_rejects_too_many_disclosures() -> None:
    compact = JWT + "".join(f"~d{i}" for i in range(1001)) + "~"
    with pytest.raises(ErrMalformed):
        split(compact)


def test_split_basic() -> None:
    issuer, disclosures, kb = split(f"{JWT}~WyJzYWx0IiwgIm4iLCAidiJd~")
    assert issuer == JWT
    assert disclosures == ["WyJzYWx0IiwgIm4iLCAidiJd"]
    assert kb == ""


def test_split_duplicate_disclosure() -> None:
    d = "WyJzYWx0IiwgIm4iLCAidiJd"
    with pytest.raises(ErrMalformed):
        split(f"{JWT}~{d}~{d}~")
