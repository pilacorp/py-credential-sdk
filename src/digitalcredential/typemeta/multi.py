"""Combining resolvers, so that one application takes documents from several retrieval methods
(draft-ietf-oauth-sd-jwt-vc-19 §5.3)."""

from __future__ import annotations

from typing import Any, Protocol

from jose.errors import ErrInvalidArgument
from digitalcredential.typemeta.errors import ErrNotFound
from digitalcredential.typemeta.ref import Ref


class CancelledError(Exception):
    """Context was cancelled before metadata could be retrieved."""


class MetadataResolver(Protocol):
    def metadata(self, ref: Ref) -> bytes: ...


def Multi(*resolvers: MetadataResolver) -> "_Multi":
    """A Resolver that asks resolvers in the order given. One that raises ErrNotFound passes ref to the
    next; the first other answer, an error included, is the result, so a failed retrieval never moves a
    type to another source. When none has the document, ErrNotFound. No resolver, or a None one, is
    jose.ErrInvalidArgument. resolvers is copied."""
    if not resolvers:
        raise ErrInvalidArgument("typemeta: Multi needs at least one resolver")
    for i, r in enumerate(resolvers):
        if r is None:
            raise ErrInvalidArgument(f"typemeta: Multi resolver {i} is nil")
    return _Multi(tuple(resolvers))


class _Multi:
    def __init__(self, resolvers: tuple[MetadataResolver, ...]) -> None:
        self._resolvers = resolvers

    def metadata(self, ref: Ref) -> bytes:
        for r in self._resolvers:
            try:
                return r.metadata(ref)
            except ErrNotFound:
                continue
        raise ErrNotFound("typemeta: no resolver has a document for the vct")

    def metadata_ctx(self, ctx: Any, ref: Ref) -> bytes:
        """metadata with a context whose cancelled() is checked before each resolver is asked; a None
        ctx is jose.ErrInvalidArgument."""
        if ctx is None:
            raise ErrInvalidArgument("typemeta: nil context")
        for r in self._resolvers:
            if ctx.cancelled():
                raise CancelledError()
            try:
                return r.metadata(ref)
            except ErrNotFound:
                continue
        raise ErrNotFound("typemeta: no resolver has a document for the vct")
