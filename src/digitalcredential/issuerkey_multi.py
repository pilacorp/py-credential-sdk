"""Combining resolvers, so that one verifier accepts issuers whose keys come from different sources (Go: issuerkey/multi.go)."""

from __future__ import annotations

from jose.errors import ErrInvalidArgument

from digitalcredential.errors import errors_is
from digitalcredential.issuerkey import ErrIssuerNotSupported, ErrNoUsableKey, PublicKey, Resolver

IssuerKeyResolver = Resolver

__all__ = ["ErrIssuerNotSupported", "ErrNoUsableKey", "IssuerKeyResolver", "multi", "Multi"]


def multi(*resolvers: Resolver) -> Resolver:
    """A Resolver that asks resolvers in the order given.

    A resolver that raises ErrIssuerNotSupported passes iss to the next; the
    first one that gives any other answer, an exception included, gives the
    result. So a failed fetch never moves an issuer to another key source.
    When none accepts iss, ErrIssuerNotSupported. No resolver, or a None one,
    is ErrInvalidArgument. resolvers is copied.
    """
    if not resolvers:
        raise ErrInvalidArgument("issuerkey: Multi needs at least one resolver")
    for i, r in enumerate(resolvers):
        if r is None:
            raise ErrInvalidArgument(f"issuerkey: Multi resolver {i} is nil")
    return _MultiResolver(tuple(resolvers))


Multi = multi


class _MultiResolver:
    def __init__(self, resolvers: tuple[Resolver, ...]) -> None:
        self._resolvers = resolvers

    def keys(self, iss: str) -> list[PublicKey]:
        for r in self._resolvers:
            try:
                return r.keys(iss)
            except Exception as e:
                if errors_is(e, ErrIssuerNotSupported):
                    continue
                raise
        raise ErrIssuerNotSupported("issuerkey: no resolver accepts this issuer")
