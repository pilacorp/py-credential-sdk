from __future__ import annotations

from typing import Protocol

from digitalcredential.issuerkey import PublicKey


class ErrIssuerNotSupported(LookupError):
    """Resolver does not accept this issuer."""


class ErrNoUsableKey(LookupError):
    """Issuer document has no usable verification key."""


class IssuerKeyResolver(Protocol):
    def keys(self, iss: str) -> list[PublicKey]: ...


def multi(*resolvers: IssuerKeyResolver) -> _MultiResolver:
    if not resolvers:
        raise ValueError("issuerkey: Multi needs at least one resolver")
    for i, r in enumerate(resolvers):
        if r is None:
            raise ValueError(f"issuerkey: Multi resolver {i} is nil")
    return _MultiResolver(tuple(resolvers))


class _MultiResolver:
    def __init__(self, resolvers: tuple[IssuerKeyResolver, ...]) -> None:
        self._resolvers = resolvers

    def keys(self, iss: str) -> list[PublicKey]:
        for r in self._resolvers:
            try:
                keys = r.keys(iss)
            except ErrIssuerNotSupported:
                continue
            return keys
        raise ErrIssuerNotSupported("issuerkey: no resolver accepts this issuer")
