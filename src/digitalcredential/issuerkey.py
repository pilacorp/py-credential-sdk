from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from credential.common.signer.p256 import P256Provider


@dataclass
class PublicKey:
    public_key: bytes
    kid: str | None = None


@dataclass
class SigningKey:
    signer: P256Provider
    public_key: bytes
    kid: str | None = None


class Resolver(Protocol):
    def keys(self, iss: str) -> list[PublicKey]: ...


class StaticResolver:
    def __init__(self, iss: str, published: list[PublicKey]) -> None:
        self.iss = iss
        self.published = published

    def keys(self, iss: str) -> list[PublicKey]:
        from digitalcredential.issuerkey_multi import ErrIssuerNotSupported

        if iss != self.iss:
            raise ErrIssuerNotSupported("issuerkey: issuer not supported")
        return self.published


def select_key(keys: list[PublicKey], kid: str | None, header: dict | None = None) -> PublicKey:
    if header is not None:
        if "kid" in header:
            v = header.get("kid")
            if not isinstance(v, str) or not v:
                raise ValueError("issuerkey: header kid is not a non-empty string")
            kid = v
        else:
            kid = None
    if not keys:
        raise ValueError("issuerkey: the resolver returned no key for this issuer")
    if kid:
        hits = [k for k in keys if k.kid == kid]
        if len(hits) != 1:
            n = sum(1 for k in keys if k.kid == kid)
            raise ValueError(f"issuerkey: {n} of the keys the resolver returned have the header kid, want 1")
        if hits[0].public_key is None:
            raise ValueError("issuerkey: the selected key is nil")
        return hits[0]
    if len(keys) != 1:
        raise ValueError(f"issuerkey: no header kid and {len(keys)} keys, want 1")
    if keys[0].public_key is None:
        raise ValueError("issuerkey: the selected key is nil")
    return keys[0]
