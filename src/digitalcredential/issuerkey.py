"""Issuer keys of draft-ietf-oauth-sd-jwt-vc-19 and draft-ietf-oauth-status-list-21 (Go: issuerkey).

The signing side is SigningKey: the issuer's jws Signer and its public key.
The verifying side is PublicKey and Resolver: a Resolver returns the keys an
issuer publishes (draft 19 §2.5), and select picks the one that verifies a JWS
by its kid (RFC 7515 §4.1.4, RFC 7517 §4.5). The token header never reaches a
Resolver, and select never tries keys in turn.
"""

from __future__ import annotations

from typing import Any, Protocol

from jose.json import JsonNumber


class ErrIssuerNotSupported(LookupError):
    """A Resolver does not accept iss at all: an issuer outside its trust list or an unknown scheme."""


class ErrNoUsableKey(LookupError):
    """The issuer's key source answered and the answer gives no usable key (the error states why)."""


class SigningKey:
    """An issuer's signing key, for issue and the Status List Token.

    signer holds the private key (a jose.jws Signer) and public is its public
    key; kid, when not empty, is written as the kid header. Nothing is checked
    here: jws.sign checks signer and public when it signs.
    """

    def __init__(self, signer: Any = None, public: Any = None, kid: str = "", *, public_key: Any = None) -> None:
        self.signer = signer
        self.public = public if public is not None else public_key
        self.kid = kid or ""

    @property
    def public_key(self) -> Any:  # legacy name
        return self.public


class PublicKey:
    """One key an issuer publishes for verifying its signatures (kid may be empty)."""

    def __init__(self, public: Any = None, kid: str = "", *, public_key: Any = None) -> None:
        self.public = public if public is not None else public_key
        self.kid = kid or ""

    @property
    def public_key(self) -> Any:  # legacy name
        return self.public

    def __repr__(self) -> str:
        return f"PublicKey(kid={self.kid!r})"


class Resolver(Protocol):
    """keys(iss) returns the keys iss currently publishes for verification.

    Outcomes, in order: raise ErrIssuerNotSupported (iss is not accepted);
    raise ErrNoUsableKey (the issuer answered with no usable key); raise
    jose.ErrInvalidArgument (the code that built the resolver is wrong); any
    other exception (keys could not be found out); otherwise the keys, possibly
    none. iss comes from an unverified token and may be "".
    """

    def keys(self, iss: str) -> list[PublicKey]: ...


class StaticResolver:
    """A Resolver over the keys of one issuer."""

    def __init__(self, iss: str, published: list[PublicKey]) -> None:
        self.iss = iss
        self.published = published

    def keys(self, iss: str) -> list[PublicKey]:
        if iss != self.iss:
            raise ErrIssuerNotSupported("issuerkey: issuer not supported")
        return self.published


def select(keys: list[PublicKey], header: dict[str, Any]) -> Any:
    """The key in keys that the JWS header names; the crypto key itself.

    With a header kid it must be a non-empty string equal to the kid of exactly
    one key; without kid, keys must hold exactly one key. Any other case, an
    empty set or a nil selected key included, is a ValueError: no key verifies
    the token. h is untrusted; only kid is read.
    """
    if not keys:
        raise ValueError("issuerkey: the resolver returned no key for this issuer")
    if "kid" in header:
        kid = header["kid"]
        # A JSON number decodes to a str subclass; only a real string is a kid.
        if not isinstance(kid, str) or isinstance(kid, JsonNumber) or kid == "":
            raise ValueError("issuerkey: header kid is not a non-empty string")
        hits = [k for k in keys if k.kid == kid]
        if len(hits) != 1:
            raise ValueError(f"issuerkey: {len(hits)} of the keys the resolver returned have the header kid, want 1")
        key = hits[0].public
    else:
        if len(keys) != 1:
            raise ValueError(f"issuerkey: no header kid and {len(keys)} keys, want 1")
        key = keys[0].public
    if key is None:
        raise ValueError("issuerkey: the selected key is nil")
    return key


def select_key(keys: list[PublicKey], kid: str | None = None, header: dict | None = None) -> PublicKey:
    """Legacy form of select: returns the PublicKey entry (kid argument used when header is None)."""
    if header is None:
        header = {"kid": kid} if kid else {}
    chosen = select(keys, header)
    for k in keys:
        if k.public is chosen:
            return k
    raise ValueError("issuerkey: the selected key is nil")  # unreachable
