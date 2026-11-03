"""JWS Signer implementations."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Protocol

from jose.errors import ErrInvalidArgument, ErrUnsupportedAlg
from jose.internal.ec import from_private_key
from jose.internal.errtext import quote
from jose.jws.jws import _alg_of, _is_supported_alg, _key_error, _supported_algs


class Signer(Protocol):
    def alg(self) -> str: ...

    def sign(self, ctx: Any, signing_input: bytes) -> bytes: ...


class _PrivateKeySigner:
    def __init__(self, key: Any, alg: str) -> None:
        self._key = key
        self._alg = alg

    def alg(self) -> str:
        return self._alg

    def sign(self, ctx: Any, signing_input: bytes) -> bytes:
        digest = hashlib.sha256(signing_input).digest()
        return self._key.sign_rs(digest)


def private_key_signer(priv: Any) -> Signer:
    try:
        k = from_private_key(priv)
    except Exception as e:
        raise _key_error("private key", e) from e
    return _PrivateKeySigner(k, _alg_of(k.point.kind))


class _DigestSigner:
    def __init__(self, alg: str, sign: Callable[[Any, bytes], bytes]) -> None:
        self._alg = alg
        self._sign = sign

    def alg(self) -> str:
        return self._alg

    def sign(self, ctx: Any, signing_input: bytes) -> bytes:
        digest = hashlib.sha256(signing_input).digest()
        return self._sign(ctx, digest)


def digest_signer(alg: str, sign: Callable[[Any, bytes], bytes] | None) -> Signer:
    if not _is_supported_alg(alg):
        raise ErrUnsupportedAlg(f"signer alg {quote(alg)}; {_supported_algs}")
    if sign is None:
        raise ErrInvalidArgument("nil sign function")
    return _DigestSigner(alg, sign)
