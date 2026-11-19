from __future__ import annotations

from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

_HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
SUPPORTED_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")


def jws_alg(alg: str = "") -> str:
    return alg or "RS256"


class RSAProvider:
    """RSA JsonWebSignature2020 signer (Go signer.RSAProvider): signs a digest already hashed with alg's SHA."""

    def __init__(self, priv: rsa.RSAPrivateKey | None = None, alg: str = "", *, sign_func: Callable[[bytes], bytes] | None = None) -> None:
        self._alg = jws_alg(alg)
        if sign_func is not None:
            self._sign = sign_func
            return
        if priv is None:
            raise ValueError("rsa private key is nil")
        if self._alg not in SUPPORTED_ALGS:
            raise ValueError(f"unsupported JWS alg: {self._alg}")
        h = _HASHES[self._alg[2:]]()
        if self._alg.startswith("RS"):
            pad = padding.PKCS1v15()
        else:
            pad = padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size)
        self._sign = lambda digest: priv.sign(digest, pad, Prehashed(h))

    @classmethod
    def from_func(cls, sign_func: Callable[[bytes], bytes], alg: str = "") -> "RSAProvider":
        if sign_func is None:
            raise ValueError("sign function is nil")
        return cls(alg=alg, sign_func=sign_func)

    def algorithm(self) -> str:
        return self._alg

    jose_algorithm = algorithm

    def sign(self, digest: bytes) -> bytes:
        return self._sign(digest)
