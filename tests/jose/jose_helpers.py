"""Shared helpers of the jose tests (Go helpers_test.go files)."""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys as eth_keys

from jose.jws import AlgES256, AlgES256K, private_key_signer, sign

CTX = object()  # Python has no context.Context; Sign only needs a non-None ctx.

N_P256 = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
N_K1 = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
K1_P = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798


def new_p256_signer():
    priv = ec.generate_private_key(ec.SECP256R1())
    return private_key_signer(priv), priv.public_key()


def new_secp_signer(with_recovery: bool = False):
    priv = ec.generate_private_key(ec.SECP256K1())
    s = private_key_signer(priv)
    if with_recovery:
        inner = s
        s = FuncSigner(AlgES256K, lambda data: inner.sign(CTX, data) + b"\x01")
    return s, priv.public_key()


class FuncSigner:
    """Signs as `alg` and answers whatever f returns for the signing input."""

    def __init__(self, alg, f):
        self._alg, self._f = alg, f

    def alg(self):
        return self._alg

    def sign(self, ctx, data):
        return self._f(data)


class CountingSigner:
    def __init__(self, inner):
        self.inner, self.calls = inner, 0

    def alg(self):
        return self.inner.alg()

    def sign(self, ctx, data):
        self.calls += 1
        return self.inner.sign(ctx, data)


def high_s(inner, n: int):
    """Wrap a signer and flip its s to n-s, the other valid encoding."""

    def f(data):
        raw = inner.sign(CTX, data)
        s = int.from_bytes(raw[32:64], "big")
        if s <= n >> 1:
            s = n - s
        return raw[:32] + s.to_bytes(32, "big")

    return FuncSigner(inner.alg(), f)


def must_sign(s, pub, header, payload: bytes | str) -> str:
    if isinstance(payload, str):
        payload = payload.encode()
    return sign(CTX, s, pub, header, payload)


def craft(s, header: str, payload: str) -> str:
    """Build a token from raw parts, signed by s over the given segments."""
    from jose import encode_segment

    signing_input = encode_segment(header.encode()) + "." + encode_segment(payload.encode())
    sig = s.sign(CTX, signing_input.encode())
    return signing_input + "." + encode_segment(sig[:64])


def b64(b: bytes) -> str:
    from jose import encode_segment

    return encode_segment(b)
