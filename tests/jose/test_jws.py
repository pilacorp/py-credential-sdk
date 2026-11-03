from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys

from jose.jws import AlgES256, AlgES256K, sign, verify
from jose.jws.signer import private_key_signer


def test_es256_sign_verify_round_trip() -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    signer = private_key_signer(priv)
    payload = b'{"iss":"https://x", "name":"Nguy\\u1ec5n <a&b>"}'
    token = sign(object(), signer, priv.public_key(), {"typ": "dc+sd-jwt", "kid": "key-2"}, payload)
    header, got = verify(token, priv.public_key(), None)
    assert got == payload
    assert header["alg"] == AlgES256
    assert header["typ"] == "dc+sd-jwt"
    assert header["kid"] == "key-2"


def test_es256k_sign_verify_round_trip() -> None:
    priv = keys.PrivateKey(os.urandom(32))
    signer = private_key_signer(priv)
    payload = b'{"sub":"0xabc"}'
    token = sign(object(), signer, priv.public_key, {"typ": "JWT"}, payload)
    header, got = verify(token, priv.public_key, [AlgES256K])
    assert got == payload
    assert header["alg"] == AlgES256K


def test_empty_payload_round_trip() -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    signer = private_key_signer(priv)
    token = sign(object(), signer, priv.public_key(), None, b"")
    parts = token.split(".")
    assert len(parts) == 3 and parts[1] == ""
    _, got = verify(token, priv.public_key(), None)
    assert got == b""
