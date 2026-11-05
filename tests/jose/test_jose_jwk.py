"""Port of jose/jwk/jwk_test.go."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as cec, ed25519

from jose import ErrUnsupportedKey, encode_segment, decode_segment
from jose.jwk import ErrBadKey, from_public_key, to_public_key


def p256():
    return cec.generate_private_key(cec.SECP256R1()).public_key()


def secp():
    return cec.generate_private_key(cec.SECP256K1()).public_key()


@pytest.mark.parametrize("name,make", [("P-256", p256), ("secp256k1", secp)])
def test_jwk_round_trip(name, make):
    key = make()
    jwk = from_public_key(key)
    assert set(jwk) == {"kty", "crv", "x", "y"} and jwk["kty"] == "EC" and jwk["crv"] == name
    back = to_public_key(jwk)
    assert back.public_numbers() == key.public_numbers()
    assert back.curve.name == key.curve.name


def key_with_leading_zero_x():
    for _ in range(20000):
        k = cec.generate_private_key(cec.SECP256R1()).public_key()
        if k.public_numbers().x.bit_length() <= 248:
            return k
    raise AssertionError("no key with a leading zero byte in x")


def test_rejects_stripped_leading_zero():
    key = key_with_leading_zero_x()
    jwk = from_public_key(key)
    assert len(decode_segment(jwk["x"])) == 32  # left-padded
    x = key.public_numbers().x
    jwk["x"] = encode_segment(x.to_bytes((x.bit_length() + 7) // 8, "big"))  # 31 bytes, same point
    with pytest.raises(ErrBadKey):
        to_public_key(jwk)


@pytest.mark.parametrize("make", [p256, secp])
def test_rejects_point_not_on_curve(make):
    key = make()
    jwk = from_public_key(key)
    jwk["y"] = encode_segment((key.public_numbers().y + 1).to_bytes(32, "big"))
    with pytest.raises(ErrBadKey):
        to_public_key(jwk)


def _with(base, k, v=...):
    m = dict(base)
    if v is None and k in ("kty", "crv", "y"):
        del m[k]
    else:
        m[k] = v
    return m


@pytest.mark.parametrize(
    "name,key,value,unsupported",
    [
        ("private key d", "d", "AAAA", False),
        ("kty RSA", "kty", "RSA", True),
        ("kty missing", "kty", None, False),
        ("crv P-384", "crv", "P-384", True),
        ("crv missing", "crv", None, False),
        ("x not string", "x", 1, False),
        ("x bad base64", "x", "QR", False),
        ("y missing", "y", None, False),
    ],
)
def test_to_public_key_rejects(name, key, value, unsupported):
    base = from_public_key(p256())
    # Each refusal matches exactly one of the two errors.
    with pytest.raises((ErrUnsupportedKey, ErrBadKey)) as e:
        to_public_key(_with(base, key, value))
    assert isinstance(e.value, ErrUnsupportedKey) == unsupported
    assert isinstance(e.value, ErrBadKey) != unsupported
    with pytest.raises(ErrBadKey):
        to_public_key(None)


def test_from_public_key_rejects_bad_keys():
    with pytest.raises(ErrBadKey):
        from_public_key(None)
    for bad in (cec.generate_private_key(cec.SECP384R1()).public_key(), ed25519.Ed25519PrivateKey.generate().public_key()):
        with pytest.raises(ErrUnsupportedKey):
            from_public_key(bad)


def test_includes_verify_and_members_of_secp256k1():
    base = from_public_key(secp())

    def w(k, v):
        m = dict(base)
        m[k] = v
        return m

    cases = {
        "alg ES256K": (w("alg", "ES256K"), True),
        "alg ES256": (w("alg", "ES256"), False),
        "alg es256k": (w("alg", "es256k"), False),
        "alg number": (w("alg", 1), False),
        "use sig": (w("use", "sig"), True),
        "use enc": (w("use", "enc"), False),
        "use null": (w("use", None), False),
        "key_ops [verify]": (w("key_ops", ["verify"]), True),
        "key_ops [sign, verify]": (w("key_ops", ["sign", "verify"]), True),
        "key_ops tuple": (w("key_ops", ("verify",)), False),  # not a decoded JSON array
        "key_ops [sign]": (w("key_ops", ["sign"]), False),
        "key_ops []": (w("key_ops", []), False),
        "key_ops [Verify]": (w("key_ops", ["Verify"]), False),
        "key_ops not an array": (w("key_ops", "verify"), False),
        "key_ops holding an array": (w("key_ops", [[], "verify"]), True),
    }
    for name, (jwk, ok) in cases.items():
        if ok:
            to_public_key(jwk)
        else:
            with pytest.raises(ErrBadKey):
                to_public_key(jwk)


def test_p256_does_not_read_alg_use_key_ops():
    jwk = from_public_key(p256())
    jwk.update({"alg": "whatever", "use": "enc", "key_ops": "x", "kid": 5})
    to_public_key(jwk)
