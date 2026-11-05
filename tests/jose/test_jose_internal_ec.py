"""Port of jose/internal/ec/ec_test.go plus the key checks Go gets from its types."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as cec, ed25519
from eth_keys import keys as eth_keys

from jose import ErrUnsupportedKey
from jose.internal import ec
from jose.internal.ec import Kind, Point, in_scalar_range
from jose_helpers import N_P256


def test_invalid_kind_raises():
    from types import SimpleNamespace

    bogus = SimpleNamespace()  # not a member of the enum
    with pytest.raises(ValueError):
        Kind.name(bogus)
    with pytest.raises(ValueError):
        Kind.curve(bogus)
    with pytest.raises(ValueError):
        Point(bogus, b"\0" * 32, b"\0" * 32).check_on_curve()
    with pytest.raises(ValueError):
        ec.verify_rs(Point(bogus, b"\0" * 32, b"\0" * 32), b"\0" * 32, b"\1" * 64)


def test_in_scalar_range():
    assert not in_scalar_range(None, N_P256)
    assert not in_scalar_range(0, N_P256)
    assert in_scalar_range(1, N_P256)
    assert in_scalar_range(N_P256 - 1, N_P256)
    assert not in_scalar_range(N_P256, N_P256)
    assert not in_scalar_range(1, None)


def test_from_public_key_classes():
    p256 = cec.generate_private_key(cec.SECP256R1()).public_key()
    k1 = cec.generate_private_key(cec.SECP256K1()).public_key()
    p384 = cec.generate_private_key(cec.SECP384R1()).public_key()
    assert ec.from_public_key(p256).kind is Kind.P256
    assert ec.from_public_key(k1).kind is Kind.SECP256K1
    # a secp256k1 key from another library is recognised the same
    assert ec.from_public_key(eth_keys.PrivateKey(b"\x01" * 32).public_key).kind is Kind.SECP256K1
    for bad in (p384, ed25519.Ed25519PrivateKey.generate().public_key(), "x", 1):
        with pytest.raises(ErrUnsupportedKey):
            ec.from_public_key(bad)
    with pytest.raises(ValueError) as e:
        ec.from_public_key(None)
    assert not isinstance(e.value, ErrUnsupportedKey)


def test_point_off_curve():
    k = cec.generate_private_key(cec.SECP256R1()).public_key().public_numbers()
    pt = Point(Kind.P256, k.x.to_bytes(32, "big"), (k.y + 1).to_bytes(32, "big"))
    with pytest.raises(ValueError):
        pt.check_on_curve()
    # x or y >= p is out of range too
    p = 2**256 - 2**224 + 2**192 + 2**96 - 1
    with pytest.raises(ValueError):
        Point(Kind.P256, (k.x + p).to_bytes(32, "big") if k.x + p < 2**256 else b"\xff" * 32, k.y.to_bytes(32, "big")).check_on_curve()


def test_from_private_key_checks():
    p256 = cec.generate_private_key(cec.SECP256R1())
    other = cec.generate_private_key(cec.SECP256R1())
    assert ec.from_private_key(p256).point.kind is Kind.P256
    assert ec.from_private_key(eth_keys.PrivateKey(b"\x02" * 32)).point.kind is Kind.SECP256K1
    with pytest.raises(ErrUnsupportedKey):
        ec.from_private_key(cec.generate_private_key(cec.SECP384R1()))
    with pytest.raises(ErrUnsupportedKey):
        ec.from_private_key(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(ValueError):
        ec.from_private_key(None)
    # a key whose two halves disagree cannot be built with these classes; the check is on d*G
    k = ec.from_private_key(p256)
    k.point = ec.from_private_key(other).point
    assert k._public_bytes() != k.point.uncompressed()
