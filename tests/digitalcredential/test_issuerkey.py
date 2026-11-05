"""Go: digitalcredential/issuerkey/issuerkey_test.go."""

import pytest

from digitalcredential.errors import errors_is
from digitalcredential.issuerkey import ErrIssuerNotSupported, PublicKey, select
from digitalcredential.issuerkey_multi import multi
from jose.errors import ErrInvalidArgument
from jose.json import JsonNumber

from dc_helpers import new_key


def pub():
    return new_key().public_key()


def test_select():
    # The selection rule (stricter than RFC 7517 §4.5 and draft-ietf-oauth-sd-jwt-vc-19 §4): a
    # header kid that is a non-empty string names exactly one key; no kid needs exactly one key;
    # anything else selects nothing, so a token never makes the verifier try keys in turn.
    a, b, d1, d2 = pub(), pub(), pub(), pub()
    two = [PublicKey(a, "a"), PublicKey(b, "b")]
    ok = [
        ("kid names one of two", two, {"kid": "b"}, b),
        ("no kid, one key", [PublicKey(a, "a")], {}, a),
    ]
    for name, keys, header, want in ok:
        assert select(keys, header) is want, name
    bad = [
        ("kid names none", two, {"kid": "c"}),
        ("no kid, two keys", two, {}),
        ("no kid, empty set", [], {}),
        ("kid not a string", [PublicKey(a, "a")], {"kid": JsonNumber("7")}),
        ("kid empty", [PublicKey(a, "")], {"kid": ""}),
        ("kid on two keys", [PublicKey(d1, "d"), PublicKey(d2, "d")], {"kid": "d"}),
        ("selected key nil", [PublicKey(None, "a")], {"kid": "a"}),
    ]
    for name, keys, header in bad:
        with pytest.raises(ValueError):
            select(keys, header)


class PrefixResolver:
    def __init__(self, prefix, keys=None, err=None):
        self.prefix, self._keys, self.err, self.calls = prefix, keys or [], err, 0

    def keys(self, iss):
        self.calls += 1
        if not iss.startswith(self.prefix):
            raise ErrIssuerNotSupported("issuer not supported")
        if self.err is not None:
            raise self.err
        return self._keys


def test_multi():
    # Multi asks in order, passes on only ErrIssuerNotSupported, and a failed fetch never moves
    # the issuer to another key source.
    ka, kb = [PublicKey(pub(), "a")], [PublicKey(pub(), "b")]
    a, b = PrefixResolver("did:", ka), PrefixResolver("https://", kb)
    m = multi(a, b)
    assert [k.kid for k in m.keys("did:x")] == ["a"]
    assert [k.kid for k in m.keys("https://x")] == ["b"]
    with pytest.raises(ErrIssuerNotSupported):
        m.keys("ftp://x")

    fetch = RuntimeError("fetch failed")
    c = PrefixResolver("https://", err=fetch)
    m = multi(c, b)
    b.calls = 0
    with pytest.raises(RuntimeError) as ei:
        m.keys("https://x")
    assert ei.value is fetch and b.calls == 0

    # a wrapped ErrIssuerNotSupported (errors.Is) still passes on to the next resolver
    class Wrapping:
        def keys(self, iss):
            raise ValueError("resolver: nope") from ErrIssuerNotSupported("x")

    assert [k.kid for k in multi(Wrapping(), b).keys("https://x")] == ["b"]

    with pytest.raises(ErrInvalidArgument):
        multi()
    with pytest.raises(ErrInvalidArgument):
        multi(a, None)
