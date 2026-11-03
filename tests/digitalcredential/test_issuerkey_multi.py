from __future__ import annotations

from digitalcredential.issuerkey import PublicKey, select_key
from digitalcredential.issuerkey_multi import ErrIssuerNotSupported, multi


class _PrefixResolver:
    def __init__(self, prefix: str, keys: list[PublicKey] | None = None, err: Exception | None = None) -> None:
        self.prefix = prefix
        self.keys_list = keys or []
        self.err = err
        self.calls = 0

    def keys(self, iss: str) -> list[PublicKey]:
        self.calls += 1
        if not iss.startswith(self.prefix):
            raise ErrIssuerNotSupported()
        if self.err is not None:
            raise self.err
        return self.keys_list


def test_select_kid_rules() -> None:
    a = PublicKey(public_key=b"\x04" + b"\x01" * 64, kid="a")
    b = PublicKey(public_key=b"\x04" + b"\x02" * 64, kid="b")
    two = [a, b]
    assert select_key(two, None, {"kid": "b"}) is b
    assert select_key([a], None, {}) is a
    for keys, kid, hdr in [
        (two, None, {"kid": "c"}),
        (two, None, {}),
        ([], None, {}),
        ([a], None, {"kid": 7}),
        ([a], None, {"kid": ""}),
        ([PublicKey(public_key=b"\x04" + b"\x03" * 64, kid="d")] * 2, None, {"kid": "d"}),
    ]:
        try:
            select_key(keys, kid, hdr)
            raise AssertionError("expected error")
        except ValueError:
            pass


def test_multi_resolver_order() -> None:
    ka = [PublicKey(public_key=b"\x04" + b"\x01" * 64, kid="a")]
    kb = [PublicKey(public_key=b"\x04" + b"\x02" * 64, kid="b")]
    a = _PrefixResolver("did:", ka)
    b = _PrefixResolver("https://", kb)
    m = multi(a, b)
    got = m.keys("did:x")
    assert len(got) == 1 and got[0].kid == "a"
    got = m.keys("https://x")
    assert len(got) == 1 and got[0].kid == "b"
    try:
        m.keys("ftp://x")
        raise AssertionError("expected ErrIssuerNotSupported")
    except ErrIssuerNotSupported:
        pass

    fetch_err = RuntimeError("fetch failed")
    c = _PrefixResolver("https://", err=fetch_err)
    m = multi(c, b)
    b.calls = 0
    try:
        m.keys("https://x")
        raise AssertionError("expected fetch error")
    except RuntimeError as exc:
        assert exc is fetch_err
    assert b.calls == 0
