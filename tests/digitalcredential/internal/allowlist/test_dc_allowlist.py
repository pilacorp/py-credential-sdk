import pytest

from digitalcredential.internal import allowlist as al

HINTS = al.Hints(all="leave empty", finer="wrap it")


@pytest.mark.parametrize("e", ["https://a.example", "https://a.example/", "https://a.example:8443", "https://*.a.example",
                               "HTTPS://A.EXAMPLE", "https://[2001:db8::1]", "https://[2001:db8::1]:8443/"])
def test_check_accepts(e):
    assert al.check(e, HINTS) == ""


@pytest.mark.parametrize("e,frag", [
    ("*", '"*"'), ("http://a.example", "https://"), ("a.example", "https://"),
    ("https://a.example/path", "not an origin"), ("https://a.example?q", "not an origin"), ("https://a.example#f", "not an origin"),
    ("https://u@a.example", "not an origin"), ("https://*.*.a.example", "not an origin"), ("https://a*.example", "not an origin"),
    ("https://a.example.", "empty label"), ("https://bücher.example", "not ASCII"), ("https://a..example", "empty label"),
    ("https://a.example:0443", "leading zeros"), ("https://a.example:0", "leading zeros"), ("https://a.example:65536", "leading zeros"),
    ("https://*.[2001:db8::1]", ":"), ("https://[a.example]", ":"),
])
def test_check_rejects(e, frag):
    assert frag in al.check(e, HINTS), e


def test_finer_hint_only_for_paths():
    assert "wrap it" in al.check("https://a.example/x", HINTS)
    assert "wrap it" not in al.check("https://a.example/x", al.Hints())


def test_covers():
    l = al.new(["https://a.example", "https://*.b.example:8443", "https://[2001:db8::1]"])
    assert l.covers("https://A.Example/anything?q#f")
    assert l.covers("https://a.example:443/")
    assert not l.covers("https://a.example:8443/")
    assert not l.covers("https://x.a.example/")
    assert l.covers("https://x.y.b.example:8443/")
    assert not l.covers("https://b.example:8443/")  # the apex is no subdomain
    assert not l.covers("https://x.b.example/")      # port 443
    assert l.covers("https://[2001:db8::1]/")
    assert not l.covers("http://a.example/")
    # A path cannot pose as a host; a zone ending in the entry host is no subdomain.
    assert not l.covers("https://evil.example/a.example")
    assert not l.covers("https://[2001:db8::1%25.b.example]:8443/")
    assert not l.covers("https://a.example@evil.example/")  # userinfo is refused outright


def test_empty_covers_everything_but_redirects_to_adds_nothing():
    assert al.new([]).covers("https://anything.example/")
    r = al.redirects_to([])
    assert not r.follows("https://a.example/x", "https://b.example/y")
    assert r.follows("https://a.example/x", "https://A.example:443/y")


def test_redirects():
    r = al.redirects_to(["https://b.example"])
    assert r.follows("https://a.example/", "https://b.example/z")
    assert not r.follows("https://a.example/", "https://c.example/z")
    assert not r.follows("https://a.example:8443/", "https://a.example/z")  # another port is another origin
    assert al.redirects_any().follows("https://a.example/", "https://c.example/")
    # Unicode case folding does not make two hosts one: KELVIN SIGN is not "k".
    assert not al.Redirects().follows("https://k.example/", "https://K.example/")
