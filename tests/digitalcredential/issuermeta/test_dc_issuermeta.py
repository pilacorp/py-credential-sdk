import base64
import pathlib
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_helpers"))
from dcsub_http import Reply, Server, redirect, routed_client  # noqa: E402

from digitalcredential import issuermeta as im  # noqa: E402
from digitalcredential.internal.safehttp import StatusError, as_, is_  # noqa: E402
from digitalcredential.issuerkey import ErrIssuerNotSupported, ErrNoUsableKey  # noqa: E402
from jose.errors import ErrInvalidArgument  # noqa: E402

FIG14 = """{
   "issuer":"https://example.com",
   "jwks":{
      "keys":[
         {"kid":"doc-signer-05-25-2022","kty": "EC", "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"},
         {"kid":"doc-signer-06-05-2025","kty": "EC", "crv": "P-256",
            "x":"DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8","y":"NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"}
      ]
   }
}"""
AX, AY = "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ", "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
BX, BY = "DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8", "NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"
TWO_KEYS = (
    '{"keys":[{"kid":"doc-signer-05-25-2022","kty":"EC","crv":"P-256","x":"%s","y":"%s"},'
    '{"kid":"doc-signer-06-05-2025","kty":"EC","crv":"P-256","x":"%s","y":"%s"}]}' % (AX, AY, BX, BY)
)
T0 = datetime.fromtimestamp(1_800_000_000, tz=timezone.utc)


def coord(s):
    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")


def x_of(k):
    return k.public.public_numbers().x


class Meta:
    """metaServer: routes[path] = (content_type, cache_control, body); redirects[path] = location."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.redirects = {}
        self.redirected = 0
        self.moved = 0
        self.srv = Server(self.handle)
        self.logical: list[str] = []

    def handle(self, r):
        path = r.path.split("?")[0]
        if path == "/moved":
            self.moved += 1
        if path in self.redirects:
            self.redirected += 1
            return redirect(self.redirects[path])
        if path not in self.routes:
            return Reply("not found", 404, ctype="text/plain")
        ct, cc, body = self.routes[path]
        return Reply(body, headers={"Cache-Control": cc} if cc else {}, ctype=ct)

    @property
    def hits(self):
        return self.srv.hits

    def resolver(self, allowed=None, now=None, disable_cache=False, redirects=None):
        cfg = im.ResolverConfig(
            trusted_issuer_origins=allowed or [],
            disable_cache=disable_cache,
            redirects=redirects or im.RedirectPolicy(),
            http_client=routed_client(self.srv, self.logical),
            now=(lambda: now[0]) if now is not None else None,
        )
        return im.new_resolver(cfg)


@pytest.fixture
def meta():
    made = []

    def mk(routes=None):
        m = Meta(routes)
        made.append(m)
        return m

    yield mk
    for m in made:
        m.srv.close()


def metadata(issuer, jwks):
    return ("application/json", "max-age=3600", '{"issuer":"%s","jwks":%s}' % (issuer, jwks))


@pytest.mark.parametrize("iss,want", [
    ("https://example.com", "https://example.com/.well-known/jwt-vc-issuer"),
    ("https://example.com/tenant/1234", "https://example.com/.well-known/jwt-vc-issuer/tenant/1234"),
    ("https://example.com/", "https://example.com/.well-known/jwt-vc-issuer"),
])
def test_metadata_url(iss, want):
    assert im.metadata_url(iss) == want


def test_figure14(meta):
    s = meta({"/.well-known/jwt-vc-issuer": ("application/json", "max-age=3600", FIG14)})
    now = [T0]
    r = s.resolver(["https://example.com"], now)
    keys = r.keys("https://example.com")
    assert [k.kid for k in keys] == ["doc-signer-05-25-2022", "doc-signer-06-05-2025"]
    assert x_of(keys[0]) == coord(AX) and x_of(keys[1]) == coord(BX)
    now[0] = T0 + timedelta(seconds=3599)
    r.keys("https://example.com")
    assert s.hits == 1  # a cache hit
    now[0] += timedelta(seconds=1)
    r.keys("https://example.com")
    assert s.hits == 2  # refetch at 3600 s
    nc = s.resolver(["https://example.com"], now, disable_cache=True)
    for _ in range(2):
        nc.keys("https://example.com")
    assert s.hits == 4


def test_cache_at_most_24_hours(meta):
    s = meta({"/.well-known/jwt-vc-issuer": ("application/json", "max-age=31536000", FIG14)})
    now = [T0]
    r = s.resolver(["https://example.com"], now)
    for at in (timedelta(0), timedelta(hours=24, seconds=-1), timedelta(hours=24)):
        now[0] = T0 + at
        r.keys("https://example.com")
    assert s.hits == 2  # cached until +24h, fetched again at +24h


def test_figure15(meta):
    s = meta({
        "/.well-known/jwt-vc-issuer": ("application/json", "max-age=3600",
                                       '{"issuer":"https://example.com","jwks_uri":"https://jwt-vc-issuer.example.com/my_public_keys.jwks"}'),
        "/my_public_keys.jwks": ("application/jwk-set+json", "max-age=60", TWO_KEYS),
    })
    now = [T0]
    r = s.resolver(["https://example.com"], now)
    keys = r.keys("https://example.com")
    assert len(keys) == 2 and x_of(keys[0]) == coord(AX)
    now[0] = T0 + timedelta(seconds=59)
    r.keys("https://example.com")
    assert s.hits == 2  # cache hit
    now[0] = T0 + timedelta(seconds=60)
    r.keys("https://example.com")
    assert s.hits == 4  # both documents fetched again: the shorter max-age decides


BAD_ENTRIES = [
    "https:/", "http://example.com", "example.com", "https://",
    "**", "https://*", "https://a*.example.com/", "https://*.*.example.com/", "https://*example.com/",
    "https://*.example.com/x", "https://user@*.example.com/", "https://*.example.com?x",
    "https://example.com/tenant/", "https://example.com/tenant", "https://example.com/a*b",
    "https://example.com?x=*", "https://example.com/?x=/", "https://example.com/#x", "https://user@example.com/",
    "https://example.com.", "https://*.example.com./", "https://bücher.example", "https://b%C3%BCcher.example",
    "https://.example.com", "https://a..example.com", "https://*..example.com",
    "https://example.com:0443", "https://example.com:0", "https://example.com:65536", "*",
]


def test_new_resolver():
    im.new_resolver(im.ResolverConfig())
    for e in BAD_ENTRIES:
        with pytest.raises(ErrInvalidArgument):
            im.new_resolver(im.ResolverConfig(trusted_issuer_origins=["https://ok.example/", e]))
        with pytest.raises(ErrInvalidArgument, match=r"RedirectTo\[1\]"):
            im.new_resolver(im.ResolverConfig(redirects=im.redirect_to("https://ok.example/", e)))
    with pytest.raises(ErrInvalidArgument, match="Resolver that wraps this one"):
        im.new_resolver(im.ResolverConfig(trusted_issuer_origins=["https://example.com/tenant/"]))
    with pytest.raises(ErrInvalidArgument, match="leave Config.TrustedIssuerOrigins empty"):
        im.new_resolver(im.ResolverConfig(trusted_issuer_origins=["*"]))
    with pytest.raises(ErrInvalidArgument, match="RedirectAny"):
        im.new_resolver(im.ResolverConfig(redirects=im.redirect_to("*")))
    with pytest.raises(ErrInvalidArgument):
        im.new_resolver(im.ResolverConfig(redirects=im.redirect_to()))
    for e in ["https://example.com/", "https://example.com", "https://EXAMPLE.com:443", "https://example.com:8443/",
              "https://xn--bcher-kva.example", "https://*.example.com", "https://*.example.com/", "https://*.example.com:8443/"]:
        im.new_resolver(im.ResolverConfig(trusted_issuer_origins=[e], redirects=im.redirect_to(e)))
    im.new_resolver(im.ResolverConfig(redirects=im.redirect_any()))


def test_cache_budget():
    from digitalcredential.issuermeta import cache as c

    now = [T0]
    r = im.new_resolver(im.ResolverConfig(now=lambda: now[0]))
    r.store("https://old", [], now[0], now[0] + timedelta(seconds=1))
    now[0] += timedelta(seconds=2)
    big = "https://a/" + "a" * (c.MAX_CACHE_BYTES - c.ENTRY_COST - 110)
    r.store(big, [], now[0], now[0] + timedelta(hours=1))
    r.store("https://b", [], now[0], now[0] + timedelta(hours=1))
    assert r.cached(big) is not None  # within the budget
    assert r.cached("https://b") is None  # over the budget


def test_keys_refused(meta):
    s = meta()
    r = s.resolver(None, [T0])
    for iss in ["", "https://user@example.com", "https://example.com?", "https://bücher.example", "https:///issuer", "https:x"]:
        with pytest.raises(ErrIssuerNotSupported):
            r.keys(iss)
    assert s.hits == 0


def test_trusted_issuer_origins(meta):
    covered = ["https://example.com", "https://example.com/tenant/1", "https://EXAMPLE.com:443/tenant/2", "https://example.com/tenant/caf%C3%A9"]
    subs = ["https://a.example.com/sub/1", "https://B.example.com:443/sub/2"]
    routes = {}
    for iss in covered + subs:
        routes[urlsplit(im.metadata_url(iss)).path] = metadata(iss, TWO_KEYS)
    cases = [
        ("empty", None, covered + subs, []),
        ("subdomain", ["https://*.example.com"], subs, [
            "https://example.com/tenant/1", "https://evilexample.com/sub/1", "https://a.example.com.evil/sub/1",
            "https://a.example.com:8443/sub/1", "https://attacker.example/a.example.com", "https://attacker.example/.example.com",
            "https://[2001:db8::1%25.example.com]/sub/1"]),
        ("origin", ["https://example.com/"], covered, ["https://example.org/tenant/1", "https://example.com:8443/tenant/1", "https://sub.example.com/tenant/1"]),
        ("origin without the final /", ["https://example.com"], covered, ["https://example.org/tenant/1", "https://example.com:8443/tenant/1", "https://sub.example.com/tenant/1"]),
        ("origin with its default port", ["https://EXAMPLE.com:443"], covered, ["https://example.com:8443/tenant/1"]),
    ]
    for name, allowed, ok, refused in cases:
        s = meta(routes)
        r = s.resolver(allowed, [T0], redirects=im.redirect_any())
        for iss in refused:
            with pytest.raises(ErrIssuerNotSupported):
                r.keys(iss)
        assert s.hits == 0, name
        for iss in ok:
            assert len(r.keys(iss)) == 2, (name, iss)


def test_issuer_mismatch_not_cached(meta):
    s = meta({"/.well-known/jwt-vc-issuer/tenant/1234": metadata("https://example.com/tenant/1234/", TWO_KEYS)})
    r = s.resolver(["https://example.com/"], [T0])
    for _ in range(2):
        with pytest.raises(ErrNoUsableKey):
            r.keys("https://example.com/tenant/1234")
    assert s.hits == 2


@pytest.mark.parametrize("jwks_uri", ["http://example.com/jwks", "https://bücher.example/jwks"])
def test_jwks_uri_http(meta, jwks_uri):
    s = meta({
        "/.well-known/jwt-vc-issuer": ("application/json", "", '{"issuer":"https://example.com","jwks_uri":"%s"}' % jwks_uri),
        "/jwks": ("application/json", "", TWO_KEYS),
    })
    r = s.resolver(["https://example.com"], [T0])
    with pytest.raises(ErrNoUsableKey):
        r.keys("https://example.com")
    assert s.hits == 1  # the metadata only


def test_default_client_refuses_loopback(meta):
    s = meta()
    r = im.new_resolver(im.ResolverConfig())
    with pytest.raises(ErrIssuerNotSupported):
        r.keys(s.srv.url)  # http://127.0.0.1: not https, refused before any request
    # an https issuer on loopback: the dial step refuses it
    s2 = Server(lambda q: Reply("{}"), tls=True)
    try:
        with pytest.raises(im.RetrievalError) as ei:
            r.keys(s2.url)
        assert is_(ei.value, im.ErrAddressBlocked)
        assert s2.hits == 0
    finally:
        s2.close()


def test_body_over_cap(meta):
    body = '{"issuer":"https://example.com","jwks":{"keys":[]},"pad":"' + "a" * (64 << 10) + '"}'
    s = meta({"/.well-known/jwt-vc-issuer": ("application/json", "", body)})
    r = s.resolver(["https://example.com"], [T0])
    with pytest.raises(im.RetrievalError) as ei:
        r.keys("https://example.com")
    assert is_(ei.value, im.ErrBodyTooLarge) and not isinstance(ei.value, (ErrNoUsableKey, ErrIssuerNotSupported))


def test_status_not_2xx(meta):
    s = meta()
    r = s.resolver(["https://example.com"], [T0])
    with pytest.raises(im.RetrievalError) as ei:
        r.keys("https://example.com")
    se = as_(ei.value, StatusError)
    assert se is not None and se.code == 404


def test_redirect_to_http(meta):
    s = meta({"/moved": metadata("https://example.com", TWO_KEYS)})
    s.redirects = {"/.well-known/jwt-vc-issuer": "http://example.com/moved"}
    r = s.resolver(None, [T0])
    with pytest.raises(im.RetrievalError) as ei:
        r.keys("https://example.com")
    assert is_(ei.value, im.ErrRedirectTargetNotAllowed) and not is_(ei.value, im.ErrRedirectNotAllowed)


def test_key_walk():
    def ec(extra=""):
        return '{"kty":"EC","crv":"P-256","x":"%s","y":"%s"%s}' % (AX, AY, extra)

    from jose import json as j

    def dec(s):
        return j.decode_json_object(s.encode())

    keys = im.signing_keys(dec('''{"keys":[
        {"kty":"RSA","e":"AQAB","n":"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ"},
        %s, %s, %s,
        {"kty":"EC","crv":"P-256","x":"%s","y":"%s","use":"sig","alg":"ES256","key_ops":["verify"]},
        {"kty":"EC","crv":"secp256k1","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg","kid":"k1s","alg":"ES256K"}
    ]}''' % (ec(',"kid":"enc","use":"enc"'), ec(',"kid":"ecdh","key_ops":["deriveKey"]'), ec(',"kid":"k1","alg":"ES256K"'), BX, BY)))
    assert len(keys) == 2 and keys[0].kid == "" and x_of(keys[0]) == coord(BX) and keys[1].kid == "k1s"
    with pytest.raises(ErrNoUsableKey):
        im.signing_keys(dec('{"keys":[%s,"x"]}' % ec()))
    assert im.signing_keys(dec('{"keys":[%s]}' % ec(',"use":"enc"'))) == []
    # members of the wrong JSON type skip the key too
    assert im.signing_keys(dec('{"keys":[%s]}' % ec(',"kid":1'))) == []
    assert im.signing_keys(dec('{"keys":[%s]}' % ec(',"key_ops":"verify"'))) == []
    assert im.signing_keys(dec('{"keys":[%s]}' % ec(',"use":1'))) == []


REDIRECT_CASES = [
    # name, allowed, policy, jwks_uri?, location, refused
    ("another hostname", ["https://example.com/"], None, False, "https://other.example/moved", True),
    ("another port", ["https://example.com/"], None, False, "https://example.com:8443/moved", True),
    ("another port, both origins listed", ["https://example.com/", "https://example.com:8443"], None, False, "https://example.com:8443/moved", True),
    ("empty TrustedIssuerOrigins, another port", None, None, False, "https://example.com:8443/moved", True),
    ("jwks_uri to another port", None, None, True, "https://example.com:8443/moved", True),
    ("same origin, another case and default port", ["https://example.com/"], None, False, "https://EXAMPLE.com:443/moved", False),
    ("jwks_uri, same origin", None, None, True, "https://example.com/moved", False),
    ("RedirectTo the target", ["https://example.com/"], im.redirect_to("https://example.com:9443", "https://EXAMPLE.com:8443/"), False, "https://example.com:8443/moved", False),
    ("RedirectTo another origin", ["https://example.com/"], im.redirect_to("https://example.com:9443"), False, "https://example.com:8443/moved", True),
    ("RedirectTo, same origin", ["https://example.com/"], im.redirect_to("https://example.com:9443"), False, "https://example.com/moved", False),
    ("RedirectTo, jwks_uri to the target", None, im.redirect_to("https://example.com:8443"), True, "https://example.com:8443/moved", False),
    ("RedirectAny", ["https://example.com/"], im.redirect_any(), False, "https://example.com:8443/moved", False),
]


@pytest.mark.parametrize("name,allowed,policy,jwks_uri,location,refused", REDIRECT_CASES, ids=[c[0] for c in REDIRECT_CASES])
def test_redirects(meta, name, allowed, policy, jwks_uri, location, refused):
    iss = "https://example.com/tenant/1"
    by_uri = ("application/json", "max-age=3600", '{"issuer":"%s","jwks_uri":"https://example.com/jwks"}' % iss)
    routes, frm = {"/moved": metadata(iss, TWO_KEYS)}, "/.well-known/jwt-vc-issuer/tenant/1"
    if jwks_uri:
        routes, frm = {frm: by_uri, "/moved": ("application/jwk-set+json", "", TWO_KEYS)}, "/jwks"
    s = meta(routes)
    s.redirects = {frm: location}
    r = s.resolver(allowed, [T0], redirects=policy)
    for _ in range(2):
        if refused:
            with pytest.raises(im.RetrievalError) as ei:
                r.keys(iss)
            assert is_(ei.value, im.ErrRedirectNotAllowed)
            assert "must serve it from that origin, or the verifier allows the target with RedirectTo" in str(ei.value)
        else:
            r.keys(iss)
    # Each call requests the redirect again: a refusal is not cached, and a 302 without freshness
    # keeps a followed answer out too.
    assert s.redirected == 2 and s.moved == (0 if refused else 2)


def test_preloaded_resolver():
    r = im.PreloadedResolver({"https://example.com": FIG14.encode()})
    assert [k.kid for k in r.keys("https://example.com")] == ["doc-signer-05-25-2022", "doc-signer-06-05-2025"]
    with pytest.raises(ErrIssuerNotSupported):
        r.keys("https://other.example")


def test_fetch_shortcut_and_old_shape():
    import json

    meta = json.dumps({"issuer": "https://example.com", "jwks": json.loads(TWO_KEYS)}).encode()
    calls = []

    def fetch(url):
        calls.append(url)
        return meta, {"content-type": "application/json", "cache-control": "max-age=3600"}

    r = im.new_resolver(im.ResolverConfig(trusted_issuer_origins=["https://example.com"], fetch=fetch))
    assert len(r.keys("https://example.com")) == 2 and len(r.keys("https://example.com")) == 2
    assert len(calls) == 1
