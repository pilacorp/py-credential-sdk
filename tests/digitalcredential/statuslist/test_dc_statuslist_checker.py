import base64
import pathlib
import sys
import threading
import zlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_helpers"))
from dcsub_http import Reply, Server, redirect, routed_client  # noqa: E402

from digitalcredential import statuslist as sl  # noqa: E402
from digitalcredential.internal.safehttp import StatusError, as_, is_  # noqa: E402
from digitalcredential.issuerkey import PublicKey, SigningKey  # noqa: E402
from digitalcredential.statuslist import checker as ck  # noqa: E402
from jose import json as jj  # noqa: E402
from jose import jws  # noqa: E402
from jose.errors import ErrInvalidArgument, ErrMalformed, ErrUnsupportedAlg, ErrUnsupportedKey  # noqa: E402

CTX = object()
NOW = datetime.fromtimestamp(1686920170 + 3600, tz=timezone.utc)  # inside the validity of the §5.1 example token
LST16 = "eNrbuRgAAhcBXQ"  # §4.2, 16 entries
TYP = {"typ": "statuslist+jwt"}


def ts(n):
    return datetime.fromtimestamp(n, tz=timezone.utc)


def unix(t):
    return int(t.timestamp())


class KeySet:
    def __init__(self, m):
        self.m = m

    def keys(self, iss):
        return self.m.get(iss, [])


def new_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    return jws.private_key_signer(priv), priv.public_key()


def sign_claims(signer, pub, header, claims):
    return jws.sign(CTX, signer, pub, dict(header), jj.encode_json(claims))


def deflate(b):
    return zlib.compress(b)


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class ListServer:
    def __init__(self, tokens=None):
        self.tokens = tokens or {}
        self.types = {}
        self.srv = Server(self.handle, tls=True)

    def handle(self, r):
        path = r.path.split("?")[0]
        return Reply(self.tokens.get(path, ""), ctype=self.types.get(path, "application/statuslist+jwt"))

    @property
    def hits(self):
        return self.srv.hits

    def checker(self, issuers, now=None, **kw):
        c = sl.new_checker(sl.CheckerConfig(issuers=issuers, http_client=routed_client(self.srv), now=(lambda: now[0]) if now else (lambda: NOW), **kw))
        return c


@pytest.fixture
def lserver():
    made = []

    def mk(tokens=None):
        s = ListServer(tokens)
        made.append(s)
        return s

    yield mk
    for s in made:
        s.srv.close()


def test_draft21_section42_example(lserver):
    signer, pub = new_p256()
    l = sl.List.from_bytes(bytes([0xC9, 0x44, 0xF9]), 2)
    uri = "https://example.com/statuslists/1"
    token = l.issue_token(sl.TokenClaims(sub=uri, issued_at=ts(1686920170), expiry=ts(2291720170), ttl_seconds=43200),
                          SigningKey(signer, pub, "12"))
    s = lserver({"/statuslists/1": token})
    c = s.checker(KeySet({"https://example.com": [PublicKey(pub, "12")]}))
    for i, want in enumerate([1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3]):
        assert c.status(sl.Ref(uri, i), "https://example.com") == want


def test_checker_rejects(lserver):
    signer_a, pub_a = new_p256()
    signer_b, pub_b = new_p256()
    issuers = KeySet({"https://a.example": [PublicKey(pub_a, "a")]})
    header = {**TYP, "kid": "a"}
    base = "https://example.com/statuslists/"

    def claims(sub, mutate=None):
        m = {"sub": sub, "iat": unix(NOW - timedelta(hours=1)), "status_list": {"bits": 1, "lst": LST16}}
        if mutate:
            mutate(m)
        return m

    def signed(h, sub, mutate=None, who=(signer_a, pub_a)):
        return sign_claims(who[0], who[1], h, claims(sub, mutate))

    def status_list(**kw):
        return lambda m: m.update(status_list={"bits": 1, "lst": "eNrbuRgAAhcBXQ", **kw})

    def set_(**kw):
        return lambda m: m.update(kw)

    bomb = b64(deflate(bytes((16 << 20) + 1)))
    iat = unix(NOW - timedelta(hours=1))
    dup = jws.sign(CTX, signer_a, pub_a, dict(header),
                   ('{"sub":"%s11","iat":%d,"iat":1,"status_list":{"bits":1,"lst":"%s"}}' % (base, iat, LST16)).encode())
    # name, token, index, oob, sentinel
    tests = [
        ("lst inflates past 16 MiB", lambda s: signed(header, s, set_(status_list={"bits": 1, "lst": bomb})), 0, False, None),
        ("index outside the list", lambda s: signed(header, s), 16, True, None),
        ("sub is not the uri", lambda s: signed(header, base + "other"), 0, False, sl.ErrSubjectMismatch),
        ("signed by another issuer's key", lambda s: signed(header, s, who=(signer_b, pub_b)), 0, False, None),
        ("expired", lambda s: signed(header, s, set_(exp=unix(NOW - timedelta(minutes=2)))), 0, False, None),
        ("typ is not statuslist+jwt", lambda s: signed({"typ": "JWT", "kid": "a"}, s), 0, False, sl.ErrTokenType),
        ("iss naming another issuer", lambda s: signed(header, s, set_(iss="https://b.example")), 0, False, sl.ErrIssuerMismatch),
        ("iss not a string", lambda s: signed(header, s, set_(iss=1)), 0, False, sl.ErrIssuerMismatch),
        ("aud present", lambda s: signed(header, s, set_(aud=["https://verifier.example"])), 0, False, None),
        ("lst holds no entries", lambda s: signed(header, s, set_(status_list={"bits": 1, "lst": b64(deflate(b""))})), 0, True, None),
        ("not a JWS", lambda s: "not-a-jws", 0, False, None),
        ("kid naming no key of the issuer", lambda s: signed({**TYP, "kid": "z"}, s), 0, False, None),
        ("duplicate claim", lambda s: dup, 0, False, None),
        ("no iat", lambda s: signed(header, s, lambda m: m.pop("iat")), 0, False, ErrMalformed),
        ("iat a string", lambda s: signed(header, s, set_(iat="yesterday")), 0, False, None),
        ("iat after now and the skew", lambda s: signed(header, s, set_(iat=unix(NOW + timedelta(minutes=2)))), 0, False, sl.ErrIssuedInFuture),
        ("ttl 0", lambda s: signed(header, s, set_(ttl=0)), 0, False, ErrMalformed),
        ("ttl a string", lambda s: signed(header, s, set_(ttl="60")), 0, False, ErrMalformed),
        ("ttl negative", lambda s: signed(header, s, set_(ttl=-5)), 0, False, ErrMalformed),
        ("status_list a string", lambda s: signed(header, s, set_(status_list="eNrbuRgAAhcBXQ")), 0, False, None),
        ("bits a string", lambda s: signed(header, s, set_(status_list={"bits": "1", "lst": LST16})), 0, False, None),
        ("bits 3", lambda s: signed(header, s, set_(status_list={"bits": 3, "lst": LST16})), 0, False, None),
        ("lst a number", lambda s: signed(header, s, set_(status_list={"bits": 1, "lst": 1})), 0, False, None),
        ("lst not base64url", lambda s: signed(header, s, set_(status_list={"bits": 1, "lst": "eNr+"})), 0, False, None),
        ("lst not ZLIB", lambda s: signed(header, s, set_(status_list={"bits": 1, "lst": b64(bytes([0, 0]))})), 0, False, None),
    ]
    toks = {f"/statuslists/{i}": t[1](base + str(i)) for i, t in enumerate(tests)}
    toks["/statuslists/11"] = dup  # the duplicate-claim token names its own sub
    s = lserver(toks)
    c = s.checker(issuers)
    for i, (name, _, index, oob, sentinel) in enumerate(tests):
        with pytest.raises(Exception) as ei:
            c.status(sl.Ref(base + str(i), index), "https://a.example")
        err = ei.value
        # None is a caller mistake: an index outside the list included (draft 21 §8.3 step 6).
        assert not isinstance(err, ErrInvalidArgument), (name, err)
        assert is_(err, sl.ErrIndexOutOfBounds) == oob, (name, err)
        if sentinel:
            assert is_(err, sentinel), (name, err)


def test_cache_isolates_issuers(lserver):
    signer_a, pub_a = new_p256()
    _, pub_b = new_p256()
    uri = "https://example.com/statuslists/1"
    token = sign_claims(signer_a, pub_a, {**TYP, "kid": "k"}, {"sub": uri, "iat": unix(NOW - timedelta(hours=1)), "ttl": 3600,
                                                              "status_list": {"bits": 1, "lst": LST16}})
    s = lserver({"/statuslists/1": token})
    c = s.checker(KeySet({"https://a.example": [PublicKey(pub_a, "k")], "https://b.example": [PublicKey(pub_b, "k")]}))
    ref = sl.Ref(uri, 0)
    assert c.status(ref, "https://a.example") == 1
    with pytest.raises(Exception):
        c.status(ref, "https://b.example")
    assert c.status(ref, "https://a.example") == 1


@pytest.mark.parametrize("name,ttl,exp,last", [
    ("ttl", 60, None, 59), ("exp before ttl ends", 60, 30, 29), ("ttl past 24 hours", 365 * 24 * 3600, None, 24 * 3600 - 1)])
def test_cache_lifetime(lserver, name, ttl, exp, last):
    signer, pub = new_p256()
    uri = "https://example.com/statuslists/1"
    cl = {"sub": uri, "iat": unix(NOW - timedelta(hours=1)), "ttl": ttl, "status_list": {"bits": 1, "lst": LST16}}
    if exp:
        cl["exp"] = unix(NOW + timedelta(seconds=exp))
    s = lserver({"/statuslists/1": sign_claims(signer, pub, {**TYP, "kid": "k"}, cl)})
    now = [NOW]
    c = s.checker(KeySet({"https://a.example": [PublicKey(pub, "k")]}), now)
    for at in (0, last, last + 2):
        now[0] = NOW + timedelta(seconds=at)
        c.status(sl.Ref(uri, 0), "https://a.example")
    assert s.hits == 2  # cached until +last, fetched again after


def test_no_ttl_is_not_cached(lserver):
    signer, pub = new_p256()
    uri = "https://example.com/statuslists/1"
    s = lserver({"/statuslists/1": sign_claims(signer, pub, {**TYP, "kid": "k"}, {"sub": uri, "iat": unix(NOW - timedelta(hours=1)), "status_list": {"bits": 1, "lst": LST16}})})
    c = s.checker(KeySet({"https://a.example": [PublicKey(pub, "k")]}))
    for _ in range(3):
        c.status(sl.Ref(uri, 0), "https://a.example")
    assert s.hits == 3


def test_max_age(lserver):
    signer, pub = new_p256()
    uri = "https://example.com/statuslists/1"
    token = sign_claims(signer, pub, {**TYP, "kid": "k"}, {"sub": uri, "iat": unix(NOW - timedelta(hours=1)), "ttl": 3600, "status_list": {"bits": 1, "lst": LST16}})
    s = lserver({"/statuslists/1": token})
    now = [NOW]
    c = s.checker(KeySet({"https://a.example": [PublicKey(pub, "k")]}), now, max_age=timedelta(minutes=90))
    for at in (0, 30):  # aged 60 and 90 minutes
        now[0] = NOW + timedelta(minutes=at)
        c.status(sl.Ref(uri, 0), "https://a.example")
    now[0] = NOW + timedelta(minutes=32)  # aged 92 minutes, past 90 plus the 1-minute skew
    with pytest.raises(sl.ErrTooOld):
        c.status(sl.Ref(uri, 0), "https://a.example")
    assert s.hits == 2  # cached, then fetched again at the max age


def test_refetches_grown_list(lserver):
    signer, pub = new_p256()
    uri, iss = "https://example.com/statuslists/g", "https://a.example"

    def sign(entries, iat):
        l = sl.List.new(entries, 1)
        if entries > 12:
            l.set(12, 1)
        return l.issue_token(sl.TokenClaims(sub=uri, issued_at=iat, ttl_seconds=3600), SigningKey(signer, pub, "k"))

    s = lserver({"/statuslists/g": sign(8, NOW - timedelta(hours=1))})
    c = s.checker(KeySet({iss: [PublicKey(pub, "k")]}))
    c.status(sl.Ref(uri, 3), iss)
    with pytest.raises(sl.ErrIndexOutOfBounds):
        c.status(sl.Ref(uri, 12), iss)
    assert s.hits == 2  # the index past the cached list fetches again
    s.tokens["/statuslists/g"] = sign(16, NOW - timedelta(minutes=1))
    assert c.status(sl.Ref(uri, 12), iss) == 1
    assert c.status(sl.Ref(uri, 12), iss) == 1 and s.hits == 3  # the grown list replaced the cached one


def test_cache_budget():
    from digitalcredential.statuslist.cache import CacheKey, ListCache

    now = [NOW]
    cache = ListCache(lambda: now[0])
    iss = "https://a.example"

    def store(n, expires):
        key = CacheKey(iss, f"https://a.example/l/{n}")
        cache.store(key, sl.List.new(1 << 23, 1), now[0], expires)  # 1 MiB
        return cache.get(key)[0] is not None

    for n in range(31):
        assert store(n, NOW + timedelta(hours=1)), n
    assert not store(31, NOW + timedelta(hours=2))  # a 32nd list of 1 MiB, past the 32 MiB budget
    now[0] = NOW + timedelta(hours=1)
    assert store(32, NOW + timedelta(hours=2))  # the cached lists expired


def test_keeps_newer_list():
    from digitalcredential.statuslist.cache import CacheKey, ListCache

    cache = ListCache(lambda: NOW)
    key = CacheKey("https://a.example", "https://example.com/statuslists/1")
    expires = NOW + timedelta(minutes=1)
    cache.store(key, sl.List.from_bytes(b"\x01", 1), NOW - timedelta(seconds=1), expires)
    cache.store(key, sl.List.from_bytes(b"\x00", 1), NOW - timedelta(hours=1), expires)
    assert cache.get(key)[0].get(0) == 1  # from the newer token


def test_keeps_newer_list_fetched_meanwhile():
    signer, pub = new_p256()
    iss, uri = "https://a.example", "https://example.com/statuslists/1"

    def token(iat, entry0):
        return sign_claims(signer, pub, {**TYP, "kid": "k"}, {"sub": uri, "iat": unix(iat), "ttl": 3600,
                                                              "status_list": {"bits": 1, "lst": sl.List.from_bytes(bytes([entry0]), 1).encode()}})

    older, newer = token(NOW - timedelta(hours=1), 0), token(NOW - timedelta(minutes=1), 1)
    arrived, release = threading.Event(), threading.Event()
    hits = []

    def handler(r):
        hits.append(1)
        if len(hits) == 1:
            arrived.set()
            release.wait(10)
            return Reply(newer, ctype="application/statuslist+jwt")
        return Reply(older, ctype="application/statuslist+jwt")

    srv = Server(handler, tls=True)
    try:
        c = sl.new_checker(sl.CheckerConfig(issuers=KeySet({iss: [PublicKey(pub, "k")]}), http_client=routed_client(srv), now=lambda: NOW))
        ref = sl.Ref(uri, 0)
        out = []
        t = threading.Thread(target=lambda: out.append(c.status(ref, iss)))
        t.start()
        assert arrived.wait(10)
        assert c.status(ref, iss) == 0  # A: the older list
        release.set()
        t.join(10)
        assert out == [1]  # B: the newer list it fetched
        assert c.status(ref, iss) == 1  # later: the newer list is cached
    finally:
        srv.close()


def test_refuses_token_expired_while_decoding(lserver):
    signer, pub = new_p256()
    uri = "https://example.com/statuslists/1"
    token = sign_claims(signer, pub, {**TYP, "kid": "k"}, {"sub": uri, "iat": unix(NOW - timedelta(hours=1)),
                                                          "exp": unix(NOW - ck.DEFAULT_CLOCK_SKEW + timedelta(seconds=1)),
                                                          "status_list": {"bits": 1, "lst": LST16}})
    s = lserver({"/statuslists/1": token})
    holder = {}
    late = [False]

    def now():
        late[0] = late[0] or holder["c"]._slots._value < ck.DECODE_SLOTS
        return NOW + timedelta(minutes=1) if late[0] else NOW

    c = sl.new_checker(sl.CheckerConfig(issuers=KeySet({"https://a.example": [PublicKey(pub, "k")]}), http_client=routed_client(s.srv), now=now))
    holder["c"] = c
    with pytest.raises(Exception):
        c.status(sl.Ref(uri, 0), "https://a.example")
    assert late[0]


def test_refuses_private_address():
    srv = Server(lambda r: Reply(""), tls=True)
    try:
        c = sl.new_checker(sl.CheckerConfig(issuers=KeySet({})))
        with pytest.raises(sl.StatusFetchError) as ei:
            c.status(sl.Ref(srv.url + "/statuslists/1", 0), "https://a.example")
        assert is_(ei.value, sl.ErrAddressBlocked)
        assert srv.hits == 0
    finally:
        srv.close()


def test_http_and_insecure_http():
    signer, pub = new_p256()
    l = sl.List.new(16, 1)
    l.set(3, 1)
    state = {}
    plain = Server(lambda r: redirect("/lists/1") if r.path == "/statuslists/1" else Reply(state["token"], ctype="application/statuslist+jwt"))
    try:
        uri = plain.url + "/statuslists/1"
        state["token"] = l.issue_token(sl.TokenClaims(sub=uri, issued_at=ts(1686920170)), SigningKey(signer, pub))
        issuers = KeySet({"https://a.example": [PublicKey(pub)]})
        ref = sl.Ref(uri, 3)
        c = sl.new_checker(sl.CheckerConfig(issuers=issuers, http_client=plain.client()))
        with pytest.raises(sl.ErrURINotSupported) as ei:
            c.status(ref, "https://a.example")
        assert not isinstance(ei.value, ErrInvalidArgument)
        assert plain.hits == 0
        # The refusal leaves the uri out: it may carry a password in its userinfo or a token in its query.
        for u in ("http://alice:SYNTHETIC_PASSWORD@status.example/list", "http://status.example/list?token=SYNTHETIC_QUERY_SECRET"):
            with pytest.raises(Exception) as ei:
                c.status(sl.Ref(u, 0), "https://a.example")
            assert not isinstance(ei.value, ErrInvalidArgument) and "SYNTHETIC" not in str(ei.value)

        down = Server(lambda r: redirect(uri), tls=True)
        try:
            c2 = sl.new_checker(sl.CheckerConfig(issuers=issuers, http_client=down.client()))
            with pytest.raises(sl.StatusFetchError) as ei:
                c2.status(sl.Ref(down.url + "/statuslists/1", 0), "https://a.example")
            assert is_(ei.value, sl.ErrRedirectTargetNotAllowed) and plain.hits == 0
        finally:
            down.close()

        c3 = sl.new_checker(sl.CheckerConfig(issuers=issuers, http_client=plain.client(), insecure_http=True, now=lambda: NOW))
        for u in ("urn:example:list", "http://user@" + plain.url.removeprefix("http://") + "/statuslists/1"):
            with pytest.raises(sl.ErrURINotSupported):
                c3.status(sl.Ref(u, 0), "https://a.example")
        assert c3.status(ref, "https://a.example") == 1
        assert plain.hits == 2  # a redirect, then the token
    finally:
        plain.close()


def test_allowed_algs(lserver):
    from eth_keys import keys as eth_keys

    priv = eth_keys.PrivateKey(b"\x01" * 32)
    signer = jws.private_key_signer(priv)
    pub = priv.public_key
    uri = "https://example.com/statuslists/1"
    token = sign_claims(signer, pub, {**TYP, "kid": "k"}, {"sub": uri, "iat": unix(NOW - timedelta(hours=1)), "status_list": {"bits": 1, "lst": LST16}})
    s = lserver({"/statuslists/1": token})
    issuers = KeySet({"https://a.example": [PublicKey(pub, "k")]})
    with pytest.raises(jws.ErrAlgNotAllowed):
        s.checker(issuers, allowed_algs=["ES256"]).status(sl.Ref(uri, 0), "https://a.example")
    assert s.checker(issuers).status(sl.Ref(uri, 0), "https://a.example") == 1  # default: ES256 and ES256K
    with pytest.raises(ErrInvalidArgument) as ei:
        sl.new_checker(sl.CheckerConfig(issuers=KeySet({}), allowed_algs=["RS256"]))
    assert isinstance(ei.value, ErrUnsupportedAlg)


def test_new_checker_validates():
    for kw in ({"clock_skew": timedelta(seconds=-1)}, {"max_age": timedelta(seconds=-1)}):
        with pytest.raises(ErrInvalidArgument):
            sl.new_checker(sl.CheckerConfig(issuers=KeySet({}), **kw))
    with pytest.raises(ErrInvalidArgument):
        sl.new_checker(sl.CheckerConfig(issuers=None))
    c = sl.new_checker(sl.CheckerConfig(issuers=KeySet({})))
    with pytest.raises(ErrInvalidArgument):  # Ref.validate
        c.status(sl.Ref("not a uri", 0), "x")
    with pytest.raises(ErrInvalidArgument):
        c.status(sl.Ref("https://example.com/l", -1), "x")


def test_key_it_cannot_verify_with(lserver):
    signer, pub = new_p256()
    uri = "https://example.com/statuslists/1"
    token = sign_claims(signer, pub, {**TYP, "kid": "k"}, {"sub": uri, "iat": unix(NOW - timedelta(hours=1)), "status_list": {"bits": 1, "lst": LST16}})
    s = lserver({"/statuslists/1": token})
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    off = ec.EllipticCurvePublicNumbers(1, 1, ec.SECP256R1())
    try:
        off_key = off.public_key()
    except ValueError:
        off_key = None
    cases = [("P-384", p384, ErrUnsupportedKey)]
    if off_key is not None:
        cases.append(("off P-256", off_key, jws.ErrBadKey))
    for name, key, want in cases:
        c = s.checker(KeySet({"https://a.example": [PublicKey(key, "k")]}))
        with pytest.raises(ErrInvalidArgument) as ei:
            c.status(sl.Ref(uri, 0), "https://a.example")
        assert isinstance(ei.value, want), name


def test_fetch_causes():
    def handler(r):
        if r.path == "/missing":
            return Reply("nope", 404, ctype="text/plain")
        if r.path == "/large":
            return Reply("a" * (ck.MAX_TOKEN_BYTES + 1), ctype="application/statuslist+jwt")
        n = int(r.path.removeprefix("/loop/"))
        return redirect(f"/loop/{n + 1}")

    srv = Server(handler, tls=True)
    try:
        c = sl.new_checker(sl.CheckerConfig(issuers=KeySet({}), http_client=srv.client()))
        for path, want in (("/large", sl.ErrBodyTooLarge), ("/loop/0", sl.ErrTooManyRedirects)):
            with pytest.raises(sl.StatusFetchError) as ei:
                c.status(sl.Ref(srv.url + path, 0), "https://a.example")
            assert is_(ei.value, want), path
        with pytest.raises(sl.StatusFetchError) as ei:
            c.status(sl.Ref(srv.url + "/missing", 0), "https://a.example")
        se = as_(ei.value, StatusError)
        assert se is not None and se.code == 404
    finally:
        srv.close()


def test_any_content_type(lserver):
    signer, pub = new_p256()
    uri = "https://example.com/statuslists/1"
    token = sign_claims(signer, pub, {**TYP, "kid": "a"}, {"sub": uri, "iat": unix(NOW - timedelta(hours=1)), "status_list": {"bits": 1, "lst": LST16}})
    s = lserver({"/statuslists/1": token, "/statuslists/html": "<html></html>"})
    s.types = {"/statuslists/1": "application/json", "/statuslists/html": "text/html"}
    c = s.checker(KeySet({"https://a.example": [PublicKey(pub, "a")]}))
    c.status(sl.Ref(uri, 0), "https://a.example")  # a token served as another type is used
    with pytest.raises(ErrMalformed):
        c.status(sl.Ref("https://example.com/statuslists/html", 0), "https://a.example")


def test_clock_skew_on_iat(lserver):
    signer, pub = new_p256()
    uri = "https://example.com/statuslists/1"
    token = sign_claims(signer, pub, {**TYP, "kid": "a"}, {"sub": uri, "iat": unix(NOW + timedelta(minutes=5)), "status_list": {"bits": 1, "lst": LST16}})
    s = lserver({"/statuslists/1": token})
    issuers = KeySet({"https://a.example": [PublicKey(pub, "a")]})
    with pytest.raises(sl.ErrIssuedInFuture):
        s.checker(issuers).status(sl.Ref(uri, 0), "https://a.example")
    assert s.checker(issuers, clock_skew=timedelta(minutes=10)).status(sl.Ref(uri, 0), "https://a.example") == 1
