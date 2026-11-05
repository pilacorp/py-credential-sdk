import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "_helpers"))
from dcsub_http import Reply, Server, plain_client, redirect  # noqa: E402

from digitalcredential.internal import safehttp as sh  # noqa: E402
from digitalcredential.internal.safehttp import Limits, as_, get, is_, new_client  # noqa: E402

LIMITS = Limits(timeout_seconds=5, max_redirects=3, max_bytes=1024)
JSON = ["application/json"]


@pytest.fixture
def serve():
    made = []

    def mk(handler, tls=True):
        s = Server(handler, tls=tls)
        made.append(s)
        return s

    yield mk
    for s in made:
        s.close()


def test_new_client_refuses_blocked_address(serve):
    s = serve(lambda r: Reply("{}"))
    with pytest.raises(sh.SafeHTTPError) as ei:
        get(new_client(), s.url, JSON, LIMITS)
    assert is_(ei.value, sh.ErrBlockedAddress)
    assert s.hits == 0


def test_get_refuses_redirects(serve):
    plain = serve(lambda r: Reply("{}"), tls=False)
    target = serve(lambda r: Reply("{}"))
    hops = []

    def handler(r):
        if r.path == "/downgrade":
            return redirect(plain.url)
        if r.path == "/nohost":
            return redirect(f"https://:{target.port}/")
        hops.append(r.path)
        n = int(r.path.removeprefix("/hop/"))
        return redirect(f"/hop/{n + 1}")

    s = serve(handler)
    c = s.client()
    with pytest.raises(sh.ErrRedirectTargetNotAllowed):
        get(c, s.url + "/downgrade", JSON, LIMITS)
    assert plain.hits == 0
    with pytest.raises(sh.ErrRedirectTargetNotAllowed):
        get(c, s.url + "/nohost", JSON, LIMITS)
    assert target.hits == 0
    with pytest.raises(sh.ErrTooManyRedirects):
        get(c, s.url + "/hop/0", JSON, LIMITS)
    assert len(hops) == LIMITS.max_redirects + 1  # the request after the last allowed redirect never arrives


def test_get_checks_every_redirect(serve):
    target = serve(lambda r: Reply("{}"))

    def handler(r):
        return redirect("/b") if r.path == "/a" else redirect(target.url + "/c")

    s = serve(handler)
    starts = []

    def follow(start, tgt):
        starts.append(start)
        return sh.parse(start).netloc == sh.parse(tgt).netloc

    lim = Limits(timeout_seconds=5, max_redirects=3, max_bytes=1024, follow=follow)
    with pytest.raises(sh.ErrNotFollowed):
        get(s.client(), s.url + "/a", JSON, lim)
    assert starts == [s.url + "/a", s.url + "/a"]
    assert target.hits == 0


def test_get_error_omits_url(serve):
    s = serve(lambda r: redirect("https://alice:SYNTHETIC_PW@status.example/x?token=SYNTHETIC_Q"))
    with pytest.raises(sh.SafeHTTPError) as ei:
        get(s.client(), s.url, JSON, LIMITS)
    assert "SYNTHETIC" not in str(ei.value) and "redirect to a URL that is not https" in str(ei.value)

    # A Location that does not parse is refused after one request, without quoting it.
    s2 = serve(lambda r: redirect("https://alice:SYNTHETIC_PASSWORD@status.example/%zz?token=SYNTHETIC_QUERY_SECRET\x01"))
    with pytest.raises(sh.SafeHTTPError) as ei:
        get(s2.client(), s2.url, JSON, LIMITS)
    assert "SYNTHETIC" not in str(ei.value) and s2.hits == 1

    s3 = serve(lambda r: Reply("{}"))
    with pytest.raises(sh.SafeHTTPError) as ei:
        get(new_client(), s3.url + "/?token=SYNTHETIC_Q", JSON, LIMITS)
    assert is_(ei.value, sh.ErrBlockedAddress) and "SYNTHETIC" not in str(ei.value)


def test_fetch_error_bounds_network_text():
    for host in ("a" * 1000 + ".example", "issuer.example‮gnp.exe"):
        cause = OSError(f"lookup {host}: no such host")
        err = sh._fetch_error("", cause)
        text = str(err)
        assert text.startswith("safehttp: Get: ") and len(text) < 300 and "‮" not in text
        assert is_(err, OSError) and err.__cause__ is cause


def test_get_media_types(serve):
    accept = []

    def handler(r):
        accept.append(r.headers["Accept"])
        return Reply("{}", ctype=r.path[1:])

    s = serve(handler)
    types = ["application/jwk-set+json", "application/json"]
    for ct in ("application/jwk-set+json", "application/JSON", "application/json; charset=utf-8"):
        get(s.client(), s.url + "/" + ct.replace(" ", "%20"), types, LIMITS)
    assert set(accept) == {"application/jwk-set+json, application/json"}
    with pytest.raises(sh.ErrContentTypeNotAccepted) as ei:
        get(s.client(), s.url + "/text/html", types, LIMITS)
    assert str(ei.value) == "safehttp: content type is not application/jwk-set+json or application/json"
    # AnyContentType skips only the Content-Type check: Accept is still sent.
    accept.clear()
    lax = Limits(timeout_seconds=5, max_redirects=3, max_bytes=1024, any_content_type=True)
    get(s.client(), s.url + "/text/html", types, lax)
    assert accept == ["application/jwk-set+json, application/json"]
    # a missing Content-Type is not accepted either
    s2 = serve(lambda r: Reply("{}", ctype=None))
    with pytest.raises(sh.ErrContentTypeNotAccepted):
        get(s2.client(), s2.url, JSON, LIMITS)


def test_get_refuses_body_over_cap(serve):
    s = serve(lambda r: Reply("a" * (LIMITS.max_bytes + 1)))
    with pytest.raises(sh.ErrBodyTooLarge):
        get(s.client(), s.url, JSON, LIMITS)
    s = serve(lambda r: Reply("a" * LIMITS.max_bytes))
    assert len(get(s.client(), s.url, JSON, LIMITS)[0]) == LIMITS.max_bytes


def test_get_status_error(serve):
    s = serve(lambda r: Reply("{}", status=404))
    with pytest.raises(sh.StatusError) as ei:
        get(s.client(), s.url, JSON, LIMITS)
    assert ei.value.code == 404
    # 3xx without Location is a status, not a redirect
    s = serve(lambda r: Reply("", status=302, ctype=None))
    with pytest.raises(sh.StatusError) as ei:
        get(s.client(), s.url, JSON, LIMITS)
    assert ei.value.code == 302


def test_get_refuses_url(serve):
    plain = serve(lambda r: Reply("{}"), tls=False)
    s = serve(lambda r: Reply("{}"))
    c = s.client()
    for u in (plain.url, f"https://:{s.port}/", f"https://user:pass@127.0.0.1:{s.port}/", f"https://127.0.0.1:{s.port}/a b",
              f"https://127.0.0.1:{s.port}/\n", f"https://127.0.0.1:{s.port}/\t", f"https://@127.0.0.1:{s.port}/"):
        with pytest.raises(ValueError):
            get(c, u, JSON, LIMITS)
    http = Limits(timeout_seconds=5, max_redirects=3, max_bytes=1024, allow_http=True)
    for u in (f"http://:{plain.port}/", f"http://user:pass@127.0.0.1:{plain.port}/"):
        with pytest.raises(ValueError):
            get(plain_client(), u, JSON, http)
    assert plain.hits == 0 and s.hits == 0
    # AllowHTTP admits a plain http URL and a redirect to it
    assert get(plain_client(), plain.url, JSON, http)[0] == b"{}"


def test_get_limits_validated():
    c = plain_client()
    for lim in (Limits(timeout_seconds=0), Limits(max_bytes=0), Limits(max_bytes=2**63 - 1), Limits(max_bytes=-1)):
        with pytest.raises(ValueError):
            get(c, "https://x.example/", JSON, lim)
    with pytest.raises(ValueError):
        get(None, "https://x.example/", JSON, LIMITS)


def test_get_times_out_stalled_body(serve):
    def stall(w):
        w.write(b"{")
        w.flush()
        time.sleep(2)

    s = serve(lambda r: Reply(stall))
    lim = Limits(timeout_seconds=0.3, max_redirects=3, max_bytes=1024)
    t = time.monotonic()
    with pytest.raises(sh.SafeHTTPError) as ei:
        get(s.client(), s.url, JSON, lim)
    assert is_(ei.value, TimeoutError) and time.monotonic() - t < 1.5


def test_client_check_redirect_runs_first(serve):
    s = serve(lambda r: redirect("/b") if r.path == "/a" else Reply("{}"))
    seen = []

    def deny(target, via, headers):
        seen.append((target, list(via)))
        raise RuntimeError("no")

    c = s.client()
    c.check_redirect = deny
    with pytest.raises(sh.FetchError) as ei:
        get(c, s.url + "/a", JSON, LIMITS)
    assert seen == [(s.url + "/b", [s.url + "/a"])] and as_(ei.value, RuntimeError)


def test_redirect_followed_to_final_body(serve):
    s = serve(lambda r: redirect("/b", 301) if r.path == "/a" else Reply('{"ok":1}'))
    body, h = get(s.client(), s.url + "/a", JSON, LIMITS)
    assert body == b'{"ok":1}' and h.get("content-type") == "application/json"


def test_from_fetch_adapter():
    c = sh.Client.from_fetch(lambda url: (b"{}", {"content-type": "application/json", "status": "200"}))
    assert get(c, "https://x.example/", JSON, LIMITS)[0] == b"{}"
    c = sh.Client.from_fetch(lambda url: (b"", {"content-type": "application/json", "status": "503"}))
    with pytest.raises(sh.StatusError):
        get(c, "https://x.example/", JSON, LIMITS)
