"""Fetch documents whose URL comes from untrusted input (port of Go internal/safehttp).

draft-ietf-oauth-sd-jwt-vc-19 §3 and §7.1: https URL with a host and no userinfo on every hop
(RFC 9110 §4.2.2, §4.2.4), bounded redirects, time and size bounds, a 2xx status of the expected
media type, and no connection to an address that is not globally reachable. The address check sits
in the dial step of `new_client()`, so it sees the address actually connected to, after DNS
resolution and on every redirect. Redirects are followed by `get` itself, never by the transport.
"""

from __future__ import annotations

import http.client
import socket
import threading
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping
from urllib.parse import SplitResult, urljoin, urlsplit

from pila_credential._deadline import Deadline
from pila_credential.digitalcredential._internal.safehttp.blocked import blocked, blocked_host, parse_addr

_MAX_HEADER_BYTES = 64 << 10  # whole header block, counted line by line as it streams in (_CappedFP)


# ---------------------------------------------------------------- errors


class SafeHTTPError(Exception):
    """Base of the sentinels of this package."""


class ErrBlockedAddress(SafeHTTPError):
    """The dial step of new_client() refused an address blocked() reports."""


class ErrNotFollowed(SafeHTTPError):
    """A redirect refused under Limits.follow."""


class ErrRedirectTargetNotAllowed(SafeHTTPError):
    """A redirect to a URL get does not request (not https, no host, or userinfo)."""


class ErrTooManyRedirects(SafeHTTPError):
    """A redirect past Limits.max_redirects."""


class ErrContentTypeNotAccepted(SafeHTTPError):
    """A final response whose media type is none of those get was given."""


class ErrBodyTooLarge(SafeHTTPError):
    """A body over Limits.max_bytes."""


class StatusError(SafeHTTPError):
    """A final response whose status is not 2xx."""

    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(f"safehttp: status {code}")


class FetchError(SafeHTTPError):
    """A failure of the transport or of reading the body. Its text never holds a URL; the cause is
    kept in __cause__ (reach it with `is_`)."""


def is_(err: BaseException | None, *classes: type) -> bool:
    """errors.Is for classes: true when err or anything in its __cause__ chain is an instance."""
    seen = 0
    while err is not None and seen < 32:
        if isinstance(err, classes):
            return True
        err = err.__cause__
        seen += 1
    return False


def as_(err: BaseException | None, cls: type):
    """errors.As: the first instance of cls in the __cause__ chain, or None."""
    seen = 0
    while err is not None and seen < 32:
        if isinstance(err, cls):
            return err
        err = err.__cause__
        seen += 1
    return None


# ---------------------------------------------------------------- headers


class Headers:
    """Response headers: ordered (name, value) pairs, names compared ASCII case-insensitively."""

    def __init__(self, pairs: Iterable[tuple[str, str]] = ()) -> None:
        self._pairs = [(k, v) for k, v in pairs]

    @classmethod
    def of(cls, h: "Headers | Mapping[str, str | list[str]] | None") -> "Headers":
        if h is None:
            return cls()
        if isinstance(h, Headers):
            return h
        pairs: list[tuple[str, str]] = []
        for k, v in h.items():
            for x in [v] if isinstance(v, str) else v:
                pairs.append((k, x))
        return cls(pairs)

    def values(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self._pairs if k.lower() == n]

    def get(self, name: str, default: str = "") -> str:
        vs = self.values(name)
        return vs[0] if vs else default

    def items(self) -> list[tuple[str, str]]:
        return list(self._pairs)

    def __contains__(self, name: str) -> bool:
        return bool(self.values(name))


# ---------------------------------------------------------------- URLs


def parse(raw: str) -> SplitResult | None:
    """url.Parse analogue: None when raw is not a URL (control characters, space, bad port or
    bracket). urlsplit alone strips tabs and newlines silently, which would hide them."""
    if not isinstance(raw, str) or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in raw):
        return None
    try:
        u = urlsplit(raw)
    except ValueError:
        return None
    p = _hostport(u)[1]
    if p is None or not all("0" <= c <= "9" for c in p):  # url.Parse: digits only, any range
        return None
    if not u.netloc.rpartition("@")[2].startswith("[") and _unescape_host(_hostport(u)[0]) is None:
        return None
    return u


def _has_userinfo(u: SplitResult) -> bool:
    return "@" in u.netloc


def _hostport(u: SplitResult) -> tuple[str, str | None]:
    """(host, port) of the authority as written; port None when it is absent or malformed."""
    a = u.netloc.rpartition("@")[2]
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        return host, (rest[1:] if rest.startswith(":") else ("" if rest == "" else None))
    host, sep, p = a.partition(":")
    return host, (p if sep else "")


def _unescape_host(h: str) -> str | None:
    """net/url unescape(host): %XX decodes only when its first digit is 8 or above (bytes of a
    non-ASCII host); "%25" and anything below are not accepted in a host. None: invalid."""
    if "%" not in h:
        return h
    out = bytearray()
    i = 0
    b = h.encode("utf-8")
    while i < len(b):
        if b[i] == 0x25:
            if i + 2 >= len(b):
                return None
            hx = b[i + 1 : i + 3].decode("ascii", "replace")
            if len(hx) < 2 or any(c not in "0123456789abcdefABCDEF" for c in hx):
                return None
            if int(hx[0], 16) < 8 and hx != "25":
                return None
            out.append(int(hx, 16))
            i += 3
        else:
            out.append(b[i])
            i += 1
    return out.decode("utf-8", "replace")


def hostname(u: SplitResult) -> str:
    """url.URL.Hostname: the host without userinfo, brackets and port, in the case written
    (urllib's .hostname lowercases with Unicode rules, which would fold U+212A to "k"); %XX of a
    non-ASCII host decoded as net/url does."""
    host = _hostport(u)[0]
    if u.netloc.rpartition("@")[2].startswith("["):
        return host
    return _unescape_host(host) or ""


def https_url(u: "SplitResult | str | None") -> bool:
    """HTTPSURL: an https URL with a host and no userinfo (RFC 9110 §4.2.2, §4.2.4)."""
    if isinstance(u, str):
        u = parse(u)
    return u is not None and u.scheme == "https" and bool(hostname(u)) and not _has_userinfo(u)


def port(u: "SplitResult | str") -> str:
    """The port of u; when absent, 80 for http and 443 otherwise."""
    if isinstance(u, str):
        u = urlsplit(u)
    p = _hostport(u)[1]
    if p:
        return p
    return "80" if u.scheme.lower() == "http" else "443"


@dataclass
class Limits:
    """Bounds of one call of `get`."""

    timeout_seconds: float = 5.0  # whole fetch; must be > 0
    max_redirects: int = 3  # redirects followed; 0 or less follows none
    max_bytes: int = 1 << 20  # largest body accepted; 0 < max_bytes < 2**63 - 1
    allow_http: bool = False  # the URL and every redirect may be http as well as https
    follow: Callable[[str, str], bool] | None = None  # (start_url, target_url) -> bool
    any_content_type: bool = False  # send Accept but do not judge Content-Type

    def allows(self, u: "SplitResult | str | None") -> bool:
        if isinstance(u, str):
            u = parse(u)
        if self.allow_http and u is not None and u.scheme == "http":
            return bool(hostname(u)) and not _has_userinfo(u)
        return https_url(u)

    def schemes(self) -> str:
        return "http or https" if self.allow_http else "https"


# ---------------------------------------------------------------- transport


@dataclass
class Response:
    status: int
    headers: Headers
    _read: Callable[[int], bytes]
    _close: Callable[[], None] = lambda: None

    def read(self, n: int) -> bytes:
        return self._read(n)

    def close(self) -> None:
        self._close()


Transport = Callable[[str, dict, float], Response]  # (url, request headers, timeout) -> Response


FetchFn = Callable[[str], tuple[bytes, Mapping[str, str]]]
"""fetch(url) -> (body, headers); see Client.from_fetch."""


@dataclass
class Client:
    """What `get` fetches with. transport None uses the socket transport (below), whose dial step
    refuses every address `address_check` reports (None: no check, for trusted clients and tests).
    check_redirect(target_url, via_urls, response_headers) runs before the checks of `get` and
    refuses a redirect by raising. A custom transport is trusted code."""

    transport: Transport | None = None
    check_redirect: Callable[[str, list[str], Headers], None] | None = None
    address_check: Callable[..., bool] | None = blocked
    ssl_context: ssl.SSLContext | None = None

    @classmethod
    def from_fetch(cls, fetch: Callable[[str], tuple[bytes, Mapping[str, str]]]) -> "Client":
        """Adapt fetch(url) -> (body, headers); a "status" header (default 200) sets the status.
        Never follows a redirect by itself."""

        def transport(url: str, headers: dict, timeout: float) -> Response:
            body, h = fetch(url)
            hs = Headers.of(h)
            status = int(str(hs.get("status") or hs.get(":status") or 200).split()[0])
            buf = [bytes(body)]

            def read(n: int) -> bytes:
                out, buf[0] = buf[0][:n], buf[0][n:]
                return out

            return Response(status, hs, read)

        return cls(transport=transport, address_check=None)


def new_client() -> Client:
    """The client to pass to `get`: refuses every address `blocked` reports, never uses a proxy."""
    return Client()


def _resolve(host: str, port_: int, deadline: float | None) -> list:
    # getaddrinfo takes no timeout, so it runs in its own daemon thread and the caller waits only until the
    # deadline. One thread per lookup: a shared pool lets slow lookups for one host starve every other fetch,
    # and its workers are joined at interpreter exit.
    box: dict[str, object] = {}
    done = threading.Event()

    def run() -> None:
        try:
            box["addrs"] = socket.getaddrinfo(host, port_, type=socket.SOCK_STREAM)
        except BaseException as e:  # noqa: BLE001
            box["err"] = e
        finally:
            done.set()

    threading.Thread(target=run, name="safehttp-dns", daemon=True).start()
    left = None if deadline is None else max(deadline - time.monotonic(), 0)
    if not done.wait(left):
        raise TimeoutError("deadline exceeded while resolving the host")
    if "err" in box:
        raise box["err"]  # type: ignore[misc]
    return box["addrs"]  # type: ignore[return-value]


def _dial(host: str, port_: int, timeout: float, check, deadline: float | None = None, dl: Deadline | None = None) -> socket.socket:
    err: Exception | None = None
    for family, stype, proto, _, sa in _resolve(host, port_, deadline):
        ip = sa[0]
        if check is not None:
            try:
                bad = check(parse_addr(ip))
            except ValueError:
                bad = True
            if bad:
                err = err or ErrBlockedAddress(f"safehttp: blocked address: {ip}:{port_}")
                continue
        left = timeout if deadline is None else deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("deadline exceeded")
        s = socket.socket(family, stype, proto)
        try:
            s.settimeout(min(left, 5.0))  # Go dialer: 5 s
            s.connect(sa)
            if dl is not None:
                dl.track(s)
            return s
        except OSError as e:
            s.close()
            err = err or e
    raise err or OSError(f"no address for {host}")


class _CappedFP:
    """The response file while its status line and headers are read: refuses more than _MAX_HEADER_BYTES in
    total as they stream in, where http.client alone allows 100 lines of 64 KiB."""

    def __init__(self, fp) -> None:  # noqa: ANN001
        self._fp, self._n = fp, 0

    def readline(self, limit: int = -1) -> bytes:
        line = self._fp.readline(limit)
        self._n += len(line)
        if self._n > _MAX_HEADER_BYTES:
            raise http.client.HTTPException("response headers over 65536 bytes")
        return line

    def __getattr__(self, name: str):  # noqa: ANN204
        return getattr(self._fp, name)


class _CappedResponse(http.client.HTTPResponse):
    def begin(self) -> None:
        fp = self.fp
        self.fp = _CappedFP(fp)
        try:
            super().begin()
        finally:
            self.fp = fp


def _socket_transport(client: Client) -> Transport:
    check = client.address_check
    ctx = client.ssl_context or ssl.create_default_context()

    def send(url: str, headers: dict, timeout: float) -> Response:
        u = urlsplit(url)
        p = int(port(u))
        host = hostname(u)
        deadline = time.monotonic() + timeout
        dl = Deadline(timeout)

        if u.scheme == "https":

            class Conn(http.client.HTTPSConnection):
                def connect(self) -> None:
                    raw = _dial(host, p, timeout, check, deadline, dl)
                    # register both sockets, and the handshake runs under the deadline too
                    tls = ctx.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
                    dl.track(tls)
                    tls.do_handshake()
                    self.sock = tls

            conn: http.client.HTTPConnection = Conn(host, p, timeout=timeout, context=ctx)
        else:

            class Plain(http.client.HTTPConnection):
                def connect(self) -> None:
                    self.sock = _dial(host, p, timeout, check, deadline, dl)

            conn = Plain(host, p, timeout=timeout)

        def close() -> None:
            dl.cancel()
            conn.close()

        def guard(e: Exception) -> Exception:
            return TimeoutError("deadline exceeded") if dl.expired.is_set() else e

        conn.response_class = _CappedResponse
        dl.start()
        try:
            target = (u.path or "/") + ("?" + u.query if u.query else "")
            conn.request("GET", target, headers={**headers, "Connection": "close"})
            resp = conn.getresponse()
        except Exception as e:  # noqa: BLE001
            close()
            raise guard(e) from e
        hdrs = resp.getheaders()

        def read(n: int) -> bytes:
            try:
                return resp.read(n)
            except Exception as e:  # noqa: BLE001
                raise guard(e) from e

        return Response(resp.status, Headers(hdrs), read, close)

    return send


# ---------------------------------------------------------------- get


def _text(s: str) -> str:
    """Quote and cut a network error text to 200 characters (it can name an untrusted host)."""
    s = ascii(s)
    return s[:200]


def _fetch_error(step: str, err: BaseException) -> SafeHTTPError:
    """Pick the text of the first class err matches; never the request URL."""
    if isinstance(err, (TimeoutError, socket.timeout)):
        text = "context deadline exceeded"
    elif isinstance(err, OSError):
        base = f"dial tcp: {err}"
        text = _text(base)
    else:
        text = step + " failed" if step else "request failed"
        step = ""
    if step:
        text = step + ": " + text
    out = FetchError("safehttp: Get: " + text)
    out.__cause__ = err
    return out


def get(
    client: Client,
    raw_url: str,
    media_types: list[str],
    limits: Limits,
    *,
    now: Callable[[], float] = time.monotonic,
) -> tuple[bytes, Headers]:
    """Fetch raw_url; returns (body, response headers). Redirects are followed here, each checked
    before the next request is sent (order: client.check_redirect, scheme/host, limits.follow,
    redirect count). Errors never quote the request URL or a redirect target."""
    if client is None:
        raise ValueError("safehttp: nil client")
    if limits.timeout_seconds <= 0:
        raise ValueError(f"safehttp: timeout {limits.timeout_seconds} out of range")
    if limits.max_bytes <= 0 or limits.max_bytes >= 2**63 - 1:
        raise ValueError(f"safehttp: max bytes {limits.max_bytes} out of range")
    start = parse(raw_url)
    if start is None or not limits.allows(start):
        raise ValueError(f"safehttp: URL is not {limits.schemes()} with a host and no userinfo")

    deadline = now() + limits.timeout_seconds

    def remaining() -> float:
        left = deadline - now()
        if left <= 0:
            raise _fetch_error("", TimeoutError("deadline exceeded"))
        return left

    send = client.transport or _socket_transport(client)
    headers = {"Accept": ", ".join(media_types), "Accept-Encoding": "identity"}
    url, via = raw_url, []
    while True:
        try:
            resp = send(url, dict(headers), remaining())
        except SafeHTTPError:
            raise
        except Exception as e:  # noqa: BLE001 - mapped through an allowlist of texts
            raise _fetch_error("", e)
        try:
            loc = resp.headers.get("Location")
            if resp.status in (301, 302, 303, 307, 308) and loc:
                resp.close()
                target = urljoin(url, loc)
                via.append(url)
                _check_redirect(client, limits, start, raw_url, target, via, resp.headers)
                url = target
                continue
            return _finish(resp, media_types, limits, remaining)
        finally:
            resp.close()


def _check_redirect(client, limits, start, raw_url, target, via, resp_headers) -> None:
    if client.check_redirect is not None:
        try:
            client.check_redirect(target, list(via), resp_headers)
        except SafeHTTPError:
            raise
        except Exception as e:  # noqa: BLE001
            raise _fetch_error("", e)
    tu = parse(target)
    if not limits.allows(tu):
        raise ErrRedirectTargetNotAllowed(
            f"safehttp: Get: redirect to a URL that is not {limits.schemes()} with a host and no userinfo"
        )
    if limits.follow is not None and not limits.follow(raw_url, target):
        raise ErrNotFollowed("safehttp: Get: redirect refused")
    if len(via) > limits.max_redirects:
        raise ErrTooManyRedirects(f"safehttp: Get: more than {limits.max_redirects} redirects")


def _finish(resp: Response, media_types, limits: Limits, remaining) -> tuple[bytes, Headers]:
    if resp.status < 200 or resp.status > 299:
        raise StatusError(resp.status)
    if not limits.any_content_type:
        mt = _media_type(resp.headers.get("Content-Type"))
        if mt is None or not any(_ascii_fold_eq(mt, want) for want in media_types):
            raise ErrContentTypeNotAccepted("safehttp: content type is not " + " or ".join(media_types))
    chunks: list[bytes] = []
    total = 0
    while total <= limits.max_bytes:
        remaining()
        try:
            b = resp.read(min(65536, limits.max_bytes + 1 - total))
        except Exception as e:  # noqa: BLE001
            raise _fetch_error("reading body", e)
        if not b:
            break
        chunks.append(b)
        total += len(b)
    if total > limits.max_bytes:
        raise ErrBodyTooLarge(f"safehttp: body over {limits.max_bytes} bytes")
    return b"".join(chunks), resp.headers


def _media_type(v: str) -> str | None:
    """mime.ParseMediaType, enough: the type before ";" when it is a token/token pair."""
    mt = v.split(";", 1)[0].strip()
    if not mt or not mt.isascii():
        return None
    return mt


def _ascii_fold_eq(a: str, b: str) -> bool:
    return len(a) == len(b) and a.isascii() and b.isascii() and a.lower() == b.lower()


__all__ = [
    "Client",
    "ErrBlockedAddress",
    "ErrBodyTooLarge",
    "ErrContentTypeNotAccepted",
    "ErrNotFollowed",
    "ErrRedirectTargetNotAllowed",
    "ErrTooManyRedirects",
    "FetchError",
    "Headers",
    "Limits",
    "Response",
    "SafeHTTPError",
    "StatusError",
    "as_",
    "blocked",
    "blocked_host",
    "get",
    "hostname",
    "https_url",
    "is_",
    "new_client",
    "parse",
    "parse_addr",
    "port",
]
