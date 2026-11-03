from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse
import ipaddress

from digitalcredential.internal.safehttp import https_url, port as url_port


@dataclass
class Hints:
    all: str = ""
    finer: str = ""


NOT_ORIGIN = (
    'is not an origin "https://host" or "https://*.host", with an optional port and final "/": '
    "an entry names a whole origin, so it has no path, query, userinfo or other \"*\""
)


def check(e: str, hints: Hints | None = None) -> str:
    hints = hints or Hints()
    if e == "*":
        return f'is "*", which is not an entry; to cover every https origin, {hints.all}'
    if len(e) < len("https://") or not e[: len("https://")].lower() == "https://":
        return 'does not start with https://; list origins as "https://host" or "https://*.host"'
    o = _parse_origin_entry(e)
    if o is None:
        if hints.finer:
            return NOT_ORIGIN + "; to trust some URLs of an origin, " + hints.finer
        return NOT_ORIGIN
    if not _plain_host(o.host):
        return (
            "has a host that is not ASCII or has an empty label, a final \".\" included; "
            'write the host in ASCII, each non-ASCII label as its A-label ("xn--..."), with no empty label'
        )
    if (":" in o.host or "[" in e) and (o.subdomain or not _ipv6_host(o.host)):
        return (
            'has ":" or "[" in a host that is not an IPv6 address, or "*." before an IPv6 address; '
            'write the port once, after the host, and an IPv6 address alone, as "https://[address]"'
        )
    if not _plain_port(o.port):
        return "has a port that is not a number from 1 to 65535 without leading zeros"
    return ""


def _plain_host(host: str) -> bool:
    if any(ord(c) >= 0x80 for c in host):
        return False
    return not host.startswith(".") and not host.endswith(".") and ".." not in host


def _ipv6_host(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return False


def _plain_port(port: str) -> bool:
    if not port.isdigit():
        return False
    n = int(port)
    return 1 <= n <= 65535 and port == str(n)


def _parse_origin_entry(e: str) -> _Origin | None:
    sub = e[len("https://") :].startswith("*.")
    if sub:
        e = "https://" + e[len("https://*.") :]
    if "*" in e and not sub:
        return None
    u = urlparse(e)
    if not https_url(e) or (u.path not in ("", "/")) or "?" in e or "#" in e:
        return None
    return _Origin(host=(u.hostname or "").lower(), port=url_port(u), subdomain=sub)


@dataclass
class _Origin:
    host: str
    port: str
    subdomain: bool


@dataclass
class List:
    any_origin: bool = False
    origins: list[_Origin] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.origins is None:
            self.origins = []

    def covers(self, raw: str) -> bool:
        if self.any_origin:
            return True
        u = urlparse(raw)
        if not https_url(raw):
            return False
        host = (u.hostname or "").lower()
        p = url_port(u)
        for o in self.origins:
            if o.subdomain:
                if ":" in host or not host.endswith("." + o.host):
                    continue
            elif host != o.host:
                continue
            if p == o.port:
                return True
        return False


def new(entries: list[str]) -> List:
    if not entries:
        return List(any_origin=True)
    origins: list[_Origin] = []
    for e in entries:
        o = _parse_origin_entry(e)
        if o is not None:
            origins.append(o)
    return List(origins=origins)


def redirects_to(entries: list[str]) -> Redirects:
    origins = [_o for e in entries if (_o := _parse_origin_entry(e)) is not None]
    return Redirects(to=List(origins=origins))


@dataclass
class Redirects:
    any_origin: bool = False
    to: List | None = None

    def follows(self, start: str, target: str) -> bool:
        if self.any_origin:
            return True
        if _same_origin(start, target):
            return True
        return self.to is not None and self.to.covers(target)


def redirects_any() -> Redirects:
    return Redirects(any_origin=True)


def _same_origin(a: str, b: str) -> bool:
    ua, ub = urlparse(a), urlparse(b)
    return (ua.hostname or "").lower() == (ub.hostname or "").lower() and url_port(ua) == url_port(ub)
