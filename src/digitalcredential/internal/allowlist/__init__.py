from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from digitalcredential.internal import safehttp
from digitalcredential.internal.safehttp import hostname, https_url, parse, port as url_port


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
    if len(e) < len("https://") or not (e[:8].isascii() and e[:8].lower() == "https://"):
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
    if not port or not all("0" <= c <= "9" for c in port):
        return False
    n = int(port)
    return 1 <= n <= 65535 and port == str(n)


def _ascii_lower(s: str) -> str:
    """RFC 6454 §4 i;ascii-casemap: A-Z only."""
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def _parse_origin_entry(e: str) -> _Origin | None:
    sub = e[len("https://") :].startswith("*.")
    if sub:
        e = "https://" + e[len("https://*.") :]
    u = parse(e)
    if u is None or not https_url(u) or u.path not in ("", "/") or any(c in e for c in "?#*"):
        return None
    return _Origin(host=_ascii_lower(hostname(u)), port=url_port(u), subdomain=sub)


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

    def covers(self, raw) -> bool:
        """Whether the list covers u, an https URL (str or urlsplit result)."""
        if self.any_origin:
            return True
        u = parse(raw) if isinstance(raw, str) else raw
        if u is None or not https_url(u):
            return False
        host = _ascii_lower(hostname(u))
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


def _parse_all(entries: list[str]) -> list[_Origin]:
    return [o for e in entries if (o := _parse_origin_entry(e)) is not None]


def new(entries: list[str]) -> List:
    """A List of entries, each of which check() accepted. Empty covers every URL."""
    return List(any_origin=not entries, origins=_parse_all(entries))


@dataclass
class Redirects:
    """Where a retrieval follows a redirect: always within the origin of the URL requested;
    redirects_to adds the origins of a list, redirects_any every https URL."""

    any_origin: bool = False
    to: List | None = None

    def follows(self, start, target) -> bool:
        if self.any_origin:
            return True
        if _same_origin(start, target):
            return True
        return self.to is not None and self.to.covers(target)


def redirects_to(entries: list[str]) -> Redirects:
    """Unlike new(), no entries adds nothing."""
    return Redirects(to=List(origins=_parse_all(entries)))


def redirects_any() -> Redirects:
    return Redirects(any_origin=True)


def _same_origin(a, b) -> bool:
    ua = parse(a) if isinstance(a, str) else a
    ub = parse(b) if isinstance(b, str) else b
    return _ascii_lower(hostname(ua)) == _ascii_lower(hostname(ub)) and url_port(ua) == url_port(ub)
