"""How long a fetched document may be reused, as RFC 9111 §4.2 and §5.2 allow a private cache.
Stores nothing itself."""

from __future__ import annotations

import copy

from digitalcredential.internal import safehttp
from digitalcredential.internal.safehttp import Client, Headers, Limits

_LIMIT = 1 << 31  # RFC 9111 §1.2.2: delta-seconds capped at 2^31


def get(
    client: Client, raw_url: str, media_types: list[str], limits: Limits, ceiling: float
) -> tuple[bytes, float]:
    """safehttp.get plus the freshness (seconds, from the time the request was sent) of the least
    fresh response of the fetch, redirects included, at most ceiling. The redirect hook wraps the
    client's check_redirect, which runs unchanged."""
    cc = copy.copy(client)
    nxt = cc.check_redirect
    fresh = [ceiling]

    def check(target: str, via: list[str], resp_headers: Headers) -> None:
        fresh[0] = min(fresh[0], freshness(resp_headers, ceiling))
        if nxt is not None:
            nxt(target, via, resp_headers)

    cc.check_redirect = check
    body, h = safehttp.get(cc, raw_url, media_types, limits)
    return body, min(fresh[0], freshness(h, ceiling))


def freshness(headers, ceiling: float) -> float:
    """max-age minus Age, at most ceiling (seconds); 0, not stored, whenever RFC 9111 lets a cache
    not store and the header gives a reason to: no-cache or no-store, a Vary member other than
    Accept or Accept-Encoding, no max-age, or a max-age invalid or given twice."""
    h = Headers.of(headers)
    cc = ",".join(h.values("Cache-Control"))
    # A quoted-string argument can hold a comma; no directive read here needs quotes.
    if '"' in cc:
        return 0.0
    for v in h.values("Vary"):
        for m in v.split(","):
            m = m.strip()
            if m and m.lower() not in ("accept", "accept-encoding"):
                return 0.0
    max_age, seen = 0, False
    for d in cc.split(","):
        name, _, arg = d.strip().partition("=")
        n = name.lower()
        if n in ("no-store", "no-cache"):
            return 0.0
        if n == "max-age":
            val = _delta_seconds(arg)
            if seen or val is None:
                return 0.0
            max_age, seen = val, True
    first = h.get("Age").split(",", 1)[0].strip()
    age = _delta_seconds(first)
    if age is not None:
        max_age -= age
    if max_age <= 0:
        return 0.0
    return float(min(max_age, ceiling))


def _delta_seconds(s: str) -> int | None:
    """1*DIGIT (ASCII), capped at 2^31; None when invalid."""
    if not s or not all("0" <= c <= "9" for c in s):
        return None
    return min(int(s), _LIMIT)
