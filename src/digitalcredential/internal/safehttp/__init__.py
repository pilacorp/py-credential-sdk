from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from digitalcredential.internal.safehttp.blocked import blocked, blocked_host, parse_addr

ErrBlockedAddress = OSError("safehttp: blocked address")
ErrRedirectTargetNotAllowed = ValueError("safehttp: redirect target not allowed")
ErrTooManyRedirects = ValueError("safehttp: too many redirects")
ErrBodyTooLarge = ValueError("safehttp: body too large")
ErrNotFollowed = ValueError("safehttp: redirect not followed")
ErrContentTypeNotAccepted = ValueError("safehttp: content type not accepted")


class StatusError(Exception):
    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(f"safehttp: HTTP status {code}")


def https_url(raw: str) -> bool:
    u = urlparse(raw)
    return u.scheme == "https" and u.hostname not in (None, "") and u.username is None


def port(u: urlparse) -> str:
    if u.port:
        return str(u.port)
    return "443" if u.scheme == "https" else "80"


@dataclass
class Limits:
    timeout_seconds: float = 5.0
    max_redirects: int = 3
    max_bytes: int = 1 << 20
    allow_http: bool = False
    follow: Callable[[str, str], bool] | None = None
    any_content_type: bool = False

    def allows(self, raw: str) -> bool:
        u = urlparse(raw)
        if self.allow_http and u.scheme == "http":
            return u.hostname not in (None, "") and u.username is None
        return https_url(raw)


FetchFn = Callable[[str], tuple[bytes, dict[str, str]]]


def get_with_fetcher(
    url: str,
    fetch: FetchFn,
    media_types: list[str],
    limits: Limits,
) -> bytes:
    if not limits.allows(url):
        raise ErrBlockedAddress
    body, headers = fetch(url)
    if len(body) > limits.max_bytes:
        raise ErrBodyTooLarge
    if not limits.any_content_type:
        ct = headers.get("content-type", "").split(";")[0].strip().lower()
        if media_types and ct not in [m.lower() for m in media_types]:
            raise ErrContentTypeNotAccepted
    return body


__all__ = [
    "ErrBlockedAddress",
    "ErrBodyTooLarge",
    "ErrContentTypeNotAccepted",
    "ErrNotFollowed",
    "ErrRedirectTargetNotAllowed",
    "ErrTooManyRedirects",
    "FetchFn",
    "Limits",
    "StatusError",
    "blocked",
    "blocked_host",
    "get_with_fetcher",
    "https_url",
    "parse_addr",
    "port",
]
