from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import urlparse

from digitalcredential.internal import uri
from digitalcredential.internal.allowlist import Hints, check, new as allowlist_new, redirects_any, redirects_to
from digitalcredential.internal.httpcache import freshness
from digitalcredential.internal.safehttp import (
    ErrBlockedAddress,
    ErrBodyTooLarge,
    ErrContentTypeNotAccepted,
    ErrNotFollowed,
    ErrRedirectTargetNotAllowed,
    ErrTooManyRedirects,
    FetchFn,
    Limits,
    StatusError,
    https_url,
)
from digitalcredential.typemeta.cache import DocumentCache
from digitalcredential.typemeta.errors import ErrNotFound
from digitalcredential.typemeta.integrity import check_integrity
from digitalcredential.typemeta.ref import Ref

MEDIA_TYPE_METADATA = "application/json"
MAX_DOCUMENT_BYTES = 256 << 10
MAX_CACHE_LIFETIME = 86400

ErrRedirectNotAllowed = ErrNotFollowed
ErrAddressBlocked = ErrBlockedAddress

_TRUST_HINTS = Hints(
    all="leave Config.TrustedPublisherOrigins empty",
    finer="list the origin and refuse the other vct in a Resolver that wraps this one",
)


@dataclass
class RedirectPolicy:
    mode: str = "same_origin"
    origins: list[str] = field(default_factory=list)


def redirect_to(*origins: str) -> RedirectPolicy:
    return RedirectPolicy(mode="to", origins=list(origins))


def redirect_any() -> RedirectPolicy:
    return RedirectPolicy(mode="any")


@dataclass
class HTTPResolverConfig:
    trusted_publisher_origins: list[str] = field(default_factory=list)
    redirects: RedirectPolicy = field(default_factory=RedirectPolicy)
    fetch: FetchFn | None = None
    disable_cache: bool = False
    now: Callable[[], datetime] | None = None


class HTTPResolver:
    def __init__(self, cfg: HTTPResolverConfig) -> None:
        if cfg.fetch is None:
            raise ValueError("typemeta: HTTPResolver requires an injectable fetch")
        self._trusted = allowlist_new(cfg.trusted_publisher_origins)
        self._fetch = cfg.fetch
        self._no_cache = cfg.disable_cache
        self._now = cfg.now or (lambda: datetime.now(timezone.utc))
        self._cache = DocumentCache()
        self._limits = Limits(max_bytes=MAX_DOCUMENT_BYTES)
        self._limits.follow = self._follow(cfg.redirects)

    @staticmethod
    def _follow(policy: RedirectPolicy):
        if policy.mode == "any":
            r = redirects_any()
        elif policy.mode == "to":
            r = redirects_to(policy.origins)
        else:
            r = redirects_to([])

        def _fn(start: str, target: str) -> bool:
            return r.follows(start, target)

        return _fn

    def metadata(self, ref: Ref) -> bytes:
        if not uri.valid(ref.vct):
            raise ErrNotFound("typemeta: vct is not a URI (RFC 3986)") from None
        if not https_url(ref.vct) or "#" in ref.vct:
            raise ErrNotFound(
                "typemeta: vct is not an https URL with a host, without userinfo or fragment "
                "(draft-ietf-oauth-sd-jwt-vc-19 §5.3.1)"
            ) from None
        if not self._trusted.covers(ref.vct):
            raise ErrNotFound(
                "typemeta: the origin of vct is not covered by Config.TrustedPublisherOrigins; "
                "list it there to trust it"
            ) from None
        now = self._now()
        if not self._no_cache:
            hit = self._cache.get(ref, now)
            if hit is not None:
                return hit
        sent = now
        if not self._limits.allows(ref.vct):
            raise ErrAddressBlocked
        body, headers = self._fetch(ref.vct)
        if len(body) > self._limits.max_bytes:
            raise ErrBodyTooLarge
        if not self._limits.any_content_type:
            ct = headers.get("content-type", "").split(";")[0].strip().lower()
            if ct not in (MEDIA_TYPE_METADATA,):
                raise ErrContentTypeNotAccepted
        status = headers.get("status") or headers.get(":status")
        if status is not None:
            try:
                code = int(str(status).split()[0])
            except ValueError:
                code = 0
            if code == 404:
                raise ErrNotFound("typemeta: the publisher answered 404") from None
            if code and not (200 <= code < 300):
                raise StatusError(code)
        doc = body
        if ref.integrity == "":
            fresh = timedelta(seconds=freshness(headers, MAX_CACHE_LIFETIME))
            if not self._no_cache:
                self._cache.put(ref, doc, sent, sent + fresh)
        elif check_integrity(doc, ref.integrity) is None:
            if not self._no_cache:
                self._cache.put(ref, doc, sent, None)
        return doc


def new_http_resolver(cfg: HTTPResolverConfig) -> HTTPResolver:
    for i, e in enumerate(cfg.trusted_publisher_origins):
        if why := check(e, _TRUST_HINTS):
            raise ValueError(f"typemeta: Config.TrustedPublisherOrigins[{i}] {why}")
    if cfg.redirects.mode == "to" and not cfg.redirects.origins:
        raise ValueError(
            "typemeta: Config.Redirects is RedirectTo with no origin; leave Redirects zero to follow "
            "redirects only within the origin requested"
        )
    for i, e in enumerate(cfg.redirects.origins):
        if why := check(e, Hints(all="use redirect_any()")):
            raise ValueError(f"typemeta: Config.Redirects RedirectTo[{i}] {why}")
    return HTTPResolver(cfg)


__all__ = [
    "ErrAddressBlocked",
    "ErrBodyTooLarge",
    "ErrContentTypeNotAccepted",
    "ErrNotFound",
    "ErrRedirectNotAllowed",
    "ErrRedirectTargetNotAllowed",
    "ErrTooManyRedirects",
    "HTTPResolver",
    "HTTPResolverConfig",
    "RedirectPolicy",
    "StatusError",
    "new_http_resolver",
    "redirect_any",
    "redirect_to",
]
