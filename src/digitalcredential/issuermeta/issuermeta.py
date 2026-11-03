from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse

from digitalcredential.internal import uri
from digitalcredential.internal.allowlist import Hints, check, new as allowlist_new
from digitalcredential.internal.httpcache import freshness
from digitalcredential.internal.safehttp import (
    ErrBlockedAddress,
    ErrBodyTooLarge,
    ErrContentTypeNotAccepted,
    ErrNotFollowed,
    FetchFn,
    Limits,
    StatusError,
    https_url,
)
from digitalcredential.issuerkey import PublicKey
from digitalcredential.issuerkey_multi import ErrIssuerNotSupported, ErrNoUsableKey

WELL_KNOWN = "/.well-known/jwt-vc-issuer"
MAX_BODY = 64 << 10
MAX_CACHE_LIFETIME = 86400
MEDIA_TYPE_METADATA = "application/json"
MEDIA_TYPES_JWKS = ["application/jwk-set+json", "application/json"]

ErrRedirectNotAllowed = ErrNotFollowed
ErrAddressBlocked = ErrBlockedAddress

_TRUST_HINTS = Hints(
    all="leave Config.TrustedIssuerOrigins empty",
    finer="list the origin and refuse the other iss in a Resolver that wraps this one",
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
class ResolverConfig:
    trusted_issuer_origins: list[str] = field(default_factory=list)
    redirects: RedirectPolicy = field(default_factory=RedirectPolicy)
    fetch: FetchFn | None = None
    disable_cache: bool = False
    now: Callable[[], datetime] | None = None


MetadataFetcher = FetchFn


def metadata_url(iss: str) -> str:
    if not uri.valid(iss):
        raise ErrIssuerNotSupported("issuermeta: iss is not a URI (RFC 3986)")
    if not https_url(iss):
        raise ErrIssuerNotSupported(
            "issuermeta: iss is not an https URL with a host (draft-ietf-oauth-sd-jwt-vc-19 §4) "
            "and no userinfo (RFC 9110 §4.2.4)"
        )
    if "?" in iss or "#" in iss:
        raise ErrIssuerNotSupported(
            "issuermeta: iss has a query or fragment, which draft-ietf-oauth-sd-jwt-vc-19 §4 forbids"
        )
    rest = iss[iss.index("://") + 3 :]
    authority, path = rest, ""
    if "/" in rest:
        authority, path = rest.split("/", 1)
        path = "/" + path
    return f"https://{authority}{WELL_KNOWN}{path.rstrip('/')}"


@dataclass
class _IssuerCacheEntry:
    keys: list[PublicKey]
    sent: datetime
    expires: datetime
    size: int


class PreloadedResolver:
    """Resolve issuer keys from preloaded JWT VC Issuer Metadata documents."""

    def __init__(self, metadata_by_iss: dict[str, bytes], jwks_by_uri: dict[str, bytes] | None = None) -> None:
        self._meta = {k: bytes(v) for k, v in metadata_by_iss.items()}
        self._jwks = {k: bytes(v) for k, v in (jwks_by_uri or {}).items()}

    def keys(self, iss: str) -> list[PublicKey]:
        meta = self._meta.get(iss)
        if meta is None:
            raise ErrIssuerNotSupported(f"issuermeta: no metadata for issuer")
        return _keys_from_metadata(iss, json.loads(meta), self._jwks, fetch=None)


def new_resolver(cfg: ResolverConfig) -> FetchingResolver:
    for i, e in enumerate(cfg.trusted_issuer_origins):
        if why := check(e, _TRUST_HINTS):
            raise ValueError(f"issuermeta: Config.TrustedIssuerOrigins[{i}] {why}")
    if cfg.fetch is None:
        raise ValueError("issuermeta: fetch is required unless using PreloadedResolver directly")
    if cfg.redirects.mode == "to" and not cfg.redirects.origins:
        raise ValueError(
            "issuermeta: Config.Redirects is RedirectTo with no origin; leave Redirects zero to follow "
            "redirects only within the origin requested"
        )
    return FetchingResolver(cfg)


class FetchingResolver:
    def __init__(self, cfg: ResolverConfig) -> None:
        self.cfg = cfg
        self._trusted = allowlist_new(cfg.trusted_issuer_origins)
        self._url_cache: dict[str, tuple[bytes, datetime]] = {}
        self._issuer_cache: dict[str, _IssuerCacheEntry] = {}
        self._now = cfg.now or (lambda: datetime.now(timezone.utc))
        self._limits = Limits(max_bytes=MAX_BODY)

    def keys(self, iss: str) -> list[PublicKey]:
        if not iss:
            raise ErrIssuerNotSupported(
                "issuermeta: the credential has no iss; issuermeta resolves only https issuers "
                "(draft-ietf-oauth-sd-jwt-vc-19 §2.5)"
            )
        meta_url = metadata_url(iss)
        if not self._trusted.covers(iss):
            raise ErrIssuerNotSupported(
                "issuermeta: the origin of iss is not covered by Config.TrustedIssuerOrigins; "
                "list it there to trust it"
            )
        now = self._now()
        hit = self._issuer_cache.get(iss)
        if hit and now < hit.expires:
            return [PublicKey(public_key=k.public_key, kid=k.kid) for k in hit.keys]
        sent = now
        keys, expires = self._fetch_keys(iss, meta_url, sent)
        if not self.cfg.disable_cache and now < expires:
            size = 222 + len(iss) + sum(250 + len(k.kid or "") for k in keys)
            self._issuer_cache[iss] = _IssuerCacheEntry(
                keys=[PublicKey(public_key=k.public_key, kid=k.kid) for k in keys],
                sent=sent,
                expires=expires,
                size=size,
            )
        return keys

    def _fetch_keys(self, iss: str, meta_url: str, sent: datetime) -> tuple[list[PublicKey], datetime]:
        assert self.cfg.fetch is not None
        body = self._get(meta_url, [MEDIA_TYPE_METADATA])
        try:
            doc = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ErrNoUsableKey(f"issuermeta: the issuer metadata is not a JSON object: {exc}") from exc
        if not isinstance(doc, dict):
            raise ErrNoUsableKey("issuermeta: the issuer metadata is not a JSON object")
        keys = _keys_from_metadata(iss, doc, None, self._get)
        fresh = timedelta(seconds=MAX_CACHE_LIFETIME)
        return keys, sent + fresh

    def _get(self, url: str, media_types: list[str]) -> bytes:
        now = self._now()
        hit = self._url_cache.get(url)
        if hit and now < hit[1]:
            return hit[0]
        assert self.cfg.fetch is not None
        if not self._limits.allows(url):
            raise ErrAddressBlocked
        body, headers = self.cfg.fetch(url)
        if len(body) > MAX_BODY:
            raise ErrBodyTooLarge
        if media_types:
            ct = headers.get("content-type", "").split(";")[0].strip().lower()
            if ct not in [m.lower() for m in media_types]:
                raise ErrContentTypeNotAccepted
        status = headers.get("status") or headers.get(":status")
        if status is not None:
            code = int(str(status).split()[0])
            if not (200 <= code < 300):
                raise StatusError(code)
        fresh = timedelta(seconds=freshness(headers, MAX_CACHE_LIFETIME))
        self._url_cache[url] = (bytes(body), now + fresh)
        return bytes(body)


def _keys_from_metadata(
    iss: str,
    doc: dict,
    jwks_by_uri: dict[str, bytes] | None,
    fetch: Callable[[str, list[str]], bytes] | None,
) -> list[PublicKey]:
    if doc.get("issuer", iss) != iss:
        raise ErrNoUsableKey(
            "issuermeta: the issuer metadata names another issuer than the credential's iss; "
            "draft-ietf-oauth-sd-jwt-vc-19 §4.3 forbids using it"
        )
    has_jwks = "jwks" in doc
    has_uri = "jwks_uri" in doc
    if has_jwks and has_uri:
        raise ErrNoUsableKey("issuermeta: the issuer metadata has both jwks and jwks_uri")
    if not has_jwks and not has_uri:
        raise ErrNoUsableKey("issuermeta: the issuer metadata has neither jwks nor jwks_uri")
    if has_jwks:
        jwks = doc["jwks"]
        if not isinstance(jwks, dict):
            raise ErrNoUsableKey("issuermeta: jwks is not a JSON object")
        return _keys_from_jwks(jwks)
    jwks_uri = doc.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not uri.valid(jwks_uri):
        raise ErrNoUsableKey("issuermeta: jwks_uri is not a URI (RFC 3986)")
    if not https_url(jwks_uri):
        raise ErrNoUsableKey("issuermeta: jwks_uri is not an https URL with a host")
    if fetch is None:
        raw = (jwks_by_uri or {}).get(jwks_uri)
        if raw is None:
            raise ErrNoUsableKey(f"issuermeta: no preloaded JWK set for jwks_uri")
        return _keys_from_jwks(json.loads(raw))
    if not jwks_uri.startswith("https://"):
        meta_url = metadata_url(iss)
        jwks_uri = urljoin(meta_url, jwks_uri)
    return _keys_from_jwks(json.loads(fetch(jwks_uri, MEDIA_TYPES_JWKS)))


def _keys_from_jwks(jwks: dict) -> list[PublicKey]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise ErrNoUsableKey("issuermeta: the JWK Set has no keys array (RFC 7517 §5)")
    out: list[PublicKey] = []
    for k in keys:
        if not isinstance(k, dict):
            raise ErrNoUsableKey("issuermeta: the JWK Set holds an element that is not a JWK object")
        if k.get("use") not in (None, "sig"):
            continue
        if k.get("kty") != "EC" or k.get("crv") != "P-256":
            continue
        x, y = k.get("x"), k.get("y")
        if not isinstance(x, str) or not isinstance(y, str):
            continue
        from credential.common.sdjwt.helper import b64url_decode

        pub = b"\x04" + b64url_decode(x) + b64url_decode(y)
        out.append(PublicKey(public_key=pub, kid=k.get("kid") if isinstance(k.get("kid"), str) else None))
    if not out:
        raise ErrNoUsableKey("issuermeta: no usable P-256 keys")
    return out
