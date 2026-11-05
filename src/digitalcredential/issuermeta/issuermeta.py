"""Resolve the keys of an issuer from its JWT VC Issuer Metadata (draft-ietf-oauth-sd-jwt-vc-19
§2.5, §4): for an https iss, the metadata at the location of §4 and §4.1, its issuer identical to iss
(§4.2, §4.3), and the JWK Set it holds in jwks or references by jwks_uri (RFC 7517 §5).

Every retrieval follows §3: https only, on every redirect too, at most 3 redirects, 5 seconds and
64 KiB each, a 2xx response of the expected media type. A cache miss makes at most two retrievals.
Responses are cached as RFC 9111 allows, at most 24 hours and no longer than the least fresh response
of the retrieval, redirects included; a failure is never cached. By default every redirect stays on
the origin of the URL requested, whatever TrustedIssuerOrigins holds. The default client refuses
addresses that are not globally reachable; a Config.http_client is trusted code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec

from digitalcredential.internal import safehttp, uri
from digitalcredential.internal.allowlist import Hints, Redirects, check, new as allowlist_new, redirects_any, redirects_to
from digitalcredential.internal.httpcache import get as httpcache_get
from digitalcredential.internal.safehttp import (
    Client,
    ErrBlockedAddress,
    ErrBodyTooLarge,
    ErrContentTypeNotAccepted,
    ErrNotFollowed,
    ErrRedirectTargetNotAllowed,
    ErrTooManyRedirects,
    Limits,
    StatusError,
    https_url,
    is_,
)
from digitalcredential.issuerkey import ErrIssuerNotSupported, ErrNoUsableKey, PublicKey
from digitalcredential.issuermeta.cache import KeyCache
from jose import json as jose_json
from jose.errors import ErrInvalidArgument
from jose.jwk import to_public_key

WELL_KNOWN = "/.well-known/jwt-vc-issuer"
MEDIA_TYPE_METADATA = "application/json"  # §4.2
# RFC 7517 §8.5 registers application/jwk-set+json; draft 19 names none for jwks_uri, so a JWK Set
# served as JSON is accepted too.
MEDIA_TYPES_JWKS = ["application/jwk-set+json", "application/json"]
FETCH_TIMEOUT = 5.0
MAX_REDIRECTS = 3
MAX_BODY = 64 << 10  # about 500 EC JWKs
MAX_CACHE_LIFETIME = 24 * 3600.0

# The causes of a failed retrieval. An error of keys() wraps one when it applies (reach it with
# safehttp.is_). Package typemeta exports the same values.
ErrRedirectNotAllowed = ErrNotFollowed
ErrAddressBlocked = ErrBlockedAddress

_TRUST_HINTS = Hints(
    all="leave Config.TrustedIssuerOrigins empty",
    finer="list the origin and refuse the other iss in a Resolver that wraps this one",
)


class RetrievalError(safehttp.SafeHTTPError):
    """A retrieval failed (§3); __cause__ is the reason (StatusError, ErrRedirectNotAllowed, ...)."""


@dataclass
class RedirectPolicy:
    """Where a redirect of the metadata or of jwks_uri is followed. The zero value follows one only
    within the origin of the URL requested; redirect_to and redirect_any widen it."""

    mode: str = ""
    origins: list[str] = field(default_factory=list)

    def rule(self) -> Redirects:
        if self.mode == "any":
            return redirects_any()
        if self.mode == "to":
            if not self.origins:
                raise ErrInvalidArgument(
                    "issuermeta: Config.Redirects is RedirectTo with no origin; leave Redirects zero to "
                    "follow redirects only within the origin requested"
                )
            for i, e in enumerate(self.origins):
                if why := check(e, Hints(all="use RedirectAny()")):
                    raise ErrInvalidArgument(f"issuermeta: Config.Redirects RedirectTo[{i}] {why}")
            return redirects_to(self.origins)
        return Redirects()


def redirect_to(*origins: str) -> RedirectPolicy:
    return RedirectPolicy(mode="to", origins=list(origins))


def redirect_any() -> RedirectPolicy:
    return RedirectPolicy(mode="any")


@dataclass
class ResolverConfig:
    trusted_issuer_origins: list[str] = field(default_factory=list)
    redirects: RedirectPolicy = field(default_factory=RedirectPolicy)
    http_client: Client | None = None
    disable_cache: bool = False
    now: Callable[[], datetime] | None = None
    # fetch(url) -> (body, headers) is a shortcut for http_client=Client.from_fetch(fetch)
    fetch: Callable[[str], tuple[bytes, dict[str, str]]] | None = None


MetadataFetcher = Callable[[str], tuple[bytes, dict[str, str]]]


def metadata_url(iss: str) -> str:
    """The location of the JWT VC Issuer Metadata of iss: the well-known string inserted between the
    host and the path of iss, after every terminating "/" is removed (§4, §4.1). Raises
    ErrIssuerNotSupported when iss is not a URI, or not an https URL with a host and no userinfo,
    query or fragment."""
    return _metadata_url(iss)[1]


def _metadata_url(iss: str):
    # §4: iss MUST be an https URL as defined in RFC 3986; a host in Unicode is not one.
    if not uri.valid(iss):
        raise ErrIssuerNotSupported("issuermeta: iss is not a URI (RFC 3986)")
    u = safehttp.parse(iss)
    if u is None or not https_url(u):
        raise ErrIssuerNotSupported(
            "issuermeta: iss is not an https URL with a host (draft-ietf-oauth-sd-jwt-vc-19 §4) "
            "and no userinfo (RFC 9110 §4.2.4)"
        )
    # RFC 3986 §3: neither character appears raw in the authority or path, so either one starts a
    # query or fragment, even an empty one.
    if "?" in iss or "#" in iss:
        raise ErrIssuerNotSupported(
            "issuermeta: iss has a query or fragment, which draft-ietf-oauth-sd-jwt-vc-19 §4 forbids"
        )
    # Split the raw iss, so the path reaches the server as the issuer wrote it.
    rest = iss[iss.index("://") + 3 :]
    authority, slash, path = rest.partition("/")
    path = slash + path
    return u, "https://" + authority + WELL_KNOWN + path.rstrip("/")


def new_resolver(cfg: ResolverConfig | None = None) -> "Resolver":
    """A Resolver for cfg. An entry of trusted_issuer_origins, or of a redirect_to, that is not an
    https origin "https://host" or "https://*.host" (optional port and final "/") is
    ErrInvalidArgument; so is a redirect_to with no origin."""
    return Resolver(cfg or ResolverConfig())


class Resolver:
    """Returns the signing keys an issuer publishes. Share one instance: the cache belongs to it. Safe
    for concurrent use except that concurrent misses on one iss each fetch."""

    def __init__(self, cfg: ResolverConfig) -> None:
        for i, e in enumerate(cfg.trusted_issuer_origins):
            if why := check(e, _TRUST_HINTS):
                raise ErrInvalidArgument(f"issuermeta: Config.TrustedIssuerOrigins[{i}] {why}")
        redirects = cfg.redirects.rule()
        self.cfg = cfg
        self._trusted = allowlist_new(cfg.trusted_issuer_origins)
        self._limits = Limits(
            timeout_seconds=FETCH_TIMEOUT, max_redirects=MAX_REDIRECTS, max_bytes=MAX_BODY, follow=redirects.follows
        )
        self._client = cfg.http_client or (Client.from_fetch(cfg.fetch) if cfg.fetch else safehttp.new_client())
        self._no_cache = cfg.disable_cache
        self._now = cfg.now or (lambda: datetime.now(timezone.utc))
        self._cache = KeyCache()

    # cache access under the names the Go tests use
    def cached(self, iss: str):
        return self._cache.cached(iss, self._now())

    def store(self, iss: str, keys: list[PublicKey], sent: datetime, expires: datetime) -> None:
        self._cache.store(iss, keys, sent, expires, self._now(), self._no_cache)

    def keys(self, iss: str) -> list[PublicKey]:
        """The signing keys the metadata of iss publishes (possibly none: a JWK this SDK cannot use
        is skipped, RFC 7517 §5). Raises ErrIssuerNotSupported before any request (iss is not a URI,
        not an https URL with a host and no query, fragment or userinfo, or the origin is not covered
        by trusted_issuer_origins); ErrNoUsableKey when the server answered and the metadata or JWK
        Set is not valid; RetrievalError (cause: StatusError, ErrRedirectNotAllowed, ...) when a
        retrieval failed. A cache hit makes no request. The returned list is the caller's; the keys
        in it are shared."""
        if not iss:
            raise ErrIssuerNotSupported(
                "issuermeta: the credential has no iss; issuermeta resolves only https issuers "
                "(draft-ietf-oauth-sd-jwt-vc-19 §2.5)"
            )
        u, meta_url = _metadata_url(iss)
        if not self._trusted.covers(u):
            raise ErrIssuerNotSupported(
                "issuermeta: the origin of iss is not covered by Config.TrustedIssuerOrigins; "
                "list it there to trust it"
            )
        hit = self.cached(iss)
        if hit is not None:
            return hit
        # RFC 9111 §4.2.3: age is measured from the time the request was sent.
        sent = self._now()
        keys, expires = self._fetch(iss, meta_url, sent)
        self.store(iss, keys, sent, expires)
        return keys

    def _get(self, url: str, media_types: list[str], what: str) -> tuple[bytes, float]:
        try:
            return httpcache_get(self._client, url, media_types, self._limits, MAX_CACHE_LIFETIME)
        except safehttp.SafeHTTPError as e:
            raise _retrieval_err(what, e) from e

    def _fetch(self, iss: str, meta_url: str, sent: datetime) -> tuple[list[PublicKey], datetime]:
        body, fresh = self._get(meta_url, [MEDIA_TYPE_METADATA], "the issuer metadata")
        expires = sent + timedelta(seconds=fresh)
        meta = _decode_object(body, "the issuer metadata is not a JSON object: {}; the issuer must fix it")
        v = meta.get("issuer")
        if not isinstance(v, str):
            raise _fault("the issuer metadata has no string issuer (draft-ietf-oauth-sd-jwt-vc-19 §4.2)")
        if v != iss:
            raise _fault(
                "the issuer metadata names another issuer than the credential's iss; "
                "draft-ietf-oauth-sd-jwt-vc-19 §4.3 forbids using it"
            )
        # A member present as null counts as present.
        has_jwks, has_uri = "jwks" in meta, "jwks_uri" in meta
        if has_jwks and has_uri:
            raise _fault("the issuer metadata has both jwks and jwks_uri (draft-ietf-oauth-sd-jwt-vc-19 §4.2 allows exactly one)")
        if not has_jwks and not has_uri:
            raise _fault("the issuer metadata has neither jwks nor jwks_uri (draft-ietf-oauth-sd-jwt-vc-19 §4.2 requires one)")
        if has_jwks:
            jwks = meta["jwks"]
            if not isinstance(jwks, dict):
                raise _fault("jwks is not a JSON object (draft-ietf-oauth-sd-jwt-vc-19 §4.2)")
            s = jwks
        else:
            # Checked here rather than by safehttp, whose refusal would read as a failed retrieval:
            # this one is a fault of the issuer's document.
            su = meta["jwks_uri"]
            # §4.2: jwks_uri is a URL string, so a URI (RFC 3986 §1.1.3).
            if isinstance(su, str) and not uri.valid(su):
                raise _fault("jwks_uri is not a URI (RFC 3986)")
            if not isinstance(su, str) or not https_url(su):
                raise _fault(
                    "jwks_uri is not an https URL with a host (draft-ietf-oauth-sd-jwt-vc-19 §3, §4.2) "
                    "and no userinfo (RFC 9110 §4.2.4)"
                )
            sent2 = self._now()
            body, fresh = self._get(su, MEDIA_TYPES_JWKS, "the JWK Set")
            e = sent2 + timedelta(seconds=fresh)
            if e < expires:
                expires = e
            s = _decode_object(body, "the JWK Set from jwks_uri is not a JSON object: {}")
        return signing_keys(s), expires


def signing_keys(jwk_set: dict[str, Any]) -> list[PublicKey]:
    """Walk the JWK Set in its order. A JWK this SDK cannot use is skipped (RFC 7517 §5); an element
    that is not a JWK object makes the set invalid (RFC 7517 §4; draft 19 §3)."""
    elems = jwk_set.get("keys")
    if not isinstance(elems, list):
        raise _fault("the JWK Set has no keys array (RFC 7517 §5)")
    keys: list[PublicKey] = []
    for m in elems:
        if not isinstance(m, dict):
            raise _fault("the JWK Set holds an element that is not a JWK object (RFC 7517 §4)")
        kid = ""
        if "kid" in m:
            if not isinstance(m["kid"], str):
                continue
            kid = m["kid"]
        try:
            pub = to_public_key(m)
        except Exception:  # noqa: BLE001 - any key the SDK cannot use is skipped
            continue
        alg = "ES256K"  # RFC 8812 §3.2
        if isinstance(pub, crypto_ec.EllipticCurvePublicKey) and isinstance(pub.curve, crypto_ec.SECP256R1):
            alg = "ES256"  # RFC 7518 §3.4
        if not _signing_key(m, alg):
            continue
        keys.append(PublicKey(public=pub, kid=kid))
    return keys


def _signing_key(m: dict[str, Any], alg: str) -> bool:
    """Whether JWK m may verify an Issuer-signed JWT signed with alg: a key marked for another use
    or algorithm is skipped (RFC 7517 §4.2-4.4; RFC 8725 §3.1); so is a member of the wrong type."""
    if "use" in m and m["use"] != "sig":
        return False
    if "alg" in m and m["alg"] != alg:
        return False
    if "key_ops" in m:
        ops = m["key_ops"]
        if not isinstance(ops, list) or "verify" not in ops:
            return False
    return True


def _decode_object(body: bytes, fmt: str) -> dict[str, Any]:
    try:
        return jose_json.decode_json_object(body)
    except Exception as e:  # noqa: BLE001
        raise ErrNoUsableKey("issuermeta: " + fmt.format(e)) from e


def _retrieval_err(what: str, err: BaseException) -> RetrievalError:
    if is_(err, ErrNotFollowed):
        return RetrievalError(
            f"issuermeta: fetching {what}: {err}: the redirect leaves the origin of the URL requested for a "
            "target Config.Redirects does not allow; the issuer must serve it from that origin, or the "
            "verifier allows the target with RedirectTo"
        )
    return RetrievalError(f"issuermeta: fetching {what}: {err}")


def _fault(msg: str) -> ErrNoUsableKey:
    """A metadata document or JWK Set that must not be used."""
    return ErrNoUsableKey("issuermeta: " + msg)


FetchingResolver = Resolver


class PreloadedResolver:
    """Resolve issuer keys from preloaded JWT VC Issuer Metadata documents (no network)."""

    def __init__(self, metadata_by_iss: dict[str, bytes], jwks_by_uri: dict[str, bytes] | None = None) -> None:
        self._meta = {k: bytes(v) for k, v in metadata_by_iss.items()}
        self._jwks = {k: bytes(v) for k, v in (jwks_by_uri or {}).items()}

    def keys(self, iss: str) -> list[PublicKey]:
        meta = self._meta.get(iss)
        if meta is None:
            raise ErrIssuerNotSupported("issuermeta: no metadata for issuer")
        doc = _decode_object(meta, "the issuer metadata is not a JSON object: {}")
        if doc.get("issuer") != iss:
            raise _fault("the issuer metadata names another issuer than the credential's iss")
        if "jwks" in doc and "jwks_uri" not in doc:
            if not isinstance(doc["jwks"], dict):
                raise _fault("jwks is not a JSON object")
            return signing_keys(doc["jwks"])
        if "jwks_uri" in doc and "jwks" not in doc:
            raw = self._jwks.get(doc["jwks_uri"]) if isinstance(doc["jwks_uri"], str) else None
            if raw is None:
                raise _fault("no preloaded JWK set for jwks_uri")
            return signing_keys(_decode_object(raw, "the JWK Set is not a JSON object: {}"))
        raise _fault("the issuer metadata has none or both of jwks and jwks_uri")
