"""Checking the status of a Referenced Token against its Status List Token in JWT format:
draft-ietf-oauth-status-list-21 §8 (§8.1 request, §8.2 response, §8.3 validation) and §5.1."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from digitalcredential.internal import jsonint, safehttp, uri
from digitalcredential.internal.safehttp import Client, Limits
from digitalcredential.issuerkey import select
from digitalcredential.statuslist.cache import CacheKey, ListCache
from digitalcredential.statuslist.errors import (
    ErrIndexOutOfBounds,
    ErrIssuedInFuture,
    ErrIssuerMismatch,
    ErrSubjectMismatch,
    ErrTokenType,
    ErrTooOld,
    ErrURINotSupported,
    StatusListError,
)
from digitalcredential.statuslist.statuslist import List, decode
from digitalcredential.statuslist.token import TYP_STATUS_LIST
from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrMalformed, ErrUnsupportedAlg, ErrUnsupportedKey
from jose.json import JsonNumber
from jose.jws import ErrBadKey, header_typ_is, unverified_header, verify
from jose.jwt import check_aud, check_exp_nbf, date_claim

# Fixed limits of the Checker; every value is SDK policy (draft 21 leaves freshness and caching to the
# Relying Party, §8.3 step 4b, §13.7, and restrictions on the uri to it, §6.2).
MEDIA_TYPE_JWT = "application/" + TYP_STATUS_LIST  # §8.1, §8.2; RFC 7515 §4.1.9
FETCH_TIMEOUT = 5.0
MAX_REDIRECTS = 3
DEFAULT_CLOCK_SKEW = timedelta(minutes=1)  # RFC 7519 §4.1.4, §4.1.5: small leeway
MAX_CACHE_LIFETIME = timedelta(hours=24)  # upper bound on ttl (§11.5)
MAX_TOKEN_BYTES = 1 << 20  # the token read, in compact form (draft 21 sets no limit, §13.4)
DECODE_SLOTS = 4  # bounds concurrent decodes: an lst of a few KiB can inflate to 16 MiB
SUPPORTED_ALGS = ("ES256", "ES256K")


@dataclass
class Ref:
    """The status_list member of a Referenced Token's status claim (draft 21 §6.2): uri is the URI of
    the Status List Token, equal to its sub; index is idx, the entry of the Referenced Token."""

    uri: str
    index: int

    def validate(self) -> None:
        """Check against §6.2, raising jose.ErrInvalidArgument: uri is a URI (RFC 3986), with a host when
        http or https (RFC 9110 §4.2.1, §4.2.2), and idx is not negative."""
        try:
            uri.check(self.uri)
        except ValueError as e:
            raise ErrInvalidArgument(f"statuslist: Ref.URI {e}") from e
        if self.index < 0:
            raise ErrInvalidArgument(f"statuslist: Ref.Index {self.index} is negative")


class IssuerResolver(Protocol):
    def keys(self, iss: str): ...


TokenFetcher = Callable[[str], str]


class StatusFetchError(StatusListError):
    """The fetch of a Status List Token failed; __cause__ is the reason (StatusError, ...)."""


@dataclass
class CheckerConfig:
    """issuers: the keys that verify a Status List Token, looked up by the iss of the Referenced Token;
    required (the resolver the Referenced Token is itself verified with). http_client: None uses the
    default client, which refuses addresses that are not globally reachable (a custom one is trusted
    code). fetch_token(url) -> compact JWS is a shortcut for tests. insecure_http also fetches http
    uris and follows redirects to http. clock_skew: leeway on exp, nbf and an iat in the future (zero:
    1 minute). max_age: how old a token may be by its iat (None or zero: no limit). allowed_algs: nil
    or empty means ES256 and ES256K."""

    issuers: IssuerResolver
    http_client: Client | None = None
    fetch_token: TokenFetcher | None = None
    insecure_http: bool = False
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW
    max_age: timedelta | None = None
    allowed_algs: list[str] | None = None
    now: Callable[[], datetime] | None = None


@dataclass
class _ListClaims:
    lst: str = ""
    bits: int = 0
    iat: datetime = field(default_factory=lambda: datetime.fromtimestamp(0, tz=timezone.utc))
    ttl: timedelta = timedelta(0)  # 0: not cached
    exp: datetime | None = None


def new_checker(cfg: CheckerConfig) -> "Checker":
    return Checker(cfg)


class Checker:
    """Reads the status of Referenced Tokens from their Status List Tokens. Share one instance: the
    decode bound, the cache and the default client belong to it. Safe for concurrent use. Fetches
    follow at most 3 redirects to any origin, end within 5 seconds and read at most 1 MiB; a list
    inflates to at most 16 MiB; verified lists are cached for the token's ttl, at most 24 hours and
    never past exp or the max age (a token without ttl is not cached)."""

    def __init__(self, cfg: CheckerConfig) -> None:
        if cfg is None or cfg.issuers is None:
            raise ErrInvalidArgument("statuslist: Config.Issuers is required")
        if cfg.clock_skew is not None and cfg.clock_skew < timedelta(0):
            raise ErrInvalidArgument(f"statuslist: Config.ClockSkew {cfg.clock_skew} is negative")
        if cfg.max_age is not None and cfg.max_age < timedelta(0):
            raise ErrInvalidArgument(f"statuslist: Config.MaxAge {cfg.max_age} is negative")
        for alg in cfg.allowed_algs or []:
            if alg not in SUPPORTED_ALGS:
                raise _both(
                    ErrUnsupportedAlg,
                    f"statuslist: Config.AllowedAlgs: {alg!r}, this SDK verifies only ES256 and ES256K",
                )
        self._issuers = cfg.issuers
        self._insecure = cfg.insecure_http
        self._skew = cfg.clock_skew or DEFAULT_CLOCK_SKEW
        self._max_age = cfg.max_age or timedelta(0)
        self._algs = list(cfg.allowed_algs) if cfg.allowed_algs else None
        self._now = cfg.now or (lambda: datetime.now(timezone.utc))
        if cfg.http_client is not None:
            self._client = cfg.http_client
        elif cfg.fetch_token is not None:
            fetch = cfg.fetch_token
            self._client = Client.from_fetch(lambda url: (fetch(url).encode("utf-8"), {"content-type": MEDIA_TYPE_JWT}))
        else:
            self._client = safehttp.new_client()
        self._slots = threading.BoundedSemaphore(DECODE_SLOTS)
        self._cache = ListCache(self._now)

    def status(self, ref: Ref, iss: str) -> int:
        """The status value of entry ref.index in the Status List Token at ref.uri, which must be signed
        by a key of the issuer iss. The value is returned raw (§7.1); what it means is the caller's
        decision (§8.3 step 7). The caller validates the Referenced Token first.

        Any exception means no statement about the status can be made (§8.3): a uri the Checker does
        not fetch (ErrURINotSupported), a failed fetch (StatusFetchError, cause StatusError and the
        others of errors.py), a token that is malformed (jose.ErrMalformed), whose typ is not
        statuslist+jwt (ErrTokenType), not signed by a key of iss, with a sub other than ref.uri
        (ErrSubjectMismatch), an iss other than iss (ErrIssuerMismatch), an iat in the future
        (ErrIssuedInFuture) or older than max_age (ErrTooOld), an lst decode refuses, or an index
        outside the list (ErrIndexOutOfBounds: the Referenced Token MUST be rejected, §8.3 step 6).
        ErrIndexOutOfBounds comes only from the token fetched during the call. No error text holds the
        userinfo, path or query of the uri."""
        ref.validate()
        # The SDK's verifier default, which §6.2 leaves to the Relying Party. The uri stays out of the
        # error: it may carry a password in its userinfo or a token in its query.
        if not Limits(allow_http=self._insecure).allows(ref.uri):
            if self._insecure:
                raise ErrURINotSupported("the Checker fetches only https or http URLs with a host and no userinfo")
            raise ErrURINotSupported(
                "the Checker fetches only https URLs with a host and no userinfo (Config.InsecureHTTP allows http)"
            )
        # Keyed by iss too: keyed by uri alone, a list verified with one issuer's key would answer for
        # another issuer's token pointing to the same uri.
        key = CacheKey(iss, ref.uri)
        lst, _ = self._cache.get(key)
        from_cache = lst is not None
        if lst is None:
            lst = self._load(key, ref.index)
        # §13.4 lets an issuer grow a list, so a cached copy may predate the entry: an index outside it
        # is read from a fresh fetch.
        if ref.index >= lst.entries() and from_cache:
            lst = self._load(key, ref.index)
        n = lst.entries()
        if ref.index >= n:
            raise ErrIndexOutOfBounds(
                f"index {ref.index} is outside the list of {n} entries (draft-ietf-oauth-status-list-21 §8.3 step 6)"
            )
        return lst.get(ref.index)

    def _load(self, key: CacheKey, idx: int) -> List:
        fetched = self._now()
        # §8.1, §8.2; redirects bounded (§11.4). §8.2 puts the content-type MUST on the Status Provider,
        # and typ carries the type, so the Content-Type is not judged.
        try:
            body, _ = safehttp.get(
                self._client,
                key.uri,
                [MEDIA_TYPE_JWT],
                Limits(
                    timeout_seconds=FETCH_TIMEOUT,
                    max_redirects=MAX_REDIRECTS,
                    max_bytes=MAX_TOKEN_BYTES,
                    allow_http=self._insecure,
                    any_content_type=True,
                ),
            )
        except safehttp.SafeHTTPError as e:
            raise StatusFetchError(f"statuslist: {e}") from e
        # §8.2: the body is the token in JWS Compact Serialization, nothing more.
        try:
            token = body.decode("utf-8")
            header = unverified_header(token)
        except (UnicodeDecodeError, ErrMalformed) as e:
            raise ErrMalformed(f"statuslist: token: {e}") from e
        # §5.1: typ MUST be statuslist+jwt (RFC 8725 §3.11). Refusing on the unverified header accepts
        # nothing and spares the resolver call.
        if not header_typ_is(header, TYP_STATUS_LIST):
            raise ErrTokenType("statuslist: token typ is not statuslist+jwt")
        keys = self._issuers.keys(key.iss)
        pub = select(keys, header)
        # §5.1 rule 2 and §8.3 step 3a: the signature is checked before any claim is read.
        try:
            _, payload = verify(token, pub, self._algs)
        except (ErrUnsupportedKey, ErrBadKey) as e:
            # pub came from Config.Issuers, so a key jws cannot use is the verifier's wiring.
            raise _both(type(e), f"statuslist: Config.Issuers returned a key that cannot verify: {e}") from e
        claims = jose_json.decode_json_object(payload)
        tc = _check_claims(claims, key.iss, key.uri, self._now(), self._skew)
        self._check_age(tc.iat, self._now())

        # Decode is the costly step; the slot bounds how many run at once. A caller that waited may
        # find the list cached by another meanwhile, and uses it only if its token is not older than
        # its own: the cache keeps the newer iat, and so does this shortcut.
        with self._slots:
            cached, iat = self._cache.get(key)
            if cached is not None and idx < cached.entries() and not iat < tc.iat:
                return cached
            lst = decode(tc.lst, tc.bits)  # §8.3 step 5
        # The wait for a slot may have taken the token past exp or the max age: the same rules again.
        now = self._now()
        check_exp_nbf(claims, now, self._skew.total_seconds())
        self._check_age(tc.iat, now)

        # §8.3 step 4d and §13.7: cached for ttl from the fetch, at most 24 hours (§11.5), never past exp
        # nor past the max age. No ttl, no cache: stricter than §13.7 because without ttl the issuer
        # states no refresh interval, and caching until exp would hide revocations that long.
        if tc.ttl > timedelta(0):
            expires = fetched + tc.ttl
            if tc.exp is not None and tc.exp < expires:
                expires = tc.exp
            if self._max_age > timedelta(0):
                aged = tc.iat + self._max_age + self._skew
                if aged < expires:
                    expires = aged
            self._cache.store(key, lst, tc.iat, expires)
        return lst

    def _check_age(self, iat: datetime, now: datetime) -> None:
        """Config.max_age applied to a token issued at iat (§8.3 step 4b)."""
        if self._max_age > timedelta(0) and iat < now - self._max_age - self._skew:
            raise ErrTooOld(f"iat {iat.isoformat()}, max age {self._max_age}")


def _both(second: type, msg: str) -> Exception:
    """An error that is both jose.ErrInvalidArgument and `second` (Go wraps both with %w)."""
    return type("_" + second.__name__, (ErrInvalidArgument, second), {})(msg)


def _check_claims(claims: dict[str, Any], iss: str, uri_: str, now: datetime, skew: timedelta) -> _ListClaims:
    """§5.1 and §8.3 step 4 applied to the claims of a verified token fetched from uri_ and verified with
    a key of iss."""
    tc = _ListClaims()
    # §5.1 and §8.3 step 4a: sub equals the uri of the Referenced Token, compared without
    # transformation (RFC 7519 §7.3).
    sub = claims.get("sub")
    if not isinstance(sub, str) or sub != uri_:
        raise ErrSubjectMismatch("statuslist: token sub is not the uri of the Referenced Token")
    # RFC 8725 §3.8: a present iss must own the key that verified the token. The Checker verifies only
    # with keys of iss, so iss, a string, must equal it unchanged.
    if "iss" in claims:
        v = claims["iss"]
        if not isinstance(v, str) or v != iss:
            raise ErrIssuerMismatch("statuslist: token iss is not the issuer of the Referenced Token")
    # §5.1: iat is REQUIRED (§8.3 step 3b). One later than now + skew is refused, an SDK policy.
    try:
        iat, ok = date_claim(claims, "iat")
    except ErrMalformed as e:
        raise ErrMalformed(f"statuslist: token: {e}") from e
    if not ok:
        raise ErrMalformed("statuslist: token has no iat")
    if iat > now + skew:
        raise ErrIssuedInFuture("statuslist: token iat is in the future")
    tc.iat = iat
    # §5.1 rule 3 and §8.3 step 4c: exp, and nbf, per RFC 7519 §4.1.4, §4.1.5.
    check_exp_nbf(claims, now, skew.total_seconds())
    try:
        exp, has_exp = date_claim(claims, "exp")
    except ErrMalformed as e:
        raise ErrMalformed(f"statuslist: token: {e}") from e
    tc.exp = exp if has_exp else None
    # RFC 7519 §4.1.3: a JWT with aud MUST be rejected by a principal that does not identify itself
    # with a value in it, and the Checker has no identity to match, so any aud fails.
    check_aud(claims, "")
    # §5.1: ttl, when present, is a positive number of seconds, a fraction allowed; values over 24
    # hours, the SDK's bound (§11.5), are cut there.
    if "ttl" in claims:
        n = claims["ttl"]
        try:
            f = float(str(n)) if isinstance(n, JsonNumber) else float("nan")
        except ValueError:
            f = float("nan")
        if math.isnan(f) or math.isinf(f) or not f > 0:
            raise ErrMalformed("statuslist: token ttl is not a positive number")
        tc.ttl = MAX_CACHE_LIFETIME if f >= MAX_CACHE_LIFETIME.total_seconds() else timedelta(seconds=f)
    # §5.1 and §4.2: status_list holds bits, a JSON integer read by its value, so 1.0 is 1 (decode
    # checks it is 1, 2, 4 or 8), and lst, a string.
    sl = claims.get("status_list")
    if not isinstance(sl, dict):
        raise ErrMalformed("statuslist: token status_list is not an object")
    try:
        bits = sl.get("bits")
        if not isinstance(bits, JsonNumber):
            raise ValueError
        tc.bits = jsonint.non_negative(str(bits))
    except ValueError:
        raise ErrMalformed("statuslist: token status_list bits is not 1, 2, 4 or 8") from None
    lst = sl.get("lst")
    if not isinstance(lst, str):
        raise ErrMalformed("statuslist: token status_list lst is not a string")
    tc.lst = lst
    return tc
