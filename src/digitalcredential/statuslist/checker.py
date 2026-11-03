from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from digitalcredential.internal import jsonint, uri
from digitalcredential.internal.safehttp import Limits, get_with_fetcher
from digitalcredential.issuerkey import select_key
from digitalcredential.jws_compact import peek_header, verify_compact_jws
from digitalcredential.statuslist.cache import CacheKey, ListCache
from digitalcredential.statuslist.errors import (
    ErrIndexOutOfBounds,
    ErrIssuedInFuture,
    ErrIssuerMismatch,
    ErrSubjectMismatch,
    ErrTokenType,
    ErrTooOld,
    ErrURINotSupported,
)
from digitalcredential.statuslist.statuslist import List
from digitalcredential.statuslist.token import TYP_STATUS_LIST

MEDIA_TYPE_JWT = "application/statuslist+jwt"
MAX_TOKEN_BYTES = 1 << 20
MAX_CACHE_LIFETIME = timedelta(hours=24)
DEFAULT_CLOCK_SKEW = timedelta(minutes=1)


@dataclass
class Ref:
    uri: str
    index: int

    def validate(self) -> None:
        uri.check(self.uri)
        if self.index < 0:
            raise ValueError(f"statuslist: Ref.Index {self.index} is negative")


TokenFetcher = Callable[[str], str]


class IssuerResolver(Protocol):
    def keys(self, iss: str): ...


@dataclass
class CheckerConfig:
    issuers: IssuerResolver
    fetch_token: TokenFetcher | None = None
    insecure_http: bool = False
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW
    max_age: timedelta | None = None
    allowed_algs: list[str] | None = None


class Checker:
    def __init__(self, cfg: CheckerConfig) -> None:
        if cfg.issuers is None:
            raise ValueError("statuslist: Config.Issuers is required")
        if cfg.clock_skew.total_seconds() < 0:
            raise ValueError("statuslist: Config.ClockSkew is negative")
        if cfg.max_age is not None and cfg.max_age.total_seconds() < 0:
            raise ValueError("statuslist: Config.MaxAge is negative")
        self._issuers = cfg.issuers
        self._fetch = cfg.fetch_token
        self._insecure = cfg.insecure_http
        self._skew = cfg.clock_skew or DEFAULT_CLOCK_SKEW
        self._max_age = cfg.max_age
        self._algs = list(cfg.allowed_algs or ["ES256", "ES256K"])
        self._cache = ListCache()

    def status(self, ref: Ref, iss: str, now: datetime | None = None) -> int:
        ref.validate()
        limits = Limits(max_bytes=MAX_TOKEN_BYTES, allow_http=self._insecure)
        if not limits.allows(ref.uri):
            raise ErrURINotSupported
        now = now or datetime.now(timezone.utc)
        key = CacheKey(iss=iss, uri=ref.uri)
        lst, _ = self._cache.get(key)
        from_cache = lst is not None
        if lst is None:
            lst = self._load(key, iss, ref.uri, now)
        if ref.index >= lst.entries() and from_cache:
            lst = self._load(key, iss, ref.uri, now)
        n = lst.entries()
        if ref.index >= n:
            raise ErrIndexOutOfBounds(f"index {ref.index} outside list of {n} entries")
        return lst.get(ref.index)

    def _load(self, key: CacheKey, iss: str, uri_s: str, now: datetime) -> List:
        if self._fetch is None:
            raise ValueError("statuslist: no token fetcher configured")

        def _fetcher(url: str):
            body = self._fetch(url).encode("utf-8")
            return body, {"content-type": MEDIA_TYPE_JWT}

        token_bytes = get_with_fetcher(uri_s, _fetcher, [MEDIA_TYPE_JWT], Limits(max_bytes=MAX_TOKEN_BYTES, allow_http=self._insecure, any_content_type=True))
        token = token_bytes.decode("ascii")
        header = peek_header(token)
        if header.get("typ") != TYP_STATUS_LIST:
            raise ErrTokenType
        keys = self._issuers.keys(iss)
        pub = select_key(keys, header.get("kid") if isinstance(header.get("kid"), str) else None)
        payload = verify_compact_jws(token, pub.public_key, self._algs)
        tc = _check_claims(payload, iss, uri_s, now, self._skew)
        self._check_age(tc["iat"], now)
        bits = tc["bits"]
        lst = List.decode(tc["lst"], bits)
        if tc.get("ttl", 0) > 0:
            ttl = min(timedelta(seconds=tc["ttl"]), MAX_CACHE_LIFETIME)
            expires = now + ttl
            if tc.get("exp"):
                exp = datetime.fromtimestamp(tc["exp"], tz=timezone.utc)
                if exp < expires:
                    expires = exp
            if self._max_age:
                aged = tc["iat"] + self._max_age + self._skew
                if aged < expires:
                    expires = aged
            self._cache.store(key, lst, tc["iat"], expires)
        return lst

    def _check_age(self, iat: datetime, now: datetime) -> None:
        if self._max_age and iat < now - self._max_age - self._skew:
            raise ErrTooOld(f"iat {iat.isoformat()}, max age {self._max_age}")

def _check_claims(claims: dict, iss: str, uri_s: str, now: datetime, skew: timedelta) -> dict:
    if claims.get("sub") != uri_s:
        raise ErrSubjectMismatch
    if "iss" in claims and claims.get("iss") != iss:
        raise ErrIssuerMismatch
    iat_raw = claims.get("iat")
    if not isinstance(iat_raw, (int, float)):
        raise ValueError("statuslist: token has no iat")
    iat = datetime.fromtimestamp(int(iat_raw), tz=timezone.utc)
    if iat > now + skew:
        raise ErrIssuedInFuture
    ttl = 0.0
    if "ttl" in claims:
        ttl = float(claims["ttl"])
        if ttl <= 0:
            raise ValueError("statuslist: token ttl is not a positive number")
        ttl = min(ttl, MAX_CACHE_LIFETIME.total_seconds())
    sl = claims.get("status_list")
    if not isinstance(sl, dict):
        raise ValueError("statuslist: token status_list is not an object")
    bits = jsonint.non_negative(sl.get("bits"))
    lst = sl.get("lst")
    if not isinstance(lst, str):
        raise ValueError("statuslist: token status_list lst is not a string")
    exp = int(claims["exp"]) if "exp" in claims else None
    return {"bits": bits, "lst": lst, "iat": iat, "ttl": ttl, "exp": exp}
