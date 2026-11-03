from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from digitalcredential.statuslist.statuslist import List

ENTRY_COST = 256
MAX_CACHE_BYTES = 32 << 20


@dataclass
class CacheKey:
    iss: str
    uri: str


@dataclass
class CacheEntry:
    list: List
    iat: datetime
    expires: datetime
    size: int


class ListCache:
    def __init__(self, now_fn=None) -> None:
        self._cache: dict[CacheKey, CacheEntry] = {}
        self._used = 0
        self._purge_at: datetime | None = None
        self._now = now_fn or (lambda: datetime.now().astimezone())

    def get(self, key: CacheKey) -> tuple[List | None, datetime | None]:
        now = self._now()
        e = self._cache.get(key)
        if e and now < e.expires:
            return e.list, e.iat
        return None, None

    def store(self, key: CacheKey, lst: List, iat: datetime, expires: datetime) -> None:
        now = self._now()
        if now >= expires:
            return
        data = lst.bytes()
        size = ENTRY_COST + len(data) + len(key.iss) + len(key.uri)
        old = self._cache.get(key)
        if old:
            if now < old.expires and old.iat > iat:
                return
            self._used -= old.size
            del self._cache[key]
        if self._used + size > MAX_CACHE_BYTES:
            if self._purge_at is None or now >= self._purge_at:
                self._purge_at = None
                for k, e in list(self._cache.items()):
                    if now >= e.expires:
                        self._used -= e.size
                        del self._cache[k]
                    elif self._purge_at is None or e.expires < self._purge_at:
                        self._purge_at = e.expires
        if self._used + size > MAX_CACHE_BYTES:
            return
        key = CacheKey(iss=str(key.iss), uri=str(key.uri))
        self._cache[key] = CacheEntry(list=lst, iat=iat, expires=expires, size=size)
        self._used += size
        if self._purge_at is None or expires < self._purge_at:
            self._purge_at = expires
