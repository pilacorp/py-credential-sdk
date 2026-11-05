"""The Checker's cache of verified Status Lists: draft-ietf-oauth-status-list-21 §8.3 step 4d, §13.7."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import NamedTuple

from digitalcredential.statuslist.statuslist import List

ENTRY_COST = 256  # estimated heap bytes of an entry besides its list's byte array and its key's strings
MAX_CACHE_BYTES = 32 << 20


class CacheKey(NamedTuple):
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
        self._lock = threading.Lock()
        self._cache: dict[CacheKey, CacheEntry] = {}
        self._used = 0
        self._purge_at: datetime | None = None
        self._now = now_fn or (lambda: datetime.now().astimezone())

    def get(self, key: CacheKey) -> tuple[List | None, datetime | None]:
        """The list cached for key and the iat of its token, or (None, None)."""
        now = self._now()
        with self._lock:
            e = self._cache.get(key)
            if e is not None and now < e.expires:
                return e.list, e.iat
        return None, None

    def store(self, key: CacheKey, lst: List, iat: datetime, expires: datetime) -> None:
        """Cache lst, from a token issued at iat, for key until expires. Replaces an entry of the same
        key unless that one is live and comes from a newer token (iat is the only signed order between
        two tokens of one list). When full, expired entries are dropped; if there is still no room, lst
        is not cached, which costs a fetch, never a wrong answer."""
        now = self._now()
        if not now < expires:
            return
        size = ENTRY_COST + len(lst._b) + len(key.iss) + len(key.uri)
        with self._lock:
            old = self._cache.get(key)
            if old is not None:
                if now < old.expires and old.iat > iat:
                    return
                self._used -= old.size
                del self._cache[key]
            if self._used + size > MAX_CACHE_BYTES and (self._purge_at is None or now >= self._purge_at):
                self._purge_at = None
                for k, e in list(self._cache.items()):
                    if not now < e.expires:
                        self._used -= e.size
                        del self._cache[k]
                    elif self._purge_at is None or e.expires < self._purge_at:
                        self._purge_at = e.expires
            if self._used + size > MAX_CACHE_BYTES:
                return
            self._cache[CacheKey(str(key.iss), str(key.uri))] = CacheEntry(lst, iat, expires, size)
            self._used += size
            if self._purge_at is None or expires < self._purge_at:
                self._purge_at = expires
