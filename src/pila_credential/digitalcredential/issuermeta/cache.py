"""The Resolver's cache of issuer keys; how long a response may be reused is internal/httpcache
(RFC 9111 §4.2, §5.2)."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any

MAX_CACHE_BYTES = 4 << 20
# Estimated heap bytes (as measured for the Go SDK): a cached key, and an entry besides its keys.
KEY_COST = 250
ENTRY_COST = 222


@dataclass
class CacheEntry:
    keys: list[Any]  # never handed out: cached() returns a copy
    sent: datetime  # when the metadata request of this answer was sent
    expires: datetime
    size: int


class KeyCache:
    """Keys by iss, expiring. Not a copy of a response: a failure is never stored here."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, CacheEntry] = {}
        self._used = 0
        self._purge_at: datetime | None = None  # no later than the earliest expiry, None when unknown

    def cached(self, iss: str, now: datetime) -> list[Any] | None:
        with self._lock:
            e = self._entries.get(iss)
            if e is not None and now < e.expires:
                return list(e.keys)
        return None

    def store(self, iss: str, keys: list[Any], sent: datetime, expires: datetime, now: datetime, no_cache: bool = False) -> None:
        """Cache keys for iss until expires, keys answering a request sent at `sent`. Replaces the
        entry of iss unless that one is live and answers a request sent later. With no_cache, or an
        expiry not after now, nothing is stored. When full, expired entries are dropped; if there is
        still no room the keys are not cached (costs a retrieval, never a wrong key)."""
        if no_cache or not now < expires:
            return
        size = ENTRY_COST + len(iss) + sum(KEY_COST + len(getattr(k, "kid", None) or "") for k in keys)
        with self._lock:
            old = self._entries.get(iss)
            if old is not None:
                if now < old.expires and old.sent > sent:
                    return
                self._used -= old.size
                del self._entries[iss]
            # Scanned only once an entry may have expired.
            if self._used + size > MAX_CACHE_BYTES and (self._purge_at is None or now >= self._purge_at):
                self._purge_at = None
                for k, e in list(self._entries.items()):
                    if not now < e.expires:
                        self._used -= e.size
                        del self._entries[k]
                    elif self._purge_at is None or e.expires < self._purge_at:
                        self._purge_at = e.expires
            if self._used + size > MAX_CACHE_BYTES:
                return
            self._entries[iss] = CacheEntry(list(keys), sent, expires, size)
            self._used += size
            if self._purge_at is None or expires < self._purge_at:
                self._purge_at = expires


# kept for callers of the previous shape
MetadataCache = KeyCache
