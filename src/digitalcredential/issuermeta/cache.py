from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

MAX_CACHE_BYTES = 4 << 20
ENTRY_COST = 128


@dataclass
class CacheEntry:
    body: bytes
    expires: datetime
    size: int


class MetadataCache:
    """In-memory cache for issuer metadata and JWK set bodies (RFC 9111-style TTL)."""

    def __init__(self, max_bytes: int = MAX_CACHE_BYTES) -> None:
        self._entries: dict[str, CacheEntry] = {}
        self._used = 0
        self._max = max_bytes

    def get(self, url: str, now: datetime) -> bytes | None:
        e = self._entries.get(url)
        if e and now < e.expires:
            return bytes(e.body)
        return None

    def put(self, url: str, body: bytes, fresh: timedelta, now: datetime) -> None:
        if fresh.total_seconds() <= 0:
            return
        expires = now + fresh
        size = ENTRY_COST + len(body) + len(url)
        old = self._entries.pop(url, None)
        if old:
            self._used -= old.size
        if self._used + size > self._max:
            return
        self._entries[url] = CacheEntry(body=bytes(body), expires=expires, size=size)
        self._used += size
