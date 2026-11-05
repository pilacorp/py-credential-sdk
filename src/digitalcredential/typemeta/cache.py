"""The cache of the HTTP resolver; how long a response without integrity may be reused is
internal/httpcache (RFC 9111 §4.2, §5.2)."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime

from digitalcredential.typemeta.ref import Ref

MAX_CACHE_BYTES = 4 << 20
ENTRY_COST = 200  # estimated heap of an entry beside the bytes it holds


@dataclass
class _Entry:
    doc: bytes  # never handed out: get() returns a copy
    sent: datetime  # when the request of this answer was sent
    expires: datetime | None  # None: no expiry, the document matched its integrity; evicted oldest first when full
    size: int

    def live(self, now: datetime) -> bool:
        return self.expires is None or now < self.expires


class DocumentCache:
    def __init__(self, max_bytes: int = MAX_CACHE_BYTES) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], _Entry] = {}
        self._used = 0
        self._pinned = 0  # the part of used held by entries with no expiry
        self._purge_at: datetime | None = None  # no later than the earliest expiry, None when unknown
        self._max = max_bytes

    def get(self, ref: Ref, now: datetime) -> bytes | None:
        with self._lock:
            e = self._entries.get((ref.vct, ref.integrity))
            if e is not None and e.live(now):
                return bytes(e.doc)
        return None

    def put(self, ref: Ref, doc: bytes, sent: datetime, expires: datetime | None, now: datetime | None = None) -> None:
        """Cache doc for ref until expires (None: no expiry), doc answering a request sent at `sent`. Keeps
        the entry of ref when that one is live and answers a later request; an expiry not after now or a
        full cache stores nothing, which costs a retrieval, never a wrong document. A full cache first
        drops its expired entries, then entries with no expiry, the oldest sent first."""
        now = now or sent
        if expires is not None and not now < expires:
            return
        key = (ref.vct, ref.integrity)
        size = ENTRY_COST + len(ref.vct) + len(ref.integrity) + len(doc)
        with self._lock:
            old = self._entries.get(key)
            if old is not None:
                if old.live(now) and old.sent > sent:
                    return
                self._used -= old.size
                if old.expires is None:
                    self._pinned -= old.size
                del self._entries[key]
            if self._used + size > self._max and self._purge_at is not None and now >= self._purge_at:
                self._purge_at = None
                for k, e in list(self._entries.items()):
                    if not e.live(now):
                        self._used -= e.size
                        del self._entries[k]
                    elif e.expires is None:
                        pass
                    elif self._purge_at is None or e.expires < self._purge_at:
                        self._purge_at = e.expires
            if self._used + size > self._max and not self._evict_pinned(size):
                return
            self._entries[key] = _Entry(bytes(doc), sent, expires, size)
            self._used += size
            if expires is None:
                self._pinned += size
            elif self._purge_at is None or expires < self._purge_at:
                self._purge_at = expires

    def _evict_pinned(self, size: int) -> bool:
        """Drop entries with no expiry, the oldest sent first, until an entry of size fits; report whether
        it does. Drops nothing when dropping all of them would not be enough."""
        if self._max - self._used + self._pinned < size:
            return False
        pinned = sorted(((k, e) for k, e in self._entries.items() if e.expires is None), key=lambda x: x[1].sent)
        for k, e in pinned:
            if self._used + size <= self._max:
                break
            self._used -= e.size
            self._pinned -= e.size
            del self._entries[k]
        return True
