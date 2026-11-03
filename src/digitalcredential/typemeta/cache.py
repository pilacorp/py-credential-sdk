from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from digitalcredential.typemeta.ref import Ref

MAX_CACHE_BYTES = 4 << 20
ENTRY_COST = 200


@dataclass
class _Entry:
    doc: bytes
    sent: datetime
    expires: datetime | None
    size: int


class DocumentCache:
    def __init__(self, max_bytes: int = MAX_CACHE_BYTES) -> None:
        self._entries: dict[tuple[str, str], _Entry] = {}
        self._used = 0
        self._pinned = 0
        self._max = max_bytes

    def get(self, ref: Ref, now: datetime) -> bytes | None:
        key = (ref.vct, ref.integrity)
        e = self._entries.get(key)
        if e is None:
            return None
        if e.expires is not None and now >= e.expires:
            return None
        return bytes(e.doc)

    def put(self, ref: Ref, doc: bytes, sent: datetime, expires: datetime | None) -> None:
        key = (ref.vct, ref.integrity)
        size = ENTRY_COST + len(ref.vct) + len(ref.integrity) + len(doc)
        old = self._entries.pop(key, None)
        if old:
            self._used -= old.size
            if old.expires is None:
                self._pinned -= old.size
        if self._used + size > self._max:
            self._evict(now=sent, need=size)
        if self._used + size > self._max:
            return
        self._entries[key] = _Entry(doc=bytes(doc), sent=sent, expires=expires, size=size)
        self._used += size
        if expires is None:
            self._pinned += size

    def _evict(self, now: datetime, need: int) -> None:
        for k in list(self._entries):
            e = self._entries[k]
            if e.expires is not None and now >= e.expires:
                self._used -= e.size
                del self._entries[k]
        pinned = sorted(
            ((k, e) for k, e in self._entries.items() if e.expires is None),
            key=lambda x: x[1].sent,
        )
        for k, e in pinned:
            if self._used + need <= self._max:
                break
            self._used -= e.size
            self._pinned -= e.size
            del self._entries[k]
