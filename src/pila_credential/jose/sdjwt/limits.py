"""Resource limits for SD-JWT processing."""

from __future__ import annotations

from typing import Any

MAX_BYTES = 1 << 20
MAX_DISCLOSURES = 1000
MAX_DEPTH = 32
MAX_PATHS = 1000
MAX_MIN_DIGESTS = 1000
MAX_DIGESTS = 20000


def nests(v: Any) -> bool:
    return isinstance(v, (dict, list))
