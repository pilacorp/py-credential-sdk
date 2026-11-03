from __future__ import annotations

import re
from typing import Mapping


def freshness(headers: Mapping[str, str], ceiling_seconds: float) -> float:
    cc = headers.get("cache-control", "")
    if '"' in cc:
        return 0.0
    vary = headers.get("vary", "")
    for part in vary.split(","):
        m = part.strip()
        if m and m.lower() not in ("accept", "accept-encoding"):
            return 0.0
    max_age: int | None = None
    seen = False
    for d in cc.split(","):
        name, _, arg = d.strip().partition("=")
        nl = name.lower()
        if nl in ("no-store", "no-cache"):
            return 0.0
        if nl == "max-age":
            if seen:
                return 0.0
            seen = True
            try:
                max_age = int(arg.strip())
            except ValueError:
                return 0.0
    if max_age is None:
        return 0.0
    age = 0
    if "age" in headers:
        try:
            age = int(re.sub(r"\D", "", headers["age"].split(",")[0]))
        except ValueError:
            age = 0
    fresh = max(0, max_age - age)
    return min(float(fresh), ceiling_seconds)
