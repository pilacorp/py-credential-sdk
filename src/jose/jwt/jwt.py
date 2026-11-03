"""JWT claim helpers (RFC 7519)."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from jose.errors import ErrInvalidArgument, ErrMalformed
from jose.json import JsonNumber

class ErrExpired(Exception):
    pass


class ErrNotYetValid(Exception):
    pass


class ErrAudience(Exception):
    pass

_MAX_UNIX = 9223372036854775807 - 62135596800
_MIN_UNIX = -9223372028741760000


def numeric_date(v: Any) -> datetime:
    if isinstance(v, JsonNumber):
        f = float(v)
    elif isinstance(v, (int, float)):
        f = float(v)
    else:
        raise ErrMalformed(f"NumericDate is {type(v).__name__}, not a number")
    return _from_float(f)


def date_claim(claims: dict[str, Any], name: str) -> tuple[datetime, bool]:
    if name not in claims:
        return datetime.fromtimestamp(0, tz=timezone.utc), False
    t = numeric_date(claims[name])
    return t, True


def check_exp_nbf(claims: dict[str, Any], now: datetime, skew_seconds: float) -> None:
    if skew_seconds < 0:
        raise ErrInvalidArgument("jwt: negative skew")
    exp, ok, err = _date_claim_safe(claims, "exp")
    if err:
        raise err
    if ok and not now.timestamp() - skew_seconds < exp.timestamp():
        raise ErrExpired(f"at {exp.isoformat()}")
    nbf, ok, err = _date_claim_safe(claims, "nbf")
    if err:
        raise err
    if ok and now.timestamp() + skew_seconds < nbf.timestamp():
        raise ErrNotYetValid(f"valid from {nbf.isoformat()}")


def check_aud(claims: dict[str, Any], audience: str) -> None:
    if "aud" not in claims:
        return
    v = claims["aud"]
    if isinstance(v, str):
        lst = [v]
    elif isinstance(v, list):
        lst = v
    else:
        raise ErrMalformed(f"aud is {type(v).__name__}, not a string or an array of strings")
    for el in lst:
        if not isinstance(el, str):
            raise ErrMalformed(f"aud holds a {type(el).__name__}, not a string")
    if audience == "":
        raise ErrAudience("aud is present and no audience was given to compare it with")
    if audience in lst:
        return
    raise ErrAudience("aud does not list this audience")


def _date_claim_safe(claims: dict[str, Any], name: str) -> tuple[datetime, bool, Exception | None]:
    if name not in claims:
        return datetime.fromtimestamp(0, tz=timezone.utc), False, None
    try:
        t = numeric_date(claims[name])
    except ErrMalformed as e:
        return datetime.fromtimestamp(0, tz=timezone.utc), True, ErrMalformed(f"{name}: {e}")
    return t, True, None


def _from_float(f: float) -> datetime:
    if math.isnan(f) or f < _MIN_UNIX or f >= float(_MAX_UNIX):
        raise ErrMalformed(f"NumericDate {f} is out of range")
    sec = math.floor(f)
    nsec = round((f - sec) * 1e9)
    return datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=int(nsec // 1000))
