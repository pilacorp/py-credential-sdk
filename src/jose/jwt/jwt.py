"""JWT claim helpers (RFC 7519): NumericDate, exp/nbf and aud checks (Go jose/jwt)."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

from jose.errors import ErrInvalidArgument, ErrMalformed
from jose.json import JsonNumber


class ErrExpired(Exception):
    """now is on or after exp plus the skew (RFC 7519 §4.1.4)."""


class ErrNotYetValid(Exception):
    """now is before nbf minus the skew (RFC 7519 §4.1.5)."""


class ErrAudience(Exception):
    """aud is present and does not list the audience, or the caller named none (RFC 7519 §4.1.3)."""


# The range of dates Go's time.Time computes; narrower than Python's datetime, see numeric_date.
_MAX_UNIX = 9223372036854775807 - 62135596800
_MIN_UNIX = -9223372028741760000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def numeric_date_ns(v: Any) -> int:
    """NumericDate (RFC 7519 §2) as integer nanoseconds since the epoch, with Go's float64 reading.

    Accepts a JsonNumber, an int or a float (never a bool). Anything else, NaN, +-Inf or a value
    outside the dates Go's time.Time computes is ErrMalformed.
    """
    if isinstance(v, JsonNumber):
        try:
            f = float(str(v))
        except ValueError as e:  # pragma: no cover - the number grammar always parses
            raise ErrMalformed(f"NumericDate: {e}") from e
    elif isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ErrMalformed(f"NumericDate is {type(v).__name__}, not a number")
    else:
        f = float(v)
    if math.isnan(f) or f < _MIN_UNIX or f >= float(_MAX_UNIX):
        raise ErrMalformed(f"NumericDate {f} is out of range")
    sec = math.floor(f)
    nsec = round((f - sec) * 1e9)  # time.Unix carries 1e9 into sec
    return int(sec) * 1_000_000_000 + int(nsec)


def _datetime(ns: int) -> datetime:
    """ns as an aware UTC datetime, clamped to Python's year 1..9999 (comparisons use numeric_date_ns)."""
    try:
        return _EPOCH + timedelta(microseconds=ns // 1000)
    except OverflowError:
        return datetime.max.replace(tzinfo=timezone.utc) if ns > 0 else datetime.min.replace(tzinfo=timezone.utc)


def numeric_date(v: Any) -> datetime:
    """numeric_date_ns as a datetime; dates beyond Python's year range are clamped to datetime.min/max."""
    return _datetime(numeric_date_ns(v))


def _date_claim_ns(claims: dict[str, Any], name: str) -> int | None:
    if name not in claims:
        return None
    try:
        return numeric_date_ns(claims[name])
    except ErrMalformed as e:
        raise ErrMalformed(f"{name}: {e}") from e


def date_claim(claims: dict[str, Any], name: str) -> tuple[datetime, bool]:
    """Read the NumericDate claim `name`; ok is False when absent, a present bad value is ErrMalformed."""
    ns = _date_claim_ns(claims, name)
    if ns is None:
        return _EPOCH, False
    return _datetime(ns), True


def _now_ns(now: datetime) -> int:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - _EPOCH) // timedelta(microseconds=1) * 1000


def check_exp_nbf(claims: dict[str, Any], now: datetime, skew_seconds: float) -> None:
    """exp refuses when now >= exp + skew, nbf when now < nbf - skew; a negative skew is ErrInvalidArgument."""
    if skew_seconds < 0:
        raise ErrInvalidArgument("jwt: negative skew")
    skew = round(skew_seconds * 1e9)
    now_ns = _now_ns(now)
    exp = _date_claim_ns(claims, "exp")
    if exp is not None and not now_ns - skew < exp:
        raise ErrExpired(f"jwt: expired at {_datetime(exp).isoformat()}")
    nbf = _date_claim_ns(claims, "nbf")
    if nbf is not None and now_ns + skew < nbf:
        raise ErrNotYetValid(f"jwt: not yet valid: valid from {_datetime(nbf).isoformat()}")


def check_aud(claims: dict[str, Any], audience: str) -> None:
    """aud, when present, is a string or an array of strings listing `audience` (byte for byte)."""
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
    raise ErrAudience("jwt: aud does not list this audience")
