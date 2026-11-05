"""Port of jose/jwt/jwt_test.go."""

import math
from datetime import datetime, timedelta, timezone

import pytest

from jose import ErrInvalidArgument, ErrMalformed, JsonNumber
from jose.jwt import ErrAudience, ErrExpired, ErrNotYetValid, check_aud, check_exp_nbf, date_claim, numeric_date, numeric_date_ns

AT = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "name,v,want_ns",
    [
        ("number fraction", JsonNumber("1700000000.25"), 1700000000_250_000_000),
        ("float", 1700000000.5, 1700000000_500_000_000),
        ("int", 1700000000, 1700000000_000_000_000),
        ("first second of the calendar", JsonNumber("-9223372028741760000"), -9223372028741760000 * 10**9),
    ],
)
def test_numeric_date_ok(name, v, want_ns):
    assert numeric_date_ns(v) == want_ns
    assert numeric_date(JsonNumber("1700000000")) == AT


@pytest.mark.parametrize(
    "v",
    [
        "1700000000",  # a string, not a number
        JsonNumber("1700000000x"),
        math.nan,
        -1e19,
        JsonNumber("-9223372036854775808"),  # before the calendar
        JsonNumber("-9223372028741761024"),  # one float64 step before the calendar
        JsonNumber("9223371974719179008"),  # past time.Time
        JsonNumber("1e999"),
        JsonNumber("-1e999"),
        True,  # bool is not a number
        False,
        None,
        [1],
        {},
    ],
)
def test_numeric_date_rejects(v):
    with pytest.raises(ErrMalformed):
        numeric_date_ns(v)


def test_numeric_date_dates_past_python_range_are_clamped():
    assert numeric_date(JsonNumber("9223371974719177984")) == datetime.max.replace(tzinfo=timezone.utc)
    assert numeric_date(JsonNumber("-9223372028741760000")) == datetime.min.replace(tzinfo=timezone.utc)


def test_date_claim():
    assert date_claim({}, "exp")[1] is False
    t, ok = date_claim({"exp": JsonNumber("1700000000")}, "exp")
    assert ok and t == AT
    with pytest.raises(ErrMalformed, match="exp"):
        date_claim({"exp": "x"}, "exp")


NOW = datetime.fromtimestamp(1748537244, tz=timezone.utc)


@pytest.mark.parametrize(
    "name,claims,err,skew",
    [
        ("neither", {}, None, 60),
        ("exp one second before the edge", {"exp": JsonNumber("1748537185")}, None, 60),
        ("exp at the edge", {"exp": JsonNumber("1748537184")}, ErrExpired, 60),
        ("nbf at the edge", {"nbf": JsonNumber("1748537304")}, None, 60),
        ("nbf one second past the edge", {"nbf": JsonNumber("1748537305")}, ErrNotYetValid, 60),
        ("exp not a number", {"exp": "1748537304"}, ErrMalformed, 60),
        ("exp bool", {"exp": True}, ErrMalformed, 60),
        ("negative skew", {"exp": JsonNumber("1748537184")}, ErrInvalidArgument, -1),
        ("exp is checked before nbf is read", {"exp": JsonNumber("1"), "nbf": "x"}, ErrExpired, 60),
        ("far-future exp", {"exp": JsonNumber("9223371974719177984")}, None, 60),
        ("far-future nbf", {"nbf": JsonNumber("9223371974719177984")}, ErrNotYetValid, 60),
        ("far-past exp", {"exp": JsonNumber("-9223372028741760000")}, ErrExpired, 60),
    ],
)
def test_check_exp_nbf(name, claims, err, skew):
    if err is None:
        check_exp_nbf(claims, NOW, skew)
    else:
        with pytest.raises(err):
            check_exp_nbf(claims, NOW, skew)


def test_check_exp_nbf_naive_now_is_utc():
    check_exp_nbf({"exp": JsonNumber("1748537304")}, NOW.replace(tzinfo=None), 0)


ME = "https://verifier.example"


@pytest.mark.parametrize(
    "name,aud,audience,err",
    [
        ("absent", ..., ME, None),
        ("string match", ME, ME, None),
        ("listed in an array", ["https://other.example", ME], ME, None),
        ("string differs", "https://other.example", ME, ErrAudience),
        ("empty array", [], ME, ErrAudience),
        ("no audience given", "", "", ErrAudience),
        ("array holding a number", [ME, JsonNumber("1")], ME, ErrMalformed),
        ("a number alone is not a string", JsonNumber("5"), "5", ErrMalformed),
        ("object", {}, ME, ErrMalformed),
        ("tuple, as Go []string is not a decoded array", (ME,), ME, ErrMalformed),
    ],
)
def test_check_aud(name, aud, audience, err):
    claims = {} if aud is ... else {"aud": aud}
    if err is None:
        check_aud(claims, audience)
    else:
        with pytest.raises(err):
            check_aud(claims, audience)
