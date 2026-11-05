import pytest

from digitalcredential.internal.httpcache import freshness

H24 = 24 * 3600.0


@pytest.mark.parametrize(
    "name,cc,vary,age,want",
    [
        ("no-store", "max-age=600, no-store", "", "", 0),
        ("no-cache", "no-cache, max-age=600", "", "", 0),
        ("Vary not set by the caller", "max-age=600", "Accept, Cookie", "", 0),
        ("Age 100", "max-age=600", "", "100", 500),
        ("Age = max-age", "max-age=600", "", "600", 0),
        ("over 24 h", "max-age=9223372037", "", "", H24),
        ("quoted max-age", 'x-ext=", max-age=86400, "', "", "", 0),
        ("Vary Accept ok", "max-age=60", "Accept, Accept-Encoding", "", 60),
        ("Vary star", "max-age=60", "*", "", 0),
        ("no max-age", "public", "", "", 0),
        ("bare max-age", "max-age", "", "", 0),
        ("signed max-age", "max-age=+60", "", "", 0),
        ("max-age twice", "max-age=60, max-age=60", "", "", 0),
        ("invalid Age ignored", "max-age=60", "", "-5", 60),
        ("Age list uses the first", "max-age=600", "", "100, 400", 500),
    ],
)
def test_freshness(name, cc, vary, age, want):
    h = {"Cache-Control": cc}
    if vary:
        h["Vary"] = vary
    if age:
        h["Age"] = age
    assert freshness(h, H24) == want, name
