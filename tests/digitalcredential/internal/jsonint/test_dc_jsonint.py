import pytest

from digitalcredential.internal import jsonint


@pytest.mark.parametrize("n,want", [("7", 7), ("7.0", 7), ("7e0", 7), ("70e-1", 7), ("0", 0), ("-0", 0), ("0.0e9", 0),
                                    ("1e3", 1000), ("12.50e1", 125), ("9223372036854775807", 2**63 - 1), ("100e-2", 1)])
def test_value(n, want):
    assert jsonint.non_negative(n) == want


@pytest.mark.parametrize("n", ["-1", "1.5", "01", "", "+1", ".5", "1.", "1e", "1e+", "0x10", "7 ", " 7", "1e-1", "NaN", "-1.0"])
def test_not_integer(n):
    with pytest.raises(jsonint.ErrNotInteger):
        jsonint.non_negative(n)


@pytest.mark.parametrize("n", ["9223372036854775808", "1e19", "1e1000000000000", "99999999999999999999"])
def test_too_large(n):
    with pytest.raises(jsonint.ErrTooLarge):
        jsonint.non_negative(n)
