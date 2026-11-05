"""errtext.quote (Go internal/errtext) and errors.wrap."""

from jose.errors import ErrMalformed, ErrUnsupportedKey, wrap
from jose.internal.errtext import quote


def test_quote_matches_strconv_quote_and_cuts_at_32_bytes():
    assert quote("abc") == '"abc"'
    assert quote('a"b\\c\n\x00é') == '"a\\"b\\\\c\\n\\x00é"'
    assert quote("x" * 32) == '"' + "x" * 32 + '"'
    assert quote("x" * 33) == '"' + "x" * 32 + '"...'
    # cut at a rune boundary: 31 ASCII bytes + a 2-byte rune straddling the limit
    assert quote("x" * 31 + "é") == '"' + "x" * 31 + '"...'
    assert quote("\ud800") == '"\\ufffd"'


def test_wrap_matches_both_classes():
    cause = ErrUnsupportedKey("k")
    e = wrap(ErrMalformed, cause, "outer")
    assert isinstance(e, ErrMalformed) and isinstance(e, ErrUnsupportedKey) and e.__cause__ is cause and str(e) == "outer"
    assert isinstance(wrap(ErrMalformed, ValueError("v")), ValueError)
