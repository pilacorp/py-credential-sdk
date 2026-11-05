import base64
import hashlib

import pytest

from digitalcredential.internal import sri


def b64(h):
    return base64.b64encode(h).decode()


DATA = b'{"vct":"https://example.com/t"}'
S256 = "sha256-" + b64(hashlib.sha256(DATA).digest())
S384 = "sha384-" + b64(hashlib.sha384(DATA).digest())
S512 = "sha512-" + b64(hashlib.sha512(DATA).digest())


@pytest.mark.parametrize("integrity", [S256, S384, S512, S256 + " " + S384 + " " + S512,
                                       "  " + S256 + "\t\n", S256 + "?opt=1", "sha256-AAAA " + S512, "SHA512-" + S512[7:]])
def test_matches(integrity):
    # the strongest algorithm decides: "sha256-AAAA " + S512 passes on the sha512 token alone
    sri.check(DATA, integrity)


def test_strongest_wins():
    with pytest.raises(ValueError, match="sha512"):
        sri.check(DATA, S256 + " sha512-" + b64(b"x" * 64))


@pytest.mark.parametrize("integrity", ["", "   ", " "])
def test_empty_is_refused_by_check_but_well_formed_where_it_has_no_token(integrity):
    if integrity.strip(" ") == "":
        with pytest.raises(ValueError, match="no sha256"):
            sri.check(DATA, integrity)
    else:  # NBSP is not ASCII whitespace: a token, and a malformed one
        assert not sri.well_formed(integrity)


@pytest.mark.parametrize("integrity", [
    "md5-AAAA", "sha256", "sha256-", "sha256-=", "sha256-A===", "sha256-@@@@", "sha256-AAAA?\x01", "sha256-AAAA?a b",
    "sha1-AAAA", "ſha256-AAAA", "sha256 -AAAA", S256 + " " + S384, "sha256-AAAA sha256-BBBB",
])
def test_malformed(integrity):
    assert not sri.well_formed(integrity)
    with pytest.raises(ValueError, match="not well formed"):
        sri.check(DATA, integrity)


def test_undecodable_token_matches_nothing():
    # one char after trimming: not a valid base64 length, but a well-formed token
    assert sri.well_formed("sha256-A")
    with pytest.raises(ValueError, match="does not match"):
        sri.check(DATA, "sha256-A")


def test_padding_variants_decode_alike():
    d = hashlib.sha256(DATA).digest()
    sri.check(DATA, "sha256-" + b64(d).rstrip("="))
