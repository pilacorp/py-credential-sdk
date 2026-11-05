"""Port of go-credential-sdk/credential/common/sdjwt/helper_test.go."""
import base64
import json

import pytest

from credential.common.sdjwt import (
    build_sd_jwt_presentation,
    carries_sd_machinery,
    hash_disclosure,
    is_sd_jwt,
    parse,
    parse_disclosure,
)
from credential.common.sdjwt.disclosure import _append_sd
from credential.common.sdjwt.helper import b64url_decode


def enc(arr) -> str:
    return base64.urlsafe_b64encode(json.dumps(arr, separators=(",", ":")).encode()).decode().rstrip("=")


def test_parse_disclosure_valid_object_field():
    info = parse_disclosure(enc(["salt-1", "name", "Alice"]))
    assert info.salt == "salt-1" and info.object_field == "name"
    assert not info.is_array_elem and info.value == "Alice"


def test_parse_disclosure_valid_array_element():
    info = parse_disclosure(enc(["salt-2", 42.0]))
    assert info.is_array_elem and info.object_field == ""


@pytest.mark.parametrize(
    "disc,want",
    [
        ("not-base64@", "failed to decode disclosure"),
        (base64.urlsafe_b64encode(b"{").decode().rstrip("="), "failed to unmarshal disclosure"),
        (enc(["only-one"]), "invalid disclosure structure"),
        (enc([1.0, "name", "Alice"]), "salt must be a string"),
        (enc(["salt", 1.0, "Alice"]), "field name must be a string"),
        # beyond Go's table: a JSON object / NaN are not disclosures either
        (enc({"a": 1}), "disclosure"),
        (base64.urlsafe_b64encode(b'["s","n",NaN]').decode().rstrip("="), "failed to unmarshal disclosure"),
    ],
)
def test_parse_disclosure_invalid_shapes(disc, want):
    with pytest.raises(ValueError, match=want):
        parse_disclosure(disc)


def test_hash_disclosure_unsupported_algorithm():
    with pytest.raises(ValueError, match="unsupported sd_alg"):
        hash_disclosure("sha-999", "abc")


def test_build_presentation_skip_empty_disclosure():
    assert build_sd_jwt_presentation("a.b.c", ["d1", "", "d2"]) == "a.b.c~d1~d2~"


def test_is_sd_jwt():
    jwt = "aaa.bbb.ccc"
    assert not is_sd_jwt("")
    assert not is_sd_jwt(jwt)
    assert is_sd_jwt(jwt + "~D1~D2~")
    assert not is_sd_jwt("not-a-jwt~something~")
    # Go trims quotes before whitespace; a trailing newline must not slip past the regex
    assert is_sd_jwt('"' + jwt + '~D1~"')
    assert not is_sd_jwt("aa a.bbb.ccc~D1~") and not is_sd_jwt("aaa.bbb.ccc.ddd~D1~")


def test_parse_sdjwt():
    jwt = "aaa.bbb.ccc"
    d1 = enc(["salt1", "name", "Alice"])
    d2 = enc(["salt2", "age", 30.0])
    parsed = parse(jwt + "~" + d1 + "~" + d2 + "~")
    assert parsed.base_jwt == jwt
    assert parsed.disclosures == [d1, d2]
    assert len(parsed.decoded_disclosures) == 2
    assert parsed.decoded_disclosures[0].field_name == "name"


def test_create_presentation():
    j = "header.payload.sig"
    assert build_sd_jwt_presentation(j, ["D1", "D2", "D3"]) == "header.payload.sig~D1~D2~D3~"
    assert build_sd_jwt_presentation(j, ["D1", "D3"]) == "header.payload.sig~D1~D3~"
    # nothing revealed is still an SD-JWT: terminated with "~"
    assert build_sd_jwt_presentation(j, None) == "header.payload.sig~"
    assert build_sd_jwt_presentation(j, ["", "D1", ""]) == "header.payload.sig~D1~"


def test_presentation():
    d1 = enc(["salt1", "firstname", "John"])
    d2 = enc(["salt2", "lastname", "Doe"])
    parsed = parse("aaa.bbb.ccc~" + d1 + "~" + d2 + "~")
    assert parsed.base_jwt == "aaa.bbb.ccc" and parsed.disclosures == [d1, d2]
    assert build_sd_jwt_presentation(parsed.base_jwt, [d1]) == "aaa.bbb.ccc~" + d1 + "~"


def test_parse_last_segment_jwt_like():
    d = enc(["salt", "sub", "123"])
    parsed = parse("aaa.bbb.ccc~" + d)
    assert parsed.base_jwt == "aaa.bbb.ccc" and d in parsed.disclosures


def test_parse_with_holder_binding_jwt():
    j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    d = enc(["salt", "name", "Alice"])
    parsed = parse(j + "~" + d + "~")
    assert parsed.base_jwt == j and parsed.disclosures == [d]
    # a real key-binding JWT after the disclosures is refused (not verified by this SDK)
    with pytest.raises(ValueError, match="key binding JWT"):
        parse(j + "~" + d + "~" + "aaa.bbb.ccc")


def test_parse_empty_disclosure_strings():
    parsed = parse("aaa.bbb.ccc~~~")
    assert parsed.base_jwt == "aaa.bbb.ccc" and parsed.disclosures == []


def test_append_sd_invalid_type():
    m = {"_sd": 123}
    _append_sd(m, "some-digest")
    assert m["_sd"] == 123


def test_append_sd_existing_list_and_missing():
    m = {"_sd": ["existing-hash"]}
    _append_sd(m, "new-hash")
    assert m["_sd"] == ["existing-hash", "new-hash"]
    m2 = {}
    _append_sd(m2, "x")
    assert m2["_sd"] == ["x"]


def test_b64url_decode_is_strict():
    assert b64url_decode("aGk") == b"hi"
    for bad in ("aGk=", "aG k", "aGk\n", "a", "aGk+", "aG/k", "é"):
        with pytest.raises(ValueError):
            b64url_decode(bad)


def test_carries_sd_machinery():
    assert carries_sd_machinery({"a": {"_sd": []}})
    assert carries_sd_machinery({"a": [{"...": "h"}]})
    assert carries_sd_machinery({"a": [[{"...": "h"}]]})
    assert not carries_sd_machinery({"a": [{"...": "h", "x": 1}], "b": "c"})
