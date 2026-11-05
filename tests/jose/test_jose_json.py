"""Port of jose/json_test.go (plus float/escape cases of EncodeJSON)."""

import pytest

from jose import (
    MAX_JSON_DEPTH,
    ErrInvalidArgument,
    ErrMalformed,
    JsonNumber,
    decode_json,
    decode_json_object,
    decode_json_string_member,
    encode_json,
)


@pytest.mark.parametrize(
    "data",
    [
        '{"_sd":["a"],"_sd":["b"]}',  # top level
        '{"a":{"x":1,"x":2}}',  # nested object
        '{"a":[{"x":1,"x":2}]}',  # inside an array
        '{"a":1,"\\u0061":2}',  # escaped spelling
    ],
)
def test_decode_json_rejects_duplicate_keys(data):
    with pytest.raises(ErrMalformed):
        decode_json(data.encode())


@pytest.mark.parametrize("data", ['{"iss":"a","x":1,"iss":"b"}', '{"iss":"a","\\u0069ss":"b"}'])
def test_decode_json_string_member_rejects_duplicates(data):
    with pytest.raises(ErrMalformed):
        decode_json_string_member(data.encode(), "iss")


@pytest.mark.parametrize(
    "data",
    [
        '{"a":"\\"},\\"iss\\":\\"b","iss":"a"}',
        '{"a":{"iss":"b"},"iss":"a"}',
        '{"a":["]}",{"iss":"b"}],"iss":"a"}',
        ' { "i\\u0073s" : "a" } ',
    ],
)
def test_decode_json_string_member_reads_top_level_json_only(data):
    assert decode_json_string_member(data.encode(), "iss") == ("a", True)


@pytest.mark.parametrize("data", ['{"iss":"a"', '{"iss":"a",}', '{"iss":"a"} x', '["iss","a"]', '{"iss":NaN}', '{"iss":01}', ""])
def test_decode_json_string_member_refuses_non_json(data):
    with pytest.raises(ErrMalformed):
        decode_json_string_member(data.encode(), "iss")


def test_decode_json_string_member_absent_and_non_string():
    assert decode_json_string_member(b'{"a":1}', "iss") == ("", False)
    for data in (b'{"iss":1}', b'{"iss":[1]}', b'{"iss":{"a":1}}', b'{"iss":null}', b'{"iss":true}'):
        with pytest.raises(ErrMalformed):
            decode_json_string_member(data, "iss")


def test_decode_json_string_member_builds_nothing_else():
    # A 1 MiB payload holding 2^19 zeros or 2^17 members: only the member asked for is built.
    with pytest.raises(ErrMalformed):
        decode_json_string_member(b'{"iss":[' + b"0," * (1 << 19) + b"0]}", "iss")
    big = b'{"iss":"x"' + b',"":0' * (1 << 17) + b"}"
    assert decode_json_string_member(big, "iss") == ("x", True)


@pytest.mark.parametrize("data", ['{"a":1}xyz', '{"a":1}{"b":2}', '{"a":1} 1'])
def test_decode_json_rejects_trailing_data(data):
    with pytest.raises(ErrMalformed):
        decode_json(data.encode())
    assert decode_json(b'{"a":1} \n') == {"a": JsonNumber("1")}


def test_decode_json_keeps_numbers():
    v = decode_json_object(b'{"n":12345678901234567890123,"f":1.50,"e":-0E+2}')
    assert v["n"] == JsonNumber("12345678901234567890123")
    assert str(v["f"]) == "1.50" and str(v["e"]) == "-0E+2"
    # A number is never a str: it must not pass an isinstance(x, str) check.
    assert not isinstance(v["n"], str)


@pytest.mark.parametrize("data", ["NaN", "Infinity", "-Infinity", "01", "1.", ".5", "+1", "-", "1e", "tru", "[1,]", "[,1]", "{'a':1}", "\x0b1"])
def test_decode_json_rejects_non_rfc8259(data):
    with pytest.raises(ErrMalformed):
        decode_json(data.encode())


def test_decode_json_strings():
    assert decode_json(b'"a\\u00e9\\n\\/"') == "aé\n/"
    assert decode_json(b'"\\ud83d\\ude00"') == "\U0001f600"
    # An unpaired surrogate escape reads as U+FFFD (encoding/json), so these two keys collide.
    assert decode_json(b'"\\ud800"') == "�"
    with pytest.raises(ErrMalformed):
        decode_json(b'{"\\ud800":1,"\\ufffd":2}')
    for bad in (b'"\x01"', b'"\\x"', b'"\\u12"', b'"abc'):
        with pytest.raises(ErrMalformed):
            decode_json(bad)


def test_decode_json_rejects_invalid_utf8():
    with pytest.raises(ErrMalformed):
        decode_json(b'{"a":"\xff"}')


@pytest.mark.parametrize("data", ["[1]", '"x"', "1", ""])
def test_decode_json_object_rejects_non_object(data):
    with pytest.raises(ErrMalformed):
        decode_json_object(data.encode())


def test_decode_json_empty_array_is_a_list():
    assert decode_json_object(b'{"a":[]}')["a"] == []


def test_encode_json_no_html_escaping_no_newline():
    assert encode_json({"b": "<a&b>", "a": "Nguyễn"}) == '{"a":"Nguyễn","b":"<a&b>"}'.encode()


def test_encode_json_escapes_like_go():
    assert encode_json("  \x01\x1f\n\r\t\b\f\"\\\x7f") == b'"\\u2028\\u2029\\u0001\\u001f\\n\\r\\t\\b\\f\\"\\\\\x7f"'
    assert encode_json("\ud800") == b'"\\ufffd"'
    assert encode_json({"z": [1, 2.5, True, None], "a": JsonNumber("1.50")}) == b'{"a":1.50,"z":[1,2.5,true,null]}'
    assert encode_json([0.0, 1e21, 1e-7, 123456789012345678901.0, 100.0, 0.000001]) == b"[0,1e+21,1e-7,123456789012345680000,100,0.000001]"


def test_decode_json_caps_nesting():
    def nested(n, op, cl):
        return (op * n + "1" + cl * n).encode()

    for data in (nested(MAX_JSON_DEPTH, "[", "]"), nested(MAX_JSON_DEPTH, '{"a":', "}")):
        decode_json(data)  # at the limit
    for data in (nested(MAX_JSON_DEPTH + 1, "[", "]"), nested(MAX_JSON_DEPTH + 1, '{"a":', "}"), b"[" * (1 << 20)):
        with pytest.raises(ErrMalformed, match="nesting deeper"):
            decode_json(data)


@pytest.mark.parametrize("v", [lambda: None, float("nan"), float("inf"), object(), {1: 2}, {"a": b"x"}, JsonNumber("1e")])
def test_encode_json_rejects_unencodable(v):
    with pytest.raises(ErrInvalidArgument):
        encode_json(v)
