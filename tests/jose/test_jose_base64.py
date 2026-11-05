"""Port of jose/base64_test.go."""

import pytest

from jose import ErrMalformed, decode_segment, encode_segment


@pytest.mark.parametrize("b", [b"", b"\x00", b"\xff\xfe", "héllo <&>".encode()])
def test_decode_segment_round_trip(b):
    assert decode_segment(encode_segment(b)) == b


def test_decode_segment_rejects_non_zero_trailing_bits():
    # "QQ" is the canonical encoding of "A"; "QR" differs only in trailing bits.
    assert decode_segment("QQ") == b"A"
    with pytest.raises(ErrMalformed):
        decode_segment("QR")


@pytest.mark.parametrize("s", ["QQ\n", "Q\nQ", "QQ\r", "\r\nQQ"])
def test_decode_segment_rejects_line_breaks(s):
    with pytest.raises(ErrMalformed):
        decode_segment(s)


@pytest.mark.parametrize("s", ["QQ==", "+/8", "ab/c", "Q", "QQQQQ", "é", "QQ "])
def test_decode_segment_rejects_padding_std_alphabet_and_bad_length(s):
    with pytest.raises(ErrMalformed):
        decode_segment(s)
