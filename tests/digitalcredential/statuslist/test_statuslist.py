from digitalcredential.statuslist import (
    List,
    bit_at,
    decode_status_list,
    encode_status_list,
    is_revoked,
)


def test_draft21_bits1() -> None:
    lst = "eNrbuRgAAhcBXQ"
    want = bytes([0xB9, 0xA3])
    status = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]
    decoded = List.decode(lst, 1)
    assert decoded.bytes() == want
    for i, v in enumerate(status):
        assert decoded.get(i) == v
    rebuilt = List.from_bytes(want, 1)
    back = List.decode(rebuilt.encode(), 1)
    assert back.bytes() == want


def test_draft21_bits2() -> None:
    lst = "eNo76fITAAPfAgc"
    want = bytes([0xC9, 0x44, 0xF9])
    status = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3]
    decoded = List.decode(lst, 2)
    assert decoded.bytes() == want
    for i, v in enumerate(status):
        assert decoded.get(i) == v


def test_lsb_helpers() -> None:
    data = encode_status_list([True, False, False, True])
    assert bit_at(data, 0) is True
    assert is_revoked(data, 1) is False
    assert is_revoked(data, 3) is True


def test_decode_rejects_bad_zlib() -> None:
    try:
        decode_status_list(b"not-zlib")
        raise AssertionError("expected error")
    except ValueError:
        pass
