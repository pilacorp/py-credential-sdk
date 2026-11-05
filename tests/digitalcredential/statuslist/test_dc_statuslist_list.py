import base64
import pathlib
import re
import struct
import tracemalloc
import zlib

import pytest

from digitalcredential import statuslist as sl
from jose.errors import ErrInvalidArgument, ErrMalformed

HERE = pathlib.Path(__file__).parent


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def deflate(b):
    return zlib.compress(b)


# The examples of draft-ietf-oauth-status-list-21 §4.1 and §4.2.
@pytest.mark.parametrize("bits,lst,data,status", [
    (1, "eNrbuRgAAhcBXQ", bytes([0xB9, 0xA3]), [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]),
    (2, "eNo76fITAAPfAgc", bytes([0xC9, 0x44, 0xF9]), [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3]),
])
def test_draft21_section42_examples(bits, lst, data, status):
    l = sl.decode(lst, bits)
    assert l.bytes() == data
    for i, want in enumerate(status):
        assert l.get(i) == want
    back = sl.decode(sl.List.from_bytes(data, bits).encode(), bits)
    assert back.bytes() == data


# Entry 917 set to the largest value and then to 1, located by hand from draft 21 §4.1 step 3.
@pytest.mark.parametrize("bits,byte_index,byte_value", [(1, 114, 0b0010_0000), (2, 229, 0b0000_0100), (4, 458, 0b0001_0000), (8, 917, 1)])
def test_draft21_section41_index917(bits, byte_index, byte_value):
    l = sl.List.new(1024, bits)
    l.set(917, (1 << bits) - 1)
    l.set(917, 1)
    want = bytearray(1024 * bits // 8)
    want[byte_index] = byte_value
    assert l.bytes() == bytes(want)
    assert (l.get(916), l.get(917), l.get(918)) == (0, 1, 0)


C1 = ("eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogE" + "AAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAA" "A7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAA" "ACAZC8L2AEb")
C2 = ("eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGV" "IAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9S"
      "wIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw")
C3 = ("eNrt0EENgDAQADAIHwImkIIEJEwCUpCEBBQRHOy35Li" "1EjoOQGabAgAAAAAAAAAAAAAAAAAAACC1SQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADrsCAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAADoxaEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIIoCgAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACArpwKAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAGhqVkAzlwIAAAAAiGVRAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAABx3AoAgLpVAQAAAAAAAAAAAAAAwM89rwMAAAAAAAAAA"
      "AjsA9xMBMA")


def c4():
    status, lst = {}, ""
    for line in (HERE / "draft21-appendix-c4.txt").read_text().strip().split("\n"):
        if line.startswith("#"):
            continue
        m = re.match(r"status\[(\d+)\] = 0b([01]+)$", line)
        if m:
            status[int(m[1])] = int(m[2], 2)
        else:
            lst += line
    assert len(status) == 256
    return status, lst


# The test vectors of draft 21 Appendix C: 2^20 entries, each listed entry with its value, every other 0.
@pytest.mark.parametrize("name,bits", [("C.1", 1), ("C.2", 2), ("C.3", 4), ("C.4", 8)])
def test_draft21_appendix_c(name, bits):
    vectors = {
        "C.1": ({0: 1, 1993: 1, 25460: 1, 159495: 1, 495669: 1, 554353: 1, 645645: 1, 723232: 1, 854545: 1, 934534: 1, 1000345: 1}, C1),
        "C.2": ({0: 1, 1993: 2, 25460: 1, 159495: 3, 495669: 1, 554353: 1, 645645: 2, 723232: 1, 854545: 1, 934534: 2, 1000345: 3}, C2),
        "C.3": ({0: 1, 1993: 2, 35460: 3, 459495: 4, 595669: 5, 754353: 6, 845645: 7, 923232: 8, 924445: 9, 934534: 10, 1004534: 11,
                 1000345: 12, 1030203: 13, 1030204: 14, 1030205: 15}, C3),
        "C.4": c4(),
    }
    status, lst = vectors[name]
    l = sl.decode(lst, bits)
    assert len(l.bytes()) == (1 << 20) * bits // 8
    want = sl.List.new(1 << 20, bits)
    for i, v in status.items():
        want.set(i, v)
        assert l.get(i) == v
    assert l.bytes() == want.bytes()  # every other entry is 0
    back = sl.decode(l.encode(), bits)
    assert back.bytes() == l.bytes()


def test_decode_rejects():
    draft = bytes.fromhex("78dadbb918000217015d")
    bad_adler = bytearray(draft)
    bad_adler[-1] ^= 1
    cases = [
        ("bad header", bytes.fromhex("0000"), zlib.error),
        ("preset dictionary", bytes.fromhex("78f900000001dab918100000ffff0217015d"), None),
        ("bad Adler-32", bytes(bad_adler), zlib.error),
        ("cut short", draft[:-3], None),
        ("empty", b"", None),
        ("inflates past 16 MiB", deflate(bytes(16 << 20 + 1)), None),
    ]
    for name, raw, cause in cases:
        with pytest.raises(ErrMalformed) as ei:
            sl.decode(b64(raw), 1)
        if cause:
            assert isinstance(ei.value.__cause__, cause), name
    l = sl.decode(b64(deflate(bytes(16 << 20))), 1)
    assert len(l.bytes()) == 16 << 20
    # not strict base64url, and a bad bits
    for lst in ("eNrb+RgAAhcBXQ", "eNrbuRgAAhcBXQ==", "eNrbuRgAAhc BXQ"):
        with pytest.raises(ErrMalformed):
            sl.decode(lst, 1)
    for bits in (0, 3, 16, -1):
        with pytest.raises(ErrMalformed):
            sl.decode("eNrbuRgAAhcBXQ", bits)
    # data after the ZLIB stream is ignored (RFC 1950 §2.2); an empty array holds no entries
    assert sl.decode(b64(draft + b"trailing"), 1).bytes() == bytes([0xB9, 0xA3])
    assert sl.decode(b64(deflate(b"")), 1).entries() == 0


def test_decode_inflate_budget():
    # A 1 GiB inflate bomb (~7.3 MiB of ZLIB) must be cut at the 16 MiB cap while inflating, not after.
    reps = (1 << 30) // 1548 + 1
    n = 1 + 1548 * reps
    raw = bytes([0x78, 0x01, 0x00, 0x01, 0x00, 0xFE, 0xFF, 0x00]) + bytes.fromhex("1a05a360148c8251300a00") * reps
    raw += bytes([0x01, 0x00, 0x00, 0xFF, 0xFF]) + struct.pack(">I", ((n % 65521) << 16) | 1)
    tracemalloc.start()
    try:
        with pytest.raises(ErrMalformed, match="inflates past"):
            sl.decode(b64(raw), 1)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 512 << 20


def test_new_and_from_bytes_limits():
    for bits in (0, 3, 9):
        with pytest.raises(ErrInvalidArgument):
            sl.List.new(8, bits)
    with pytest.raises(ErrInvalidArgument):
        sl.List.new(-1, 1)
    with pytest.raises(ErrInvalidArgument):
        sl.List.new((16 << 20) * 8 + 1, 1)
    assert sl.List.new(0, 1).entries() == 0 and sl.List.new(9, 1).entries() == 16
    with pytest.raises(ErrInvalidArgument):
        sl.List.from_bytes(bytes((16 << 20) + 1), 1)
    l = sl.List.new(8, 2)
    for i in (-1, 8):
        with pytest.raises(ErrInvalidArgument):
            l.get(i)
    with pytest.raises(ErrInvalidArgument):
        l.set(0, 4)
    with pytest.raises(ErrInvalidArgument):
        l.set(0, -1)
    with pytest.raises(ErrInvalidArgument):
        sl.List().get(0)  # the zero List
    with pytest.raises(ErrInvalidArgument):
        sl.List().encode()
    data = bytearray(b"\x01")
    l = sl.List.from_bytes(data, 1)
    data[0] = 0
    assert l.get(0) == 1  # a copy
