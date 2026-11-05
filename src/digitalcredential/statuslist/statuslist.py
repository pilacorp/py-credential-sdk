"""The Status List and the Status List Token of Token Status List, draft-ietf-oauth-status-list-21:
the byte array and its encoding (§4.1, §4.2), status values (§7), signing the token (§5.1) and
reading the status of a Referenced Token (checker, §8).

Malformed input to `decode` raises jose.ErrMalformed (the cause, e.g. zlib.error, in __cause__); a
caller mistake (an index or value out of range, a list not made by this package, missing claims) is
jose.ErrInvalidArgument. A List is not safe for concurrent use while `set` runs.
"""

from __future__ import annotations

import zlib

from jose import base64 as jose_b64
from jose.errors import ErrInvalidArgument, ErrMalformed

# Caps the byte array of a list. New and from_bytes refuse a larger one, which bounds what they
# allocate and what encode and issue_token compress and sign; decode refuses to inflate past it.
# Draft 21 sets no limit (§13.4); zeros compress about 1000:1.
MAX_LIST_BYTES = 16 << 20


def valid_bits(bits: int) -> bool:
    """Draft 21 §4.1 step 1: bits is 1, 2, 4 or 8, so an entry never spans two bytes."""
    return isinstance(bits, int) and not isinstance(bits, bool) and bits in (1, 2, 4, 8)


class List:
    """A Status List (§4.1): entries of `bits` bits each, len*8/bits of them, packed into bytes. Make
    one with new, from_bytes or decode."""

    def __init__(self, bits: int = 0, data: bytes = b"") -> None:
        self._bits = bits
        self._b = bytearray(data)

    @classmethod
    def new(cls, size: int, bits: int) -> "List":
        """At least `size` entries of `bits` bits each, all 0 (VALID, §7.1); the byte array is
        ceil(size*bits/8) bytes (§4.1 step 2). size may be 0. bits must be 1, 2, 4 or 8, and the byte
        array at most 16 MiB."""
        if not valid_bits(bits):
            raise ErrInvalidArgument(f"statuslist: bits {bits}, want 1, 2, 4 or 8")
        if size < 0 or size > MAX_LIST_BYTES * 8 // bits:
            raise ErrInvalidArgument(f"statuslist: size {size} out of range for {bits}-bit entries")
        return cls(bits, bytes((size * bits + 7) // 8))

    @classmethod
    def from_bytes(cls, data: bytes, bits: int) -> "List":
        """A list over a copy of data, a byte array kept elsewhere; it holds len*8/bits entries."""
        if not valid_bits(bits):
            raise ErrInvalidArgument(f"statuslist: bits {bits}, want 1, 2, 4 or 8")
        if len(data) > MAX_LIST_BYTES:
            raise ErrInvalidArgument(f"statuslist: {len(data)} bytes, want at most {MAX_LIST_BYTES}")
        return cls(bits, bytes(data))

    @classmethod
    def decode(cls, lst: str, bits: int) -> "List":
        return decode(lst, bits)

    def valid(self) -> bool:
        return self._bits != 0

    def bits(self) -> int:
        return self._bits

    def entries(self) -> int:
        return len(self._b) * 8 // self._bits if self._bits else 0

    def bytes(self) -> bytes:
        """A copy of the uncompressed byte array; empty for the zero List."""
        return bytes(self._b)

    def get(self, i: int) -> int:
        """The status value of entry i (§7). An index outside the list is an error."""
        at, shift = self._position(i)
        return (self._b[at] >> shift) & self._mask()

    def set(self, i: int, v: int) -> None:
        """Write status value v for entry i. v must fit in the list's bits."""
        at, shift = self._position(i)
        if not (isinstance(v, int) and 0 <= v <= self._mask()):
            raise ErrInvalidArgument(f"statuslist: value {v} does not fit in {self._bits} bits")
        self._b[at] = (self._b[at] & ~(self._mask() << shift) & 0xFF) | (v << shift)

    def encode(self) -> str:
        """The lst of the list: its byte array compressed with DEFLATE at the best level in the ZLIB
        format (§4.1 step 4), then base64url (§4.2)."""
        if not self.valid():
            raise ErrInvalidArgument("statuslist: list not made by New, FromBytes or Decode")
        c = zlib.compressobj(level=zlib.Z_BEST_COMPRESSION, wbits=15)
        return jose_b64.encode_segment(c.compress(bytes(self._b)) + c.flush())

    def _mask(self) -> int:
        return (1 << self._bits) - 1

    def _position(self, i: int) -> tuple[int, int]:
        # Draft 21 §4.1 step 3 and §11.1: entries are packed from the least significant bit of each
        # byte, and bytes follow in their natural order.
        if not self.valid():
            raise ErrInvalidArgument("statuslist: list not made by New, FromBytes or Decode")
        n = self.entries()
        if not isinstance(i, int) or i < 0 or i >= n:
            raise ErrInvalidArgument(f"statuslist: index {i} outside [0, {n})")
        per_byte = 8 // self._bits
        return i // per_byte, (i % per_byte) * self._bits


def decode(lst: str, bits: int) -> List:
    """Read lst, the lst member of a Status List (§4.2), as a list of `bits`-bit entries. Refuses with
    jose.ErrMalformed: bits other than 1, 2, 4 or 8; an lst that is not strict base64url; a ZLIB stream
    with a bad header or Adler-32, cut short or that does not inflate (zlib.error in __cause__); a
    stream with a preset dictionary (RFC 1950 §2.3); a byte array over 16 MiB (bounded while
    inflating). An empty byte array is a list with no entries. Data after the stream is ignored."""
    if not valid_bits(bits):
        raise ErrMalformed(f"statuslist: bits {bits}, want 1, 2, 4 or 8")
    try:
        raw = jose_b64.decode_segment(lst)
    except ErrMalformed as e:
        raise ErrMalformed(f"statuslist: lst: {e}") from e
    # RFC 1950 §2.2: FDICT is bit 5 of FLG, the second byte.
    if len(raw) >= 2 and raw[1] & 0x20:
        raise ErrMalformed("statuslist: lst uses a preset dictionary")
    d = zlib.decompressobj(wbits=15)
    out = bytearray()
    try:
        data = raw
        while True:
            chunk = d.decompress(data, MAX_LIST_BYTES + 1 - len(out))
            out += chunk
            if len(out) > MAX_LIST_BYTES:
                raise ErrMalformed(f"statuslist: lst inflates past {MAX_LIST_BYTES} bytes")
            data = d.unconsumed_tail
            if d.eof or not data:
                break
    except zlib.error as e:
        raise ErrMalformed(f"statuslist: lst: {e}") from e
    if not d.eof:  # input ended before the stream did (io.ErrUnexpectedEOF)
        raise ErrMalformed("statuslist: lst: unexpected EOF") from EOFError("unexpected EOF")
    return List(bits, bytes(out))


# Legacy helpers over a 1-bit byte array.
def bit_at(data: bytes, index: int) -> bool:
    return List.from_bytes(data, 1).get(index) == 1


def is_revoked(data: bytes, index: int) -> bool:
    return bit_at(data, index)


def encode_status_list(bits: "list[bool]") -> bytes:
    lst = List.new(len(bits), 1)
    for i, flag in enumerate(bits):
        if flag:
            lst.set(i, 1)
    return lst.bytes()


def decode_status_list(encoded: bytes) -> bytes:
    d = zlib.decompressobj(wbits=15)
    out = d.decompress(encoded, MAX_LIST_BYTES + 1)
    if len(out) > MAX_LIST_BYTES:
        raise ErrMalformed(f"statuslist: lst inflates past {MAX_LIST_BYTES} bytes")
    return out
