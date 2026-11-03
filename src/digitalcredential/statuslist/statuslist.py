from __future__ import annotations

import base64
import zlib

MAX_LIST_BYTES = 16 << 20


def valid_bits(bits: int) -> bool:
    return bits in (1, 2, 4, 8)


def b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class List:
    def __init__(self, bits: int, data: bytes) -> None:
        self._bits = bits
        self._b = bytearray(data)

    @classmethod
    def new(cls, size: int, bits: int) -> List:
        if not valid_bits(bits):
            raise ValueError(f"statuslist: bits {bits}, want 1, 2, 4 or 8")
        if size < 0 or size > MAX_LIST_BYTES * 8 // bits:
            raise ValueError(f"statuslist: size {size} out of range for {bits}-bit entries")
        return cls(bits, bytes((size * bits + 7) // 8))

    @classmethod
    def from_bytes(cls, data: bytes, bits: int) -> List:
        if not valid_bits(bits):
            raise ValueError(f"statuslist: bits {bits}, want 1, 2, 4 or 8")
        if len(data) > MAX_LIST_BYTES:
            raise ValueError(f"statuslist: {len(data)} bytes, want at most {MAX_LIST_BYTES}")
        return cls(bits, data)

    @classmethod
    def decode(cls, lst: str, bits: int) -> List:
        if not valid_bits(bits):
            raise ValueError(f"statuslist: bits {bits}, want 1, 2, 4 or 8")
        raw = b64url_decode(lst)
        return cls.from_bytes(_inflate_limited(raw), bits)

    def bits(self) -> int:
        return self._bits

    def entries(self) -> int:
        return len(self._b) * 8 // self._bits

    def bytes(self) -> bytes:
        return bytes(self._b)

    def get(self, i: int) -> int:
        at, shift = self._position(i)
        return (self._b[at] >> shift) & self._mask()

    def set(self, i: int, v: int) -> None:
        at, shift = self._position(i)
        if v > self._mask():
            raise ValueError(f"statuslist: value {v} does not fit in {self._bits} bits")
        self._b[at] = (self._b[at] & ~(self._mask() << shift)) | (v << shift)

    def encode(self) -> str:
        compressor = zlib.compressobj(level=zlib.Z_BEST_COMPRESSION, wbits=15)
        raw = compressor.compress(bytes(self._b)) + compressor.flush()
        return b64url_encode(raw)

    def _mask(self) -> int:
        return (1 << self._bits) - 1

    def _position(self, i: int) -> tuple[int, int]:
        n = self.entries()
        if i < 0 or i >= n:
            raise ValueError(f"statuslist: index {i} outside [0, {n})")
        per_byte = 8 // self._bits
        return i // per_byte, (i % per_byte) * self._bits


def _inflate_limited(raw: bytes) -> bytes:
    if len(raw) >= 2 and raw[1] & 0x20:
        raise ValueError("statuslist: lst uses a preset dictionary")
    decoder = zlib.decompressobj(wbits=15)
    try:
        out = decoder.decompress(raw, MAX_LIST_BYTES + 1)
    except zlib.error as exc:
        raise ValueError(f"statuslist: lst: {exc}") from exc
    if len(out) > MAX_LIST_BYTES:
        raise ValueError(f"statuslist: lst inflates past {MAX_LIST_BYTES} bytes")
    if decoder.unconsumed_tail:
        extra = decoder.decompress(decoder.unconsumed_tail, MAX_LIST_BYTES + 1 - len(out))
        out += extra
        if len(out) > MAX_LIST_BYTES:
            raise ValueError(f"statuslist: lst inflates past {MAX_LIST_BYTES} bytes")
    try:
        out += decoder.flush()
    except zlib.error as exc:
        raise ValueError(f"statuslist: lst: {exc}") from exc
    if len(out) > MAX_LIST_BYTES:
        raise ValueError(f"statuslist: lst inflates past {MAX_LIST_BYTES} bytes")
    return out


def bit_at(data: bytes, index: int) -> bool:
    return List.from_bytes(data, 1).get(index) == 1


def is_revoked(data: bytes, index: int) -> bool:
    return bit_at(data, index)


def encode_status_list(bits: list[bool]) -> bytes:
    lst = List.new(len(bits), 1)
    for i, flag in enumerate(bits):
        if flag:
            lst.set(i, 1)
    return lst.bytes()


def decode_status_list(encoded: bytes) -> bytes:
    return _inflate_limited(encoded)


def decode(lst: str, bits: int) -> List:
    return List.decode(lst, bits)
