import re

from didv2.hexutil import with_0x

_HEX = re.compile(r"^(?:[0-9a-f]{2})*$")


def normalize_hash32(value: str) -> tuple[str, bytes]:
    """Go normalizeHash32: TrimSpace, lowercase, strip 0x, strict hex, exactly 32 bytes."""
    raw_hex = value.strip().lower().removeprefix("0x")
    if not _HEX.match(raw_hex):
        raise ValueError(f"invalid 32-byte hash {value!r}: invalid hex")
    raw = bytes.fromhex(raw_hex)
    if len(raw) != 32:
        raise ValueError(f"invalid 32-byte hash {value!r}: got {len(raw)} bytes")
    return with_0x(raw), raw


def hex_hash(raw: bytes) -> str:
    return with_0x(raw)
