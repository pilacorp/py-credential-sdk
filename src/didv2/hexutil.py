def normalize_hex(value: str) -> str:
    v = value[2:] if value.startswith(("0x", "0X")) else value
    if len(v) % 2:
        raise ValueError(f"hex string must be even length, got {len(v)}")
    return v.lower()


_HEX = frozenset("0123456789abcdef")


def hex_to_bytes(value: str) -> bytes:
    v = normalize_hex(value)
    # bytes.fromhex silently skips ASCII whitespace; Go's hex.DecodeString does not.
    if not _HEX.issuperset(v):
        raise ValueError("invalid hex string")
    return bytes.fromhex(v)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def with_0x(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if value.startswith(("0x", "0X")):
        return "0x" + value[2:].lower()
    return "0x" + value.lower()


def is_hex_address(value: str) -> bool:
    """go-ethereum common.IsHexAddress: 40 hex digits with an optional lowercase 0x prefix (no checksum)."""
    v = value[2:] if value.startswith(("0x", "0X")) else value
    return len(v) == 40 and _HEX.issuperset(v.lower())


def address_bytes(value: str) -> bytes:
    """common.HexToAddress for an already validated address."""
    return bytes.fromhex(value[2:] if value.startswith(("0x", "0X")) else value)
