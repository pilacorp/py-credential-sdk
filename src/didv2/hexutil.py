def normalize_hex(value: str) -> str:
    v = value[2:] if value.startswith(("0x", "0X")) else value
    if len(v) % 2:
        raise ValueError(f"hex string must be even length, got {len(v)}")
    return v.lower()


def hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex(normalize_hex(value))


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def with_0x(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if value.startswith(("0x", "0X")):
        return "0x" + value[2:].lower()
    return "0x" + value.lower()
