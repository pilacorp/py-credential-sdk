from didv2.hexutil import hex_to_bytes, with_0x


def normalize_hash32(value: str) -> tuple[str, bytes]:
    raw = hex_to_bytes(value.strip())
    if len(raw) != 32:
        raise ValueError(f"invalid 32-byte hash {value!r}: got {len(raw)} bytes")
    return with_0x(raw), raw


def hex_hash(raw: bytes) -> str:
    return with_0x(raw)
