from __future__ import annotations

from eth_keys import keys
from eth_utils import to_checksum_address

from didv2.hexutil import hex_to_bytes

MAX_ATTRIBUTE_NAME_LENGTH = 32
ATTRIBUTE_VALIDITY_SECONDS = 86400
ATTRIBUTE_NAME = "type"


def parse_private_key(key: str) -> keys.PrivateKey:
    raw = key[2:] if key.startswith("0x") else key
    if not raw or len(raw) % 2 != 0:
        raise ValueError("invalid private key: empty or odd length")
    try:
        return keys.PrivateKey(hex_to_bytes(key))
    except Exception as exc:
        raise ValueError(f"failed to parse private key: {exc}") from exc


def prepare_attribute_inputs(address: str, name: str, value: str) -> tuple[str, bytes, bytes, int]:
    if not address:
        raise ValueError("identity is empty")
    if not name:
        raise ValueError("name is empty")
    if len(name) > MAX_ATTRIBUTE_NAME_LENGTH:
        raise ValueError(f"name exceeds {MAX_ATTRIBUTE_NAME_LENGTH} bytes")

    did_address = to_checksum_address(address)
    name_bytes = name.encode("utf-8")
    if len(name_bytes) > 32:
        raise ValueError(f"name exceeds {MAX_ATTRIBUTE_NAME_LENGTH} bytes")
    name_padded = name_bytes.ljust(32, b"\x00")
    value_bytes = value.encode("utf-8")
    return did_address, name_padded, value_bytes, ATTRIBUTE_VALIDITY_SECONDS
