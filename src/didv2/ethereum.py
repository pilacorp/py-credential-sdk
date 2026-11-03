from eth_keys import keys

from didv2.hexutil import hex_to_bytes, with_0x
from didv2.keccak import keccak256


def address_from_public_key_hex(public_key_hex: str) -> str:
    raw = hex_to_bytes(public_key_hex)
    pub = keys.PublicKey.from_compressed_bytes(raw) if len(raw) == 33 else keys.PublicKey.from_bytes(raw[1:] if len(raw) == 65 else raw)
    return with_0x(bytes(pub.to_canonical_address()))


def eip191_hash(message: bytes) -> bytes:
    prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode("utf-8")
    return keccak256(prefix + message)
