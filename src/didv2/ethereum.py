from cryptography.hazmat.primitives.asymmetric import ec

from didv2.hexutil import hex_to_bytes, with_0x
from didv2.keccak import keccak256


def secp256k1_point(raw: bytes) -> tuple[int, int]:
    """Parse a 33-byte compressed (02/03) or 65-byte uncompressed (04) SEC1 key; the point must be on
    the curve (eth_keys does not check, so go through ``cryptography``).  Raises ValueError."""
    if not ((len(raw) == 33 and raw[0] in (2, 3)) or (len(raw) == 65 and raw[0] == 4)):
        raise ValueError(
            "unsupported public key format: expected 33 bytes (compressed) or 65 bytes (uncompressed), "
            f"got {len(raw)} bytes"
        )
    try:
        nums = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw).public_numbers()
    except ValueError as exc:
        raise ValueError(f"failed to parse public key: {exc}") from exc
    return nums.x, nums.y


def compress_secp256k1(x: int, y: int) -> bytes:
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def address_from_public_key_hex(public_key_hex: str) -> str:
    """Lowercase 0x address of a 33-byte compressed (02/03) or 65-byte uncompressed (04) secp256k1 key."""
    try:
        if public_key_hex.startswith("0X"):  # Go strips only a lowercase "0x"
            raise ValueError("invalid hex prefix")
        raw = hex_to_bytes(public_key_hex)
    except ValueError as exc:
        raise ValueError(f"failed to decode public key hex: {exc}") from exc
    x, y = secp256k1_point(raw)
    return with_0x(keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:])


def eip191_hash(message: bytes) -> bytes:
    prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode("utf-8")
    return keccak256(prefix + message)
