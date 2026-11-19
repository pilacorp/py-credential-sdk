import re

from cryptography.hazmat.primitives.asymmetric import ec

_HEX = re.compile(r"^(?:[0-9a-fA-F]{2})*$")


def _decode_hex(value: str, what: str) -> bytes:
    # Go hex.DecodeString: no 0x prefix accepted, even length, hex digits only
    if not _HEX.match(value):
        raise ValueError(f"failed to decode {what}: invalid hex")
    return bytes.fromhex(value)


def get_from_keys(sender_pub_hex: str, receiver_priv_hex: str) -> bytes:
    """secp256k1 ECDH; the shared key is the raw 32-byte X coordinate (no KDF), as in Go."""
    sender_pub = _decode_hex(sender_pub_hex, "sender public key")
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), sender_pub)
    except ValueError as exc:
        raise ValueError(f"failed to parse sender public key: {exc}") from exc
    priv_bytes = _decode_hex(receiver_priv_hex, "receiver private key")
    # Go's PrivKeyFromBytes reduces mod N; a zero/out-of-range scalar is refused here instead
    priv = ec.derive_private_key(int.from_bytes(priv_bytes, "big"), ec.SECP256K1())
    return priv.exchange(ec.ECDH(), pub)
