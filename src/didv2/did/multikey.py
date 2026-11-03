from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

P256_PUB_MULTICODEC = bytes([0x80, 0x24])
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    enc = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        enc.append(_B58_ALPHABET[rem])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return (b"1" * pad + bytes(reversed(enc or b"\x00"))).decode("ascii")


def _b58decode(s: str) -> bytes:
    num = 0
    for ch in s.encode("ascii"):
        num = num * 58 + _B58_ALPHABET.index(ch)
    out = num.to_bytes((num.bit_length() + 7) // 8 or 1, "big")
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + out


def encode_pub_multibase(pub: ec.EllipticCurvePublicKey) -> str:
    if not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("multikey: unsupported curve (want P-256)")
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    prefix = b"\x02" if (nums.y % 2) == 0 else b"\x03"
    compressed = prefix + x
    raw = P256_PUB_MULTICODEC + compressed
    return "z" + _b58encode(raw)


def decode_multibase_key(s: str) -> bytes:
    if not s or s[0] != "z":
        raise ValueError("multikey: expected base58btc 'z' multibase")
    try:
        return _b58decode(s[1:])
    except ValueError as exc:
        raise ValueError("multikey: base58 decode failed") from exc


def ec_pub_from_multikey_bytes(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) < 2:
        raise ValueError("multikey: value too short")
    if raw[:2] != P256_PUB_MULTICODEC:
        raise ValueError(f"multikey: unsupported multicodec prefix {raw[:2]!r}")
    compressed = raw[2:]
    if len(compressed) != 33:
        raise ValueError("multikey: invalid P-256 compressed point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), compressed)
