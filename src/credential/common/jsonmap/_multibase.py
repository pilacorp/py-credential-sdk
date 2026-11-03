from __future__ import annotations

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
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


def b58decode(s: str) -> bytes:
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


def encode_multibase_key(raw: bytes) -> str:
    return "z" + b58encode(raw)


def decode_multibase_key(s: str) -> bytes:
    if not s or s[0] != "z":
        raise ValueError("failed to decode multibase proofValue: expected base58btc 'z' prefix")
    try:
        return b58decode(s[1:])
    except ValueError as exc:
        raise ValueError("failed to decode multibase proofValue: base58 decode failed") from exc
