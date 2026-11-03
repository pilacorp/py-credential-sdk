from __future__ import annotations

import hmac
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import ec

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _bits2int(b: bytes, qlen: int) -> int:
    v = int.from_bytes(b, "big")
    blen = len(b) * 8
    if blen > qlen:
        v >>= blen - qlen
    return v


def _int2octets(v: int, rolen: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if len(b) > rolen:
        b = b[-rolen:]
    return b.rjust(rolen, b"\x00")


def _bits2octets(b: bytes, q: int, qlen: int, rolen: int) -> bytes:
    z1 = _bits2int(b, qlen)
    z2 = z1 - q
    if z2 < 0:
        return _int2octets(z1, rolen)
    return _int2octets(z2, rolen)


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, sha256).digest()


def rfc6979_nonce(d: int, q: int, hash_bytes: bytes) -> int:
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8
    holen = 32
    bx = _int2octets(d, rolen) + _bits2octets(hash_bytes, q, qlen, rolen)
    v = b"\x01" * holen
    k = b"\x00" * holen
    k = _hmac_sha256(k, v + b"\x00" + bx)
    v = _hmac_sha256(k, v)
    k = _hmac_sha256(k, v + b"\x01" + bx)
    v = _hmac_sha256(k, v)
    while True:
        t = b""
        while len(t) < rolen:
            v = _hmac_sha256(k, v)
            t += v
        n = _bits2int(t, qlen)
        if 0 < n < q:
            return n
        k = _hmac_sha256(k, v + b"\x00")
        v = _hmac_sha256(k, v)


def _hash_to_int(hash_bytes: bytes, q: int) -> int:
    order_bytes = (q.bit_length() + 7) // 8
    hb = hash_bytes[:order_bytes]
    ret = int.from_bytes(hb, "big")
    excess = len(hb) * 8 - q.bit_length()
    if excess > 0:
        ret >>= excess
    return ret


def sign_rfc6979(priv: ec.EllipticCurvePrivateKey, hash_bytes: bytes) -> bytes:
    order = P256_ORDER
    d = priv.private_numbers().private_value
    k = rfc6979_nonce(d, order, hash_bytes)
    tmp = ec.derive_private_key(k, ec.SECP256R1())
    r = tmp.public_key().public_numbers().x % order
    e = _hash_to_int(hash_bytes, order)
    kinv = pow(k, -1, order)
    s = (kinv * (r * d + e)) % order
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
