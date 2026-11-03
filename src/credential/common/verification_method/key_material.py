from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from eth_keys import keys

from didv2.did.multikey import decode_multibase_key, ec_pub_from_multikey_bytes
from didv2.hexutil import hex_to_bytes

P256_PUB_MULTICODEC = bytes([0x80, 0x24])


def strip_hex_prefix(s: str) -> str:
    if len(s) >= 2 and s[0] == "0" and s[1].lower() == "x":
        return s[2:]
    return s


def ec_pub_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC":
        raise ValueError(f"unsupported key type: {jwk.get('kty')}")
    crv = jwk.get("crv") or ""
    size = {"secp256k1": 32, "P-256": 32, "P-384": 48}.get(crv)
    if size is None:
        raise ValueError(f"unsupported curve: {crv}")
    x = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    y = base64.urlsafe_b64decode(jwk["y"] + "=" * (-len(jwk["y"]) % 4))
    if len(x) > size or len(y) > size:
        raise ValueError("jwk coordinates too long")
    curve = ec.SECP256R1() if crv == "P-256" else ec.SECP384R1()
    nums = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve)
    return nums.public_key()


def secp256k1_pub_from_hex(h: str) -> keys.PublicKey:
    b = hex_to_bytes(h if h.startswith("0x") else "0x" + h)
    if len(b) == 33 and b[0] in (2, 3):
        return keys.PublicKey.from_compressed_bytes(b)
    if len(b) == 65 and b[0] == 4:
        return keys.PublicKey.from_bytes(b[1:])
    raise ValueError(f"secp256k1 public key: want 33 compressed or 65 uncompressed bytes, got {len(b)}")


def ec_pub_from_vm(vm: dict[str, Any] | Any) -> ec.EllipticCurvePublicKey | keys.PublicKey:
    if vm is None:
        raise ValueError("verification method is nil")
    if isinstance(vm, dict):
        if vm.get("publicKeyHex"):
            return secp256k1_pub_from_hex(vm["publicKeyHex"])
        if vm.get("publicKeyJwk"):
            return ec_pub_from_jwk(vm["publicKeyJwk"])
        if vm.get("publicKeyMultibase"):
            return ec_pub_from_multibase(vm["publicKeyMultibase"])
    else:
        if getattr(vm, "public_key_hex", ""):
            return secp256k1_pub_from_hex(vm.public_key_hex)
        if getattr(vm, "public_key_jwk", None):
            j = vm.public_key_jwk
            return ec_pub_from_jwk(j.__dict__ if hasattr(j, "__dict__") else j)
        if getattr(vm, "public_key_multibase", ""):
            return ec_pub_from_multibase(vm.public_key_multibase)
    raise ValueError(f"verification method has no public key material")


def ec_pub_from_multibase(s: str) -> ec.EllipticCurvePublicKey:
    raw = decode_multibase_key(s)
    return ec_pub_from_multikey_bytes(raw)


def encode_pub_multibase(pub: ec.EllipticCurvePublicKey) -> str:
    from didv2.did.multikey import encode_pub_multibase as _enc

    return _enc(pub)


def rsa_pub_from_jwk(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        raise ValueError(f"unsupported key type: {jwk.get('kty')}")
    n = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
    e = base64.urlsafe_b64decode(jwk["e"] + "=" * (-len(jwk["e"]) % 4))
    return rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
