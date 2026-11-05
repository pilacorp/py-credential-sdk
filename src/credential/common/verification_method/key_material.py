from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from eth_keys import keys

from credential.common.verification_method.verification_method import JWK

P256_PUB_MULTICODEC = bytes([0x80, 0x24])
P256_PRIV_MULTICODEC = bytes([0x86, 0x26])
P384_PUB_MULTICODEC = bytes([0x81, 0x24])

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_CURVES: dict[str, tuple[ec.EllipticCurve, int]] = {
    "secp256k1": (ec.SECP256K1(), 32),
    "P-256": (ec.SECP256R1(), 32),
    "P-384": (ec.SECP384R1(), 48),
}


def b64url_decode_raw(s: str) -> bytes:
    """Strict base64url without padding, like Go's base64.RawURLEncoding."""
    if not isinstance(s, str) or not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("illegal base64url data")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("illegal base64url data") from exc


def strip_hex_prefix(s: str) -> str:
    if len(s) >= 2 and s[0] == "0" and s[1] in "xX":
        return s[2:]
    return s


def _jwk_field(jwk: Any, name: str) -> str:
    if isinstance(jwk, dict):
        return str(jwk.get(name) or "")
    return str(getattr(jwk, name, "") or "")


def curve_name(pub: Any) -> str:
    """Name of the curve a public key lives on: secp256k1, P-256 or P-384."""
    if isinstance(pub, keys.PublicKey):
        return "secp256k1"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"secp256k1": "secp256k1", "secp256r1": "P-256", "secp384r1": "P-384"}.get(
            pub.curve.name, pub.curve.name
        )
    raise ValueError("invalid public key")


def to_crypto_pub(pub: Any) -> ec.EllipticCurvePublicKey:
    """Normalise eth_keys / cryptography public keys to a cryptography EC key."""
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub
    if isinstance(pub, keys.PublicKey):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x04" + pub.to_bytes())
    raise ValueError("invalid public key")


def ec_pub_from_jwk(jwk: JWK | dict[str, Any] | None) -> ec.EllipticCurvePublicKey:
    """EC JWK on secp256k1, P-256 or P-384; off-curve points are rejected.

    A short coordinate is left-padded (some DID documents strip leading zeros);
    one longer than the field is refused.
    """
    if jwk is None:
        raise ValueError("jwk is nil")
    kty = _jwk_field(jwk, "kty")
    if kty != "EC":
        raise ValueError(f"unsupported key type: {kty}")
    crv = _jwk_field(jwk, "crv")
    if crv not in _CURVES:
        raise ValueError(f"unsupported curve: {crv} (want secp256k1, P-256 or P-384)")
    curve, size = _CURVES[crv]
    try:
        xb = b64url_decode_raw(_jwk_field(jwk, "x"))
    except ValueError as exc:
        raise ValueError(f"failed to decode X coordinate: {exc}") from exc
    try:
        yb = b64url_decode_raw(_jwk_field(jwk, "y"))
    except ValueError as exc:
        raise ValueError(f"failed to decode Y coordinate: {exc}") from exc
    if len(xb) > size or len(yb) > size:
        raise ValueError(f"jwk {crv}: coordinates must be at most {size} bytes, got x={len(xb)} y={len(yb)}")
    try:
        nums = ec.EllipticCurvePublicNumbers(int.from_bytes(xb, "big"), int.from_bytes(yb, "big"), curve)
        return nums.public_key()
    except ValueError as exc:
        raise ValueError(f"jwk {crv}: invalid public key point: {exc}") from exc


def p256_pub_key_from_jwk(jwk: JWK | dict[str, Any] | None) -> ec.EllipticCurvePublicKey:
    if jwk is None:
        raise ValueError("jwk is nil")
    crv = _jwk_field(jwk, "crv")
    if crv != "P-256":
        raise ValueError(f"unsupported curve: {crv} (want P-256)")
    return ec_pub_from_jwk(jwk)


def rsa_pub_from_jwk(jwk: JWK | dict[str, Any] | None) -> rsa.RSAPublicKey:
    if jwk is None:
        raise ValueError("jwk is nil")
    kty = _jwk_field(jwk, "kty")
    if kty != "RSA":
        raise ValueError(f"unsupported key type: {kty}")
    n, e = _jwk_field(jwk, "n"), _jwk_field(jwk, "e")
    if not n or not e:
        raise ValueError("RSA jwk missing n or e")
    try:
        nb = b64url_decode_raw(n)
    except ValueError as exc:
        raise ValueError(f"decode n: {exc}") from exc
    try:
        eb = b64url_decode_raw(e)
    except ValueError as exc:
        raise ValueError(f"decode e: {exc}") from exc
    return rsa.RSAPublicNumbers(int.from_bytes(eb, "big"), int.from_bytes(nb, "big")).public_key()


def secp256k1_pub_from_hex(h: str) -> keys.PublicKey:
    """Compressed (02/03||X) or uncompressed (04||X||Y) secp256k1 key; 0x prefix optional."""
    try:
        b = bytes.fromhex(strip_hex_prefix(h))
    except ValueError as exc:
        raise ValueError(f"decode secp256k1 public key hex: {exc}") from exc
    if not ((len(b) == 33 and b[0] in (2, 3)) or (len(b) == 65 and b[0] == 4)):
        raise ValueError(f"secp256k1 public key: want 33 compressed or 65 uncompressed bytes, got {len(b)}")
    try:
        # validates the point is on the curve
        pt = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b)
        nums = pt.public_numbers()
        return keys.PublicKey(nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"))
    except Exception as exc:
        raise ValueError(f"invalid secp256k1 public key: {exc}") from exc


def b58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def b58_decode(s: str) -> bytes:
    num = 0
    for ch in s:
        i = _B58_ALPHABET.find(ch)
        if i < 0:
            raise ValueError(f"invalid base58 character {ch!r}")
        num = num * 58 + i
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def decode_multibase_key(s: str) -> bytes:
    """base58btc ('z') multibase string -> raw bytes (including any multicodec prefix)."""
    if not s or s[0] != "z":
        raise ValueError("multikey: expected base58btc 'z' multibase")
    try:
        return b58_decode(s[1:])
    except ValueError as exc:
        raise ValueError(f"multikey: base58 decode: {exc}") from exc


def encode_multibase_key(raw: bytes) -> str:
    return "z" + b58_encode(raw)


def ec_pub_from_multikey_bytes(raw: bytes) -> ec.EllipticCurvePublicKey:
    """2-byte multicodec prefix + compressed point; only P-256 and P-384 (CID 1.0)."""
    if len(raw) < 2:
        raise ValueError("multikey: value too short")
    if raw.startswith(P256_PUB_MULTICODEC):
        curve = ec.SECP256R1()
    elif raw.startswith(P384_PUB_MULTICODEC):
        curve = ec.SECP384R1()
    else:
        raise ValueError(f"multikey: unsupported multicodec prefix 0x{raw[:2].hex()}")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, raw[2:])
    except ValueError as exc:
        raise ValueError(f"multikey: invalid {curve.name} compressed point") from exc


def ec_pub_from_multibase(s: str) -> ec.EllipticCurvePublicKey:
    return ec_pub_from_multikey_bytes(decode_multibase_key(s))


def pub_to_multikey_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    if pub is None:
        raise ValueError("public key is nil")
    if isinstance(pub.curve, ec.SECP256R1):
        prefix = P256_PUB_MULTICODEC
    elif isinstance(pub.curve, ec.SECP384R1):
        prefix = P384_PUB_MULTICODEC
    else:
        raise ValueError(f"multikey: unsupported curve {pub.curve.name}")
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return prefix + pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def encode_pub_multibase(pub: ec.EllipticCurvePublicKey) -> str:
    return encode_multibase_key(pub_to_multikey_bytes(pub))


def decode_p256_priv_multibase(s: str) -> ec.EllipticCurvePrivateKey:
    raw = decode_multibase_key(s)
    if not raw.startswith(P256_PRIV_MULTICODEC):
        raise ValueError("multikey: not a p256-priv multikey")
    d = raw[len(P256_PRIV_MULTICODEC):]
    if len(d) != 32:
        raise ValueError(f"multikey: p256 secret key must be 32 bytes, got {len(d)}")
    try:
        return ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())
    except ValueError as exc:
        raise ValueError(f"multikey: invalid p256 secret key: {exc}") from exc


def _vm_field(vm: Any, camel: str, snake: str) -> Any:
    if isinstance(vm, dict):
        return vm.get(camel)
    return getattr(vm, snake, None)


def ec_pub_from_vm(vm: Any) -> ec.EllipticCurvePublicKey | keys.PublicKey:
    """Public key of a VM (dict or VerificationMethodEntry) on whichever curve it names.

    publicKeyHex names no curve, so it is read as secp256k1 (returned as an
    eth_keys.PublicKey); JWK and Multikey material come back as cryptography keys.
    """
    if vm is None:
        raise ValueError("verification method is nil")
    if _vm_field(vm, "publicKeyHex", "public_key_hex"):
        return secp256k1_pub_from_hex(_vm_field(vm, "publicKeyHex", "public_key_hex"))
    jwk = _vm_field(vm, "publicKeyJwk", "public_key_jwk")
    if jwk:
        return ec_pub_from_jwk(jwk)
    mb = _vm_field(vm, "publicKeyMultibase", "public_key_multibase")
    if mb:
        return ec_pub_from_multibase(mb)
    raise ValueError(f"verification method '{_vm_field(vm, 'id', 'id')}' has no public key material")


def verify_rs(pub: Any, digest: bytes, signature: bytes) -> bool:
    """Plain ECDSA over a 32-byte digest with a 64-byte r||s signature (high-S accepted)."""
    if pub is None or len(signature) != 64:
        return False
    try:
        cpub = to_crypto_pub(pub)
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        cpub.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False
