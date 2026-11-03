from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_keys import keys

from didv2.ethereum import address_from_public_key_hex
from didv2.subdid.document import parse_sub_id
from didv2.hexutil import hex_to_bytes, with_0x

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
KDF_SALT = b"subdid-keygen-v1"
KDF_INFO_PREFIX = b"subdid-key-v1"


def derive_sub_did_key(root_private_key_hex: str, sub_id: str) -> dict[str, str]:
    root = hex_to_bytes(root_private_key_hex)
    if len(root) != 32:
        raise ValueError("subdid: root private key must be 32 bytes of hex")
    root_scalar = int.from_bytes(root, "big")
    if root_scalar == 0 or root_scalar >= SECP256K1_N:
        raise ValueError("subdid: root private key is out of range")
    ident = parse_sub_id(sub_id)
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=KDF_SALT,
        info=KDF_INFO_PREFIX + ident.encode("utf-8"),
    ).derive(root)
    child = _reduce_to_p256_scalar(okm)
    priv = keys.PrivateKey(child)
    pub = priv.public_key.to_compressed_bytes()
    p256 = ec.derive_private_key(int.from_bytes(child, "big"), ec.SECP256R1()).public_key().public_numbers()
    return {
        "privateKeyHex": with_0x(child),
        "publicKeyHex": with_0x(pub),
        "address": address_from_public_key_hex(with_0x(pub)),
        "p256X": f"{p256.x:064x}",
        "p256Y": f"{p256.y:064x}",
    }


def _reduce_to_p256_scalar(okm: bytes) -> bytes:
    k = int.from_bytes(okm, "big") % (P256_N - 1)
    k += 1
    return k.to_bytes(32, "big")
