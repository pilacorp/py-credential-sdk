from cryptography.hazmat.primitives.asymmetric import ec

from didv2.hexutil import hex_to_bytes


def get_from_keys(sender_pub_hex: str, receiver_priv_hex: str) -> bytes:
    priv = ec.derive_private_key(int.from_bytes(hex_to_bytes(receiver_priv_hex), "big"), ec.SECP256K1())
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), hex_to_bytes(sender_pub_hex))
    return priv.exchange(ec.ECDH(), pub)
