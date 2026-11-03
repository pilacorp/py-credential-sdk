from eth_keys import keys

from didcomm import decrypt_jwe, encrypt, get_from_keys
from didv2.hexutil import hex_to_bytes

A = "11" * 32
B = "22" * 32


def test_encrypt_decrypt_roundtrip() -> None:
    pub = keys.PrivateKey(hex_to_bytes(A)).public_key.to_compressed_bytes().hex()
    shared = get_from_keys(pub, B)
    blob = encrypt(shared, "hello didcomm")
    assert decrypt_jwe(blob, shared) == "hello didcomm"
