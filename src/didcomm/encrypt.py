from didcomm.crypto.aes import encrypt_aes_gcm
from didcomm.jwe.jwe import build_jwe


def encrypt(key: bytes, plaintext: str) -> str:
    nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext.encode("utf-8"))
    return build_jwe(nonce, ciphertext, tag)
