import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    sealed = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, sealed[:-16], sealed[-16:]
