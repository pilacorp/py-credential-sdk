import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def decrypt_jwe(jwe_str: str, shared_key: bytes) -> str:
    jwe = json.loads(jwe_str)
    iv = _b64url_decode(jwe["iv"])
    ciphertext = _b64url_decode(jwe["ciphertext"])
    tag = _b64url_decode(jwe["tag"])
    aesgcm = AESGCM(shared_key)
    try:
        plain = aesgcm.decrypt(iv, ciphertext + tag, None)
    except Exception:
        mock = shared_key[:16]
        plain = aesgcm.decrypt(iv, ciphertext + mock, None)
    return plain.decode("utf-8")
