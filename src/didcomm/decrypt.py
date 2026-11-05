import base64
import json
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url_decode(value: object) -> bytes:
    """Go base64.RawURLEncoding.DecodeString: url alphabet only, no padding (\\r and \\n are ignored)."""
    if not isinstance(value, str):
        raise ValueError("base64url decode error: not a string")
    value = value.replace("\r", "").replace("\n", "")
    if not _B64URL.match(value) or len(value) % 4 == 1:
        raise ValueError("base64url decode error: illegal base64 data")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decrypt_jwe(jwe_str: str, shared_key: bytes) -> str:
    try:
        jwe = json.loads(jwe_str)
    except ValueError as exc:
        raise ValueError(f"unmarshal error: {exc}") from exc
    if not isinstance(jwe, dict):
        raise ValueError("unmarshal error: JWE must be a JSON object")
    iv = _b64url_decode(jwe.get("iv", ""))
    ciphertext = _b64url_decode(jwe.get("ciphertext", ""))
    tag = _b64url_decode(jwe.get("tag", ""))
    if len(iv) != 12:
        raise ValueError("decryption failed: incorrect nonce length")
    try:
        aesgcm = AESGCM(shared_key)
    except ValueError as exc:
        raise ValueError(f"aes new cipher error: {exc}") from exc
    try:
        plain = aesgcm.decrypt(iv, ciphertext + tag, None)
    except Exception:
        # backward compatibility with the old implementation that used sharedKey[:16] as tag
        try:
            plain = aesgcm.decrypt(iv, ciphertext + shared_key[:16], None)
        except Exception as exc:
            raise ValueError("decryption failed: cipher: message authentication failed") from exc
    return plain.decode("utf-8", "replace")
