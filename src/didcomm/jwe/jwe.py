import base64
import json


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_jwe(iv: bytes, ciphertext: bytes, tag: bytes) -> str:
    header = {
        "alg": "ECDH-ES",
        "enc": "A256GCM",
        "crv": "secp256k1",
        "typ": "application/didcomm-encrypted+json",
    }
    body = {
        "protected": _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        "iv": _b64url(iv),
        "ciphertext": _b64url(ciphertext),
        "tag": _b64url(tag),
    }
    return json.dumps(body, indent=2)
