import base64
import json


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_jwe(iv: bytes, ciphertext: bytes, tag: bytes) -> str:
    # Go marshals the header map with sorted keys, so protected is byte-identical across SDKs
    header = {
        "alg": "ECDH-ES",
        "crv": "secp256k1",
        "enc": "A256GCM",
        "typ": "application/didcomm-encrypted+json",
    }
    body = {
        "protected": _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")),
        "iv": _b64url(iv),
        "ciphertext": _b64url(ciphertext),
        "tag": _b64url(tag),  # real AES-GCM authentication tag
    }
    return json.dumps(body, indent=2)
