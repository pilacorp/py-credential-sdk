from __future__ import annotations

import base64
import hashlib

from eth_keys import keys

from didv2.hexutil import with_0x


def b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def verify_es256k(signing_string: str, signature_b64: str, expected_address: str) -> None:
    digest = hashlib.sha256(signing_string.encode("utf-8")).digest()
    raw = b64url_decode(signature_b64)
    if len(raw) != 64:
        raise ValueError("JWT ES256K signature must be 64 bytes")
    want = expected_address.lower()
    for rec_id in (0, 1):
        try:
            sig = keys.Signature(raw + bytes([rec_id]))
            pub = sig.recover_public_key_from_msg_hash(digest)
            got = with_0x(bytes(pub.to_canonical_address()))
            if got == want:
                return
        except Exception:
            continue
    raise ValueError("JWT signature does not match expected address")
