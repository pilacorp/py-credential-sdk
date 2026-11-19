# didcomm

DIDComm JWE: `encrypt.py`, `decrypt.py` (ECDH-ES + AES-GCM).

- `decrypt_jwe` raises `ValueError` on bad tag or a payload that is not valid UTF-8 (no silent replacement).
- **Network**: none.
