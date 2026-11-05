from __future__ import annotations

from typing import Protocol, runtime_checkable

from eth_keys import keys

from didv2.hexutil import hex_to_bytes, with_0x


@runtime_checkable
class SignerProvider(Protocol):
    """Signing abstraction (local key, HSM, Vault, ...): sign a 32-byte digest -> 65-byte r||s||v
    (v is the 0/1 recovery id, as go-ethereum's crypto.Sign) and report the signer's address."""

    def sign(self, digest: bytes) -> bytes: ...

    def get_address(self) -> str: ...


class DefaultProvider:
    def __init__(self, private_key_hex: str) -> None:
        self._key = keys.PrivateKey(hex_to_bytes(private_key_hex))

    def sign(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise ValueError("failed to sign payload: hash is required to be exactly 32 bytes")
        sig = self._key.sign_msg_hash(digest).to_bytes()
        if len(sig) != 65:
            raise ValueError(f"invalid signature length: expected 65 bytes, got {len(sig)}")
        return sig

    def get_address(self) -> str:
        return with_0x(bytes(self._key.public_key.to_canonical_address()))

    def private_key_hex(self) -> str:
        return with_0x(self._key.to_bytes())
