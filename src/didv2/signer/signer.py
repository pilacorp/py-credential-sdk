from eth_keys import keys

from didv2.hexutil import hex_to_bytes, with_0x


class DefaultProvider:
    def __init__(self, private_key_hex: str) -> None:
        self._key = keys.PrivateKey(hex_to_bytes(private_key_hex))

    def sign(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise ValueError("failed to sign payload: digest must be 32 bytes")
        sig = self._key.sign_msg_hash(digest)
        return sig.to_bytes()

    def get_address(self) -> str:
        return with_0x(bytes(self._key.public_key.to_canonical_address()))

    def private_key_hex(self) -> str:
        return with_0x(self._key.to_bytes())
