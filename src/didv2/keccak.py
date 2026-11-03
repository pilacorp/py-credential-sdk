from Crypto.Hash import keccak


def keccak256(data: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def keccak256_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()
