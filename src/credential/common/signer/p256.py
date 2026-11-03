from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature

from didv2.hexutil import with_0x


class P256Provider:
    def __init__(self, private_key: bytes | None = None) -> None:
        if private_key is None:
            self._key = ec.generate_private_key(ec.SECP256R1())
        else:
            self._key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())

    def sign(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise ValueError("digest must be 32 bytes")
        der = self._key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public_key_uncompressed(self) -> bytes:
        nums = self._key.public_key().public_numbers()
        return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def private_key_bytes(self) -> bytes:
        return self._key.private_numbers().private_value.to_bytes(32, "big")

    def get_address(self) -> str:
        return with_0x(self.public_key_uncompressed()[-20:])


def verify_p256(pub_uncompressed: bytes, digest: bytes, signature: bytes) -> bool:
    nums = ec.EllipticCurvePublicNumbers(
        int.from_bytes(pub_uncompressed[1:33], "big"),
        int.from_bytes(pub_uncompressed[33:65], "big"),
        ec.SECP256R1(),
    )
    pub = nums.public_key()
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    try:
        pub.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False
