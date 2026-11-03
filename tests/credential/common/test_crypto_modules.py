from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.crypto.ecdsa_rdfc import verify_ecdsa
from credential.common.signer.p256 import P256Provider


def test_verify_ecdsa_accepts_64_byte_signature():
    signer = P256Provider()
    digest = b"\x01" * 32
    sig = signer.sign(digest)
    pub = signer._key.public_key()  # noqa: SLF001
    assert verify_ecdsa(pub, digest, sig) is True
