from credential.common.verification_method.key_material import secp256k1_pub_from_hex
from didv2.signer import DefaultProvider


def test_secp256k1_pub_from_compressed_hex():
    signer = DefaultProvider("0x" + "11" * 32)
    pub_hex = signer._key.public_key.to_compressed_bytes().hex()  # noqa: SLF001
    pub = secp256k1_pub_from_hex("0x" + pub_hex)
    assert pub.to_compressed_bytes().hex() == pub_hex
