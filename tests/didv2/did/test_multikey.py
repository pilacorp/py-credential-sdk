from cryptography.hazmat.primitives.asymmetric import ec

from didv2.did.multikey import decode_multibase_key, encode_pub_multibase, ec_pub_from_multikey_bytes


def test_p256_multikey_roundtrip():
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key()
    mb = encode_pub_multibase(pub)
    raw = decode_multibase_key(mb)
    recovered = ec_pub_from_multikey_bytes(raw)
    assert recovered.public_numbers().x == pub.public_numbers().x
