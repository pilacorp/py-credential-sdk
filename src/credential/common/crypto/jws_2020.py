from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def verify_rsa_jws(alg: str, pub: rsa.RSAPublicKey, signing_input: bytes, sig: bytes) -> None:
    if pub is None:
        raise ValueError("nil RSA public key")
    if alg == "RS256":
        pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "PS256":
        pub.verify(sig, signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif alg == "RS384":
        pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA384())
    elif alg == "PS384":
        pub.verify(sig, signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
    elif alg == "RS512":
        pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA512())
    elif alg == "PS512":
        pub.verify(sig, signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512())
    else:
        raise ValueError(f"unsupported JWS alg: {alg}")
