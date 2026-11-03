from __future__ import annotations

from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from credential.common.dto.proof import Proof, proof_from_map
from credential.common.processor import canonicalize_document
from credential.common.signer.p256 import verify_p256


def verify_ecdsa(pub: ec.EllipticCurvePublicKey, digest: bytes, sig: bytes) -> bool:
    if len(sig) == 65:
        sig = sig[:64]
    if len(sig) != 64 or len(digest) != 32:
        return False
    nums = pub.public_numbers()
    uncompressed = b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return verify_p256(uncompressed, digest, sig)


def ecdsa_verify_signature(pub: ec.EllipticCurvePublicKey, signature_hex: str, msg: bytes) -> bool:
    sig_bytes = bytes.fromhex(signature_hex[2:] if signature_hex.startswith("0x") else signature_hex)
    if len(sig_bytes) == 65:
        sig_bytes = sig_bytes[:64]
    if len(sig_bytes) != 64:
        return False
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:], "big")
    try:
        pub.verify(encode_dss_signature(r, s), msg, ec.ECDSA(prehashed=None))
        return True
    except Exception:
        return False


def verify_ecdsa_rdfc_proof(
    document: dict[str, Any], proof: Proof | dict[str, Any], pub: ec.EllipticCurvePublicKey
) -> bool:
    if isinstance(proof, dict):
        proof = proof_from_map(proof)
    body = {k: v for k, v in document.items() if k != "proof"}
    doc_canon = canonicalize_document(body)
    doc_hash = sha256(doc_canon).digest()

    cfg = proof.to_map()
    cfg.pop("proofValue", None)
    cfg.pop("jws", None)
    ctx = document.get("@context")
    if ctx is None:
        return False
    cfg["@context"] = ctx
    cfg_canon = canonicalize_document(cfg)
    proof_cfg_hash = sha256(cfg_canon).digest()
    hash_data = proof_cfg_hash + doc_hash
    digest = sha256(hash_data).digest()

    proof_value = proof.proof_value
    if proof_value.startswith("z"):
        from credential.common.verification_method.key_material import decode_multibase_key

        sig = decode_multibase_key(proof_value)
    else:
        sig = bytes.fromhex(proof_value[2:] if proof_value.startswith("0x") else proof_value)
    if len(sig) != 64:
        return False
    return verify_ecdsa(pub, digest, sig)
