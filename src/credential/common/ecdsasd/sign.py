from __future__ import annotations

import os
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.ecdsasd.crypto_util import encode_rs_p256, normalize_low_s_p256, verify_ecdsa
from credential.common.ecdsasd.hashes import hash_mandatory, hash_proof_config
from credential.common.ecdsasd.keys import new_ephemeral_key, pub_to_multikey_bytes
from credential.common.ecdsasd.labelmap import canonicalize_and_group, sorted_indexes
from credential.common.ecdsasd.proofvalue import SpecBaseProof, serialize_base_proof_value
from credential.common.signer.p256 import P256Provider


def ordered_values(m: dict[int, str]) -> list[str]:
    return [m[k] for k in sorted_indexes(m)]


def _normalize_signature(sig: bytes) -> bytes:
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    return encode_rs_p256(r, s)


def create_base_proof(
    document: dict[str, Any],
    proof_config: dict[str, Any],
    mandatory_pointers: list[str],
    issuer_signer: P256Provider,
    issuer_pub: ec.EllipticCurvePublicKey | None = None,
) -> str:
    proof_hash = hash_proof_config(proof_config)
    hmac_key = os.urandom(32)
    grouped = canonicalize_and_group(document, hmac_key, {"mandatory": mandatory_pointers})
    mg = grouped.groups["mandatory"]
    non_mandatory = ordered_values(mg.non_matching)
    mandatory_hash = hash_mandatory(mg.matching)

    eph = new_ephemeral_key()
    signatures: list[bytes] = []
    for nq in non_mandatory:
        signatures.append(eph.sign_statement(nq))
    eph_pub = pub_to_multikey_bytes(eph.priv.public_key())

    to_sign = proof_hash + eph_pub + mandatory_hash
    digest = sha256(to_sign).digest()
    base_sig = _normalize_signature(issuer_signer.sign(digest))

    if issuer_pub is not None and not verify_ecdsa(issuer_pub, digest, base_sig):
        raise ValueError(
            "ecdsasd: the base signature does not verify against the verification method; "
            "the signer does not hold that key"
        )

    return serialize_base_proof_value(
        SpecBaseProof(
            base_signature=base_sig,
            public_key=eph_pub,
            hmac_key=hmac_key,
            signatures=signatures,
            mandatory_pointers=mandatory_pointers,
        )
    )


def create_base_proof_deterministic(
    document: dict[str, Any],
    proof_config: dict[str, Any],
    mandatory_pointers: list[str],
    hmac_key: bytes,
    ephemeral_priv: ec.EllipticCurvePrivateKey,
    issuer_priv: ec.EllipticCurvePrivateKey,
) -> str:
    from hashlib import sha256 as _sha256

    from credential.common.ecdsasd.rfc6979 import sign_rfc6979

    proof_hash = hash_proof_config(proof_config)
    grouped = canonicalize_and_group(document, hmac_key, {"mandatory": mandatory_pointers})
    mg = grouped.groups["mandatory"]
    non_mandatory = ordered_values(mg.non_matching)
    mandatory_hash = hash_mandatory(mg.matching)

    signatures = [sign_rfc6979(ephemeral_priv, _sha256(nq.encode()).digest()) for nq in non_mandatory]
    eph_pub = pub_to_multikey_bytes(ephemeral_priv.public_key())

    to_sign = proof_hash + eph_pub + mandatory_hash
    digest = _sha256(to_sign).digest()
    base_sig = sign_rfc6979(issuer_priv, digest)

    return serialize_base_proof_value(
        SpecBaseProof(
            base_signature=base_sig,
            public_key=eph_pub,
            hmac_key=hmac_key,
            signatures=signatures,
            mandatory_pointers=mandatory_pointers,
        )
    )
