from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.ecdsasd.disclose import create_disclosure_data
from credential.common.ecdsasd.proofvalue import (
    BASE_PROOF_HEADER,
    DERIVED_PROOF_HEADER,
    SpecDerivedProof,
    decode_proof_value,
    serialize_disclosure_proof_value,
)
from credential.common.ecdsasd.sign import create_base_proof as _create_base_proof
from credential.common.ecdsasd.verify import verify_base_proof as _verify_base_proof
from credential.common.ecdsasd.verify import verify_derived_proof as _verify_derived_proof
from credential.common.signer.p256 import P256Provider

CRYPTOSUITE = "ecdsa-sd-2023"


def create_base_proof(
    document: dict[str, Any],
    proof_config: dict[str, Any],
    mandatory_pointers: list[str],
    issuer_signer: P256Provider,
    issuer_pub: ec.EllipticCurvePublicKey | None = None,
) -> str:
    return _create_base_proof(document, proof_config, mandatory_pointers, issuer_signer, issuer_pub)


def derive_proof(
    document: dict[str, Any],
    base_proof_value: str,
    selective_pointers: list[str],
) -> tuple[dict[str, Any], str]:
    dd = create_disclosure_data(document, base_proof_value, selective_pointers)
    proof_value = serialize_disclosure_proof_value(
        SpecDerivedProof(
            base_signature=dd.base_signature,
            public_key=dd.public_key,
            signatures=dd.signatures,
            label_map=dd.label_map,
            mandatory_indexes=dd.mandatory_indexes,
        )
    )
    return dd.reveal_doc, proof_value


def verify_proof(
    document: dict[str, Any],
    proof_config: dict[str, Any],
    proof_value: str,
    issuer_pub: ec.EllipticCurvePublicKey,
) -> None:
    if _decode_ok(proof_value, BASE_PROOF_HEADER):
        return _verify_base_proof(document, proof_config, proof_value, issuer_pub)
    if _decode_ok(proof_value, DERIVED_PROOF_HEADER):
        return _verify_derived_proof(document, proof_config, proof_value, issuer_pub)
    raise ValueError("ecdsasd: unrecognized proof value header")


def verify_base_proof(
    document: dict[str, Any],
    proof_config: dict[str, Any],
    proof_value: str,
    issuer_pub: bytes,
) -> bool:
    nums = ec.EllipticCurvePublicNumbers(
        int.from_bytes(issuer_pub[1:33], "big"),
        int.from_bytes(issuer_pub[33:65], "big"),
        ec.SECP256R1(),
    )
    pub = nums.public_key()
    try:
        _verify_base_proof(document, proof_config, proof_value, pub)
        return True
    except ValueError:
        return False


def _decode_ok(proof_value: str, header: bytes) -> bool:
    try:
        decode_proof_value(proof_value, header)
        return True
    except ValueError:
        return False
