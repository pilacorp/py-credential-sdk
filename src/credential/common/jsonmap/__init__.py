from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.dto.proof import Proof
from credential.common.signer.p256 import P256Provider

from credential.common.jsonmap._context import ensure_data_integrity_context
from credential.common.jsonmap._ecdsa_common import (
    document_digest,
    ecdsa_hash_data,
    ecdsa_proof_config,
    has_multibase_proof,
    legacy_hex_canonicalize,
    proof_hash_data,
)
from credential.common.jsonmap._ecdsa_rdfc import add_ecdsa_proof, verify_ecdsa_rdfc
from credential.common.jsonmap._ecdsasd import add_ecdsasd_base_proof, derive_ecdsasd
from credential.common.jsonmap._jws import add_jws_proof
from credential.common.jsonmap._options import ProofOptions, new_proof_options
from credential.common.jsonmap._proof_helpers import (
    parse_raw_to_proof,
    strict_purpose_check,
)
from credential.common.jsonmap._secp256k1 import add_ecdsa_secp256k1_proof, signing_suite_for_key
from credential.common.jsonmap._ecdsa_common import canonicalize_full
from credential.common.jsonmap.map import JSONMap, verify_one_proof

__all__ = [
    "JSONMap",
    "ProofOptions",
    "add_ecdsa_proof",
    "add_ecdsa_rdfc_proof",
    "add_ecdsa_secp256k1_proof",
    "add_ecdsasd_base_proof",
    "add_jws_proof",
    "canonicalize_full",
    "derive_ecdsasd",
    "document_digest",
    "ecdsa_hash_data",
    "ecdsa_proof_config",
    "ensure_data_integrity_context",
    "has_multibase_proof",
    "legacy_hex_canonicalize",
    "new_proof_options",
    "parse_raw_to_proof",
    "proof_hash_data",
    "signing_suite_for_key",
    "strict_purpose_check",
    "verify_ecdsa_rdfc",
    "verify_one_proof",
]


def add_ecdsa_rdfc_proof(
    m: dict[str, Any],
    signer: P256Provider,
    verification_method: str,
    purpose: str,
    *,
    vm_pub: ec.EllipticCurvePublicKey | None = None,
    challenge: str = "",
    domain: str = "",
) -> None:
    """Attach a Data Integrity ecdsa-rdfc-2019 proof (backward-compatible entry point)."""
    options = new_proof_options(vm_pub=vm_pub, challenge=challenge, domain=domain)
    add_ecdsa_proof(m, signer, verification_method, purpose, options=options)


def canonicalize(m: dict[str, Any]) -> bytes:
    """Document digest (body without proof) for legacy callers."""
    return document_digest(m)
