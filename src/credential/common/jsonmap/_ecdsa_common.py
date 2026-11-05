from __future__ import annotations

from hashlib import sha256
from typing import Any

from credential.common.dto.proof import Proof
from credential.common.processor import canonicalize, canonicalize_document

from credential.common.jsonmap._constants import ECDSA_SECP256K1_SIGNATURE_2019, PROOF_FIELD
from credential.common.jsonmap._proof_helpers import body_without_proof, to_map_roundtrip


def signature_field(proof_type: str) -> str:
    if proof_type == ECDSA_SECP256K1_SIGNATURE_2019:
        return "jws"
    return "proofValue"


def ecdsa_proof_config(m: dict[str, Any], proof: Proof | None) -> dict[str, Any]:
    if proof is None:
        raise ValueError("proof is nil")
    ctx = m.get("@context")
    if ctx is None:
        raise ValueError("document is missing the @context needed to canonicalize the proof configuration")

    cfg = proof.to_map()
    cfg.pop(signature_field(proof.type), None)
    cfg["@context"] = ctx
    return to_map_roundtrip(cfg)


def concat_hash_data(proof_config_hash: bytes, transformed_document_hash: bytes) -> bytes:
    return proof_config_hash + transformed_document_hash


def document_digest(m: dict[str, Any]) -> bytes:
    body = body_without_proof(m)
    body_canonical = canonicalize(body)
    return sha256(body_canonical).digest()


def proof_hash_data(m: dict[str, Any], doc_hash: bytes, proof: Proof) -> bytes:
    if len(doc_hash) != sha256().digest_size:
        raise ValueError(f"document digest must be {sha256().digest_size} bytes, got {len(doc_hash)}")
    cfg = ecdsa_proof_config(m, proof)
    cfg_canonical = canonicalize(cfg)
    cfg_hash = sha256(cfg_canonical).digest()
    return concat_hash_data(cfg_hash, doc_hash)


def ecdsa_hash_data(m: dict[str, Any], proof: Proof) -> bytes:
    doc_hash = document_digest(m)
    return proof_hash_data(m, doc_hash, proof)


def legacy_hex_canonicalize(m: dict[str, Any]) -> bytes:
    """Digest hex proofs from SDK <= v1.7.0 signed: SHA-256 of the legacy-canonicalized body
    (proof removed). Never use it to issue: it covers no proof option (ecdsa_hash_data does)."""
    body = to_map_roundtrip({k: v for k, v in m.items() if k != PROOF_FIELD})
    return sha256(canonicalize_document(body)).digest()


def canonicalize_full(m: dict[str, Any]) -> bytes:
    """Legacy-canonicalize the whole map, proof included, and return its SHA-256."""
    return sha256(canonicalize_document(to_map_roundtrip(m))).digest()


def has_multibase_proof(m: dict[str, Any]) -> bool:
    proof = m.get(PROOF_FIELD)
    if isinstance(proof, list) and proof:
        proof = proof[0]
    if not isinstance(proof, dict):
        return False
    pv = proof.get("proofValue") or ""
    if not isinstance(pv, str):
        return False
    return pv.startswith("z") or pv.startswith("u")
