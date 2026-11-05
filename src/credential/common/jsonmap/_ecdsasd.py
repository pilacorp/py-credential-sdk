from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.dto.proof import Proof
from credential.common.verification_method.verification_method import DIDDocument

from credential.common.jsonmap._constants import DATA_INTEGRITY_PROOF, ECDSA_SD_2023, PROOF_FIELD
from credential.common.jsonmap._context import context_snapshot, ensure_data_integrity_context
from credential.common.jsonmap._ecdsa_common import ecdsa_proof_config
from credential.common.jsonmap._options import ProofOptions, SignerProvider, new_proof_options
from credential.common.jsonmap._proof_helpers import (
    body_without_proof,
    get_first_proof,
    parse_raw_to_proof,
    set_single_proof,
    strict_purpose_check,
)
from credential.common.jsonmap._vm import find_vm_entry, pub_from_entry

try:
    from credential.common.ecdsasd import create_base_proof as _create_base_proof
except ImportError:  # pragma: no cover
    _create_base_proof = None  # type: ignore[assignment]

try:
    from credential.common.ecdsasd import derive_proof as _derive_proof
except ImportError:  # pragma: no cover
    _derive_proof = None  # type: ignore[assignment]

try:
    from credential.common.ecdsasd import verify_proof as _verify_proof
except ImportError:  # pragma: no cover
    _verify_proof = None  # type: ignore[assignment]


class ResolverProvider(Protocol):
    def resolve_document(self, did: str) -> DIDDocument: ...


def add_ecdsasd_base_proof(
    m: dict[str, Any],
    signer: SignerProvider,
    verification_method: str,
    proof_purpose: str,
    mandatory_pointers: list[str] | None = None,
    *,
    options: ProofOptions | None = None,
) -> None:
    if _create_base_proof is None:
        raise NotImplementedError("credential.common.ecdsasd.create_base_proof is not available")

    if m.get(PROOF_FIELD) is not None:
        raise ValueError(
            "jsonmap: the document already carries a proof; an ecdsa-sd-2023 base proof replaces the proof set, "
            "so remove the existing proof first if that is intended"
        )

    restore = context_snapshot(m)
    try:
        ensure_data_integrity_context(m)
        proof = Proof(
            type=DATA_INTEGRITY_PROOF,
            cryptosuite=ECDSA_SD_2023,
            created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            verification_method=verification_method,
            proof_purpose=proof_purpose,
        )
        doc_no_proof = body_without_proof(m)
        proof_config = ecdsa_proof_config(m, proof)
        opts = options or new_proof_options()
        proof_value = _create_base_proof(
            doc_no_proof,
            proof_config,
            mandatory_pointers or [],
            signer,
        )
        if isinstance(proof_value, dict):
            raise TypeError(
                "jsonmap: ecdsa-sd create_base_proof must return a proofValue string once the ecdsasd API is finalized"
            )
        proof.proof_value = str(proof_value)
        set_single_proof(m, proof)
    except Exception:
        restore()
        raise


def derive_ecdsasd(m: dict[str, Any], selective_pointers: list[str]) -> dict[str, Any]:
    if _derive_proof is None:
        raise NotImplementedError("credential.common.ecdsasd.derive_proof is not available")
    base = find_ecdsasd_proof(m)
    if base is None:
        raise ValueError("jsonmap: credential has no ecdsa-sd-2023 proof to derive from")
    doc_no_proof = body_without_proof(m)
    reveal_doc, derived_value = _derive_proof(doc_no_proof, base.proof_value, selective_pointers)
    derived = base
    derived.proof_value = derived_value
    result = dict(reveal_doc)
    set_single_proof(result, derived)
    return result


def find_ecdsasd_proof(m: dict[str, Any]) -> Proof | None:
    raw = get_first_proof(m)
    if raw is None:
        return None
    try:
        proof = parse_raw_to_proof(raw)
    except ValueError:
        return None
    if proof.type == DATA_INTEGRITY_PROOF and proof.cryptosuite == ECDSA_SD_2023:
        return proof
    return None


def verify_ecdsasd_proof(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    if _verify_proof is None:
        raise NotImplementedError("credential.common.ecdsasd.verify_proof is not available")
    try:
        vm = find_vm_entry(doc, proof.verification_method)
    except ValueError as exc:
        raise ValueError(f"failed to resolve verification method: {exc}") from exc
    pub = pub_from_entry(vm)
    doc_no_proof = body_without_proof(m)
    try:
        proof_config = ecdsa_proof_config(m, proof)
    except ValueError as exc:
        raise ValueError(f"failed to build proof configuration: {exc}") from exc
    _verify_proof(doc_no_proof, proof_config, proof.proof_value, pub)
    strict_purpose_check(doc, vm, proof.proof_purpose, proof.created)
    return True
