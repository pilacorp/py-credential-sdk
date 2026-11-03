from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.crypto.ecdsa_rdfc import ecdsa_verify_signature, verify_ecdsa
from credential.common.dto.proof import Proof, StringOrStrings
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.common.verification_method.verification_method import DIDDocument

from credential.common.jsonmap._constants import (
    DATA_INTEGRITY_PROOF,
    ECDSA_RDFC_2019,
    MULTIBASE_BASE58_BTC_PREFIX,
)
from credential.common.jsonmap._context import context_snapshot, ensure_data_integrity_context
from credential.common.jsonmap._ecdsa_common import (
    ecdsa_hash_data,
    legacy_hex_canonicalize,
)
from credential.common.jsonmap._multibase import decode_multibase_key, encode_multibase_key
from credential.common.jsonmap._options import ProofOptions, SignerProvider, domain_value, new_proof_options
from credential.common.jsonmap._proof_helpers import append_proof, strict_purpose_check, vm_entry_to_dict
from didv2.did.verification_method_ops import find_verification_method


def add_ecdsa_proof(
    m: dict[str, Any],
    signer: SignerProvider,
    verification_method: str,
    proof_purpose: str,
    *,
    options: ProofOptions | None = None,
) -> None:
    if not verification_method:
        raise ValueError("jsonmap: verification method is required")
    if not proof_purpose:
        raise ValueError("jsonmap: proof purpose is required")

    restore = context_snapshot(m)
    try:
        ensure_data_integrity_context(m)
        opts = options or new_proof_options()
        domain = domain_value(opts.domain)
        proof = Proof(
            type=DATA_INTEGRITY_PROOF,
            created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            verification_method=verification_method,
            proof_purpose=proof_purpose,
            cryptosuite=ECDSA_RDFC_2019,
            challenge=opts.challenge,
            domain=domain if domain is not None else StringOrStrings(),
        )
        hash_data = ecdsa_hash_data(m, proof)
        sign_digest = sha256(hash_data).digest()
        signature = signer.sign(sign_digest)
        if len(signature) != 64:
            raise ValueError(
                "jsonmap: ecdsa-rdfc-2019 expects a 64-byte P-256 signature (r||s) but the signer returned "
                f"{len(signature)} bytes; the signer does not match the verification method — "
                "pin the right VM with WithVerificationMethodKey"
            )
        if opts.vm_pub is not None:
            if not verify_ecdsa(opts.vm_pub, sign_digest, signature):
                raise ValueError(
                    f"jsonmap: the signature does not verify against verification method {verification_method!r}; "
                    "the signer does not hold that key"
                )
        proof.proof_value = encode_multibase_key(signature)
        append_proof(m, proof)
    except Exception:
        restore()
        raise


def verify_ecdsa_rdfc(m: dict[str, Any], pub: ec.EllipticCurvePublicKey, proof: Proof) -> bool:
    pv = proof.proof_value
    if pv.startswith(MULTIBASE_BASE58_BTC_PREFIX):
        if not isinstance(pub.curve, ec.SECP256R1):
            raise ValueError(
                f'ecdsa-rdfc-2019: verification method {proof.verification_method!r} uses curve '
                f"{pub.curve.name if hasattr(pub.curve, 'name') else pub.curve!r}, "
                "but this SDK supports P-256 only"
            )
        return _verify_ecdsa_spec_conformant(m, pub, proof)

    doc = legacy_hex_canonicalize(m)
    return ecdsa_verify_signature(pub, pv, doc)


def _verify_ecdsa_spec_conformant(m: dict[str, Any], pub: ec.EllipticCurvePublicKey, proof: Proof) -> bool:
    try:
        signature = decode_multibase_key(proof.proof_value)
    except ValueError as exc:
        raise ValueError(f"failed to decode multibase proofValue: {exc}") from exc
    hash_data = ecdsa_hash_data(m, proof)
    digest = sha256(hash_data).digest()
    if len(signature) != 64:
        raise ValueError(f"ecdsa-rdfc-2019 proofValue decodes to {len(signature)} bytes, want 64 (r||s)")
    return verify_ecdsa(pub, digest, signature)


def verify_data_integrity_proof(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    doc_dict = {
        "id": doc.id,
        "verificationMethod": [vm_entry_to_dict(v) for v in doc.verification_method],
    }
    vm_raw = find_verification_method(doc_dict, proof.verification_method)
    if vm_raw is None:
        raise ValueError(f"failed to resolve verification method: {proof.verification_method!r}")
    pub = ec_pub_from_vm(vm_raw)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("verification method is not P-256")
    ok = verify_ecdsa_rdfc(m, pub, proof)
    if not ok:
        return False
    vm_entry = next(v for v in doc.verification_method if v.id == vm_raw.get("id"))
    strict_purpose_check(doc, vm_entry, proof.proof_purpose, proof.created)
    return True
