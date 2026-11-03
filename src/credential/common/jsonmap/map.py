from __future__ import annotations

import base64
import json
from typing import Any, Protocol

from credential.common.crypto.jwt_proof_2020 import verify_jwt_proof
from credential.common.dto.proof import Proof
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.common.verification_method.verification_method import DIDDocument

from credential.common.jsonmap._constants import (
    DATA_INTEGRITY_PROOF,
    ECDSA_RDFC_2019,
    ECDSA_SD_2023,
    ECDSA_SECP256K1_SIGNATURE_2019,
    JSON_WEB_SIGNATURE_2020,
    JWT_PROOF_2020,
)
from credential.common.jsonmap._ecdsa_common import has_multibase_proof, legacy_hex_canonicalize
from credential.common.jsonmap._ecdsa_rdfc import verify_data_integrity_proof, verify_ecdsa_rdfc
from credential.common.jsonmap._ecdsasd import ResolverProvider, verify_ecdsasd_proof
from credential.common.jsonmap._jws import verify_jws_proof
from credential.common.jsonmap._proof_helpers import (
    did_from_vm_url,
    get_first_proof,
    parse_raw_to_proof,
    proofs,
    strict_purpose_check,
    vm_entry_to_dict,
)
from credential.common.jsonmap._secp256k1 import verify_ecdsa_secp256k1_proof
from didv2.did.verification_method_ops import find_verification_method


class JSONMap:
    """Mutable JSON-LD document with Data Integrity proof helpers (Go jsonmap.JSONMap port)."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def to_json(self) -> bytes:
        if self.data is None:
            raise ValueError("JSONMap is nil")
        raw = json.dumps(self.data, separators=(",", ":"), ensure_ascii=True).encode()
        json.loads(raw)
        return raw

    def to_map(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.data))

    def legacy_hex_canonicalize(self) -> bytes:
        return legacy_hex_canonicalize(self.data)

    def has_multibase_proof(self) -> bool:
        return has_multibase_proof(self.data)

    def proofs(self) -> list[Proof]:
        return proofs(self.data)

    def verify_proof(self, resolver: ResolverProvider, target_vm: str = "") -> tuple[bool, None] | tuple[bool, str]:
        if resolver is None:
            raise ValueError("document resolver is required")
        proof_list = self.proofs()
        if not proof_list:
            raise ValueError("credential has no proof")

        if target_vm:
            for proof in proof_list:
                if proof.verification_method == target_vm:
                    ok = verify_one_proof(self.data, resolver, proof)
                    return ok, None
            raise ValueError(f"no proof found for verification method {target_vm!r}")

        for i, proof in enumerate(proof_list):
            ok = verify_one_proof(self.data, resolver, proof)
            if not ok:
                return False, None
        return True, None

    def verify_detached_proof(self, resolver: ResolverProvider, proof: Proof) -> None:
        if proof.type != DATA_INTEGRITY_PROOF or proof.cryptosuite != ECDSA_RDFC_2019:
            suite = proof.type
            if proof.cryptosuite:
                suite += "/" + proof.cryptosuite
            raise ValueError(
                f"jsonmap: a {suite} proof cannot be checked before it is attached; only "
                f"{DATA_INTEGRITY_PROOF}/{ECDSA_RDFC_2019} can — attach it without WithVerifyProof and call Verify instead"
            )
        ok = verify_one_proof(self.data, resolver, proof)
        if not ok:
            raise ValueError(
                f"jsonmap: the proof does not verify against verification method {proof.verification_method!r}; "
                "it was signed by another key or over data other than this document"
            )


def verify_one_proof(m: dict[str, Any], resolver: ResolverProvider, proof: Proof) -> bool:
    signer_did = did_for_proof(m, proof)
    doc = resolver.resolve_document(signer_did)

    if proof.type == JWT_PROOF_2020:
        return verify_jwt_proof_doc(m, doc, proof)
    if proof.type == ECDSA_SECP256K1_SIGNATURE_2019:
        return verify_ecdsa_secp256k1_proof(m, doc, proof)
    if proof.type == DATA_INTEGRITY_PROOF and proof.cryptosuite == ECDSA_RDFC_2019:
        return verify_data_integrity_proof(m, doc, proof)
    if proof.type == DATA_INTEGRITY_PROOF and proof.cryptosuite == ECDSA_SD_2023:
        return verify_ecdsasd_proof(m, doc, proof)
    if proof.type == JSON_WEB_SIGNATURE_2020:
        return verify_jws_proof(m, doc, proof)
    raise ValueError(f"unsupported proof type: {proof.type}")


def did_for_proof(m: dict[str, Any], proof: Proof) -> str:
    did = did_from_vm_url(proof.verification_method)
    if did:
        return did
    if proof.type == JWT_PROOF_2020:
        vm_url, err = jwt_verification_method_url(m)
        if err is None:
            did = did_from_vm_url(vm_url)
            if did:
                return did
    raise ValueError(
        f"proof verificationMethod {proof.verification_method!r} is not a DID URL; "
        "it must name a key in the signer's DID document"
    )


def jwt_verification_method_url(m: dict[str, Any]) -> tuple[str, Exception | None]:
    proof = m.get("proof")
    if isinstance(proof, list) and proof:
        proof = proof[0]
    if not isinstance(proof, dict):
        return "", ValueError("token is missing verification method id (kid/verificationMethod)")
    vm = proof.get("verificationMethod")
    if isinstance(vm, str) and vm:
        return vm, None
    jws = proof.get("jws")
    if isinstance(jws, str) and jws:
        kid, ok = jws_kid(jws)
        if ok and kid:
            return kid, None
    return "", ValueError("token is missing verification method id (kid/verificationMethod)")


def jws_kid(jws: str) -> tuple[str, bool]:
    dot = jws.find(".")
    if dot <= 0:
        return "", False
    header_b64 = jws[:dot]
    try:
        header_bytes = base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4))
        hdr = json.loads(header_bytes)
    except (ValueError, json.JSONDecodeError):
        return "", False
    kid = hdr.get("kid")
    if isinstance(kid, str) and kid:
        return kid, True
    return "", False


def verify_jwt_proof_doc(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    vm_url, err = jwt_verification_method_url(m)
    if err is not None:
        raise err
    doc_dict = {
        "id": doc.id,
        "verificationMethod": [vm_entry_to_dict(v) for v in doc.verification_method],
    }
    vm_raw = find_verification_method(doc_dict, vm_url)
    if vm_raw is None:
        raise ValueError(f"failed to resolve verification method: {vm_url!r}")
    pub = ec_pub_from_vm(vm_raw)
    from eth_keys import keys

    if isinstance(pub, keys.PublicKey):
        compressed = pub.to_compressed_bytes()
    else:
        raise ValueError("JwtProof2020 expects a secp256k1 verification method")
    ok = verify_jwt_proof(m, compressed)
    if not ok:
        return False
    vm_entry = next(v for v in doc.verification_method if v.id == vm_raw.get("id"))
    strict_purpose_check(doc, vm_entry, "assertionMethod", proof.created)
    return True
