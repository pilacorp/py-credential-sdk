from __future__ import annotations

import json
from typing import Any, Protocol

from credential.common.crypto.jwt_proof_2020 import verify_jwt_proof
from credential.common.dto.proof import Proof
from credential.common.verification_method.verification_method import DIDDocument

from credential.common.jsonmap._constants import (
    DATA_INTEGRITY_PROOF,
    ECDSA_RDFC_2019,
    ECDSA_SD_2023,
    ECDSA_SECP256K1_SIGNATURE_2019,
    JSON_WEB_SIGNATURE_2020,
    JWT_PROOF_2020,
)
from credential.common.jsonmap._ecdsa_common import (
    canonicalize_full,
    document_digest,
    ecdsa_hash_data,
    has_multibase_proof,
    legacy_hex_canonicalize,
    proof_hash_data,
)
from credential.common.jsonmap._ecdsa_rdfc import add_ecdsa_proof, verify_data_integrity_proof
from credential.common.jsonmap._ecdsasd import add_ecdsasd_base_proof, derive_ecdsasd, verify_ecdsasd_proof
from credential.common.jsonmap._jws import add_jws_proof, verify_jws_proof
from credential.common.jsonmap._options import new_proof_options
from credential.common.jsonmap._proof_helpers import (
    append_proof,
    did_from_vm_url,
    parse_raw_to_proof,
    proofs,
    strict_purpose_check,
)
from credential.common.jsonmap._secp256k1 import add_ecdsa_secp256k1_proof, verify_ecdsa_secp256k1_proof
from credential.common.jsonmap._vm import find_vm_entry, pub_from_entry
from credential.common.util.b64 import b64url_decode


class ResolverProvider(Protocol):
    def resolve_document(self, did: str) -> DIDDocument: ...


class JSONMap:
    """Mutable JSON-LD document with Data Integrity proof helpers (Go jsonmap.JSONMap port)."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def to_json(self) -> bytes:
        if self.data is None:
            raise ValueError("JSONMap is nil")
        # Go json.Marshal: sorted keys, raw UTF-8, <, >, & and U+2028/2029 escaped.
        text = json.dumps(self.data, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
        for ch, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
            text = text.replace(ch, esc)
        return text.encode("utf-8")

    def to_map(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.data))

    # --- digests -----------------------------------------------------------
    def legacy_hex_canonicalize(self) -> bytes:
        return legacy_hex_canonicalize(self.data)

    def canonicalize_full(self) -> bytes:
        return canonicalize_full(self.data)

    def document_digest(self) -> bytes:
        return document_digest(self.data)

    def proof_hash_data(self, doc_hash: bytes, proof: Proof) -> bytes:
        return proof_hash_data(self.data, doc_hash, proof)

    def ecdsa_hash_data(self, proof: Proof) -> bytes:
        return ecdsa_hash_data(self.data, proof)

    def has_multibase_proof(self) -> bool:
        return has_multibase_proof(self.data)

    def proofs(self) -> list[Proof]:
        return proofs(self.data)

    # --- issuing -----------------------------------------------------------
    def add_ecdsa_proof(self, signer: Any, verification_method: str, purpose: str, **kw: Any) -> None:
        add_ecdsa_proof(self.data, signer, verification_method, purpose, options=new_proof_options(**kw))

    def add_ecdsa_secp256k1_proof(self, signer: Any, verification_method: str, purpose: str, **kw: Any) -> None:
        add_ecdsa_secp256k1_proof(self.data, signer, verification_method, purpose, options=new_proof_options(**kw))

    def add_ecdsasd_base_proof(
        self, signer: Any, verification_method: str, purpose: str, mandatory_pointers: list[str] | None = None, **kw: Any
    ) -> None:
        add_ecdsasd_base_proof(
            self.data, signer, verification_method, purpose, mandatory_pointers, options=new_proof_options(**kw)
        )

    def add_jws_proof(self, signer: Any, verification_method: str, purpose: str) -> None:
        add_jws_proof(self.data, signer, verification_method, purpose)

    def derive_ecdsasd(self, selective_pointers: list[str]) -> dict[str, Any]:
        if self.data is None:
            raise ValueError("jsonmap: JSONMap is nil")
        return derive_ecdsasd(self.data, selective_pointers)

    def add_custom_proof(self, proof: Proof) -> None:
        if proof is None:
            raise ValueError("proof is nil")
        append_proof(self.data, proof)

    # --- verifying ---------------------------------------------------------
    def verify_proof(self, resolver: ResolverProvider, target_vm: str = "") -> bool:
        """Verify the proof set (AND semantics) or only the proof bound to ``target_vm``.
        Returns False for a proof that does not check out, raises ``ValueError`` for malformed input."""
        if resolver is None:
            raise ValueError("document resolver is required")
        try:
            proof_list = self.proofs()
        except ValueError as exc:
            raise ValueError(f"failed to parse proof: {exc}") from exc
        if not proof_list:
            raise ValueError("credential has no proof")

        if target_vm:
            for proof in proof_list:
                if proof.verification_method == target_vm:
                    try:
                        return verify_one_proof(self.data, resolver, proof)
                    except ValueError as exc:
                        raise ValueError(f"proof ({target_vm}): {exc}") from exc
            raise ValueError(f"no proof found for verification method {target_vm!r}")

        for i, proof in enumerate(proof_list):
            try:
                ok = verify_one_proof(self.data, resolver, proof)
            except ValueError as exc:
                raise ValueError(f"proof {i} ({proof.verification_method}): {exc}") from exc
            if not ok:
                return False
        return True

    def verify_detached_proof(self, resolver: ResolverProvider, proof: Proof) -> None:
        """Verify one proof against the document as it stands, before it is attached (rdfc-2019 only)."""
        if proof is None:
            raise ValueError("jsonmap: proof is nil")
        if resolver is None:
            raise ValueError("jsonmap: document resolver is required")
        if proof.type != DATA_INTEGRITY_PROOF or proof.cryptosuite != ECDSA_RDFC_2019:
            suite = proof.type
            if proof.cryptosuite:
                suite += "/" + proof.cryptosuite
            raise ValueError(
                f"jsonmap: a {suite} proof cannot be checked before it is attached; only "
                f"{DATA_INTEGRITY_PROOF}/{ECDSA_RDFC_2019} can — attach it without WithVerifyProof and call Verify instead"
            )
        try:
            ok = verify_one_proof(self.data, resolver, proof)
        except ValueError as exc:
            raise ValueError(f"jsonmap: proof ({proof.verification_method}): {exc}") from exc
        if not ok:
            raise ValueError(
                f"jsonmap: the proof does not verify against verification method {proof.verification_method!r}; "
                "it was signed by another key or over data other than this document"
            )


def verify_one_proof(m: dict[str, Any], resolver: ResolverProvider, proof: Proof) -> bool:
    signer_did = did_for_proof(m, proof)
    try:
        doc = resolver.resolve_document(signer_did)
    except Exception as exc:
        raise ValueError(f"failed to resolve DID document for '{signer_did}': {exc}") from exc

    if proof.type == JWT_PROOF_2020:
        return verify_jwt_proof_doc(m, doc, proof)
    # One type, one verifier: a proof's own key is never trusted (issuer-forgery #89).
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
    """The DID embedded in the proof's own verificationMethod; no fallback to issuer/holder (#89)."""
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
    if isinstance(proof, dict):
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
    try:
        hdr = json.loads(b64url_decode(jws[:dot]))
    except (ValueError, UnicodeDecodeError):
        return "", False
    kid = hdr.get("kid") if isinstance(hdr, dict) else None
    if isinstance(kid, str) and kid:
        return kid, True
    return "", False


def verify_jwt_proof_doc(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    vm_url, err = jwt_verification_method_url(m)
    if err is not None:
        raise err
    try:
        vm = find_vm_entry(doc, vm_url)
    except ValueError as exc:
        raise ValueError(f"failed to resolve verification method: {exc}") from exc
    pub = pub_from_entry(vm)
    from eth_keys import keys

    if not isinstance(pub, keys.PublicKey):
        raise ValueError("JwtProof2020 expects a secp256k1 verification method")
    if not verify_jwt_proof(m, pub.to_compressed_bytes()):
        return False
    strict_purpose_check(doc, vm, "assertionMethod", proof.created)
    return True
