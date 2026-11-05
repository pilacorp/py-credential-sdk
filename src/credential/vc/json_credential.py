"""JSON-LD (Data Integrity) credential: port of Go credential/vc/json_credential.go."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from credential.common.dto.proof import Proof
from credential.common.jsonmap import JSONMap, signing_suite_for_key
from credential.common.jsonmap._constants import (
    DATA_INTEGRITY_PROOF,
    ECDSA_RDFC_2019,
    ECDSA_SECP256K1_SIGNATURE_2019,
    MULTIBASE_BASE58_BTC_PREFIX,
)
from credential.common.processor import canonicalize
from credential.common.signer.p256 import P256Provider
from credential.common.verification_method import resolve_signing_vm, vm_key_kind
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.vc import credential_helper as helper
from credential.vc.credential import (
    Credential,
    CredentialOpt,
    CredentialOptions,
    get_options,
    refuse_replace_on_jsonld,
    run_options,
    signing_options,
    with_verify_proof,
)
from credential.vc.helper import serialize_credential_contents

CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"


def require_v2_context(v: Any) -> None:
    first = ""
    if isinstance(v, str):
        first = v
    elif isinstance(v, list) and v and isinstance(v[0], str):
        first = v[0]
    if first != CREDENTIALS_V2_CONTEXT:
        raise ValueError(f"credential must name {CREDENTIALS_V2_CONTEXT!r} first in @context, got {first!r}")


def require_credential_type(v: Any) -> None:
    if not helper.has_type(v, "VerifiableCredential"):
        raise ValueError(f"credential type must include VerifiableCredential, got {v}")


def require_jose_credential(m: dict[str, Any]) -> None:
    """A vc+jwt payload must be the VC 2.0 credential its media type claims (Go requireJOSECredential)."""
    helper.require_credential_properties(m)
    require_v2_context(m.get("@context"))
    require_credential_type(m.get("type"))


class JSONCredential(Credential):
    def __init__(self, data: dict[str, Any]) -> None:
        self.credential_data = data

    # ---- construction ------------------------------------------------------
    @classmethod
    def create(cls, vcc: Any, *opts: CredentialOpt) -> "JSONCredential":
        try:
            m = serialize_credential_contents(vcc)
        except ValueError as exc:
            raise ValueError(f"failed to serialize credential contents: {exc}") from exc
        e = cls(m)
        e._execute_options(*opts)
        return e

    @classmethod
    def parse(cls, raw: str | bytes, *opts: CredentialOpt) -> "JSONCredential":
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if not _is_json_object(raw):
            raise ValueError("invalid JSON format")
        m = json.loads(raw)
        helper.require_credential_properties(m)
        e = cls(m)
        e._execute_options(*opts)
        return e

    @property
    def data(self) -> dict[str, Any]:
        return self.credential_data

    def _jm(self) -> JSONMap:
        return JSONMap(self.credential_data)

    # ---- signing -----------------------------------------------------------
    def add_proof(self, priv: str, *opts: CredentialOpt) -> None:
        """Sign with a raw P-256 private key (hex scalar). Deprecated: prefer add_proof_by_provider."""
        try:
            provider = P256Provider.from_hex(priv)
        except ValueError as exc:
            raise ValueError(f"failed to create P-256 signer: {exc}") from exc
        self.add_proof_by_provider(provider, *opts)

    def add_proof_by_provider(self, provider: Any, *opts: CredentialOpt) -> None:
        """Sign with a provider bound to the pinned / default assertionMethod VM. The suite follows the
        VM's key: P-256 -> ecdsa-rdfc-2019, secp256k1 -> EcdsaSecp256k1Signature2019; RSA is rejected."""
        if provider is None:
            raise ValueError("signer provider cannot be nil")
        refuse_replace_on_jsonld(get_options(*opts))
        self._execute_options(*signing_options(list(opts)))

        vm = self.resolve_signing_vm_entry(*opts)
        kind, ok = vm_key_kind(vm)
        if not ok:
            raise ValueError(f"verification method {vm.id!r} has an unrecognized key type")
        suite = signing_suite_for_key(kind)
        try:
            vm_pub = ec_pub_from_vm(vm)
        except ValueError as exc:
            raise ValueError(f"verification method {vm.id!r}: {exc}") from exc

        m = self._jm()
        if suite == ECDSA_SECP256K1_SIGNATURE_2019:
            m.add_ecdsa_secp256k1_proof(provider, vm.id, "assertionMethod", vm_pub=vm_pub)
        else:
            m.add_ecdsa_proof(provider, vm.id, "assertionMethod", vm_pub=vm_pub)

    def resolve_signing_vm_entry(self, *opts: CredentialOpt):
        """Resolve the VM to sign with; the entry lets the caller read its key type and pick the suite."""
        issuer, ok = helper.did_from_field(self.credential_data.get("issuer"))
        if not ok:
            raise ValueError("issuer is missing or invalid")
        options = get_options(*opts)
        return resolve_signing_vm(issuer, "assertionMethod", options.verification_method_key, options.resolver)

    # ---- external signing --------------------------------------------------
    def get_signing_input(self) -> bytes:
        """SHA-256 of the canonicalized document body (input of create_proof_signing)."""
        return self._jm().document_digest()

    def create_proof_signing(self, doc_hash: bytes, proof: Proof) -> bytes:
        """32-byte digest the external signer signs: SHA-256 of the section 3.2.4 hashData."""
        return sha256(self._jm().proof_hash_data(doc_hash, proof)).digest()

    def add_custom_proof(self, proof: Proof, *opts: CredentialOpt) -> None:
        """Attach a proof signed outside the SDK; with ``with_verify_proof()`` it is checked first
        (rdfc-2019 only) so a wrong digest / key fails here and leaves the credential untouched."""
        if proof is None:
            raise ValueError("proof cannot be nil")
        options = get_options(*opts)
        refuse_replace_on_jsonld(options)
        if (
            proof.type == DATA_INTEGRITY_PROOF
            and proof.cryptosuite == ECDSA_RDFC_2019
            and not proof.proof_value.startswith(MULTIBASE_BASE58_BTC_PREFIX)
        ):
            raise ValueError(
                f"proofValue must be multibase base58btc ({MULTIBASE_BASE58_BTC_PREFIX!r} prefix); hex proofs are no longer issued"
            )
        # The proof arrives signed: its verificationMethod is part of the configuration it covers.
        if options.verification_method_key:
            raise ValueError(
                "WithVerificationMethodKey cannot be applied by AddCustomProof: set proof.VerificationMethod on the proof you sign"
            )
        m = self._jm()
        if options.is_verify_proof:
            m.verify_detached_proof(options.resolver, proof)
        self._execute_options(*signing_options(list(opts)))
        m.add_custom_proof(proof)

    # ---- consumer surface --------------------------------------------------
    def verify(self, *opts: CredentialOpt) -> None:
        self._execute_options(*opts, with_verify_proof())

    def serialize(self) -> dict[str, Any]:
        if self.credential_data.get("proof") is None:
            raise ValueError("credential must have proof before serialization")
        return self._jm().to_map()

    def to_json(self) -> str:
        return json.dumps(self.serialize(), separators=(",", ":"), ensure_ascii=False)

    def hash(self) -> str:
        """Hex SHA-256 of the URDNA2015 canonical full credential, proof included (the Merkle leaf).
        Data Integrity ("z"/"u") proofs hash through the strict canonicalizer; legacy hex keeps the legacy one."""
        if self.credential_data.get("proof") is None:
            raise ValueError("credential must have proof before hashing")
        m = self._jm()
        if m.has_multibase_proof():
            try:
                digest = sha256(canonicalize(m.to_map())).digest()
            except ValueError as exc:
                raise ValueError(f"failed to canonicalize credential: {exc}") from exc
        else:
            try:
                digest = m.canonicalize_full()
            except ValueError as exc:
                raise ValueError(f"failed to canonicalize credential: {exc}") from exc
        return digest.hex()

    def get_contents(self) -> bytes:
        return self._jm().to_json()

    def get_type(self) -> str:
        return "JSON"

    def extract_field(self, path: str) -> Any:
        if not self.credential_data:
            return None
        return helper.extract_field_from_map(self.credential_data, path)

    def _execute_options(self, *opts: CredentialOpt) -> None:
        options: CredentialOptions = get_options(*opts)

        def verify() -> None:
            ok = JSONMap(self.credential_data).verify_proof(options.resolver, options.proof_verification_method)
            if not ok:
                raise ValueError("invalid proof")

        run_options(self.credential_data, options, verify)


def _is_json_object(raw: bytes) -> bool:
    if not raw:
        return False
    try:
        return isinstance(json.loads(raw), dict)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
