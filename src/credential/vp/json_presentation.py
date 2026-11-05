from __future__ import annotations

import hashlib
import json
from typing import Any

from credential.common.dto.proof import Proof
from credential.common.jsonmap import JSONMap, new_proof_options
from credential.common.jsonmap._constants import (
    DATA_INTEGRITY_PROOF,
    ECDSA_RDFC_2019,
    ECDSA_SECP256K1_SIGNATURE_2019,
)
from credential.common.jwt.jwtutil import json_loads
from credential.common.signer.p256 import P256Provider
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.common.verification_method.resolve import resolve_signing_vm
from credential.common.verification_method.selector import KeyKind, vm_key_kind
from credential.vp.presentation import (
    AudienceUnboundError,
    Presentation,
    PresentationContents,
    PresentationOpt,
    get_options,
    is_json_presentation,
    refuse_replace_on_jsonld,
    signing_options,
)
from credential.vp.presentation_helper import (
    PresentationData,
    check_expiration,
    did_from_field,
    extract_field_from_map,
    serialize_presentation_contents,
    verify_credentials,
)

MULTIBASE_BASE58BTC_PREFIX = "z"


class JSONPresentation(Presentation):
    def __init__(self, presentation_data: PresentationData) -> None:
        self.presentation_data = presentation_data

    @classmethod
    def create(cls, vpc: PresentationContents, *opts: PresentationOpt) -> JSONPresentation:
        try:
            m = serialize_presentation_contents(vpc)
        except ValueError as exc:
            raise ValueError(f"failed to serialize presentation contents: {exc}") from exc
        e = cls(m)
        e._execute_options(*opts)
        return e

    @classmethod
    def parse(cls, raw: bytes | str, *opts: PresentationOpt) -> JSONPresentation:
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if not raw:
            raise ValueError("JSON string is empty")
        if not is_json_presentation(raw):
            raise ValueError("invalid JSON format")
        e = cls(json_loads(raw))
        e._execute_options(*opts)
        return e

    def add_proof(self, priv_hex: str, *opts: PresentationOpt) -> None:
        """Deprecated: prefer add_proof_by_provider."""
        h = priv_hex[2:] if priv_hex.startswith("0x") else priv_hex
        try:
            b = bytes.fromhex(h)
        except ValueError as exc:
            raise ValueError(f"failed to create P-256 signer: decode p256 private key hex: {exc}") from exc
        self.add_proof_by_provider(P256Provider(b.rjust(32, b"\x00") if 0 < len(b) < 32 else b), *opts)

    def add_proof_by_provider(self, provider: Any, *opts: PresentationOpt) -> None:
        """Sign bound to the pinned VM (or the holder's only / latest active authentication VM).

        The suite follows the VM's key: P-256 -> ecdsa-rdfc-2019, secp256k1 ->
        EcdsaSecp256k1Signature2019. A resolver is required."""
        if provider is None:
            raise ValueError("signer provider cannot be nil")
        refuse_replace_on_jsonld(get_options(*opts))
        self._execute_options(*signing_options(opts))
        vm = self._resolve_signing_vm(*opts)
        kind, ok = vm_key_kind(vm)
        if not ok:
            raise ValueError(f"verification method {vm.id!r} has an unrecognized key type")
        options = get_options(*opts)
        if kind not in (KeyKind.P256, KeyKind.SECP256K1):
            raise ValueError(f"unsupported key kind {kind} for JSON-LD signing")
        try:
            vm_pub = ec_pub_from_vm(vm)
        except ValueError as exc:
            raise ValueError(f"verification method {vm.id!r}: {exc}") from exc
        m = JSONMap(self.presentation_data)
        kw = dict(vm_pub=vm_pub, challenge=options.challenge, domain=options.domain)
        if kind == KeyKind.SECP256K1:
            m.add_ecdsa_secp256k1_proof(provider, vm.id, "authentication", **kw)
        else:
            m.add_ecdsa_proof(provider, vm.id, "authentication", **kw)

    def _resolve_signing_vm(self, *opts: PresentationOpt):
        holder, ok = did_from_field(self.presentation_data.get("holder"))
        if not ok:
            raise ValueError("holder is missing or invalid")
        options = get_options(*opts)
        return resolve_signing_vm(holder, "authentication", options.verification_method_key, options.resolver)

    def get_signing_input(self) -> bytes:
        """SHA-256 digest of the canonicalized document body."""
        return JSONMap(self.presentation_data).document_digest()

    def create_proof_signing(self, doc_hash: bytes, proof: Proof) -> bytes:
        """32-byte digest an external signer signs (SHA-256 of the section 3.2.4 hashData)."""
        return hashlib.sha256(JSONMap(self.presentation_data).proof_hash_data(doc_hash, proof)).digest()

    def add_custom_proof(self, proof: Proof | None, *opts: PresentationOpt) -> None:
        """Attach a proof signed outside the SDK; with_verify_proof checks it first."""
        if proof is None:
            raise ValueError("proof cannot be nil")
        refuse_replace_on_jsonld(get_options(*opts))
        if (
            proof.type == DATA_INTEGRITY_PROOF
            and proof.cryptosuite == ECDSA_RDFC_2019
            and not proof.proof_value.startswith(MULTIBASE_BASE58BTC_PREFIX)
        ):
            raise ValueError(
                f'proofValue must be multibase base58btc ("{MULTIBASE_BASE58BTC_PREFIX}" prefix); '
                "hex proofs are no longer issued"
            )
        options = get_options(*opts)
        if options.challenge or options.domain or options.verification_method_key:
            raise ValueError(
                "WithChallenge / WithDomain / WithVerificationMethodKey cannot be applied by AddCustomProof: "
                "set proof.Challenge, proof.Domain and proof.VerificationMethod on the proof you sign"
            )
        m = JSONMap(self.presentation_data)
        if options.is_verify_proof:
            m.verify_detached_proof(options.resolver, proof)
        self._execute_options(*signing_options(opts))
        m.add_custom_proof(proof)

    def verify(self, *opts: PresentationOpt) -> None:
        from credential.vp.presentation import with_verify_proof

        self._execute_options(*opts, with_verify_proof())

    def serialize(self) -> dict[str, Any]:
        if self.presentation_data.get("proof") is None:
            raise ValueError("presentation must have proof before serialization")
        return self.presentation_data

    def get_contents(self) -> bytes:
        return JSONMap(self.presentation_data).to_json()

    def get_type(self) -> str:
        return "JSON"

    def extract_field(self, path: str) -> Any:
        return extract_field_from_map(self.presentation_data, path)

    def _execute_options(self, *opts: PresentationOpt) -> None:
        options = get_options(*opts)
        if options.is_validate_vc:
            try:
                verify_credentials(self.presentation_data, options)
            except ValueError as exc:
                raise ValueError(f"failed to verify presentation: {exc}") from exc
        if options.is_check_expiration:
            try:
                check_expiration(self.presentation_data, options.leeway)
            except ValueError as exc:
                raise ValueError(f"failed to check expiration: {exc}") from exc
        if options.is_verify_proof:
            try:
                ok = JSONMap(self.presentation_data).verify_proof(options.resolver, options.proof_verification_method)
            except ValueError as exc:
                raise ValueError(f"failed to verify presentation: {exc}") from exc
            if not ok:
                raise ValueError("invalid proof")
            try:
                self._check_challenge_and_domain(options)
            except ValueError as exc:
                raise ValueError(f"failed to verify presentation: {exc}") from exc

    def _check_challenge_and_domain(self, options) -> None:
        """Enforce expected challenge/domain on the proofs verify_proof just validated.

        Runs after signature verification. Only ecdsa-rdfc-2019 signs its challenge and
        domain; on legacy hex / JsonWebSignature2020 proofs these values are unbound."""
        if options.require_audience and not options.expected_domain:
            raise AudienceUnboundError()
        if not options.expected_challenge and not options.expected_domain:
            return
        for p in JSONMap(self.presentation_data).proofs():
            if options.proof_verification_method and p.verification_method != options.proof_verification_method:
                continue
            if options.expected_challenge and p.challenge != options.expected_challenge:
                raise ValueError(
                    f"proof ({p.verification_method}): challenge {p.challenge!r} does not match "
                    f"expected {options.expected_challenge!r}"
                )
            if options.expected_domain and options.expected_domain not in p.domain.values:
                raise ValueError(
                    f"proof ({p.verification_method}): domain {p.domain.values} does not match "
                    f"expected {options.expected_domain!r}"
                )


def new_json_presentation(vpc: PresentationContents, *opts: PresentationOpt) -> JSONPresentation:
    return JSONPresentation.create(vpc, *opts)


def parse_json_presentation(raw: bytes | str, *opts: PresentationOpt) -> JSONPresentation:
    return JSONPresentation.parse(raw, *opts)
