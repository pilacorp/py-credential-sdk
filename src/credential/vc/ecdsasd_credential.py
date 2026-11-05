"""ecdsa-sd-2023 credential: port of Go credential/vc/ecdsasd_credential.go."""

from __future__ import annotations

from typing import Any

from credential.common.verification_method import KeyKind, vm_key_kind
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.vc import credential_helper as helper
from credential.vc.credential import Credential, CredentialOpt, get_options, refuse_replace_on_jsonld, signing_options
from credential.vc.json_credential import JSONCredential


class ECDSASDCredential(Credential):
    """A JSON-LD credential signed with ecdsa-sd-2023: issuers sign a base proof, holders ``derive``."""

    def __init__(self, base: JSONCredential) -> None:
        self._base = base

    @classmethod
    def create(cls, vcc: Any, *opts: CredentialOpt) -> "ECDSASDCredential":
        return cls(JSONCredential.create(vcc, *opts))

    @classmethod
    def parse(cls, raw: str | bytes, *opts: CredentialOpt) -> "ECDSASDCredential":
        return cls(JSONCredential.parse(raw, *opts))

    @property
    def data(self) -> dict[str, Any]:
        return self._base.credential_data

    def add_proof_by_provider(self, signer: Any, mandatory_paths: list[str] | None = None, *opts: CredentialOpt) -> None:
        """Sign into an ecdsa-sd-2023 base proof. ``mandatory_paths`` (JSON pointers or dot paths) are always
        disclosed; the VM (pinned or default) must hold a P-256 key."""
        if signer is None:
            raise ValueError("signer provider cannot be nil")
        refuse_replace_on_jsonld(get_options(*opts))
        self._base._execute_options(*signing_options(list(opts)))
        vm = self._base.resolve_signing_vm_entry(*opts)
        kind, ok = vm_key_kind(vm)
        if not ok:
            raise ValueError(f"verification method {vm.id!r} has an unrecognized key type")
        if kind != KeyKind.P256:
            raise ValueError(f"unsupported key kind {kind} for ecdsa-sd-2023 credential")
        try:
            vm_pub = ec_pub_from_vm(vm)
        except ValueError as exc:
            raise ValueError(f"verification method {vm.id!r}: {exc}") from exc
        self._base._jm().add_ecdsasd_base_proof(
            signer, vm.id, "assertionMethod", helper.dot_paths_to_pointers(mandatory_paths), vm_pub=vm_pub
        )

    def derive(self, selective_paths: list[str] | None = None) -> JSONCredential:
        """New credential revealing the mandatory claims plus ``selective_paths``; the receiver is unchanged."""
        try:
            derived = self._base._jm().derive_ecdsasd(helper.dot_paths_to_pointers(selective_paths))
        except ValueError as exc:
            raise ValueError(f"failed to derive selective disclosure: {exc}") from exc
        return JSONCredential(derived)

    # forwarded consumer surface
    def verify(self, *opts: CredentialOpt) -> None:
        self._base.verify(*opts)

    def serialize(self) -> dict[str, Any]:
        return self._base.serialize()

    def get_contents(self) -> bytes:
        return self._base.get_contents()

    def get_type(self) -> str:
        return self._base.get_type()

    def hash(self) -> str:
        return self._base.hash()

    def extract_field(self, path: str) -> Any:
        return self._base.extract_field(path)
