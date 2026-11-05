from __future__ import annotations

import base64
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Protocol

from credential.common.sdjwt.helper import b64url_decode, is_jwt, is_sd_jwt
from credential.vc import credential_helper as helper

CredentialData = helper.CredentialData
SchemaLoaderFunc = helper.SchemaLoaderFunc

DEFAULT_BASE_URL = "https://api.ndadid.vn/api/v1/did"
_config_base_url = DEFAULT_BASE_URL

TYPE_VC_JWT = "vc+jwt"
TYPE_VC_SD_JWT = "vc+sd-jwt"
TYPE_ENVELOPED_VC = "EnvelopedVerifiableCredential"

ERR_SDJWT_REQUIRES_JOSE = ValueError(
    "selective disclosure is supported only as vc+sd-jwt; use NewJOSECredential / ParseJOSECredential"
)


def init(base_url: str = "") -> None:
    global _config_base_url
    if base_url:
        _config_base_url = base_url


@dataclass
class Status:
    id: str = ""
    type: str = ""
    status_purpose: str = ""
    status_list_index: str = ""
    status_list_credential: str = ""


@dataclass
class Subject:
    id: str = ""
    custom_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class Schema:
    id: str = ""
    type: str = ""


@dataclass
class TermsOfUse:
    id: str = ""
    type: str = ""


@dataclass
class Decoy:
    path: str = ""
    count: int = 0


@dataclass
class CredentialContents:
    context: list[Any] = field(default_factory=list)
    id: str = ""
    types: list[str] = field(default_factory=list)
    issuer: str = ""
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    credential_status: list[Status] = field(default_factory=list)
    subject: list[Subject] = field(default_factory=list)
    schemas: list[Schema] = field(default_factory=list)
    terms_of_use: list[TermsOfUse] = field(default_factory=list)


from credential.common.verification_method import HTTPResolver, ResolverProvider  # noqa: E402,F401


@dataclass
class CredentialOptions:
    is_validate_schema: bool = False
    is_verify_proof: bool = False
    is_check_expiration: bool = False
    leeway: timedelta = timedelta(0)
    is_check_revocation: bool = False
    did_base_url: str = DEFAULT_BASE_URL
    verification_method_key: str = ""
    sd_disclosures: list[str] = field(default_factory=list)
    sd_selective_paths: list[str] = field(default_factory=list)
    sd_alg: str = ""
    sd_shuffle: bool = False
    sd_decoys: list[Decoy] = field(default_factory=list)
    loaded_schema_loader: SchemaLoaderFunc | None = None
    resolver: ResolverProvider | None = None
    proof_verification_method: str = ""
    replace_proof: bool = False

    def has_sd_options(self) -> bool:
        return bool(
            self.sd_disclosures
            or self.sd_selective_paths
            or self.sd_alg
            or self.sd_shuffle
            or self.sd_decoys
        )


CredentialOpt = Callable[[CredentialOptions], None]


def with_replace_proof() -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.replace_proof = True

    return apply


def with_proof_verification_method(vm: str) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.proof_verification_method = vm

    return apply


def with_base_url(base_url: str) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.did_base_url = base_url

    return apply


def with_verification_method_key(key: str) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        if key:
            opts.verification_method_key = key

    return apply


def with_schema_validation() -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.is_validate_schema = True

    return apply


def with_verify_proof() -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.is_verify_proof = True

    return apply


def with_check_expiration() -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.is_check_expiration = True

    return apply


def with_leeway(delta: timedelta) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.leeway = max(delta, timedelta(0))

    return apply


def with_check_revocation() -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.is_check_revocation = True

    return apply


def with_sd_disclosures(disclosures: list[str]) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.sd_disclosures = list(disclosures)

    return apply


def with_sd_selective_paths(paths: list[str]) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.sd_selective_paths = list(paths)

    return apply


def with_sd_hash_algorithm(alg: str) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.sd_alg = alg

    return apply


def with_sd_shuffle(enabled: bool = True) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.sd_shuffle = enabled

    return apply


def with_sd_decoy_digests(decoys: list[Decoy]) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.sd_decoys = list(decoys)

    return apply


def with_schema_loader(loader: SchemaLoaderFunc | None) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        if loader is not None:
            opts.loaded_schema_loader = loader

    return apply


def with_resolver(resolver: ResolverProvider | None) -> CredentialOpt:
    def apply(opts: CredentialOptions) -> None:
        opts.resolver = resolver

    return apply


def signing_options(opts: list[CredentialOpt]) -> list[CredentialOpt]:
    def disable_verify(o: CredentialOptions) -> None:
        o.is_verify_proof = False

    return [*opts, disable_verify]


def refuse_overwrite(current: str, options: CredentialOptions) -> None:
    """A JWT holds one signature: signing again replaces it, so it needs ``with_replace_proof()``."""
    if not current or options.replace_proof:
        return
    raise ValueError(
        "credential is already signed; signing again would replace that signature — pass WithReplaceProof to do so deliberately"
    )


def refuse_replace_on_jsonld(options: CredentialOptions) -> None:
    """JSON-LD signing appends to the proof set, so ``with_replace_proof()`` is refused rather than ignored."""
    if not options.replace_proof:
        return
    raise ValueError(
        "WithReplaceProof does not apply to JSON-LD: proofs are appended to the proof set, not replaced; "
        "build a new credential without the proof to re-sign"
    )


def run_options(
    credential_data: CredentialData,
    options: CredentialOptions,
    verify_proof: Callable[[], None] | None = None,
) -> None:
    """Schema / revocation / proof checks (first failure wins), then the validity window (Go executeOptions)."""
    errors: list[str] = []
    if options.is_validate_schema:
        try:
            helper.validate_credential(credential_data, options)
        except Exception as exc:
            errors.append(f"validate credential: {exc}")
    if not errors and options.is_check_revocation:
        try:
            helper.check_revocation(credential_data)
        except Exception as exc:
            errors.append(f"check revocation: {exc}")
    if not errors and options.is_verify_proof and verify_proof is not None:
        try:
            verify_proof()
        except Exception as exc:
            errors.append(f"verify proof: {exc}")
    if errors:
        raise ValueError(f"credential verification failed: {errors[0]}")
    if options.is_check_expiration:
        try:
            helper.check_expiration(credential_data, options.leeway)
        except Exception as exc:
            raise ValueError(f"failed to check expiration: {exc}") from exc


def get_options(*opts: CredentialOpt) -> CredentialOptions:
    options = CredentialOptions(did_base_url=_config_base_url)
    for opt in opts:
        opt(options)
    if options.resolver is None:
        options.resolver = HTTPResolver(options.did_base_url)
    return options


class Credential(ABC):
    @abstractmethod
    def extract_field(self, path: str) -> Any: ...

    def get_contents(self) -> bytes:
        raise NotImplementedError


class ParsedJWTCredential(Credential):
    def __init__(
        self,
        signing_input: str,
        payload_data: CredentialData,
        jwt_claims: dict[str, Any] | None = None,
        signature: str = "",
    ) -> None:
        self.signing_input = signing_input
        self.payload_data = payload_data
        self.jwt_claims = jwt_claims or {}
        self.signature = signature

    def extract_field(self, path: str) -> Any:
        if not self.payload_data:
            return None
        return helper.extract_field_from_map(self.payload_data, path)

    def get_contents(self) -> bytes:
        return json.dumps(self.payload_data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def get_type(self) -> str:
        return "JWT"


def subject_from_json(subject_obj: CredentialData) -> Subject:
    try:
        ident = helper.parse_string_field(subject_obj, "id")
    except ValueError as exc:
        raise ValueError(f"failed to parse subject id: {exc}") from exc
    _, rest = helper.split_json_obj(subject_obj, "id")
    return Subject(id=ident, custom_fields=rest)


def serialize_credential_contents(vcc: CredentialContents | None) -> CredentialData:
    return helper.serialize_credential_contents(vcc)


def _execute_options(credential_data: CredentialData, opts: list[CredentialOpt]) -> None:
    run_options(credential_data, get_options(*opts))


def parse_json_credential(raw_json: bytes | str, *opts: CredentialOpt) -> Credential:
    from credential.vc.json_credential import JSONCredential

    return JSONCredential.parse(raw_json, *opts)


def parse_jwt_credential(raw_jwt: str, *opts: CredentialOpt) -> Any:
    from credential.vc.jwt_credential import JWTCredential

    return JWTCredential.parse(raw_jwt, *opts)


def new_jwt_credential(vcc: CredentialContents, *opts: CredentialOpt) -> Any:
    from credential.vc.jwt_credential import JWTCredential

    return JWTCredential.create(vcc, *opts)


def _b64url_json(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _is_jose_credential_typ(typ: str) -> bool:
    return typ in (
        TYPE_VC_JWT,
        f"application/{TYPE_VC_JWT}",
        TYPE_VC_SD_JWT,
        f"application/{TYPE_VC_SD_JWT}",
    )


def _is_json_credential(raw: bytes) -> bool:
    if not raw:
        return False
    try:
        text = raw.decode("utf-8")
        json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    obj = json.loads(raw)
    return isinstance(obj, dict)


def _is_jwt_credential(val: str) -> bool:
    val = val.strip().strip('"')
    return bool(re.match(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$", val))


def parse_credential(raw_credential: bytes | str, *opts: CredentialOpt) -> Credential:
    if isinstance(raw_credential, str):
        raw_bytes = raw_credential.encode("utf-8")
    else:
        raw_bytes = raw_credential
    if not raw_bytes:
        raise ValueError("JSON string is empty")

    if _is_json_credential(raw_bytes):
        peek = json.loads(raw_bytes)
        ident = peek.get("id")
        if isinstance(ident, str):
            for prefix in (
                f"data:application/{TYPE_VC_JWT},",
                f"data:application/{TYPE_VC_SD_JWT},",
            ):
                if ident.startswith(prefix):
                    if not helper.has_type(peek.get("type"), TYPE_ENVELOPED_VC):
                        raise ValueError(
                            f"credential carries a {prefix} id but its type is not {TYPE_ENVELOPED_VC}"
                        )
                    token = ident[len(prefix) :]
                    return _parse_jose_credential(token, *opts)
        return parse_json_credential(raw_bytes, *opts)

    val_str = raw_bytes.decode("utf-8").strip().strip('"')
    if is_sd_jwt(val_str) or _is_jwt_credential(val_str):
        base_jwt = val_str
        if is_sd_jwt(val_str):
            base_jwt = val_str.split("~", 1)[0]
        parts = base_jwt.split(".")
        if len(parts) >= 2:
            try:
                header = json.loads(b64url_decode(parts[0]))
            except ValueError:  # unreadable header: fall through to the VC 1.1 path
                header = {}
            if isinstance(header, dict):
                typ = header.get("typ")
                if isinstance(typ, str):
                    if typ.endswith("+sd-jwt") and not _is_jose_credential_typ(typ):
                        raise ValueError(
                            f'failed to parse credential: unsupported SD-JWT typ "{typ}": only vc+sd-jwt is read'
                        )
                    if _is_jose_credential_typ(typ):
                        return _parse_jose_credential(val_str, *opts)
        return parse_jwt_credential(val_str, *opts)

    raise ValueError("failed to parse credential: not a valid JSON, SD-JWT, or JWT credential")


def _parse_jose_credential(token: str, *opts: CredentialOpt) -> Any:
    from credential.vc.jose_credential import JOSECredential

    return JOSECredential.parse(token, *opts)


def parse_credential_with_validation(raw_credential: bytes | str) -> Credential:
    return parse_credential(raw_credential, with_schema_validation(), with_verify_proof())



def __getattr__(name: str):  # PEP 562: ParsedJSONCredential is the JSON-LD credential (kept for old imports)
    if name == "ParsedJSONCredential":
        from credential.vc.json_credential import JSONCredential

        return JSONCredential
    raise AttributeError(name)
