from __future__ import annotations

import base64
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Protocol

from credential.common.sdjwt.helper import is_jwt, is_sd_jwt
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


class ResolverProvider(Protocol):
    def resolve_document(self, did: str) -> Any: ...


class HTTPResolver:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def resolve_document(self, did: str) -> Any:
        from urllib.request import urlopen

        url = f"{self.base_url}/{did}"
        with urlopen(url) as resp:  # noqa: S310
            body = resp.read()
        return json.loads(body)


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


class ParsedJSONCredential(Credential):
    def __init__(self, credential_data: CredentialData) -> None:
        self.credential_data = credential_data

    def extract_field(self, path: str) -> Any:
        if not self.credential_data:
            return None
        return helper.extract_field_from_map(self.credential_data, path)

    def get_contents(self) -> bytes:
        return json.dumps(self.credential_data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def get_type(self) -> str:
        return "JSON"


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
    options = get_options(*opts)
    errors: list[Exception] = []
    if options.is_validate_schema:
        try:
            helper.validate_credential(credential_data, options)
        except Exception as exc:
            errors.append(ValueError(f"validate credential: {exc}"))
    if options.is_check_revocation:
        try:
            helper.check_revocation(credential_data)
        except Exception as exc:
            errors.append(ValueError(f"check revocation: {exc}"))
    if errors:
        raise ValueError(f"credential verification failed: {errors[0]}")
    if options.is_check_expiration:
        helper.check_expiration(credential_data, options.leeway)


def parse_json_credential(raw_json: bytes | str, *opts: CredentialOpt) -> ParsedJSONCredential:
    if isinstance(raw_json, str):
        raw = raw_json.encode("utf-8")
    else:
        raw = raw_json
    if not raw:
        raise ValueError("JSON string is empty")
    if not _is_json_credential(raw):
        raise ValueError("invalid JSON format")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid JSON format")
    helper.require_credential_properties(data)
    cred = ParsedJSONCredential(data)
    _execute_options(data, list(opts))
    return cred


def parse_jwt_credential(raw_jwt: str, *opts: CredentialOpt) -> ParsedJWTCredential:
    raw_jwt = raw_jwt.strip().strip('"')
    if "~" in raw_jwt:
        raise ValueError(
            f"ParseJWTCredential: token is in SD-JWT combined form: {ERR_SDJWT_REQUIRES_JOSE.args[0]}"
        )
    if not _is_jwt_credential(raw_jwt):
        raise ValueError("invalid JWT format")
    parts = raw_jwt.split(".")
    header_b64, payload_b64 = parts[0], parts[1]
    signature = parts[2] if len(parts) == 3 else ""
    payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4))
    payload_map = json.loads(payload_bytes)
    if not isinstance(payload_map, dict):
        raise ValueError("failed to unmarshal payload")
    vc_data = payload_map.get("vc")
    if vc_data is None:
        raise ValueError("vc claim not found in JWT payload")
    if not isinstance(vc_data, dict):
        raise ValueError("vc claim is not a valid JSON object")
    signing_input = header_b64 + "." + payload_b64
    cred = ParsedJWTCredential(signing_input, vc_data, payload_map, signature)
    _execute_options(vc_data, list(opts))
    return cred


def new_jwt_credential(vcc: CredentialContents, *opts: CredentialOpt) -> ParsedJWTCredential:
    options = get_options(*opts)
    if options.has_sd_options():
        raise ValueError(f"NewJWTCredential: {ERR_SDJWT_REQUIRES_JOSE}")
    vc_map = helper.serialize_credential_contents(vcc)
    vc_map = helper.normalize_credential_data(vc_map)
    payload_data = vc_map
    other_claims: dict[str, Any] = {}
    if vcc.issuer:
        other_claims["iss"] = vcc.issuer
    if vcc.subject and vcc.subject[0].id:
        other_claims["sub"] = vcc.subject[0].id
    if vcc.valid_until:
        other_claims["exp"] = int(vcc.valid_until.timestamp())
    if vcc.valid_from:
        other_claims["iat"] = int(vcc.valid_from.timestamp())
        other_claims["nbf"] = int(vcc.valid_from.timestamp())
    if vcc.id:
        other_claims["jti"] = vcc.id
    payload: dict[str, Any] = {"vc": payload_data, **other_claims}
    kid = f"{vcc.issuer}#{options.verification_method_key or 'key-1'}"
    header = {"typ": "JWT", "alg": "ES256K", "kid": kid}
    header_b64 = _b64url_json(header)
    payload_b64 = _b64url_json(payload)
    signing_input = header_b64 + "." + payload_b64
    cred = ParsedJWTCredential(signing_input, payload_data, other_claims)
    _execute_options(payload_data, list(opts))
    return cred


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
            header_bytes = base64.urlsafe_b64decode(parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4))
            try:
                header = json.loads(header_bytes)
            except json.JSONDecodeError:
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


def _parse_jose_credential(token: str, *opts: CredentialOpt) -> Credential:
    from credential.vc.jose_credential import JOSECredential

    inner = JOSECredential.parse(token)
    payload = inner.payload()
    if not isinstance(payload, dict):
        raise ValueError("invalid JOSE credential payload")
    helper.require_credential_properties(payload)
    cred = ParsedJWTCredential("", payload, payload)
    _execute_options(payload, list(opts))
    return cred


def parse_credential_with_validation(raw_credential: bytes | str) -> Credential:
    return parse_credential(raw_credential, with_schema_validation(), with_verify_proof())

