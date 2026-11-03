from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from credential.common.credential_status.credential_status import fetch_and_check_revocation
from credential.common.util.json import shallow_copy_obj
from credential.common.util.vc import map_slice, serialize_contexts, serialize_types

CredentialData = dict[str, Any]
SchemaLoaderFunc = Callable[[str], bytes]


def split_json_obj(obj: dict[str, Any], *fields: str) -> tuple[dict[str, Any], dict[str, Any]]:
    flds_map: dict[str, Any] = {}
    rest: dict[str, Any] = {}
    for key, value in obj.items():
        if key in fields:
            flds_map[key] = value
        else:
            rest[key] = value
    return flds_map, rest


def did_from_field(value: Any) -> tuple[str, bool]:
    if isinstance(value, str) and value:
        return value, True
    if isinstance(value, dict):
        ident = value.get("id")
        if isinstance(ident, str) and ident:
            return ident, True
    return "", False


def extract_field_from_map(m: dict[str, Any] | None, path: str) -> Any:
    if m is None or not path:
        return None
    parts = path.split(".")
    current: Any = m
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        else:
            return None
    return current


def dot_paths_to_pointers(paths: list[str] | None) -> list[str]:
    out: list[str] = []
    for p in paths or []:
        if not p:
            continue
        if p.startswith("/"):
            out.append(p)
            continue
        segments = p.split(".")
        encoded: list[str] = []
        for seg in segments:
            seg = seg.replace("~", "~0").replace("/", "~1")
            encoded.append(seg)
        out.append("/" + "/".join(encoded))
    return out


def is_empty_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value == ""
    if isinstance(value, list):
        return len(value) == 0
    if isinstance(value, dict):
        return len(value) == 0
    return False


def convert_to_array(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


REQUIRED_CREDENTIAL_PROPERTIES = ("@context", "type", "issuer", "credentialSubject")


def require_credential_properties(m: CredentialData) -> None:
    for prop in REQUIRED_CREDENTIAL_PROPERTIES:
        if is_empty_value(m.get(prop)):
            raise ValueError(f"credential is missing {prop}")


def has_type(value: Any, want: str) -> bool:
    if isinstance(value, str):
        return value == want
    if isinstance(value, list):
        return any(isinstance(item, str) and item == want for item in value)
    return False


def check_validity_period(what: str, valid_from: str, valid_until: str, leeway: timedelta) -> None:
    now = datetime.now(timezone.utc)
    if leeway.total_seconds() < 0:
        leeway = timedelta(0)
    if valid_from:
        try:
            start = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"failed to parse validFrom: {exc}") from exc
        if now + leeway < start:
            raise ValueError(f"{what} is not valid yet")
    if valid_until:
        try:
            end = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"failed to parse validUntil: {exc}") from exc
        if now - leeway > end:
            raise ValueError(f"{what} is expired")


def parse_string_field(obj: CredentialData, field_name: str) -> str:
    if field_name not in obj:
        return ""
    value = obj[field_name]
    if isinstance(value, str):
        return value
    raise ValueError(f'field "{field_name}" must be a string, got {type(value).__name__}')


def check_expiration(c: CredentialData, leeway: timedelta) -> None:
    try:
        valid_from = parse_string_field(c, "validFrom")
    except ValueError as exc:
        raise ValueError(f"failed to parse validFrom: {exc}") from exc
    try:
        valid_until = parse_string_field(c, "validUntil")
    except ValueError as exc:
        raise ValueError(f"failed to parse validUntil: {exc}") from exc
    check_validity_period("credential", valid_from, valid_until, leeway)


def check_revocation(c: CredentialData) -> None:
    if "credentialStatus" not in c or c["credentialStatus"] is None:
        return
    raw_status = c["credentialStatus"]
    if not isinstance(raw_status, dict):
        raise ValueError("credentialStatus must be an object")
    if len(raw_status) == 0:
        return
    raw_list_cred = raw_status.get("statusListCredential")
    if raw_list_cred is None:
        raise ValueError("credentialStatus.statusListCredential is required")
    if not isinstance(raw_list_cred, str) or not raw_list_cred:
        raise ValueError("credentialStatus.statusListCredential must be a non-empty string")
    raw_index = raw_status.get("statusListIndex")
    if raw_index is None:
        raise ValueError("credentialStatus.statusListIndex is required")
    if not isinstance(raw_index, str) or not raw_index:
        raise ValueError("credentialStatus.statusListIndex must be a non-empty string")
    try:
        position = int(raw_index)
    except ValueError as exc:
        raise ValueError(f"invalid credentialStatus.statusListIndex: {exc}") from exc
    try:
        is_revoked = fetch_and_check_revocation(raw_list_cred, position)
    except Exception as exc:
        raise ValueError(f"failed to check revocation: {exc}") from exc
    if is_revoked:
        raise ValueError("credential is revoked")


def serialize_subject(subject: dict[str, Any]) -> CredentialData:
    json_obj = shallow_copy_obj(subject.get("custom_fields") or subject.get("customFields") or {})
    if isinstance(subject, dict):
        subj_id = subject.get("id")
        if isinstance(subj_id, str) and subj_id:
            json_obj["id"] = subj_id
    return json_obj


def serialize_subjects(subjects: list[Any]) -> Any:
    if not subjects:
        return None
    items = []
    for s in subjects:
        if hasattr(s, "custom_fields"):
            obj = shallow_copy_obj(getattr(s, "custom_fields", None) or {})
            sid = getattr(s, "id", "")
            if sid:
                obj["id"] = sid
            items.append(obj)
        elif isinstance(s, dict):
            items.append(serialize_subject_from_dict(s))
        else:
            items.append(s)
    if len(items) == 1:
        return items[0]
    return items


def serialize_subject_from_dict(subject: dict[str, Any]) -> CredentialData:
    flds, rest = split_json_obj(subject, "id")
    out = shallow_copy_obj(rest)
    ident = flds.get("id")
    if isinstance(ident, str) and ident:
        out["id"] = ident
    return out


def serialize_schema(schema: Any) -> CredentialData:
    if hasattr(schema, "id"):
        return {"id": getattr(schema, "id", ""), "type": getattr(schema, "type", "")}
    if isinstance(schema, dict):
        return {"id": schema.get("id", ""), "type": schema.get("type", "")}
    return {}


def serialize_schemas(schemas: list[Any]) -> Any:
    if not schemas:
        return None
    items = [serialize_schema(s) for s in schemas]
    if len(items) == 1:
        return items[0]
    return items


def serialize_status(status: Any) -> CredentialData:
    if hasattr(status, "type"):
        result: CredentialData = {"type": status.type}
        if getattr(status, "id", ""):
            result["id"] = status.id
        if getattr(status, "status_purpose", ""):
            result["statusPurpose"] = status.status_purpose
        if getattr(status, "status_list_index", ""):
            result["statusListIndex"] = status.status_list_index
        if getattr(status, "status_list_credential", ""):
            result["statusListCredential"] = status.status_list_credential
        return result
    if isinstance(status, dict):
        return dict(status)
    return {}


def serialize_statuses(statuses: list[Any]) -> Any:
    if not statuses:
        return None
    items = [serialize_status(s) for s in statuses]
    if len(items) == 1:
        return items[0]
    return items


def serialize_terms_of_use(term: Any) -> CredentialData:
    if hasattr(term, "type"):
        result: CredentialData = {"type": term.type}
        if getattr(term, "id", ""):
            result["id"] = term.id
        return result
    if isinstance(term, dict):
        out: CredentialData = {"type": term["type"]}
        if term.get("id"):
            out["id"] = term["id"]
        return out
    return {}


def serialize_credential_contents(vcc: Any) -> CredentialData:
    if vcc is None:
        raise ValueError("credential contents is nil")

    context = getattr(vcc, "context", None) or (vcc.get("@context") if isinstance(vcc, dict) else None)
    ident = getattr(vcc, "id", None) or (vcc.get("id") if isinstance(vcc, dict) else None)
    issuer = getattr(vcc, "issuer", None) or (vcc.get("issuer") if isinstance(vcc, dict) else None)

    if not context and not ident and not issuer:
        raise ValueError("credential contents must have at least one of: context, ID, or issuer")

    vc_json: CredentialData = {}
    ctx_list = context or []
    if ctx_list:
        validated, err = _serialize_contexts_safe(ctx_list)
        if err:
            raise ValueError(err)
        vc_json["@context"] = validated

    if ident:
        vc_json["id"] = ident

    types = getattr(vcc, "types", None) or (vcc.get("type") if isinstance(vcc, dict) else None)
    if types:
        type_list = types if isinstance(types, list) else [types]
        serialized_types = serialize_types([t for t in type_list if isinstance(t, str)])
        if serialized_types is not None:
            vc_json["type"] = serialized_types

    subjects = getattr(vcc, "subject", None)
    if subjects:
        vc_json["credentialSubject"] = serialize_subjects(subjects)
    elif isinstance(vcc, dict) and vcc.get("credentialSubject"):
        vc_json["credentialSubject"] = vcc["credentialSubject"]

    if issuer:
        vc_json["issuer"] = issuer

    schemas = getattr(vcc, "schemas", None)
    if schemas:
        vc_json["credentialSchema"] = serialize_schemas(schemas)
    elif isinstance(vcc, dict) and vcc.get("credentialSchema"):
        vc_json["credentialSchema"] = vcc["credentialSchema"]

    statuses = getattr(vcc, "credential_status", None)
    if statuses:
        for i, status in enumerate(statuses):
            stype = getattr(status, "type", None) or (status.get("type") if isinstance(status, dict) else None)
            if not stype:
                raise ValueError(f"credentialStatus[{i}].type is required")
        vc_json["credentialStatus"] = serialize_statuses(statuses)

    terms = getattr(vcc, "terms_of_use", None)
    if terms:
        for i, term in enumerate(terms):
            ttype = getattr(term, "type", None) or (term.get("type") if isinstance(term, dict) else None)
            if not ttype:
                raise ValueError(f"termsOfUse[{i}].type is required")
        vc_json["termsOfUse"] = map_slice(terms, serialize_terms_of_use)

    valid_from = getattr(vcc, "valid_from", None)
    valid_until = getattr(vcc, "valid_until", None)
    if isinstance(vcc, dict):
        valid_from = valid_from or vcc.get("validFrom")
        valid_until = valid_until or vcc.get("validUntil")
    if valid_from and not isinstance(valid_from, str):
        if isinstance(valid_from, datetime):
            vc_json["validFrom"] = _format_rfc3339(valid_from)
    elif isinstance(valid_from, str) and valid_from:
        vc_json["validFrom"] = valid_from
    if valid_until and not isinstance(valid_until, str):
        if isinstance(valid_until, datetime):
            vc_json["validUntil"] = _format_rfc3339(valid_until)
    elif isinstance(valid_until, str) and valid_until:
        vc_json["validUntil"] = valid_until

    require_credential_properties(vc_json)
    return vc_json


def _serialize_contexts_safe(contexts: list[Any]) -> tuple[list[Any] | None, str | None]:
    try:
        return serialize_contexts(contexts), None
    except ValueError as exc:
        return None, f"invalid @context: {exc}"


def _format_rfc3339(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return normalize_map(value)
    if isinstance(value, list):
        return [normalize_value(v) for v in value]
    return value


def normalize_map(in_map: dict[str, Any]) -> dict[str, Any]:
    return {k: normalize_value(v) for k, v in in_map.items()}


def normalize_credential_data(cd: CredentialData) -> dict[str, Any]:
    return normalize_map(dict(cd))


def parse_context(c: CredentialData, contents: Any) -> None:
    ctx = c.get("@context")
    if not isinstance(ctx, list):
        return
    for item in ctx:
        if isinstance(item, (str, dict)):
            contents.context.append(item)
        else:
            raise ValueError(f"unsupported context type: {type(item).__name__}")


def parse_id(c: CredentialData, contents: Any) -> None:
    ident = c.get("id")
    if isinstance(ident, str):
        contents.id = ident


def parse_types(c: CredentialData, contents: Any) -> None:
    value = c.get("type")
    if isinstance(value, str):
        contents.types.append(value)
        return
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                contents.types.append(item)
        return
    if value is not None:
        raise ValueError(f"unsupported type field: {type(value).__name__}")


def parse_issuer(c: CredentialData, contents: Any) -> None:
    issuer, ok = did_from_field(c.get("issuer"))
    if ok:
        contents.issuer = issuer


def parse_dates(c: CredentialData, contents: Any) -> None:
    vf = c.get("validFrom")
    if isinstance(vf, str):
        contents.valid_from = datetime.fromisoformat(vf.replace("Z", "+00:00"))
    vu = c.get("validUntil")
    if isinstance(vu, str):
        contents.valid_until = datetime.fromisoformat(vu.replace("Z", "+00:00"))


def parse_subject(c: CredentialData, contents: Any) -> None:
    subject_raw = c.get("credentialSubject")
    if subject_raw is None:
        return
    if isinstance(subject_raw, str):
        from credential.vc.credential import Subject

        contents.subject = [Subject(id=subject_raw)]
        return
    if isinstance(subject_raw, dict):
        from credential.vc.credential import subject_from_json

        try:
            parsed = subject_from_json(subject_raw)
        except ValueError as exc:
            raise ValueError(f"failed to parse subject: {exc}") from exc
        contents.subject = [parsed]
        return
    if isinstance(subject_raw, list):
        from credential.vc.credential import subject_from_json

        subjects = []
        for raw in subject_raw:
            if not isinstance(raw, dict):
                raise ValueError(f"unsupported subject format: {type(raw).__name__}")
            try:
                subjects.append(subject_from_json(raw))
            except ValueError as exc:
                raise ValueError(f"failed to parse subjects array: {exc}") from exc
        contents.subject = subjects
        return
    raise ValueError(f"unsupported subject format: {type(subject_raw).__name__}")


def parse_schema_id(value: Any) -> Any:
    from credential.vc.credential import Schema

    schema = Schema()
    if isinstance(value, str):
        schema.id = value
        return schema
    if isinstance(value, dict):
        if isinstance(value.get("id"), str):
            schema.id = value["id"]
        if isinstance(value.get("type"), str):
            schema.type = value["type"]
        return schema
    raise ValueError(f"invalid schema format: {type(value).__name__}")


def parse_schema(c: CredentialData, contents: Any) -> None:
    schema_raw = c.get("credentialSchema")
    if schema_raw is None:
        return
    if isinstance(schema_raw, dict):
        try:
            contents.schemas.append(parse_schema_id(schema_raw))
        except ValueError as exc:
            raise ValueError(f"failed to parse schema: {exc}") from exc
        return
    if isinstance(schema_raw, list):
        for raw in schema_raw:
            try:
                contents.schemas.append(parse_schema_id(raw))
            except ValueError as exc:
                raise ValueError(f"failed to parse schema: {exc}") from exc
        return
    raise ValueError(f"unsupported schema format: {type(schema_raw).__name__}")


def parse_status_entry(status: dict[str, Any]) -> Any:
    from credential.vc.credential import Status

    s = Status()
    if isinstance(status.get("id"), str):
        s.id = status["id"]
    if isinstance(status.get("type"), str):
        s.type = status["type"]
    if isinstance(status.get("statusPurpose"), str):
        s.status_purpose = status["statusPurpose"]
    if isinstance(status.get("statusListIndex"), str):
        s.status_list_index = status["statusListIndex"]
    if isinstance(status.get("statusListCredential"), str):
        s.status_list_credential = status["statusListCredential"]
    return s


def parse_status(c: CredentialData, contents: Any) -> None:
    status_raw = c.get("credentialStatus")
    if status_raw is None:
        return
    if isinstance(status_raw, dict):
        try:
            contents.credential_status.append(parse_status_entry(status_raw))
        except ValueError as exc:
            raise ValueError(f"failed to parse status: {exc}") from exc
        return
    if isinstance(status_raw, list):
        for raw in status_raw:
            if not isinstance(raw, dict):
                raise ValueError(f"unsupported status format: {type(raw).__name__}")
            try:
                contents.credential_status.append(parse_status_entry(raw))
            except ValueError as exc:
                raise ValueError(f"failed to parse status: {exc}") from exc
        return
    raise ValueError(f"unsupported status format: {type(status_raw).__name__}")


def parse_proofs(c: CredentialData, contents: Any) -> None:
    return None


def validate_credential(m: CredentialData, opts: Any) -> None:
    copy_map = shallow_copy_obj(m)
    required_keys = ["credentialSchema", *REQUIRED_CREDENTIAL_PROPERTIES]
    schema_list: list[Any] = []
    for key in required_keys:
        if is_empty_value(copy_map.get(key)):
            raise ValueError(f"{key} is required")
        if key == "credentialSchema":
            schema_list = convert_to_array(copy_map[key])
    for schema in schema_list:
        if isinstance(schema, dict):
            schema_map = schema
        else:
            schema_map = json.loads(json.dumps(schema))
        if schema_map.get("id") is None:
            raise ValueError("credentialSchema.id is required")
        schema_id = schema_map.get("id")
        if not isinstance(schema_id, str) or not schema_id:
            raise ValueError("credentialSchema.id must be a non-empty string")
        loader = getattr(opts, "loaded_schema_loader", None)
        if loader is not None:
            try:
                schema_bytes = loader(schema_id)
            except Exception as exc:
                raise ValueError(f"failed to load schema via custom loader: {exc}") from exc
            if not schema_bytes:
                raise ValueError("failed to load schema via custom loader: schema is empty")
            try:
                import jsonschema

                schema_doc = json.loads(schema_bytes.decode("utf-8"))
                jsonschema.validate(instance=copy_map, schema=schema_doc)
            except ImportError:
                pass
