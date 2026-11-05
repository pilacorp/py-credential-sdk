from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from credential.common.util.vc import serialize_contexts, serialize_types
from credential.vc import credential as vc
from credential.vc.credential_helper import check_validity_period

PresentationData = dict[str, Any]

CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
CONTEXT_V1 = "https://www.w3.org/2018/credentials/v1"


def has_type(v: Any, want: str) -> bool:
    if isinstance(v, str):
        return v == want
    if isinstance(v, list):
        return any(isinstance(e, str) and e == want for e in v)
    return False


def first_context(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, list) and v and isinstance(v[0], str):
        return v[0]
    return ""


def did_from_field(v: Any) -> tuple[str, bool]:
    if isinstance(v, str) and v:
        return v, True
    if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]:
        return v["id"], True
    return "", False


def format_rfc3339(dt: datetime) -> str:
    """Go time.Format(RFC3339): 'Z' for UTC, otherwise the numeric offset."""
    s = dt.strftime("%Y-%m-%dT%H:%M:%S")
    off = dt.utcoffset()
    if off is None or off == timedelta(0):
        return s + "Z"
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"{s}{sign}{total // 3600:02d}:{total % 3600 // 60:02d}"


def extract_field_from_map(m: PresentationData | None, path: str) -> Any:
    cur: Any = m
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def parse_string_field(obj: PresentationData, name: str) -> str:
    if name in obj:
        v = obj[name]
        if isinstance(v, str):
            return v
        raise ValueError(f'field "{name}" must be a string, got {type(v).__name__}')
    return ""


def check_expiration(p: PresentationData, leeway: timedelta) -> None:
    try:
        valid_from = parse_string_field(p, "validFrom")
    except ValueError as exc:
        raise ValueError(f"failed to parse validFrom: {exc}") from exc
    try:
        valid_until = parse_string_field(p, "validUntil")
    except ValueError as exc:
        raise ValueError(f"failed to parse validUntil: {exc}") from exc
    check_validity_period("presentation", valid_from, valid_until, leeway)


def verify_credentials(p: PresentationData, options: Any) -> None:
    """Verify every embedded credential's proof plus the vc options WithVCValidation forwarded."""
    try:
        contents = parse_presentation_contents(p)
    except ValueError as exc:
        raise ValueError(f"failed to parse presentation contents: {exc}") from exc
    vcs = contents.verifiable_credentials
    if not vcs:
        raise ValueError("credential input is nil")
    # presentation resolver and leeway go first so a caller's vc option overrides them
    vc_opts = [vc.with_resolver(options.resolver), vc.with_leeway(options.leeway), *options.vc_opts]
    for i, cred in enumerate(vcs):
        if cred is None:
            raise ValueError(f"credential at index {i} is nil")
        try:
            cred.verify(*vc_opts)
        except Exception as exc:
            raise ValueError(f"failed to verify credential at index {i}: {exc}") from exc


def serialize_presentation_contents(vpc: Any) -> PresentationData:
    from credential.vp.presentation import PresentationContents

    if vpc is None:
        raise ValueError("presentation contents is nil")
    assert isinstance(vpc, PresentationContents)
    if not vpc.context and not vpc.id and not vpc.holder:
        raise ValueError("contents must have context, ID, or holder")
    out: PresentationData = {}
    if vpc.context:
        try:
            out["@context"] = serialize_contexts(list(vpc.context))
        except ValueError as exc:
            raise ValueError(f"invalid @context: {exc}") from exc
    if vpc.id:
        out["id"] = vpc.id
    if vpc.types:
        out["type"] = serialize_types(list(vpc.types))
    if vpc.holder:
        out["holder"] = vpc.holder
    if vpc.valid_from is not None:
        out["validFrom"] = format_rfc3339(vpc.valid_from)
    if vpc.valid_until is not None:
        out["validUntil"] = format_rfc3339(vpc.valid_until)
    if vpc.verifiable_credentials:
        creds = []
        for i, c in enumerate(vpc.verifiable_credentials):
            if c is None:
                raise ValueError(f"credential at index {i} is nil")
            try:
                creds.append(c.serialize())
            except Exception as exc:
                raise ValueError(f"failed to serialize credential {i}: {exc}") from exc
        out["verifiableCredential"] = creds
    return out


def parse_presentation_contents(p: PresentationData) -> Any:
    from credential.vp.presentation import PresentationContents

    try:
        c = PresentationContents()
        ctx = p.get("@context")
        if isinstance(ctx, list):
            for e in ctx:
                if isinstance(e, (str, dict)):
                    c.context.append(e)
                else:
                    raise ValueError(f"unsupported context type: {type(e).__name__}")
        if isinstance(p.get("id"), str):
            c.id = p["id"]
        t = p.get("type")
        if isinstance(t, str):
            c.types.append(t)
        elif isinstance(t, list):
            c.types.extend(x for x in t if isinstance(x, str))
        else:
            raise ValueError(f"unsupported type field: {type(t).__name__}")
        holder, ok = did_from_field(p.get("holder"))
        if ok:
            c.holder = holder
        for name, attr in (("validFrom", "valid_from"), ("validUntil", "valid_until")):
            if isinstance(p.get(name), str):
                try:
                    setattr(c, attr, _parse_rfc3339(p[name]))
                except ValueError as exc:
                    raise ValueError(f"failed to parse {name}: {exc}") from exc
        _parse_verifiable_credentials(p, c)
        return c
    except ValueError as exc:
        raise ValueError(f"failed to parse presentation contents: {exc}") from exc


def _parse_rfc3339(s: str) -> datetime:
    from credential.common.verification_method.verification_method import parse_rfc3339

    return parse_rfc3339(s)


def _parse_verifiable_credentials(p: PresentationData, c: Any) -> None:
    v = p.get("verifiableCredential")
    if v is None:
        return
    items = v if isinstance(v, list) else [v]
    for i, item in enumerate(items):
        if item is None:
            raise ValueError(f"credential at index {i} is nil")
        try:
            if isinstance(item, str):
                cred = vc.parse_credential(item.encode("utf-8"))
            else:
                cred = vc.parse_credential(json.dumps(item).encode("utf-8"))
        except Exception as exc:
            raise ValueError(f"failed to parse credential at index {i}: {exc}") from exc
        c.verifiable_credentials.append(cred)


def parse_holder(vp: PresentationData, contents: Any) -> None:
    """holder may be a string or an object with an id; contents keeps only the id."""
    holder, ok = did_from_field(vp.get("holder"))
    if ok:
        contents.holder = holder
