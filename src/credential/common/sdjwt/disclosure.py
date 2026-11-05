from __future__ import annotations

import copy
import json
import secrets
from dataclasses import dataclass
from typing import Any

from credential.common.sdjwt.helper import (
    ALG_SHA256,
    ALG_SHA384,
    ALG_SHA512,
    DEFAULT_HASH_ALGORITHM,
    SUPPORTED,
    b64url,
    hash_disclosure,
    random_salt,
)

TARGET_OBJECT_FIELD = "objectField"
TARGET_ARRAY_CONTAINER = "arrayContainer"
TARGET_ARRAY_ELEM = "arrayElem"

__all__ = [
    "ALG_SHA256",
    "ALG_SHA384",
    "ALG_SHA512",
    "DecoyConfig",
    "PathSegment",
    "ResolvedTarget",
    "build_disclosures",
    "parse_path",
    "resolve_path",
]


@dataclass
class DecoyConfig:
    """Where and how many decoy digests to add ("" = root, "credentialSubject", "a.tags", ...)."""

    path: str = ""
    count: int = 0


@dataclass
class PathSegment:
    key: str
    index: int | None = None


@dataclass
class ResolvedTarget:
    parent: Any
    kind: str
    field_name: str = ""
    index: int = 0
    value: Any = None
    parent_map: dict[str, Any] | None = None  # object that holds `parent` (an array) under parent_key
    parent_key: str = ""


def build_disclosures(
    vc: dict[str, Any],
    selective_paths: list[str] | None = None,
    hash_algorithm: str = "",
    shuffle: bool = False,
    decoys: list[Any] | None = None,
) -> dict[str, Any]:
    """Issue-time SD-JWT construction. Returns {"processed_vc": ..., "disclosures": [...]}.

    Paths use dot + [index] notation ("a.b", "tags[0]", "p.children[0].name"). decoys is a
    list of DecoyConfig (or anything with .path/.count, or {"path","count"} dicts).
    """
    sd_alg = hash_algorithm or DEFAULT_HASH_ALGORITHM
    if sd_alg not in SUPPORTED:
        raise ValueError(f'unsupported hash algorithm "{sd_alg}"')
    paths = selective_paths or []
    decoy_cfgs = [_as_decoy(d) for d in decoys or []]

    processed = copy.deepcopy(vc)
    if decoy_cfgs:
        processed["_sd_alg"] = sd_alg
    if not paths and not decoy_cfgs:
        return {"processed_vc": processed, "disclosures": []}
    if paths:
        processed["_sd_alg"] = sd_alg

    disclosures = _process_selective_paths(processed, paths, sd_alg)
    _process_decoys(processed, decoy_cfgs, sd_alg)
    if shuffle:
        _shuffle_sd_arrays(processed)
    return {"processed_vc": processed, "disclosures": disclosures}


def _as_decoy(d: Any) -> DecoyConfig:
    if isinstance(d, dict):
        return DecoyConfig(d.get("path", ""), d.get("count", 0))
    return DecoyConfig(getattr(d, "path", ""), getattr(d, "count", 0))


def _process_selective_paths(vc: dict[str, Any], paths: list[str], sd_alg: str) -> list[str]:
    out: list[str] = []
    for path in paths:
        path = path.strip()
        if not path:
            raise ValueError("empty path")
        try:
            resolved = resolve_path(vc, path)
        except ValueError as exc:
            raise ValueError(f"resolve path {path!r}: {exc}") from exc
        if resolved is None:
            raise ValueError(f'path "{path}" not found')
        out.append(_build_and_apply(resolved, sd_alg))
    return out


def _json_bytes(arr: list[Any]) -> bytes:
    # Go json.Marshal: sorted map keys, compact, HTML-escaped, UTF-8 kept.
    s = json.dumps(arr, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    s = s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return s.encode("utf-8")


def _build_and_apply(resolved: ResolvedTarget, sd_alg: str) -> str:
    salt = random_salt()
    if resolved.kind == TARGET_ARRAY_ELEM:
        arr = [salt, resolved.value]
    else:
        arr = [salt, resolved.field_name, resolved.value]
    encoded = b64url(_json_bytes(arr))
    digest = hash_disclosure(sd_alg, encoded)
    if resolved.kind == TARGET_ARRAY_ELEM:
        if not isinstance(resolved.parent, list):
            raise ValueError("parent is not an array")
        resolved.parent[resolved.index] = {"...": digest}
    else:
        if not isinstance(resolved.parent, dict):
            raise ValueError("parent is not a map")
        _append_sd(resolved.parent, digest)
        resolved.parent.pop(resolved.field_name, None)
    return encoded


def _process_decoys(vc: dict[str, Any], decoys: list[DecoyConfig], sd_alg: str) -> None:
    for decoy in decoys:
        if decoy.count <= 0:
            continue
        hashes = [hash_disclosure(sd_alg, random_salt()) for _ in range(decoy.count)]
        try:
            resolved = resolve_path(vc, decoy.path)
        except ValueError as exc:
            raise ValueError(f"resolve decoy path {decoy.path!r}: {exc}") from exc
        if resolved is None:
            continue
        if resolved.kind == TARGET_OBJECT_FIELD:
            if resolved.value is not None:
                target = resolved.value
                if not isinstance(target, dict):
                    raise ValueError(f"decoy target value is not an object, got {type(target).__name__}")
            else:
                target = resolved.parent
                if not isinstance(target, dict):
                    raise ValueError(f"decoy target parent is not an object, got {type(target).__name__}")
            for h in hashes:
                _append_sd(target, h)
        elif resolved.kind == TARGET_ARRAY_CONTAINER:
            if not isinstance(resolved.value, list):
                raise ValueError(f"decoy target value is not an array, got {type(resolved.value).__name__}")
            if not isinstance(resolved.parent, dict):
                raise ValueError(f"decoy target parent is not an object, got {type(resolved.parent).__name__}")
            resolved.parent[resolved.field_name] = list(resolved.value) + [{"...": h} for h in hashes]
        elif resolved.kind == TARGET_ARRAY_ELEM:
            if not isinstance(resolved.parent, list):
                raise ValueError(f"decoy target parent is not an array, got {type(resolved.parent).__name__}")
            resolved.parent.extend({"...": h} for h in hashes)


def _append_sd(m: dict[str, Any], digest: str) -> None:
    existing = m.get("_sd")
    if existing is None:
        m["_sd"] = [digest]
    elif isinstance(existing, list):
        existing.append(digest)
    # any other type is left untouched, as in Go


def _shuffle_sd_arrays(node: Any) -> None:
    if isinstance(node, dict):
        sd = node.get("_sd")
        if isinstance(sd, list):
            for i in range(len(sd) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                sd[i], sd[j] = sd[j], sd[i]
        for v in node.values():
            _shuffle_sd_arrays(v)
    elif isinstance(node, list):
        for v in node:
            _shuffle_sd_arrays(v)


def resolve_path(root: dict[str, Any], path: str) -> ResolvedTarget | None:
    """Walk a dot + [index] path; "" is the root itself; None when the path does not exist."""
    if path == "":
        return ResolvedTarget(parent=root, kind=TARGET_OBJECT_FIELD)
    segs = parse_path(path)
    if not segs:
        return ResolvedTarget(parent=root, kind=TARGET_OBJECT_FIELD)

    current: Any = root
    for i, seg in enumerate(segs):
        last = i == len(segs) - 1
        if seg.index is None:
            if not isinstance(current, dict):
                raise ValueError(f"segment {seg.key!r} expects object but got {_go_type(current)}")
            if seg.key not in current:
                return None
            val = current[seg.key]
            if last:
                if isinstance(val, list):
                    return ResolvedTarget(current, TARGET_ARRAY_CONTAINER, field_name=seg.key, value=val)
                return ResolvedTarget(current, TARGET_OBJECT_FIELD, field_name=seg.key, value=val)
            current = val
            continue

        arr = _resolve_array(current, seg)
        if arr is None:
            return None
        idx = seg.index
        if idx < 0 or idx >= len(arr):
            raise ValueError(f"index {idx} out of range (len {len(arr)}) for path {path!r}")
        if last:
            parent_map = current if seg.key != "" and isinstance(current, dict) else None
            return ResolvedTarget(
                arr,
                TARGET_ARRAY_ELEM,
                index=idx,
                value=arr[idx],
                parent_map=parent_map,
                parent_key=seg.key if parent_map is not None else "",
            )
        current = arr[idx]
    return None


def _go_type(v: Any) -> str:
    return {dict: "map[string]interface {}", list: "[]interface {}", str: "string", bool: "bool", type(None): "<nil>"}.get(
        type(v), "float64" if isinstance(v, (int, float)) else type(v).__name__
    )


def _resolve_array(current: Any, seg: PathSegment) -> list[Any] | None:
    if seg.key != "":
        if not isinstance(current, dict):
            raise ValueError(f"segment {seg.key!r} expects object but got {_go_type(current)}")
        if seg.key not in current:
            return None
        raw = current[seg.key]
        if not isinstance(raw, list):
            raise ValueError(f"segment {seg.key!r} expects array but got {_go_type(raw)}")
        return raw
    if not isinstance(current, list):
        raise ValueError(f"segment [{seg.index}] expects array but got {_go_type(current)}")
    return current


def parse_path(path: str) -> list[PathSegment]:
    segs: list[PathSegment] = []
    for p in path.split("."):
        p = p.strip()
        if p == "":
            continue
        b = p.find("[")
        if b == -1:
            segs.append(PathSegment(p))
            continue
        key, rest = p[:b], p[b:]
        if not rest.endswith("]"):
            raise ValueError(f"invalid array segment {p!r} in path {path!r}")
        idx_str = rest[1:-1]
        if idx_str == "":
            raise ValueError(f"empty index in path {path!r}")
        if idx_str == "*":
            raise ValueError(f"wildcard index '*' is not supported in path {path!r}")
        try:
            # Go strconv.Atoi: optional sign, ASCII digits only
            if not idx_str.lstrip("+-").isascii() or not idx_str.lstrip("+-").isdigit() or len(idx_str) - len(idx_str.lstrip("+-")) > 1:
                raise ValueError
            i = int(idx_str)
        except ValueError:
            raise ValueError(f"invalid index {idx_str!r} in path {path!r}") from None
        segs.append(PathSegment(key, i))
    return segs
