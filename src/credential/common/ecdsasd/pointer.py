from __future__ import annotations

from typing import Any

from credential.common.ecdsasd.helpers import deep_copy


def parse_pointer(pointer: str) -> list[Any]:
    parts = pointer.split("/")
    if parts:
        parts = parts[1:]
    parsed: list[Any] = []
    for part in parts:
        if "~" not in part:
            if part.isdigit() or (part.startswith("-") and part[1:].isdigit()):
                parsed.append(int(part))
                continue
            parsed.append(part)
            continue
        un = part.replace("~1", "/").replace("~0", "~")
        parsed.append(un)
    return parsed


def select_json_ld(document: dict[str, Any], pointers: list[str]) -> dict[str, Any] | None:
    if not pointers:
        return None
    sel: dict[str, Any] = {}
    if "@context" in document:
        sel["@context"] = deep_copy(document["@context"])
    init_selection(sel, document)

    for pointer in pointers:
        paths = parse_pointer(pointer)
        if not paths:
            cloned = deep_copy(document)
            assert isinstance(cloned, dict)
            return cloned
        _, err = select_into(document, paths, sel)
        if err:
            raise ValueError(f"pointer {pointer!r}: {err}")
    densify_arrays(sel)
    return sel


def select_into(source: Any, paths: list[Any], sel: Any) -> tuple[Any, str | None]:
    if not paths:
        if isinstance(source, dict):
            merged: dict[str, Any] = {}
            if isinstance(sel, dict):
                merged.update(sel)
            merged.update({k: deep_copy(v) for k, v in source.items()})
            return merged, None
        if isinstance(source, list):
            return deep_copy(source), None
        return source, None

    path = paths[0]
    child_source = get_child(source, path)
    if child_source is None:
        return None, "JSON pointer does not match document"

    child_sel = get_child(sel, path)
    if child_sel is None:
        if isinstance(child_source, list):
            child_sel = []
        else:
            child_sel = init_selection({}, child_source)

    new_child, err = select_into(child_source, paths[1:], child_sel)
    if err:
        return None, err
    return set_child(sel, path, new_child), None


def init_selection(sel: dict[str, Any], source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return sel
    id_val = source.get("id")
    if isinstance(id_val, str) and not id_val.startswith("_:"):
        sel["id"] = id_val
    if "type" in source:
        sel["type"] = source["type"]
    return sel


def get_child(parent: Any, path: Any) -> Any | None:
    if isinstance(parent, dict):
        if not isinstance(path, str):
            return None
        return parent.get(path)
    if isinstance(parent, list):
        if not isinstance(path, int) or path < 0 or path >= len(parent):
            return None
        return parent[path]
    return None


def set_child(parent: Any, path: Any, val: Any) -> Any:
    if isinstance(parent, dict) and isinstance(path, str):
        parent[path] = val
        return parent
    if isinstance(parent, list) and isinstance(path, int):
        while len(parent) <= path:
            parent.append(None)
        parent[path] = val
        return parent
    return parent


def densify_arrays(value: Any) -> Any:
    if isinstance(value, dict):
        for k, v in list(value.items()):
            value[k] = densify_arrays(v)
        return value
    if isinstance(value, list):
        out: list[Any] = []
        for e in value:
            if e is None:
                continue
            out.append(densify_arrays(e))
        return out
    return value
