from __future__ import annotations

import copy
from typing import Any

from credential.common.sdjwt.helper import DEFAULT_HASH_ALGORITHM, SUPPORTED, DisclosureInfo, hash_disclosure, parse_disclosure


def reconstruct(vc_map: dict[str, Any], disclosures: list[str], validate_alg: bool) -> dict[str, Any]:
    sd_alg = vc_map.get("_sd_alg") or DEFAULT_HASH_ALGORITHM
    if validate_alg and sd_alg not in SUPPORTED:
        raise ValueError(f'unsupported _sd_alg: "{sd_alg}"')
    disclosure_map: dict[str, DisclosureInfo] = {}
    for disc in disclosures:
        if not disc:
            continue
        h = hash_disclosure(sd_alg, disc)
        if h in disclosure_map:
            raise ValueError(f'disclosure for digest "{h}" was sent more than once')
        disclosure_map[h] = parse_disclosure(disc)
    used: set[str] = set()
    processed = _process(copy.deepcopy(vc_map), disclosure_map, used)
    for digest in disclosure_map:
        if digest not in used:
            raise ValueError(f'disclosure for digest "{digest}" matches nothing in the payload')
    if not isinstance(processed, dict):
        raise ValueError("processed payload is not an object")
    processed.pop("_sd_alg", None)
    return processed


def _process(node: Any, disclosure_map: dict[str, DisclosureInfo], used: set[str]) -> Any:
    if isinstance(node, list):
        out: list[Any] = []
        array_digests: set[str] = set()
        for elem in node:
            if isinstance(elem, dict) and list(elem.keys()) == ["..."] and isinstance(elem["..."], str):
                h = elem["..."]
                if h in array_digests:
                    raise ValueError(f'duplicate digest "{h}" found in array')
                array_digests.add(h)
                if h in used:
                    raise ValueError(f'digest "{h}" is referenced more than once in the payload')
                used.add(h)
                info = disclosure_map.get(h)
                if not info:
                    out.append({"...": h})
                    continue
                if not info.is_array_elem:
                    raise ValueError("object field disclosure used in array context")
                out.append(_process(info.value, disclosure_map, used))
                continue
            out.append(_process(elem, disclosure_map, used))
        return out
    if isinstance(node, dict):
        raw_sd = node.get("_sd")
        for k, v in list(node.items()):
            if k != "_sd":
                node[k] = _process(v, disclosure_map, used)
        if raw_sd is not None:
            if not isinstance(raw_sd, list) or not all(isinstance(x, str) for x in raw_sd):
                raise ValueError("_sd must be an array of digests")
            _apply_sd(raw_sd, node, disclosure_map, used)
            node.pop("_sd", None)
        return node
    return node


def _apply_sd(
    hashes: list[str],
    obj: dict[str, Any],
    disclosure_map: dict[str, DisclosureInfo],
    used: set[str],
) -> None:
    seen: set[str] = set()
    for h in hashes:
        if h in seen:
            raise ValueError(f'duplicate digest "{h}" found in _sd array')
        seen.add(h)
        if h in used:
            raise ValueError(f'digest "{h}" is referenced more than once in the payload')
        used.add(h)
        info = disclosure_map.get(h)
        if not info:
            continue
        if info.is_array_elem or not info.object_field:
            raise ValueError("array element disclosure used in object context")
        if info.object_field in obj:
            raise ValueError(f'duplicate field "{info.object_field}" when reconstructing SD-JWT object')
        obj[info.object_field] = _process(info.value, disclosure_map, used)
