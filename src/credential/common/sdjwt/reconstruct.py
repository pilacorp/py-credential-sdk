from __future__ import annotations

import copy
from typing import Any

from credential.common.sdjwt.helper import DEFAULT_HASH_ALGORITHM, SUPPORTED, DisclosureInfo, hash_disclosure, parse_disclosure

SD_KEY = "_sd"


def reconstruct(vc_map: dict[str, Any], disclosures: list[str], validate_alg: bool) -> dict[str, Any]:
    """Rebuild the payload from digests + disclosures (Go sdjwt.Reconstruct)."""
    sd_alg = validate_and_get_algorithm(vc_map, validate_alg)
    disclosure_map = build_disclosure_map(disclosures or [], sd_alg)
    used: set[str] = set()
    try:
        processed = process_node(copy.deepcopy(vc_map), disclosure_map, used)
    except RecursionError as exc:
        raise ValueError("SD-JWT payload is nested too deeply") from exc
    # RFC 9901 §7.1 step 5: every disclosure must be referenced by a digest.
    for digest in disclosure_map:
        if digest not in used:
            raise ValueError(
                f'disclosure for digest "{digest}" matches nothing in the payload; '
                "it was not part of what the issuer signed"
            )
    if not isinstance(processed, dict):
        raise ValueError("processed payload is not an object")
    processed.pop("_sd_alg", None)
    return processed


def validate_and_get_algorithm(vc_map: dict[str, Any], validate_alg: bool) -> str:
    sd_alg = DEFAULT_HASH_ALGORITHM
    v = vc_map.get("_sd_alg")
    if isinstance(v, str) and v != "":
        sd_alg = v
    if validate_alg and sd_alg not in SUPPORTED:
        raise ValueError(f'unsupported _sd_alg: "{sd_alg}"')
    return sd_alg


def build_disclosure_map(disclosures: list[str], sd_alg: str) -> dict[str, DisclosureInfo]:
    out: dict[str, DisclosureInfo] = {}
    for disc in disclosures:
        if disc == "":
            continue
        try:
            h = hash_disclosure(sd_alg, disc)
        except ValueError as exc:
            raise ValueError(f"failed to hash disclosure: {exc}") from exc
        info = parse_disclosure(disc)
        if h in out:
            raise ValueError(f'disclosure for digest "{h}" was sent more than once')
        out[h] = info
    return out


def process_node(node: Any, disclosure_map: dict[str, DisclosureInfo], used: set[str]) -> Any:
    if isinstance(node, dict):
        # The issuer's own fields first, then _sd: applying _sd first would walk a
        # disclosed claim twice and count its nested digests twice.
        for key in list(node.keys()):
            if key == SD_KEY:
                continue
            node[key] = process_node(node[key], disclosure_map, used)
        if SD_KEY in node:
            raw_sd = node[SD_KEY]
            if not isinstance(raw_sd, list):
                raise ValueError(f"_sd must be an array of digests, got {type(raw_sd).__name__}")
            # non-string entries are dropped, as in Go
            _apply_sd_hashes([h for h in raw_sd if isinstance(h, str)], node, disclosure_map, used)
            del node[SD_KEY]
        return node
    if isinstance(node, list):
        out: list[Any] = []
        array_digests: set[str] = set()
        for elem in node:
            if isinstance(elem, dict) and len(elem) == 1 and isinstance(elem.get("..."), str):
                h = elem["..."]
                if h in array_digests:
                    raise ValueError(f'duplicate digest "{h}" found in array')
                array_digests.add(h)
                if h in used:
                    raise ValueError(f'digest "{h}" is referenced more than once in the payload')
                used.add(h)
                info = disclosure_map.get(h)
                if info is None:
                    out.append({"...": h})
                    continue
                if not info.is_array_elem:
                    raise ValueError("object field disclosure used in array context")
                out.append(process_node(info.value, disclosure_map, used))
                continue
            out.append(process_node(elem, disclosure_map, used))
        return out
    return node


def _apply_sd_hashes(
    hashes: list[str],
    obj: dict[str, Any],
    disclosure_map: dict[str, DisclosureInfo],
    used: set[str],
) -> None:
    object_digests: set[str] = set()
    for h in hashes:
        if h in object_digests:
            raise ValueError(f'duplicate digest "{h}" found in _sd array')
        object_digests.add(h)
        # §7.1 step 4 counts a digest across the whole payload, revealed or not.
        if h in used:
            raise ValueError(f'digest "{h}" is referenced more than once in the payload')
        used.add(h)
        info = disclosure_map.get(h)
        if info is None:
            continue
        if info.is_array_elem or not info.object_field:
            raise ValueError("array element disclosure used in object context")
        if info.object_field in obj:
            raise ValueError(f'duplicate field "{info.object_field}" when reconstructing SD-JWT object')
        obj[info.object_field] = process_node(info.value, disclosure_map, used)
