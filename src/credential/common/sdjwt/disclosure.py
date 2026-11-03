from __future__ import annotations

import copy
import json
from typing import Any

from credential.common.sdjwt.helper import DEFAULT_HASH_ALGORITHM, SUPPORTED, b64url, hash_disclosure, random_salt


def build_disclosures(
    vc: dict[str, Any],
    selective_paths: list[str] | None = None,
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
) -> dict[str, Any]:
    if hash_algorithm not in SUPPORTED:
        raise ValueError(f'unsupported hash algorithm "{hash_algorithm}"')
    processed = copy.deepcopy(vc)
    paths = selective_paths or []
    if not paths:
        return {"processed_vc": processed, "disclosures": []}
    processed["_sd_alg"] = hash_algorithm
    disclosures = [_conceal(processed, path, hash_algorithm) for path in paths]
    return {"processed_vc": processed, "disclosures": disclosures}


def _conceal(vc: dict[str, Any], path: str, sd_alg: str) -> str:
    path = path.strip()
    if not path:
        raise ValueError("empty path")
    parent, key = _resolve_object_field(vc, path)
    value = parent.pop(key)
    salt = random_salt()
    encoded = b64url(json.dumps([salt, key, value], separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    digest = hash_disclosure(sd_alg, encoded)
    parent.setdefault("_sd", []).append(digest)
    return encoded


def _resolve_object_field(vc: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    parts = path.split(".")
    cur: Any = vc
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            raise ValueError(f'path "{path}" not found')
        cur = cur[part]
    key = parts[-1]
    if not isinstance(cur, dict) or key not in cur:
        raise ValueError(f'path "{path}" not found')
    return cur, key
