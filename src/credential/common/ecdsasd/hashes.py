from __future__ import annotations

from hashlib import sha256
from typing import Any

from credential.common.ecdsasd.ld import canonicalize
from credential.common.ecdsasd.labelmap import sorted_indexes


def hash_proof_config(proof_config: dict[str, Any]) -> bytes:
    try:
        nquads = canonicalize(proof_config)
    except ValueError as exc:
        raise ValueError(f"ecdsasd: hash proof config: {exc}") from exc
    return sha256(nquads).digest()


def hash_mandatory(matching: dict[int, str]) -> bytes:
    parts = [matching[i] for i in sorted_indexes(matching)]
    return sha256("".join(parts).encode("utf-8")).digest()
