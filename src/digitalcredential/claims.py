"""Draft-ietf-oauth-sd-jwt-vc-19 typ header and never-disclosable claims."""

from __future__ import annotations

TYP_DC_SD_JWT = "dc+sd-jwt"

NEVER_DISCLOSABLE: frozenset[str] = frozenset(
    {
        "iss",
        "nbf",
        "exp",
        "cnf",
        "vct",
        "vct#integrity",
        "aka_vcts",
        "status",
    }
)


def is_never_disclosable(path: list[object]) -> bool:
    if not path:
        return False
    first = path[0]
    return isinstance(first, str) and first in NEVER_DISCLOSABLE
