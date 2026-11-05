"""The claims draft-ietf-oauth-sd-jwt-vc-19 fixes for every SD-JWT VC: the typ
header (§2.2.1) and the claims that must not be concealed (§2.2.2.3)."""

from __future__ import annotations

from typing import Any

from jose.json import JsonNumber

# typ: draft 19 §2.2.1, the typ header MUST be dc+sd-jwt.
TYP_DC_SD_JWT = "dc+sd-jwt"

# The eight claims draft 19 §2.2.2.3 says MUST NOT be included in Disclosures,
# sub-claims included. All are top-level claims, so a path is judged by its
# first element.
NEVER_DISCLOSABLE: frozenset[str] = frozenset(
    {"iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"}
)
NEVER_DISCLOSABLE_SORTED: tuple[str, ...] = tuple(sorted(NEVER_DISCLOSABLE))


def is_never_disclosable(path: list[object]) -> bool:
    if not path:
        return False
    first = path[0]
    return is_str(first) and first in NEVER_DISCLOSABLE


def is_str(v: Any) -> bool:
    """A JSON string. jose decodes a JSON number to JsonNumber, a str subclass, which is not one."""
    return isinstance(v, str) and not isinstance(v, JsonNumber)
