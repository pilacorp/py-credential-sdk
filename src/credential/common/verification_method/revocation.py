from __future__ import annotations

# Revocation reasons follow RFC 5280 section 5.3.1 naming. Two tiers:
#   soft - credentials signed BEFORE the revoked timestamp stay valid;
#   hard - (keyCompromise only) invalidates every signature the key ever made.
REASON_SUPERSEDED = "superseded"
REASON_KEY_COMPROMISE = "keyCompromise"


def is_hard_revocation_reason(reason: str) -> bool:
    return reason == REASON_KEY_COMPROMISE
