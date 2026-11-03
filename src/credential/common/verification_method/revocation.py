from __future__ import annotations

REASON_SUPERSEDED = "superseded"
REASON_KEY_COMPROMISE = "keyCompromise"


def is_hard_revocation_reason(reason: str) -> bool:
    return reason == REASON_KEY_COMPROMISE
