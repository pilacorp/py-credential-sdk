from __future__ import annotations

import copy
from typing import Any

from credential.common.jsonmap._constants import (
    CREDENTIALS_V1_CONTEXT,
    CREDENTIALS_V2,
    DATA_INTEGRITY_V2_CONTEXT,
    ECDSA_SECP256K1_SIGNATURE_2019,
    SECP256K1_SUITE_CONTEXT_ACCEPTED,
    SECP256K1_SUITE_CONTEXT_NARROW,
)


def ensure_data_integrity_context(m: dict[str, Any]) -> None:
    covers = lambda s: s in (CREDENTIALS_V2, DATA_INTEGRITY_V2_CONTEXT)  # noqa: E731

    ctx = m.get("@context")
    if ctx is None:
        m["@context"] = [DATA_INTEGRITY_V2_CONTEXT]
        return
    if isinstance(ctx, str):
        if not covers(ctx):
            m["@context"] = [ctx, DATA_INTEGRITY_V2_CONTEXT]
        return
    if isinstance(ctx, list):
        for entry in ctx:
            if isinstance(entry, str) and covers(entry):
                return
        m["@context"] = list(ctx) + [DATA_INTEGRITY_V2_CONTEXT]
        return
    if isinstance(ctx, tuple):
        generic = list(ctx)
        m["@context"] = generic
        ensure_data_integrity_context(m)
        return
    if isinstance(ctx, dict):
        m["@context"] = [ctx, DATA_INTEGRITY_V2_CONTEXT]
        return


def context_snapshot(m: dict[str, Any]):
    previous = m.get("@context", _MISSING)
    had = "@context" in m

    def restore() -> None:
        if had:
            m["@context"] = previous
        else:
            m.pop("@context", None)

    return restore


_MISSING = object()


def defines_secp256k1_suite(m: dict[str, Any]) -> bool:
    def defines(s: str) -> bool:
        return s in (
            CREDENTIALS_V1_CONTEXT,
            CREDENTIALS_V1_CONTEXT + ".jsonld",
            SECP256K1_SUITE_CONTEXT_ACCEPTED,
            SECP256K1_SUITE_CONTEXT_NARROW,
        )

    ctx = m.get("@context")
    if isinstance(ctx, str):
        return defines(ctx)
    if isinstance(ctx, list):
        return any(isinstance(e, str) and defines(e) for e in ctx)
    if isinstance(ctx, tuple):
        return any(isinstance(e, str) and defines(e) for e in ctx)
    return False


def ensure_secp256k1_suite_context(m: dict[str, Any]) -> None:
    if defines_secp256k1_suite(m):
        return
    ctx = m.get("@context")
    narrow = SECP256K1_SUITE_CONTEXT_NARROW
    if ctx is None:
        raise ValueError(
            f"document has no @context, so {ECDSA_SECP256K1_SIGNATURE_2019} cannot be expanded; "
            f"build the credential through vc.NewJSONCredential or add {narrow!r} yourself"
        )
    if isinstance(ctx, str):
        m["@context"] = [ctx, narrow]
        return
    if isinstance(ctx, list):
        m["@context"] = copy.deepcopy(ctx) + [narrow]
        return
    if isinstance(ctx, tuple):
        m["@context"] = list(ctx) + [narrow]
        return
    raise ValueError(f"document @context has unexpected type {type(ctx).__name__}")


def add_suite_context_without_changing_meaning(m: dict[str, Any]) -> None:
    from credential.common.jsonmap._ecdsa_common import document_digest

    if defines_secp256k1_suite(m):
        return
    try:
        before = document_digest(m)
    except ValueError as exc:
        raise ValueError(f"failed to canonicalize the document: {exc}") from exc
    ensure_secp256k1_suite_context(m)
    try:
        after = document_digest(m)
    except ValueError as exc:
        raise ValueError(
            f"adding {SECP256K1_SUITE_CONTEXT_NARROW!r}, which {ECDSA_SECP256K1_SIGNATURE_2019} needs, stopped the "
            "document from canonicalizing; a term it defines collides with one this document uses — rename that "
            f"term, or define the suite in @context yourself: {exc}"
        ) from exc
    if before != after:
        raise ValueError(
            f"adding {SECP256K1_SUITE_CONTEXT_NARROW!r}, which {ECDSA_SECP256K1_SIGNATURE_2019} needs, "
            "changed what the document says; it defines proof at the root, so a term of that name used "
            "elsewhere in this document is redefined — rename that term, or define the suite in @context yourself"
        )
