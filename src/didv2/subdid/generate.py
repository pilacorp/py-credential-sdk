from __future__ import annotations

from typing import Any

from didv2.did.did import generate_did_document
from didv2.signer import DefaultProvider
from didv2.subdid.document import parse_sub_id, sub_did_for, validate_sub_did
from didv2.subdid.signature import (
    set_root_consent,
    sign_document,
    sign_root_consent,
    verify_document_signature,
    verify_root_consent,
)
from didv2.model import did_type_string
from didv2.hexutil import with_0x


def generate_sub_did(
    root_did: str,
    sub_id: str,
    sub_public_key_hex: str,
    did_type: int,
    metadata: dict[str, Any] | None,
    root_signer: DefaultProvider,
    sub_signer: DefaultProvider,
) -> dict[str, Any]:
    if did_type_string(did_type) == "unknown":
        raise ValueError(f"subdid: unknown DID type {did_type}")
    parse_sub_id(sub_id)
    sub_did = sub_did_for(root_did, sub_public_key_hex)
    consent = sign_root_consent(sub_did, root_signer)
    meta = dict(metadata or {})
    meta["subId"] = sub_id
    doc = generate_did_document(sub_public_key_hex, sub_did, "", root_did, did_type, meta)
    set_root_consent(doc, consent)
    validate_sub_did(doc, root_did)
    try:
        verify_root_consent(doc, root_did)
    except Exception as exc:
        raise ValueError(
            f"subdid: the root signer does not hold the primary key of {root_did}: {exc}"
        ) from exc
    sig = sign_document(doc, sub_signer)
    try:
        verify_document_signature(doc, sig)
    except Exception as exc:
        raise ValueError(
            f"subdid: the Sub-DID signer does not hold the key of {sub_did}: {exc}"
        ) from exc
    return {
        "did": sub_did,
        "document": doc,
        "type": did_type_string(did_type),
        "signature": with_0x(sig),
    }
