from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from credential.common.dto.proof import Proof, proof_from_map
from credential.common.verification_method.revocation import is_hard_revocation_reason
from credential.common.verification_method.verification_method import DIDDocument, VerificationMethodEntry

from credential.common.jsonmap._constants import PROOF_FIELD


def parse_raw_to_proof(raw: Any) -> Proof:
    if raw is None:
        raise ValueError("JSONMap has no proof")
    if not isinstance(raw, dict):
        raise ValueError(f"invalid proof format: expected dict, got {type(raw).__name__}")
    return proof_from_map(raw)


def raw_proof_list(m: dict[str, Any]) -> list[Any]:
    raw = m.get(PROOF_FIELD)
    if raw is None:
        return []
    if isinstance(raw, list):
        return list(raw)
    return [raw]


def get_first_proof(m: dict[str, Any]) -> Any:
    lst = raw_proof_list(m)
    return lst[0] if lst else None


def append_proof(m: dict[str, Any], proof: Proof) -> None:
    lst = raw_proof_list(m) + [proof.to_map()]
    m[PROOF_FIELD] = lst[0] if len(lst) == 1 else lst


def set_single_proof(m: dict[str, Any], proof: Proof) -> None:
    m[PROOF_FIELD] = proof.to_map()


def proofs(m: dict[str, Any]) -> list[Proof]:
    out: list[Proof] = []
    for raw in raw_proof_list(m):
        out.append(parse_raw_to_proof(raw))
    return out


def body_without_proof(m: dict[str, Any]) -> dict[str, Any]:
    full = json.loads(json.dumps(m))
    full.pop(PROOF_FIELD, None)
    return full


def to_map_roundtrip(m: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(m))


def did_from_field(value: Any) -> tuple[str, bool]:
    if isinstance(value, str) and value:
        return value, True
    if isinstance(value, dict):
        ident = value.get("id")
        if isinstance(ident, str) and ident:
            return ident, True
    return "", False


def did_from_vm_url(vm: str) -> str:
    if not vm.startswith("did:"):
        return ""
    idx = vm.find("#")
    if idx > 0:
        return vm[:idx]
    return vm


def id_in_array(vm_id: str, doc_id: str, arr: list[str]) -> bool:
    frag = vm_id
    if len(vm_id) > len(doc_id) and vm_id[: len(doc_id)] == doc_id and vm_id[len(doc_id)] == "#":
        frag = vm_id[len(doc_id) :]
    return any(ref == vm_id or ref == frag for ref in arr)


_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def parse_rfc3339(ts: str) -> datetime:
    """Go time.Parse(time.RFC3339, ...): strict RFC 3339 only."""
    if not isinstance(ts, str) or not _RFC3339.match(ts):
        raise ValueError(f"invalid proof.created timestamp '{ts}': not RFC 3339")
    try:
        return datetime.fromisoformat(ts.upper().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid proof.created timestamp '{ts}': {exc}") from exc


def strict_purpose_check(
    doc: DIDDocument,
    vm: VerificationMethodEntry,
    proof_purpose: str,
    proof_created: str,
) -> None:
    if is_hard_revocation_reason(vm.revocation_reason):
        raise ValueError(
            f"verification method '{vm.id}' revoked with hard reason '{vm.revocation_reason}'"
        )

    if vm.revoked is not None:
        created = parse_rfc3339(proof_created)
        revoked = vm.revoked
        if revoked.tzinfo is None:
            revoked = revoked.replace(tzinfo=timezone.utc)
        if created >= revoked:
            raise ValueError(
                f"verification method '{vm.id}' was revoked at {revoked.isoformat().replace('+00:00', 'Z')}; "
                f"proof.created {created.isoformat().replace('+00:00', 'Z')} is not earlier"
            )

    if proof_purpose == "authentication":
        arr = doc.authentication
    elif proof_purpose == "assertionMethod":
        arr = doc.assertion_method
    else:
        raise ValueError(f"unsupported proofPurpose '{proof_purpose}'")

    if not id_in_array(vm.id, doc.id, arr):
        raise ValueError(
            f"verification method '{vm.id}' is not granted purpose '{proof_purpose}' on DID '{doc.id}'"
        )
