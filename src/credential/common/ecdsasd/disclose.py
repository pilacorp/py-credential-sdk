from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from credential.common.ecdsasd.labelmap import canonicalize_and_group, sorted_indexes
from credential.common.ecdsasd.ld import canonicalize_nquads_with_id_map
from credential.common.ecdsasd.pointer import select_json_ld
from credential.common.ecdsasd.proofvalue import parse_base_proof_value


@dataclass
class DisclosureData:
    base_signature: bytes
    public_key: bytes
    signatures: list[bytes]
    label_map: dict[str, str]
    mandatory_indexes: list[int]
    reveal_doc: dict[str, Any]


def create_disclosure_data(
    document: dict[str, Any], base_proof_value: str, selective_pointers: list[str]
) -> DisclosureData:
    bp = parse_base_proof_value(base_proof_value)
    combined = list(bp.mandatory_pointers) + list(selective_pointers)
    grouped = canonicalize_and_group(
        document,
        bp.hmac_key,
        {
            "mandatory": bp.mandatory_pointers,
            "selective": selective_pointers,
            "combined": combined,
        },
    )
    mandatory_group = grouped.groups["mandatory"]
    selective_group = grouped.groups["selective"]
    combined_group = grouped.groups["combined"]

    mandatory_indexes: list[int] = []
    for rel, abs_idx in enumerate(sorted_indexes(combined_group.matching)):
        if abs_idx in mandatory_group.matching:
            mandatory_indexes.append(rel)

    filtered: list[bytes] = []
    index = 0
    for sig in bp.signatures:
        while index in mandatory_group.matching:
            index += 1
        if index in selective_group.matching:
            filtered.append(sig)
        index += 1

    reveal_doc = select_json_ld(document, combined)
    if reveal_doc is None:
        raise ValueError("ecdsasd: no statements to reveal; provide mandatory or selective pointers")

    _, raw_id_map = canonicalize_nquads_with_id_map(combined_group.deskolemized_nquads)
    verifier_label_map: dict[str, str] = {}
    for input_label, c14n in raw_id_map.items():
        in_label = input_label.removeprefix("_:")
        verifier = c14n.removeprefix("_:")
        verifier_label_map[verifier] = grouped.label_map[in_label]

    return DisclosureData(
        base_signature=bp.base_signature,
        public_key=bp.public_key,
        signatures=filtered,
        label_map=verifier_label_map,
        mandatory_indexes=mandatory_indexes,
        reveal_doc=reveal_doc,
    )
