from __future__ import annotations

import base64
import hmac
import os
import re
from hashlib import sha256
from typing import Any

from credential.common.ecdsasd.helpers import deep_copy
from credential.common.ecdsasd.ld import (
    canonicalize_nquads_with_id_map,
    compact_jsonld,
    expand_jsonld,
    to_rdf_nquads,
)
from credential.common.ecdsasd.pointer import select_json_ld

URN_BNID_RE = re.compile(r"<urn:bnid:([^>]+)>")
BNODE_RE = re.compile(r"_:([^\s]+)")


class SkolemLabeler:
    def __init__(self, prefix: str, random_hex: str) -> None:
        self.prefix = prefix
        self.random = random_hex
        self.count = 0


def skolemize_expanded(expanded: list[Any], labeler: SkolemLabeler) -> list[Any]:
    out: list[Any] = []
    for element in expanded:
        if not isinstance(element, dict):
            out.append(deep_copy(element))
            continue
        if "@value" in element:
            out.append(deep_copy(element))
            continue
        node: dict[str, Any] = {}
        for prop, value in element.items():
            if isinstance(value, list):
                node[prop] = skolemize_expanded(value, labeler)
            else:
                node[prop] = skolemize_expanded([value], labeler)[0]
        id_val = node.get("@id")
        if not isinstance(id_val, str):
            node["@id"] = f"{labeler.prefix}_{labeler.random}_{labeler.count}"
            labeler.count += 1
        elif id_val.startswith("_:"):
            node["@id"] = labeler.prefix + id_val[2:]
        out.append(node)
    return out


def skolemize_compact_json_ld(document: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    expanded = expand_jsonld(document)
    random_hex = os.urandom(16).hex()
    labeler = SkolemLabeler("urn:bnid:", random_hex)
    skolemized = skolemize_expanded(expanded, labeler)
    compact = compact_jsonld(skolemized, document["@context"])
    return skolemized, compact


def deskolemize_nquads(nquads: list[str]) -> list[str]:
    out: list[str] = []
    for nq in nquads:
        if "<urn:bnid:" in nq:
            out.append(URN_BNID_RE.sub(r"_:\1", nq))
        else:
            out.append(nq)
    return out


def to_deskolemized_nquads(document: Any) -> list[str]:
    return deskolemize_nquads(to_rdf_nquads(document))


def relabel_blank_nodes(nquads: list[str], label_map: dict[str, str]) -> list[str]:
    out: list[str] = []

    def repl(match: re.Match[str]) -> str:
        label = match.group(1)
        nl = label_map.get(label)
        if nl is not None:
            return "_:" + nl
        return match.group(0)

    for nq in nquads:
        out.append(BNODE_RE.sub(repl, nq))
    return out


def create_hmac_label_map(canonical_id_map: dict[str, str], hmac_key: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for input_label, c14n in canonical_id_map.items():
        mac = hmac.new(hmac_key, c14n.encode("utf-8"), sha256).digest()
        out[input_label] = "u" + base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")
    return out


def label_replacement_canonicalize_nquads(
    nquads: list[str], hmac_key: bytes
) -> tuple[list[str], dict[str, str]]:
    canonical_nquads, raw_id_map = canonicalize_nquads_with_id_map(nquads)
    canonical_id_map = {k.removeprefix("_:"): v.removeprefix("_:") for k, v in raw_id_map.items()}
    label_map = create_hmac_label_map(canonical_id_map, hmac_key)
    c14n_to_new = {canonical_id_map[inp]: new for inp, new in label_map.items()}
    out = relabel_blank_nodes(canonical_nquads, c14n_to_new)
    out.sort()
    return out, label_map


def select_canonical_nquads(
    compact: dict[str, Any], pointers: list[str], label_map: dict[str, str]
) -> tuple[list[str] | None, list[str] | None]:
    selection = select_json_ld(compact, pointers)
    if selection is None:
        return None, None
    deskolemized = to_deskolemized_nquads(selection)
    return deskolemized, relabel_blank_nodes(deskolemized, label_map)


class GroupIndexes:
    def __init__(self) -> None:
        self.matching: dict[int, str] = {}
        self.non_matching: dict[int, str] = {}
        self.deskolemized_nquads: list[str] = []


class GroupedCanon:
    def __init__(self) -> None:
        self.hmac_nquads: list[str] = []
        self.label_map: dict[str, str] = {}
        self.skolemized_compact: dict[str, Any] = {}
        self.groups: dict[str, GroupIndexes] = {}


def canonicalize_and_group(
    document: dict[str, Any], hmac_key: bytes, groups: dict[str, list[str]]
) -> GroupedCanon:
    sk_expanded, compact = skolemize_compact_json_ld(document)
    deskolemized = to_deskolemized_nquads(sk_expanded)
    hmac_nquads, label_map = label_replacement_canonicalize_nquads(deskolemized, hmac_key)

    result = GroupedCanon()
    result.hmac_nquads = hmac_nquads
    result.label_map = label_map
    result.skolemized_compact = compact

    for name, pointers in groups.items():
        desk, sel_nquads = select_canonical_nquads(compact, pointers, label_map)
        sel_set = set(sel_nquads or [])
        gi = GroupIndexes()
        gi.deskolemized_nquads = desk or []
        for idx, nq in enumerate(hmac_nquads):
            if nq in sel_set:
                gi.matching[idx] = nq
            else:
                gi.non_matching[idx] = nq
        result.groups[name] = gi
    return result


def sorted_indexes(m: dict[int, str]) -> list[int]:
    return sorted(m.keys())
