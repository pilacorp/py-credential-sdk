from __future__ import annotations

import copy
import json
from functools import lru_cache
from importlib import resources
from typing import Any

from pyld import jsonld
from pyld.canon import URDNA2015
from pyld.jsonld import JsonLdError, JsonLdProcessor
from pyld.nquads import parse_nquads

from credential.common.processor.processor import document_loader as _processor_document_loader

_CITIZENSHIP_URL = "https://w3id.org/citizenship/v4rc1"


@lru_cache  # type: ignore[name-defined]
def _load_citizenship_context() -> Any:
    pkg = resources.files("credential.common.ecdsasd")
    return json.loads(pkg.joinpath("w3c.citizenship.v4rc1.json").read_text(encoding="utf-8"))


def document_loader(url: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    if url == _CITIZENSHIP_URL or url == _CITIZENSHIP_URL + ".jsonld":
        return {"contextUrl": None, "document": _load_citizenship_context(), "documentUrl": url}
    return _processor_document_loader(url, options)


def _jsonld_options() -> dict[str, Any]:
    return {"documentLoader": document_loader, "processingMode": "json-ld-1.1"}


def preserve_native_types(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: preserve_native_types(v) for k, v in value.items()}
    if isinstance(value, list):
        return [preserve_native_types(v) for v in value]
    return value


def _is_relative_iri(s: str) -> bool:
    if not s or s.startswith("_:"):
        return False
    if s.startswith("urn:") or "://" in s:
        return False
    # Any other scheme (did:, data:, etc.) is not a relative IRI for RDF conversion.
    if ":" in s:
        return False
    return True


def _relative_keyword_values(value: Any, keyword: str, out: list[str] | None = None) -> list[str]:
    if out is None:
        out = []
    if isinstance(value, dict):
        for k, val in value.items():
            if k != keyword:
                _relative_keyword_values(val, keyword, out)
                continue
            items = val if isinstance(val, list) else [val]
            for kv in items:
                if isinstance(kv, str) and _is_relative_iri(kv):
                    out.append(kv)
    elif isinstance(value, list):
        for item in value:
            _relative_keyword_values(item, keyword, out)
    return out


def _raise_on_property_dropped(prop: str) -> None:
    raise JsonLdError(
        f"json-ld: property {prop!r} is not defined by @context and would be dropped, leaving it unsigned",
        "jsonld.ReadonlyContext",
    )


def expand_jsonld(doc: dict[str, Any]) -> list[Any]:
    std = preserve_native_types(doc)
    try:
        out = jsonld.expand(std, _jsonld_options(), on_property_dropped=_raise_on_property_dropped)
    except JsonLdError as exc:
        raise ValueError(f"expand: {exc}") from exc
    dropped = _relative_keyword_values(out, "@type")
    if dropped:
        raise ValueError(
            f"json-ld: type {dropped[0]!r} is not defined by @context and would be dropped, leaving it unsigned"
        )
    dropped = _relative_keyword_values(out, "@id")
    if dropped:
        raise ValueError(
            f"json-ld: id {dropped[0]!r} is not an absolute IRI and would be dropped, leaving the node unsigned"
        )
    return out


def compact_jsonld(expanded: list[Any], ctx: Any) -> dict[str, Any]:
    try:
        return jsonld.compact(expanded, ctx, _jsonld_options())
    except JsonLdError as exc:
        raise ValueError(f"compact: {exc}") from exc


def to_rdf_dataset(doc: Any) -> dict[str, list[dict[str, Any]]]:
    opts = {**_jsonld_options(), "produceGeneralizedRdf": False}
    try:
        dataset = JsonLdProcessor().to_rdf(doc, opts)
    except JsonLdError as exc:
        raise ValueError(f"canonicalize: to rdf: {exc}") from exc
    if not isinstance(dataset, dict):
        raise ValueError(f"canonicalize: unexpected to_rdf type {type(dataset)!r}")
    return dataset


def split_nquads_keep_nl(s: str) -> list[str]:
    parts = s.splitlines(keepends=True)
    out: list[str] = []
    for part in parts:
        if part.strip():
            if not part.endswith("\n"):
                part += "\n"
            out.append(part)
    return out


def _node_at(quad: dict[str, Any], idx: int) -> dict[str, Any] | None:
    key = ("subject", "object", "name")[idx]
    return quad.get(key)


def canonicalize_dataset_with_id_map(
    dataset: dict[str, list[dict[str, Any]]],
) -> tuple[list[str], dict[str, str]]:
    dataset_copy = copy.deepcopy(dataset)
    slots: list[tuple[dict[str, Any], int, str]] = []
    for triples in dataset_copy.values():
        for quad in triples:
            for idx in range(3):
                node = _node_at(quad, idx)
                if node is not None and node.get("type") == "blank node":
                    slots.append((quad, idx, node["value"]))

    opts = {**_jsonld_options(), "algorithm": "URDNA2015", "format": "application/n-quads"}
    try:
        res = URDNA2015().main(dataset_copy, opts)
    except JsonLdError as exc:
        raise ValueError(f"canonicalize: normalize: {exc}") from exc
    if not isinstance(res, str):
        raise ValueError(f"canonicalize: unexpected normalize type {type(res)!r}")

    id_map: dict[str, str] = {}
    for quad, idx, orig in slots:
        node = _node_at(quad, idx)
        if node is not None:
            id_map[orig] = node["value"]
    return split_nquads_keep_nl(res), id_map


def canonicalize_with_id_map(doc: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    if doc is None:
        raise ValueError("canonicalize: document is nil")
    dataset = to_rdf_dataset(expand_jsonld(doc))
    return canonicalize_dataset_with_id_map(dataset)


def canonicalize_nquads_with_id_map(nquads: list[str]) -> tuple[list[str], dict[str, str]]:
    try:
        dataset = parse_nquads("".join(nquads))
    except Exception as exc:
        raise ValueError(f"canonicalize: parse nquads: {exc}") from exc
    return canonicalize_dataset_with_id_map(dataset)


def canonicalize(doc: dict[str, Any]) -> bytes:
    nquads, err = _canonicalize_nquads(doc)
    if err:
        raise ValueError(f"failed to canonicalize document: {err}")
    canonical = "".join(nquads).encode("utf-8")
    if not canonical:
        raise ValueError("canonicalization produced no N-Quads; the document has no @context or no JSON-LD terms")
    return canonical


def _canonicalize_nquads(doc: dict[str, Any]) -> tuple[list[str] | None, str | None]:
    if doc is None:
        return None, "canonicalize: document is nil"
    try:
        dataset = to_rdf_dataset(expand_jsonld(doc))
    except ValueError as exc:
        return None, str(exc)
    opts = {**_jsonld_options(), "algorithm": "URDNA2015", "format": "application/n-quads"}
    try:
        res = URDNA2015().main(dataset, opts)
    except JsonLdError as exc:
        return None, f"canonicalize: normalize: {exc}"
    if not isinstance(res, str):
        return None, f"canonicalize: unexpected normalize type {type(res)!r}"
    return split_nquads_keep_nl(res), None


def to_rdf_nquads(doc: Any) -> list[str]:
    opts = {**_jsonld_options(), "format": "application/n-quads"}
    try:
        rdf = JsonLdProcessor().to_rdf(doc, opts)
    except JsonLdError as exc:
        raise ValueError(f"to rdf: {exc}") from exc
    if not isinstance(rdf, str):
        raise ValueError(f"to rdf: unexpected type {type(rdf)!r}")
    return split_nquads_keep_nl(rdf)
