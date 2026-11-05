"""JSON-LD processing: legacy canonicalizer + strict (lossless) canonicalizer.

Ports Go credential/common/processor.

* ``canonicalize_document``  == Go CanonicalizeDocument: numbers are coerced to
  xsd:string, undefined terms are silently dropped. Used ONLY for legacy hex
  proofs / JsonWebSignature2020 / legacy hash.
* ``canonicalize``           == Go Canonicalize: native number types are kept
  (xsd:integer / xsd:double) and undefined terms / types / relative ids are
  rejected. Both Data Integrity cryptosuites hash through here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from decimal import Decimal
from functools import lru_cache
from importlib import resources
from typing import Any, Callable
from urllib.request import urlopen

from pyld import jsonld
from pyld.canon import URDNA2015
from pyld.jsonld import JsonLdError, JsonLdProcessor
from pyld.nquads import parse_nquads

_CONTEXT_FILES = {
    "https://www.w3.org/2018/credentials/v1": "w3c.credential.v1.json",
    "https://www.w3.org/2018/credentials/v1.jsonld": "w3c.credential.v1.json",
    "https://www.w3.org/ns/credentials/v2": "w3c.credential.v2.json",
    "https://www.w3.org/ns/credentials/v2.jsonld": "w3c.credential.v2.json",
    "https://www.w3.org/ns/credentials/examples/v2": "w3c.credential.examples.v2.json",
    "https://www.w3.org/ns/credentials/examples/v2.jsonld": "w3c.credential.examples.v2.json",
    "https://w3id.org/security/data-integrity/v2": "w3c.security.data-integrity.v2.json",
    "https://w3id.org/security/v1": "w3c.security.v1.json",
    "https://w3id.org/security/v2": "w3c.security.v2.json",
    "https://w3id.org/security/suites/secp256k1-2019/v1": "w3c.security.secp256k1-2019.v1.json",
}

# Extra offline contexts registered by other modules (url -> zero-arg loader).
_EXTRA_CONTEXTS: dict[str, Callable[[], Any]] = {}


def register_context(url: str, loader: Callable[[], Any]) -> None:
    _EXTRA_CONTEXTS[url] = loader


@lru_cache(maxsize=32)
def _load_context_text(name: str) -> str:
    pkg = resources.files("credential.common.processor")
    return pkg.joinpath(name).read_text(encoding="utf-8")


def _load_context(name: str) -> Any:
    # Fresh object per call: pyld must never be able to mutate a shared context.
    return json.loads(_load_context_text(name))


def document_loader(url: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    name = _CONTEXT_FILES.get(url)
    if name:
        return {"contextUrl": None, "document": _load_context(name), "documentUrl": url}
    extra = _EXTRA_CONTEXTS.get(url)
    if extra is not None:
        return {"contextUrl": None, "document": copy.deepcopy(extra()), "documentUrl": url}
    with urlopen(url, timeout=30) as resp:  # noqa: S310
        return {"contextUrl": None, "document": json.loads(resp.read()), "documentUrl": url}


# ---------------------------------------------------------------- legacy path


class _LegacyProcessor(JsonLdProcessor):
    """pyld drops a relative IRI @type object when converting to RDF; json-gold (the Go legacy path) emits
    it as ``<Type>``. Credentials whose type no context defines (very common on VC 1.1 documents) were
    hashed that way, so legacy proofs only verify if the same quad is produced."""

    def _graph_to_rdf(self, graph, issuer, options):  # noqa: ANN001
        triples = super()._graph_to_rdf(graph, issuer, options)
        extra = []
        for id_, node in sorted(graph.items()):
            if not _is_abs(id_):
                continue
            for item in node.get("@type", []):
                if isinstance(item, str) and not item.startswith("@") and not _is_abs(item):
                    extra.append(
                        {
                            "subject": {"type": "blank node" if id_.startswith("_:") else "IRI", "value": id_},
                            "predicate": {"type": "IRI", "value": "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"},
                            "object": {"type": "IRI", "value": item},
                        }
                    )
        return triples + extra


def _is_abs(v: str) -> bool:
    return bool(re.match(r"^([A-Za-z][A-Za-z0-9+.-]*|_):[^\s]*$", v))


_UNGRAPHED_TERMS = frozenset({"verifiableCredential"})  # see _strip_graph_containers


def _strip_graph_containers(node: Any) -> Any:
    """json-gold (the Go legacy path) scopes a ``@container: @graph`` value into its own named
    graph only when the value is anonymous (e.g. a ``proof``); a value that carries its own
    ``@id`` (e.g. ``verifiableCredential``, always an IRI-identified VC) is referenced directly
    and its triples stay in the default graph instead. pyld always creates the named graph, so a
    legacy (pre-v1.7.0) proof only verifies if this quirk is reproduced for THIS canonicalizer.
    Term names, not values, are matched: the bundled contexts have exactly two @graph-container
    terms (``proof``, ``verifiableCredential``), and only the latter is ever @id-bearing."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in _UNGRAPHED_TERMS and isinstance(v, dict) and v.get("@container") == "@graph":
                v = {kk: vv for kk, vv in v.items() if kk != "@container"}
            out[k] = _strip_graph_containers(v)
        return out
    if isinstance(node, list):
        return [_strip_graph_containers(v) for v in node]
    return node


def _legacy_document_loader(url: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    result = document_loader(url, options)
    doc = result.get("document")
    if isinstance(doc, dict) and "@context" in doc:
        result = {**result, "document": {**doc, "@context": _strip_graph_containers(doc["@context"])}}
    return result


def canonicalize_document(doc: dict[str, Any]) -> bytes:
    """Legacy URDNA2015 canonicalization (numbers -> xsd:string, undefined terms dropped)."""
    if doc is None:
        raise ValueError("failed to canonicalize document: document is nil")
    try:
        nquads = _LegacyProcessor().normalize(
            _standardize(doc),
            {
                "algorithm": "URDNA2015",
                "format": "application/n-quads",
                "documentLoader": _legacy_document_loader,
                # No base IRI (like Go's NewJsonLdOptions("")): pyld otherwise resolves a relative id against a
                # made-up http://example.org/base/, signing a node Go would drop or reject.
                "base": None,
            },
        )
    except Exception as exc:  # pyld raises JsonLdError and, on adversarial input, plain exceptions
        raise ValueError(f"canonicalize document: malformed JSON-LD input: {exc}") from exc
    return nquads.encode("utf-8")


def compute_digest(data: bytes) -> bytes:
    if data is None:
        raise ValueError("failed to compute digest: input data is nil")
    return hashlib.sha256(data).digest()


def compute_document_digest(doc: dict[str, Any]) -> bytes:
    return compute_digest(canonicalize_document(doc))


def _standardize(input: dict[str, Any]) -> dict[str, Any]:
    if input is None:
        raise ValueError("failed to standardize to JSON-LD: input is nil")
    return {k: _convert(v) for k, v in input.items()}


def go_fmt_number(value: int | float) -> str:
    """Render a JSON number like Go ``fmt.Sprintf("%v", float64(x))``: shortest digits, e-notation when the
    decimal exponent is < -4 or >= 6 (so 1234567 -> "1.234567e+06", 100000 -> "100000")."""
    f = float(value)
    if f != f:
        return "NaN"
    if f in (float("inf"), float("-inf")):
        return "+Inf" if f > 0 else "-Inf"
    if f == 0:
        return "-0" if str(f).startswith("-") else "0"
    sign, digits, exp = Decimal(repr(f)).as_tuple()
    ds = "".join(map(str, digits)).rstrip("0") or "0"
    dp = len(digits) + exp  # decimal point position relative to the digit string
    e10 = dp - 1
    neg = "-" if sign else ""
    if e10 < -4 or e10 >= 6:
        mant = ds[0] + ("." + ds[1:] if len(ds) > 1 else "")
        return f"{neg}{mant}e{'-' if e10 < 0 else '+'}{abs(e10):02d}"
    if dp <= 0:
        return f"{neg}0.{'0' * -dp}{ds}"
    if dp >= len(ds):
        return f"{neg}{ds}{'0' * (dp - len(ds))}"
    return f"{neg}{ds[:dp]}.{ds[dp:]}"


def _convert(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_convert(v) for v in value]
    if isinstance(value, dict):
        return {k: _convert(v) for k, v in value.items()}
    if isinstance(value, bool):
        return {"@value": "true" if value else "false", "@type": "http://www.w3.org/2001/XMLSchema#boolean"}
    if isinstance(value, (int, float)):
        # Go parses every JSON number as float64, so format as one.
        return {"@value": go_fmt_number(value), "@type": "http://www.w3.org/2001/XMLSchema#string"}
    return {"@value": str(value), "@type": "http://www.w3.org/2001/XMLSchema#string"}


# ---------------------------------------------------------------- strict path


def _opts(**extra: Any) -> dict[str, Any]:
    return {"documentLoader": document_loader, "processingMode": "json-ld-1.1", "base": None, **extra}


def preserve_native_types(value: Any) -> Any:
    # Go reads every JSON number as float64, so integers beyond 2**53 are rounded there.
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2**53:
        return float(value)
    if isinstance(value, dict):
        return {k: preserve_native_types(v) for k, v in value.items()}
    if isinstance(value, list):
        return [preserve_native_types(v) for v in value]
    return value


def _is_relative_iri(s: str) -> bool:
    if not s or s.startswith("_:"):
        return False
    if s.startswith("@"):
        return False
    return ":" not in s


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
    """Lossless expansion: rejects dropped properties, types and relative ids."""
    if doc is None:
        raise ValueError("expand: standardize: failed to standardize to JSON-LD: input is nil")
    std = preserve_native_types(doc)
    try:
        out = jsonld.expand(std, _opts(), on_property_dropped=_raise_on_property_dropped)
    except JsonLdError as exc:
        raise ValueError(f"expand: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"expand: malformed JSON-LD input: {exc}") from exc
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
        return jsonld.compact(expanded, ctx, _opts())
    except JsonLdError as exc:
        raise ValueError(f"compact: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"compact: malformed JSON-LD input: {exc}") from exc


def to_rdf_dataset(doc: Any) -> dict[str, list[dict[str, Any]]]:
    opts = _opts(produceGeneralizedRdf=False)
    try:
        dataset = JsonLdProcessor().to_rdf(doc, opts)
    except JsonLdError as exc:
        raise ValueError(f"canonicalize: to rdf: {exc}") from exc
    if not isinstance(dataset, dict):
        raise ValueError(f"canonicalize: unexpected to_rdf type {type(dataset)!r}")
    return dataset


def split_nquads_keep_nl(s: str) -> list[str]:
    out: list[str] = []
    for part in s.splitlines(keepends=True):
        if part.strip():
            if not part.endswith("\n"):
                part += "\n"
            out.append(part)
    return out


def _node_at(quad: dict[str, Any], idx: int) -> dict[str, Any] | None:
    return quad.get(("subject", "object", "name")[idx])


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
    opts = _opts(algorithm="URDNA2015", format="application/n-quads")
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
    return canonicalize_dataset_with_id_map(to_rdf_dataset(expand_jsonld(doc)))


def canonicalize_nquads_with_id_map(nquads: list[str]) -> tuple[list[str], dict[str, str]]:
    try:
        dataset = parse_nquads("".join(nquads))
    except Exception as exc:
        raise ValueError(f"canonicalize: parse nquads: {exc}") from exc
    return canonicalize_dataset_with_id_map(dataset)


def canonicalize_nquads(doc: dict[str, Any]) -> list[str]:
    if doc is None:
        raise ValueError("canonicalize: document is nil")
    nquads, _ = canonicalize_dataset_with_id_map(to_rdf_dataset(expand_jsonld(doc)))
    return nquads


def canonicalize(doc: dict[str, Any]) -> bytes:
    """Strict canonicalization (Go processor.Canonicalize)."""
    try:
        nquads = canonicalize_nquads(doc)
    except ValueError as exc:
        raise ValueError(f"failed to canonicalize document: {exc}") from exc
    canonical = "".join(nquads).encode("utf-8")
    if not canonical:
        raise ValueError("canonicalization produced no N-Quads; the document has no @context or no JSON-LD terms")
    return canonical


def to_rdf_nquads(doc: Any) -> list[str]:
    """N-Quads of ``doc`` in toRDF order (not canonicalized), each ending in newline."""
    try:
        rdf = JsonLdProcessor().to_rdf(doc, _opts(format="application/n-quads"))
    except JsonLdError as exc:
        raise ValueError(f"to rdf: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"to rdf: malformed JSON-LD input: {exc}") from exc
    if not isinstance(rdf, str):
        raise ValueError(f"to rdf: unexpected type {type(rdf)!r}")
    return split_nquads_keep_nl(rdf)


def sort_nquads(nquads: list[str]) -> list[str]:
    return sorted(nquads)


def to_nquads(doc: Any) -> list[str]:
    """Sorted N-Quads of a JSON-LD document (Go processor.ToNQuads)."""
    return sort_nquads([q.rstrip("\n") for q in to_rdf_nquads(doc)])
