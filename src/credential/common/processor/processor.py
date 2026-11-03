from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from importlib import resources
from typing import Any
from urllib.request import urlopen

from pyld import jsonld

_CONTEXT_FILES = {
    "https://www.w3.org/2018/credentials/v1": "w3c.credential.v1.json",
    "https://www.w3.org/2018/credentials/v1.jsonld": "w3c.credential.v1.json",
    "https://www.w3.org/ns/credentials/v2": "w3c.credential.v2.json",
    "https://www.w3.org/ns/credentials/v2.jsonld": "w3c.credential.v2.json",
    "https://www.w3.org/ns/credentials/examples/v2": "w3c.credential.examples.v2.json",
    "https://www.w3.org/ns/credentials/examples/v2.jsonld": "w3c.credential.examples.v2.json",
    "https://w3id.org/security/data-integrity/v2": "w3c.security.data-integrity.v2.json",
    "https://w3id.org/security/data-integrity/v2.jsonld": "w3c.security.data-integrity.v2.json",
    "https://w3id.org/security/v1": "w3c.security.v1.json",
    "https://w3id.org/security/v2": "w3c.security.v2.json",
    "https://w3id.org/security/suites/secp256k1-2019/v1": "w3c.security.secp256k1-2019.v1.json",
}


@lru_cache(maxsize=32)
def _load_context(name: str) -> Any:
    pkg = resources.files("credential.common.processor")
    return json.loads(pkg.joinpath(name).read_text(encoding="utf-8"))


def document_loader(url: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    name = _CONTEXT_FILES.get(url)
    if name:
        return {"contextUrl": None, "document": _load_context(name), "documentUrl": url}
    with urlopen(url) as resp:  # noqa: S310
        return {"contextUrl": None, "document": json.loads(resp.read()), "documentUrl": url}


def canonicalize_document(doc: dict[str, Any]) -> bytes:
    if not doc:
        raise ValueError("failed to canonicalize document: document is nil")
    nquads = jsonld.normalize(
        _standardize(doc),
        {
            "algorithm": "URDNA2015",
            "format": "application/n-quads",
            "documentLoader": document_loader,
        },
    )
    return nquads.encode("utf-8")


def compute_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_document_digest(doc: dict[str, Any]) -> bytes:
    return compute_digest(canonicalize_document(doc))


def expand_jsonld(doc: Any) -> list[Any]:
    return jsonld.expand(doc, {"documentLoader": document_loader})


def compact_jsonld(expanded: Any, ctx: Any) -> dict[str, Any]:
    return jsonld.compact(expanded, ctx, {"documentLoader": document_loader})


def to_rdf_nquads(doc: Any) -> list[str]:
    nquads = jsonld.normalize(
        doc,
        {"algorithm": "URDNA2015", "format": "application/n-quads", "documentLoader": document_loader},
    )
    return [line for line in nquads.split("\n") if line]


def _standardize(input: dict[str, Any]) -> dict[str, Any]:
    return {k: _convert(v) for k, v in input.items()}


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
        return {"@value": str(value), "@type": "http://www.w3.org/2001/XMLSchema#string"}
    return {"@value": str(value), "@type": "http://www.w3.org/2001/XMLSchema#string"}
