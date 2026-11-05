"""Thin re-export of the processor's strict JSON-LD primitives (Go: credential/common/processor)."""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from credential.common.processor import processor as _p
from credential.common.processor.processor import (  # noqa: F401
    canonicalize,
    canonicalize_dataset_with_id_map,
    canonicalize_nquads_with_id_map,
    canonicalize_with_id_map,
    compact_jsonld,
    document_loader,
    expand_jsonld,
    preserve_native_types,
    split_nquads_keep_nl,
    to_rdf_dataset,
    to_rdf_nquads,
)

_CITIZENSHIP_URL = "https://w3id.org/citizenship/v4rc1"


@lru_cache
def _load_citizenship_context() -> Any:
    pkg = resources.files("credential.common.ecdsasd")
    return json.loads(pkg.joinpath("w3c.citizenship.v4rc1.json").read_text(encoding="utf-8"))


# Test-vector context (W3C ecdsa-sd-2023 spec examples); the Go suite fetches it over the network.
_p.register_context(_CITIZENSHIP_URL, _load_citizenship_context)
_p.register_context(_CITIZENSHIP_URL + ".jsonld", _load_citizenship_context)
