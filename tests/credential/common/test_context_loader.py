"""Untrusted @context fetch (issue #4) and canonicalization work limit (issue #5)."""

import pytest
from pyld.jsonld import JsonLdError

from credential.common.processor import processor as P


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://127.0.0.1:9/x", "https://127.0.0.1/x"])
def test_unknown_context_is_not_fetched(url):
    with pytest.raises(JsonLdError):
        P.document_loader(url)


def test_blank_node_work_limit():
    def doc(k):
        return {"@context": {"@vocab": "https://ex.example/"}, "@id": "https://ex.example/x",
                "a": [{"c": [{"v": "1"} for _ in range(k)]} for _ in range(2)]}

    P.canonicalize_with_id_map(doc(3))
    with pytest.raises(P.ErrBlankNodeWork):
        P.canonicalize_with_id_map(doc(8))
    with pytest.raises(ValueError):
        P.canonicalize_document(doc(8))
