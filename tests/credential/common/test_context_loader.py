"""Untrusted @context fetch (issue #4) and canonicalization work limit (issue #5)."""

import pytest
from pyld.jsonld import JsonLdError

from pila_credential.credential.common.processor import processor as P


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


def test_schema_validation_rejects():
    import json

    from pila_credential.credential.vc import credential_helper as h

    class O:
        loaded_schema_loader = None

    cred = {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"], "issuer": "did:x:1",
            "credentialSubject": {"id": "did:x:2"}, "credentialSchema": {"id": "https://s.example/1", "type": "JsonSchema"}}
    # reproduce only the schema branch: other required props may fail first, so call with required keys present
    for k in h.REQUIRED_CREDENTIAL_PROPERTIES:
        cred.setdefault(k, "x")
    with pytest.raises(ValueError, match="requires a schema loader"):
        h.validate_credential(cred, O())
    O.loaded_schema_loader = staticmethod(lambda u: b"not json")
    with pytest.raises(ValueError, match="parse schema"):
        h.validate_credential(cred, O())
    O.loaded_schema_loader = staticmethod(lambda u: json.dumps({"required": ["nope"]}).encode())
    with pytest.raises(ValueError, match="does not match schema"):
        h.validate_credential(cred, O())


def test_non_finite_numbers_and_uncompressed_multikey_rejected():
    from pila_credential.credential.common.util.json import strict_loads
    from pila_credential.credential.common.verification_method.key_material import ec_pub_from_multikey_bytes

    for bad in ('{"a": NaN}', '{"a": Infinity}', '{"a": 1e400}'):
        with pytest.raises(ValueError):
            strict_loads(bad)
    assert strict_loads('{"a": 1.5}') == {"a": 1.5}
    with pytest.raises(ValueError):
        ec_pub_from_multikey_bytes(bytes([0x80, 0x24]) + b"\x04" + b"\x01" * 64)
