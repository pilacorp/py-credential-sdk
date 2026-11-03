from credential.common.processor import canonicalize_document, compute_document_digest


def test_rdfc_digest() -> None:
    doc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "credentialSubject": {"id": "did:example:subject"},
    }
    nquads = canonicalize_document(doc)
    assert b"<urn:uuid:1>" in nquads or b"urn:uuid:1" in nquads
    digest = compute_document_digest(doc)
    assert len(digest) == 32
    assert compute_document_digest(doc) == digest
