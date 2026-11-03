from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from credential.vc import credential_helper as helper
from credential.vc.credential import (
    CredentialContents,
    ParsedJSONCredential,
    Schema,
    Status,
    Subject,
    TermsOfUse,
    get_options,
    new_jwt_credential,
    parse_credential,
    subject_from_json,
    with_base_url,
    with_check_revocation,
    with_resolver,
    with_verification_method_key,
)


def test_dot_paths_to_pointers_cases():
    cases = [
        (["credentialSubject.name"], ["/credentialSubject/name"]),
        (["issuer"], ["/issuer"]),
        (["credentialSubject.0.name"], ["/credentialSubject/0/name"]),
        (["a.b.c.d"], ["/a/b/c/d"]),
        (["meta.a/b"], ["/meta/a~1b"]),
        (["meta.a~b"], ["/meta/a~0b"]),
        (["meta.a~1b"], ["/meta/a~01b"]),
        (["a~b.c/d"], ["/a~0b/c~1d"]),
        (["họ tên.số nhà"], ["/họ tên/số nhà"]),
        (["/credentialSubject/name"], ["/credentialSubject/name"]),
        (["/issuer"], ["/issuer"]),
        (["/credentialSubject/0/name"], ["/credentialSubject/0/name"]),
        (["/a~0b/c~1d"], ["/a~0b/c~1d"]),
        (["/meta/a~1b"], ["/meta/a~1b"]),
        (["/meta/a.b"], ["/meta/a.b"]),
        (["/"], ["/"]),
        (
            ["credentialSubject.name", "/credentialSubject/name"],
            ["/credentialSubject/name", "/credentialSubject/name"],
        ),
        (["meta.a/b", "/meta/a~1b"], ["/meta/a~1b", "/meta/a~1b"]),
        (["/issuer", "credentialSubject.name", "/validFrom"], ["/issuer", "/credentialSubject/name", "/validFrom"]),
        (["", "/issuer", ""], ["/issuer"]),
        (["", ""], []),
        (None, []),
        ([], []),
        ([".a"], ["//a"]),
        (["a."], ["/a/"]),
        (["a..b"], ["/a//b"]),
    ]
    for inp, want in cases:
        assert helper.dot_paths_to_pointers(inp) == want


def test_dot_paths_to_pointers_does_not_mutate_input():
    inp = ["credentialSubject.name", "/issuer"]
    orig = copy.copy(inp)
    helper.dot_paths_to_pointers(inp)
    assert inp == orig


def test_parse_context():
    contents = CredentialContents()
    err = helper.parse_context(
        {"@context": ["https://www.w3.org/2018/credentials/v1", {"custom": "context"}]},
        contents,
    )
    assert err is None
    assert contents.context == ["https://www.w3.org/2018/credentials/v1", {"custom": "context"}]

    contents = CredentialContents()
    with pytest.raises(ValueError, match="unsupported context type: int"):
        helper.parse_context({"@context": [1]}, contents)


def test_parse_id():
    contents = CredentialContents()
    helper.parse_id({"id": "urn:uuid:1234"}, contents)
    assert contents.id == "urn:uuid:1234"


@pytest.mark.parametrize(
    ("credential", "expected", "error_msg"),
    [
        ({"type": "VerifiableCredential"}, ["VerifiableCredential"], None),
        (
            {"type": ["VerifiableCredential", "CustomCredential"]},
            ["VerifiableCredential", "CustomCredential"],
            None,
        ),
        ({"type": 123}, None, "unsupported type field: int"),
    ],
)
def test_parse_types(credential, expected, error_msg):
    contents = CredentialContents()
    if error_msg:
        with pytest.raises(ValueError, match=error_msg):
            helper.parse_types(credential, contents)
    else:
        helper.parse_types(credential, contents)
        assert contents.types == expected


@pytest.mark.parametrize(
    ("issuer", "expected"),
    [
        ("did:example:issuer", "did:example:issuer"),
        ({"id": "did:example:issuer", "name": "Example"}, "did:example:issuer"),
        ({"name": "Example"}, ""),
        ("", ""),
        (None, ""),
    ],
)
def test_parse_issuer(issuer, expected):
    credential: dict = {}
    if issuer is not None:
        credential["issuer"] = issuer
    contents = CredentialContents()
    helper.parse_issuer(credential, contents)
    assert contents.issuer == expected


def test_parse_dates():
    fixed = datetime(2025, 8, 5, 10, 0, 0, tzinfo=timezone.utc)
    credential = {
        "validFrom": fixed.isoformat().replace("+00:00", "Z"),
        "validUntil": (fixed + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
    }
    contents = CredentialContents()
    helper.parse_dates(credential, contents)
    assert contents.valid_from == fixed
    assert contents.valid_until == fixed + timedelta(hours=24)


def test_check_expiration_valid_window():
    now = datetime.now(timezone.utc)
    credential = {
        "validFrom": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "validUntil": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    helper.check_expiration(credential, timedelta(0))


def test_check_expiration_not_valid_yet():
    now = datetime.now(timezone.utc)
    credential = {"validFrom": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    with pytest.raises(ValueError, match="credential is not valid yet"):
        helper.check_expiration(credential, timedelta(0))


def test_check_expiration_expired():
    now = datetime.now(timezone.utc)
    credential = {"validUntil": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    with pytest.raises(ValueError, match="credential is expired"):
        helper.check_expiration(credential, timedelta(0))


def test_parse_subject():
    contents = CredentialContents()
    helper.parse_subject(
        {"credentialSubject": {"id": "did:example:subject1", "name": "John Doe"}},
        contents,
    )
    assert contents.subject == [
        Subject(id="did:example:subject1", custom_fields={"name": "John Doe"}),
    ]

    contents = CredentialContents()
    helper.parse_subject(
        {
            "credentialSubject": [
                {"id": "did:example:subject1"},
                {"id": "did:example:subject2"},
            ]
        },
        contents,
    )
    assert contents.subject == [
        Subject(id="did:example:subject1"),
        Subject(id="did:example:subject2"),
    ]

    contents = CredentialContents()
    with pytest.raises(ValueError, match="unsupported subject format: int"):
        helper.parse_subject({"credentialSubject": 123}, contents)


def test_parse_schema():
    contents = CredentialContents()
    helper.parse_schema(
        {
            "credentialSchema": {
                "id": "https://example.org/schema/1",
                "type": "JsonSchemaValidator2019",
            }
        },
        contents,
    )
    assert contents.schemas == [
        Schema(id="https://example.org/schema/1", type="JsonSchemaValidator2019"),
    ]


def test_parse_status():
    contents = CredentialContents()
    helper.parse_status(
        {
            "credentialStatus": {
                "id": "https://example.org/status/1",
                "type": "StatusList2021Entry",
            }
        },
        contents,
    )
    assert contents.credential_status == [
        Status(id="https://example.org/status/1", type="StatusList2021Entry"),
    ]


def test_parse_proofs():
    fixed = datetime(2025, 8, 5, 10, 0, 0, tzinfo=timezone.utc)
    contents = CredentialContents()
    helper.parse_proofs(
        {
            "proof": {
                "type": "Ed25519Signature2020",
                "created": fixed.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        },
        contents,
    )


def test_subject_from_json():
    result = subject_from_json({"id": "did:example:subject1", "name": "John Doe"})
    assert result == Subject(id="did:example:subject1", custom_fields={"name": "John Doe"})


def test_parse_status_entry():
    result = helper.parse_status_entry(
        {
            "id": "https://example.org/status/1",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "123",
            "statusListCredential": "https://example.org/credential/1",
        }
    )
    assert result == Status(
        id="https://example.org/status/1",
        type="StatusList2021Entry",
        status_purpose="revocation",
        status_list_index="123",
        status_list_credential="https://example.org/credential/1",
    )


def test_parse_schema_id():
    result = helper.parse_schema_id(
        {"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"}
    )
    assert result == Schema(id="https://example.org/schema/1", type="JsonSchemaValidator2019")


def test_parse_string_field():
    assert helper.parse_string_field({"id": "did:example:subject1"}, "id") == "did:example:subject1"
    with pytest.raises(ValueError, match='field "id" must be a string'):
        helper.parse_string_field({"id": 123}, "id")


REVOKED_JSON = b"""{
  "id": "did:nda:testnet:95c00e62-76ff-46a1-b2bc-f1d3b80d0aa9",
  "type": "VerifiableCredential",
  "proof": {
    "type": "DataIntegrityProof",
    "created": "2025-12-03T14:31:25Z",
    "proofValue": "e693cea7102b8edee4ccc12a48682fe2836a28c52cc6936600ec39e962cec89b729ccf98d96c2124ee23cee9cdacaef0c31565a98a09b3a5087bb0c7cdf1df48",
    "cryptosuite": "ecdsa-rdfc-2019",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb#key-1"
  },
  "issuer": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "validFrom": "2025-08-29T09:01:51Z",
  "validUntil": "2026-08-29T09:01:51Z",
  "credentialSchema": {
    "id": "https://auth-dev.pila.vn/api/v1/schemas/71a14ce1-c8fa-4df4-960b-e18bb6282cee",
    "type": "JsonSchema"
  },
  "credentialStatus": {
    "id": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb/credentials/status/0#18",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "18",
    "statusListCredential": "https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb/credentials/status/0"
  },
  "credentialSubject": {
    "id": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb",
    "age": 10,
    "name": "Test Create",
    "salary": 50000,
    "department": "Engineering"
  }
}"""

NOT_REVOKED_JSON = b"""{
  "id": "did:nda:testnet:593c544e-6df8-4bfa-bc61-c45b53b07b03",
  "type": "VerifiableCredential",
  "issuer": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "validFrom": "2025-09-25T07:57:04Z",
  "validUntil": "2026-09-25T07:57:04Z",
  "credentialSchema": {
    "id": "https://auth-dev.pila.vn/api/v1/schemas/63a39bc9-b52b-42cb-be7e-28c096d93174",
    "type": "JsonSchema"
  },
  "credentialStatus": {
    "id": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/260#790",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "790",
    "statusListCredential": "https://auth-dev.pila.vn/api/v1/issuers/did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/260"
  },
  "credentialSubject": {
    "id": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
    "age": 10,
    "name": "Test Create JSON",
    "salary": 50000,
    "department": "Engineering"
  }
}"""


def test_check_revocation_revoked_json_credential():
    with pytest.raises(ValueError, match="credential is revoked"):
        parse_credential(REVOKED_JSON, with_check_revocation())


def test_check_revocation_not_revoked_json_credential():
    parse_credential(NOT_REVOKED_JSON, with_check_revocation())


def test_check_revocation_empty_status_json_credential():
    doc = NOT_REVOKED_JSON.decode("utf-8").replace(
        '"statusListIndex": "790",', ""
    ).replace(
        '"statusListCredential": "https://auth-dev.pila.vn/api/v1/issuers/did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/260",',
        "",
    )
    import json as json_mod

    payload = json_mod.loads(doc)
    payload["credentialStatus"] = {}
    parse_credential(json_mod.dumps(payload).encode("utf-8"), with_check_revocation())


def test_check_revocation_no_status_field_json_credential():
    import json as json_mod

    payload = json_mod.loads(NOT_REVOKED_JSON)
    payload.pop("credentialStatus", None)
    parse_credential(json_mod.dumps(payload).encode("utf-8"), with_check_revocation())


REVOKED_JWT = (
    "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyMjIxMzdmYjAwOTkxMTViZDBiMDQ0NmM0ZDY2YzgxY2NmNDFlMGJiI2tleS0xIiwidHlwIjoiSldUIn0."
    "eyJleHAiOjE3ODc5OTQxMTEsImlhdCI6MTc1NjQ1ODExMSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDpjOGFjZjdmNC05ZDQzLTRhYjctYWRhOC03NjZmYmU3NTA2ZDMiLCJuYmYiOjE3NTY0NTgxMTEsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXV0aC1kZXYucGlsYS52bi9hcGkvdjEvc2NoZW1hcy83MWExNGNlMS1jOGZhLTRkZjQtOTYwYi1lMThiYjYyODJjZWUiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYi9jcmVkZW50aWFscy9zdGF0dXMvMCMxNSIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly9hdXRoLWRldi5waWxhLnZuL2FwaS92MS9pc3N1ZXJzL2RpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIvY3JlZGVudGlhbHMvc3RhdHVzLzAiLCJzdGF0dXNMaXN0SW5kZXgiOiIxNSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZ2UiOjEwLCJkZXBhcnRtZW50IjoiRW5naW5lZXJpbmciLCJpZCI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJuYW1lIjoiVGVzdCBDcmVhdGUiLCJzYWxhcnkiOjUwMDAwfSwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6YzhhY2Y3ZjQtOWQ0My00YWI3LWFkYTgtNzY2ZmJlNzUwNmQzIiwiaXNzdWVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInZhbGlkRnJvbSI6IjIwMjUtMDgtMjlUMDk6MDE6NTFaIiwidmFsaWRVbnRpbCI6IjIwMjYtMDgtMjlUMDk6MDE6NTFaIn19."
    "P5ulGrKwY9KlxwqSN3Bs6aTQSGqS4z--brmJp3XtcTomXe8mse7gD3MHZF8C74V9zvgXV6RIM0vFzqdxzVUfnQ"
)

NOT_REVOKED_JWT = (
    "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyMjIxMzdmYjAwOTkxMTViZDBiMDQ0NmM0ZDY2YzgxY2NmNDFlMGJiI2tleS0xIiwidHlwIjoiSldUIn0."
    "eyJleHAiOjE3ODc5OTQxMTEsImlhdCI6MTc1NjQ1ODExMSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDpjMGExNDU3YS1kYTdmLTRlYTQtOWZmOC0xYTgxMDFhZjViMjAiLCJuYmYiOjE3NTY0NTgxMTEsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXV0aC1kZXYucGlsYS52bi9hcGkvdjEvc2NoZW1hcy83MWExNGNlMS1jOGZhLTRkZjQtOTYwYi1lMThiYjYyODJjZWUiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYi9jcmVkZW50aWFscy9zdGF0dXMvMCMxNyIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly9hdXRoLWRldi5waWxhLnZuL2FwaS92MS9pc3N1ZXJzL2RpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIvY3JlZGVudGlhbHMvc3RhdHVzLzAiLCJzdGF0dXNMaXN0SW5kZXgiOiIxNyIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZ2UiOjEwLCJkZXBhcnRtZW50IjoiRW5naW5lZXJpbmciLCJpZCI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJuYW1lIjoiVGVzdCBDcmVhdGUiLCJzYWxhcnkiOjUwMDAwfSwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6YzBhMTQ1N2EtZGE3Zi00ZWE0LTlmZjgtMWE4MTAxYWY1YjIwIiwiaXNzdWVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInZhbGlkRnJvbSI6IjIwMjUtMDgtMjlUMDk6MDE6NTFaIiwidmFsaWRVbnRpbCI6IjIwMjYtMDgtMjlUMDk6MDE6NTFaIn19."
    "95u0K9WTZdmAr-s7jCTppk75VqpM-vyMZVARhopZBoE418g4T3tT_1UhNZMrgFmPgvEqvLl1xJ-ZvHXqpwMKqw"
)


def test_check_revocation_revoked_jwt_credential():
    with pytest.raises(ValueError):
        parse_credential(REVOKED_JWT.encode("utf-8"), with_check_revocation())


def test_check_revocation_not_revoked_jwt_credential():
    parse_credential(NOT_REVOKED_JWT.encode("utf-8"), with_check_revocation())


JSON_EXTRACT = b"""{
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "urn:uuid:extract-test",
    "type": ["VerifiableCredential"],
    "issuer": "did:example:issuer",
    "credentialSubject": {
        "id": "did:example:subject",
        "name": "John Doe",
        "age": 30,
        "address": {"city": "Hanoi", "country": "Vietnam"},
        "emails": ["john@example.com", "john@work.com"]
    }
}"""


def test_extract_field():
    cred = parse_credential(JSON_EXTRACT)
    assert cred.extract_field("credentialSubject.name") == "John Doe"
    assert cred.extract_field("credentialSubject.address.city") == "Hanoi"
    assert cred.extract_field("credentialSubject.emails[0]") is None
    assert cred.extract_field("credentialSubject.nonexistent") is None
    assert cred.extract_field("credentialSubject.address.zipcode") is None

    vcc = CredentialContents(
        context=["https://www.w3.org/2018/credentials/v1"],
        id="urn:uuid:jwt-extract-test",
        issuer="did:example:issuer",
        types=["VerifiableCredential"],
        subject=[
            Subject(
                id="did:example:subject1",
                custom_fields={
                    "name": "Alice",
                    "age": 25,
                    "address": {"city": "HoChiMinh"},
                },
            )
        ],
        valid_from=datetime.now(timezone.utc),
        valid_until=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    jwt_cred = new_jwt_credential(vcc, with_verification_method_key("key-1"))
    assert jwt_cred.extract_field("credentialSubject.name") == "Alice"
    assert jwt_cred.extract_field("credentialSubject.address.city") == "HoChiMinh"
    assert jwt_cred.extract_field("credentialSubject.email") is None


def test_extract_field_edge_cases():
    cred = parse_credential(JSON_EXTRACT)
    assert cred.extract_field("") is None
    assert cred.extract_field("id") == "urn:uuid:extract-test"
    with pytest.raises(ValueError):
        parse_credential(b"{}")
    empty = ParsedJSONCredential({})
    assert empty.extract_field("any.path") is None


def test_get_options_defaults():
    opts = get_options()
    assert opts.is_validate_schema is False
    assert opts.is_verify_proof is False
    assert opts.is_check_expiration is False
    assert opts.is_check_revocation is False
    assert opts.did_base_url == "https://api.ndadid.vn/api/v1/did"
    assert opts.verification_method_key == ""
    assert opts.loaded_schema_loader is None
    assert opts.resolver is not None


def test_get_options_with_base_url_and_verification_method_key():
    opts = get_options(with_base_url("https://custom.example/did"), with_verification_method_key("key-custom"))
    assert opts.did_base_url == "https://custom.example/did"
    assert opts.verification_method_key == "key-custom"


def test_get_options_with_resolver_overrides_default():
    opts = get_options(with_resolver(None))
    assert opts.resolver is not None
    assert opts.did_base_url == "https://api.ndadid.vn/api/v1/did"


def _base_contents() -> CredentialContents:
    return CredentialContents(
        context=["https://www.w3.org/ns/credentials/v2"],
        id="urn:uuid:1234",
        issuer="did:example:issuer",
        types=["VerifiableCredential"],
        subject=[Subject(id="did:example:holder")],
    )


def test_serialize_credential_contents_terms_of_use():
    vcc = _base_contents()
    out = helper.serialize_credential_contents(vcc)
    assert "termsOfUse" not in out

    vcc = _base_contents()
    vcc.terms_of_use = [TermsOfUse(type="PresentationRequiredPolicy")]
    out = helper.serialize_credential_contents(vcc)
    terms = out["termsOfUse"]
    assert isinstance(terms, list)
    assert len(terms) == 1
    assert terms[0] == {"type": "PresentationRequiredPolicy"}

    vcc = _base_contents()
    vcc.terms_of_use = [
        TermsOfUse(id="https://example.com/policies/credential/4", type="IssuerPolicy")
    ]
    out = helper.serialize_credential_contents(vcc)
    assert out["termsOfUse"][0] == {
        "id": "https://example.com/policies/credential/4",
        "type": "IssuerPolicy",
    }

    vcc = _base_contents()
    vcc.terms_of_use = [
        TermsOfUse(type="PresentationRequiredPolicy"),
        TermsOfUse(type="IssuerPolicy", id="https://example.com/policies/credential/4"),
    ]
    out = helper.serialize_credential_contents(vcc)
    assert out["termsOfUse"][0]["type"] == "PresentationRequiredPolicy"
    assert out["termsOfUse"][1]["type"] == "IssuerPolicy"

    vcc = _base_contents()
    vcc.terms_of_use = [
        TermsOfUse(type="PresentationRequiredPolicy"),
        TermsOfUse(id="https://example.com/policies/credential/4"),
    ]
    with pytest.raises(ValueError, match="termsOfUse\\[1\\].type is required"):
        helper.serialize_credential_contents(vcc)

    vcc = _base_contents()
    vcc.terms_of_use = [TermsOfUse(type="PresentationRequiredPolicy")]
    cred = new_jwt_credential(vcc, with_verification_method_key("key-1"))
    import json as json_mod

    payload = json_mod.loads(cred.get_contents())
    assert len(payload["termsOfUse"]) == 1
    assert payload["termsOfUse"][0]["type"] == "PresentationRequiredPolicy"


def test_serialize_credential_contents_credential_status_type_required():
    vcc = _base_contents()
    vcc.credential_status = [
        Status(id="https://example.com/status/0#0", type="BitstringStatusListEntry"),
        Status(id="https://example.com/status/0#1", status_purpose="revocation"),
    ]
    with pytest.raises(ValueError, match="credentialStatus\\[1\\].type is required"):
        helper.serialize_credential_contents(vcc)

    vcc = _base_contents()
    vcc.credential_status = [
        Status(
            id="https://example.com/status/0#0",
            type="BitstringStatusListEntry",
            status_purpose="revocation",
        )
    ]
    out = helper.serialize_credential_contents(vcc)
    status = out["credentialStatus"]
    assert isinstance(status, dict)
    assert status["type"] == "BitstringStatusListEntry"
