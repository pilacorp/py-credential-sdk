from credential.vc.ecdsasd_credential import ECDSASDCredential


def test_ecdsasd_credential_parse_and_create():
    raw = '{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:ex:1","credentialSubject":{"id":"did:ex:sub"}}'
    cred = ECDSASDCredential.parse(raw)
    assert cred.data["issuer"] == "did:ex:1"
    built = ECDSASDCredential.create({"@context": ["https://www.w3.org/ns/credentials/v2"], "issuer": "did:ex:2", "credentialSubject": {"id": "x"}})
    assert built.data["issuer"] == "did:ex:2"
