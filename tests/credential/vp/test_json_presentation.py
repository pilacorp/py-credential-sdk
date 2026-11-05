"""Ports of the JSON-LD tests: json_presentation, challenge_domain (JSON), addcustomproof_verify,
external_sign, addproof, revoked_vm, legacy_hex, multikey_e2e, secp256k1_suite_e2e, jws_e2e."""
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from vp_helpers import (
    HOLDER_P256_PRIV,
    HOLDER_SECP,
    JWS_HOLDER_DID,
    WRONG_P256_PRIV,
    P256Provider,
    RSAProvider,
    StaticResolver,
    V2,
    default_signer,
    new_did_document,
    new_secp256k1_vm,
    p256_from_hex,
    p256_pub,
    p256_vm,
    proof_from_json,
    secp_pub_hex,
    sign_via_jsonmap,
    vp_doc,
)
from credential.common.dto.proof import Proof, StringOrStrings
from credential.common.jsonmap import JSONMap
from credential.common.verification_method import (
    encode_multibase_key,
    new_p256_multikey_vm,
    new_rsa_vm,
)
from credential.vc import credential as vc
from credential.vc.json_credential import JSONCredential
from credential import vp


def _p256_setup(holder):
    prov = P256Provider()
    return prov, StaticResolver([new_did_document(holder, [p256_vm(holder, "key-1", prov)])])


def _rs(prov_key, digest):
    r, s = decode_dss_signature(prov_key.sign(digest, ec.ECDSA(__import__("cryptography.hazmat.primitives.asymmetric.utils", fromlist=["Prehashed"]).Prehashed(__import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()))))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---- json_presentation_test.go ----
def test_vp_holder_object_sign_and_verify():
    holder = "did:example:vp-holder-object"
    prov, resolver = _p256_setup(holder)
    doc = json.dumps({"@context": [V2], "id": "urn:uuid:vp-holder-object", "type": ["VerifiablePresentation"],
                      "holder": {"id": holder, "name": "Alice"}, "verifiableCredential": []})
    pres = vp.parse_json_presentation(doc)
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
    pres.verify(vp.with_resolver(resolver))
    assert pres.extract_field("holder.id") == holder  # the object form must not be flattened


def test_vp_holder_object_without_id_rejected_at_signing():
    pres = vp.parse_json_presentation(json.dumps({"@context": [V2], "type": ["VerifiablePresentation"],
                                                  "holder": {"name": "Alice"}, "verifiableCredential": []}))
    with pytest.raises(ValueError):
        pres.add_proof_by_provider(P256Provider())


# ---- addproof_test.go ----
def test_vp_add_proof_p256_hex():
    did = "did:example:vp-addproof"
    prov = P256Provider()
    resolver = StaticResolver([new_did_document(did, [p256_vm(did, "key-1", prov)])])
    pres = vp.parse_json_presentation(vp_doc(did))
    pres.add_proof(prov.private_key_bytes().hex(), vp.with_resolver(resolver))
    pres.verify(vp.with_resolver(resolver))


# ---- revoked_vm_test.go ----
def test_vp_revoked_vm_rejected_at_signing():
    did = "did:example:vp-rotated"
    prov = P256Provider()
    old = p256_vm(did, "key-1", prov)
    old.revoked = datetime.now(timezone.utc) - timedelta(hours=1)
    resolver = StaticResolver([new_did_document(did, [old, p256_vm(did, "key-2", prov)])])

    pres = vp.parse_json_presentation(vp_doc(did))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver))  # default skips revoked key-1
    pres.verify(vp.with_resolver(resolver))

    pres = vp.parse_json_presentation(vp_doc(did))
    with pytest.raises(ValueError, match="was revoked at"):
        pres.add_proof_by_provider(prov, vp.with_resolver(resolver), vp.with_verification_method_key("key-1"))

    pres = vp.parse_json_presentation(vp_doc(did))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver), vp.with_verification_method_key("key-2"))
    pres.verify(vp.with_resolver(resolver))


# ---- challenge_domain_test.go (JSON-LD) ----
def _check(fn, want):
    if not want:
        fn()
        return
    with pytest.raises(ValueError, match=want):
        fn()


def test_vp_challenge_domain_sign_and_verify():
    holder = "did:example:vp-challenge"
    prov, resolver = _p256_setup(holder)
    pres = vp.parse_json_presentation(vp_doc(holder))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver), vp.with_challenge("nonce-123"), vp.with_domain("verifier.example"))
    assert pres.extract_field("proof.challenge") == "nonce-123"
    assert pres.extract_field("proof.domain") == "verifier.example"
    cases = [
        ([vp.with_expected_challenge("nonce-123"), vp.with_expected_domain("verifier.example")], ""),
        ([], ""),
        ([vp.with_expected_challenge("nonce-999")], "challenge"),
        ([vp.with_expected_domain("attacker.example")], "domain"),
    ]
    for opts, want in cases:
        _check(lambda: pres.verify(vp.with_resolver(resolver), *opts), want)
    reparsed = vp.parse_json_presentation(pres.get_contents())
    reparsed.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-123"))


def test_vp_challenge_domain_missing_challenge_rejected():
    holder = "did:example:vp-nochallenge"
    prov, resolver = _p256_setup(holder)
    pres = vp.parse_json_presentation(vp_doc(holder))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-123"))


def test_vp_challenge_domain_expected_implies_verify():
    holder = "did:example:vp-implies"
    prov, resolver = _p256_setup(holder)
    pres = vp.parse_json_presentation(vp_doc(holder))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver), vp.with_challenge("nonce-123"), vp.with_domain("example.com"))
    raw = pres.get_contents()
    cases = [
        (vp.with_expected_challenge("nonce-123"), ""), (vp.with_expected_domain("example.com"), ""),
        (vp.with_expected_challenge("other"), "challenge"), (vp.with_expected_domain("evil.example"), "domain"),
    ]
    for opt, want in cases:
        _check(lambda: vp.parse_json_presentation(raw, vp.with_resolver(resolver), opt), want)
    # an unsigned document cannot satisfy an expected challenge
    with pytest.raises(ValueError):
        vp.parse_json_presentation(vp_doc(holder), vp.with_resolver(resolver), vp.with_expected_challenge("nonce-123"))


def _attach_external(m, key_prov, holder, proof):
    doc_hash = m.document_digest()
    digest = hashlib.sha256(m.proof_hash_data(doc_hash, proof)).digest()
    proof.proof_value = encode_multibase_key(key_prov.sign(digest))
    m.add_custom_proof(proof)


def test_vp_challenge_domain_accepts_domain_set():
    holder = "did:example:vp-domain-set"
    prov, resolver = _p256_setup(holder)
    m = JSONMap(json.loads(vp_doc(holder)))
    proof = Proof(type="DataIntegrityProof", cryptosuite="ecdsa-rdfc-2019", created="2026-01-01T00:00:00Z",
                  verification_method=holder + "#key-1", proof_purpose="authentication", challenge="nonce-123",
                  domain=StringOrStrings(["rp-a.example", "rp-b.example"]))
    _attach_external(m, prov, holder, proof)
    pres = vp.parse_json_presentation(json.dumps(m.data))
    for d in ("rp-a.example", "rp-b.example"):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_domain(d))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_domain("evil.example"))


# ---- addcustomproof_verify_test.go ----
def _custom_proof_presentation(holder):
    return vp.new_json_presentation(vp.PresentationContents(
        context=["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/data-integrity/v2"],
        id="urn:uuid:vp-addcustomproof-verify", types=["VerifiablePresentation"], holder=holder))


def _external_vp_proof(pres, prov, vm_url, challenge, domain):
    proof = Proof(type="DataIntegrityProof", cryptosuite="ecdsa-rdfc-2019", created="2026-01-01T00:00:00Z",
                  verification_method=vm_url, proof_purpose="authentication", challenge=challenge,
                  domain=StringOrStrings([domain]))
    digest = pres.create_proof_signing(pres.get_signing_input(), proof)
    proof.proof_value = encode_multibase_key(prov.sign(digest))
    return proof


def _custom_holder():
    did = "did:example:vp-addcustomproof"
    prov = P256Provider()
    return did, prov, StaticResolver([new_did_document(did, [new_p256_multikey_vm(did, "key-1", p256_pub(prov))])])


def test_vp_add_custom_proof_verify_proof_attaches_a_valid_proof():
    did, prov, resolver = _custom_holder()
    pres = _custom_proof_presentation(did)
    proof = _external_vp_proof(pres, prov, did + "#key-1", "nonce-123", "verifier.example")
    pres.add_custom_proof(proof, vp.with_verify_proof(), vp.with_resolver(resolver))
    pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-123"), vp.with_expected_domain("verifier.example"))


def test_vp_add_custom_proof_verify_proof_refuses_a_swapped_challenge():
    did, prov, resolver = _custom_holder()
    pres = _custom_proof_presentation(did)
    proof = _external_vp_proof(pres, prov, did + "#key-1", "nonce-123", "verifier.example")
    proof.challenge = "nonce-999"
    with pytest.raises(ValueError, match="does not verify"):
        pres.add_custom_proof(proof, vp.with_verify_proof(), vp.with_resolver(resolver))
    assert pres.extract_field("proof") is None
    pres.add_custom_proof(proof)  # without the option it attaches as given
    assert pres.extract_field("proof") is not None


def test_vp_add_custom_proof_verify_proof_refuses_a_swapped_domain():
    did, prov, resolver = _custom_holder()
    pres = _custom_proof_presentation(did)
    proof = _external_vp_proof(pres, prov, did + "#key-1", "nonce-123", "verifier.example")
    proof.domain = StringOrStrings(["attacker.example"])
    with pytest.raises(ValueError):
        pres.add_custom_proof(proof, vp.with_verify_proof(), vp.with_resolver(resolver))
    assert pres.extract_field("proof") is None


# ---- external_sign_test.go ----
def test_external_signing_flow_vp():
    prov = P256Provider()
    pres = vp.new_json_presentation(vp.PresentationContents(
        context=["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/data-integrity/v2"],
        types=["VerifiablePresentation"]))
    proof = Proof(type="DataIntegrityProof", cryptosuite="ecdsa-rdfc-2019",
                  created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  verification_method="did:example:123#key-1", proof_purpose="authentication",
                  challenge="12345-challenge", domain=StringOrStrings(["example.com"]))
    proof_hash = pres.create_proof_signing(pres.get_signing_input(), proof)
    proof.proof_value = encode_multibase_key(prov.sign(proof_hash))
    pres.add_custom_proof(proof)
    out = pres.serialize()
    assert out["proof"]["challenge"] == "12345-challenge"
    assert out["proof"]["domain"] == "example.com"
    assert out["proof"]["type"] == "DataIntegrityProof"
    assert out["proof"]["proofValue"][0] == "z"


# ---- legacy_hex_test.go ----
LEGACY_HEX_VP = """{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "holder": "did:example:legacy-holder",
  "id": "urn:uuid:9a8b7c6d-legacy-vp",
  "proof": {
    "created": "2026-09-14T08:51:57Z",
    "cryptosuite": "ecdsa-rdfc-2019",
    "proofPurpose": "authentication",
    "proofValue": "255945a9f6b7adf05d2261f2ae68f1fb11789fc86b22eb28bb72788b34fbbf07143054ca8eebb479cf706543be5d9e350b4833a1ddae1c91ef80c5b7d75c6ffe01",
    "type": "DataIntegrityProof",
    "verificationMethod": "did:example:legacy-holder#key-1"
  },
  "type": ["VerifiablePresentation"],
  "verifiableCredential": [{
      "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
      "credentialSubject": {"age": 30, "id": "did:example:legacy-subject", "name": "Alice"},
      "id": "urn:uuid:7f1e2c3d-legacy-vc",
      "issuer": "did:example:legacy-issuer",
      "proof": {
        "created": "2026-09-14T08:51:57Z",
        "cryptosuite": "ecdsa-rdfc-2019",
        "proofPurpose": "assertionMethod",
        "proofValue": "b95159fb2c2a5f9a5a04f23342eafb0aa66875a0c41b07c0d4f6bff3205a401f078c75299f88d6553cfdfce08050ca566736c23a47c6b575fef656e4f1ce768200",
        "type": "DataIntegrityProof",
        "verificationMethod": "did:example:legacy-issuer#key-1"
      },
      "type": ["VerifiableCredential", "ExampleDegreeCredential"],
      "validFrom": "2025-01-01T00:00:00Z"
  }]
}"""
LEGACY_PUB = "04e962c45627a43f3bec0af18c6c780ddbacceb8275b5204d494bc2cc44dc96d9805e64ee5ffeb6d05ed37284636c7cf6bfbaaa0d131f950cecc43110ac5510cad"


def test_vp_legacy_hex_proof_still_verifies():
    did = "did:example:legacy-holder"
    resolver = StaticResolver([new_did_document(did, [new_secp256k1_vm(did, "key-1", LEGACY_PUB)])])
    pres = vp.parse_json_presentation(LEGACY_HEX_VP)
    pres.verify(vp.with_resolver(resolver))


def test_vp_proof_carrying_its_own_key_is_refused():
    did = "did:example:legacy-holder"
    resolver = StaticResolver([new_did_document(did, [new_secp256k1_vm(did, "key-1", LEGACY_PUB)])])
    forged = json.dumps({
        "@context": [V2], "id": "urn:uuid:forged-vp", "type": ["VerifiablePresentation"], "holder": did,
        "proof": {"type": "EcdsaSecp256k1Signature2019", "created": "2026-01-01T00:00:00Z",
                  "proofPurpose": "authentication",
                  "verificationMethod": "0x02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737",
                  "proofValue": "00"}})
    pres = vp.parse_json_presentation(forged)
    with pytest.raises(ValueError, match="is not a DID URL"):
        pres.verify(vp.with_resolver(resolver))


# ---- multikey_e2e_test.go ----
def test_vp_multikey_sign_verify():
    p256 = P256Provider()
    rsa_prov = RSAProvider()
    mk_vm = new_p256_multikey_vm("did:example:vp-p256-mb", "key-1", p256_pub(p256))
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa  # noqa: F401

    cases = [
        ("secp256k1/EcdsaSecp256k1Signature2019 on a VC 2.0 document", "did:example:vp-secp", default_signer(HOLDER_SECP),
         new_secp256k1_vm("did:example:vp-secp", "key-1", secp_pub_hex(HOLDER_SECP)), ""),
        ("P-256 JWK/ecdsa-rdfc-2019", "did:example:vp-p256", p256, p256_vm("did:example:vp-p256", "key-1", p256), ""),
        ("P-256 Multikey/ecdsa-rdfc-2019", "did:example:vp-p256-mb", p256, mk_vm, ""),
        ("RSA rejected", "did:example:vp-rsa", rsa_prov,
         new_rsa_vm("did:example:vp-rsa", "key-1", rsa_prov.key.public_key()), "unsupported key kind"),
    ]
    for name, did, prov, vm, want in cases:
        resolver = StaticResolver([new_did_document(did, [vm])])
        pres = vp.parse_json_presentation(vp_doc(did))
        if want:
            with pytest.raises(ValueError, match=want):
                pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
            continue
        pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
        pres.verify(vp.with_resolver(resolver))


# ---- jws_e2e_test.go ----
def test_vp_add_proof_by_provider_rsa():
    rsa_prov = RSAProvider()
    resolver = StaticResolver([new_did_document(JWS_HOLDER_DID, [new_rsa_vm(JWS_HOLDER_DID, "key-1", rsa_prov.key.public_key())])])
    pres = vp.parse_json_presentation(vp_doc(JWS_HOLDER_DID))
    signed = sign_via_jsonmap(pres, rsa_prov, JWS_HOLDER_DID + "#key-1", True)
    signed.verify(vp.with_resolver(resolver))


def test_vp_verify_specific_proof():
    rsa_prov = RSAProvider()
    p256_prov = p256_from_hex(HOLDER_P256_PRIV)
    wrong = p256_from_hex(WRONG_P256_PRIV)
    pres = vp.parse_json_presentation(vp_doc(JWS_HOLDER_DID))
    # the verifier resolves a WRONG P-256 key for key-2, so only that proof fails
    resolver = StaticResolver([new_did_document(JWS_HOLDER_DID, [
        new_rsa_vm(JWS_HOLDER_DID, "key-1", rsa_prov.key.public_key()),
        p256_vm(JWS_HOLDER_DID, "key-2", wrong)])])
    signed = sign_via_jsonmap(pres, rsa_prov, JWS_HOLDER_DID + "#key-1", True)
    signed = sign_via_jsonmap(signed, p256_prov, JWS_HOLDER_DID + "#key-2", False)
    with pytest.raises(ValueError):
        signed.verify(vp.with_resolver(resolver))
    signed.verify(vp.with_resolver(resolver), vp.with_proof_verification_method(JWS_HOLDER_DID + "#key-1"))


# ---- secp256k1_suite_e2e_test.go ----
def _suite_setup(holder):
    return default_signer(HOLDER_SECP), StaticResolver([new_did_document(holder, [new_secp256k1_vm(holder, "key-1", secp_pub_hex(HOLDER_SECP))])])


def _suite_doc(holder):
    return json.dumps({"@context": [V2], "id": "urn:uuid:vp-secp-suite-001", "type": ["VerifiablePresentation"],
                       "holder": holder, "verifiableCredential": []})


def test_vp_secp256k1_suite_sign_verify():
    holder = "did:example:vp-secp-suite"
    prov, resolver = _suite_setup(holder)
    pres = vp.parse_json_presentation(_suite_doc(holder))
    pres.add_proof_by_provider(prov, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    assert pres.extract_field("proof.type") == "EcdsaSecp256k1Signature2019"
    assert pres.extract_field("proof.jws")
    pres.verify(vp.with_resolver(resolver))


def test_vp_secp256k1_suite_challenge_domain():
    holder = "did:example:vp-secp-suite-cd"
    prov, resolver = _suite_setup(holder)
    pres = vp.parse_json_presentation(_suite_doc(holder))
    pres.add_proof_by_provider(prov, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver),
                               vp.with_challenge("nonce-secp-1"), vp.with_domain("verifier.example"))
    assert pres.extract_field("proof.challenge") == "nonce-secp-1"
    for opts, want in (
        ([vp.with_expected_challenge("nonce-secp-1"), vp.with_expected_domain("verifier.example")], ""),
        ([vp.with_expected_challenge("nonce-999")], "challenge"),
        ([vp.with_expected_domain("attacker.example")], "domain"),
    ):
        _check(lambda: pres.verify(vp.with_resolver(resolver), *opts), want)


def test_vp_secp256k1_suite_validity_period_is_extensible():
    holder = "did:example:vp-secp-extensible"
    prov, resolver = _suite_setup(holder)
    cases = [
        ("term left undefined", [V2], True),
        ("defined through @vocab", [V2, {"@vocab": "https://nda.vn/vocab#"}], False),
        ("mapped explicitly to the W3C IRI", [V2, {"validUntil": {
            "@id": "https://www.w3.org/2018/credentials#expirationDate",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}}], False),
    ]
    for name, ctx, want_err in cases:
        doc = json.dumps({"@context": ctx, "id": "urn:uuid:vp-extensible-001", "type": ["VerifiablePresentation"],
                          "holder": holder, "verifiableCredential": [], "validUntil": "2027-09-21T00:00:00Z"})
        pres = vp.parse_json_presentation(doc)
        if want_err:
            with pytest.raises(ValueError):
                pres.add_proof_by_provider(prov, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
            continue
        pres.add_proof_by_provider(prov, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
        pres.verify(vp.with_resolver(resolver))
        assert pres.extract_field("validUntil") == "2027-09-21T00:00:00Z"


def test_vp_secp256k1_suite_signs_vc2_presentation():
    holder = "did:example:vp-secp-suite-vc2"
    prov, resolver = _suite_setup(holder)
    pres = vp.parse_json_presentation(_suite_doc(holder))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver), vp.with_verification_method_key("key-1"),
                               vp.with_challenge("nonce-vc2"), vp.with_domain("https://verifier.example"))
    pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-vc2"), vp.with_expected_domain("https://verifier.example"))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("other"))
    doc = json.loads(pres.get_contents())
    assert isinstance(doc["proof"], dict) and doc["proof"]["type"] == "EcdsaSecp256k1Signature2019"
    assert isinstance(doc["proof"]["jws"], str)
    assert doc["@context"][0] == V2


def test_vp_secp256k1_suite_carries_a_credential():
    holder = "did:example:vp-secp-with-vc"
    prov, holder_resolver = _suite_setup(holder)
    issuer = "did:example:vc-issuer-p256"
    p256 = P256Provider()
    issuer_resolver = StaticResolver([new_did_document(issuer, [p256_vm(issuer, "key-1", p256)])])
    cred = JSONCredential.create(vc.CredentialContents(
        context=[V2], id="urn:uuid:vp-embedded-vc", types=["VerifiableCredential"], issuer=issuer,
        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc), subject=[vc.Subject(id="did:example:subject")]))
    cred.add_proof_by_provider(p256, vc.with_resolver(issuer_resolver), vc.with_verification_method_key("key-1"))
    cred_map = json.loads(cred.get_contents())
    pres = vp.parse_json_presentation(json.dumps({
        "@context": [V2], "id": "urn:uuid:vp-with-vc-001", "type": ["VerifiablePresentation"],
        "holder": holder, "verifiableCredential": [cred_map]}))
    pres.add_proof_by_provider(prov, vp.with_resolver(holder_resolver), vp.with_verification_method_key("key-1"),
                               vp.with_challenge("nonce-with-vc"))
    pres.verify(vp.with_resolver(holder_resolver), vp.with_expected_challenge("nonce-with-vc"))
    embedded = json.loads(pres.get_contents())["verifiableCredential"][0]
    JSONCredential.parse(json.dumps(embedded)).verify(vc.with_resolver(issuer_resolver))
