"""Port of credential/vp/jose_presentation_test.go."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from vp_helpers import *  # noqa: F401,F403
from vp_helpers import (
    HOLDER_SECP,
    FailingSigner,
    P256Provider,
    StaticResolver,
    V2,
    default_signer,
    jose_vp_contents,
    jose_vp_credential_contents,
    jose_vp_fixture,
    jwt_header,
    jwt_payload,
    new_did_document,
    new_secp256k1_vm,
    p256_vm,
    secp_pub_hex,
)
from credential.common.jwt.jwtutil import b64url_encode, json_dumps
from credential.vc import credential as vc
from credential.vc.json_credential import JSONCredential
from credential.vc.jwt_credential import JWTCredential
from credential.vc.jose_credential import JOSECredential
from credential import vp

SECP = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"


def _cases():
    p256 = P256Provider()
    return [
        ("secp256k1/ES256K", "did:example:jose-vp-secp", default_signer(SECP),
         new_secp256k1_vm("did:example:jose-vp-secp", "key-1", secp_pub_hex(SECP)), "ES256K"),
        ("P-256/ES256", "did:example:jose-vp-p256", p256, p256_vm("did:example:jose-vp-p256", "key-1", p256), "ES256"),
    ]


@pytest.mark.parametrize("name,did,prov,vm,want_alg", _cases(), ids=lambda v: v if isinstance(v, str) and "/" in v else None)
def test_jose_presentation_multikey_issue_verify(name, did, prov, vm, want_alg):
    resolver = StaticResolver([new_did_document(did, [vm])])
    pres = vp.new_jose_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    tok = pres.serialize()
    assert jwt_header(tok)["typ"] == "vp+jwt"
    assert jwt_header(tok)["alg"] == want_alg
    payload = jwt_payload(tok)
    assert "vp" not in payload and "vc" not in payload
    assert payload.get("iss") == did or payload.get("holder") == did

    pres.add_proof_by_provider(prov)
    pres.verify(vp.with_resolver(resolver))
    assert len(pres.hash()) == 64

    jwt_str = pres.serialize()
    parsed = vp.parse_jose_presentation(jwt_str)
    parsed.verify(vp.with_resolver(resolver))
    assert parsed.get_type() == "JOSE"

    auto = vp.parse_presentation(jwt_str.encode(), vp.with_resolver(resolver))
    assert auto.get_type() == "JOSE"
    auto.verify(vp.with_resolver(resolver))


def _fake(header, payload):
    return b64url_encode(json_dumps(header)) + "." + b64url_encode(json_dumps(payload)) + ".fakesig"


def test_jose_presentation_rejects_forbidden_vp_claim():
    tok = _fake({"typ": "vp+jwt", "alg": "ES256", "kid": "did:example:123#key-1"}, {"vp": {"id": "123"}})
    with pytest.raises(ValueError, match="'vp' claim MUST NOT be present"):
        vp.parse_jose_presentation(tok)


def test_jose_presentation_rejects_invalid_typ():
    tok = _fake({"typ": "JWT", "alg": "ES256", "kid": "did:example:123#key-1"}, {"holder": "did:example:123"})
    with pytest.raises(ValueError, match="invalid typ header"):
        vp.parse_jose_presentation(tok)


def test_jose_presentation_with_vc_validation_enveloped_vc():
    issuer, holder = "did:example:jose-issuer", "did:example:jose-holder"
    p256 = P256Provider()
    resolver = StaticResolver([
        new_did_document(issuer, [new_secp256k1_vm(issuer, "key-1", secp_pub_hex(SECP))]),
        new_did_document(holder, [p256_vm(holder, "key-1", p256)]),
    ])
    cred = JOSECredential.create(
        vc.CredentialContents(
            context=[V2], id="urn:uuid:jose-vc-embedded", types=["VerifiableCredential", "MembershipCredential"],
            issuer=issuer, valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
            subject=[vc.Subject(id="did:example:subject", custom_fields={"memberId": "MEM-1234"})],
        ),
        vc.with_verification_method_key("key-1"), vc.with_resolver(resolver),
    )
    cred.add_proof_by_provider(default_signer(SECP))
    pres = vp.new_jose_presentation(
        vp.PresentationContents(context=[V2], id="urn:uuid:jose-vp-with-vc", types=["VerifiablePresentation"],
                                holder=holder, verifiable_credentials=[cred]),
        vp.with_verification_method_key("key-1"), vp.with_resolver(resolver),
    )
    pres.add_proof_by_provider(p256)
    pres.verify(vp.with_resolver(resolver), vp.with_vc_validation())
    vcs = jwt_payload(pres.serialize())["verifiableCredential"]
    assert len(vcs) == 1
    assert vcs[0]["id"].startswith("data:application/vc+jwt,")


def test_jose_presentation_challenge_domain_replay_protection():
    holder = "did:example:jose-replay-holder"
    resolver = StaticResolver([new_did_document(holder, [new_secp256k1_vm(holder, "key-1", secp_pub_hex(SECP))])])
    pres = vp.new_jose_presentation(jose_vp_contents(holder), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    challenge, domain = "test-challenge-nonce-12345", "verifier.example.com"
    pres.add_proof_by_provider(default_signer(SECP), vp.with_challenge(challenge), vp.with_domain(domain))
    pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge(challenge), vp.with_expected_domain(domain))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("replayed-tampered-challenge"), vp.with_expected_domain(domain))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge(challenge), vp.with_expected_domain("attacker.phishing.com"))


def _signed(cred_cls, did, resolver, prov):
    c = cred_cls.create(jose_vp_credential_contents(did), vc.with_verification_method_key("key-1"), vc.with_resolver(resolver))
    c.add_proof_by_provider(prov, vc.with_resolver(resolver))
    return c


def test_jose_presentation_rejects_non_enveloping_credential():
    did = "did:example:jose-vp-kinds"
    resolver, prov = jose_vp_fixture(did)
    json_cred = _signed(JSONCredential, did, resolver, prov)
    legacy = _signed(JWTCredential, did, resolver, prov)
    for cred in (json_cred, legacy):
        contents = jose_vp_contents(did)
        contents.verifiable_credentials = [cred]
        with pytest.raises(ValueError, match="can only carry enveloping-secured credentials"):
            vp.new_jose_presentation(contents, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))


def test_jose_presentation_rejects_unsigned_credential():
    did = "did:example:jose-vp-unsigned"
    resolver, _ = jose_vp_fixture(did)
    cred = JOSECredential.create(jose_vp_credential_contents(did), vc.with_verification_method_key("key-1"), vc.with_resolver(resolver))
    contents = jose_vp_contents(did)
    contents.verifiable_credentials = [cred]
    with pytest.raises(ValueError, match="is not signed"):
        vp.new_jose_presentation(contents, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))


def test_jose_presentation_labels_envelope_by_scheme():
    did = "did:example:jose-vp-label"
    resolver, prov = jose_vp_fixture(did)
    cred = _signed(JOSECredential, did, resolver, prov)
    contents = jose_vp_contents(did)
    contents.verifiable_credentials = [cred]
    pres = vp.new_jose_presentation(contents, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    m = json.loads(pres.get_contents())
    assert len(m["verifiableCredential"]) == 1
    entry = m["verifiableCredential"][0]
    assert entry["id"].startswith("data:application/vc+jwt,")
    # the envelope must be readable by the parser its media type names
    vc.parse_credential(json.dumps(entry).encode(), vc.with_resolver(resolver))


def test_parse_presentation_rejects_sd_jwt_shape():
    did = "did:example:vp-sdjwt-shape"
    resolver, prov = jose_vp_fixture(did)
    pres = vp.new_jose_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
    token = pres.serialize()
    vp.parse_presentation(token.encode(), vp.with_resolver(resolver))
    for suffix in ("~", "~WyJhIiwgImIiXQ", "~junk!!!"):
        with pytest.raises(ValueError, match="SD-JWT disclosures, which are not supported"):
            vp.parse_presentation((token + suffix).encode(), vp.with_resolver(resolver))


def test_jose_presentation_failed_signing_leaves_no_challenge_or_domain():
    did = "did:example:vp-rollback"
    resolver, prov = jose_vp_fixture(did)
    pres = vp.new_jose_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    with pytest.raises(ValueError):
        pres.add_proof_by_provider(FailingSigner(), vp.with_challenge("nonce-session-A"),
                                   vp.with_domain("https://bank-a.example"), vp.with_resolver(resolver))
    pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
    payload = jwt_payload(pres.serialize())
    assert "nonce" not in payload and "aud" not in payload
    pres.verify(vp.with_resolver(resolver))


def test_jose_presentation_challenge_and_domain_are_signed():
    did = "did:example:vp-challenge"
    resolver, prov = jose_vp_fixture(did)
    pres = vp.new_jose_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    pres.add_proof_by_provider(prov, vp.with_challenge("nonce-1"), vp.with_domain("https://bank-a.example"), vp.with_resolver(resolver))
    payload = jwt_payload(pres.serialize())
    assert payload["nonce"] == "nonce-1" and payload["aud"] == "https://bank-a.example"
    pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-1"), vp.with_expected_domain("https://bank-a.example"))


def test_jose_presentation_require_audience():
    did = "did:example:vp-aud"
    resolver, prov = jose_vp_fixture(did)

    def sign(domain):
        pres = vp.new_jose_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
        opts = [vp.with_resolver(resolver)] + ([vp.with_domain(domain)] if domain else [])
        pres.add_proof_by_provider(prov, *opts)
        return pres.serialize()

    for_a, none = sign("https://bank-a.example"), sign("")
    cases = [
        ("bank-a names itself", for_a, [vp.with_require_audience(), vp.with_expected_domain("https://bank-a.example")], ""),
        ("bank-b names itself", for_a, [vp.with_require_audience(), vp.with_expected_domain("https://bank-b.example")], "does not match expected domain"),
        ("option alone, names bank-a", for_a, [vp.with_require_audience()], "needs WithExpectedDomain"),
        ("bank-b names nobody, without the option", for_a, [], ""),
        ("option alone, names nobody", none, [vp.with_require_audience()], "needs WithExpectedDomain"),
        ("paired, names nobody", none, [vp.with_require_audience(), vp.with_expected_domain("https://bank-b.example")], "does not match expected domain"),
        ("no aud, verifier names itself", none, [vp.with_expected_domain("https://bank-b.example")], "does not match expected domain"),
    ]
    for name, token, opts, want in cases:
        parsed = vp.parse_presentation(token.encode(), vp.with_resolver(resolver))
        if want == "":
            parsed.verify(*opts, vp.with_resolver(resolver))
        else:
            with pytest.raises(ValueError, match=want):
                parsed.verify(*opts, vp.with_resolver(resolver))
