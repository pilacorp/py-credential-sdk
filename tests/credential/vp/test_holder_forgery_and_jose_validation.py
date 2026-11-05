"""Ports of holder_forgery_test.go, jose_validation_test.go, jose_signing_paths_test.go."""
import json

import pytest
from vp_helpers import (
    P256Provider,
    StaticResolver,
    V2,
    jose_vp_contents,
    jose_vp_credential_contents,
    jose_vp_fixture,
    new_did_document,
    p256_vm,
    sign_compact,
)
from credential.common.dto.proof import Proof
from credential.common.verification_method import DIDDocument
from credential.vc import credential as vc
from credential.vc.json_credential import JSONCredential
from credential.vc.jose_credential import JOSECredential
from credential import vp
import hashlib


def test_vp_holder_forgery_through_the_signer_binding():
    holder_did, attacker_did = "did:example:vp-binding-holder", "did:example:vp-binding-attacker"
    holder_key, attacker_key = P256Provider(), P256Provider()
    holder_vm = p256_vm(holder_did, "key-1", holder_key)
    attacker_vm = p256_vm(attacker_did, "key-1", attacker_key)
    # key-1 may issue and may not authenticate: an issuing key, not a login key
    issuing_only = DIDDocument(id=holder_did, verification_method=[holder_vm], assertion_method=[holder_vm.id], authentication=[])
    both = new_did_document(holder_did, [holder_vm])
    attacker_doc = new_did_document(attacker_did, [attacker_vm])

    cases = [
        ("a key granted only assertionMethod signs a presentation", issuing_only, holder_key, holder_vm.id,
         {"holder": holder_did}, "is not granted purpose 'authentication'"),
        ("issuer names the attacker, no holder at all", both, attacker_key, attacker_vm.id,
         {"issuer": attacker_did}, "holder"),
        ("holder names the victim, kid points at the attacker", both, attacker_key, attacker_vm.id,
         {"holder": holder_did}, "verification method"),
        ("the honest shape", both, holder_key, holder_vm.id, {"holder": holder_did}, ""),
    ]
    for name, doc, key, kid, claims, want in cases:
        resolver = StaticResolver([doc, attacker_doc])
        payload = {"@context": [V2], "type": ["VerifiablePresentation"], **claims}
        pres = vp.parse_presentation(sign_compact(key, kid, payload).encode(), vp.with_resolver(resolver))
        if not want:
            pres.verify(vp.with_resolver(resolver))
            continue
        with pytest.raises(ValueError, match=want):
            pres.verify(vp.with_resolver(resolver))


# --- extra forgery shapes the lead asked for (payload holder vs iss, {id} form, nested vp, case variants) ---
def _forge(claims, nested=False, typ="vp+jwt"):
    victim, attacker = "did:example:victim", "did:example:attacker"
    vk, ak = P256Provider(), P256Provider()
    resolver = StaticResolver([new_did_document(victim, [p256_vm(victim, "key-1", vk)]),
                               new_did_document(attacker, [p256_vm(attacker, "key-1", ak)])])
    body = {"@context": [V2], "type": ["VerifiablePresentation"], **claims(victim, attacker)}
    payload = {"vp": body, **{k: body[k] for k in ("iss",) if k in body}} if nested else body
    tok = sign_compact(ak, attacker + "#key-1", payload, typ=typ)
    return resolver, tok


@pytest.mark.parametrize("claims,nested", [
    (lambda v, a: {"iss": a, "holder": v}, False),                       # iss attacker, holder victim
    (lambda v, a: {"iss": a, "holder": {"id": v}}, False),               # {id: ...} form
    (lambda v, a: {"iss": a, "Holder": v}, False),                       # case variant key
    (lambda v, a: {"iss": a, "holder": [v]}, False),                     # not a string / object
    (lambda v, a: {"iss": a, "holder": {"name": "x"}}, False),           # object without id
    (lambda v, a: {"iss": a, "holder": None}, False),                    # explicit null
    (lambda v, a: {"iss": a, "holder": v}, True),                        # nested vp claim
])
def test_forged_holder_is_rejected(claims, nested):
    resolver, tok = _forge(claims, nested)
    with pytest.raises(ValueError):
        pres = vp.parse_presentation(tok.encode(), vp.with_resolver(resolver))
        pres.verify(vp.with_resolver(resolver))


def test_typ_contradicting_payload_is_rejected():
    # a vc+jwt typ over a presentation payload: the purposes disagree
    resolver, tok = _forge(lambda v, a: {"holder": a, "issuer": a}, typ="vc+jwt")
    with pytest.raises(ValueError):
        vp.parse_presentation(tok.encode(), vp.with_resolver(resolver)).verify(vp.with_resolver(resolver))


def test_jose_presentation_refuses_a_non_vcdm2_payload():
    did = "did:example:jose-vp-shape"
    resolver, prov = jose_vp_fixture(did)
    kid = did + "#key-1"
    cases = [
        ("no @context", {"type": ["VerifiablePresentation"], "holder": did}, "must name"),
        ("the VC 1.1 context", {"@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiablePresentation"], "holder": did}, "must name"),
        ("v2 context but not first", {"@context": ["https://example.org/custom", V2], "type": ["VerifiablePresentation"], "holder": did}, "must name"),
        ("no type", {"@context": [V2], "holder": did}, "must have type VerifiablePresentation"),
        ("a credential wearing the vp+jwt label", {"@context": [V2], "type": ["VerifiableCredential"], "holder": did}, "must have type VerifiablePresentation"),
        ("nothing but a holder", {"holder": did}, "must name"),
    ]
    for name, payload, want in cases:
        token = sign_compact(prov, kid, payload)
        with pytest.raises(ValueError, match=want):
            vp.parse_jose_presentation(token, vp.with_resolver(resolver))


def test_jose_presentation_shape_is_checked_without_vc_validation():
    did = "did:example:jose-vp-ungated"
    resolver, prov = jose_vp_fixture(did)
    token = sign_compact(prov, did + "#key-1", {"holder": did})
    with pytest.raises(ValueError):
        vp.parse_presentation(token.encode(), vp.with_resolver(resolver))


def test_new_jose_presentation_refuses_a_non_v2_context():
    did = "did:example:jose-vp-build"
    resolver, _ = jose_vp_fixture(did)
    c = jose_vp_contents(did)
    c.context = ["https://www.w3.org/2018/credentials/v1"]
    with pytest.raises(ValueError, match="must name"):
        vp.new_jose_presentation(c, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))


def test_jose_presentation_refuses_bare_credentials():
    did = "did:example:jose-vp-envelope"
    resolver, prov = jose_vp_fixture(did)
    kid = did + "#key-1"
    jose_cred = JOSECredential.create(jose_vp_credential_contents(did), vc.with_verification_method_key("key-1"), vc.with_resolver(resolver))
    jose_cred.add_proof_by_provider(prov, vc.with_resolver(resolver))
    token = jose_cred.serialize()
    json_cred = JSONCredential.create(jose_vp_credential_contents(did), vc.with_verification_method_key("key-1"), vc.with_resolver(resolver))
    json_cred.add_proof_by_provider(prov, vc.with_resolver(resolver))
    json_obj = json.loads(json.dumps(json_cred.serialize()))
    enveloped = {"@context": [V2], "type": ["EnvelopedVerifiableCredential"], "id": "data:application/vc+jwt," + token}
    cases = [
        ("enveloped, as the spec requires", enveloped, False),
        ("a bare vc+jwt string", token, True),
        ("a bare JSON-LD credential object", json_obj, True),
        ("an envelope missing its type", {"@context": [V2], "id": "data:application/vc+jwt," + token}, True),
    ]
    for name, item, want_err in cases:
        for shape in (lambda v: [v], lambda v: v):  # in an array / as a single value
            vp_token = sign_compact(prov, kid, {"@context": [V2], "type": ["VerifiablePresentation"], "holder": did,
                                                "verifiableCredential": shape(item)})
            if want_err:
                with pytest.raises(ValueError, match="EnvelopedVerifiableCredential"):
                    vp.parse_jose_presentation(vp_token, vp.with_resolver(resolver))
            else:
                pres = vp.parse_jose_presentation(vp_token, vp.with_resolver(resolver))
                pres.verify(vp.with_resolver(resolver), vp.with_vc_validation())


def test_jose_presentation_signing_paths():
    did = "did:example:jose-vp-signing"
    held, other = P256Provider(), P256Provider()
    resolver = StaticResolver([new_did_document(did, [p256_vm(did, "key-1", held)])])

    def new_pres(*opts):
        return vp.new_jose_presentation(jose_vp_contents(did), *opts, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))

    def sign_outside(pres, key):
        return key.sign(hashlib.sha256(pres.get_signing_input()).digest())

    p = new_pres()
    p.add_proof_by_provider(held, vp.with_resolver(resolver))
    p.verify(vp.with_resolver(resolver))

    with pytest.raises(ValueError, match="does not verify against verification method"):
        new_pres().add_proof_by_provider(other, vp.with_resolver(resolver))

    p = new_pres()
    p.add_custom_proof(Proof(signature=sign_outside(p, held)), vp.with_resolver(resolver))
    p.verify(vp.with_resolver(resolver))

    p = new_pres()
    with pytest.raises(ValueError, match="does not verify against verification method"):
        p.add_custom_proof(Proof(signature=sign_outside(p, other)), vp.with_resolver(resolver))

    with pytest.raises(ValueError, match=r"64-byte r\|\|s"):
        new_pres().add_custom_proof(Proof(signature=bytes(100)), vp.with_resolver(resolver))

    p = new_pres()
    with pytest.raises(ValueError, match="cannot be applied by AddCustomProof"):
        p.add_custom_proof(Proof(signature=sign_outside(p, held)), vp.with_challenge("n0nce"), vp.with_resolver(resolver))

    p = new_pres()
    p.add_proof_by_provider(held, vp.with_challenge("n0nce"), vp.with_domain("https://verifier.example"), vp.with_resolver(resolver))
    p.verify(vp.with_resolver(resolver), vp.with_expected_challenge("n0nce"), vp.with_expected_domain("https://verifier.example"))

    p = vp.new_jose_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    with pytest.raises(ValueError, match="cannot be applied when signing"):
        p.add_proof_by_provider(held, vp.with_verification_method_key("key-2"), vp.with_resolver(resolver))
