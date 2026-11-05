"""Port of Go issuer_forgery_test.go: signer binding / proofPurpose routing through parse_credential."""
import json

import pytest
from jwtvc_kit import V1, V2, p256_pair, sign_input, signing_input

from credential.common import sdjwt
from credential.common.verification_method import StaticResolver, new_did_document, new_p256_vm
from credential.vc.credential import parse_credential, with_resolver


def two_parties(a, v):
    ap, apub = p256_pair()
    vp_, vpub = p256_pair()
    avm, vvm = new_p256_vm(a, "key-1", apub), new_p256_vm(v, "key-1", vpub)
    return ap, avm, vp_, vvm, StaticResolver([new_did_document(a, [avm]), new_did_document(v, [vvm])])


def sd_token(prov, kid, payload, shown):
    si = signing_input({"typ": "vc+sd-jwt", "alg": "ES256", "kid": kid}, payload)
    tok = si + "." + sign_input(prov, si)
    for d in shown:
        tok += "~" + d
    return tok + "~"


@pytest.mark.parametrize(
    "path,show,by_victim",
    [("issuer", True, False), ("validUntil", False, True), ("credentialStatus", False, True),
     ("validFrom", False, True), ("type", True, True)],
)
def test_secured_claims_must_not_be_selectively_disclosed(path, show, by_victim):
    a, v = "did:example:sd-attacker", "did:example:sd-victim"
    ap, avm, vp_, vvm, res = two_parties(a, v)
    prov, vm, iss = (vp_, vvm, v) if by_victim else (ap, avm, a)
    inner = {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": v,
        "validFrom": "2019-01-01T00:00:00Z", "validUntil": "2020-01-01T00:00:00Z",
        "credentialStatus": {"type": "BitstringStatusListEntry", "id": "https://example.org/status/1"},
        "credentialSubject": {"id": "did:example:subject", "role": "admin"},
    }
    built = sdjwt.build_disclosures(inner, [path])
    payload = built["processed_vc"]
    payload["iss"] = iss
    token = sd_token(prov, vm.id, payload, built["disclosures"] if show else [])
    try:
        cred = parse_credential(token, with_resolver(res))
    except ValueError as exc:
        assert any(s in str(exc) for s in (
            "selective disclosure is not permitted", "carries _sd at the root", "selectively disclosed",
            "hides top-level properties behind _sd")), exc
        return
    with pytest.raises(ValueError):
        cred.verify(with_resolver(res))


@pytest.mark.parametrize(
    "typ,types",
    [("vc+jwt", ["VerifiablePresentation", "VerifiableCredential"]),
     ("vc+jwt", ["VerifiableCredential", "VerifiablePresentation"]),
     ("application/vc+jwt", ["VerifiablePresentation", "VerifiableCredential"])],
)
def test_forgery_through_proof_purpose_routing(typ, types):
    a, v = "did:example:attacker", "did:example:victim"
    ap, avm, _, _, res = two_parties(a, v)
    body = {"@context": [V2], "type": types, "iss": a, "issuer": v,
            "credentialSubject": {"id": "did:example:subject", "role": "admin"}}
    si = signing_input({"typ": typ, "alg": "ES256", "kid": avm.id}, body)
    cred = parse_credential(si + "." + sign_input(ap, si), with_resolver(res))  # not refused at parse
    with pytest.raises(ValueError) as ei:
        cred.verify(with_resolver(res))
    assert any(w in str(ei.value) for w in ("names both a credential and a presentation", "but its payload is a", "does not match"))


@pytest.mark.parametrize(
    "claims,want",
    [({"iss": "A", "issuer": "V"}, "does not match"),
     ({"issuer": "V"}, "failed to resolve verification method"),
     ({"iss": "A", "issuer": "A"}, None)],
)
def test_forgery_through_the_signer_binding(claims, want):
    a, v = "did:example:binding-attacker", "did:example:binding-victim"
    ap, avm, _, _, res = two_parties(a, v)
    claims = {k: {"A": a, "V": v}[x] for k, x in claims.items()}
    body = {"@context": [V2], "type": ["VerifiableCredential"],
            "credentialSubject": {"id": "did:example:subject", "role": "admin"}, **claims}
    si = signing_input({"typ": "vc+jwt", "alg": "ES256", "kid": avm.id}, body)
    cred = parse_credential(si + "." + sign_input(ap, si), with_resolver(res))
    if want is None:
        cred.verify(with_resolver(res))
        return
    with pytest.raises(ValueError, match=want):
        cred.verify(with_resolver(res))


@pytest.mark.parametrize("shape", [["did:example:shape-victim"], {"name": "did:example:shape-victim"}, {"id": 123}])
@pytest.mark.parametrize("layout", ["vc+jwt", "vc11"])
def test_issuer_shapes_that_name_no_did(layout, shape):
    a, v = "did:example:shape-attacker", "did:example:shape-victim"
    ap, avm, _, _, res = two_parties(a, v)
    subj = {"id": "did:example:subject", "role": "admin"}
    if layout == "vc+jwt":
        typ, body = "vc+jwt", {"@context": [V2], "type": ["VerifiableCredential"], "iss": a, "issuer": shape, "credentialSubject": subj}
    else:
        typ, body = "JWT", {"iss": a, "vc": {"@context": [V1], "type": ["VerifiableCredential"], "issuer": shape, "credentialSubject": subj}}
    si = signing_input({"typ": typ, "alg": "ES256", "kid": avm.id}, body)
    try:
        cred = parse_credential(si + "." + sign_input(ap, si), with_resolver(res))
    except ValueError:
        return
    with pytest.raises(ValueError, match="must be a string or an object with a string id"):
        cred.verify(with_resolver(res))


def test_case_variant_issuer_key_refused():
    a, v = "did:example:case-attacker", "did:example:case-victim"
    ap, avm, _, _, res = two_parties(a, v)
    body = {"@context": [V2], "type": ["VerifiableCredential"], "iss": a, "Issuer": v,
            "credentialSubject": {"id": "did:example:subject"}}
    si = signing_input({"typ": "vc+jwt", "alg": "ES256", "kid": avm.id}, body)
    try:
        cred = parse_credential(si + "." + sign_input(ap, si), with_resolver(res))
    except ValueError:
        return
    with pytest.raises(ValueError, match="differs from issuer only by case"):
        cred.verify(with_resolver(res))


def test_foreign_kid_is_rejected():
    """Attacker signs with its own key and a kid in its own (resolvable) DID, naming the victim as issuer."""
    a, v = "did:example:fk-attacker", "did:example:fk-victim"
    ap, avm, _, vvm, res = two_parties(a, v)
    body = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": v, "credentialSubject": {"id": "did:example:s"}}
    si = signing_input({"typ": "vc+jwt", "alg": "ES256", "kid": avm.id}, body)
    cred = parse_credential(si + "." + sign_input(ap, si), with_resolver(res))
    with pytest.raises(ValueError, match="failed to resolve verification method"):
        cred.verify(with_resolver(res))
