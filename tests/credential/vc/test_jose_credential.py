"""Port of Go credential/vc jose_credential_test.go + jose_signing_paths_test.go."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from jwtvc_kit import *  # noqa: F401,F403
from jwtvc_kit import (
    SECP_PRIV, V1, V2, b64, header_of, jose_contents, p256_setup, payload_of, secp_setup, sign_input,
    sign_outside, signing_input, token,
)

from credential.common.dto.proof import Proof
from credential.common.verification_method import StaticResolver, new_did_document
from credential.vc.credential import (
    parse_credential, with_check_expiration, with_resolver, with_sd_selective_paths,
    with_verification_method_key, with_verify_proof,
)
from credential.vc.jose_credential import JOSECredential


def _new(contents, resolver, *extra):
    return JOSECredential.create(contents, with_verification_method_key("key-1"), with_resolver(resolver), *extra)


@pytest.mark.parametrize("kind", ["secp", "p256"])
def test_multikey_issue_verify(kind):
    did = f"did:example:jose-{kind}"
    prov, vm, res = secp_setup(did) if kind == "secp" else p256_setup(did)
    cred = _new(jose_contents(did), res)
    tok = cred.signing_input
    assert header_of(tok)["typ"] == "vc+jwt"
    assert header_of(tok)["alg"] == ("ES256K" if kind == "secp" else "ES256")
    payload = payload_of(tok)
    assert "vc" not in payload and "vp" not in payload and payload["issuer"] == did
    cred.add_proof_by_provider(prov)
    cred.verify(with_resolver(res))
    assert len(cred.hash()) == 64
    jwt_str = cred.serialize()
    parsed = JOSECredential.parse(jwt_str)
    parsed.verify(with_resolver(res))
    assert parsed.extract_field("credentialSubject.name") == "Nguyen Van A"
    auto = parse_credential(jwt_str, with_resolver(res))
    assert auto.get_type() == "JOSE"
    auto.verify(with_resolver(res))


def test_rejects_forbidden_vc_claim():
    tok = token({"typ": "vc+jwt", "alg": "ES256", "kid": "did:example:123#key-1"}, {"vc": {"id": "123"}})
    with pytest.raises(ValueError, match="'vc' claim MUST NOT be present"):
        JOSECredential.parse(tok)


def test_rejects_forbidden_vp_claim():
    tok = token({"typ": "vc+jwt", "alg": "ES256", "kid": "k"}, {"vp": {}})
    with pytest.raises(ValueError, match="'vp' claim MUST NOT be present"):
        JOSECredential.parse(tok)


def test_rejects_invalid_typ():
    tok = token({"typ": "JWT", "alg": "ES256", "kid": "did:example:123#key-1"}, {"issuer": "did:example:123"})
    with pytest.raises(ValueError, match="invalid typ header"):
        JOSECredential.parse(tok)


SUBJECT = {"id": "did:example:subject"}


@pytest.mark.parametrize(
    "payload,want",
    [
        ({"@context": [V1], "type": ["VerifiableCredential"], "issuer": "did:example:123", "credentialSubject": SUBJECT},
         f'must name "{V2}" first in @context'),
        ({"type": ["VerifiableCredential"], "issuer": "did:example:123", "credentialSubject": SUBJECT}, "missing @context"),
        ({"@context": [V2], "type": ["VerifiablePresentation"], "issuer": "did:example:123", "credentialSubject": SUBJECT},
         "type must include VerifiableCredential"),
        ({"@context": [V2], "type": ["VerifiableCredential"], "credentialSubject": SUBJECT}, "missing issuer"),
    ],
)
def test_rejects_non_credential_payload(payload, want):
    with pytest.raises(ValueError, match=want.replace("[", r"\[")):
        JOSECredential.parse(token({"typ": "vc+jwt", "alg": "ES256", "kid": "did:example:123#key-1"}, payload))


def test_new_rejects_non_v2_context():
    c = jose_contents("did:example:123")
    c.context = [V1]
    with pytest.raises(ValueError, match="first in @context"):
        JOSECredential.create(c)


def _envelope(typ, tok):
    m = {"@context": [V2], "id": "data:application/vc+jwt," + tok}
    if typ is not None:
        m["type"] = typ
    return json.dumps(m)


def test_envelope_requires_enveloped_type():
    tok = token(
        {"typ": "vc+jwt", "alg": "ES256", "kid": "did:example:123#key-1"},
        {"@context": [V2], "type": ["VerifiableCredential"], "issuer": "did:example:123", "credentialSubject": SUBJECT},
    )
    with pytest.raises(ValueError, match="not EnvelopedVerifiableCredential"):
        parse_credential(_envelope(None, tok))
    with pytest.raises(ValueError, match="not EnvelopedVerifiableCredential"):
        parse_credential(_envelope(["VerifiableCredential"], tok))
    v11 = token({"typ": "JWT", "alg": "ES256", "kid": "k"}, {"vc": {"id": "urn:uuid:1"}})
    with pytest.raises(ValueError, match="invalid typ header"):
        parse_credential(_envelope(["EnvelopedVerifiableCredential"], v11))


def test_emits_iat_as_signing_time():
    did = "did:example:jose-time"
    prov, vm, res = p256_setup(did)
    c = jose_contents(did)
    c.valid_from = datetime(2020, 1, 1, tzinfo=timezone.utc)
    c.valid_until = datetime(2030, 1, 1, tzinfo=timezone.utc)
    before = int(datetime.now(timezone.utc).timestamp()) - 60
    cred = _new(c, res)
    cred.add_proof_by_provider(prov, with_resolver(res))
    payload = payload_of(cred.serialize())
    assert before <= payload["iat"] <= before + 180
    assert payload["iat"] != int(c.valid_from.timestamp())
    assert "exp" not in payload and "nbf" not in payload
    cred.verify(with_resolver(res), with_check_expiration())


def _hand_signed(did, vm_id, prov, extra):
    header = {"typ": "vc+jwt", "alg": "ES256", "kid": vm_id}
    body = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did, "credentialSubject": SUBJECT, **extra}
    si = signing_input(header, body)
    return si + "." + sign_input(prov, si)


def test_expired_by_exp_claim_alone():
    did = "did:example:jose-exp"
    prov, vm, res = p256_setup(did)
    now = datetime.now(timezone.utc)
    tok = _hand_signed(did, vm.id, prov, {
        "iat": int((now - timedelta(hours=48)).timestamp()), "exp": int((now - timedelta(hours=24)).timestamp())})
    parsed = JOSECredential.parse(tok, with_resolver(res))
    with pytest.raises(ValueError, match="signature expired at"):
        parsed.verify(with_resolver(res))


def test_allows_exp_different_from_valid_until():
    did = "did:example:jose-exp-differs"
    prov, vm, res = p256_setup(did)
    tok = _hand_signed(did, vm.id, prov, {
        "validUntil": "2040-01-01T00:00:00Z", "exp": int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())})
    JOSECredential.parse(tok, with_resolver(res)).verify(with_resolver(res), with_check_expiration())


def test_nbf_in_future_rejected():
    did = "did:example:jose-nbf"
    prov, vm, res = p256_setup(did)
    tok = _hand_signed(did, vm.id, prov, {"nbf": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())})
    with pytest.raises(ValueError, match="not valid before"):
        JOSECredential.parse(tok, with_resolver(res)).verify(with_resolver(res))


def test_enveloped_credential_unwrap():
    did = "did:example:jose-enveloped"
    prov, vm, res = secp_setup(did)
    cred = _new(jose_contents(did), res)
    cred.add_proof_by_provider(prov)
    env = json.dumps({"@context": [V2], "type": ["EnvelopedVerifiableCredential"],
                      "id": "data:application/vc+jwt," + cred.serialize()})
    parsed = parse_credential(env, with_resolver(res))
    assert parsed.get_type() == "JOSE"
    parsed.verify(with_resolver(res))


def test_typ_names_the_securing_mechanism():
    did = "did:example:jose-typ"
    prov, vm, res = p256_setup(did)
    cred = _new(jose_contents(did), res)
    cred.add_proof_by_provider(prov, with_resolver(res))
    assert header_of(cred.serialize())["typ"] == "vc+jwt"
    assert "~" not in cred.serialize()
    parse_credential(cred.serialize(), with_resolver(res)).verify(with_resolver(res))


def _sd_contents(did):
    c = jose_contents(did)
    c.subject[0].custom_fields = {"name": "Alice", "bloodType": "O-"}
    return c


def test_selective_disclosure_roundtrip_and_withhold():
    did = "did:example:jose-sd"
    prov, vm, res = p256_setup(did)
    cred = _new(_sd_contents(did), res, with_sd_selective_paths(["credentialSubject.bloodType"]))
    cred.add_proof_by_provider(prov, with_resolver(res))
    tok = cred.serialize()
    assert header_of(tok)["typ"] == "vc+sd-jwt" and "~" in tok
    parsed = parse_credential(tok, with_resolver(res))
    parsed.verify(with_resolver(res))
    assert parsed.extract_field("credentialSubject")["bloodType"] == "O-"

    presented = cred.present(None)
    presented.verify(with_resolver(res))
    subj = presented.extract_field("credentialSubject")
    assert "bloodType" not in subj and subj["name"] == "Alice"


@pytest.mark.parametrize("path", ["issuer", "validUntil", "validFrom", "credentialStatus", "type"])
def test_selective_disclosure_top_level_refused(path):
    did = "did:example:jose-sd"
    _, _, res = p256_setup(did)
    c = _sd_contents(did)
    c.valid_until = datetime.now(timezone.utc) + timedelta(hours=1)
    with pytest.raises(ValueError) as ei:
        _new(c, res, with_sd_selective_paths([path]))
    assert "_sd at the root" in str(ei.value) or "failed to build SD-JWT disclosures" in str(ei.value)


@pytest.mark.parametrize("kind", ["P-256", "secp"])
def test_add_custom_proof_verifies_what_it_attaches(kind):
    did = "did:example:jose-custom-" + kind
    prov, vm, res = p256_setup(did) if kind == "P-256" else secp_setup(did)
    cred = _new(jose_contents(did), res)
    raw = sign_outside(prov, cred.get_signing_input())
    cred.add_custom_proof(Proof(signature=raw), with_resolver(res), with_verify_proof())
    cred.verify(with_resolver(res))


def test_add_custom_proof_rolls_back_on_failure():
    did = "did:example:jose-custom-rollback"
    _, _, res = p256_setup(did)
    cred = _new(jose_contents(did), res)
    with pytest.raises(ValueError) as ei:
        cred.add_custom_proof(Proof(signature=bytes(64)), with_resolver(res), with_verify_proof())
    assert "credential is not signed" not in str(ei.value)
    assert cred.serialize().count(".") == 1


# ---- jose_signing_paths_test.go -------------------------------------------------
@pytest.fixture
def paths():
    did = "did:example:jose-signing"
    held, vm, res = p256_setup(did)
    other, _, _ = p256_setup(did)
    c = jose_contents(did)
    c.id = ""
    c.types = ["VerifiableCredential"]
    c.subject[0].custom_fields = {}
    return held, other, res, lambda: _new(c, res)


def test_paths_provider_right_key(paths):
    held, other, res, new = paths
    cred = new()
    cred.add_proof_by_provider(held, with_resolver(res))
    cred.verify(with_resolver(res))


def test_paths_provider_other_key(paths):
    held, other, res, new = paths
    with pytest.raises(ValueError, match="does not verify against verification method"):
        new().add_proof_by_provider(other, with_resolver(res))


def test_paths_custom_right_and_other_key(paths):
    held, other, res, new = paths
    cred = new()
    cred.add_custom_proof(Proof(signature=sign_outside(held, cred.get_signing_input())), with_resolver(res))
    cred.verify(with_resolver(res))
    cred = new()
    with pytest.raises(ValueError, match="does not verify against verification method"):
        cred.add_custom_proof(Proof(signature=sign_outside(other, cred.get_signing_input())), with_resolver(res))


def test_paths_custom_wrong_shape(paths):
    held, other, res, new = paths
    with pytest.raises(ValueError, match=r"64-byte r\|\|s"):
        new().add_custom_proof(Proof(signature=bytes(100)), with_resolver(res))


def test_paths_build_time_option_at_signing(paths):
    held, other, res, new = paths
    with pytest.raises(ValueError, match="cannot be applied when signing"):
        new().add_proof_by_provider(held, with_verification_method_key("key-2"), with_resolver(res))


def test_paths_failed_call_leaves_signature(paths):
    held, other, res, new = paths
    cred = new()
    cred.add_proof_by_provider(held, with_resolver(res))
    before = cred.serialize()
    with pytest.raises(ValueError):
        cred.add_proof_by_provider(other, with_resolver(res))
    assert cred.serialize() == before
    cred.verify(with_resolver(res))
