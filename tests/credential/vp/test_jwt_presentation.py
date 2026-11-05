"""Ports of the JWT (VC 1.1) parts of challenge_domain_test.go, require_audience_test.go,
unsigned_verify_test.go, nil_credential_test.go, signing_atomicity_test.go, leeway_test.go,
sdjwt_envelope_test.go and the JWT flows of presentation_test.go."""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from vp_helpers import (
    FailingSigner,
    P256Provider,
    StaticResolver,
    TEST_DID,
    TEST_SECP_PRIV_HEX,
    V2,
    CountingSigner,
    default_signer,
    err_chain_has,
    jose_vp_contents,
    jose_vp_credential_contents,
    jose_vp_fixture,
    jwt_header,
    jwt_payload,
    new_did_document,
    p256_from_hex,
    p256_vm,
    sign_compact,
    sign_externally,
    test_resolver,
    verify_by_hand,
)
from credential.common.dto.proof import Proof
from credential.common.jwt.jwtutil import b64url_encode, json_dumps
from credential.vc import credential as vc
from credential.vc.jose_credential import JOSECredential
from credential import vp


def jwt_vp_contents():
    return vp.PresentationContents(context=[V2], id="urn:uuid:jwt-challenge-test", types=["VerifiablePresentation"], holder=TEST_DID)


def _err_match(fn, want):
    if want == "":
        fn()
        return
    with pytest.raises(ValueError, match=want):
        fn()


CD_CASES = [
    ("matching both", [lambda: vp.with_expected_challenge("nonce-123"), lambda: vp.with_expected_domain("verifier.example")], ""),
    ("no expectations", [], ""),
    ("wrong challenge", [lambda: vp.with_expected_challenge("nonce-999")], "nonce"),
    ("wrong domain", [lambda: vp.with_expected_domain("evil.example")], "aud"),
]


def test_jwt_vp_challenge_domain_sign_and_verify():
    resolver = test_resolver()
    pres = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_verification_method_key("#key-1"), vp.with_resolver(resolver),
                                   vp.with_challenge("nonce-123"), vp.with_domain("verifier.example"))
    pres.add_proof_by_provider(default_signer())
    token = pres.serialize()
    claims = jwt_payload(token)
    assert claims["nonce"] == "nonce-123" and claims["aud"] == "verifier.example"
    for name, mk, want in CD_CASES:
        opts = [f() for f in mk]
        _err_match(lambda: pres.verify(vp.with_resolver(resolver), *opts), want)
        reparsed = vp.parse_jwt_presentation(token)
        _err_match(lambda: reparsed.verify(vp.with_resolver(resolver), *opts), want)


def test_jwt_vp_challenge_domain_missing_rejected():
    resolver = test_resolver()
    pres = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_verification_method_key("#key-1"), vp.with_resolver(resolver))
    pres.add_proof_by_provider(default_signer())
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-123"))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_domain("verifier.example"))


def test_jwt_vp_challenge_domain_tampered_aud_rejected():
    resolver = test_resolver()
    pres = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_verification_method_key("#key-1"), vp.with_resolver(resolver),
                                   vp.with_domain("verifier.example"))
    pres.add_proof_by_provider(default_signer())
    parts = pres.serialize().split(".")
    claims = jwt_payload(pres.serialize())
    claims["aud"] = "evil.example"
    tampered = parts[0] + "." + b64url_encode(json_dumps(claims)) + "." + parts[2]
    reparsed = vp.parse_jwt_presentation(tampered)
    with pytest.raises(ValueError):
        reparsed.verify(vp.with_resolver(resolver), vp.with_expected_domain("evil.example"))


def test_jwt_vp_p256_verification_method():
    resolver = test_resolver()
    pres = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_resolver(resolver), vp.with_verification_method_key("#key-2"))
    pres.add_proof_by_provider(p256_from_hex())
    token = pres.serialize()
    h = jwt_header(token)
    assert h["alg"] == "ES256" and h["kid"] == TEST_DID + "#key-2"
    pres.verify(vp.with_resolver(resolver))
    vp.parse_jwt_presentation(token).verify(vp.with_resolver(resolver))


def test_jwt_vp_add_proof_by_provider_ignores_verify_options():
    resolver = test_resolver()
    pres = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_resolver(resolver), vp.with_verification_method_key("#key-1"),
                                   vp.with_challenge("nonce-123"))
    pres.add_proof_by_provider(default_signer(), vp.with_resolver(resolver), vp.with_expected_challenge("wrong"))
    assert pres.serialize().count(".") == 2
    pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-123"))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("wrong"))


def test_jwt_vp_challenge_domain_set_at_sign_time():
    resolver = test_resolver()
    pres = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_resolver(resolver), vp.with_verification_method_key("#key-1"),
                                   vp.with_challenge("stale"), vp.with_domain("stale.example"))
    pres.add_proof_by_provider(default_signer(), vp.with_challenge("nonce-123"), vp.with_domain("verifier.example"))
    claims = jwt_payload(pres.serialize())
    assert claims["nonce"] == "nonce-123" and claims["aud"] == "verifier.example"
    pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-123"), vp.with_expected_domain("verifier.example"))
    with pytest.raises(ValueError):
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("stale"))


def _sign_jwt11(prov, kid, payload):
    return sign_compact(prov, kid, payload, typ="JWT")


def test_jwt_presentation_checks_exp_and_nbf():
    did = "did:example:vp-time"
    resolver, prov = jose_vp_fixture(did)
    now = int(time.time())
    cases = [
        ("inside the window", {"nbf": now - 3600, "exp": now + 3600}, ""),
        ("exp has passed", {"exp": now - 3600}, "expired"),
        ("nbf is in the future", {"nbf": now + 3600}, "not valid before"),
    ]
    for name, claims, want in cases:
        payload = {"iss": did, "holder": did,
                   "vp": {"@context": [V2], "type": ["VerifiablePresentation"], "holder": did}, **claims}
        token = _sign_jwt11(prov, did + "#key-1", payload)
        parsed = vp.parse_jwt_presentation(token, vp.with_resolver(resolver))
        parsed.verify(vp.with_resolver(resolver))  # a plain verify must not look at time claims
        _err_match(lambda: parsed.verify(vp.with_resolver(resolver), vp.with_check_expiration()), want)


def test_with_require_audience_needs_a_verifier_identity():
    did, challenge, domain = "did:example:require-aud", "nonce-from-the-verifier", "https://verifier.example"
    resolver, prov = jose_vp_fixture(did)

    # vp+jwt
    pres = vp.new_jose_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    pres.add_proof_by_provider(prov, vp.with_challenge(challenge), vp.with_domain(domain), vp.with_resolver(resolver))
    parsed = vp.parse_jose_presentation(pres.serialize(), vp.with_resolver(resolver))
    with pytest.raises(ValueError) as ei:
        parsed.verify(vp.with_resolver(resolver), vp.with_require_audience())
    assert err_chain_has(ei.value, vp.AudienceUnboundError)
    parsed.verify(vp.with_resolver(resolver), vp.with_require_audience(), vp.with_expected_domain(domain))
    with pytest.raises(ValueError, match="does not match expected domain"):
        parsed.verify(vp.with_resolver(resolver), vp.with_require_audience(), vp.with_expected_domain("https://someone-else.example"))

    # JSON-LD, through proof.domain
    jpres = vp.new_json_presentation(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    jpres.add_proof_by_provider(prov, vp.with_challenge(challenge), vp.with_domain(domain),
                                vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    with pytest.raises(ValueError) as ei:
        jpres.verify(vp.with_resolver(resolver), vp.with_require_audience())
    assert err_chain_has(ei.value, vp.AudienceUnboundError)
    jpres.verify(vp.with_resolver(resolver), vp.with_require_audience(), vp.with_expected_domain(domain))
    with pytest.raises(ValueError, match="domain"):
        jpres.verify(vp.with_resolver(resolver), vp.with_require_audience(), vp.with_expected_domain("https://someone-else.example"))
    with pytest.raises(ValueError, match="domain"):
        jpres.verify(vp.with_resolver(resolver), vp.with_expected_domain("https://someone-else.example"))
    jpres.verify(vp.with_resolver(resolver), vp.with_expected_domain(domain))


def test_verify_unsigned_says_it_is_unsigned():
    did = "did:example:unsigned-vp"
    resolver, _ = jose_vp_fixture(did)
    for build in (vp.new_jose_presentation, vp.new_jwt_presentation):
        pres = build(jose_vp_contents(did), vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
        with pytest.raises(ValueError, match="not signed"):
            pres.verify(vp.with_resolver(resolver))


@pytest.mark.parametrize("builder", ["new_jose_presentation", "new_json_presentation", "new_jwt_presentation"])
def test_presentation_builders_refuse_nil_credentials(builder):
    did = "did:example:nil-cred"
    resolver, _ = jose_vp_fixture(did)
    contents = jose_vp_contents(did)
    contents.verifiable_credentials = [None]
    with pytest.raises(ValueError, match="credential at index 0 is nil"):
        getattr(vp, builder)(contents, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))


# --- signing atomicity ---
def _kinds():
    holder = "did:example:vp-atomicity"
    prov = P256Provider()
    resolver = StaticResolver([new_did_document(holder, [p256_vm(holder, "key-1", prov)])])
    contents = vp.PresentationContents(context=[V2], id="urn:uuid:vp-atomicity", types=["VerifiablePresentation"], holder=holder)
    out = []
    for name, ctor in (("VC 1.1 JWT", vp.new_jwt_presentation), ("vp+jwt", vp.new_jose_presentation)):
        p = ctor(contents, vp.with_resolver(resolver), vp.with_verification_method_key("key-1"), vp.with_challenge("nonce-AAA"))
        p.add_proof_by_provider(prov, vp.with_resolver(resolver))
        out.append((name, p, resolver, prov))
    return out


def test_signing_failed_resign_leaves_the_presentation_signed():
    for name, pres, resolver, prov in _kinds():
        before = pres.serialize()
        with pytest.raises(ValueError):
            pres.add_proof_by_provider(FailingSigner("signer unreachable"), vp.with_resolver(resolver),
                                       vp.with_challenge("nonce-BBB"), vp.with_replace_proof())
        assert pres.serialize() == before, name
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-AAA"))


def test_signing_resign_with_a_new_challenge_still_works():
    for name, pres, resolver, prov in _kinds():
        pres.add_proof_by_provider(prov, vp.with_resolver(resolver), vp.with_challenge("nonce-BBB"), vp.with_replace_proof())
        pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-BBB"))
        with pytest.raises(ValueError):
            pres.verify(vp.with_resolver(resolver), vp.with_expected_challenge("nonce-AAA"))


def test_signing_refuses_to_replace_a_signature():
    for name, pres, resolver, prov in _kinds():
        before = pres.serialize()
        with pytest.raises(ValueError, match="already signed"):
            pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
        assert pres.serialize() == before
        pres.add_proof_by_provider(prov, vp.with_resolver(resolver), vp.with_replace_proof())
        pres.verify(vp.with_resolver(resolver))


# --- leeway ---
def test_with_leeway_presentation():
    did = "did:example:vp-leeway"
    resolver, prov = jose_vp_fixture(did)

    def build_jwt(c):
        p = vp.new_jwt_presentation(c, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
        p.add_proof_by_provider(prov)
        return p.serialize()

    def build_jose(c):
        p = vp.new_jose_presentation(c, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
        p.add_proof_by_provider(prov)
        return p.serialize()

    now = datetime.now(timezone.utc)
    s = timedelta(seconds=1)
    cases = [
        ("holder clock ahead, no leeway", now + 5 * s, None, timedelta(0), "not valid yet"),
        ("holder clock ahead, within leeway", now + 5 * s, None, 30 * s, ""),
        ("holder clock ahead, beyond leeway", now + 60 * s, None, 30 * s, "not valid yet"),
        ("just expired, no leeway", now - timedelta(hours=1), now - 5 * s, timedelta(0), "expired"),
        ("just expired, within leeway", now - timedelta(hours=1), now - 5 * s, 30 * s, ""),
        ("negative leeway counts as zero", now + 5 * s, None, -timedelta(hours=1), "not valid yet"),
    ]
    for fmt, build in (("vp jwt", build_jwt), ("vp+jwt", build_jose)):
        for name, vf, vu, lw, want in cases:
            c = jose_vp_contents(did)
            c.valid_from, c.valid_until = vf, vu
            token = build(c)
            _err_match(lambda: vp.parse_presentation(token.encode(), vp.with_resolver(resolver), vp.with_verify_proof(),
                                                     vp.with_check_expiration(), vp.with_leeway(lw)), want)


def test_with_leeway_reaches_embedded_credentials():
    did = "did:example:vp-leeway-vc"
    resolver, prov = jose_vp_fixture(did)
    cc = jose_vp_credential_contents(did)
    cc.valid_from = datetime.now(timezone.utc) + timedelta(seconds=5)  # issuer clock ahead
    cred = JOSECredential.create(cc, vc.with_verification_method_key("key-1"), vc.with_resolver(resolver))
    cred.add_proof_by_provider(prov)
    c = jose_vp_contents(did)
    c.valid_from = datetime.now(timezone.utc) - timedelta(hours=1)
    c.verifiable_credentials = [cred]
    pres = vp.new_jose_presentation(c, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
    pres.add_proof_by_provider(prov)
    cases = [
        ("no leeway", [vp.with_vc_validation(vc.with_check_expiration())], "credential is not valid yet"),
        ("presentation leeway is forwarded", [vp.with_leeway(timedelta(seconds=30)), vp.with_vc_validation(vc.with_check_expiration())], ""),
        ("credential leeway overrides the forwarded one",
         [vp.with_leeway(timedelta(seconds=30)), vp.with_vc_validation(vc.with_check_expiration(), vc.with_leeway(timedelta(0)))],
         "credential is not valid yet"),
    ]
    for name, opts, want in cases:
        _err_match(lambda: pres.verify(vp.with_resolver(resolver), *opts), want)


# --- sd-jwt envelope ---
def test_jose_presentation_envelopes_an_sd_jwt_by_its_own_media_type():
    did = "did:example:vp-sd-envelope"
    resolver, prov = jose_vp_fixture(did)
    cc = jose_vp_credential_contents(did)
    cc.subject = [vc.Subject(id="did:example:subject", custom_fields={"name": "Alice", "bloodType": "O-"})]
    sd = JOSECredential.create(cc, vc.with_sd_selective_paths(["credentialSubject.bloodType"]),
                               vc.with_verification_method_key("key-1"), vc.with_resolver(resolver))
    sd.add_proof_by_provider(prov, vc.with_resolver(resolver))
    reveal_nothing = sd.present(None or [])
    for name, held in (("every disclosure sent", sd), ("nothing revealed", reveal_nothing)):
        c = jose_vp_contents(did)
        c.verifiable_credentials = [held]
        pres = vp.new_jose_presentation(c, vp.with_verification_method_key("key-1"), vp.with_resolver(resolver))
        pres.add_proof_by_provider(prov, vp.with_resolver(resolver))
        env = json.loads(pres.get_contents())["verifiableCredential"]
        assert len(env) == 1
        assert env[0]["id"].startswith("data:application/" + vc.TYPE_VC_SD_JWT + ",")
        back = vp.parse_jose_presentation(pres.serialize(), vp.with_resolver(resolver))
        back.verify(vp.with_resolver(resolver), vp.with_vc_validation())


# --- sign options ---
def _sign_paths(resolver):
    def jwt_attached(p):
        return lambda: p.serialize().count(".") == 2

    def jwt_add(t_contents, s, *opts):
        p = vp.new_jwt_presentation(t_contents, vp.with_resolver(resolver))
        err = None
        try:
            p.add_proof_by_provider(s, *opts)
        except ValueError as e:
            err = e
        return (lambda: p.verify(vp.with_resolver(resolver))), jwt_attached(p), err

    def jwt_custom(t_contents, s, *opts):
        p = vp.new_jwt_presentation(t_contents, vp.with_resolver(resolver))
        inp = p.get_signing_input().decode()
        err = None
        try:
            p.add_custom_proof(Proof(signature=sign_externally(s, inp)), *opts)
        except ValueError as e:
            err = e
        return (lambda: p.verify(vp.with_resolver(resolver))), jwt_attached(p), err

    def json_custom(t_contents, s, *opts):
        p = vp.new_json_presentation(t_contents)
        err = None
        try:
            p.add_custom_proof(_external_json_proof(t_contents, s, resolver), *opts)
        except ValueError as e:
            err = e
        return (lambda: p.verify(vp.with_resolver(resolver))), (lambda: p.extract_field("proof") is not None), err

    def json_add(t_contents, s, *opts):
        p = vp.new_json_presentation(t_contents)
        err = None
        try:
            p.add_proof_by_provider(s, vp.with_resolver(resolver), *opts)
        except ValueError as e:
            err = e

        def attached():
            try:
                p.serialize()
                return True
            except ValueError:
                return False
        return (lambda: p.verify(vp.with_resolver(resolver))), attached, err

    return [("JWT AddProofByProvider", jwt_add), ("JWT AddCustomProof", jwt_custom),
            ("JSON AddCustomProof", json_custom), ("JSON AddProofByProvider", json_add)]


def _external_json_proof(c, s, resolver):
    import copy

    c = copy.copy(c)
    # the v2 context defines no validFrom/validUntil on a presentation
    c.valid_from = c.valid_until = None
    signed = vp.new_json_presentation(c)
    signed.add_proof_by_provider(s, vp.with_resolver(resolver))
    from vp_helpers import proof_from_json

    return proof_from_json(signed.extract_field("proof"))


def _sign_options_contents():
    return vp.PresentationContents(context=[V2], id="urn:uuid:sign-options-test", types=["VerifiablePresentation"], holder=TEST_DID)


def test_sign_verify_option_does_not_block_a_correct_signature():
    resolver = test_resolver()
    for name, path in _sign_paths(resolver):
        verify, _, err = path(_sign_options_contents(), p256_from_hex(), vp.with_verify_proof(), vp.with_resolver(resolver))
        assert err is None, f"{name}: {err}"
        verify()


def test_sign_content_options_run_before_signing():
    resolver = test_resolver()
    not_yet = _sign_options_contents()
    not_yet.valid_from = datetime.now(timezone.utc) + timedelta(hours=1)
    for name, path in _sign_paths(resolver):
        want_calls = 1 if name.endswith("AddCustomProof") else 0  # the test signs outside before the call
        s = CountingSigner(p256_from_hex())
        _, attached, err = path(not_yet, s, vp.with_check_expiration())
        assert err is not None and "not valid yet" in str(err), name
        assert s.inner is not None
        # JSON paths sign a copy once (external proof helper), mirroring the Go counting
        if name.startswith("JWT"):
            assert s.calls == want_calls, name
        assert not attached(), name


def test_jwt_presentation_signing_refuses_build_time_options():
    want_vm = "WithVerificationMethodKey cannot be applied when signing a JWT"
    want_ch = "pass them to NewJWTPresentation before GetSigningInput"
    resolver = test_resolver()
    p256 = p256_from_hex()
    cases = [
        (lambda: vp.with_verification_method_key("key-2"), ["JWT AddProofByProvider", "JWT AddCustomProof"], want_vm),
        (lambda: vp.with_challenge("my-nonce"), ["JWT AddCustomProof"], want_ch),
        (lambda: vp.with_domain("https://verifier.example"), ["JWT AddCustomProof"], want_ch),
    ]
    for name, path in _sign_paths(resolver):
        for mk, paths, want in cases:
            if name not in paths:
                continue
            s = CountingSigner(p256)
            _, attached, err = path(jwt_vp_contents(), s, mk())
            assert err is not None and want in str(err), (name, err)
            assert s.calls == (1 if name == "JWT AddCustomProof" else 0)
            assert not attached()

    p = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_resolver(resolver))
    before = p.get_signing_input().decode()
    with pytest.raises(ValueError, match=want_vm):
        p.add_proof_by_provider(p256, vp.with_verification_method_key("key-2"), vp.with_challenge("n"))
    assert p.serialize() == before

    p = vp.new_jwt_presentation(jwt_vp_contents(), vp.with_resolver(resolver))
    p.add_custom_proof(Proof(signature=sign_externally(p256, p.get_signing_input().decode())))
    p.verify(vp.with_resolver(resolver))


def test_json_presentation_add_custom_proof_refuses_proof_options():
    def proof():
        return Proof(type="DataIntegrityProof", cryptosuite="ecdsa-rdfc-2019", proof_purpose="authentication",
                     verification_method=TEST_DID + "#key-2", proof_value="z3FXQ", created="2026-09-19T00:00:00Z")

    for opt in (vp.with_challenge("my-nonce"), vp.with_domain("https://verifier.example"), vp.with_verification_method_key("key-1")):
        p = vp.new_json_presentation(jwt_vp_contents())
        with pytest.raises(ValueError, match="on the proof you sign"):
            p.add_custom_proof(proof(), opt)
        assert p.extract_field("proof") is None
    p = vp.new_json_presentation(jwt_vp_contents())
    p.add_custom_proof(proof())
    assert p.extract_field("proof") is not None


def test_jwt_presentation_signer_must_hold_the_header_key():
    vpc = vp.PresentationContents(context=[V2], id="urn:uuid:jwt-signer-key-test", types=["VerifiablePresentation"], holder=TEST_DID)
    resolver = test_resolver()
    secp, p256 = default_signer(), p256_from_hex()
    cases = [
        ("default key-2 (P-256), P-256 signer", "", p256, False, True),
        ("default key-2 (P-256), secp256k1 signer", "", secp, False, False),
        ("pinned key-1 (secp256k1), secp256k1 signer", "#key-1", secp, False, True),
        ("pinned key-1 (secp256k1), P-256 signer", "#key-1", p256, False, False),
        ("custom: default key-2 (P-256), P-256 signature", "", p256, True, True),
        ("custom: pinned key-1 (secp256k1), 65-byte secp256k1 signature", "#key-1", secp, True, True),
        ("custom: default key-2 (P-256), secp256k1 signature", "", secp, True, False),
        ("custom: pinned key-1 (secp256k1), P-256 signature", "#key-1", p256, True, False),
    ]
    for name, pin, signer, custom, want_ok in cases:
        opts = [vp.with_resolver(resolver)] + ([vp.with_verification_method_key(pin)] if pin else [])
        p = vp.new_jwt_presentation(vpc, *opts)
        signing_input = p.get_signing_input().decode()
        external = sign_externally(signer, signing_input)
        try:
            if custom:
                p.add_custom_proof(Proof(signature=external))
            else:
                p.add_proof_by_provider(signer)
            err = None
        except ValueError as e:
            err = e
        if want_ok:
            assert err is None, f"{name}: {err}"
            p.verify(vp.with_resolver(resolver))
            continue
        assert err is not None and "does not verify against verification method" in str(err), name
        assert p.serialize().count(".") == 1, name
        with pytest.raises(ValueError):
            verify_by_hand(resolver, signing_input, external)
