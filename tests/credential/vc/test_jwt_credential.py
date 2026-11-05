"""Port of Go credential/vc JWT (VC 1.1) tests: jwt_multikey_e2e, jwt_time_claims, leeway,
revoked_vm, sign_options (JWT), signing_atomicity (replace), vc11_sdjwt_refused, signer_vm_match."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwtvc_kit import (
    SECP_PRIV, V1, V2, header_of, jose_contents, p256_pair, p256_setup, parts, payload_of, pub_hex, secp_setup,
    sign_input, sign_outside, signing_input, token, vc11_contents,
)

from credential.common.dto.proof import Proof
from credential.common.jwt import JWTVerifier
from credential.common.signer.p256 import P256Provider
from credential.common.verification_method import (
    StaticResolver, new_did_document, new_p256_multikey_vm, new_p256_vm, new_rsa_vm, new_secp256k1_vm,
)
from credential.vc.credential import (
    CredentialContents, Decoy, Subject, parse_credential, with_check_expiration, with_leeway, with_replace_proof,
    with_resolver, with_sd_disclosures, with_sd_decoy_digests, with_sd_hash_algorithm, with_sd_selective_paths,
    with_sd_shuffle, with_verification_method_key, with_verify_proof,
)
from credential.vc.jwt_credential import JWTCredential
from didv2.signer import DefaultProvider


def contents(did):
    c = jose_contents(did)
    c.id = "urn:uuid:jwt-multikey-001"
    c.types = ["VerifiableCredential"]
    return c


def _new(c, res, *extra):
    return JWTCredential.create(c, with_resolver(res), *extra)


@pytest.mark.parametrize("kind,alg", [("secp", "ES256K"), ("p256", "ES256")])
def test_multikey_issue_verify(kind, alg):
    did = f"did:example:jwt-{kind}"
    prov, vm, res = secp_setup(did) if kind == "secp" else p256_setup(did)
    cred = _new(contents(did), res, with_verification_method_key("key-1"))
    assert header_of(cred.signing_input)["alg"] == alg
    cred.add_proof_by_provider(prov)
    cred.verify(with_resolver(res))
    parsed = JWTCredential.parse(cred.serialize())
    parsed.verify(with_resolver(res))
    assert parsed.extract_field("credentialSubject.name") == "Nguyen Van A"
    assert parse_credential(cred.serialize(), with_resolver(res)).get_type() == "JWT"


def test_alg_must_match_vm():
    did = "did:example:jwt-alg-mismatch"
    prov, vm, res = p256_setup(did)
    cred = _new(contents(did), res, with_verification_method_key("key-1"))
    cred.add_proof_by_provider(prov)
    secp_res = StaticResolver([new_did_document(did, [new_secp256k1_vm(did, "key-1", pub_hex())])])
    with pytest.raises(ValueError, match="does not match verification method"):
        cred.verify(with_resolver(secp_res))


def test_rsa_vm_rejected():
    did = "did:example:jwt-rsa"
    key = rsa.generate_private_key(65537, 2048)
    res = StaticResolver([new_did_document(did, [new_rsa_vm(did, "key-1", key.public_key())])])
    with pytest.raises(ValueError, match="not supported for JWT"):
        _new(contents(did), res, with_verification_method_key("key-1"))


def dual(did):
    secp = DefaultProvider(SECP_PRIV)
    p256, pub = p256_pair()
    res = StaticResolver([new_did_document(did, [new_secp256k1_vm(did, "key-1", pub_hex()), new_p256_vm(did, "key-2", pub)])])
    return res, secp, p256


@pytest.mark.parametrize(
    "pin,who,via,ok",
    [
        ("", "p256", "provider", True),
        ("", "secp", "provider", False),
        ("", "secp", "addProof", False),
        ("key-1", "secp", "provider", True),
        ("key-1", "p256", "provider", False),
        ("", "p256", "custom", True),
        ("key-1", "secp", "custom", True),
        ("", "secp", "custom", False),
        ("key-1", "p256", "custom", False),
    ],
)
def test_signer_must_hold_the_header_key(pin, who, via, ok):
    did = "did:example:jwt-dual"
    res, secp, p256 = dual(did)
    s = secp if who == "secp" else p256
    opts = [with_resolver(res)] + ([with_verification_method_key(pin)] if pin else [])
    cred = JWTCredential.create(contents(did), *opts)
    external = sign_outside(s, cred.get_signing_input())
    try:
        if via == "provider":
            cred.add_proof_by_provider(s)
        elif via == "addProof":
            cred.add_proof(SECP_PRIV)
        else:
            cred.add_custom_proof(Proof(signature=external))
    except ValueError as exc:
        assert not ok and "does not verify against verification method" in str(exc)
        with pytest.raises(ValueError):
            cred.hash()  # nothing attached
        # independent check: the hand-built token must fail the plain verifier too
        sig = external[:64]
        from jwtvc_kit import b64

        with pytest.raises(ValueError):
            JWTVerifier(res).verify_jwt(cred.signing_input + "." + b64(sig))
        return
    assert ok
    cred.verify(with_resolver(res))


def test_mismatch_error_hint_works():
    did = "did:example:jwt-hint"
    res, secp, _ = dual(did)
    cred = JWTCredential.create(contents(did), with_resolver(res))
    with pytest.raises(ValueError, match="pass WithVerificationMethodKey to NewJWTCredential"):
        cred.add_proof_by_provider(secp)
    cred = JWTCredential.create(contents(did), with_resolver(res), with_verification_method_key("key-1"))
    cred.add_proof_by_provider(secp)
    cred.verify(with_resolver(res))


def test_parsed_token_signs_without_key_check():
    did = "did:example:jwt-dual"
    res, secp, p256 = dual(did)
    built = JWTCredential.create(contents(did), with_resolver(res))
    built.add_proof_by_provider(p256)
    parsed = JWTCredential.parse(built.serialize(), with_resolver(res))
    wrong = sign_outside(secp, parsed.get_signing_input())
    parsed.add_custom_proof(Proof(signature=wrong), with_replace_proof())
    with pytest.raises(ValueError):
        parsed.verify(with_resolver(res))


# ---- jwt_time_claims_test.go ----------------------------------------------------
@pytest.mark.parametrize(
    "claims,want",
    [
        (lambda n: {"nbf": n - 3600, "exp": n + 3600}, None),
        (lambda n: {"exp": n - 3600}, "expired"),
        (lambda n: {"nbf": n + 3600}, "not valid before"),
        (lambda n: {}, None),
    ],
)
def test_jwt_checks_exp_and_nbf(claims, want):
    did = "did:example:jwt-time"
    prov, vm, res = p256_setup(did)
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "iss": did,
        "vc": {
            "@context": [V1], "type": ["VerifiableCredential"], "issuer": did,
            "issuanceDate": (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expirationDate": (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "credentialSubject": {"id": "did:example:subject"},
        },
        **claims(now),
    }
    si = signing_input({"typ": "JWT", "alg": "ES256", "kid": vm.id}, payload)
    parsed = JWTCredential.parse(si + "." + sign_input(prov, si), with_resolver(res))
    parsed.verify(with_resolver(res))  # a plain verify does not look at time claims
    if want is None:
        parsed.verify(with_resolver(res), with_check_expiration())
    else:
        with pytest.raises(ValueError, match=want):
            parsed.verify(with_resolver(res), with_check_expiration())


# ---- leeway_test.go -------------------------------------------------------------
NOW = lambda: datetime.now(timezone.utc)  # noqa: E731
LEEWAY = [
    ("clock ahead, no leeway", 5, None, 0, "not valid yet"),
    ("clock ahead, within leeway", 5, None, 30, None),
    ("clock ahead, beyond leeway", 60, None, 30, "not valid yet"),
    ("just expired, no leeway", -3600, -5, 0, "expired"),
    ("just expired, within leeway", -3600, -5, 30, None),
    ("negative leeway counts as zero", 5, None, -3600, "not valid yet"),
]


@pytest.mark.parametrize("fmt", ["jwt", "jose"])
@pytest.mark.parametrize("name,vf,vu,lw,want", LEEWAY)
def test_with_leeway(fmt, name, vf, vu, lw, want):
    from credential.vc.jose_credential import JOSECredential

    cls = JWTCredential if fmt == "jwt" else JOSECredential
    did = "did:example:vc-leeway"
    prov, vm, res = p256_setup(did)
    c = contents(did)
    c.valid_from = NOW() + timedelta(seconds=vf)
    c.valid_until = NOW() + timedelta(seconds=vu) if vu is not None else None
    cred = cls.create(c, with_verification_method_key("key-1"), with_resolver(res))
    cred.add_proof_by_provider(prov)
    opts = (with_resolver(res), with_verify_proof(), with_check_expiration(), with_leeway(timedelta(seconds=lw)))
    if want is None:
        cls.parse(cred.serialize(), *opts)
    else:
        with pytest.raises(ValueError, match=want):
            cls.parse(cred.serialize(), *opts)


# ---- revoked_vm_test.go (jwt path) ----------------------------------------------
def _rotated(did, pub):
    old = new_p256_vm(did, "key-1", pub)
    old.revoked = NOW() - timedelta(hours=1)
    return StaticResolver([new_did_document(did, [old, new_p256_vm(did, "key-2", pub)])])


def test_revoked_vm_at_signing():
    did = "did:example:vc-rotated"
    prov, pub = p256_pair()
    res = _rotated(did, pub)

    cred = JWTCredential.create(contents(did), with_resolver(res))
    cred.add_proof_by_provider(prov)
    cred.verify(with_resolver(res))  # default skips revoked key-1

    with pytest.raises(ValueError, match="was revoked at"):
        JWTCredential.create(contents(did), with_resolver(res), with_verification_method_key("key-1"))

    cred = JWTCredential.create(contents(did), with_resolver(res), with_verification_method_key("key-2"))
    cred.add_proof_by_provider(prov)
    cred.verify(with_resolver(res))


# ---- sign_options_test.go (JWT paths) -------------------------------------------
class Counting:
    def __init__(self, inner):
        self.inner, self.calls = inner, 0

    def sign(self, d):
        self.calls += 1
        return self.inner.sign(d)


@pytest.mark.parametrize("path", ["provider", "custom"])
def test_verify_option_does_not_block_correct_signature(path):
    did = "did:example:sign-opts"
    res, secp, p256 = dual(did)
    cred = JWTCredential.create(contents(did), with_resolver(res))
    if path == "provider":
        cred.add_proof_by_provider(p256, with_verify_proof(), with_resolver(res))
    else:
        cred.add_custom_proof(Proof(signature=sign_outside(p256, cred.get_signing_input())), with_verify_proof(), with_resolver(res))
    cred.verify(with_resolver(res))


@pytest.mark.parametrize("path", ["provider", "custom"])
def test_content_options_run_before_signing(path):
    did = "did:example:sign-opts"
    res, secp, p256 = dual(did)
    c = contents(did)
    c.valid_from = NOW() + timedelta(hours=1)
    cred = JWTCredential.create(c, with_resolver(res))
    s = Counting(p256)
    want_calls = 0
    with pytest.raises(ValueError, match="not valid yet"):
        if path == "provider":
            cred.add_proof_by_provider(s, with_check_expiration())
        else:
            raw = sign_outside(s, cred.get_signing_input())
            want_calls = 1
            cred.add_custom_proof(Proof(signature=raw), with_check_expiration())
    assert s.calls == want_calls
    with pytest.raises(ValueError):
        cred.hash()


BUILD_OPTS = [
    ("vm", lambda: with_verification_method_key("key-2"), "WithVerificationMethodKey cannot be applied when signing a JWT"),
    ("paths", lambda: with_sd_selective_paths(["credentialSubject.name"]), "SD-JWT options cannot be applied when signing"),
    ("disclosures", lambda: with_sd_disclosures(["WyJzYWx0IiwibmFtZSIsIkEiXQ"]), "SD-JWT options cannot be applied when signing"),
    ("alg", lambda: with_sd_hash_algorithm("sha-256"), "SD-JWT options cannot be applied when signing"),
    ("shuffle", lambda: with_sd_shuffle(True), "SD-JWT options cannot be applied when signing"),
    ("decoys", lambda: with_sd_decoy_digests([Decoy()]), "SD-JWT options cannot be applied when signing"),
]


@pytest.mark.parametrize("via", ["provider", "custom"])
@pytest.mark.parametrize("name,opt,want", BUILD_OPTS)
def test_signing_refuses_build_time_options(via, name, opt, want):
    did = "did:example:sign-opts"
    res, secp, p256 = dual(did)
    cred = JWTCredential.create(contents(did), with_resolver(res))
    s = Counting(p256)
    with pytest.raises(ValueError, match=want):
        if via == "provider":
            cred.add_proof_by_provider(s, opt())
        else:
            cred.add_custom_proof(Proof(signature=sign_outside(s, cred.get_signing_input())), opt())
    assert s.calls == (1 if via == "custom" else 0)
    with pytest.raises(ValueError):
        cred.hash()


# ---- signing_atomicity_test.go: refuse to replace -------------------------------
@pytest.mark.parametrize("fmt", ["jwt", "jose"])
def test_refuses_to_replace_a_signature(fmt):
    from credential.vc.jose_credential import JOSECredential

    cls = JWTCredential if fmt == "jwt" else JOSECredential
    did = "did:example:signing-atomicity"
    prov, vm, res = p256_setup(did)
    cred = cls.create(jose_contents(did), with_verification_method_key("key-1"), with_resolver(res))
    cred.add_proof_by_provider(prov, with_resolver(res))
    first = cred.hash()
    with pytest.raises(ValueError, match="already signed"):
        cred.add_proof_by_provider(prov, with_resolver(res))
    assert cred.hash() == first
    cred.add_proof_by_provider(prov, with_resolver(res), with_replace_proof())
    cred.verify(with_resolver(res))
    assert cred.hash() != first


def test_signer_key_must_match_vm_jwt():
    did = "did:example:vm-match"
    prov, _ = p256_pair()
    _, _, res = p256_setup(did)  # DID publishes a different P-256 key
    cred = JWTCredential.create(contents(did), with_resolver(res), with_verification_method_key("key-1"))
    with pytest.raises(ValueError, match="does not verify against verification method"):
        cred.add_proof_by_provider(prov)
    with pytest.raises(ValueError):
        cred.hash()


def test_external_signing_flow_jwt():
    did = "did:example:ext"
    prov, vm, res = p256_setup(did)
    cred = JWTCredential.create(contents(did), with_resolver(res))
    cred.add_custom_proof(Proof(signature=sign_outside(prov, cred.get_signing_input())))
    cred.verify(with_resolver(res))
    with pytest.raises(ValueError, match="proof signature cannot be empty"):
        JWTCredential.create(contents(did), with_resolver(res)).add_custom_proof(Proof())
    with pytest.raises(ValueError, match="proof cannot be nil"):
        JWTCredential.create(contents(did), with_resolver(res)).add_custom_proof(None)


# ---- vc11_sdjwt_refused_test.go -------------------------------------------------
V1131_PLAIN = (
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAja2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3NjcyMjU2MDAsImlzcyI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAiLCJqdGkiOiJ1cm46dXVpZDpmaXh0dXJlLTEwMCIsIm5iZiI6MTc2NzIyNTYwMCwic3ViIjoiZGlkOmV4YW1wbGU6c3ViamVjdCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImJsb29kVHlwZSI6Ik8tIiwiaWQiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwibmFtZSI6IkFsaWNlIn0sImlkIjoidXJuOnV1aWQ6Zml4dHVyZS0xMDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTppc3N1ZXItMTAwIiwidHlwZSI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwidmFsaWRGcm9tIjoiMjAyNi0wMS0wMVQwMDowMDowMFoifX0"
)
V1131_SDJWT = (
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAja2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3NjcyMjU2MDAsImlzcyI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAiLCJqdGkiOiJ1cm46dXVpZDpmaXh0dXJlLTEwMCIsIm5iZiI6MTc2NzIyNTYwMCwic3ViIjoiZGlkOmV4YW1wbGU6c3ViamVjdCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIm1IQUNvTWRXWlNRVlR0VzRUaWZaZmxjdFFmdXpGV0J5djdHakRLc1NBVmsiXSwiaWQiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwibmFtZSI6IkFsaWNlIn0sImlkIjoidXJuOnV1aWQ6Zml4dHVyZS0xMDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTppc3N1ZXItMTAwIiwidHlwZSI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwidmFsaWRGcm9tIjoiMjAyNi0wMS0wMVQwMDowMDowMFoifX0.sxJUM-F2eqllXcqIxOk3uJAmW8WWxA1yaR11zuZ6m8Arh5_BD-3X_z-eKU8xdLkaGVhsuc8f2Pvxw9Zbh-1k9w~WyJnU1dreU9MZW1TSDFhcnFfZWpWWG13IiwiYmxvb2RUeXBlIiwiTy0iXQ~"
)
FIX_DID = "did:example:issuer-100"
SDJWT_ERR = r"selective disclosure is supported only as vc\+sd-jwt"


def _fixture():
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    d = int("6f2e3a8c1b9d4e7f0a1c2b3d4e5f60718293a4b5c6d7e8f90112233445566778", 16)
    k = _ec.derive_private_key(d, _ec.SECP256R1())
    prov = P256Provider(d.to_bytes(32, "big"))
    vm = new_p256_multikey_vm(FIX_DID, "key-1", k.public_key())
    c = vc11_contents(FIX_DID)
    c.id = "urn:uuid:fixture-100"
    c.types = ["VerifiableCredential"]
    c.valid_from = datetime(2026, 1, 1, tzinfo=timezone.utc)
    c.subject[0].custom_fields = {"name": "Alice", "bloodType": "O-"}
    return prov, StaticResolver([new_did_document(FIX_DID, [vm])]), c


class CountingResolver:
    def __init__(self, inner):
        self.inner, self.calls = inner, 0

    def resolve_document(self, did):
        self.calls += 1
        return self.inner.resolve_document(did)


@pytest.mark.parametrize(
    "opt",
    [
        lambda: with_sd_selective_paths(["credentialSubject.bloodType"]),
        lambda: with_sd_disclosures(["WyJzYWx0IiwibmFtZSIsIkEiXQ"]),
        lambda: with_sd_decoy_digests([Decoy(path="credentialSubject", count=1)]),
        lambda: with_sd_hash_algorithm("sha-256"),
        lambda: with_sd_shuffle(True),
    ],
)
def test_vc11_new_refuses_sd_options_before_resolving(opt):
    _, res, c = _fixture()
    r = CountingResolver(res)
    with pytest.raises(ValueError, match=SDJWT_ERR):
        JWTCredential.create(c, with_verification_method_key("key-1"), with_resolver(r), opt())
    assert r.calls == 0


def test_vc11_new_refuses_contents_carrying_digests():
    from credential.common import sdjwt

    res_ = sdjwt.build_disclosures(
        {"credentialSubject": {"id": "did:example:subject", "name": "Alice", "bloodType": "O-",
                               "emails": ["a@example.com", "b@example.com"]}},
        ["credentialSubject.bloodType", "credentialSubject.emails[1]"],
    )
    processed = res_["processed_vc"]["credentialSubject"]
    for custom in ({"name": "Alice", "_sd": processed["_sd"]}, {"emails": processed["emails"]}):
        _, res, c = _fixture()
        c.subject = [Subject(id="did:example:subject", custom_fields=custom)]
        r = CountingResolver(res)
        with pytest.raises(ValueError, match=SDJWT_ERR):
            JWTCredential.create(c, with_verification_method_key("key-1"), with_resolver(r))
        assert r.calls == 0


def test_vc11_plain_jwt_is_unchanged_since_v1131():
    prov, res, c = _fixture()
    cred = JWTCredential.create(c, with_verification_method_key("key-1"), with_resolver(res))
    assert cred.signing_input == V1131_PLAIN  # byte-identical to what the Go SDK built
    cred.add_proof_by_provider(prov)
    parsed = parse_credential(cred.serialize(), with_resolver(res))
    parsed.verify(with_resolver(res))


def test_vc11_sdjwt_from_v1131_is_refused():
    with pytest.raises(ValueError, match=SDJWT_ERR):
        JWTCredential.parse(V1131_SDJWT)
    with pytest.raises(ValueError, match=SDJWT_ERR):
        parse_credential(V1131_SDJWT)


@pytest.mark.parametrize("where", ["root", "inside_vc"])
def test_vc11_sd_alg_refused_wherever_it_sits(where):
    prov, res, _ = _fixture()
    vc_claim = {"@context": [V1], "type": ["VerifiableCredential"], "issuer": FIX_DID,
                "issuanceDate": "2026-01-01T00:00:00Z", "credentialSubject": {"id": "did:example:subject", "name": "Alice"}}
    payload = {"iss": FIX_DID, "vc": vc_claim}
    if where == "root":
        payload["_sd_alg"] = "sha-256"
    else:
        vc_claim["_sd_alg"] = "sha-256"
    si = signing_input({"typ": "JWT", "alg": "ES256", "kid": FIX_DID + "#key-1"}, payload)
    with pytest.raises(ValueError, match=SDJWT_ERR):
        parse_credential(si + "." + sign_input(prov, si))


def test_vc11_decoded_disclosures_and_present():
    prov, res, c = _fixture()
    cred = JWTCredential.create(c, with_verification_method_key("key-1"), with_resolver(res))
    cred.add_proof_by_provider(prov)
    assert cred.decoded_disclosures() == []
    with pytest.raises(ValueError, match=SDJWT_ERR):
        cred.present(None)
