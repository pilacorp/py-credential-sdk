"""Go: digitalcredential/present_test.go."""

from datetime import timedelta

import pytest

from digitalcredential.credential import compact_sd_jwt, parse
from digitalcredential.errors import ErrKeyBindingUnsupported, errors_is
from digitalcredential.issue import issue
from digitalcredential.present import KeyBinding, PresentRequest
from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrMalformed, ErrUnsupportedKey
from jose.jwk import jwk as jose_jwk
from jose.jws import errors as jws_errors
from jose.jws import jws as jose_jws
from jose.jws import private_key_signer
from jose.sdjwt import KBVerifyParams, conceal, parse_disclosure, sd_hash, split, verify_kb_jwt

from dc_helpers import TESTDATA, new_key, test_key, test_request, unix

BAD_KEY = (jws_errors.ErrBadKey, jose_jwk.ErrBadKey)


def disclosure_names(c) -> list[str]:
    """The claim name of each disclosure c sends, or "[]" for an array element."""
    _, encoded, _ = split(c.serialize())
    names = []
    for e in encoded:
        d = parse_disclosure(e)
        names.append("[]" if d.array_element else d.name)
    return names


def test_present_a1():
    # TC-16, TC-17: the issued PID of draft-ietf-oauth-sd-jwt-vc-19 Appendix A.1 (Figure 24).
    # age_equal_or_over is a concealed object holding a concealed "18"; nationalities is a
    # concealed array whose elements are not.
    cred = parse((TESTDATA / "draft-ietf-oauth-sd-jwt-vc-19-A.1-figure24.txt").read_text().strip())
    issuer_jwt, _, _ = split(cred.serialize())
    for name, reveal, want in [
        # RFC 9901 §4.2.6: a nested claim goes with its parent's disclosure.
        ("a nested claim", [["age_equal_or_over", "18"]], ["18", "age_equal_or_over"]),
        ("nothing", [], []),
        ("one claim named twice", [["given_name"], ["given_name"]], ["given_name"]),
        # OpenID4VP 1.0 §7.1.1: null selects every element of the array.
        ("all elements of an array", [["nationalities", None]], ["nationalities"]),
        # address and its locality are both concealed.
        ("a concealed claim in a concealed object", [["address", "locality"]], ["locality", "address"]),
    ]:
        got = cred.present(PresentRequest(reveal=reveal))
        assert disclosure_names(got) == want, name
        assert got.serialize().startswith(issuer_jwt + "~") and got.serialize().endswith("~"), name
    for name, p in {
        "empty path": [],
        "absent claim": ["family_name_birth"],
        "key into a string element": ["nationalities", None, "x"],
        "null on an object": ["age_equal_or_over", None],
        "index past the end": ["nationalities", 5],
        "negative index": ["nationalities", -1],
        "a float component": ["nationalities", 1.0],
        "index on an object": ["address", 0],
        "key into a top-level array member": ["nationalities", 0, "x"],
    }.items():
        with pytest.raises(ErrInvalidArgument) as ei:
            cred.present(PresentRequest(reveal=[p]))
        assert not errors_is(ei.value, ErrMalformed), name


def test_present_concealed_array():
    # TC-17: null over an array whose elements are concealed sends the array's disclosure and every
    # element's; an index sends one element's.
    req = test_request()
    req.claims["degrees"] = [{"type": "BSc"}, {"name": "Hanoi University"}]
    req.claims["mixed"] = [{"type": "BSc"}, "BA", ["MSc"]]
    req.disclose = [["nationalities"], ["nationalities", 0], ["nationalities", 1], ["nationalities", 2], ["degrees", 0], ["degrees", 1]]
    cred = issue(req, test_key())
    for reveal, want in [
        (["nationalities", None], 4),
        (["nationalities", 1], 2),
        (["nationalities"], 1),
        # OpenID4VP 1.0 §7.1.1: the second degree has no type, so it drops out and only the first
        # one's disclosure goes.
        (["degrees", None, "type"], 1),
    ]:
        got = cred.present(PresentRequest(reveal=[reveal]))
        assert len(disclosure_names(got)) == want, reveal
    # The element an index names is the one sent: VN, FR, US in order.
    for i, want in enumerate(["VN", "FR", "US"]):
        got = cred.present(PresentRequest(reveal=[["nationalities", i]]))
        _, encoded, _ = split(got.serialize())
        values = [d.value for d in map(parse_disclosure, encoded) if d.array_element]
        assert values == [want], i
    # OpenID4VP 1.0 §7.1.1: one selected element of the wrong type aborts the selection, even when
    # the others fit.
    for p in (["mixed", None, "type"], ["mixed", None, None], ["mixed", None, 0]):
        with pytest.raises(ErrInvalidArgument):
            cred.present(PresentRequest(reveal=[p]))


def test_present_key_binding():
    # TC-18: the Key Binding JWT signs exactly the SD-JWT sent before it (RFC 9901 §4.3.1), with
    # the key of cnf.jwk.
    holder = new_key()
    signer = private_key_signer(holder)
    req = test_request()
    req.holder_key = holder.public_key()
    # address is concealed and not presented, so the SD-JWT sent differs from the one issued.
    req.disclose = [["given_name"], ["address"]]
    cred = issue(req, test_key())
    iat = unix(1700000500)
    kb = KeyBinding(signer=signer, audience="https://verifier.example", nonce="n-0S6_WzA2Mj", issued_at=iat)
    reveal = [["given_name"]]

    bare = cred.present(PresentRequest(reveal=reveal))
    assert split(bare.serialize())[2] == "", "KeyBinding nil wrote a Key Binding JWT"
    bound = cred.present(PresentRequest(reveal=reveal, key_binding=kb))
    assert bound.serialize().startswith(bare.serialize())
    kb_jwt = bound.serialize()[len(bare.serialize()) :]
    assert kb_jwt
    verify_kb_jwt(
        kb_jwt,
        holder.public_key(),
        KBVerifyParams(
            audience=kb.audience,
            nonce=kb.nonce,
            sd_hash=sd_hash(bare.serialize()),
            now=iat,
            max_age_seconds=60,
        ),
    )
    # RFC 9901 §7.2: a Holder MUST reject an SD-JWT+KB.
    again = parse(bound.serialize())
    with pytest.raises(ErrMalformed):
        again.present(PresentRequest())

    wrong = private_key_signer(new_key())
    for name, mutate, want in [
        ("a Signer of another key", lambda k: setattr(k, "signer", wrong), jws_errors.ErrSelfCheck),
        ("no Audience", lambda k: setattr(k, "audience", ""), ErrInvalidArgument),
        ("Claims holding sd_hash", lambda k: setattr(k, "claims", {"sd_hash": "x"}), ErrInvalidArgument),
    ]:
        k = KeyBinding(signer=kb.signer, audience=kb.audience, nonce=kb.nonce, issued_at=kb.issued_at)
        mutate(k)
        with pytest.raises(want):
            cred.present(PresentRequest(reveal=reveal, key_binding=k))


def signed_credential(payload: dict, disclosures=None):
    """Sign payload as an Issuer-signed JWT with a test key and parse it with disclosures: a
    credential issue would not write."""
    key = test_key()
    body = jose_json.encode_json(payload)
    issuer_jwt = jose_jws.sign(object(), key.signer, key.public, {"typ": "dc+sd-jwt"}, body)
    return parse(compact_sd_jwt(issuer_jwt, disclosures or []))


def test_present_key_binding_cnf():
    # TC-18: what cnf holds decides the error class, and each error matches exactly one of the three.
    holder = new_key()
    signer = private_key_signer(holder)
    jwk_p256 = jose_jwk.from_public_key(holder.public_key())
    kb = KeyBinding(signer=signer, audience="https://verifier.example", nonce="n", issued_at=unix(1700000500))
    classes = [ErrInvalidArgument, ErrKeyBindingUnsupported, ErrMalformed]
    cases = [
        ("no cnf", None, [ErrInvalidArgument]),
        ("cnf with kid only", {"kid": "holder-1"}, [ErrKeyBindingUnsupported]),
        # RFC 8037 OKP: a key type jose/jwk does not convert.
        (
            "Ed25519 cnf.jwk",
            {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
            [ErrKeyBindingUnsupported, ErrUnsupportedKey],
        ),
        # RFC 7800 §3.1: one proof-of-possession key.
        ("jwk and jku", {"jwk": jwk_p256, "jku": "https://holder.example/jwks"}, [ErrMalformed]),
        # RFC 7800 §3.2: no symmetric key in a JWS.
        (
            "symmetric cnf.jwk",
            {"jwk": {"kty": "oct", "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}},
            [ErrMalformed, BAD_KEY],
        ),
        ("cnf a string", "holder-1", [ErrMalformed, BAD_KEY]),
        ("cnf.jwk a string", {"jwk": "holder-1"}, [ErrMalformed, BAD_KEY]),
        (
            "cnf.jwk off the curve",
            {"jwk": {"kty": "EC", "crv": "P-256", "x": jwk_p256["x"], "y": jwk_p256["x"]}},
            [ErrMalformed, BAD_KEY],
        ),
    ]
    for name, cnf, want in cases:
        # Issue refuses the malformed ones, so every credential is signed here, as one from another issuer.
        claims = {"iss": "https://issuer.example", "vct": "urn:example:pid"}
        if cnf is not None:
            claims["cnf"] = cnf
        with pytest.raises(Exception) as ei:
            signed_credential(claims).present(PresentRequest(key_binding=kb))
        err = ei.value
        for w in want:
            assert errors_is(err, *(w if isinstance(w, tuple) else (w,))), f"{name}: {err!r} want {w}"
        n = sum(1 for c in classes if errors_is(err, c))
        assert n == 1, f"{name}: {err!r} matches {n} of the three classes, want 1"


def test_present_concealed_cnf():
    # TC-18: draft 19 §2.2.2.3 forbids cnf and its sub-claims in a disclosure; Issue never writes
    # one, so the credential is built with jose directly.
    holder = new_key()
    signer = private_key_signer(holder)
    jwk_p256 = jose_jwk.from_public_key(holder.public_key())
    kb = KeyBinding(signer=signer, audience="https://verifier.example", nonce="n", issued_at=unix(1700000500))
    with_kid = dict(jwk_p256, kid="holder-1")
    for cnf, conc in [
        ({"jwk": jwk_p256}, ["cnf"]),
        ({"jwk": jwk_p256}, ["cnf", "jwk"]),
        ({"jwk": jwk_p256, "jku": "https://holder.example/jwks"}, ["cnf", "jku"]),
        ({"jwk": with_kid}, ["cnf", "jwk", "kid"]),
    ]:
        claims = {"iss": "https://issuer.example", "vct": "urn:example:pid", "cnf": cnf}
        payload, ds = conceal(claims, [conc])
        with pytest.raises(ErrMalformed) as ei:
            signed_credential(payload, ds).present(PresentRequest(key_binding=kb))
        assert not errors_is(ei.value, ErrKeyBindingUnsupported, ErrInvalidArgument), conc


def test_present_over_limit():
    # TC-36: Issue signs what Present cannot read back; Present keeps the 1 MiB limit of sdjwt.split.
    req = test_request()
    req.claims["photo"] = "A" * (1 << 20)
    cred = issue(req, test_key())
    with pytest.raises(ErrMalformed):
        cred.present(PresentRequest())
