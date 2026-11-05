"""Port of Go sdjwt_integrity_test.go (vc+sd-jwt via JOSECredential / parse_credential)."""
import http.server
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest
from jwtvc_kit import V1, V2, b64, header_of, jose_contents, p256_setup, sign_input, signing_input

from credential.common.dto.proof import Proof
from credential.common.jwt import JWTVerifier
from credential.common.sdjwt import b64url_decode  # noqa: F401
from credential.common.util.compress import compress_to_base64url
from credential.vc.credential import (
    Decoy, parse_credential, with_check_revocation, with_resolver, with_sd_decoy_digests, with_sd_disclosures,
    with_sd_selective_paths, with_verification_method_key,
)
from credential.vc.jose_credential import JOSECredential

import hashlib


def digest_of(d: str) -> str:
    return b64(hashlib.sha256(d.encode()).digest())


def raw_disclosure(salt, name, value) -> str:
    return b64(json.dumps([salt, name, value], separators=(",", ":")).encode())


def sign_by_hand(prov, typ, kid, payload) -> str:
    si = signing_input({"typ": typ, "alg": "ES256", "kid": kid}, payload)
    return si + "." + sign_input(prov, si)


def sd_cred(did, paths=("credentialSubject.bloodType",), **kw):
    prov, vm, res = p256_setup(did)
    c = jose_contents(did)
    c.subject[0].custom_fields = {"name": "Alice", "bloodType": "O-"}
    cred = JOSECredential.create(c, with_sd_selective_paths(list(paths)), with_verification_method_key("key-1"), with_resolver(res), **kw)
    cred.add_proof_by_provider(prov, with_resolver(res))
    return cred, prov, res


def test_disclosure_list_integrity():
    cred, prov, res = sd_cred("did:example:sd-integrity")
    token = cred.serialize()
    cut = token.index("~")
    base, real = token[:cut], token[cut:].strip("~")
    fake = b64(json.dumps(["c2FsdA", "bloodType", "A+"], separators=(",", ":")).encode())
    kb = b64(b'{"typ":"kb+jwt","alg":"ES256"}') + "." + b64(b'{"nonce":"n","aud":"a"}') + ".c2ln"
    cases = [
        (token, None), (base + "~", None),
        (base + "~" + fake + "~", "matches nothing in the payload"),
        (base + "~" + real + "~" + fake + "~", "matches nothing in the payload"),
        (base + "~" + real + "~" + real + "~", "sent more than once"),
        (base + "~" + real + "~" + kb, "key binding JWT"),
    ]
    for tok, want in cases:
        if want:
            with pytest.raises(ValueError, match=want):
                parse_credential(tok, with_resolver(res))
        else:
            parse_credential(tok, with_resolver(res)).verify(with_resolver(res))


@pytest.mark.parametrize("suffix_fn", [lambda b: b + "~", lambda b: b])
def test_revealing_nothing_still_folds_out_digests(suffix_fn):
    cred, prov, res = sd_cred("did:example:sd-reveal-nothing")
    token = cred.serialize()
    base = token[: token.index("~")]
    parsed = parse_credential(suffix_fn(base), with_resolver(res))
    parsed.verify(with_resolver(res))
    m = json.loads(parsed.get_contents())
    assert "_sd_alg" not in m
    assert "_sd" not in m["credentialSubject"] and "bloodType" not in m["credentialSubject"]
    assert m["credentialSubject"]["name"] == "Alice"


def test_present_keeps_the_token_an_sdjwt():
    cred, prov, res = sd_cred("did:example:sd-present-shape")
    presented = cred.present(None)
    assert presented.serialize().endswith("~")
    assert header_of(presented.serialize())["typ"] == "vc+sd-jwt"
    plain_prov, vm, plain_res = p256_setup("did:example:sd-present-plain")
    plain = JOSECredential.create(jose_contents("did:example:sd-present-plain"), with_verification_method_key("key-1"), with_resolver(plain_res))
    plain.add_proof_by_provider(plain_prov, with_resolver(plain_res))
    with pytest.raises(ValueError, match="nothing to present selectively"):
        plain.present(None)


def test_decoys_alone_still_make_it_an_sdjwt():
    did = "did:example:sd-decoys-only"
    prov, vm, res = p256_setup(did)
    c = jose_contents(did)
    c.subject[0].custom_fields = {"name": "Alice"}
    cred = JOSECredential.create(c, with_sd_decoy_digests([Decoy(path="credentialSubject", count=2)]),
                                 with_verification_method_key("key-1"), with_resolver(res))
    cred.add_proof_by_provider(prov, with_resolver(res))
    assert header_of(cred.serialize())["typ"] == "vc+sd-jwt"
    token = cred.serialize()
    assert token.endswith("~")
    back = parse_credential(token, with_resolver(res))
    back.verify(with_resolver(res))
    assert back.serialize() == token and back.hash() == cred.hash()
    m = json.loads(back.get_contents())
    assert "_sd_alg" not in m and "_sd" not in m["credentialSubject"] and m["credentialSubject"]["name"] == "Alice"


DISC = raw_disclosure("c2FsdDAxc2FsdDAxc2FsdDAx", "bloodType", "O-")


def _payload(did, with_alg):
    m = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did, "validFrom": "2026-01-01T00:00:00Z",
         "credentialSubject": {"id": "did:example:subject", "name": "Alice", "_sd": [digest_of(DISC)]}}
    if with_alg:
        m["_sd_alg"] = "sha-256"
    return m


@pytest.mark.parametrize(
    "typ,suffix,reveals",
    [("vc+sd-jwt", "~" + DISC + "~", True), ("vc+sd-jwt", "~", False), ("vc+sd-jwt", "", False),
     ("application/vc+sd-jwt", "~" + DISC + "~", True)],
)
def test_format_read_from_media_type_not_sd_alg(typ, suffix, reveals):
    did = "did:example:sd-marker"
    prov, vm, res = p256_setup(did)
    token = sign_by_hand(prov, typ, did + "#key-1", _payload(did, False)) + suffix
    cred = parse_credential(token, with_resolver(res))
    cred.verify(with_resolver(res))
    subj = cred.extract_field("credentialSubject")
    assert "_sd" not in subj
    assert (subj.get("bloodType") == "O-") == reveals
    out = cred.serialize()
    assert out.endswith("~")
    back = parse_credential(out, with_resolver(res))
    assert back.serialize() == out and back.hash() == cred.hash()


@pytest.mark.parametrize("with_alg,suffix", [(False, "~" + DISC + "~"), (True, "")])
def test_vc_jwt_must_not_carry_sdjwt_format(with_alg, suffix):
    did = "did:example:sd-marker"
    prov, vm, res = p256_setup(did)
    token = sign_by_hand(prov, "vc+jwt", did + "#key-1", _payload(did, with_alg)) + suffix
    with pytest.raises(ValueError, match="does not match the SD-JWT format"):
        parse_credential(token, with_resolver(res))


@pytest.mark.parametrize("suffix", ["~" + DISC + "~", "~", ""])
def test_vc11_with_digests_refused(suffix):
    did = "did:example:sd-marker"
    prov, vm, res = p256_setup(did)
    inner = {"@context": [V1], "type": ["VerifiableCredential"], "issuer": did, "issuanceDate": "2026-01-01T00:00:00Z",
             "credentialSubject": {"id": "did:example:subject", "_sd": [digest_of(DISC)]}}
    token = sign_by_hand(prov, "JWT", did + "#key-1", {"iss": did, "vc": inner}) + suffix
    with pytest.raises(ValueError, match=r"selective disclosure is supported only as vc\+sd-jwt"):
        parse_credential(token, with_resolver(res))


class _Status(http.server.BaseHTTPRequestHandler):
    encoded = ""

    def do_GET(self):
        body = json.dumps({"data": {"credentialSubject": {"statusPurpose": "revocation", "encodedList": self.encoded}}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def status_server():
    bits = bytearray(16)
    bits[7 // 8] |= 1 << (7 % 8)
    _Status.encoded = compress_to_base64url(bytes(bits))
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Status)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_sd_is_confined_to_the_subject(status_server):
    did = "did:example:sd-confine"
    prov, vm, res = p256_setup(did)
    status = [
        raw_disclosure("c2FsdDAwc2FsdDAwc2FsdDAw", "type", "BitstringStatusListEntry"),
        raw_disclosure("c2FsdDExc2FsdDExc2FsdDEx", "statusListCredential", status_server + "/status/1"),
        raw_disclosure("c2FsdDIyc2FsdDIyc2FsdDIy", "statusListIndex", "7"),
        raw_disclosure("c2FsdDMzc2FsdDMzc2FsdDMz", "statusPurpose", "revocation"),
    ]
    hidden = {"_sd": [digest_of(d) for d in status]}
    withheld = raw_disclosure("c2FsdDk5c2FsdDk5c2FsdDk5", "validUntil", "2020-01-01T00:00:00Z")

    def payload(extra):
        return {"@context": [V2], "id": "urn:uuid:sd-confine", "type": ["VerifiableCredential"], "issuer": did,
                "validFrom": "2026-01-01T00:00:00Z", "credentialSubject": {"id": "did:example:subject", "name": "Alice"},
                "_sd_alg": "sha-256", **extra}

    base = sign_by_hand(prov, "vc+sd-jwt", did + "#key-1", payload({"credentialStatus": hidden}))
    for tok in (base + "~" + "~".join(status) + "~", base + "~"):
        with pytest.raises(ValueError, match='not permitted in "credentialStatus"'):
            parse_credential(tok, with_resolver(res))

    cases = [
        ({"_sd": [digest_of(withheld)]}, "carries _sd at the root"),
        ({"termsOfUse": {"type": "TrustFrameworkPolicy", "_sd": [digest_of(withheld)]}}, 'not permitted in "termsOfUse"'),
        ({"evidence": {"verification": {"_sd": [digest_of(withheld)]}}}, 'not permitted in "evidence"'),
        ({"termsOfUse": [{"...": digest_of(withheld)}]}, 'not permitted in "termsOfUse"'),
    ]
    for extra, want in cases:
        tok = sign_by_hand(prov, "vc+sd-jwt", did + "#key-1", payload(extra)) + "~"
        with pytest.raises(ValueError, match=want):
            parse_credential(tok, with_resolver(res))

    tok = sign_by_hand(prov, "vc+jwt", did + "#key-1", {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": did, "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:subject", "_sd": [digest_of(withheld)]}})
    with pytest.raises(ValueError, match='not permitted in "credentialSubject"'):
        parse_credential(tok, with_resolver(res))

    blood = raw_disclosure("c2FsZEJCc2FsZEJCc2FsZEJC", "bloodType", "O-")
    tok = sign_by_hand(prov, "vc+sd-jwt", did + "#key-1", {
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": did, "validFrom": "2026-01-01T00:00:00Z",
        "_sd_alg": "sha-256", "credentialSubject": {"id": "did:example:subject", "name": "Alice", "_sd": [digest_of(blood)]}}) + "~" + blood + "~"
    cred = parse_credential(tok, with_resolver(res))
    cred.verify(with_resolver(res))
    assert cred.extract_field("credentialSubject")["bloodType"] == "O-"


def test_prebuilt_disclosures_are_validated_not_refused():
    from credential.common import sdjwt

    did = "did:example:sd-prebuilt"
    prov, vm, res = p256_setup(did)
    built = sdjwt.build_disclosures({"credentialSubject": {"id": "did:example:subject", "name": "Alice", "bloodType": "O-"}},
                                    ["credentialSubject.bloodType"])
    c = jose_contents(did)
    c.subject[0].custom_fields = {k: v for k, v in built["processed_vc"]["credentialSubject"].items() if k != "id"}
    cred = JOSECredential.create(c, with_sd_disclosures(built["disclosures"]), with_verification_method_key("key-1"), with_resolver(res))
    cred.add_proof_by_provider(prov, with_resolver(res))
    assert header_of(cred.serialize())["typ"] == "vc+sd-jwt"
    parse_credential(cred.serialize(), with_resolver(res)).verify(with_resolver(res))
    # a disclosure matching no digest is refused at build time
    with pytest.raises(ValueError, match="invalid SD-JWT disclosures"):
        JOSECredential.create(c, with_sd_disclosures([built["disclosures"][0], raw_disclosure("c2FsdA", "x", 1)]),
                              with_verification_method_key("key-1"), with_resolver(res))
