"""Go: digitalcredential/verify_test.go (the context-cancellation and TLS issuer-metadata tests have
no Python counterpart: Verify takes no context here, and issuermeta is covered in its own tests)."""

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from digitalcredential import errors as E
from digitalcredential.errors import DigitalCredentialError, ErrKeyBindingUnsupported, ErrPolicy, code_of, errors_is
from digitalcredential.issue import issue
from digitalcredential.issuerkey import ErrIssuerNotSupported, ErrNoUsableKey, PublicKey
from digitalcredential.present import KeyBinding, PresentRequest
from digitalcredential.verify_options import (
    KeyBindingMode,
    with_accepted_issuers,
    with_accepted_status,
    with_allowed_algs,
    with_clock_skew,
    with_credential_audience,
    with_ignore_unchecked_kb_jwt,
    with_key_binding,
    with_max_kb_age,
    with_now,
    with_status,
    without_status_check,
)
from jose import base64 as jose_b64
from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrUnsupportedAlg, ErrUnsupportedKey
from jose.jws import errors as jws_errors
from jose.jws import private_key_signer
from jose.sdjwt import split

from dc_helpers import (
    DRAFT19_FIG8,
    DRAFT19_FIG10,
    FailingResolver,
    FixedStatus,
    KeysOf,
    RecordingStatus,
    Ref,
    Setting,
    draft19_key,
    draft19_setting,
    new_key,
    own_credentials,
    split_jws,
    test_key,
    test_request,
    unix,
)

ISS = "https://example.com/issuer"
KID = "doc-signer-05-25-2022"
UNREACHABLE = ConnectionRefusedError("connection refused")


def test_verify_draft19_example():
    # TC-19: draft 19 §2.3.2, Figure 8 verifies, the processed payload is Figure 9, and the claims
    # of its Key Binding JWT come back only when that KB-JWT is checked.
    s = draft19_setting()
    got = s.verify(DRAFT19_FIG8)
    fig9 = jose_json.decode_json_object(
        b"""{
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "vct": "https://credentials.example.com/identity_credential",
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}},
        "is_over_65": true,
        "address": {"street_address": "123 Main St", "locality": "Anytown",
            "region": "Anystate", "country": "US"}
    }"""
    )
    assert jose_json.encode_json(got.claims) == jose_json.encode_json(fig9)
    assert got.key_bound and got.status is None and not got.status_skipped
    assert got.issuer == ISS
    assert got.vct == "https://credentials.example.com/identity_credential"
    assert got.aka_vcts is None
    assert got.key_binding_claims["aud"] == "https://example.com/verifier"
    assert got.key_binding_claims["nonce"] == "1234567890"
    s.extra = [with_accepted_issuers("https://other.example", ISS)]
    s.verify(DRAFT19_FIG8)

    # RFC 9901 §7.2, §4: a KB-JWT that is not checked is rejected, unless the caller ignores it;
    # then none of its claims may come back.
    s.extra = [with_key_binding(KeyBindingMode.NOT_REQUIRED)]
    with pytest.raises(DigitalCredentialError) as ei:
        s.verify(DRAFT19_FIG8)
    assert ei.value.code == E.KB_UNEXPECTED
    s.extra.append(with_ignore_unchecked_kb_jwt())
    got = s.verify(DRAFT19_FIG8)
    assert not got.key_bound and got.key_binding_claims is None


def _rows():
    issuer_jwt, disclosures, kb_jwt = split(DRAFT19_FIG8)
    header, payload, sig = split_jws(issuer_jwt)

    def with_header(h: str) -> str:
        return jose_b64.encode_segment(h.encode()) + "." + payload + "." + sig + "~" + "~".join(disclosures) + "~" + kb_jwt

    sig_bytes = bytearray(jose_b64.decode_segment(sig))
    sig_bytes[0] ^= 1
    tampered = DRAFT19_FIG8.replace(sig, jose_b64.encode_segment(bytes(sig_bytes)), 1)
    stripped = DRAFT19_FIG8.removesuffix(kb_jwt)
    # The KB-JWT signed sd_hash over both disclosures.
    dropped = DRAFT19_FIG8.replace("~" + disclosures[0] + "~", "~", 1)
    # Figure 8's header and signature over a payload with a duplicate claim: the signature is
    # checked before the payload is decoded in full.
    dup_claim = header + "." + jose_b64.encode_segment(b'{"iss":"https://example.com/issuer","vct":"x","vct":"y"}') + "." + sig + "~"

    def iss_with(iss: str) -> str:
        return header + "." + jose_b64.encode_segment(('{"iss":"%s","vct":"x"}' % iss).encode()) + "." + sig + "~"

    # A Key Binding JWT whose alg the caller does not allow; its signature is never reached.
    kb_es256k = DRAFT19_FIG8.replace(kb_jwt[: kb_jwt.index(".")], jose_b64.encode_segment(b'{"alg":"ES256K","typ":"kb+jwt"}'), 1)
    # A 60 KB header key, twice: the text quotes it bounded.
    long_key = "é" * 15000
    echo = with_header('{"alg":"ES256","typ":"dc+sd-jwt","' + long_key + '":1,"' + long_key + '":2}')

    issued, own = own_credentials()
    # test_request's issuer, and the status_list own_credentials sets.
    ref, iss = Ref(uri="http://status.example/lists/1", index=7), "https://issuer.example"

    def with_status_(c):
        def f(s):
            own.set(s)
            s.extra = [with_status(c)]

        return f

    # draft 19 §2.2.2.3: claims that MUST NOT be in a Disclosure. The credential is valid but for the
    # concealed claim; a concealed iss leaves none, which the resolver answers too.
    never_disclosed = {
        "iss": iss,
        "vct": "urn:example:pid",
        "exp": 1800000000,
        "nbf": 1700000100,
        "status": {"status_list": {"uri": ref.uri, "idx": ref.index}},
    }

    def concealed(s):
        own.set(s)
        s.issuers = KeysOf({iss: own.keys, "": own.keys})
        s.extra = [without_status_check()]

    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    a5 = draft19_key()

    def alg_es256k(s):
        s.extra = [with_allowed_algs("ES256K")]

    def set_now(t, *extra, own_set=False):
        def f(s):
            if own_set:
                own.set(s)
            s.now = unix(t)
            s.extra = list(extra)

        return f

    def set_extra(*extra):
        def f(s):
            s.extra = list(extra)

        return f

    def set_issuers(r, *extra):
        def f(s):
            s.issuers = r
            s.extra = list(extra)

        return f

    ns = ErrIssuerNotSupported("resolver: issuer not supported")
    P = ""  # ErrPolicy
    rows = [
        # (name, compact, set, want code ("" = ErrPolicy), is-also)
        ("typ vc+sd-jwt", with_header('{"alg":"ES256","typ":"vc+sd-jwt","kid":"doc-signer-05-25-2022"}'), None, E.TYP_INVALID, None),
        ("alg none", with_header('{"alg":"none","typ":"dc+sd-jwt","kid":"doc-signer-05-25-2022"}'), None, E.ALG_NOT_ALLOWED, None),
        ("issuer alg not allowed", DRAFT19_FIG8, alg_es256k, E.ALG_NOT_ALLOWED, None),
        ("signature altered", tampered, None, E.SIGNATURE_INVALID, None),
        ("bad signature over a duplicate claim", dup_claim, None, E.SIGNATURE_INVALID, None),
        ("duplicate 60 KB header key", echo, None, E.MALFORMED, None),
        ("expired", DRAFT19_FIG8, set_now(1883000060), E.EXPIRED, None),
        ("not yet valid", issued, set_now(1700000039, own_set=True), E.NOT_YET_VALID, None),
        (
            "credential for another audience",
            own.with_aud,
            lambda s: (own.set(s), setattr(s, "extra", [with_credential_audience("https://other.example")])),
            E.AUDIENCE_MISMATCH,
            None,
        ),
        ("credential aud, no WithCredentialAudience", own.with_aud, own.set, E.AUDIENCE_MISMATCH, None),
        ("issuer not supported", DRAFT19_FIG8, set_issuers(FailingResolver(ns)), E.ISSUER_NOT_SUPPORTED, ErrIssuerNotSupported),
        (
            "issuer not accepted",
            DRAFT19_FIG8,
            set_issuers(
                FailingResolver(UNREACHABLE),
                with_accepted_issuers("https://example.com/issuer/", "HTTPS://example.com/issuer", "https://Example.com/issuer"),
            ),
            E.ISSUER_NOT_ACCEPTED,
            None,
        ),
        ("iss with a host in Unicode", iss_with("https://bücher.example/issuer"), set_issuers(FailingResolver(UNREACHABLE)), E.MALFORMED, None),
        ("https iss without a host reaches the resolver", iss_with("https:///issuer"), set_issuers(FailingResolver(ns)), E.ISSUER_NOT_SUPPORTED, ErrIssuerNotSupported),
        ("https iss with no authority reaches the resolver", iss_with("https:x"), set_issuers(FailingResolver(ns)), E.ISSUER_NOT_SUPPORTED, ErrIssuerNotSupported),
        ("issuer keys unavailable", DRAFT19_FIG8, set_issuers(FailingResolver(UNREACHABLE)), E.ISSUER_KEY_UNAVAILABLE, ConnectionRefusedError),
        ("resolver wiring", DRAFT19_FIG8, set_issuers(FailingResolver(ErrInvalidArgument("resolver: bad"))), P, None),
        (
            "two keys share the kid",
            DRAFT19_FIG8,
            set_issuers(KeysOf({ISS: [PublicKey(a5, KID), PublicKey(a5, KID)]})),
            E.ISSUER_KEY_NOT_FOUND,
            None,
        ),
        ("resolver key on P-384", DRAFT19_FIG8, set_issuers(KeysOf({ISS: [PublicKey(p384, KID)]})), P, ErrUnsupportedKey),
        # RFC 9901 §7.3 step 2, §9.5: the credential binds a key (cnf).
        ("KB-JWT stripped", stripped, None, E.KB_MISSING, None),
        ("KB-JWT stripped, KeyBindingRequired", stripped, set_extra(with_key_binding(KeyBindingMode.REQUIRED)), E.KB_MISSING, None),
        # draft 19 §2.4: Key Binding is checked with cnf, and Figure 10 has none, so no
        # presentation can pass, Figure 8's KB-JWT included.
        ("no cnf, KeyBindingRequired", DRAFT19_FIG10 + kb_jwt, set_extra(with_key_binding(KeyBindingMode.REQUIRED)), E.KB_UNSUPPORTED, None),
        # draft 19 §2.4: no cnf, so no key checks the KB-JWT that came.
        ("KB-JWT with no cnf", DRAFT19_FIG10 + kb_jwt, None, E.KB_UNEXPECTED, None),
        # RFC 9901 §7.3 step 5f: a KB-JWT to check needs aud and nonce.
        ("KB-JWT, no WithAudience", DRAFT19_FIG8, lambda s: setattr(s, "audience", ""), P, None),
        # RFC 9901 §7.3 step 5b, RFC 8725 §3.1: the holder's alg too.
        ("KB-JWT alg not allowed", kb_es256k, set_extra(with_allowed_algs("ES256")), E.KB_INVALID, jws_errors.ErrAlgNotAllowed),
        ("KB-JWT older than WithMaxKBAge", DRAFT19_FIG8, set_now(1788209978 + 180, with_max_kb_age(timedelta(minutes=1))), E.KB_INVALID, None),
        ("KB-JWT iat ahead, WithClockSkew(0)", DRAFT19_FIG8, set_now(1788209978 - 30, with_clock_skew(0)), E.KB_INVALID, None),
        ("KB-JWT for another verifier", DRAFT19_FIG8, lambda s: setattr(s, "audience", "https://other.example"), E.KB_AUDIENCE_MISMATCH, None),
        ("KB-JWT for another transaction", DRAFT19_FIG8, lambda s: setattr(s, "nonce", "0987654321"), E.KB_NONCE_MISMATCH, None),
        ("disclosure dropped after binding", dropped, None, E.KB_SD_HASH_MISMATCH, None),
        ("cnf.jwk in a Disclosure", own.concealed_jwk, own.set, E.DISCLOSURE_INVALID, None),
        ("cnf with jwk and jku", own.two_methods, own.set, E.MALFORMED, None),
        ("KB-JWT aud an array", own.kb_aud_array, own.set, E.KB_INVALID, None),
        ("no vct", own.issue({"iss": iss}), own.set, E.MALFORMED, None),
        ("aka_vcts holding vct", own.issue({"iss": iss, "vct": "urn:example:pid", "aka_vcts": ["urn:example:pid"]}), own.set, E.MALFORMED, None),
        ("vct#integrity a number", own.issue({"iss": iss, "vct": "urn:example:pid", "vct#integrity": 1}), own.set, E.MALFORMED, None),
        (
            "vct#integrity not integrity metadata",
            own.issue({"iss": iss, "vct": "urn:example:pid", "vct#integrity": "md5-x sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}),
            own.set,
            E.MALFORMED,
            None,
        ),
        ("status a string", own.issue({"iss": iss, "vct": "urn:example:pid", "status": "valid"}), with_status_(RecordingStatus()), E.MALFORMED, None),
        (
            "status without status_list",
            own.issue({"iss": iss, "vct": "urn:example:pid", "status": {"other": {}}}),
            with_status_(RecordingStatus()),
            E.STATUS_UNAVAILABLE,
            None,
        ),
        ("cnf without jwk", own.issue({"iss": iss, "vct": "urn:example:pid", "cnf": {"kid": "holder-key-1"}}), own.set, E.KB_UNSUPPORTED, ErrKeyBindingUnsupported),
        ("revoked", issued, with_status_(FixedStatus(ref, iss, 0x01)), E.REVOKED, None),
        ("suspended", issued, with_status_(FixedStatus(ref, iss, 0x02)), E.SUSPENDED, None),
        ("status 0x03", issued, with_status_(FixedStatus(ref, iss, 0x03)), E.STATUS_NOT_ACCEPTED, None),
        ("status unavailable", issued, with_status_(FixedStatus(ref, iss, err=UNREACHABLE)), E.STATUS_UNAVAILABLE, ConnectionRefusedError),
        ("status and no WithStatus", issued, own.set, P, None),
    ]
    for name in ("iss", "exp", "nbf", "vct", "status"):
        rows.append((name + " in a Disclosure", own.issue(never_disclosed, [[name]]), concealed, E.DISCLOSURE_INVALID, None))
    return rows


def test_verify_rejects():
    # TC-20, TC-22, TC-23, TC-51: each rejection has its one Code, or is ErrPolicy for the caller's mistake.
    failures = []
    for name, compact, set_, want, is_ in _rows():
        s = draft19_setting()
        if set_ is not None:
            set_(s)
        try:
            res = s.verify(compact)
        except Exception as err:
            if want == "":
                if not errors_is(err, ErrPolicy) or code_of(err) or errors_is(err, ErrInvalidArgument):
                    failures.append(f"{name}: got {err!r}; want ErrPolicy only")
                    continue
            elif code_of(err) != want or errors_is(err, ErrPolicy):
                failures.append(f"{name}: got {err!r}; want Code {want}")
                continue
            if is_ is not None and not errors_is(err, is_):
                failures.append(f"{name}: got {err!r}; want it to match {is_}")
            if len(str(err)) > 1024:
                failures.append(f"{name}: error text is {len(str(err))} bytes")
        else:
            failures.append(f"{name}: accepted: {res.claims}")
    assert not failures, "\n".join(failures)


def test_verify_status_skipped():
    # TC-22: status is checked, skipped only when the caller says so, and accepted by the caller's set.
    issued, own = own_credentials()
    s = Setting()
    own.set(s)
    s.extra = [without_status_check()]
    res = s.verify(issued)
    assert res.status_skipped and res.status is None
    # draft 21 §7.1: which status values pass is the Verifier's policy.
    s.extra = [with_status(FixedStatus(Ref(uri="http://status.example/lists/1", index=7), "https://issuer.example", 0x02)), with_accepted_status(0x00, 0x02)]
    res = s.verify(issued)
    assert res.status == 0x02
    s.extra = []
    res = s.verify(own.no_status)
    assert not res.status_skipped and res.status is None


def test_verify_policy():
    # TC-35, TC-37, TC-51: the caller's mistakes are ErrPolicy before the token is read, and the
    # checker is not called.
    issued, own = own_credentials()
    rec = RecordingStatus()
    cases = {
        "WithoutStatusCheck twice": [without_status_check(), without_status_check()],
        "WithStatus and WithoutStatusCheck": [with_status(rec), without_status_check()],
        "a nil option": [with_status(rec), None],
        "WithAcceptedStatus()": [with_status(rec), with_accepted_status()],
        "WithAcceptedIssuers()": [with_status(rec), with_accepted_issuers()],
        'WithAcceptedIssuers("")': [with_status(rec), with_accepted_issuers("https://example.com/issuer", "")],
        "WithStatus(nil)": [with_status(None)],
        "WithKeyBinding(7)": [with_status(rec), with_key_binding(7)],
        "WithMaxKBAge(0)": [with_status(rec), with_max_kb_age(0)],
        "WithClockSkew(-1s)": [with_status(rec), with_clock_skew(timedelta(seconds=-1))],
        "WithAllowedAlgs()": [with_status(rec), with_allowed_algs()],
        "WithAllowedAlgs(RS256)": [with_status(rec), with_allowed_algs("RS256")],
        "WithNow twice": [with_status(rec), with_now(unix(1700000500))],
        "KeyBindingRequired without WithNonce": [with_status(rec), with_key_binding(KeyBindingMode.REQUIRED)],
    }
    for name, extra in cases.items():
        s = Setting()
        own.set(s)
        if name == "KeyBindingRequired without WithNonce":
            s.nonce = ""
        s.extra = extra
        with pytest.raises(Exception) as ei:
            s.verify(issued)
        assert errors_is(ei.value, ErrPolicy) and not isinstance(ei.value, DigitalCredentialError), name
        if name == "WithAllowedAlgs(RS256)":
            assert errors_is(ei.value, ErrUnsupportedAlg), name
    assert rec.refs == [], "checker asked"
    # Options are checked before the token is read, so a credential without status refuses
    # WithStatus(nil) too.
    s = Setting(extra=[with_status(None)])
    own.set(s)
    s.extra = [with_status(None)]
    with pytest.raises(ErrPolicy):
        s.verify(own.no_status)
    s = Setting()
    own.set(s)
    s.now = None  # the zero time is no time of check
    with pytest.raises(ErrPolicy):
        s.verify(own.no_status)

    from digitalcredential.credential import parse

    c = parse(issued)
    with pytest.raises(ErrPolicy):
        c.verify(None)


def test_verify_time_options():
    # TC-50: the defaults are a 1 minute skew and a 5 minute Key Binding JWT age, and a passed
    # option is used with exactly its value.
    req = test_request()
    holder = new_key()
    signer = private_key_signer(holder)
    now = unix(1800000030)
    req.holder_key = holder.public_key()  # exp is 1800000000, 30 s before now
    key = test_key()
    cred = issue(req, key)
    kb = KeyBinding(signer=signer, audience="https://verifier.example", nonce="n-1", issued_at=now - timedelta(minutes=7))
    bound = cred.present(PresentRequest(key_binding=kb))
    s = Setting(issuers=KeysOf({req.issuer: [PublicKey(key.public, key.kid)]}), audience=kb.audience, nonce=kb.nonce, now=now)
    for name, opts, want in [
        ("defaults", [], E.KB_INVALID),
        ("WithClockSkew(0)", [with_clock_skew(0)], E.EXPIRED),
        ("WithMaxKBAge(10m)", [with_max_kb_age(timedelta(minutes=10))], ""),
    ]:
        s.extra = opts
        try:
            s.verify(bound.serialize())
            got = ""
        except DigitalCredentialError as e:
            got = e.code
        assert got == want, name


STATUS_URI = "http://status.example/lists/1"
J = jose_json.JsonNumber


@pytest.mark.parametrize(
    "idx,klass,want",
    [
        (J("1.0"), "accepted", 1),
        (J("1e3"), "accepted", 1000),
        (J("1E+3"), "accepted", 1000),
        (J("10e-1"), "accepted", 1),
        (J("1.5e1"), "accepted", 15),
        (J("-0"), "accepted", 0),
        (J("-0.0"), "accepted", 0),
        (J("0e5"), "accepted", 0),
        # 2^53+1: a float64 reads it as 2^53.
        (J("9007199254740993.0"), "accepted", 9007199254740993),
        (J("9007199254740993e0"), "accepted", 9007199254740993),
        (J("0e-99999999999999999999"), "accepted", 0),
        (J("9223372036854775807"), "accepted", 9223372036854775807),
        (J("1.5"), "refused", 0),
        (J("-1"), "refused", 0),
        (J("1e-1"), "refused", 0),
        (J("-10e-1"), "refused", 0),
        (J("1.00000000000000000001"), "refused", 0),
        (J("1e-99999999999999999999"), "refused", 0),
        ("1", "refused", 0),
        (None, "refused", 0),
        (J("1e400"), "past_int", 0),
        (J("1e99999999999999999999"), "past_int", 0),
        (J("99999999999999999999"), "past_int", 0),
        (J("9223372036854775808"), "past_int", 0),  # one past the largest 64-bit int
    ],
)
@pytest.mark.parametrize("skip", [False, True])
def test_verify_status_idx(idx, klass, want, skip):
    # draft-ietf-oauth-status-list-21 §6.2: idx is a non-negative Integer, a value, which RFC 8259
    # §6 writes in many forms. Each form is read as its exact value, refused, or, past an int, past
    # every list (§8.3 step 6), with status checked and skipped.
    _, own = own_credentials()
    lst = {"uri": STATUS_URI}
    if idx is not None:
        lst["idx"] = idx
    compact = own.issue({"iss": "https://issuer.example", "vct": "urn:example:pid", "status": {"status_list": lst}})
    rec = RecordingStatus()
    s = Setting()
    own.set(s)
    s.extra = [without_status_check()] if skip else [with_status(rec)]
    if klass == "refused" or (klass == "past_int" and not skip):
        oob = klass == "past_int"
        from digitalcredential.statuslist.errors import ErrIndexOutOfBounds

        with pytest.raises(DigitalCredentialError) as ei:
            s.verify(compact)
        assert ei.value.code == E.MALFORMED
        assert errors_is(ei.value, ErrIndexOutOfBounds) == oob
        if isinstance(idx, J) and len(str(idx)) > 4:
            assert str(idx) not in str(ei.value), "the error quotes idx"
        assert rec.refs == []
        return
    res = s.verify(compact)
    if skip:
        assert res.status_skipped and res.status is None
    else:
        assert res.status == 0 and rec.refs == [(STATUS_URI, want)]
    got = res.claims["status"]["status_list"]["idx"]
    assert got == idx, "Claims idx as signed"


def test_verify_draft19_issuer_metadata():
    # TC-19: draft 19 §2.5 and §4, Figure 8 verifies through an issuermeta resolver, its key found in
    # the jwks of Figure 14 published for the Figure 8 iss. (The TLS redirect-downgrade half of the Go
    # test is covered by the issuermeta tests; here the metadata is preloaded.)
    from digitalcredential.issuermeta.issuermeta import PreloadedResolver

    meta = (
        b'{"issuer":"https://example.com/issuer","jwks":{"keys":['
        b'{"kid":"doc-signer-05-25-2022","kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"},'
        b'{"kid":"doc-signer-06-05-2025","kty":"EC","crv":"P-256","x":"DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8","y":"NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"}]}}'
    )
    s = draft19_setting()
    s.issuers = PreloadedResolver({ISS: meta})
    assert s.verify(DRAFT19_FIG8).key_bound
    # An issuer the resolver has no metadata for is ISSUER_NOT_SUPPORTED, with the sentinel reachable.
    s.issuers = PreloadedResolver({"https://other.example/x": meta})
    with pytest.raises(DigitalCredentialError) as ei:
        s.verify(DRAFT19_FIG8)
    assert ei.value.code == E.ISSUER_NOT_SUPPORTED and errors_is(ei.value, ErrIssuerNotSupported)
    # Metadata naming another issuer than iss gives no usable key.
    s.issuers = PreloadedResolver({ISS: meta.replace(b"example.com/issuer", b"example.com/other")})
    with pytest.raises(DigitalCredentialError) as ei:
        s.verify(DRAFT19_FIG8)
    assert ei.value.code == E.ISSUER_KEY_NOT_FOUND and errors_is(ei.value, ErrNoUsableKey)
