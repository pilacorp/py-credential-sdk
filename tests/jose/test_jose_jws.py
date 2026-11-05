"""Port of jose/jws/jws_test.go and signer_test.go."""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as cec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from eth_keys import keys as eth_keys

from jose import (
    MAX_JSON_DEPTH,
    ErrInvalidArgument,
    ErrMalformed,
    ErrUnsupportedAlg,
    ErrUnsupportedKey,
    JsonNumber,
    decode_segment,
    encode_segment,
)
from jose.jwk import from_public_key as jwk_from_public_key, to_public_key as jwk_to_public_key
from jose.jws import (
    AlgES256,
    AlgES256K,
    ErrAlgKeyMismatch,
    ErrAlgNotAllowed,
    ErrBadKey,
    ErrBadSignature,
    ErrSelfCheck,
    ErrSignerFailed,
    ErrUnsupportedHeader,
    Header,
    digest_signer,
    private_key_signer,
    sign,
    unverified_header,
    unverified_payload,
    verify,
)
from jose_helpers import (
    CTX,
    K1_GX,
    N_K1,
    N_P256,
    CountingSigner,
    FuncSigner,
    b64,
    craft,
    high_s,
    must_sign,
    new_p256_signer,
    new_secp_signer,
)


@pytest.mark.parametrize("name,new,alg", [("P-256", new_p256_signer, AlgES256), ("secp256k1", new_secp_signer, AlgES256K)])
def test_sign_verify_round_trip(name, new, alg):
    s, pub = new()
    payload = '{"iss":"https://x", "name":"Nguyễn <a&b>"}'
    token = must_sign(s, pub, {"typ": "dc+sd-jwt", "kid": "key-2"}, payload)
    h, got = verify(token, pub, None)
    assert got == payload.encode()  # the signed bytes unchanged
    assert h.alg() == alg and h.typ() == "dc+sd-jwt" and h.kid() == "key-2"
    assert len(decode_segment(token.rsplit(".", 1)[1])) == 64


@pytest.mark.parametrize("payload", [None, b""])
def test_empty_payload_round_trip(payload):
    s, pub = new_p256_signer()
    token = sign(CTX, s, pub, None, payload)
    parts = token.split(".")
    assert len(parts) == 3 and parts[1] == ""
    _, got = verify(token, pub, None)
    assert got == b""


def test_sign_alg_from_public_key_with_eth_keys_signer_and_key():
    # secp256k1 keys of another library are recognised by their curve.
    priv = eth_keys.PrivateKey(b"\x07" * 32)
    s = private_key_signer(priv)
    h, _ = verify(must_sign(s, priv.public_key, None, "{}"), priv.public_key, None)
    assert h.alg() == AlgES256K


@pytest.mark.parametrize("alg", ["ES256K", "RS256", "none", "", 1, None])
def test_sign_header_alg_must_match_key(alg):
    s, pub = new_p256_signer()
    with pytest.raises(ErrInvalidArgument):
        sign(CTX, s, pub, {"alg": alg}, b"{}")
    sign(CTX, s, pub, {"alg": "ES256"}, b"{}")


def test_sign_rejects_before_signing():
    p256, pub = new_p256_signer()
    k1, _ = new_secp_signer()
    rs256 = FuncSigner("RS256", lambda data: p256.sign(CTX, data))
    cases = [
        ("nil key", p256, None, ErrBadKey),
        ("P-384", p256, cec.generate_private_key(cec.SECP384R1()).public_key(), ErrUnsupportedKey),
        ("Ed25519", p256, ed25519.Ed25519PrivateKey.generate().public_key(), ErrUnsupportedKey),
        ("alg RS256", rs256, pub, ErrUnsupportedAlg),
        ("alg ES256K, P-256 key", k1, pub, ErrAlgKeyMismatch),
    ]
    for name, signer, key, want in cases:
        s = CountingSigner(signer)
        with pytest.raises(want) as e:
            sign(CTX, s, key, None, b"{}")
        # no error matches both ErrBadKey and ErrUnsupportedKey
        assert not (isinstance(e.value, ErrBadKey) and isinstance(e.value, ErrUnsupportedKey)), name
        assert s.calls == 0, name


def test_sign_header_not_html_escaped():
    s, pub = new_p256_signer()
    token = must_sign(s, pub, {"kid": "a<b>&c"}, "{}")
    assert b'"a<b>&c"' in decode_segment(token.split(".")[0])


@pytest.mark.parametrize("h", [{"crit": ["exp"]}, {"b64": False}, {"b64": True}])
def test_sign_rejects_extension_headers(h):
    p256, pub = new_p256_signer()
    s = CountingSigner(p256)
    with pytest.raises(ErrUnsupportedHeader):
        sign(CTX, s, pub, h, b"{}")
    assert s.calls == 0


def test_sign_rejects_header_verify_would_refuse():
    p256, pub = new_p256_signer()
    deep = "x"
    for _ in range(MAX_JSON_DEPTH + 1):
        deep = {"a": deep}
    for name, h in {
        "nesting deeper than MaxJSONDepth": {"x": deep},
        "over the 64 KiB Verify reads": {"x": "a" * (64 << 10)},
        "unencodable": {"x": object()},
    }.items():
        s = CountingSigner(p256)
        with pytest.raises(ErrInvalidArgument) as e:
            sign(CTX, s, pub, h, b"{}")
        assert not isinstance(e.value, ErrMalformed), name  # ErrMalformed means bad received input
        assert s.calls == 0, name


def test_sign_self_check():
    p256, p256_pub = new_p256_signer()
    k1, _ = new_secp_signer()
    _, other_p256 = new_p256_signer()
    _, other_k1 = new_secp_signer()
    one = (1).to_bytes(32, "big")
    nb = N_P256.to_bytes(32, "big")

    def answer(raw):
        return FuncSigner(AlgES256, lambda data: raw)

    def der(data):
        raw = p256.sign(CTX, data)
        return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))

    cases = {
        "another P-256 key": (p256, other_p256),
        "another secp256k1 key": (k1, other_k1),
        "DER": (FuncSigner(AlgES256, der), p256_pub),
        "64 bytes plus one": (FuncSigner(AlgES256, lambda d: p256.sign(CTX, d) + b"\0"), p256_pub),
        "63 bytes": (answer(bytes(63)), p256_pub),
        "empty": (answer(b""), p256_pub),
        "r = 0": (answer(bytes(32) + one), p256_pub),
        "s = 0": (answer(one + bytes(32)), p256_pub),
        "r = n": (answer(nb + one), p256_pub),
        "s = n": (answer(one + nb), p256_pub),
        "not bytes": (answer("str"), p256_pub),
    }
    for name, (s, pub) in cases.items():
        with pytest.raises(ErrSelfCheck) as e:
            sign(CTX, s, pub, None, b"{}")
        # the fault is the signer's: not also a Verify error
        assert not isinstance(e.value, (ErrBadSignature, ErrAlgKeyMismatch)), name


def test_sign_65_byte_answer_is_self_check():
    s, pub = new_secp_signer(with_recovery=True)
    with pytest.raises(ErrSelfCheck):
        sign(CTX, s, pub, None, b"{}")


@pytest.mark.parametrize("new,n", [(new_p256_signer, N_P256), (new_secp_signer, N_K1)])
def test_sign_keeps_signer_signature_high_s_verifies(new, n):
    s, pub = new()
    answered = []
    high = high_s(s, n)

    def rec(data):
        raw = high.sign(CTX, data)
        answered.append(raw)
        return raw

    token = must_sign(FuncSigner(high.alg(), rec), pub, None, '{"a":1}')
    sig = decode_segment(token.rsplit(".", 1)[1])
    assert sig == answered[0]
    assert int.from_bytes(sig[32:], "big") > n >> 1  # the test signer did answer high-S
    verify(token, pub, None)  # high-S must verify


def test_sign_propagates_signer_error():
    _, pub = new_p256_signer()

    class Boom(Exception):
        pass

    def fail(data):
        raise Boom("signer down")

    with pytest.raises(ErrSignerFailed) as e:
        sign(CTX, FuncSigner(AlgES256, fail), pub, None, b"{}")
    assert isinstance(e.value, Boom) and isinstance(e.value.__cause__, Boom)  # the signer's error wrapped too


def test_sign_passes_context():
    priv = cec.generate_private_key(cec.SECP256R1())
    seen = []

    class Canceled(Exception):
        pass

    def do(ctx, digest):
        seen.append(ctx)
        raise Canceled()

    s = digest_signer(AlgES256, do)
    ctx = {"caller": True}
    with pytest.raises(ErrSignerFailed) as e:
        sign(ctx, s, priv.public_key(), None, b"{}")
    assert seen == [ctx] and isinstance(e.value, Canceled)


def test_sign_rejects_invalid_arguments():
    s, pub = new_p256_signer()
    with pytest.raises(ErrInvalidArgument):
        sign(CTX, None, pub, None, b"{}")
    counted = CountingSigner(s)
    with pytest.raises(ErrInvalidArgument):
        sign(None, counted, pub, None, b"{}")
    assert counted.calls == 0
    with pytest.raises(ErrInvalidArgument):
        sign(CTX, s, pub, Header({"x": object()}), b"{}")


def test_verify_malformed():
    s, pub = new_p256_signer()
    good = must_sign(s, pub, None, "{}")
    p = good.split(".")
    cases = {
        "two parts": p[0] + "." + p[1],
        "four parts": good + ".x",
        "empty header": "." + p[1] + "." + p[2],
        "line break in sig": p[0] + "." + p[1] + "." + p[2][:10] + "\n" + p[2][10:],
        "header not object": craft(s, '["ES256"]', "{}"),
        "alg not string": craft(s, '{"alg":1}', "{}"),
        "duplicate alg": craft(s, '{"alg":"ES256","alg":"ES256K"}', "{}"),
        "header trailing": craft(s, '{"alg":"ES256"}x', "{}"),
        "header not base64": "@@@." + p[1] + "." + p[2],
        "non-zero trailing bits": p[0][:-1] + ("Q" if p[0][-1] != "Q" else "R") + "." + p[1] + "." + p[2],
        "header over 64 KiB": craft(s, '{"alg":"ES256","x":"' + "a" * (64 << 10) + '"}', "{}"),
        "not a string": None,
    }
    for name, tok in cases.items():
        if tok is None:
            continue
        with pytest.raises(ErrMalformed):
            verify(tok, pub, None)


@pytest.mark.parametrize("h", ['{"alg":"ES256","crit":["exp"]}', '{"alg":"ES256","b64":false}', '{"alg":"ES256","b64":true}'])
def test_verify_rejects_extension_headers(h):
    s, pub = new_p256_signer()
    with pytest.raises(ErrUnsupportedHeader):
        verify(craft(s, h, "{}"), pub, None)
    with pytest.raises(ErrUnsupportedHeader):  # UnverifiedHeader refuses the same tokens
        unverified_header(craft(s, h, "{}"))


def test_verify_alg_rules():
    p256, p256_pub = new_p256_signer()
    k1, k1_pub = new_secp_signer()
    for alg in ["none", "HS256", "RS256", "PS256", "EdDSA", "ES384"]:
        tok = craft(p256, '{"alg":"%s"}' % alg, "{}")
        with pytest.raises(ErrAlgNotAllowed) as e:
            verify(tok, p256_pub, None)
        # an alg read from the token is a refused token, never the caller's ErrUnsupportedAlg
        assert not isinstance(e.value, ErrUnsupportedAlg) and "the SDK supports ES256 and ES256K" in str(e.value)
        # the caller names the algorithms; one the SDK cannot verify is reported as such
        with pytest.raises(ErrUnsupportedAlg) as e:
            verify(tok, p256_pub, [alg, AlgES256])
        assert not isinstance(e.value, ErrAlgNotAllowed)
    es256k = must_sign(k1, k1_pub, None, "{}")
    with pytest.raises(ErrAlgNotAllowed):
        verify(es256k, k1_pub, [AlgES256])
    verify(es256k, k1_pub, [AlgES256, AlgES256K])
    # the key decides: an ES256 header over a secp256k1 key, and the reverse
    with pytest.raises(ErrAlgKeyMismatch):
        verify(craft(k1, '{"alg":"ES256"}', "{}"), k1_pub, None)
    with pytest.raises(ErrAlgKeyMismatch):
        verify(craft(p256, '{"alg":"ES256K"}', "{}"), p256_pub, None)


def test_verify_ignores_key_in_header():
    attacker, attacker_pub = new_p256_signer()
    _, victim_pub = new_p256_signer()
    tok = must_sign(attacker, attacker_pub, {"jwk": jwk_from_public_key(attacker_pub)}, "{}")
    with pytest.raises(ErrBadSignature):
        verify(tok, victim_pub, None)


def test_verify_signature_formats():
    s, pub = new_p256_signer()
    p = must_sign(s, pub, None, "{}").split(".")
    sig = decode_segment(p[2])
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    cases = {
        "65 bytes": sig + b"\x01",
        "r, one zero, s": sig[:32] + b"\0" + sig[32:],
        "r, 32 zeros, s": sig[:32] + bytes(32) + sig[32:],
        "DER": der,
        "63 bytes": sig[:63],
        "empty": b"",
    }
    for name, raw in cases.items():
        with pytest.raises(ErrBadSignature):
            verify(p[0] + "." + p[1] + "." + b64(raw), pub, None)


def test_verify_rejects_scalars_out_of_range():
    s, pub = new_p256_signer()
    p = must_sign(s, pub, None, "{}").split(".")
    sig = decode_segment(p[2])
    for raw in (bytes(32) + sig[32:], sig[:32] + N_P256.to_bytes(32, "big")):
        with pytest.raises(ErrBadSignature):
            verify(p[0] + "." + p[1] + "." + b64(raw), pub, None)


def _recovered_secp_key(r: int, s: int, signing_input: str):
    digest = hashlib.sha256(signing_input.encode()).digest()
    sig = eth_keys.Signature(vrs=(0, r, s))
    return sig.recover_public_key_from_msg_hash(digest)


@pytest.mark.parametrize("r,s,r_big,s_big", [(K1_GX, 1, False, True), (1, 1, True, False)])
def test_verify_secp256k1_rejects_scalars_above_n(r, s, r_big, s_big):
    # The key is recovered so that (r, s) is a valid signature over the signing input;
    # r or s of n+1 must not verify as 1 (a verifier reducing mod n would accept it).
    signing_input = b64(b'{"alg":"ES256K"}') + "." + b64(b"{}")
    pub = _recovered_secp_key(r, s, signing_input)
    key = cec.EllipticCurvePublicNumbers(
        int.from_bytes(pub.to_bytes()[:32], "big"), int.from_bytes(pub.to_bytes()[32:], "big"), cec.SECP256K1()
    ).public_key()
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    verify(signing_input + "." + b64(sig), key, None)  # (r, s) must verify
    n1 = (N_K1 + 1).to_bytes(32, "big")
    bad = (n1 + s.to_bytes(32, "big")) if r_big else (r.to_bytes(32, "big") + n1)
    with pytest.raises(ErrBadSignature):
        verify(signing_input + "." + b64(bad), key, None)
    # eth_keys keys are accepted as verification keys too
    verify(signing_input + "." + b64(sig), pub, None)


def test_verify_rfc7515_appendix_a3():
    key = jwk_to_public_key(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        }
    )
    token = (
        "eyJhbGciOiJFUzI1NiJ9"
        "."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        "."
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
        "pmWQxfKTUJqPP3-Kg6NU1Q"
    )
    header, payload = verify(token, key, None)
    assert header.alg() == AlgES256
    assert payload == b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    p = token.split(".")
    sig = bytearray(decode_segment(p[2]))
    sig[10] ^= 1
    with pytest.raises(ErrBadSignature):
        verify(p[0] + "." + p[1] + "." + b64(bytes(sig)), key, None)


def test_verify_hashes_received_bytes():
    s, pub = new_p256_signer()
    p = must_sign(s, pub, None, '{"a": 1}').split(".")
    with pytest.raises(ErrBadSignature):
        verify(p[0] + "." + b64(b'{"a":1}') + "." + p[2], pub, None)


def test_verify_wrong_key():
    s, pub = new_secp_signer()
    _, other = new_secp_signer()
    with pytest.raises(ErrBadSignature):
        verify(must_sign(s, pub, None, "{}"), other, None)


def test_verify_rejects_bad_key():
    s, pub = new_p256_signer()
    tok = must_sign(s, pub, None, "{}")
    with pytest.raises(ErrBadKey):
        verify(tok, None, None)
    for bad in (cec.generate_private_key(cec.SECP384R1()).public_key(), ed25519.Ed25519PrivateKey.generate().public_key()):
        with pytest.raises(ErrUnsupportedKey):
            verify(tok, bad, None)


def test_verify_many_dots_is_malformed_quickly():
    _, pub = new_p256_signer()
    with pytest.raises(ErrMalformed):
        verify("." * (1 << 20), pub, None)


def test_unverified_header_and_payload():
    s, pub = new_p256_signer()
    token = must_sign(s, pub, {"kid": "key-1"}, "{}")
    h = unverified_header(token)
    assert h.kid() == "key-1" and h.alg() == AlgES256
    with pytest.raises(ErrMalformed):
        unverified_header(token[: token.rindex(".")])
    assert unverified_payload(token) == b"{}"
    with pytest.raises(ErrMalformed):
        unverified_payload(token[: token.rindex(".")])


@pytest.mark.parametrize(
    "typ,media,want",
    [
        ("kb+jwt", "application/kb+jwt", True),
        ("application/kb+jwt", "kb+jwt", True),
        ("KB+JWT", "kb+jwt", True),
        ("kb+jwt", "Application/KB+JWT", True),
        ("text/kb+jwt", "application/kb+jwt", False),
        ('application/example;part="1/2"', 'application/example;part="1/2"', False),
        ("kb+jwt ", "kb+jwt", False),
        ("Kb+jwt", "kb+jwt", False),  # KELVIN SIGN folds to k only under Unicode rules
        (None, "", False),
        (123, "123", False),
        (JsonNumber("123"), "123", False),
    ],
)
def test_header_typ_is(typ, media, want):
    h = Header({"alg": AlgES256})
    if typ is not None:
        h["typ"] = typ
    assert h.typ_is(media) is want


# --- signer_test.go ---------------------------------------------------------------


def test_digest_signer():
    priv = cec.generate_private_key(cec.SECP256R1())
    got = []

    def do(ctx, digest):
        got.append(digest)
        r, sv = decode_dss_signature(priv.sign(digest, cec.ECDSA(Prehashed(hashes.SHA256()))))
        return r.to_bytes(32, "big") + sv.to_bytes(32, "big")

    s = digest_signer(AlgES256, do)
    token = must_sign(s, priv.public_key(), None, '{"a":1}')
    verify(token, priv.public_key(), None)
    assert got[0] == hashlib.sha256(token[: token.rindex(".")].encode()).digest()
    with pytest.raises(ErrUnsupportedAlg):
        digest_signer("RS256", lambda c, d: b"")
    with pytest.raises(ErrInvalidArgument):
        digest_signer(AlgES256, None)


def test_private_key_signer():
    p256 = cec.generate_private_key(cec.SECP256R1())
    k1 = cec.generate_private_key(cec.SECP256K1())
    eth = eth_keys.PrivateKey(b"\x09" * 32)
    for priv, pub, alg in ((p256, p256.public_key(), AlgES256), (k1, k1.public_key(), AlgES256K), (eth, eth.public_key, AlgES256K)):
        s = private_key_signer(priv)
        assert s.alg() == alg
        h, _ = verify(must_sign(s, pub, None, "{}"), pub, None)
        assert h.alg() == alg
    for bad in (ed25519.Ed25519PrivateKey.generate(), cec.generate_private_key(cec.SECP384R1())):
        with pytest.raises(ErrUnsupportedKey):
            private_key_signer(bad)
    with pytest.raises(ErrBadKey):
        private_key_signer(None)
