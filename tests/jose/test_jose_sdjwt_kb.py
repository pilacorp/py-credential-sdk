"""Port of jose/sdjwt/kb_test.go."""

import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as cec

from jose import (
    ErrInvalidArgument,
    ErrMalformed,
    ErrUnsupportedAlg,
    ErrUnsupportedKey,
    JsonNumber,
    decode_json,
    decode_json_object,
    decode_segment,
    encode_json,
)
from jose.jwk import to_public_key as jwk_to_public_key
from jose.jws import AlgES256K, ErrAlgNotAllowed, Header, private_key_signer, sign
from jose.sdjwt import (
    ErrKBAudience,
    ErrKBInvalid,
    ErrKBNonce,
    ErrKBSDHash,
    KBClaims,
    KBVerifyParams,
    new_kb_jwt,
    sd_hash,
    verify_kb_jwt,
)
from jose_helpers import CTX

TESTDATA = pathlib.Path(__file__).parent / "testdata" / "rfc9901-examples.json"
UTC = timezone.utc
SD_HASH = "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY"


def unix(sec, nsec=0):
    return datetime.fromtimestamp(sec, UTC) + timedelta(microseconds=nsec // 1000)


class MemSigner:
    def __init__(self, curve):
        self.priv = cec.generate_private_key(curve)
        self.pub = self.priv.public_key()
        self.signer = private_key_signer(self.priv)

    def alg(self):
        return self.signer.alg()

    def sign(self, ctx, data):
        return self.signer.sign(ctx, data)


def decode_payload(compact):
    return decode_json_object(decode_segment(compact.split(".")[1]))


def test_kb_jwt_rfc_example():
    # The SD-JWT+KB of RFC 9901 §5.2: SDHash of everything up to the last ~ is the sd_hash printed
    # there, and the KB-JWT verifies with the cnf.jwk of the Issuer-signed JWT.
    presentation = next(e["presentation"] for e in decode_json(TESTDATA.read_bytes()) if e["source"] == "RFC 9901 Section 5.2")
    cut = presentation.rindex("~") + 1
    sd_jwt, kb = presentation[:cut], presentation[cut:]
    assert sd_hash(sd_jwt) == SD_HASH
    cnf = decode_payload(sd_jwt[: sd_jwt.index("~")])["cnf"]
    holder = jwk_to_public_key(cnf["jwk"])
    params = KBVerifyParams(
        audience="https://verifier.example.org", nonce="1234567890", sd_hash=SD_HASH, now=unix(1748537244), max_age_seconds=300
    )
    verify_kb_jwt(kb, holder, params)


@pytest.mark.parametrize("curve", [cec.SECP256R1(), cec.SECP256K1()], ids=["ES256", "ES256K"])
def test_kb_jwt_round_trip(curve):
    s = MemSigner(curve)
    c = KBClaims(
        audience="https://verifier.example",
        nonce="n-0S6_WzA2Mj",
        issued_at=unix(1748537244, 900_000_000),
        sd_hash=SD_HASH,
        extra={"transaction_data_hashes": ["fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"]},
    )
    kb = new_kb_jwt(CTX, s, s.pub, c)
    want = {
        "iat": JsonNumber("1748537244"),  # whole seconds, the fraction dropped
        "aud": "https://verifier.example",
        "nonce": "n-0S6_WzA2Mj",
        "sd_hash": SD_HASH,
        "transaction_data_hashes": ["fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"],
    }
    assert decode_payload(kb) == want
    got = verify_kb_jwt(kb, s.pub, KBVerifyParams(audience=c.audience, nonce=c.nonce, sd_hash=c.sd_hash, now=c.issued_at, max_age_seconds=60))
    assert got == want


def test_new_kb_jwt_header_is_kb_jwt_typ():
    s = MemSigner(cec.SECP256R1())
    kb = new_kb_jwt(CTX, s, s.pub, KBClaims("a", "n", unix(1748537244), SD_HASH))
    assert decode_json_object(decode_segment(kb.split(".")[0])) == {"alg": "ES256", "typ": "kb+jwt"}


def _reject_cases(now, want):
    D = timedelta
    return [
        # name, other-key, edit(h, c), caller(params), holder, err, not
        ("signed by another key", True, None, None, None, ErrKBInvalid, None),
        ("typ jwt", False, lambda h, c: h.update(typ="jwt"), None, None, ErrKBInvalid, None),
        ("iat older than MaxAge plus skew", False, lambda h, c: c.update(iat=int((now - D(minutes=6, seconds=1)).timestamp())), None, None, ErrKBInvalid, None),
        ("iat later than skew", False, lambda h, c: c.update(iat=int((now + D(minutes=1, seconds=1)).timestamp())), None, None, ErrKBInvalid, None),
        # RFC 9901 §7.3 step 5e leaves the window to the Verifier: a zero ClockSkew is no skew, never a default.
        ("iat a second ahead with ClockSkew 0", False, lambda h, c: c.update(iat=int((now + D(seconds=1)).timestamp())), lambda w: setattr(w, "clock_skew_seconds", 0), None, ErrKBInvalid, None),
        ("iat missing", False, lambda h, c: c.pop("iat"), None, None, ErrKBInvalid, None),
        ("iat a string", False, lambda h, c: c.update(iat="1748537244"), None, None, ErrKBInvalid, None),
        ("iat a bool", False, lambda h, c: c.update(iat=True), None, None, ErrKBInvalid, None),
        ("aud differs", False, lambda h, c: c.update(aud="https://other.example"), None, None, ErrKBAudience, None),
        # RFC 9901 §4.3: aud is a single string; an array is malformed, not a KB-JWT for another verifier.
        ("aud array holding the verifier", False, lambda h, c: c.update(aud=[want.audience]), None, None, ErrKBInvalid, ErrKBAudience),
        ("aud a number", False, lambda h, c: c.update(aud=5), None, None, ErrKBInvalid, ErrKBAudience),
        ("aud missing", False, lambda h, c: c.pop("aud"), None, None, ErrKBInvalid, ErrKBAudience),
        ("nonce differs", False, lambda h, c: c.update(nonce="replayed"), None, None, ErrKBNonce, None),
        ("nonce a number", False, lambda h, c: c.update(nonce=5), lambda w: setattr(w, "nonce", "5"), None, ErrKBInvalid, ErrKBNonce),
        ("sd_hash differs", False, lambda h, c: c.update(sd_hash="A" * 43), None, None, ErrKBSDHash, None),
        ("sd_hash missing", False, lambda h, c: c.pop("sd_hash"), None, None, ErrKBInvalid, ErrKBSDHash),
        # RFC 7519 §4.1.4: refused on or after exp, here exactly exp + skew.
        ("exp passed", False, lambda h, c: c.update(exp=int((now - D(minutes=1)).timestamp())), None, None, ErrKBInvalid, None),
        ("nbf later than skew", False, lambda h, c: c.update(nbf=int((now + D(minutes=1, seconds=1)).timestamp())), None, None, ErrKBInvalid, None),
        # RFC 9901 §7.3 step 5b: the application names the algorithms.
        ("alg not in AllowedAlgs", False, None, lambda w: setattr(w, "allowed_algs", [AlgES256K]), None, ErrAlgNotAllowed, None),
        ("caller: AllowedAlgs lists none", False, None, lambda w: setattr(w, "allowed_algs", ["none"]), None, ErrUnsupportedAlg, ErrKBInvalid),
        ("caller: holder on P-384", False, None, None, cec.generate_private_key(cec.SECP384R1()).public_key(), ErrUnsupportedKey, ErrKBInvalid),
        ("caller: nil holder", False, None, None, "nil", ErrInvalidArgument, ErrKBInvalid),
        ("caller: zero MaxAge", False, None, lambda w: setattr(w, "max_age_seconds", 0), None, ErrInvalidArgument, None),
        ("caller: negative ClockSkew", False, None, lambda w: setattr(w, "clock_skew_seconds", -1), None, ErrInvalidArgument, None),
        # An empty expected nonce must not match a KB-JWT whose nonce is empty.
        ("caller: empty Nonce", False, lambda h, c: c.update(nonce=""), lambda w: setattr(w, "nonce", ""), None, ErrInvalidArgument, None),
        ("caller: empty Audience", False, None, lambda w: setattr(w, "audience", ""), None, ErrInvalidArgument, None),
        ("caller: empty SDHash", False, None, lambda w: setattr(w, "sd_hash", ""), None, ErrInvalidArgument, None),
    ]


def test_kb_jwt_rejects():
    now = unix(1748537244)
    holder_signer, other_signer = MemSigner(cec.SECP256R1()), MemSigner(cec.SECP256R1())
    want = KBVerifyParams(audience="https://verifier.example", nonce="n-0S6_WzA2Mj", sd_hash=SD_HASH, now=now, max_age_seconds=300, clock_skew_seconds=60)
    for name, other, edit, caller, holder, err, nope in _reject_cases(now, want):
        h = Header({"typ": "kb+jwt"})
        c = {"iat": int(now.timestamp()), "aud": want.audience, "nonce": want.nonce, "sd_hash": want.sd_hash}
        if edit:
            edit(h, c)
        s = other_signer if other else holder_signer
        kb = sign(CTX, s, s.pub, h, encode_json(c))
        w = KBVerifyParams(**want.__dict__)
        if caller:
            caller(w)
        hk = holder_signer.pub if holder is None else (None if holder == "nil" else holder)
        with pytest.raises(err) as e:
            verify_kb_jwt(kb, hk, w)
        if nope is not None:
            assert not isinstance(e.value, nope), name


def test_kb_jwt_error_wraps_cause_like_go():
    # ErrKBInvalid wraps the jws or jose cause: a malformed KB-JWT matches both.
    s = MemSigner(cec.SECP256R1())
    p = KBVerifyParams(audience="a", nonce="n", sd_hash=SD_HASH, max_age_seconds=60)
    with pytest.raises(ErrKBInvalid) as e:
        verify_kb_jwt("not-a-jws", s.pub, p)
    assert isinstance(e.value, ErrMalformed)
    kb = new_kb_jwt(CTX, s, s.pub, KBClaims("a", "n", datetime.now(UTC), SD_HASH))
    other = MemSigner(cec.SECP256R1())
    from jose.jws import ErrBadSignature

    with pytest.raises(ErrKBInvalid) as e:
        verify_kb_jwt(kb, other.pub, p)
    assert isinstance(e.value, ErrBadSignature)
    assert verify_kb_jwt(kb, s.pub, p)["aud"] == "a"  # default now = the clock


def test_kb_jwt_rejects_crit_and_b64_header():
    s = MemSigner(cec.SECP256R1())
    p = KBVerifyParams(audience="a", nonce="n", sd_hash=SD_HASH, now=unix(1748537244), max_age_seconds=60)
    from jose import encode_segment

    for h in ('{"alg":"ES256","typ":"kb+jwt","crit":["exp"]}', '{"alg":"ES256","typ":"kb+jwt","b64":false}'):
        inp = encode_segment(h.encode()) + "." + encode_segment(b"{}")
        kb = inp + "." + encode_segment(s.sign(CTX, inp.encode()))
        with pytest.raises(ErrKBInvalid):
            verify_kb_jwt(kb, s.pub, p)


def test_new_kb_jwt_keeps_its_claims():
    # Extra cannot replace the claims that bind the KB-JWT.
    s = MemSigner(cec.SECP256R1())
    for name in ("iat", "aud", "nonce", "sd_hash"):
        c = KBClaims("https://verifier.example", "n-0S6_WzA2Mj", unix(1748537244), SD_HASH, {name: "https://other.example"})
        with pytest.raises(ErrInvalidArgument):
            new_kb_jwt(CTX, s, s.pub, c)


def test_new_kb_jwt_rejects_bad_arguments():
    s = MemSigner(cec.SECP256R1())
    ok = KBClaims("a", "n", unix(1748537244), SD_HASH)
    with pytest.raises(ErrInvalidArgument):
        new_kb_jwt(CTX, None, s.pub, ok)
    with pytest.raises(ErrInvalidArgument):
        new_kb_jwt(CTX, s, None, ok)
    for bad in (KBClaims("", "n", unix(1), SD_HASH), KBClaims("a", "", unix(1), SD_HASH), KBClaims("a", "n", unix(1), ""), KBClaims("a", "n", datetime.min, SD_HASH)):
        with pytest.raises(ErrInvalidArgument):
            new_kb_jwt(CTX, s, s.pub, bad)
    with pytest.raises(ErrInvalidArgument):  # Extra that cannot be encoded
        new_kb_jwt(CTX, s, s.pub, KBClaims("a", "n", unix(1), SD_HASH, {"x": object()}))
    # a signer that does not hold the holder key fails the self check
    from jose.jws import ErrSelfCheck

    with pytest.raises(ErrSelfCheck):
        new_kb_jwt(CTX, s, MemSigner(cec.SECP256R1()).pub, ok)


def test_verify_kb_jwt_classes_holder_first():
    # The holder key is the caller's: its class must not depend on the kb the holder sends.
    p384 = cec.generate_private_key(cec.SECP384R1()).public_key()
    p = KBVerifyParams(audience="https://verifier.example", nonce="n-0S6_WzA2Mj", sd_hash=SD_HASH, max_age_seconds=60)
    with pytest.raises(ErrUnsupportedKey) as e:
        verify_kb_jwt("not-a-jws", p384, p)
    assert not isinstance(e.value, ErrKBInvalid)
