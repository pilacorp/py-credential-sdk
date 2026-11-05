"""Shared fixtures of the digitalcredential core tests (Go: issue_test.go, verify_test.go helpers)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from digitalcredential.claims import TYP_DC_SD_JWT
from digitalcredential.credential import Credential, compact_sd_jwt, parse
from digitalcredential.errors import DigitalCredentialError
from digitalcredential.issue import IssueRequest, issue
from digitalcredential.issuerkey import PublicKey, SigningKey
from digitalcredential.verify_options import with_audience, with_nonce, with_now
from jose import json as jose_json
from jose.jwk import jwk as jose_jwk
from jose.jws import jws as jose_jws
from jose.jws import private_key_signer
from jose.sdjwt import conceal, sd_hash

try:
    from digitalcredential.statuslist import Ref
except ImportError:
    from digitalcredential.statuslist.checker import Ref

TESTDATA = Path(__file__).parent / "testdata"

# draft-ietf-oauth-sd-jwt-vc-19 §2.3.2 Figure 8, a presentation with a KB-JWT, and Figure 10, one
# without, line breaks removed.
DRAFT19_FIG8 = (
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJf"
    "c2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpy"
    "UGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRB"
    "IiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVa"
    "dTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwg"
    "IlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQ"
    "ZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJp"
    "c3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAs"
    "ICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGci"
    "OiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTla"
    "dnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1"
    "ZWNDRTZ0NGpUOUYySFpRIn19fQ.EO_qzbkRHC_Kyzfd3yQiL3uNzuwfJ1MR3-i-YIXg82Y4ar7m8i0ksfqhsy3RzEhKro9MJ"
    "f7F6iuJipJ78MWD_w~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF"
    "4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5Ijo"
    "gIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHl"
    "wIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaW"
    "VyIiwgImlhdCI6IDE3ODgyMDk5NzgsICJzZF9oYXNoIjogIlhSQUhCTjhRa0JQMm1mYUh3bmhnV3BvTG1haS1JNElnX2hSNm"
    "FadWJLTjAifQ.P3Stdkgrv_Q46LpQBzLJBP1mnryWb-4FJoOpi2vwOT0_HBy4h3gWZNfNAUWmM1ZQK4yBoLkUzQqzkWmXZuK"
    "KUw"
)
DRAFT19_FIG10 = (
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCJ9.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJ"
    "RMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa08"
    "4ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZ"
    "nbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnB"
    "LdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnR"
    "Ec3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHd"
    "RUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI"
    "iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGF"
    "tcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiJ9.NpdjRPpZ4naL6ceMyUZ_JpqHJq"
    "8M5pRL1TOTUeKtv8niRGTc_UpjCn5AVPUz6omZDmGX5wTpLrEiOKyjNPkaAQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiw"
    "gImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRy"
    "ZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50"
    "cnkiOiAiVVMifV0~"
)


def unix(sec: float) -> datetime:
    return datetime.fromtimestamp(sec, tz=timezone.utc)


class KeysOf:
    """A Resolver over a fixed map of issuers."""

    def __init__(self, m: dict[str, list[PublicKey]]) -> None:
        self.m = m

    def keys(self, iss: str) -> list[PublicKey]:
        return self.m.get(iss, [])


class FailingResolver:
    """Answers every iss with err."""

    def __init__(self, err: BaseException) -> None:
        self.err = err

    def keys(self, iss: str):
        raise self.err


class FixedStatus:
    """A StatusChecker that answers v or raises err for one reference of one issuer, and fails for any other."""

    def __init__(self, ref, iss: str, v: int = 0, err: BaseException | None = None) -> None:
        self.ref, self.iss, self.v, self.err = ref, iss, v, err

    def status(self, ref, iss):
        if (ref.uri, ref.index) != (self.ref.uri, self.ref.index) or iss != self.iss:
            raise Exception("FixedStatus: asked for another reference or issuer")
        if self.err is not None:
            raise self.err
        return self.v


class RecordingStatus:
    """Answers 0, VALID, and records each reference it is asked for."""

    def __init__(self) -> None:
        self.refs: list[tuple[str, int]] = []

    def status(self, ref, iss):
        self.refs.append((ref.uri, ref.index))
        return 0


class Setting:
    """One call of verify: the resolver, the options every test sets, and extra options."""

    def __init__(self, issuers=None, audience: str = "", nonce: str = "", now=None, extra=None) -> None:
        self.issuers, self.audience, self.nonce, self.now = issuers, audience, nonce, now
        self.extra = list(extra or [])

    def verify(self, compact: str):
        c = parse(compact)
        opts = [with_now(self.now)]
        if self.audience:
            opts.append(with_audience(self.audience))
        if self.nonce:
            opts.append(with_nonce(self.nonce))
        return c.verify(self.issuers, *opts, *self.extra)


def draft19_key():
    """The RFC 9901 Appendix A.5 issuer key, which signs the examples of draft-ietf-oauth-sd-jwt-vc-19."""
    return jose_jwk.to_public_key(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8",
        }
    )


def draft19_setting() -> Setting:
    """Verifies the examples of draft 19 §2.3.2: the A.5 key under the kid of §4.2 Figure 14, the
    Figure 8 aud and nonce, and a time at its KB-JWT iat."""
    return Setting(
        issuers=KeysOf({"https://example.com/issuer": [PublicKey(draft19_key(), "doc-signer-05-25-2022")]}),
        audience="https://example.com/verifier",
        nonce="1234567890",
        now=unix(1788209978),
    )


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_key() -> SigningKey:
    priv = new_key()
    return SigningKey(signer=private_key_signer(priv), public=priv.public_key(), kid="issuer-key-1")


def test_request() -> IssueRequest:
    """Sets every field, so every claim of draft 19 §2.2.2.3 but status is present."""
    holder = new_key()
    return IssueRequest(
        issuer="https://issuer.example",
        vct="urn:example:pid",
        issued_at=unix(1700000000.9),
        not_before=unix(1700000100),
        expiry=unix(1800000000),
        holder_key=holder.public_key(),
        claims={
            "sub": "user-42",
            "given_name": "An",
            "address": {"locality": "Hanoi", "country": "VN"},
            "nationalities": ["VN", "FR", "US"],
            "vct#integrity": "sha256-vJKakJAQkDYkIhGrT1M3nxRuSj9udH0l1PXB06QHto8=",
            "aka_vcts": ["urn:example:id"],
        },
    )


test_key.__test__ = False  # not a pytest test
test_request.__test__ = False


def split_jws(compact: str) -> tuple[str, str, str]:
    parts = compact.split(".")
    assert len(parts) == 3
    return parts[0], parts[1], parts[2]


def encode_json(v: Any) -> str:
    return jose_json.encode_json(v).decode()


def code_name(err: BaseException | None) -> str:
    e = err
    while e is not None:
        if isinstance(e, DigitalCredentialError):
            return e.code
        e = e.__cause__
    return ""


class OwnTokens:
    """Rejections no standard example shows, signed with a generated issuer key; set verifies them."""


def own_credentials() -> tuple[str, OwnTokens]:
    """An issued credential with status and no cnf, from test_request, and the OwnTokens."""
    req, key = test_request(), test_key()
    req.holder_key = None
    req.status = Ref(uri="http://status.example/lists/1", index=7)
    issued = issue(req, key)
    holder = new_key()
    holder_signer = private_key_signer(holder)
    holder_jwk = jose_jwk.from_public_key(holder.public_key())
    now = unix(1700000500)

    def sign(signer, pub, typ: str, claims: dict) -> str:
        return jose_jws.sign(object(), signer, pub, {"typ": typ, "kid": key.kid}, jose_json.encode_json(claims))

    def issue_(claims: dict, conc: list | None = None) -> str:
        payload, ds = conceal(claims, conc or [])
        return compact_sd_jwt(sign(key.signer, key.public, TYP_DC_SD_JWT, payload), ds)

    def credential(cnf: dict, conc: list | None = None) -> str:
        return issue_({"iss": req.issuer, "vct": req.vct, "cnf": cnf}, conc)

    keys = [PublicKey(key.public, key.kid)]
    own = OwnTokens()

    def set_(s: Setting) -> None:
        s.issuers = KeysOf({req.issuer: keys})
        s.audience, s.nonce, s.now = "https://verifier.example", "n-1", now

    bound = credential({"jwk": holder_jwk})
    kb = sign(
        holder_signer,
        holder.public_key(),
        "kb+jwt",
        {"aud": ["https://verifier.example"], "nonce": "n-1", "iat": 1700000500, "sd_hash": sd_hash(bound)},
    )
    own.set = set_
    own.keys = keys
    own.issue = issue_
    own.with_aud = issue_({"iss": req.issuer, "vct": req.vct, "aud": "https://verifier.example"})
    own.no_status = issue_({"iss": req.issuer, "vct": req.vct})
    own.concealed_jwk = credential({"jwk": holder_jwk}, [["cnf", "jwk"]])
    own.two_methods = credential({"jwk": holder_jwk, "jku": "https://issuer.example/jwks"}) + "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
    own.kb_aud_array = bound + kb
    return issued.serialize(), own
