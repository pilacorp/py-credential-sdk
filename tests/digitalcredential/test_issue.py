"""Go: digitalcredential/issue_test.go."""

import copy
from datetime import datetime, timezone

import pytest

from digitalcredential.issue import issue
from jose import json as jose_json
from jose.errors import ErrInvalidArgument
from jose.jws import jws as jose_jws
from jose.sdjwt import Disclosure, recreate, split

from dc_helpers import Ref, encode_json, test_key, test_request


def nested(depth: int):
    v = "leaf"
    for _ in range(depth):
        v = [v]
    return v


def _claim(k, v):
    def f(r):
        r.claims[k] = v

    return f


def _no_holder_claim(k, v):
    def f(r):
        r.holder_key = None
        r.claims[k] = v

    return f


def _set(field, v):
    return lambda r: setattr(r, field, v)


def _status_and_claim(r):
    r.status = Ref(uri="https://status.example/lists/1", index=7)
    r.claims["status"] = {"status_list": {"idx": 7, "uri": "https://status.example/lists/1"}}


def _exp_datetime(r):
    r.expiry = None
    r.claims["exp"] = datetime(2027, 1, 1, tzinfo=timezone.utc)


def _no_iss_sub(r):
    r.issuer = ""
    r.claims.pop("sub", None)


def _min_digests_no_disclose(r):
    r.disclose = []
    r.min_digests = 3


CASES = {
    "no VCT (draft 19 §2.2.2.3)": _set("vct", ""),
    # draft 19 §2.2.2.3: aka_vcts and its sub-claims MUST NOT be concealed.
    "Disclose aka_vcts[0]": _set("disclose", [["aka_vcts", 0]]),
    # draft 19 §2.2.2.5: no _sd without a selectively disclosable claim.
    "MinDigests without Disclose": _min_digests_no_disclose,
    "Claims holding iss": _claim("iss", "https://other.example"),
    "Claims holding exp and Expiry set": _claim("exp", 1800000000),
    # draft 19 §2.2.2.2: aka_vcts MUST NOT contain the vct value.
    "aka_vcts holding vct": _claim("aka_vcts", ["urn:example:id", "urn:example:pid"]),
    "aka_vcts empty": _claim("aka_vcts", []),
    "aka_vcts a string": _claim("aka_vcts", "urn:example:id"),
    "aka_vcts an empty name": _claim("aka_vcts", [""]),
    "aka_vcts a number": _claim("aka_vcts", [1]),
    # draft 19 §5.3: vct#integrity is an integrity metadata string.
    "vct#integrity a number": _claim("vct#integrity", 1),
    "vct#integrity null": _claim("vct#integrity", None),
    "vct#integrity an array": _claim("vct#integrity", []),
    # Shapes a Verifier reads as malformed: draft-ietf-oauth-status-list-21 §6.2, RFC 7519 §4.1.3, RFC 7800 §3.
    "status a string": _claim("status", "valid"),
    "status idx past every list": _claim(
        "status",
        {"status_list": {"uri": "https://issuer.example/status/1", "idx": jose_json.JsonNumber("9223372036854775808")}},
    ),
    "aud a number": _claim("aud", 1),
    "cnf a string": _no_holder_claim("cnf", "holder-1"),
    # Deeper than jose MAX_JSON_DEPTH: the request's mistake, not a malformed token.
    "Claims nested too deep": _claim("deep", nested(70)),
    "Disclose path absent": _set("disclose", [["family_name"]]),
    "Claims exp a datetime": _exp_datetime,
    # draft-ietf-oauth-status-list-21 §6.2: idx is a non-negative integer.
    "Status with a negative Index": _set("status", Ref(uri="https://status.example/lists/1", index=-1)),
    "Claims holding status and Status set": _status_and_claim,
    # RFC 7800 §3: iss or sub MUST be present beside cnf.
    "cnf without iss or sub": _no_iss_sub,
    # RFC 9901 §4.1: _sd is reserved, in the eight claims too.
    "cnf in Claims with _sd": _no_holder_claim("cnf", {"_sd": ["x"]}),
}


@pytest.mark.parametrize("name", list(CASES))
def test_issue_refuses_request(name):
    # TC-14: each request breaks a rule of IssueRequest, and validate gives the error issue gives.
    key = test_key()
    req = test_request()
    CASES[name](req)
    with pytest.raises(ErrInvalidArgument) as ei:
        issue(req, key)
    with pytest.raises(Exception) as vi:
        req.validate()
    assert str(vi.value) == str(ei.value)


def test_validate_of_valid_request():
    test_request().validate()


def test_issue_keeps_eight_claims_plain():
    # TC-15: the eight claims, here cnf and status from Claims, sit in the signed payload as given,
    # with no disclosure and no decoy, although MinDigests pads every other object.
    req = test_request()
    req.holder_key = None
    req.claims["cnf"] = {"kid": "holder-key-1"}
    req.claims["status"] = {"status_list": {"idx": 7, "uri": "https://status.example/lists/1"}}
    req.disclose = [["iat"], ["given_name"], ["address", "locality"]]
    req.min_digests = 2
    key = test_key()
    c = issue(req, key)
    issuer_jwt, encoded, kb = split(c.serialize())
    assert kb == "" and len(encoded) == 3
    header, body = jose_jws.verify(issuer_jwt, key.public, None)
    assert len(header) == 3 and header["typ"] == "dc+sd-jwt" and header["kid"] == "issuer-key-1"
    payload = jose_json.decode_json_object(body)
    for name, want in {
        "cnf": '{"kid":"holder-key-1"}',
        "status": '{"status_list":{"idx":7,"uri":"https://status.example/lists/1"}}',
        "aka_vcts": '["urn:example:id"]',
        "iss": '"https://issuer.example"',
        "vct": '"urn:example:pid"',
        "nbf": "1700000100",
        "exp": "1800000000",
    }.items():
        assert encode_json(payload[name]) == want, name
    r = recreate(payload, [Disclosure(salt="", encoded=e) for e in encoded])
    # iat: IssuedAt is 1700000000.9 s, written in whole seconds.
    assert encode_json(r.claims["iat"]) == "1700000000"
    for name in ("cnf", "status"):
        n = r.issued.fields[name]
        assert n is not None and not n.disclosed and n.hidden_fields == 0, name


def test_issue_does_not_modify_claims():
    req = test_request()
    before = copy.deepcopy(req.claims)
    issue(req, test_key())
    assert req.claims == before
