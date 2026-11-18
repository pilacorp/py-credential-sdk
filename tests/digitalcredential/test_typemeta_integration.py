"""Type Metadata through issue and verify (issue #1)."""

import json
from datetime import datetime, timezone

import pytest

from digitalcredential import IssueRequest, PublicKey, SigningKey, StaticResolver, issue, parse, typemeta
from digitalcredential.verify_options import with_all_disclosures, with_type_metadata
from jose.errors import ErrInvalidArgument
from jose.jws import private_key_signer

from dc_helpers import new_key

VCT = "https://credentials.example/addr"
ISS = "https://issuer.example"


def _meta(claims):
    doc = json.dumps({"vct": VCT, "claims": claims}).encode()
    return typemeta.Load(typemeta.Static(doc), typemeta.Ref(vct=VCT, integrity=typemeta.Integrity(doc)))


def _issue(m, claims, disclose):
    k = new_key()
    cred = issue(
        IssueRequest(
            issuer=ISS, vct=VCT, issued_at=datetime.now(timezone.utc), claims=claims, disclose=disclose,
            type_metadata=m,
        ),
        SigningKey(signer=private_key_signer(k), public=k.public_key(), kid="k"),
    )
    return cred, StaticResolver(ISS, [PublicKey(k.public_key(), "k")])


def test_valid_credential_verifies_and_violations_reject():
    m = _meta([{"path": ["address", "city"], "mandatory": True, "sd": "always"}])
    claims = {"address": {"city": "Hanoi"}}
    cred, res = _issue(m, claims, [["address", "city"]])
    parse(cred.serialize()).verify(res, with_type_metadata(typemeta.Static(m.documents()[0])))
    parse(cred.serialize()).verify(res, with_type_metadata(typemeta.Static(m.documents()[0])), with_all_disclosures())
    # sd "always" but the claim is not concealed
    with pytest.raises(Exception, match="sd is always"):
        _issue(m, claims, [])
    # mandatory claim missing
    with pytest.raises(Exception, match="mandatory"):
        _issue(m, {"address": {}}, [])


def test_iat_type_checked_and_future_rejected():
    from datetime import timedelta

    from digitalcredential.errors import DigitalCredentialError
    from digitalcredential.verify_options import with_iat_check, with_reject_future_iat

    k = new_key()
    now = datetime.now(timezone.utc)

    def make(**kw):
        cred = issue(
            IssueRequest(issuer=ISS, vct=VCT, issued_at=kw.get("iat", now), claims={"a": 1}),
            SigningKey(signer=private_key_signer(k), public=k.public_key(), kid="k"),
        )
        return cred

    res = StaticResolver(ISS, [PublicKey(k.public_key(), "k")])
    parse(make().serialize()).verify(res, with_reject_future_iat())
    with pytest.raises(DigitalCredentialError) as e:
        parse(make(iat=now + timedelta(days=1)).serialize()).verify(res, with_reject_future_iat())
    assert e.value.code == "NOT_YET_VALID"
    seen = []
    parse(make().serialize()).verify(res, with_iat_check(seen.append))
    assert len(seen) == 1

    def boom(iat):
        raise RuntimeError("x")

    with pytest.raises(DigitalCredentialError) as e:
        parse(make().serialize()).verify(res, with_iat_check(boom))
    assert e.value.code == "IAT_CHECK_FAILED"
