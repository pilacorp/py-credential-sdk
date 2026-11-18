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
