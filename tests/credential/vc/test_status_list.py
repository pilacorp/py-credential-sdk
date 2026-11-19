"""Bitstring Status List: proof, issuer, bit order, purpose (issue #11)."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "vp"))
from vp_helpers import StaticResolver, V2, new_did_document, p256_from_hex, p256_pub, p256_vm  # noqa: E402

from pila_credential.credential.common.credential_status import Client
from pila_credential.credential.common.jsonmap import JSONMap
from pila_credential.credential.common.util.compress import compress_to_base64url
from pila_credential.credential.vc import credential as vc
from pila_credential.credential.vc import credential_helper as helper

ISSUER = "did:example:status-issuer"
LIST_URL = "https://status.example/lists/1"
PROV = p256_from_hex()
RESOLVER = StaticResolver([new_did_document(ISSUER, [p256_vm(ISSUER, "key-1", PROV)])])


def _list_body(revoked_positions=(), purpose="revocation", issuer=ISSUER, sign=True, prefix="u", size=16384):
    bits = bytearray(size)
    for p in revoked_positions:
        bits[p // 8] |= 0x80 >> (p % 8)
    doc = {
        "@context": [V2],
        "id": LIST_URL,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {
            "id": LIST_URL + "#list",
            "type": "BitstringStatusList",
            "statusPurpose": purpose,
            "encodedList": prefix + compress_to_base64url(bytes(bits)),
        },
    }
    if sign:
        JSONMap(doc).add_ecdsa_proof(PROV, f"{ISSUER}#key-1", "assertionMethod", vm_pub=p256_pub(PROV))
    return json.dumps({"data": doc}).encode()


def _check(index, body, entry_purpose="revocation", vc_issuer=ISSUER):
    cred = {
        "issuer": vc_issuer,
        "credentialStatus": {
            "type": "BitstringStatusListEntry",
            "statusPurpose": entry_purpose,
            "statusListIndex": str(index),
            "statusListCredential": LIST_URL,
        },
    }
    opts = vc.get_options(vc.with_resolver(RESOLVER), vc.with_status_client(Client(fetch=lambda url: body)))
    helper.check_revocation(cred, opts)


def test_msb_first_and_signed_list():
    body = _list_body([0])
    with pytest.raises(ValueError, match="revoked"):
        _check(0, body)
    _check(7, body)  # old LSB-first reading would call this revoked
    _check(1, _list_body([0], prefix=""))  # unprefixed legacy encoding still decodes


def test_unsigned_or_foreign_list_is_refused():
    with pytest.raises(ValueError, match="verify proof|proof"):
        _check(1, _list_body([0], sign=False))
    # BSL §3.2: the list may come from another issuer; which issuers to trust is the verifier's call.
    with pytest.raises(ValueError, match="revoked"):
        _check(0, _list_body([0], issuer="did:example:other"))


def test_purpose_mismatch_and_unknown_purpose():
    with pytest.raises(ValueError, match="statusPurpose"):
        _check(1, _list_body(purpose="suspension"))
    with pytest.raises(ValueError, match="unsupported statusPurpose"):
        _check(1, _list_body(purpose="message"), entry_purpose="message")


def test_short_list_and_index_forms():
    with pytest.raises(ValueError, match="at least"):
        _check(1, _list_body(size=10))
    for bad in (" 5", "1_0", "٥"):
        with pytest.raises(ValueError, match="statusListIndex"):
            _check(bad, _list_body())


def test_enveloped_list_id_does_not_skip_body_proof():
    body = json.loads(_list_body([], sign=False))
    body["data"]["id"] = "data:application/vc+jwt,aaa.bbb.ccc"
    body["data"]["type"] = ["VerifiableCredential", "BitstringStatusListCredential", "EnvelopedVerifiableCredential"]
    with pytest.raises(ValueError, match="proof"):
        _check(0, json.dumps(body).encode())


def test_status_list_validity_uses_leeway():
    from datetime import datetime, timedelta, timezone

    future = (datetime.now(timezone.utc) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = json.loads(_list_body([], sign=False))
    body["data"]["validFrom"] = future
    JSONMap(body["data"]).add_ecdsa_proof(PROV, f"{ISSUER}#key-1", "assertionMethod", vm_pub=p256_pub(PROV))
    raw = json.dumps(body).encode()
    cred = {"issuer": ISSUER, "credentialStatus": {"statusListIndex": "1", "statusListCredential": LIST_URL}}
    mk = lambda *o: vc.get_options(vc.with_resolver(RESOLVER), vc.with_status_client(Client(fetch=lambda u: raw)), *o)  # noqa: E731
    with pytest.raises(ValueError, match="not valid yet"):
        helper.check_revocation(cred, mk())
    helper.check_revocation(cred, mk(vc.with_leeway(timedelta(seconds=60))))
