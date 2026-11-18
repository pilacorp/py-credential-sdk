"""Bitstring Status List: proof, issuer, bit order, purpose (issue #11)."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "vp"))
from vp_helpers import StaticResolver, V2, new_did_document, p256_from_hex, p256_pub, p256_vm  # noqa: E402

from credential.common.credential_status import Client
from credential.common.jsonmap import JSONMap
from credential.common.util.compress import compress_to_base64url
from credential.vc import credential as vc
from credential.vc import credential_helper as helper

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
    with pytest.raises(ValueError, match="issuer"):
        _check(1, _list_body([0], issuer="did:example:other"))


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
