"""One check per fix of issues #7, #8, #9 and #12 that has no test elsewhere."""
import json
from datetime import datetime, timezone

import pytest

from pila_credential.did.model import DIDType, KeyPair, Secret
from pila_credential.didv2 import DIDGenerator, DefaultProvider
from pila_credential.didv2.did import verification_method_ops as ops
from pila_credential.didv2.did.did import generate_ecdsa_key_pair

K = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"


def test_didv2_override_signs_for_overridden_contract(monkeypatch):
    from pila_credential.didv2 import did_generator as dg

    seen = []
    real = dg.generate_issue_did_signature
    monkeypatch.setattr(dg, "generate_issue_did_signature", lambda contract, *a: (seen.append(contract), real(contract, *a))[1])
    gen = DIDGenerator(issuer_signer=DefaultProvider(K))
    other = "0x" + "11" * 20
    res = gen.generate_did(1, did_smc_addr=other)
    assert seen == [other]
    assert res["transaction"]
    gen.generate_did(1, enable_p256_vm=True, add_vms=[])  # no duplicate-id error


def test_revoke_superseded_then_key_compromise():
    doc = {"id": "did:nda:0x1", "verificationMethod": [{"id": "did:nda:0x1#key-1", "type": "t"}]}
    ops.revoke_verification_method(doc, "did:nda:0x1#key-1", "superseded")
    first = doc["verificationMethod"][0]["revoked"]
    assert isinstance(first, str)
    json.dumps(doc)  # no datetime left in the document
    ops.revoke_verification_method(doc, "did:nda:0x1#key-1", "keyCompromise")
    vm = doc["verificationMethod"][0]
    assert vm["revocationReason"] == "keyCompromise" and vm["revoked"] == first
    with pytest.raises(ValueError):
        ops.revoke_verification_method(doc, "did:nda:0x1#key-1", "keyCompromise")
    with pytest.raises(ValueError):
        ops.revoke_verification_method(doc, "did:nda:0x1#key-1", "superseded")


def test_did_type_is_value_and_secrets_not_in_repr():
    from pila_credential.did.helper import generate_did_document  # noqa: F401
    from pila_credential.did.did_generator import DIDGenerator as Legacy
    from pila_credential.did.model import CreateDID

    out = Legacy().generate_did(CreateDID(type=DIDType.PEOPLE))
    assert "DIDType" not in json.dumps(out, default=str)
    assert "deadbeef" not in repr(Secret("deadbeef")) and "deadbeef" not in repr(KeyPair("a", "b", "deadbeef", "d"))


def test_decrypt_invalid_utf8():
    from pila_credential.didcomm.crypto.aes import encrypt_aes_gcm
    from pila_credential.didcomm.decrypt import decrypt_jwe
    from pila_credential.didcomm.jwe.jwe import build_jwe

    key = b"k" * 32
    jwe = build_jwe(*encrypt_aes_gcm(key, b"\xff\xfe"))
    with pytest.raises(ValueError, match="UTF-8"):
        decrypt_jwe(jwe, key)


def test_dot_segment_iss_and_huge_max_age():
    from pila_credential.digitalcredential.internal.httpcache import _delta_seconds
    from pila_credential.digitalcredential.issuermeta import issuermeta as im

    for iss in ("https://e.com/a/../b", "https://e.com/%2e%2e/x"):
        with pytest.raises(Exception):
            im._metadata_url(iss)
    assert _delta_seconds("9" * 5000) is not None


def test_present_needs_issued_at_and_naive_time_is_utc():
    from datetime import datetime

    from pila_credential.digitalcredential.issue import _put_time

    c = {}
    _put_time(c, "iat", datetime(2024, 1, 1))
    assert c["iat"] == int(datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp())


def test_valid_from_rfc3339_strict():
    from pila_credential.credential.vc import credential_helper as h

    for bad in ("2024-01-01T00:00Z", "20240101T000000Z"):
        with pytest.raises(ValueError):
            h.check_validity_period("c", bad, "", __import__("datetime").timedelta(0))
    h.check_validity_period("c", "2024-01-01T00:00:00Z", "", __import__("datetime").timedelta(0))


def test_ecdsasd_signer_must_hold_vm_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    from pila_credential.credential.common.jsonmap import JSONMap
    from pila_credential.credential.common.signer.p256 import P256Provider

    a = P256Provider.from_hex("1f2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff001")
    b = P256Provider.from_hex("11" * 32)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), a.public_key_uncompressed())

    def doc():
        return {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"],
                "issuer": "did:example:i", "credentialSubject": {"id": "did:example:s"}}

    JSONMap(doc()).add_ecdsasd_base_proof(a, "did:example:i#key-1", "assertionMethod", [], vm_pub=pub)
    with pytest.raises(ValueError, match="does not verify"):
        JSONMap(doc()).add_ecdsasd_base_proof(b, "did:example:i#key-1", "assertionMethod", [], vm_pub=pub)


def test_jsonrpc_deadline_and_no_redirect():
    import socket
    import threading
    import time

    from pila_credential.didv2.jsonrpc import JsonRpc

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)

    def serve():
        for _ in range(2):
            c, _a = srv.accept()
            req = c.recv(4096)
            if b"/redir" in req:
                c.sendall(b"HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                c.close()
                continue
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
            for _i in range(100):
                try:
                    c.sendall(b"x")
                except OSError:
                    return
                time.sleep(0.25)

    threading.Thread(target=serve, daemon=True).start()
    base = f"http://127.0.0.1:{srv.getsockname()[1]}"
    with pytest.raises(ValueError, match="HTTP error 302"):
        JsonRpc(base + "/redir").call("m", [])
    t = time.monotonic()
    with pytest.raises(ValueError, match="timed out"):
        JsonRpc(base + "/slow", timeout=1).call("m", [])
    assert time.monotonic() - t < 3
    srv.close()
