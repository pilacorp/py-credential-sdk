"""Checks for the review comments of PR #14."""
import json
import socket
import ssl
import threading
import time
from datetime import datetime

import pytest

from pila_credential.didv2 import DIDGenerator, DefaultProvider
from pila_credential.didv2.did import verification_method_ops as ops
from pila_credential.didv2.did.did import new_secp256k1_vm, new_spec

K = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"


@pytest.mark.parametrize("p256", [False, True])
def test_add_vms_kept_once(p256):
    vm = new_secp256k1_vm("did:nda:0x1", "#key-9", "0x02" + "11" * 32)
    res = DIDGenerator(issuer_signer=DefaultProvider(K)).generate_did(1, enable_p256_vm=p256, add_vms=[new_spec(vm)])
    ids = [v["id"].split("#")[1] for v in res["document"]["verificationMethod"]]
    assert ids.count("key-9") == 1 and ids.count("key-1") == 1 and (ids.count("key-2") == int(p256))


def test_chain_client_per_contract(monkeypatch):
    made = []

    class Fake:
        def __init__(self, rpc, addr):
            made.append(addr)

    import pila_credential.didv2.rpc as rpc

    monkeypatch.setattr(rpc, "DIDChain", Fake)
    g = DIDGenerator(issuer_signer=DefaultProvider(K))
    a, b = "0x" + "11" * 20, "0x" + "22" * 20
    for addr in (a, b, a):
        g._get_chain(g._resolve({"did_smc_addr": addr}))
    assert made == [a, b]


def test_already_revoked_is_distinguishable():
    doc = {"id": "did:nda:0x1", "verificationMethod": [{"id": "did:nda:0x1#key-1", "type": "t"}]}
    ops.revoke_verification_method(doc, "did:nda:0x1#key-1", "keyCompromise")
    with pytest.raises(ops.ErrAlreadyRevoked):
        ops.revoke_verification_method(doc, "did:nda:0x1#key-1", "keyCompromise")


def test_schema_ref_cannot_leave_schema():
    from pila_credential.credential.vc import credential_helper as h

    class O:
        loaded_schema_loader = staticmethod(lambda u: json.dumps({"$ref": "file:///etc/hostname"}).encode())

    cred = {"credentialSchema": {"id": "https://s/1"}}
    for k in h.REQUIRED_CREDENTIAL_PROPERTIES:
        cred.setdefault(k, "x")
    with pytest.raises(ValueError, match="not in the schema"):
        h.validate_credential(cred, O())


def test_with_now_naive_is_utc_and_max_age_leading_zeros():
    from pila_credential.digitalcredential._internal.httpcache import _delta_seconds
    from pila_credential.digitalcredential.verify_options import VerifyConfig, with_now

    c = VerifyConfig()
    with_now(datetime(2025, 1, 1)).set_on(c)
    assert c.now.tzinfo is not None
    assert _delta_seconds("00000000060") == 60


def test_claim_budget_refuses_quickly():
    from pila_credential.digitalcredential import typemeta as T
    from pila_credential.digitalcredential.typemeta import validate as V

    doc = json.dumps({"vct": "https://x.example/t", "claims": [{"path": ["a", None]} for _ in range(300)]}).encode()
    m = T.Load(T.Static(doc), T.Ref(vct="https://x.example/t", integrity=T.Integrity(doc)))
    payload = {"a": list(range(20000))}
    t = time.monotonic()
    with pytest.raises(T.ErrClaims):
        T.validate_issuance(m, payload, [])
    assert time.monotonic() - t < 5
    assert V.MAX_CLAIM_VISITS == 1 << 20


def _self_signed(tmp_path):
    from datetime import timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(key, hashes.SHA256())
    )
    cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cf, kf


def test_https_slow_body_ends_within_timeout(tmp_path):
    from pila_credential.digitalcredential._internal import safehttp as sh

    cf, kf = _self_signed(tmp_path)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cf, kf)
    cctx = ssl.create_default_context(cafile=str(cf))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        try:
            t = sctx.wrap_socket(c, server_side=True)
            t.recv(4096)
            t.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
            for _i in range(100):
                t.sendall(b"x")
                time.sleep(0.25)
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    t0 = time.monotonic()
    with pytest.raises(sh.FetchError):
        sh.get(sh.Client(address_check=None, ssl_context=cctx), f"https://localhost:{srv.getsockname()[1]}/",
               ["application/json"], sh.Limits(timeout_seconds=1))
    assert time.monotonic() - t0 < 3
    srv.close()


def test_dns_lookup_under_deadline(monkeypatch):
    from pila_credential.digitalcredential._internal import safehttp as sh

    monkeypatch.setattr(sh.socket, "getaddrinfo", lambda *a, **k: time.sleep(3))
    t = time.monotonic()
    with pytest.raises(sh.FetchError):
        sh.get(sh.Client(), "https://slow-dns.example/", ["application/json"], sh.Limits(timeout_seconds=1))
    assert time.monotonic() - t < 2
