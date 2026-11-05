"""Port of go-credential-sdk/credential/common/credential-status/credential_status_test.go."""
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from credential.common.credential_status import Client, fetch_and_check_revocation, is_revoked
from credential.common.credential_status.credential_status import DEFAULT_TIMEOUT, MAX_DECODED_BYTES
from credential.common.credential_status.model import StatusListCredentialSubject
from credential.common.util.compress import compress_to_base64url


def _subject(raw: bytes, purpose="revocation") -> StatusListCredentialSubject:
    return StatusListCredentialSubject(encoded_list=compress_to_base64url(raw), status_purpose=purpose)


def _body(raw: bytes, purpose="revocation") -> bytes:
    return json.dumps(
        {
            "data": {
                "credentialSubject": {
                    "encodedList": compress_to_base64url(raw),
                    "statusPurpose": purpose,
                    "id": "did:example:status/0#list",
                    "type": "BitstringStatusList",
                },
                "id": "did:example:status/0",
                "issuer": "did:example:issuer",
                "proof": {},
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "validFrom": "2025-01-01T00:00:00Z",
                "validUntil": "2025-01-02T00:00:00Z",
            }
        }
    ).encode()


def test_is_revoked():
    # 0x01 -> [1,0,0,0,0,0,0,0] (LSB-first)
    s = _subject(bytes([0x01]))
    assert is_revoked(0, s) is True
    assert is_revoked(1, s) is False


def test_is_revoked_non_revocation_purpose():
    assert is_revoked(0, _subject(bytes([0x01]), "suspension")) is False


def test_is_revoked_bit_order_and_range():
    s = _subject(bytes([0b00000000, 0b10000000]))
    assert is_revoked(15, s) is True and is_revoked(14, s) is False
    for pos in (-1, 16, 10**9):
        with pytest.raises(ValueError, match="out of range"):
            is_revoked(pos, s)


def test_is_revoked_bad_encodings():
    for enc in ("", "!!!", "AAAA", compress_to_base64url(b"\x01") + "="):
        with pytest.raises(ValueError):
            is_revoked(0, StatusListCredentialSubject(encoded_list=enc, status_purpose="revocation"))
    # truncated gzip
    good = compress_to_base64url(b"\x01" * 10)
    with pytest.raises(ValueError):
        is_revoked(0, StatusListCredentialSubject(encoded_list=good[:-6], status_purpose="revocation"))


def test_gzip_bomb_is_capped():
    import base64

    bomb = base64.urlsafe_b64encode(gzip.compress(b"\x00" * (MAX_DECODED_BYTES + 1), 1)).decode().rstrip("=")
    with pytest.raises(ValueError, match="too large"):
        is_revoked(0, StatusListCredentialSubject(encoded_list=bomb, status_purpose="revocation"))


def test_fetch_and_check_revocation_injected():
    c = Client(fetch=lambda url: _body(bytes([0x01])))
    assert fetch_and_check_revocation("https://status.example/1", 0, c) is True
    assert fetch_and_check_revocation("https://status.example/1", 1, c) is False


def test_fetch_missing_data_is_empty_credential_not_revoked():
    # Go decodes into {"data": ...}: a bare credential has no data -> empty subject -> not revoked
    bare = json.loads(_body(bytes([0x01])))["data"]
    c = Client(fetch=lambda url: json.dumps(bare).encode())
    assert fetch_and_check_revocation("https://status.example/1", 0, c) is False


def test_fetch_rejects_empty_url_and_bad_json():
    with pytest.raises(ValueError, match="URL is empty"):
        Client().fetch_status_list_credential("")
    with pytest.raises(ValueError, match="unmarshal"):
        Client(fetch=lambda u: b"not json").fetch_status_list_credential("https://x")
    with pytest.raises(ValueError, match="unmarshal"):
        Client(fetch=lambda u: b'{"data":{"credentialSubject":{"encodedList":5}}}').fetch_status_list_credential("https://x")


def test_default_http_client_against_local_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ok":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(_body(bytes([0x01])))
            else:
                self.send_response(500)
                self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        assert fetch_and_check_revocation(base + "/ok", 0) is True
        with pytest.raises(ValueError):
            fetch_and_check_revocation(base + "/bad", 0)
    finally:
        srv.shutdown()


def test_default_client_refuses_non_http_schemes(tmp_path):
    f = tmp_path / "x.json"
    f.write_bytes(_body(bytes([0x01])))
    for url in (f.as_uri(), "ftp://example.com/x", "data:application/json,{}"):
        with pytest.raises(ValueError):
            Client().fetch_status_list_credential(url)


def test_client_defaults():
    assert Client().fetch is None and Client().timeout == DEFAULT_TIMEOUT == 10.0
