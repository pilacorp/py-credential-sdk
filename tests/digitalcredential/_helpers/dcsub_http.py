"""Local HTTP(S) test servers for the digitalcredential subpackage tests (stand-in for httptest)."""

from __future__ import annotations

import datetime
import ipaddress
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from digitalcredential.internal.safehttp import Client


class Req:
    def __init__(self, h: BaseHTTPRequestHandler) -> None:
        self.path = h.path
        self.headers = h.headers


class Reply:
    def __init__(self, body=b"", status=200, headers=None, ctype="application/json") -> None:
        self.body = body.encode() if isinstance(body, str) else body
        self.status = status
        self.headers = dict(headers or {})
        if ctype is not None:
            self.headers.setdefault("Content-Type", ctype)


def redirect(location: str, status: int = 302) -> Reply:
    return Reply(b"", status, {"Location": location}, ctype=None)


_CERT = {}


def _cert():
    if not _CERT:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256())
        )
        d = tempfile.mkdtemp()
        with open(d + "/c.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(d + "/k.pem", "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _CERT["dir"] = d
    return _CERT["dir"]


class Server:
    """handler(Req) -> Reply. `.url` is http(s)://127.0.0.1:port; `.hits` counts requests."""

    def __init__(self, handler, tls: bool = False) -> None:
        self.hits = 0
        self.paths: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):  # noqa: D401
                pass

            def do_GET(self):  # noqa: N802
                outer.hits += 1
                outer.paths.append(self.path)
                r = handler(Req(self))
                try:
                    self.send_response(r.status)
                    for k, v in r.headers.items():
                        self.send_header(k, v)
                    if callable(r.body):
                        self.end_headers()
                        r.body(self.wfile)
                        return
                    self.send_header("Content-Length", str(len(r.body)))
                    self.end_headers()
                    self.wfile.write(r.body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.tls = tls
        if tls:
            d = _cert()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(d + "/c.pem", d + "/k.pem")
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def client(self) -> Client:
        """A trusted client (no address check) that trusts the test certificate."""
        ctx = ssl.create_default_context(cafile=_cert() + "/c.pem") if self.tls or True else None
        return Client(address_check=None, ssl_context=ctx)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def plain_client() -> Client:
    return Client(address_check=None, ssl_context=ssl.create_default_context(cafile=_cert() + "/c.pem"))


def routed_client(server: Server, urls: list[str] | None = None) -> Client:
    """A client that sends every URL, whatever its host or port, to `server` (the Go tests dial
    every host to the httptest server). `urls` collects the logical URLs requested."""
    import http.client
    from urllib.parse import urlsplit

    from digitalcredential.internal.safehttp import Headers, Response

    ctx = ssl.create_default_context(cafile=_cert() + "/c.pem")
    ctx.check_hostname = False

    def transport(url: str, headers: dict, timeout: float) -> Response:
        if urls is not None:
            urls.append(url)
        u = urlsplit(url)
        if server.tls:
            conn = http.client.HTTPSConnection("127.0.0.1", server.port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=timeout)
        conn.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""), headers={**headers, "Host": u.netloc})
        r = conn.getresponse()
        return Response(r.status, Headers(r.getheaders()), r.read, conn.close)

    return Client(transport=transport, address_check=None)
