"""The timeout covers the whole fetch, not each recv (issue #3)."""

import socket
import threading
import time

import pytest

from pila_credential.digitalcredential._internal import safehttp as sh


def test_slow_body_ends_within_timeout():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
        for _ in range(100):
            try:
                c.sendall(b"x")
            except OSError:
                return
            time.sleep(0.25)

    threading.Thread(target=serve, daemon=True).start()
    t = time.monotonic()
    with pytest.raises(sh.FetchError):
        sh.get(
            sh.Client(address_check=None),
            f"http://127.0.0.1:{srv.getsockname()[1]}/",
            ["application/json"],
            sh.Limits(timeout_seconds=1, allow_http=True),
        )
    assert time.monotonic() - t < 2
    srv.close()


def test_oversized_headers_refused_while_streaming():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.recv(4096)
        try:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n")
            for i in range(80):
                c.sendall(b"X-%d: %s\r\n" % (i, b"a" * 60000))
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    with pytest.raises(sh.FetchError):
        sh.get(sh.Client(address_check=None), f"http://127.0.0.1:{srv.getsockname()[1]}/", ["application/json"],
               sh.Limits(timeout_seconds=5, allow_http=True))
    srv.close()
