from __future__ import annotations

import http.client
import json
import socket
import urllib.parse
from typing import Any

from pila_credential._deadline import Deadline

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = 30.0


class JsonRpc:
    def __init__(self, url: str, timeout: float = TIMEOUT_SECONDS) -> None:
        if not url:
            raise ValueError("RPC URL is required")
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            # file:// and ftp:// must never be opened
            raise ValueError("RPC URL must be http(s)")
        self.url = url
        self._u = u
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode("utf-8")
        u = self._u
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        dl = Deadline(self.timeout)

        class Conn(cls):  # type: ignore[valid-type, misc]
            def connect(self) -> None:
                if cls is http.client.HTTPSConnection:
                    raw = socket.create_connection((self.host, self.port), self.timeout)
                    dl.track(raw)
                    tls = self._context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
                    dl.track(tls)
                    tls.do_handshake()
                    self.sock = tls
                else:
                    super().connect()
                    dl.track(self.sock)

        conn = Conn(u.hostname, u.port, timeout=self.timeout)
        dl.start()
        try:
            conn.request("POST", (u.path or "/") + ("?" + u.query if u.query else ""), body, {"Content-Type": "application/json"})
            resp = conn.getresponse()  # http.client never follows redirects
            if resp.status != 200:
                raise ValueError(f"RPC HTTP error {resp.status}")
            data = resp.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            if dl.expired.is_set() or isinstance(exc, TimeoutError):
                raise ValueError("RPC call timed out") from exc
            if isinstance(exc, ValueError):
                raise
            raise ValueError(f"RPC request failed: {type(exc).__name__}") from exc
        finally:
            dl.cancel()
            conn.close()
        if dl.expired.is_set():  # a shut-down socket can end the read early without an error
            raise ValueError("RPC call timed out")
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("RPC response too large")
        try:
            payload = json.loads(data)
        except ValueError as exc:
            raise ValueError("RPC response is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("RPC response is not a JSON object")
        if payload.get("error"):
            raise ValueError(str(payload["error"]))
        if "result" not in payload:
            raise ValueError("RPC response has no result")
        return payload["result"]
