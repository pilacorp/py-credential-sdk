from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = 30.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        # a redirect would resend the POST as a bodiless GET to another host
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class JsonRpc:
    def __init__(self, url: str, timeout: float = TIMEOUT_SECONDS) -> None:
        if not url:
            raise ValueError("RPC URL is required")
        if urllib.parse.urlparse(url).scheme not in ("http", "https"):
            # urllib would happily open file:// and ftp:// URLs
            raise ValueError("RPC URL must be http(s)")
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        deadline = time.monotonic() + self.timeout
        try:
            with _opener.open(req, timeout=self.timeout) as resp:  # noqa: S310
                chunks, size = [], 0
                while True:
                    # ponytail: deadline checked between reads; a single stalled recv is bounded by timeout
                    if time.monotonic() > deadline:
                        raise ValueError("RPC call timed out")
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ValueError("RPC response too large")
                    chunks.append(chunk)
        except urllib.error.HTTPError as exc:
            raise ValueError(f"RPC HTTP error {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ValueError(f"RPC request failed: {exc.reason}") from exc
        try:
            payload = json.loads(b"".join(chunks))
        except ValueError as exc:
            raise ValueError("RPC response is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("RPC response is not a JSON object")
        if payload.get("error"):
            raise ValueError(str(payload["error"]))
        if "result" not in payload:
            raise ValueError("RPC response has no result")
        return payload["result"]
