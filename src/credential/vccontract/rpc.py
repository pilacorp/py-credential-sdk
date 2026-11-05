from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any


MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class JsonRpc:
    def __init__(self, url: str) -> None:
        if not url:
            raise ValueError("RPC URL is required")
        if urllib.parse.urlparse(url).scheme not in ("http", "https"):
            # urllib would happily open file:// and ftp:// URLs
            raise ValueError("RPC URL must be http(s)")
        self.url = url
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data = resp.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("RPC response too large")
        payload = json.loads(data)
        if payload.get("error"):
            raise ValueError(str(payload["error"]))
        return payload.get("result")
