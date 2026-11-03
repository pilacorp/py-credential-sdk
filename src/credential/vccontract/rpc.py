from __future__ import annotations

import json
import urllib.request
from typing import Any


class JsonRpc:
    def __init__(self, url: str) -> None:
        if not url:
            raise ValueError("RPC URL is required")
        self.url = url
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            payload = json.loads(resp.read())
        if payload.get("error"):
            raise ValueError(str(payload["error"]))
        return payload.get("result")
