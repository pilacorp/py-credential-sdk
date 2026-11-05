from __future__ import annotations

import json
from typing import Callable, Protocol
from urllib.parse import quote
from urllib.request import urlopen

from credential.common.verification_method.verification_method import DIDDocument, did_document_from_dict


class ResolverProvider(Protocol):
    """Resolves a DID Document by DID. Fetching/parsing only; VM selection, key
    extraction and purpose checks are free functions in this package."""

    def resolve_document(self, did: str) -> DIDDocument: ...


class HTTPResolver:
    """Fetches DID Documents from a Pila-style endpoint (``<base_url>/<did>`` -> JSON)."""

    def __init__(self, base_url: str, fetch: Callable[[str], tuple[int, bytes]] | None = None, timeout: float = 10.0) -> None:
        self.base_url = base_url
        self._fetch = fetch
        self._timeout = timeout

    def _get(self, url: str) -> tuple[int, bytes]:
        if self._fetch is not None:
            return self._fetch(url)
        with urlopen(url, timeout=self._timeout) as resp:  # noqa: S310
            return resp.status, resp.read()

    def resolve_document(self, did: str) -> DIDDocument:
        if not did:
            raise ValueError("did is empty")
        url = self.base_url + "/" + quote(did, safe="$&+=:@")
        try:
            status, body = self._get(url)
        except Exception as exc:
            raise ValueError(f"failed to make HTTP request to DID resolver: {exc}") from exc
        if status != 200:
            raise ValueError(f"DID resolver API returned non-200 status: {status}")
        try:
            return did_document_from_dict(json.loads(body))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"failed to unmarshal DID document JSON: {exc}") from exc
