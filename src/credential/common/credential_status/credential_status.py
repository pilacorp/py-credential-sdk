from __future__ import annotations

import gzip
import io
import json
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from credential.common.credential_status.model import (
    StatusListCredential,
    StatusListCredentialResponse,
    StatusListCredentialSubject,
)
from credential.common.sdjwt.helper import b64url_decode

DEFAULT_TIMEOUT = 10.0  # Go: http.Client{Timeout: 10s}
# Go reads and gunzips without a bound; these caps are hardening beyond Go (a status
# list is at most a few KiB compressed / tens of KiB decoded in practice).
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_DECODED_BYTES = 64 * 1024 * 1024


@dataclass
class Client:
    """Fetches status list credentials. `fetch(url) -> bytes` is the injection point (tests, custom HTTP)."""

    fetch: Callable[[str], bytes] | None = None
    timeout: float = DEFAULT_TIMEOUT

    def fetch_status_list_credential(self, url: str) -> StatusListCredentialResponse:
        if not url:
            raise ValueError("statusListCredential URL is empty")
        body = (self.fetch or self._http_get)(url)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("status list credential response body is too large")
        try:
            raw = json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"failed to unmarshal status list credential JSON: {exc}") from exc
        return _parse_response(raw)

    def _http_get(self, url: str) -> bytes:
        try:
            resp = _OPENER.open(url, timeout=self.timeout)  # noqa: S310 (http/https only, see _OPENER)
        except Exception as exc:
            raise ValueError(f"failed to call status list credential endpoint: {exc}") from exc
        if resp is None:  # no handler for the scheme (file:, ftp:, data: ...)
            raise ValueError(f"failed to call status list credential endpoint: unsupported protocol scheme in {url!r}")
        with resp:
            if resp.status != 200:
                raise ValueError(f"status list credential API returned non-200 status: {resp.status}")
            body = resp.read(MAX_RESPONSE_BYTES + 1)
        return body


def _build_opener() -> urllib.request.OpenerDirector:
    # Go's http.Client speaks http/https only; urllib's default opener also opens file:// and ftp://.
    op = urllib.request.OpenerDirector()
    for h in (
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        op.add_handler(h)
    return op


_OPENER = _build_opener()


def _str(v: Any, name: str) -> str:
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError(f"failed to unmarshal status list credential JSON: {name} must be a string")
    return v


def _str_list(v: Any, name: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"failed to unmarshal status list credential JSON: {name} must be an array of strings")
    return list(v)


def _parse_response(raw: Any) -> StatusListCredentialResponse:
    # Go decodes into {"data": {...}}: a body without "data" is an empty credential.
    if not isinstance(raw, dict):
        raise ValueError("failed to unmarshal status list credential JSON: expected an object")
    data = raw.get("data")
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("failed to unmarshal status list credential JSON: data must be an object")
    subj = data.get("credentialSubject")
    if subj is None:
        subj = {}
    if not isinstance(subj, dict):
        raise ValueError("failed to unmarshal status list credential JSON: credentialSubject must be an object")
    proof = data.get("proof")
    if proof is not None and not isinstance(proof, dict):
        raise ValueError("failed to unmarshal status list credential JSON: proof must be an object")
    cred = StatusListCredential(
        context=_str_list(data.get("@context"), "@context"),
        credential_subject=StatusListCredentialSubject(
            encoded_list=_str(subj.get("encodedList"), "encodedList"),
            id=_str(subj.get("id"), "id"),
            status_purpose=_str(subj.get("statusPurpose"), "statusPurpose"),
            type=_str(subj.get("type"), "type"),
        ),
        id=_str(data.get("id"), "id"),
        issuer=_str(data.get("issuer"), "issuer"),
        proof=proof or {},
        type=_str_list(data.get("type"), "type"),
        valid_from=_str(data.get("validFrom"), "validFrom"),
        valid_until=_str(data.get("validUntil"), "validUntil"),
    )
    return StatusListCredentialResponse(data=cred, raw_data=data)


MIN_BITSTRING_BYTES = 16 * 1024  # W3C Bitstring Status List §2.2: at least 131,072 entries
PURPOSES = ("revocation", "suspension")


def fetch_and_check_revocation(
    status_list_credential_url: str,
    position: int,
    client: Client | None = None,
    *,
    verify: Callable[[StatusListCredentialResponse], None],
    status_purpose: str = "revocation",
) -> bool:
    """Fetch the list credential, call ``verify(resp)`` (it must raise unless the list credential's proof,
    issuer and validity hold), then read the bit. ``verify`` is required: an unsigned list decides nothing."""
    resp = (client or Client()).fetch_status_list_credential(status_list_credential_url)
    verify(resp)
    return is_revoked(position, resp.data.credential_subject, status_purpose)


def decode_bitstring(encoded_list: str) -> bytes:
    """Multibase base64url (``u`` prefix, no padding) -> gunzip. A list without the prefix (the format
    published before the prefix was written) is still read: gzip's base64 always starts ``H4sI``."""
    if encoded_list.startswith("u"):
        encoded_list = encoded_list[1:]
    compressed = b64url_decode(encoded_list)
    if not compressed:
        raise ValueError("EOF")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz:
            out = gz.read(MAX_DECODED_BYTES + 1)
    except (OSError, EOFError) as exc:
        raise ValueError(f"invalid gzip data: {exc}") from exc
    if len(out) > MAX_DECODED_BYTES:
        raise ValueError("decoded status list is too large")
    if len(out) < MIN_BITSTRING_BYTES:
        raise ValueError(f"status list has {len(out)} bytes, want at least {MIN_BITSTRING_BYTES} (Bitstring Status List §2.2)")
    return out


def is_revoked(position: int, subject: StatusListCredentialSubject, status_purpose: str = "revocation") -> bool:
    """Whether the bit at ``position`` is set. Index 0 is the left-most bit, the high bit of the first byte
    (Bitstring Status List §2.2). The list's statusPurpose must be the one asked for; any other, or an
    unknown one, raises instead of reading as "not revoked"."""
    if status_purpose not in PURPOSES:
        raise ValueError(f"unsupported statusPurpose {status_purpose!r}")
    if subject.status_purpose != status_purpose:
        raise ValueError(
            f"status list statusPurpose {subject.status_purpose!r} does not match the credential's {status_purpose!r}"
        )
    byte_string = decode_bitstring(subject.encoded_list)
    max_position = len(byte_string) * 8 - 1
    if position < 0 or position > max_position:
        raise ValueError(
            f"position {position} is out of range for bitstring of length {len(byte_string)} (max position: {max_position})"
        )
    return ((byte_string[position // 8] >> (7 - position % 8)) & 1) == 1
