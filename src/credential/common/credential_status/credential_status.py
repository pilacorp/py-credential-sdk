from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable
from urllib.request import urlopen

from credential.common.credential_status.model import (
    StatusListCredential,
    StatusListCredentialResponse,
    StatusListCredentialSubject,
)
from credential.common.util.compress import decompress_from_base64url


@dataclass
class Client:
    fetch: Callable[[str], bytes] | None = None

    def fetch_status_list_credential(self, url: str) -> StatusListCredentialResponse:
        if not url:
            raise ValueError("statusListCredential URL is empty")
        fetcher = self.fetch or _http_get
        body = fetcher(url)
        raw = json.loads(body)
        data = raw.get("data") or raw
        subject_raw = data.get("credentialSubject") or {}
        subject = StatusListCredentialSubject(
            encoded_list=subject_raw.get("encodedList") or "",
            id=subject_raw.get("id") or "",
            status_purpose=subject_raw.get("statusPurpose") or "",
            type=subject_raw.get("type") or "",
        )
        cred = StatusListCredential(
            context=data.get("@context") or [],
            credential_subject=subject,
            id=data.get("id") or "",
            issuer=data.get("issuer") or "",
            proof=data.get("proof") or {},
            type=data.get("type") or [],
            valid_from=data.get("validFrom") or "",
            valid_until=data.get("validUntil") or "",
        )
        return StatusListCredentialResponse(data=cred)


def fetch_and_check_revocation(status_list_credential_url: str, position: int) -> bool:
    client = Client()
    resp = client.fetch_status_list_credential(status_list_credential_url)
    if resp.data.credential_subject is None:
        return False
    return is_revoked(position, resp.data.credential_subject)


def is_revoked(position: int, subject: StatusListCredentialSubject) -> bool:
    if subject.status_purpose != "revocation":
        return False
    byte_string = decompress_from_base64url(subject.encoded_list)
    max_position = len(byte_string) * 8 - 1
    if position < 0 or position > max_position:
        raise ValueError(
            f"position {position} is out of range for bitstring of length {len(byte_string)} (max position: {max_position})"
        )
    byte_index = position // 8
    bit_index = position % 8
    return ((byte_string[byte_index] >> bit_index) & 1) == 1


def _http_get(url: str) -> bytes:
    with urlopen(url) as resp:  # noqa: S310
        if resp.status != 200:
            raise ValueError(f"status list credential API returned non-200 status: {resp.status}")
        return resp.read()
