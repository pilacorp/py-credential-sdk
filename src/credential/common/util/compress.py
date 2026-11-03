from __future__ import annotations

import base64
import gzip
import io


def compress(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(data)
    return buf.getvalue()


def decompress(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
        return gz.read()


def compress_to_base64(data: bytes) -> str:
    return base64.standard_b64encode(compress(data)).decode("ascii")


def decompress_from_base64(data: str) -> bytes:
    return decompress(base64.standard_b64decode(data))


def compress_to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(compress(data)).decode("ascii").rstrip("=")


def decompress_from_base64url(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return decompress(base64.urlsafe_b64decode(data + pad))
