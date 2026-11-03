"""Compact JWS with ES256 and ES256K."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from jose import base64 as jose_b64
from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrMalformed, ErrUnsupportedAlg, ErrUnsupportedKey
from jose.internal.ec import Kind, from_public_key, verify_rs
from jose.internal.errtext import quote
from jose.jws.errors import (
    ErrAlgKeyMismatch,
    ErrAlgNotAllowed,
    ErrBadKey,
    ErrBadSignature,
    ErrSelfCheck,
    ErrSignerFailed,
    ErrUnsupportedHeader,
)

AlgES256 = "ES256"
AlgES256K = "ES256K"

_MAX_HEADER_BYTES = 64 << 10
_MAX_HEADER_SEGMENT = (4 * _MAX_HEADER_BYTES + 2) // 3

_supported_algs = "the SDK supports ES256 and ES256K"

Header = dict[str, Any]


@dataclass
class _Parsed:
    header: Header
    payload: bytes
    sig: bytes
    signing_input: str


def sign(ctx: Any, signer: Any, pub: Any, header: Header | None, payload: bytes | None) -> str:
    if payload is None:
        payload = b""
    try:
        pt = from_public_key(pub)
    except Exception as e:
        raise _key_error("signer public key", e) from e
    if signer is None:
        raise ErrInvalidArgument("nil signer")
    if ctx is None:
        raise ErrInvalidArgument("nil context")
    alg = signer.alg()
    if not _is_supported_alg(alg):
        raise ErrUnsupportedAlg(f"signer alg {quote(alg)}; {_supported_algs}")
    want = _alg_of(pt.kind)
    if alg != want:
        raise ErrAlgKeyMismatch(f"signer alg {alg}, key on {pt.kind.name()} needs {want}")
    h: dict[str, Any] = dict(header or {})
    if "alg" in h and h["alg"] != alg:
        got = h["alg"]
        if not isinstance(got, str):
            got = f"of type {type(got).__name__}"
        else:
            got = quote(got)
        raise ErrInvalidArgument(f"header alg {got} differs from {alg!r}, the alg of the signer")
    _check_header_extensions(h)
    h["alg"] = alg
    header_json = jose_json.encode_json(h)
    if len(header_json) > _MAX_HEADER_BYTES:
        raise ErrInvalidArgument(
            f"header is {len(header_json)} bytes; Verify reads at most {_MAX_HEADER_BYTES}"
        )
    try:
        jose_json.decode_json_object(header_json)
    except ErrMalformed as e:
        raise ErrInvalidArgument(f"header: {e}") from e
    signing_input = jose_b64.encode_segment(header_json) + "." + jose_b64.encode_segment(payload)
    try:
        sig = signer.sign(ctx, signing_input.encode("ascii"))
    except Exception as e:
        raise ErrSignerFailed(str(e)) from e
    token = signing_input + "." + jose_b64.encode_segment(sig)
    try:
        verify(token, pub, [alg])
    except Exception as e:
        raise ErrSelfCheck(str(e)) from e
    return token


def verify(compact: str, key: Any, allowed: list[str] | None) -> tuple[Header, bytes]:
    allowed = allowed or []
    for a in allowed:
        if not _is_supported_alg(a):
            raise ErrUnsupportedAlg(f"allowed algs list {quote(a)}; {_supported_algs}")
    tok = _parse(compact)
    header, alg = tok.header, _header_str(tok.header, "alg")
    if not _is_supported_alg(alg):
        raise ErrAlgNotAllowed(f"{quote(alg)}; {_supported_algs}")
    if allowed and alg not in allowed:
        raise ErrAlgNotAllowed(f"{quote(alg)} is not in the allowed list")
    try:
        pt = from_public_key(key)
    except Exception as e:
        raise _key_error("verification key", e) from e
    if _alg_of(pt.kind) != alg:
        raise ErrAlgKeyMismatch(f"header alg {alg!r}, key on {pt.kind.name()}")
    if len(tok.sig) != 64:
        raise ErrBadSignature(f"signature is {len(tok.sig)} bytes, want 64-byte r||s")
    digest = hashlib.sha256(tok.signing_input.encode("ascii")).digest()
    try:
        verify_rs(pt, digest, tok.sig)
    except ValueError as e:
        raise ErrBadSignature(str(e)) from e
    return header, tok.payload


def unverified_header(compact: str) -> Header:
    return _parse(compact).header


def unverified_payload(compact: str) -> bytes:
    return _parse(compact).payload


def _parse(compact: str) -> _Parsed:
    parts = compact.split(".", 3)
    if len(parts) != 3:
        raise ErrMalformed("a compact JWS has three parts")
    if len(parts[0]) > _MAX_HEADER_SEGMENT:
        raise ErrMalformed(f"header is over {_MAX_HEADER_BYTES} bytes, the most this package reads")
    try:
        header_json = jose_b64.decode_segment(parts[0])
    except ErrMalformed as e:
        raise ErrMalformed(f"header: {e}") from e
    try:
        payload = jose_b64.decode_segment(parts[1])
    except ErrMalformed as e:
        raise ErrMalformed(f"payload: {e}") from e
    try:
        sig = jose_b64.decode_segment(parts[2])
    except ErrMalformed as e:
        raise ErrMalformed(f"signature: {e}") from e
    try:
        obj = jose_json.decode_json_object(header_json)
    except ErrMalformed as e:
        raise ErrMalformed(f"header: {e}") from e
    header = Header(obj)
    if not isinstance(header.get("alg"), str):
        raise ErrMalformed("header alg must be a string")
    _check_header_extensions(header)
    signing_input = compact[: len(parts[0]) + 1 + len(parts[1])]
    return _Parsed(header=header, payload=payload, sig=sig, signing_input=signing_input)


def _check_header_extensions(h: Mapping[str, Any]) -> None:
    if "crit" in h:
        raise ErrUnsupportedHeader("crit")
    if "b64" in h:
        raise ErrUnsupportedHeader("b64")


def _alg_of(kind: Kind) -> str:
    if kind is Kind.P256:
        return AlgES256
    if kind is Kind.SECP256K1:
        return AlgES256K
    raise ValueError(f"jose: invalid curve kind {kind}")


def _is_supported_alg(alg: str) -> bool:
    return alg in (AlgES256, AlgES256K)


def _key_error(what: str, err: Exception) -> Exception:
    if isinstance(err, ErrUnsupportedKey):
        return ErrUnsupportedKey(f"{what}: {err}")
    return ErrBadKey(f"{what}: {err}")


def _header_str(h: Header, name: str) -> str:
    v = h.get(name)
    return v if isinstance(v, str) else ""


def _full_media_type(v: str) -> tuple[str, bool]:
    if not v or ";" in v:
        return "", False
    if "/" not in v:
        return "application/" + v, True
    return v, True


def _lower_ascii(c: str) -> str:
    o = ord(c)
    if 65 <= o <= 90:
        return chr(o + 32)
    return c


def _equal_fold_ascii(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if _lower_ascii(a[i]) != _lower_ascii(b[i]):
            return False
    return True


def header_typ_is(h: Header, media_type: str) -> bool:
    typ, ok = _full_media_type(_header_str(h, "typ"))
    want, want_ok = _full_media_type(media_type)
    return ok and want_ok and _equal_fold_ascii(typ, want)
