"""Issuer-side selective disclosure (RFC 9901 §4.2)."""

from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any

from jose import base64 as jose_b64
from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrMalformed
from jose.sdjwt.disclosure import (
    KEY_ELLIPSIS,
    KEY_SD,
    KEY_SD_ALG,
    SD_ALG_SHA256,
    Disclosure,
    digest_of,
    reserved,
)
from jose.sdjwt.limits import MAX_DIGESTS, MAX_MIN_DIGESTS, MAX_PATHS
from jose.sdjwt.path import Path, child_path, compare_paths, format_path, lookup, validate_path


@dataclass
class ConcealOptions:
    min_digests: int = 0
    no_array_decoys: bool = False


def conceal(claims: dict[str, Any] | None, paths: list[Path], opts: ConcealOptions | None = None) -> tuple[dict[str, Any], list[Disclosure]]:
    opts = opts or ConcealOptions()
    if opts.min_digests < 0 or opts.min_digests > MAX_MIN_DIGESTS:
        raise ErrInvalidArgument(f"sdjwt: MinDigests {opts.min_digests} is outside [0, {MAX_MIN_DIGESTS}]")
    if len(paths) > MAX_PATHS:
        raise ErrInvalidArgument(f"sdjwt: {len(paths)} paths, at most {MAX_PATHS}")
    payload = _copy_claims(claims or {})
    containers = _check_claims(payload, [])
    if opts.min_digests > 0 and containers > MAX_DIGESTS // opts.min_digests:
        raise ErrInvalidArgument(
            f"sdjwt: {containers} objects and arrays × MinDigests {opts.min_digests} is over {MAX_DIGESTS} digests"
        )
    for p in paths:
        validate_path(p)
        if not lookup(payload, p)[1]:
            raise ErrInvalidArgument(f"sdjwt: path {format_path(p)} does not exist in the claims")
    order = sorted(paths, key=cmp_to_key(compare_paths))
    for i in range(1, len(order)):
        if compare_paths(order[i - 1], order[i]) == 0:
            raise ErrInvalidArgument(f"sdjwt: path {format_path(order[i])} given twice")
    c = _Concealer(opts.min_digests, opts.no_array_decoys)
    disclosures: list[Disclosure] = []
    for p in order:
        disclosures.append(c.conceal(payload, p))
    c.finish(payload)
    if paths or opts.min_digests > 0:
        payload[KEY_SD_ALG] = SD_ALG_SHA256
    return payload, disclosures


class _Concealer:
    def __init__(self, min_digests: int, no_array_decoys: bool) -> None:
        self.min_digests = min_digests
        self.no_array_decoys = no_array_decoys

    def conceal(self, payload: dict[str, Any], p: Path) -> Disclosure:
        parent, _ = lookup(payload, p[:-1])
        value, ok = lookup(parent, p[-1:])
        if not ok:
            raise ErrInvalidArgument(f"sdjwt: path {format_path(p)} does not exist in the claims")
        value = self.finish(value)
        salt = _new_salt()
        d = Disclosure(salt=salt, value=value)
        if isinstance(p[-1], str):
            d.name = p[-1]
            items: list[Any] = [salt, d.name, value]
        else:
            d.array_element = True
            items = [salt, value]
        raw = jose_json.encode_json(items)
        d.encoded = jose_b64.encode_segment(raw)
        d.digest = digest_of(d.encoded)
        if isinstance(parent, dict):
            del parent[d.name]
            digests = parent.get(KEY_SD)
            if not isinstance(digests, list):
                digests = []
            digests = list(digests)
            digests.append(d.digest)
            parent[KEY_SD] = digests
        elif isinstance(parent, list):
            idx = p[-1]
            assert isinstance(idx, int)
            parent[idx] = _ArrayDigest(d.digest)
        return d

    def finish(self, v: Any) -> Any:
        if isinstance(v, dict):
            digests_raw = v.get(KEY_SD)
            digests: list[str] = []
            if isinstance(digests_raw, list) and all(isinstance(x, str) for x in digests_raw):
                digests = list(digests_raw)
            for k, child in list(v.items()):
                if k != KEY_SD:
                    v[k] = self.finish(child)
            while len(digests) < self.min_digests:
                digests.append(_decoy())
            if not digests:
                return v
            digests.sort()
            v[KEY_SD] = list(digests)
            return v
        if isinstance(v, list):
            placeholders = 0
            for i, el in enumerate(v):
                if isinstance(el, _ArrayDigest):
                    placeholders += 1
                    continue
                v[i] = self.finish(el)
            while not self.no_array_decoys and placeholders < self.min_digests:
                i = random.randrange(len(v) + 1)
                v.insert(i, _ArrayDigest(_decoy()))
                placeholders += 1
            for i, el in enumerate(v):
                if isinstance(el, _ArrayDigest):
                    v[i] = {KEY_ELLIPSIS: str(el)}
            return v
        return v


class _ArrayDigest(str):
    pass


def _decoy() -> str:
    return jose_b64.encode_segment(hashlib.sha256(os.urandom(16)).digest())


def _new_salt() -> str:
    return jose_b64.encode_segment(os.urandom(16))


def _copy_claims(claims: dict[str, Any]) -> dict[str, Any]:
    raw = jose_json.encode_json(claims)
    try:
        obj = jose_json.decode_json_object(raw)
    except ErrMalformed as e:
        raise ErrInvalidArgument(f"sdjwt: claims: {e}") from e
    return obj


def _check_claims(v: Any, p: Path) -> int:
    if isinstance(v, dict):
        containers = 1
        for k, child in v.items():
            if reserved(k):
                raise ErrInvalidArgument(f'sdjwt: claims hold the reserved name {k!r} at {format_path(p)}')
            containers += _check_claims(child, child_path(p, k))
        return containers
    if isinstance(v, list):
        containers = 1
        for i, child in enumerate(v):
            containers += _check_claims(child, child_path(p, i))
        return containers
    return 0
