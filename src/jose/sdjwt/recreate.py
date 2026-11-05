"""Recreate SD-JWT payload from disclosures (RFC 9901 §7.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jose.errors import ErrMalformed
from jose.internal.errtext import quote
from jose.sdjwt.disclosure import (
    KEY_ELLIPSIS,
    KEY_SD,
    KEY_SD_ALG,
    SD_ALG_SHA256,
    Disclosure,
    digest_of,
    parse_disclosure,
)
from jose.sdjwt.limits import MAX_DEPTH, MAX_DISCLOSURES, nests
from jose.sdjwt.path import Path, format_path, lookup, validate_path


@dataclass
class Node:
    value: Any = None
    disclosed: bool = False
    hidden: bool = False
    fields: dict[str, Node] | None = None
    hidden_fields: int = 0
    elems: list[Node] | None = None


@dataclass
class Recreated:
    claims: dict[str, Any]
    issued: Node | None = field(default=None, repr=False)
    _steps: dict[tuple[int, Any], int] = field(default_factory=dict, repr=False)
    _opened: dict[int, Disclosure] = field(default_factory=dict, repr=False)

    def issued_root(self) -> Node | None:
        return self.issued

    def disclosures(self, path: Path) -> tuple[list[Disclosure], bool]:
        try:
            validate_path(path)
        except Exception:
            return [], False
        if not lookup(self.claims, path)[1]:
            return [], False
        ds: list[Disclosure] = []
        node = 0
        for el in path:
            nxt = self._steps.get((node, el))
            if nxt is None:
                break
            node = nxt
            if nxt in self._opened:
                ds.append(self._opened[nxt])
        return ds, True

    def disclosed(self, path: Path) -> bool:
        try:
            validate_path(path)
        except Exception:
            return False
        if not lookup(self.claims, path)[1]:
            return False
        node = 0
        for el in path:
            nxt = self._steps.get((node, el))
            if nxt is None:
                return False
            node = nxt
            if nxt in self._opened:
                return True
        return True


def recreate(payload: dict[str, Any], disclosures: list[Disclosure]) -> Recreated:
    if len(disclosures) > MAX_DISCLOSURES:
        raise ErrMalformed(f"sdjwt: {len(disclosures)} disclosures, at most {MAX_DISCLOSURES}")
    if KEY_SD_ALG in payload and payload[KEY_SD_ALG] != SD_ALG_SHA256:
        alg = payload[KEY_SD_ALG]
        name = alg if isinstance(alg, str) else ""
        raise ErrMalformed(
            f"sdjwt: _sd_alg {type(alg).__name__} {quote(name)} is not supported, only {SD_ALG_SHA256!r}"
        )
    r = _Recreator()
    for given in disclosures:
        digest = digest_of(given.encoded)
        if digest in r.by_digest:
            raise ErrMalformed(f"sdjwt: disclosure {digest} given twice")
        r.by_digest[digest] = given.encoded
        r.order.append(digest)
    claims, issued, err = r.object(payload, _At(node=0))  # node 0 is the payload
    if err:
        raise err
    for digest in r.order:
        if digest not in r.seen:
            raise ErrMalformed(f"sdjwt: no digest references disclosure {digest}")
    return Recreated(claims=claims, issued=issued, _steps=r.steps, _opened=r.opened)


@dataclass
class _At:
    up: _At | None = None
    el: Any = None
    depth: int = 0
    node: int = -1

    def child(self, el: Any) -> _At:
        return _At(up=self, el=el, depth=self.depth + 1, node=-1)

    def path(self) -> str:
        p: Path = []
        n: _At | None = self
        while n and n.up is not None:
            p.insert(0, n.el)
            n = n.up
        return format_path(p, quote=quote)


class _Recreator:
    def __init__(self) -> None:
        self.by_digest: dict[str, str] = {}
        self.seen: dict[str, bool] = {}
        self.steps: dict[tuple[int, Any], int] = {}
        self.opened: dict[int, Disclosure] = {}
        self.order: list[str] = []

    def index(self, a: _At) -> int:
        if a.node < 0:
            parent = 0 if a.up is None else self.index(a.up)
            a.node = len(self.steps) + 1
            self.steps[(parent, a.el)] = a.node
        return a.node

    def value(self, v: Any, a: _At) -> tuple[Any, Node, Exception | None]:
        if a.depth + 1 > MAX_DEPTH and nests(v):
            return None, Node(), ErrMalformed(f"sdjwt: nesting deeper than {MAX_DEPTH} at {a.path()}")
        if isinstance(v, dict):
            return self.object(v, a)
        if isinstance(v, list):
            return self.array(v, a)
        return v, Node(value=v), None

    def object(self, obj: dict[str, Any], a: _At) -> tuple[dict[str, Any], Node, Exception | None]:
        if KEY_ELLIPSIS in obj:
            return {}, Node(), ErrMalformed(f'sdjwt: {KEY_ELLIPSIS!r} at {a.path()} is not an array element placeholder')
        if KEY_SD_ALG in obj and a.depth > 0:
            return {}, Node(), ErrMalformed(f"sdjwt: _sd_alg below the top level, at {a.path()}")
        out: dict[str, Any] = {}
        node = Node(value=out, fields={})
        keys = sorted(k for k in obj if k not in (KEY_SD, KEY_SD_ALG))
        for k in keys:
            v, n, err = self.value(obj[k], a.child(k))
            if err:
                return {}, Node(), err
            out[k] = v
            assert node.fields is not None
            node.fields[k] = n
        if KEY_SD not in obj:
            return out, node, None
        sd = obj[KEY_SD]
        if not isinstance(sd, list):
            return {}, Node(), ErrMalformed(f"sdjwt: _sd at {a.path()} is not an array")
        for item in sd:
            if not isinstance(item, str):
                return {}, Node(), ErrMalformed(f"sdjwt: _sd at {a.path()} holds a {type(item).__name__}, not a string")
            d, ok, err = self.match(item)
            if err:
                return {}, Node(), err
            if not ok:
                node.hidden_fields += 1
                continue
            if d.array_element:
                return {}, Node(), ErrMalformed(f"sdjwt: _sd at {a.path()} references the array element disclosure {item}")
            if d.name in out:
                return {}, Node(), ErrMalformed(
                    f"sdjwt: disclosure {item} repeats the claim {quote(d.name)} at {a.path()}"
                )
            ca = a.child(d.name)
            self.opened[self.index(ca)] = d
            v, n, err = self.value(d.value, ca)
            if err:
                return {}, Node(), err
            n.disclosed = True
            out[d.name] = v
            assert node.fields is not None
            node.fields[d.name] = n
        return out, node, None

    def array(self, arr: list[Any], a: _At) -> tuple[list[Any], Node, Exception | None]:
        out: list[Any] = []
        node = Node(value=out, elems=[])
        for el in arr:
            digest, is_ph = _placeholder(el)
            if not is_ph:
                v, n, err = self.value(el, a.child(len(out)))
                if err:
                    return [], Node(), err
                out.append(v)
                assert node.elems is not None
                node.elems.append(n)
                continue
            d, ok, err = self.match(digest)
            if err:
                return [], Node(), err
            if not ok:
                assert node.elems is not None
                node.elems.append(Node(hidden=True))
                continue
            if not d.array_element:
                return [], Node(), ErrMalformed(
                    f"sdjwt: array element at {a.path()} references the object property disclosure {digest}"
                )
            ca = a.child(len(out))
            self.opened[self.index(ca)] = d
            v, n, err = self.value(d.value, ca)
            if err:
                return [], Node(), err
            n.disclosed = True
            out.append(v)
            assert node.elems is not None
            node.elems.append(n)
        node.value = out
        return out, node, None

    def match(self, digest: str) -> tuple[Disclosure, bool, Exception | None]:
        if self.seen.get(digest):
            return Disclosure(), False, ErrMalformed(f"sdjwt: digest {quote(digest[:64])} appears more than once")
        self.seen[digest] = True
        encoded = self.by_digest.get(digest)
        if encoded is None:
            return Disclosure(), False, None
        try:
            d = parse_disclosure(encoded)
        except ErrMalformed as e:
            return Disclosure(), False, e
        return d, True, None


def _placeholder(el: Any) -> tuple[str, bool]:
    if not isinstance(el, dict) or len(el) != 1:
        return "", False
    digest = el.get(KEY_ELLIPSIS)
    if not isinstance(digest, str):
        return "", False
    return digest, True
