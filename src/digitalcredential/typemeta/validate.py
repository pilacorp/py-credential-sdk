from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from digitalcredential.typemeta.errors import ErrInvalid, ErrViolated
from digitalcredential.typemeta.format import SD_ALWAYS, SD_NEVER
from digitalcredential.typemeta.load import Metadata


@dataclass
class ValidateOptions:
    all_disclosures: bool = False


@dataclass
class _Node:
    value: Any = None
    fields: dict[str, _Node] | None = None
    elems: list[_Node] | None = None
    disclosed: bool = False
    hidden: bool = False
    hidden_fields: int = 0


def validate_claims_payload(m: Metadata | None, issued: dict[str, Any], opts: ValidateOptions | None = None) -> None:
    if m is None or not m.vct:
        raise ErrInvalid("typemeta: ValidateClaims needs Metadata from Load")
    opts = opts or ValidateOptions()
    root = _issued_node(issued)
    for i, c in enumerate(m.claims):
        try:
            _check_claim(c, root, opts.all_disclosures)
        except ValueError as exc:
            raise ErrViolated(f"typemeta: claims[{i}] with path {c.path!r}: {exc}") from exc


def _issued_node(v: Any) -> _Node:
    n = _Node(value=v)
    if isinstance(v, dict):
        n.fields = {k: _issued_node(f) for k, f in v.items()}
    elif isinstance(v, list):
        n.elems = [_issued_node(e) for e in v]
    return n


def _check_claim(c, root: _Node, all_disclosures: bool) -> None:
    sel = [root]
    for el in c.path:
        nxt: list[_Node] = []
        for n in sel:
            if n.hidden:
                continue
            if isinstance(el, str):
                if not n.fields:
                    raise ValueError("a key is selected in a value that is not an object (§5.6.1.2)")
                f = n.fields.get(el)
                if f is None:
                    if c.mandatory and (all_disclosures or n.hidden_fields == 0):
                        raise ValueError("a mandatory claim is not in the credential (§5.6.3)")
                    continue
                nxt.append(f)
            elif el is None:
                if not n.elems:
                    raise ValueError("every element is selected in a value that is not an array (§5.6.1.2)")
                nxt.extend(_elems(n, all_disclosures))
            else:
                if not n.elems:
                    raise ValueError("an index is selected in a value that is not an array (§5.6.1.2)")
                es = _elems(n, all_disclosures)
                if el >= len(es):
                    if c.mandatory:
                        raise ValueError("a mandatory claim is not in the credential (§5.6.3)")
                    continue
                nxt.append(es[el])
        sel = nxt
    for n in sel:
        sd = n.disclosed or n.hidden
        if c.sd == SD_ALWAYS and not sd:
            raise ValueError("a selected claim is not selectively disclosable, and sd is always (§5.6.4)")
        if c.sd == SD_NEVER and sd:
            raise ValueError("a selected claim is selectively disclosable, and sd is never (§5.6.4)")


def _elems(n: _Node, all_disclosures: bool) -> list[_Node]:
    if not n.elems:
        return []
    if not all_disclosures:
        return n.elems
    return [e for e in n.elems if not e.hidden]
