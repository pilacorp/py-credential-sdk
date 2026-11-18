from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pila_credential.digitalcredential.typemeta.errors import ErrInvalid, ErrViolated
from pila_credential.digitalcredential.typemeta.format import SD_ALWAYS, SD_NEVER
from pila_credential.digitalcredential.typemeta.load import Metadata
from pila_credential.jose.errors import ErrInvalidArgument
from pila_credential.jose.sdjwt.recreate import Node as _Node


@dataclass
class ValidateOptions:
    all_disclosures: bool = False


def validate_claims_payload(m: Metadata | None, issued: _Node, opts: ValidateOptions | None = None) -> None:
    """Check ``issued`` (an sdjwt ``Node`` tree, e.g. ``Recreated.issued``) against the claim metadata of m."""
    if m is None or not m.vct:
        raise ErrInvalid("typemeta: ValidateClaims needs Metadata from Load")
    if not isinstance(issued, _Node):
        raise ErrInvalidArgument("typemeta: ValidateClaims needs the sdjwt Node of the issued payload")
    opts = opts or ValidateOptions()
    root = issued
    for i, c in enumerate(m.claims):
        try:
            _check_claim(c, root, opts.all_disclosures)
        except ValueError as exc:
            raise ErrViolated(f"typemeta: claims[{i}] with path {c.path!r}: {exc}") from exc


def validate_issuance(m: Metadata | None, payload: dict[str, Any], disclose: list[list[Any]]) -> None:
    """Check the claims about to be signed: each path in ``disclose`` becomes a disclosure, the rest stays in
    the clear, then validate_claims_payload with all_disclosures. Bad paths raise ErrInvalidArgument."""
    if m is None or not m.vct:
        raise ErrInvalidArgument("typemeta: ValidateIssuance needs a Metadata made by Load")
    if payload is None:
        raise ErrInvalidArgument("typemeta: ValidateIssuance of a nil payload")
    root = _issued_node(payload)
    for i, p in enumerate(disclose):
        n = root
        ok = bool(p)
        for el in p if ok else []:
            if isinstance(el, str) and n.fields is not None and el in n.fields:
                n = n.fields[el]
            elif isinstance(el, int) and not isinstance(el, bool) and n.elems is not None and 0 <= el < len(n.elems):
                n = n.elems[el]
            else:
                ok = False
                break
        if not ok:
            raise ErrInvalidArgument(f"typemeta: disclose[{i}]: path {p!r} is empty or names no claim of the payload")
        n.disclosed = True
    validate_claims_payload(m, root, ValidateOptions(all_disclosures=True))


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
                if n.fields is None:
                    raise ValueError("a key is selected in a value that is not an object (§5.6.1.2)")
                f = n.fields.get(el)
                if f is None:
                    if c.mandatory and (all_disclosures or n.hidden_fields == 0):
                        raise ValueError("a mandatory claim is not in the credential (§5.6.3)")
                    continue
                nxt.append(f)
            elif el is None:
                if n.elems is None:
                    raise ValueError("every element is selected in a value that is not an array (§5.6.1.2)")
                nxt.extend(_elems(n, all_disclosures))
            else:
                if n.elems is None:
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
    if n.elems is None:
        return []
    if not all_disclosures:
        return n.elems
    return [e for e in n.elems if not e.hidden]
