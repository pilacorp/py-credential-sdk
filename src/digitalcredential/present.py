"""Presenting an SD-JWT VC on the Holder side: RFC 9901 §7.2 (selection §4, §4.2.6; Key Binding JWT
§4.3, §4.3.1), claims path pointers of OpenID4VP 1.0 §7.1.1, and draft-ietf-oauth-sd-jwt-vc-19
§2.2.2.3 (cnf) (Go: present.go)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrMalformed
from jose.jws import jws as jose_jws
from jose.sdjwt import Disclosure, KBClaims, new_kb_jwt, recreate, sd_hash, split
from jose.sdjwt.path import Path, format_path

from digitalcredential.claims import is_str
from digitalcredential.cnf import ErrNoCnf, holder_key
from digitalcredential.credential import Credential, compact_sd_jwt
from digitalcredential.errors import ErrKeyBindingUnsupported, combine, errors_is
from digitalcredential.issue import BACKGROUND

TYP_KB_JWT = "kb+jwt"


@dataclass
class KeyBinding:
    """The content of a Key Binding JWT (RFC 9901 §4.3). Every field but claims is required.

    signer must hold the private key of the credential's cnf.jwk; that key decides the alg.
    claims are other claims of the Key Binding JWT (a protocol's own, such as
    transaction_data_hashes); it must not hold iat, aud, nonce or sd_hash.
    """

    signer: Any = None
    audience: str = ""
    nonce: str = ""
    issued_at: datetime | None = None
    claims: dict[str, Any] | None = None


@dataclass
class PresentRequest:
    """What Credential.present sends to a Verifier.

    reveal lists claims path pointers (OpenID4VP 1.0 §7.1.1): a str selects an object key, a
    non-negative int an array index, None every element of an array. Empty sends no disclosure.
    key_binding asks for a Key Binding JWT (RFC 9901 §4.3); None sends none.
    """

    reveal: list[Path] = field(default_factory=list)
    key_binding: KeyBinding | None = None


def present(c: Credential | None, req: PresentRequest, ctx: Any = None) -> Credential:
    """What a Holder sends to a Verifier (RFC 9901 §7.2): the Issuer-signed JWT with the
    disclosures req.reveal selects and, when req.key_binding is set, a Key Binding JWT.

    Verifies neither the Issuer's signature nor any claim: the Holder checks the credential when
    it receives it. Each path of req.reveal is resolved as OpenID4VP 1.0 §7.1.1 says: a missing key
    drops that element from the selection and a missing index drops that array, while a string
    meeting a selected element that is not an object, None or an index meeting one that is not an
    array, or an empty final selection is ErrInvalidArgument. Each selected element sends the
    disclosure of that claim, if concealed, and those of its concealed ancestors (§4.2.6), never a
    descendant's. Disclosures go out each once, in the order of the credential.

    Errors: a zero Credential: ErrInvalidArgument; a credential that is not an SD-JWT, or already
    has a Key Binding JWT (§7.2): ErrMalformed; crit or b64 in the Issuer-signed header:
    ErrUnsupportedHeader; with key_binding, a credential with no cnf: ErrInvalidArgument; a cnf this
    SDK cannot bind: ErrKeyBindingUnsupported (the second also ErrUnsupportedKey); a cnf the Issuer
    got wrong: ErrMalformed (and jwk ErrBadKey for a non-object, symmetric or broken key); new_kb_jwt
    errors unchanged.
    """
    if c is None or not c.compact:
        raise ErrInvalidArgument("dc: Present on a nil or zero Credential; make one with Parse or Issue")
    if req is None:
        req = PresentRequest()
    issuer_jwt, encoded, kb_jwt = split(c.compact)
    if kb_jwt != "":
        raise ErrMalformed("dc: Present takes an SD-JWT, not an SD-JWT+KB (RFC 9901 §7.2)")
    raw = jose_jws.unverified_payload(issuer_jwt)
    payload = jose_json.decode_json_object(raw)
    r = recreate(payload, [_parsed(e) for e in encoded])

    # Keyed by digest: many paths can name one large ancestor.
    keep: dict[str, str] = {}
    for i, p in enumerate(req.reveal or []):
        try:
            paths = select_claims(r.claims, p)
        except ValueError as e:
            raise ErrInvalidArgument(f"dc: Reveal[{i}] {e}") from None
        for cp in paths:
            ds, ok = r.disclosures(cp)
            if not ok:
                raise ErrInvalidArgument(
                    f"dc: Reveal[{i}] selects {format_path(cp)}, which is not a claim of the credential"
                )
            for d in ds:
                keep[d.digest] = d.encoded
    send = set(keep.values())
    # split refuses a disclosure given twice, so each goes out once, in the order of the credential.
    sent = [e for e in encoded if e in send]
    sd_jwt = compact_sd_jwt(issuer_jwt, sent)
    kb = req.key_binding
    if kb is None:
        return Credential(sd_jwt)

    try:
        holder = holder_key(payload, r)
    except ErrNoCnf:
        raise ErrInvalidArgument(
            "dc: KeyBinding given, but the credential has no cnf claim: it binds no Holder key, so it cannot "
            "carry a Key Binding JWT; call Present with KeyBinding nil"
        ) from None
    except Exception as e:
        if errors_is(e, ErrKeyBindingUnsupported):
            raise combine(
                f"{e}; call Present with KeyBinding nil, or use a library that supports this cnf", type(e)
            ) from e
        raise
    binding = new_kb_jwt(
        BACKGROUND if ctx is None else ctx,
        kb.signer,
        holder,
        KBClaims(
            audience=kb.audience,
            nonce=kb.nonce,
            issued_at=kb.issued_at if kb.issued_at is not None else _zero_time(),
            sd_hash=sd_hash(sd_jwt),
            extra=kb.claims,
        ),
    )
    return Credential(sd_jwt + binding)


def _zero_time() -> datetime:
    from datetime import timezone

    return datetime.fromtimestamp(0, tz=timezone.utc)


def _parsed(encoded: str) -> Disclosure:
    # recreate reads the digest and the content of each disclosure from `encoded`.
    return Disclosure(salt="", encoded=encoded)


def select_claims(claims: dict[str, Any], p: Path) -> list[Path]:
    """Resolve the claims path pointer p over claims as OpenID4VP 1.0 §7.1.1 says and return the
    concrete path of every selected element, each holding only strings and ints. ValueError text
    names the component at fault, never a claim value."""
    if len(p) == 0:
        raise ValueError("is empty; a claims path pointer has at least one component (OpenID4VP 1.0 §7)")
    sel: list[tuple[Any, Path]] = [(claims, [])]
    for i, comp in enumerate(p):
        nxt: list[tuple[Any, Path]] = []
        if comp is None:
            for value, path in sel:
                if not isinstance(value, list):
                    raise ValueError(f"component {i} is null, and {_where(path)} is not an array")
                nxt.extend((v, path + [j]) for j, v in enumerate(value))
        elif is_str(comp):
            for value, path in sel:
                if not isinstance(value, dict):
                    raise ValueError(f"component {i} is a key, and {_where(path)} is not an object")
                if comp in value:
                    nxt.append((value[comp], path + [comp]))
        elif isinstance(comp, int) and not isinstance(comp, bool):
            if comp < 0:
                raise ValueError(f"component {i} is a negative index")
            for value, path in sel:
                if not isinstance(value, list):
                    raise ValueError(f"component {i} is an index, and {_where(path)} is not an array")
                if comp < len(value):
                    nxt.append((value[comp], path + [comp]))
        else:
            raise ValueError(f"component {i} is a {type(comp).__name__}; a component is a string, a non-negative int or None")
        sel = nxt
    if not sel:
        raise ValueError(f"{format_path(p)} selects no claim of the credential")
    return [path for _, path in sel]


def _where(p: Path) -> str:
    return "the top level" if len(p) == 0 else format_path(p)


present_credential = present  # legacy name
