"""The SD-JWT VC object and its compact serialization: RFC 9901 §4 (Go: credential.go)."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from jose.errors import ErrInvalidArgument
from jose.sdjwt import Disclosure, split

from digitalcredential.errors import MALFORMED, DigitalCredentialError


class Credential:
    """One SD-JWT VC in compact form, an SD-JWT or an SD-JWT+KB (RFC 9901 §4).

    It holds only the string it was made from and never changes. parse, issue
    and Credential.present make one; a zero Credential ("") is not a credential.
    """

    def __init__(self, compact: str = "") -> None:
        self.compact = compact

    def serialize(self) -> str:
        """The string the credential was made from, exactly."""
        return self.compact

    def hash(self) -> str:
        """SHA-256, as 64 lowercase hex characters, of the Issuer-signed JWT exactly as held.

        That is the part of the string before the first "~" (RFC 9901 §4). The
        credential issue returns and every presentation of it have one hash.
        The signature is not normalized. Checks nothing, so take it only of a
        credential issue just returned, or one a Verifier accepted. A zero
        Credential is ErrInvalidArgument, so that it never stands for the hash of "".
        """
        if not self.compact:
            raise ErrInvalidArgument("dc: Hash of a nil or zero Credential; make one with Parse, Issue or Present")
        jwt = self.compact.split("~", 1)[0]
        return sha256(jwt.encode("utf-8")).hexdigest()

    def present(self, req: Any, ctx: Any = None) -> "Credential":
        from digitalcredential.present import present

        return present(self, req, ctx)

    def verify(self, issuers: Any, *opts: Any, ctx: Any = None) -> Any:
        from digitalcredential.verify import verify

        return verify(self, issuers, *opts, ctx=ctx)


def parse(compact: str) -> Credential:
    """Read compact, a credential as received, and keep the string as is.

    It checks only the structure with sdjwt.split: it reads no header, payload
    or signature, so it checks nothing a credential claims. A string split
    refuses is DigitalCredentialError MALFORMED wrapping that error (a jose
    ErrMalformed).
    """
    try:
        split(compact)
    except Exception as exc:
        raise DigitalCredentialError(MALFORMED, exc) from exc
    return Credential(compact)


def compact_sd_jwt(issuer_jwt: str, disclosures: list[Disclosure | str]) -> str:
    """An SD-JWT in compact form (RFC 9901 §4): the Issuer-signed JWT, then each disclosure, each followed by "~"."""
    out = [issuer_jwt, "~"]
    for d in disclosures:
        out.append(d if isinstance(d, str) else d.encoded)
        out.append("~")
    return "".join(out)
