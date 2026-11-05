"""The error model of package dc (Go: digitalcredential/errors.go).

Codes name why Parse or Credential.verify rejected a token. The strings are
part of the API: a caller may branch on them and store them.

Go's errors.Is/errors.As become `errors_is(err, *sentinels)` (walks __cause__
and the extra causes of combined errors) and `except DigitalCredentialError`.
"""

from __future__ import annotations

from typing import Any

from jose.errors import ErrInvalidArgument, ErrMalformed, ErrUnsupportedAlg, ErrUnsupportedKey  # noqa: F401

# Codes (Go type Code).
MALFORMED = "MALFORMED"
TYP_INVALID = "TYP_INVALID"
ISSUER_NOT_SUPPORTED = "ISSUER_NOT_SUPPORTED"
ISSUER_NOT_ACCEPTED = "ISSUER_NOT_ACCEPTED"
ISSUER_KEY_NOT_FOUND = "ISSUER_KEY_NOT_FOUND"
ISSUER_KEY_UNAVAILABLE = "ISSUER_KEY_UNAVAILABLE"
ALG_NOT_ALLOWED = "ALG_NOT_ALLOWED"
SIGNATURE_INVALID = "SIGNATURE_INVALID"
DISCLOSURE_INVALID = "DISCLOSURE_INVALID"
EXPIRED = "EXPIRED"
NOT_YET_VALID = "NOT_YET_VALID"
AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"
VCT_NOT_ACCEPTED = "VCT_NOT_ACCEPTED"
KB_MISSING = "KB_MISSING"
KB_UNEXPECTED = "KB_UNEXPECTED"
KB_UNSUPPORTED = "KB_UNSUPPORTED"
KB_INVALID = "KB_INVALID"
KB_AUDIENCE_MISMATCH = "KB_AUDIENCE_MISMATCH"
KB_NONCE_MISMATCH = "KB_NONCE_MISMATCH"
KB_SD_HASH_MISMATCH = "KB_SD_HASH_MISMATCH"
TYPE_METADATA_NOT_FOUND = "TYPE_METADATA_NOT_FOUND"
TYPE_METADATA_UNAVAILABLE = "TYPE_METADATA_UNAVAILABLE"
TYPE_METADATA_INVALID = "TYPE_METADATA_INVALID"
TYPE_METADATA_VIOLATED = "TYPE_METADATA_VIOLATED"
REVOKED = "REVOKED"
SUSPENDED = "SUSPENDED"
STATUS_NOT_ACCEPTED = "STATUS_NOT_ACCEPTED"
STATUS_UNAVAILABLE = "STATUS_UNAVAILABLE"


class DigitalCredentialError(ValueError):
    """A token that parse or Credential.verify rejected (Go *Error).

    `code` says why, `err` holds the cause (also __cause__), for logs only.
    errors_is reaches through it, so the sentinel of the package that refused
    the token and a resolver's or checker's own error stay matchable.
    """

    def __init__(self, code: str, err: BaseException | str | None = None) -> None:
        if isinstance(err, str):
            err = Exception(err)
        self.code = code
        self.err = err
        text = "dc: " + code
        if err is not None:
            msg = str(err)
            text += ": " + (msg[4:] if msg.startswith("dc: ") else msg)
            self.__cause__ = err
        super().__init__(text)


Error = DigitalCredentialError


class ErrKeyBindingUnsupported(Exception):
    """The credential's cnf is in a form this SDK cannot use for Key Binding."""


class ErrPolicy(Exception):
    """Verify was called with arguments, options or a dependency that cannot verify."""


_combined: dict[tuple[type, ...], type] = {}


def combine(text: str, *classes: type) -> Exception:
    """An exception that is an instance of every class given (Go: fmt.Errorf with several %w)."""
    key = tuple(classes)
    cls = _combined.get(key)
    if cls is None:
        cls = type("Combined_" + "_".join(c.__name__ for c in classes), key, {})
        _combined[key] = cls
    return cls(text)


def policy_err(msg: str, *also: type) -> Exception:
    """ErrPolicy with the fix; `also` adds sentinels it matches too (a key class, ErrUnsupportedAlg)."""
    return combine("dc: invalid verify policy: " + msg, ErrPolicy, *also)


def errors_is(err: Any, *sentinels: Any) -> bool:
    """True when err, or anything it wraps, is an instance (or is the instance) of a sentinel."""
    seen: set[int] = set()
    stack = [err]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        for s in sentinels:
            if isinstance(s, type):
                if isinstance(e, s):
                    return True
            elif e is s:
                return True
        stack.append(getattr(e, "__cause__", None))
        stack.extend(getattr(e, "causes", ()) or ())
    return False


def code_of(err: BaseException | None) -> str:
    """The Code of the first DigitalCredentialError in err's chain, "" when none."""
    e = err
    while e is not None:
        if isinstance(e, DigitalCredentialError):
            return e.code
        e = e.__cause__
    return ""
