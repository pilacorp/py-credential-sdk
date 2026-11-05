"""The failures Checker.status finds in a Ref's uri or in a Status List Token, and the causes of a
failed fetch. An error of status wraps at most one of them (reach it with safehttp.is_ or
digitalcredential.errors.errors_is); none is jose.ErrInvalidArgument."""

from __future__ import annotations

from digitalcredential.internal.safehttp import (
    ErrBlockedAddress,
    ErrBodyTooLarge,
    ErrContentTypeNotAccepted,
    ErrRedirectTargetNotAllowed,
    ErrTooManyRedirects,
    StatusError,
)


class StatusListError(Exception):
    """Base of the sentinels of this package."""


class ErrURINotSupported(StatusListError):
    """The uri is not an https URL with a host and no userinfo (nor, with insecure_http, an http one);
    no request is sent. Draft 21 §6.2 leaves this rule to the Relying Party."""


class ErrTokenType(StatusListError):
    """The typ of the Status List Token is not statuslist+jwt (§5.1; RFC 8725 §3.11)."""


class ErrSubjectMismatch(StatusListError):
    """The sub of the token is not the uri of the Referenced Token (§5.1, §8.3 step 4a)."""


class ErrIssuerMismatch(StatusListError):
    """The token has an iss other than the issuer of the Referenced Token (RFC 8725 §3.8)."""


class ErrIssuedInFuture(StatusListError):
    """The iat of the token is later than now plus the clock skew (SDK policy)."""


class ErrTooOld(StatusListError):
    """The iat of the token is older than Config.max_age plus the clock skew (§8.3 step 4b)."""


class ErrIndexOutOfBounds(StatusListError):
    """The index of the Referenced Token is outside the fetched Status List: the Referenced Token MUST
    be rejected (§8.3 step 6), and the caller made no mistake."""


ErrAddressBlocked = ErrBlockedAddress

__all__ = [
    "ErrAddressBlocked",
    "ErrBlockedAddress",
    "ErrBodyTooLarge",
    "ErrContentTypeNotAccepted",
    "ErrIndexOutOfBounds",
    "ErrIssuedInFuture",
    "ErrIssuerMismatch",
    "ErrRedirectTargetNotAllowed",
    "ErrSubjectMismatch",
    "ErrTokenType",
    "ErrTooManyRedirects",
    "ErrTooOld",
    "ErrURINotSupported",
    "StatusError",
    "StatusListError",
]
