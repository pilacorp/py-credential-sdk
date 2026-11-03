from __future__ import annotations

from digitalcredential.internal.safehttp import (
    ErrBlockedAddress,
    ErrBodyTooLarge,
    ErrContentTypeNotAccepted,
    ErrRedirectTargetNotAllowed,
    ErrTooManyRedirects,
    StatusError,
)

ErrURINotSupported = ValueError("statuslist: status list uri not supported")
ErrTokenType = ValueError("statuslist: token typ is not statuslist+jwt")
ErrSubjectMismatch = ValueError("statuslist: token sub is not the uri of the Referenced Token")
ErrIssuerMismatch = ValueError("statuslist: token iss is not the issuer of the Referenced Token")
ErrIssuedInFuture = ValueError("statuslist: token iat is in the future")
ErrTooOld = ValueError("statuslist: token is older than Config.MaxAge")
ErrIndexOutOfBounds = ValueError("statuslist: index outside the list")

__all__ = [
    "ErrAddressBlocked",
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
]

ErrAddressBlocked = ErrBlockedAddress
