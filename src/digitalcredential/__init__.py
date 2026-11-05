"""IETF SD-JWT VC (dc+sd-jwt, draft-ietf-oauth-sd-jwt-vc-19) on RFC 9901 SD-JWT, for the three roles
of the standard (Go: package dc, digitalcredential).

A Credential holds one SD-JWT VC string and never changes. The Issuer makes one with issue, signing
through a jose.jws Signer it supplies; the Holder reads what it receives with parse and builds what it
sends to a Verifier with Credential.present, choosing the claims to disclose and, when asked, adding a
Key Binding JWT (RFC 9901 §4.3). The Verifier checks what it receives with Credential.verify, which
resolves the Issuer's key through an issuerkey Resolver and reads the credential's status through a
StatusChecker such as a statuslist.Checker.

parse and verify raise DigitalCredentialError (alias Error) for a rejected token, with a `code` a
caller can branch on; verify raises ErrPolicy for a fault of the caller. issue and present raise the
sentinels of package jose (ErrInvalidArgument, ErrMalformed, ErrUnsupportedKey, ErrUnsupportedAlg),
plus those of jws, jwk and ErrKeyBindingUnsupported. Use errors_is(err, Sentinel) where Go uses
errors.Is.
"""

from digitalcredential.credential import Credential, parse
from digitalcredential.errors import (
    DigitalCredentialError,
    Error,
    ErrKeyBindingUnsupported,
    ErrPolicy,
    code_of,
    errors_is,
)
from digitalcredential.issue import IssueRequest, issue
from digitalcredential.issuerkey import (
    ErrIssuerNotSupported,
    ErrNoUsableKey,
    PublicKey,
    SigningKey,
    StaticResolver,
    select,
)
from digitalcredential.issuerkey_multi import multi
from digitalcredential.present import KeyBinding, PresentRequest, present, present_credential
from digitalcredential.statuslist import List, bit_at, decode_status_list, encode_status_list, is_revoked
from digitalcredential.verify import Result, verify, verify_credential
from digitalcredential.verify_options import (
    KeyBindingMode,
    with_accepted_issuers,
    with_accepted_status,
    with_accepted_vcts,
    with_all_disclosures,
    with_allowed_algs,
    with_audience,
    with_clock_skew,
    with_credential_audience,
    with_extended_vct_match,
    with_ignore_unchecked_kb_jwt,
    with_key_binding,
    with_max_kb_age,
    with_nonce,
    with_now,
    with_optional_type_metadata,
    with_status,
    with_type_metadata,
    without_status_check,
)

__all__ = [
    "Credential",
    "DigitalCredentialError",
    "Error",
    "ErrIssuerNotSupported",
    "ErrKeyBindingUnsupported",
    "ErrNoUsableKey",
    "ErrPolicy",
    "IssueRequest",
    "KeyBinding",
    "KeyBindingMode",
    "List",
    "PresentRequest",
    "PublicKey",
    "Result",
    "SigningKey",
    "StaticResolver",
    "bit_at",
    "code_of",
    "decode_status_list",
    "encode_status_list",
    "errors_is",
    "is_revoked",
    "issue",
    "multi",
    "parse",
    "present",
    "present_credential",
    "select",
    "verify",
    "verify_credential",
    "with_accepted_issuers",
    "with_accepted_status",
    "with_accepted_vcts",
    "with_all_disclosures",
    "with_allowed_algs",
    "with_audience",
    "with_clock_skew",
    "with_credential_audience",
    "with_extended_vct_match",
    "with_ignore_unchecked_kb_jwt",
    "with_key_binding",
    "with_max_kb_age",
    "with_nonce",
    "with_now",
    "with_optional_type_metadata",
    "with_status",
    "with_type_metadata",
    "without_status_check",
]
