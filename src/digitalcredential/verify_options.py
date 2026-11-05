"""The options of Credential.verify (Go: verify_options.go). Each sets what the standards leave to the
Verifier; when one is not passed, verify follows the standard's rule where it sets one and otherwise
the SDK default its docstring names, which never accepts what the standard rejects.

Each option may be passed once per call: a second one is ErrPolicy, never "last one wins". An option
holds no state, so one value can be reused across calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any, Callable, Protocol

from jose.errors import ErrUnsupportedAlg

from digitalcredential.errors import policy_err

SUPPORTED_ALGS = ("ES256", "ES256K")
DEFAULT_MAX_KB_AGE = timedelta(minutes=5)
DEFAULT_CLOCK_SKEW = timedelta(minutes=1)


class KeyBindingMode(IntEnum):
    """When verify requires Key Binding. RFC 9901 §7.3 step 1 leaves it to the Verifier's policy."""

    # The default: required exactly when the credential has cnf; a credential without cnf passes
    # with Result.key_bound False.
    IF_CNF = 0
    # Required for every credential, so one without cnf is rejected too, as KB_UNSUPPORTED.
    REQUIRED = 1
    # Checks no Key Binding JWT; one that comes is KB_UNEXPECTED unless with_ignore_unchecked_kb_jwt.
    NOT_REQUIRED = 2


class StatusChecker(Protocol):
    """status(ref, iss) returns the raw status of the Referenced Token ref points to
    (draft-ietf-oauth-status-list-21 §8); a statuslist.Checker is one. Verify reads an exception
    of status in this order: ErrIndexOutOfBounds is MALFORMED; one wrapping jose ErrInvalidArgument
    is ErrPolicy (keeping a key sentinel it also wraps); any other is STATUS_UNAVAILABLE."""

    def status(self, ref: Any, iss: str) -> int: ...


def _seconds(d: Any) -> float:
    return d.total_seconds() if isinstance(d, timedelta) else float(d)


@dataclass
class VerifyConfig:
    algs: list[str] = field(default_factory=lambda: list(SUPPORTED_ALGS))
    key_binding: KeyBindingMode = KeyBindingMode.IF_CNF
    ignore_unchecked_kb: bool = False
    audience: str = ""
    nonce: str = ""
    cred_audience: str = ""
    max_kb_age: timedelta = DEFAULT_MAX_KB_AGE
    skew: timedelta = DEFAULT_CLOCK_SKEW
    status: StatusChecker | None = None
    skip_status: bool = False
    accepted_status: list[int] = field(default_factory=lambda: [0x00])
    accepted_issuers: list[str] | None = None
    accepted_vcts: list[str] | None = None
    extended_vct: bool = False
    types: Any = None
    types_optional: bool = False
    all_disclosures: bool = False
    now: datetime | None = None
    seen: set[str] = field(default_factory=set)


class VerifyOption:
    """One choice of verify; the with_* functions of this module make them. name is the function,
    for the error texts and the duplicate check, and set applies it."""

    def __init__(self, name: str, set_fn: Callable[[VerifyConfig], None]) -> None:
        self.name = name
        self.set_fn = set_fn

    def set_on(self, c: VerifyConfig) -> None:
        if self.name in c.seen:
            raise policy_err(f"{self.name} is passed more than once; pass each option once")
        c.seen.add(self.name)
        self.set_fn(c)


def new_verify_config(opts: tuple[Any, ...] | list[Any]) -> VerifyConfig:
    """The configuration of one call from opts: the defaults, then the options in the order passed.
    Its errors are all ErrPolicy, naming the option."""
    c = VerifyConfig()
    for i, o in enumerate(opts):
        if o is None:
            raise policy_err(f"option {i} is nil")
        o.set_on(c)
    if "with_status" in c.seen and "without_status_check" in c.seen:
        raise policy_err("with_status and without_status_check are both passed; pass one")
    type_option = "with_type_metadata" in c.seen or "with_optional_type_metadata" in c.seen
    if "with_type_metadata" in c.seen and "with_optional_type_metadata" in c.seen:
        raise policy_err("with_type_metadata and with_optional_type_metadata are both passed; pass one")
    if c.all_disclosures and not type_option:
        raise policy_err(
            "with_all_disclosures without with_type_metadata or with_optional_type_metadata checks nothing; pass one of them"
        )
    if c.extended_vct and (c.accepted_vcts is None or not type_option):
        raise policy_err(
            "with_extended_vct_match needs with_accepted_vcts, the types it matches, and with_type_metadata or "
            "with_optional_type_metadata, the extends chain it matches them on"
        )
    if c.key_binding == KeyBindingMode.REQUIRED and (c.audience == "" or c.nonce == ""):
        raise policy_err(
            "with_key_binding(REQUIRED) needs with_audience and with_nonce, which every Key Binding JWT is checked against (RFC 9901 §7.3 step 5f)"
        )
    if c.now is None:
        c.now = datetime.now(timezone.utc)
    return c


def with_allowed_algs(*algs: str) -> VerifyOption:
    """The algorithms accepted for the Issuer-signed JWT and the Key Binding JWT (RFC 8725 §3.1;
    RFC 9901 §7.1 step 2a, §7.3 step 5b). Not passed, ES256 and ES256K are. No alg, or one other
    than these two, is ErrPolicy, the second also ErrUnsupportedAlg. algs is copied."""
    algs = tuple(algs)

    def set_(c: VerifyConfig) -> None:
        if not algs:
            raise policy_err("with_allowed_algs needs at least one alg")
        for a in algs:
            if a not in SUPPORTED_ALGS:
                raise policy_err(f"with_allowed_algs: {a!r}; this SDK verifies ES256 and ES256K", ErrUnsupportedAlg)
        c.algs = list(algs)

    return VerifyOption("with_allowed_algs", set_)


def with_key_binding(m: KeyBindingMode | int) -> VerifyOption:
    """When Key Binding is required (RFC 9901 §7.3 step 1); not passed, IF_CNF. A value that is none
    of the three modes is ErrPolicy, and so is REQUIRED without with_audience and with_nonce."""

    def set_(c: VerifyConfig) -> None:
        if isinstance(m, bool) or not isinstance(m, int) or m not in (0, 1, 2):
            raise policy_err(f"with_key_binding({m!r}) is none of IF_CNF, REQUIRED and NOT_REQUIRED")
        c.key_binding = KeyBindingMode(m)

    return VerifyOption("with_key_binding", set_)


def with_ignore_unchecked_kb_jwt() -> VerifyOption:
    """Accept a Key Binding JWT that verify does not check, because Key Binding is not required, and
    ignore it: key_bound stays False and key_binding_claims None. Not passed, such a Key Binding JWT
    is KB_UNEXPECTED."""

    def set_(c: VerifyConfig) -> None:
        c.ignore_unchecked_kb = True

    return VerifyOption("with_ignore_unchecked_kb_jwt", set_)


def with_audience(aud: str) -> VerifyOption:
    """The aud this Verifier expects in the Key Binding JWT (RFC 9901 §7.3 step 5f), compared byte
    for byte. Needed whenever a Key Binding JWT is checked; without it that is ErrPolicy."""

    def set_(c: VerifyConfig) -> None:
        c.audience = aud

    return VerifyOption("with_audience", set_)


def with_nonce(nonce: str) -> VerifyOption:
    """The nonce of this transaction, which the Key Binding JWT must carry (RFC 9901 §7.3 step 5f).
    Verify keeps no state: issuing a fresh nonce per transaction and accepting it once, the replay
    check of step 5f, is the caller's."""

    def set_(c: VerifyConfig) -> None:
        c.nonce = nonce

    return VerifyOption("with_nonce", set_)


def with_credential_audience(aud: str) -> VerifyOption:
    """How this Verifier names itself in the Issuer-signed JWT's aud (RFC 7519 §4.1.3), read only when
    the credential has aud. Not passed, a credential with aud is AUDIENCE_MISMATCH."""

    def set_(c: VerifyConfig) -> None:
        c.cred_audience = aud

    return VerifyOption("with_credential_audience", set_)


def with_max_kb_age(d: timedelta | float) -> VerifyOption:
    """How old the Key Binding JWT iat may be (RFC 9901 §7.3 step 5e); not passed, 5 minutes. A value
    that is not positive is ErrPolicy. A number is seconds."""

    def set_(c: VerifyConfig) -> None:
        if _seconds(d) <= 0:
            raise policy_err(f"with_max_kb_age({d!r}) is not positive")
        c.max_kb_age = d if isinstance(d, timedelta) else timedelta(seconds=d)

    return VerifyOption("with_max_kb_age", set_)


def with_clock_skew(d: timedelta | float) -> VerifyOption:
    """The leeway on exp and nbf of the credential and the Key Binding JWT and on the Key Binding JWT
    iat; not passed, 1 minute. 0 allows no skew; a negative value is ErrPolicy. A number is seconds."""

    def set_(c: VerifyConfig) -> None:
        if _seconds(d) < 0:
            raise policy_err(f"with_clock_skew({d!r}) is negative")
        c.skew = d if isinstance(d, timedelta) else timedelta(seconds=d)

    return VerifyOption("with_clock_skew", set_)


def with_status(s: StatusChecker | None) -> VerifyOption:
    """The StatusChecker for a credential with status_list (draft-ietf-oauth-status-list-21 §8.3).
    Not passed, such a credential is ErrPolicy, unless without_status_check is, so that a forgotten
    checker never accepts a revoked credential. None is ErrPolicy."""

    def set_(c: VerifyConfig) -> None:
        if s is None:
            raise policy_err("with_status(None); pass a StatusChecker such as a statuslist.Checker")
        c.status = s

    return VerifyOption("with_status", set_)


def without_status_check() -> VerifyOption:
    """Accept a credential with status without checking it; Result.status_skipped says so. The shape
    of status is checked anyway. Passing it with with_status is ErrPolicy."""

    def set_(c: VerifyConfig) -> None:
        c.skip_status = True

    return VerifyOption("without_status_check", set_)


def with_accepted_status(*v: int) -> VerifyOption:
    """The status values accepted; not passed, only 0x00, VALID. No value is ErrPolicy."""
    v = tuple(v)

    def set_(c: VerifyConfig) -> None:
        if not v:
            raise policy_err("with_accepted_status needs at least one value")
        c.accepted_status = list(v)

    return VerifyOption("with_accepted_status", set_)


def with_accepted_issuers(*iss: str) -> VerifyOption:
    """The issuers this Verifier accepts: the credential passes when its iss equals one byte for byte
    (RFC 7519 §2); otherwise ISSUER_NOT_ACCEPTED, before issuers is asked for a key. A credential
    without iss is ISSUER_NOT_ACCEPTED. No issuer, or an empty one, is ErrPolicy."""
    iss = tuple(iss)

    def set_(c: VerifyConfig) -> None:
        if not iss:
            raise policy_err("with_accepted_issuers needs at least one issuer")
        if "" in iss:
            raise policy_err(
                f'with_accepted_issuers issuer {iss.index("")} is empty; verify reads an absent iss as "", '
                "so the entry would let a credential without iss past this check"
            )
        c.accepted_issuers = list(iss)

    return VerifyOption("with_accepted_issuers", set_)


def with_accepted_vcts(*vcts: str) -> VerifyOption:
    """The types this Verifier accepts: the credential passes when its vct, or an element of its
    aka_vcts, equals one byte for byte; otherwise VCT_NOT_ACCEPTED. With with_extended_vct_match, the
    types its Type Metadata extends count too. No type, or an empty one, is ErrPolicy."""
    vcts = tuple(vcts)

    def set_(c: VerifyConfig) -> None:
        if not vcts:
            raise policy_err("with_accepted_vcts needs at least one type")
        if "" in vcts:
            raise policy_err(
                f"with_accepted_vcts type {vcts.index('')} is empty, which identifies no type (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.1)"
            )
        c.accepted_vcts = list(vcts)

    return VerifyOption("with_accepted_vcts", set_)


def with_extended_vct_match() -> VerifyOption:
    """Let with_accepted_vcts match the types the credential's type extends (draft 19 §5.4), besides
    vct and aka_vcts; the comparison then runs after Type Metadata is processed. Without
    with_accepted_vcts, or without a Type Metadata option, it is ErrPolicy."""

    def set_(c: VerifyConfig) -> None:
        c.extended_vct = True

    return VerifyOption("with_extended_vct_match", set_)


def with_type_metadata(r: Any) -> VerifyOption:
    """Process the credential's Type Metadata through the typemeta Resolver r (draft 19 §5.7), as a
    policy that requires it: one that cannot be retrieved or processed rejects the credential, with
    the TYPE_METADATA_ codes. None is ErrPolicy, and so is passing it with with_optional_type_metadata."""

    def set_(c: VerifyConfig) -> None:
        if r is None:
            raise policy_err("with_type_metadata(None); pass a typemeta Resolver such as typemeta.new_http_resolver")
        c.types = r

    return VerifyOption("with_type_metadata", set_)


def with_optional_type_metadata(r: Any) -> VerifyOption:
    """Process the Type Metadata through r when it can, as a policy that does not require it: a
    document no resolver has, a failed retrieval or an unusable document skips the step, and
    Result.type_metadata_skipped holds why. Claim metadata that breaks §5.6, an extends cycle (§7.4)
    and a payload that violates the claim metadata still reject. None is ErrPolicy."""

    def set_(c: VerifyConfig) -> None:
        if r is None:
            raise policy_err("with_optional_type_metadata(None); pass a typemeta Resolver such as typemeta.new_http_resolver")
        c.types, c.types_optional = r, True

    return VerifyOption("with_optional_type_metadata", set_)


def with_all_disclosures() -> VerifyOption:
    """The caller holds every Disclosure the issuer issued, as the Holder does when it receives the
    credential: the claim metadata is checked with all_disclosures, so a missing mandatory claim is
    seen (draft 19 §5.6). A Verifier never passes it; a presentation with a Key Binding JWT is
    ErrPolicy. Without a Type Metadata option it is ErrPolicy."""

    def set_(c: VerifyConfig) -> None:
        c.all_disclosures = True

    return VerifyOption("with_all_disclosures", set_)


def with_now(t: datetime | None) -> VerifyOption:
    """The time of the check, for exp, nbf and the Key Binding JWT alike; not passed, now read once.
    It does not reach the StatusChecker, which checks the Status List Token with its own clock. None
    is ErrPolicy."""

    def set_(c: VerifyConfig) -> None:
        if t is None:
            raise policy_err("with_now(None); pass the time of the check")
        c.now = t

    return VerifyOption("with_now", set_)
