from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Any, Protocol

from digitalcredential.errors import DigitalCredentialError

SUPPORTED_ALGS = ("ES256", "ES256K")
DEFAULT_MAX_KB_AGE = timedelta(minutes=5)
DEFAULT_CLOCK_SKEW = timedelta(minutes=1)


class KeyBindingMode(IntEnum):
    IF_CNF = 0
    REQUIRED = 1
    NOT_REQUIRED = 2


class StatusChecker(Protocol):
    def status(self, ref: dict[str, Any], iss: str) -> int: ...


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
    types_resolver: Any = None
    types_optional: bool = False
    all_disclosures: bool = False
    now: datetime | None = None


def _policy(msg: str) -> DigitalCredentialError:
    return DigitalCredentialError("POLICY", msg)


def new_verify_config(opts: dict[str, Any] | None = None) -> VerifyConfig:
    o = opts or {}
    c = VerifyConfig(
        algs=list(o.get("allowed_algs") or SUPPORTED_ALGS),
        audience=str(o.get("audience") or ""),
        nonce=str(o.get("nonce") or ""),
        cred_audience=str(o.get("credential_audience") or ""),
        skip_status=bool(o.get("skip_status")),
        status=o.get("status"),
        accepted_issuers=o.get("accepted_issuers"),
        accepted_vcts=o.get("accepted_vcts"),
        extended_vct=bool(o.get("extended_vct_match")),
        types_resolver=o.get("type_metadata"),
        types_optional=bool(o.get("optional_type_metadata")),
        all_disclosures=bool(o.get("all_disclosures")),
        now=o.get("now"),
    )
    if o.get("clock_skew_seconds") is not None:
        c.skew = timedelta(seconds=int(o["clock_skew_seconds"]))
    if o.get("max_kb_age_seconds") is not None:
        c.max_kb_age = timedelta(seconds=int(o["max_kb_age_seconds"]))
    kb = o.get("key_binding")
    if kb is not None:
        c.key_binding = KeyBindingMode(int(kb))
    if o.get("ignore_unchecked_kb"):
        c.ignore_unchecked_kb = True
    if o.get("accepted_status"):
        c.accepted_status = list(o["accepted_status"])
    for a in c.algs:
        if a not in SUPPORTED_ALGS:
            raise _policy(f"WithAllowedAlgs: unsupported alg {a!r}")
    if c.skip_status and c.status is not None:
        raise _policy("WithStatus and WithoutStatusCheck are both passed")
    type_opt = c.types_resolver is not None or c.types_optional
    if c.all_disclosures and not type_opt:
        raise _policy("WithAllDisclosures without WithTypeMetadata checks nothing")
    if c.extended_vct and (not c.accepted_vcts or not type_opt):
        raise _policy("WithExtendedVCTMatch needs WithAcceptedVCTs and type metadata")
    if c.key_binding == KeyBindingMode.REQUIRED and (not c.audience or not c.nonce):
        raise _policy("KeyBindingRequired needs audience and nonce")
    if c.now is None:
        c.now = datetime.now().astimezone()
    return c
