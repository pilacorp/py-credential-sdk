from __future__ import annotations

import base64
import binascii
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from credential.common.verification_method.provider import HTTPResolver
from credential.vp.presentation_helper import PresentationData

DEFAULT_BASE_URL = "https://api.ndadid.vn/api/v1/did"
_config_base_url = DEFAULT_BASE_URL


def init(base_url: str = "") -> None:
    global _config_base_url
    if base_url:
        _config_base_url = base_url


class AudienceUnboundError(ValueError):
    """with_require_audience was set without with_expected_domain."""

    def __init__(self) -> None:
        super().__init__("WithRequireAudience needs WithExpectedDomain")


ERR_AUDIENCE_UNBOUND = AudienceUnboundError


class Presentation(ABC):
    @abstractmethod
    def verify(self, *opts: PresentationOpt) -> None: ...

    @abstractmethod
    def serialize(self) -> Any: ...

    @abstractmethod
    def get_contents(self) -> bytes: ...

    @abstractmethod
    def get_type(self) -> str: ...

    @abstractmethod
    def extract_field(self, path: str) -> Any: ...


@dataclass
class PresentationContents:
    context: list[Any] = field(default_factory=list)
    id: str = ""
    types: list[str] = field(default_factory=list)
    holder: str = ""
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    verifiable_credentials: list[Any] = field(default_factory=list)


@dataclass
class PresentationOptions:
    is_validate_vc: bool = False
    vc_opts: list[Any] = field(default_factory=list)
    is_verify_proof: bool = False
    is_check_expiration: bool = False
    leeway: timedelta = timedelta(0)
    did_base_url: str = ""
    verification_method_key: str = ""
    resolver: Any = None
    proof_verification_method: str = ""
    challenge: str = ""
    domain: str = ""
    expected_challenge: str = ""
    expected_domain: str = ""
    require_audience: bool = False
    replace_proof: bool = False


PresentationOpt = Callable[[PresentationOptions], None]


def with_proof_verification_method(vm: str) -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.proof_verification_method = vm

    return apply


def with_vc_validation(*vc_opts: Any) -> PresentationOpt:
    """Verify every embedded credential; vc options are forwarded to Credential.verify."""

    def apply(p: PresentationOptions) -> None:
        p.is_validate_vc = True
        p.vc_opts.extend(vc_opts)

    return apply


def with_base_url(base_url: str) -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.did_base_url = base_url

    return apply


def with_verification_method_key(key: str) -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        if key:
            p.verification_method_key = key

    return apply


def with_verify_proof() -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.is_verify_proof = True

    return apply


def with_check_expiration() -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.is_check_expiration = True

    return apply


def with_leeway(d: timedelta) -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.leeway = max(d, timedelta(0))

    return apply


def with_challenge(challenge: str) -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.challenge = challenge

    return apply


def with_domain(domain: str) -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.domain = domain

    return apply


def with_replace_proof() -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.replace_proof = True

    return apply


def with_expected_challenge(challenge: str) -> PresentationOpt:
    """Every verified proof must carry this challenge. Implies with_verify_proof."""

    def apply(p: PresentationOptions) -> None:
        p.expected_challenge = challenge
        p.is_verify_proof = True

    return apply


def with_expected_domain(domain: str) -> PresentationOpt:
    """Every verified proof must carry this domain. Implies with_verify_proof."""

    def apply(p: PresentationOptions) -> None:
        p.expected_domain = domain
        p.is_verify_proof = True

    return apply


def with_require_audience() -> PresentationOpt:
    """Presentation must be bound to this verifier; needs with_expected_domain. Implies with_verify_proof."""

    def apply(p: PresentationOptions) -> None:
        p.require_audience = True
        p.is_verify_proof = True

    return apply


def with_resolver(resolver: Any) -> PresentationOpt:
    def apply(p: PresentationOptions) -> None:
        p.resolver = resolver

    return apply


def signing_options(opts: tuple[PresentationOpt, ...] | list[PresentationOpt]) -> list[PresentationOpt]:
    """opts for a signing call minus proof verification (there is no signature to verify yet)."""

    def no_verify(p: PresentationOptions) -> None:
        p.is_verify_proof = False

    return [*opts, no_verify]


def get_options(*opts: PresentationOpt) -> PresentationOptions:
    o = PresentationOptions(did_base_url=_config_base_url)
    for opt in opts:
        opt(o)
    if o.resolver is None:
        o.resolver = HTTPResolver(o.did_base_url)
    return o


def refuse_overwrite(current: str, options: PresentationOptions) -> None:
    """A JWT holds one signature: signing again needs with_replace_proof."""
    if current == "" or options.replace_proof:
        return
    raise ValueError(
        "presentation is already signed; signing again would replace that signature — "
        "pass WithReplaceProof to do so deliberately"
    )


def refuse_replace_on_jsonld(options: PresentationOptions) -> None:
    if not options.replace_proof:
        return
    raise ValueError(
        "WithReplaceProof does not apply to JSON-LD: proofs are appended to the proof set, not replaced; "
        "build a new presentation without the proof to re-sign"
    )


_JWT_RE = re.compile(r"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")


def is_jwt_presentation(val: str) -> bool:
    """Three-segment compact JWS shape. Disclosures are deliberately not tolerated."""
    return _JWT_RE.fullmatch(val.strip('"')) is not None


def is_sd_jwt_shaped(val: str) -> bool:
    head, sep, _ = val.strip('"').partition("~")
    return bool(sep) and is_jwt_presentation(head)


def is_json_presentation(raw: bytes | str) -> bool:
    if not raw:
        return False
    try:
        data = json.loads(raw, parse_constant=lambda n: (_ for _ in ()).throw(ValueError(n)))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(data, dict)


def parse_presentation(raw: bytes | str, *opts: PresentationOpt) -> Presentation:
    """Parse a presentation, routing by format (JSON-LD, vp+jwt, VC 1.1 JWT)."""
    from credential.vp.jose_presentation import is_jose_presentation_typ, parse_jose_presentation
    from credential.vp.json_presentation import parse_json_presentation
    from credential.vp.jwt_presentation import parse_jwt_presentation

    raw_b = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(raw_b) == 0:
        raise ValueError("presentation is empty")
    if is_json_presentation(raw_b):
        return parse_json_presentation(raw_b, *opts)

    val = raw_b.decode("utf-8", errors="replace").strip('"').strip()
    if is_jwt_presentation(val):
        parts = val.split(".")
        typ = None
        try:
            from credential.common.jwt.jwtutil import b64url_decode, json_loads

            header = json_loads(b64url_decode(parts[0]))
            typ = header.get("typ") if isinstance(header, dict) else None
        except (ValueError, binascii.Error):
            pass
        if isinstance(typ, str) and is_jose_presentation_typ(typ):
            return parse_jose_presentation(val, *opts)
        return parse_jwt_presentation(val, *opts)
    if is_sd_jwt_shaped(val):
        raise ValueError("presentation carries SD-JWT disclosures, which are not supported for presentations")
    raise ValueError("failed to parse presentation")


def parse_presentation_with_validation(raw: bytes | str) -> Presentation:
    return parse_presentation(raw, with_vc_validation(), with_verify_proof())


def check_audience(aud: Any, options: PresentationOptions) -> None:
    """RFC 7519 4.1.3: naming this verifier is what checks aud."""
    if options.expected_domain:
        if not aud_contains(aud, options.expected_domain):
            raise ValueError(f"aud {_go_fmt(aud)} does not match expected domain {options.expected_domain!r}")
        return
    if options.require_audience:
        raise AudienceUnboundError()


def aud_contains(aud: Any, domain: str) -> bool:
    if isinstance(aud, str):
        return aud == domain
    if isinstance(aud, list):
        return any(isinstance(s, str) and s == domain for s in aud)
    return False


def _go_fmt(v: Any) -> str:
    if v is None:
        return "<nil>"
    if isinstance(v, list):
        return "[" + " ".join(map(str, v)) + "]"
    return str(v)
