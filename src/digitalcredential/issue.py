"""Issuing an SD-JWT VC: draft-ietf-oauth-sd-jwt-vc-19 §2.2, the SD-JWT and its claims on the
Issuer side; RFC 9901 §4, §4.2 (Go: issue.go)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrMalformed
from jose.jwk import jwk as jose_jwk
from jose.jws import jws as jose_jws
from jose.jwt import jwt as jose_jwt
from jose.sdjwt import ConcealOptions, conceal
from jose.sdjwt.path import Path, format_path

from digitalcredential.claims import NEVER_DISCLOSABLE, TYP_DC_SD_JWT, is_str
from digitalcredential.credential import Credential, compact_sd_jwt
from digitalcredential.errors import combine, errors_is
from digitalcredential.internal import sri
from digitalcredential.issuerkey import SigningKey

BACKGROUND = object()  # the context.Background() of this port: there is no cancellation


@dataclass
class IssueRequest:
    """The content of one SD-JWT VC. Issue writes the values as given and checks only what the
    standard requires of the Issuer: vct set, aka_vcts (draft 19 §2.2.2.2), vct#integrity as
    integrity metadata (§6), iat/nbf/exp as NumericDate, status as Ref.validate checks it, iss or
    sub beside cnf (RFC 7800 §3), the claim metadata of type_metadata (§5.6), and the structure it
    builds itself.

    issuer: iss ("" writes none). vct: required. issued_at/not_before/expiry: iat/nbf/exp as
    datetime, written in whole seconds; None writes none (a time with a fraction goes in claims).
    holder_key: written as cnf.jwk (a cryptography EC public key); None writes no cnf. status: a
    statuslist.Ref written as status.status_list {"idx","uri"}. claims: every other claim.
    disclose: paths to conceal. min_digests: decoy digests (0 when disclose is empty).
    type_metadata: the Type Metadata of vct made by typemeta.Load; checked before concealing.
    """

    issuer: str = ""
    vct: str = ""
    issued_at: datetime | None = None
    not_before: datetime | None = None
    expiry: datetime | None = None
    holder_key: Any = None
    status: Any = None
    claims: dict[str, Any] | None = None
    disclose: list[Path] = field(default_factory=list)
    min_digests: int = 0
    type_metadata: Any = None

    def validate(self) -> None:
        """Run exactly the checks of issue on the request, without signing."""
        _prepare(self)


# requestClaims: the claims an IssueRequest field writes. Claims may hold one only while
# the field is unset. The fixed order makes the error deterministic.
_REQUEST_CLAIMS = (
    ("iss", "issuer", True, None),
    ("vct", "vct", True, None),
    ("iat", "issued_at", False, lambda r: r.issued_at is not None),
    ("nbf", "not_before", False, lambda r: r.not_before is not None),
    ("exp", "expiry", False, lambda r: r.expiry is not None),
    ("cnf", "holder_key", False, lambda r: r.holder_key is not None),
    ("status", "status", False, lambda r: r.status is not None),
)


def issue(req: IssueRequest, key: SigningKey, ctx: Any = None) -> Credential:
    """Sign an SD-JWT VC (draft 19) with key and return it.

    Its serialize() is <Issuer-signed JWT>~<D1>~...~<Dn>~, ending in "~" even with no disclosure.
    The header is {"alg", "typ": "dc+sd-jwt", "kid"}: alg is key.signer's, which jws.sign checks
    against key.public, and kid is written only when key.kid is set. iat and the claims go through
    sdjwt.conceal, except the eight draft 19 §2.2.2.3 forbids disclosing; those are added after, so
    they are neither concealed nor padded with decoys.

    Errors, checked before key.signer is called: ErrInvalidArgument for a request breaking the
    rules of IssueRequest (naming the field); a payload breaking the claim metadata of type_metadata:
    ErrInvalidArgument also wrapping typemeta ErrViolated (or ErrClaims); a holder_key jwk
    from_public_key refuses: its error; jws.sign errors unchanged; after it ErrSignerFailed /
    ErrSelfCheck.
    """
    payload, disclosures = _prepare(req)
    body = jose_json.encode_json(payload)
    header: dict[str, Any] = {"typ": TYP_DC_SD_JWT}
    if key.kid:
        header["kid"] = key.kid
    token = jose_jws.sign(BACKGROUND if ctx is None else ctx, key.signer, key.public, header, body)
    return Credential(compact_sd_jwt(token, disclosures))


def _prepare(req: IssueRequest) -> tuple[dict[str, Any], list]:
    """Check req and build the payload and the disclosures; validate and issue share it."""
    if req.disclose is None:
        req.disclose = []
    claims = _copy_claims(req.claims)
    _check(req, claims)

    if req.holder_key is not None:
        try:
            holder = jose_jwk.from_public_key(req.holder_key)
        except Exception as e:
            raise combine(f"dc: HolderKey: {e}", type(e)) from e
        claims["cnf"] = {"jwk": holder}
    if req.status is not None:
        claims["status"] = {"status_list": {"idx": req.status.index, "uri": req.status.uri}}
    _put_time(claims, "iat", req.issued_at)
    if req.issuer != "":
        claims["iss"] = req.issuer
    claims["vct"] = req.vct
    _put_time(claims, "nbf", req.not_before)
    _put_time(claims, "exp", req.expiry)
    # Every claim to be signed is in place and none is concealed yet.
    if req.type_metadata is not None:
        try:
            _tm_validate_issuance(req.type_metadata, claims, req.disclose)
        except Exception as e:
            raise combine(f"dc: TypeMetadata: {e}", ErrInvalidArgument, type(e)) from e

    # The eight claims go apart, so that conceal neither conceals them nor pads them with decoys,
    # then come back after it.
    plain = {name: claims.pop(name) for name in list(claims) if name in NEVER_DISCLOSABLE}
    payload, disclosures = conceal(
        claims,
        req.disclose,
        ConcealOptions(min_digests=req.min_digests, no_array_decoys=req.type_metadata is not None),
    )
    # Through conceal with no path and no decoy, so the reserved names _sd, _sd_alg and ... are
    # refused in the eight claims as in the rest (RFC 9901 §4.1 rule 7, §4.1.1).
    plain_payload, _ = conceal(plain, [], ConcealOptions())
    payload.update(plain_payload)
    return payload, disclosures


def _copy_claims(c: dict[str, Any] | None) -> dict[str, Any]:
    """Claims as jose.decode_json_object reads them from their JSON, so every later step sees
    numbers as JsonNumber, whatever Python types the caller used; req.claims is never modified."""
    if c is None:
        return {}
    try:
        b = jose_json.encode_json(c)
    except Exception as e:
        raise combine(f"dc: Claims: {e}", ErrInvalidArgument) from e
    try:
        return jose_json.decode_json_object(b)
    except Exception as e:
        # Duplicate keys or depth over MAX_JSON_DEPTH in what the caller gave: a mistake of the
        # request, not a malformed token.
        raise ErrInvalidArgument(f"dc: Claims: {e}") from e


def _invalid(msg: str) -> Exception:
    return ErrInvalidArgument(msg)


def _check(req: IssueRequest, claims: dict[str, Any]) -> None:
    """Apply the rules of IssueRequest to req, claims being its Claims as _copy_claims returns them."""
    from digitalcredential.verify import check_aka_vcts, read_status

    if req.vct == "":
        raise _invalid("dc: VCT is required (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3)")
    for name, field_name, field_only, is_set in _REQUEST_CLAIMS:
        if name not in claims:
            continue
        if field_only:
            raise _invalid(f'dc: Claims holds "{name}", which only IssueRequest.{field_name} may set')
        if is_set(req):
            raise _invalid(f'dc: Claims holds "{name}" and IssueRequest.{field_name} is set; give it in one place')
    # A Verifier refuses exp and nbf of another type (jwt.check_exp_nbf), and iat is a
    # NumericDate too (RFC 7519 §4.1.4-4.1.6).
    for name in ("iat", "nbf", "exp"):
        if name in claims:
            v = claims[name]
            try:
                if isinstance(v, bool):
                    raise ErrMalformed("bool")
                jose_jwt.numeric_date(v)
            except Exception:
                raise _invalid(
                    f'dc: Claims "{name}" is not a NumericDate (RFC 7519 §2); give a number of seconds, or set the field'
                ) from None
    if "aka_vcts" in claims:
        err = check_aka_vcts(claims["aka_vcts"], req.vct)
        if err:
            raise _invalid(f"dc: Claims aka_vcts {err} (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2)")
    if "vct#integrity" in claims:
        v = claims["vct#integrity"]
        if not is_str(v) or not sri.well_formed(v):
            raise _invalid(
                "dc: Claims vct#integrity is not integrity metadata (sha256-, sha384- or sha512- and base64, "
                "tokens separated by spaces; W3C SRI §3.5, draft-ietf-oauth-sd-jwt-vc-19 §5.3); take it from typemeta.Encoded.Integrity"
            )
    # A status, aud or cnf given in Claims is read by the readers Verify uses, so Issue signs
    # none that a Verifier on this SDK reads as malformed.
    if "status" in claims:
        try:
            st = read_status(claims)
        except Exception as e:
            raise _invalid(f"dc: Claims {e}; set Status for a Status List entry") from None
        # Verify reads such an idx as past every status list (check_status).
        if st.past_int:
            raise _invalid("dc: Claims status.status_list.idx is past every status list; set Status for a Status List entry")
    try:
        _check_aud_shape(claims)
    except ErrMalformed:
        raise _invalid("dc: Claims aud is not a string or an array of strings (RFC 7519 §4.1.3)") from None
    if "cnf" in claims:
        from digitalcredential.cnf import cnf_key

        try:
            cnf_key(claims["cnf"])
        except Exception as e:
            if errors_is(e, ErrMalformed):
                raise _invalid(
                    f"dc: Claims cnf is one a Verifier reads as malformed ({e}); set HolderKey for a cnf.jwk"
                ) from None
    if req.status is not None:
        try:
            req.status.validate()
        except Exception as e:
            raise ErrInvalidArgument(f"dc: Status: {e}") from e
    for i, p in enumerate(req.disclose):
        # An empty path or one starting with an index is conceal's to refuse.
        if len(p) == 0:
            continue
        name = p[0]
        if is_str(name) and name in NEVER_DISCLOSABLE:
            raise _invalid(
                f"dc: Disclose[{i}] {format_path(p)}: draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids concealing {name}"
            )
    # draft 19 §2.2.2.5: with no selectively disclosable claim the credential MUST NOT contain
    # _sd, and decoys alone would add one.
    if len(req.disclose) == 0 and req.min_digests > 0:
        raise _invalid(
            f"dc: MinDigests {req.min_digests} with no Disclose path: draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.5 "
            "forbids _sd when no claim is selectively disclosable"
        )
    m = req.type_metadata
    if m is not None:
        # The zero Metadata has vct "" and vct is not empty here.
        if _tm_vct(m) != req.vct:
            raise _invalid("dc: TypeMetadata is not the Type Metadata of VCT made by typemeta.Load")
        s = claims.get("vct#integrity")
        if is_str(s):
            try:
                _tm_check_integrity(m, s)
            except Exception as e:
                raise _invalid(
                    f"dc: Claims vct#integrity does not match the document TypeMetadata was loaded from "
                    f"(draft-ietf-oauth-sd-jwt-vc-19 §6): {e}"
                ) from None
    # RFC 7800 §3: "At least one of the sub and iss claims MUST be present" beside cnf.
    # draft-ietf-oauth-sd-jwt-vc-20 §2.2.2.3 lifts this; drop the check when the pin moves past draft 19.
    if "cnf" in claims or req.holder_key is not None:
        if "sub" not in claims and req.issuer == "":
            raise _invalid("dc: a credential with cnf needs iss or sub (RFC 7800 §3); set Issuer, or sub in Claims")


def _check_aud_shape(claims: dict[str, Any]) -> None:
    """aud is a string or an array of strings (RFC 7519 §4.1.3); ErrMalformed otherwise."""
    if "aud" not in claims:
        return
    v = claims["aud"]
    items = v if isinstance(v, list) else [v]
    if not all(is_str(x) for x in items):
        raise ErrMalformed("aud is not a string or an array of strings")


def _put_time(claims: dict[str, Any], name: str, t: datetime | None) -> None:
    """Write t as a NumericDate (RFC 7519 §2) in whole seconds, the fraction dropped, unless t is None."""
    if t is not None:
        claims[name] = math.floor(t.timestamp())


# --- Type Metadata adapters (digitalcredential.typemeta is ported separately) ---------------------


def _tm_vct(m: Any) -> str:
    v = getattr(m, "vct", "")
    return v() if callable(v) else v


def _tm_validate_issuance(m: Any, claims: dict[str, Any], disclose: list[Path]) -> None:
    m.validate_issuance(claims, disclose)


def _tm_check_integrity(m: Any, value: str) -> None:
    from digitalcredential import typemeta

    docs = m.documents()
    typemeta.check_integrity(docs[0], value)
