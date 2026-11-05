"""Verifying an SD-JWT VC on the Verifier side (Go: verify.go): draft-ietf-oauth-sd-jwt-vc-19 §2.4
(verification), §2.2.2.1-2.2.2.3 (claims) and §2.5 (issuer key); RFC 9901 §4, §7.1 (the SD-JWT), §7.3
(Key Binding) and §9.5; RFC 7519 §4.1.3-4.1.5; draft-ietf-oauth-status-list-21 §6.2, §7.1 and §8.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jose import json as jose_json
from jose.errors import ErrInvalidArgument, ErrMalformed, ErrUnsupportedKey
from jose.jwk import jwk as jose_jwk
from jose.jws import jws as jose_jws
from jose.jws import errors as jws_errors
from jose.jwt import jwt as jose_jwt
from jose.sdjwt import Disclosure, KBVerifyParams, recreate, sd_hash, split, verify_kb_jwt
from jose.sdjwt import kb as sdjwt_kb

from digitalcredential import errors as E
from digitalcredential.claims import NEVER_DISCLOSABLE_SORTED, TYP_DC_SD_JWT, is_str
from digitalcredential.cnf import holder_key
from digitalcredential.credential import Credential
from digitalcredential.errors import (
    DigitalCredentialError,
    ErrKeyBindingUnsupported,
    ErrPolicy,
    combine,
    errors_is,
    policy_err,
)
from digitalcredential.internal import jsonint, sri, uri
from digitalcredential.issuerkey import ErrIssuerNotSupported, ErrNoUsableKey, select
from digitalcredential.verify_options import KeyBindingMode, VerifyConfig, new_verify_config

_KEY_SENTINELS = (ErrUnsupportedKey, jws_errors.ErrBadKey, jose_jwk.ErrBadKey)


@dataclass
class Result:
    """A credential verify accepted.

    claims: the processed payload (RFC 9901 §7.1): the Issuer-signed JWT claims with the disclosed
    ones in place and _sd, _sd_alg and digests removed, numbers as JsonNumber. Do not modify.
    issuer: the iss the issuer key was resolved for, "" when the credential has none.
    vct / aka_vcts: the credential's vct and aka_vcts (None when absent).
    key_bound: a Key Binding JWT was checked against the credential's cnf.
    key_binding_claims: every claim of that Key Binding JWT; None when key_bound is False.
    status: the status value checked, None when no status or without_status_check skipped it.
    status_skipped: the credential has status and without_status_check skipped it.
    type_metadata: the processed Type Metadata; None when no Type Metadata option or skipped.
    type_metadata_skipped: why with_optional_type_metadata skipped it, for logs; None otherwise.
    """

    claims: dict[str, Any]
    issuer: str = ""
    vct: str = ""
    aka_vcts: list[str] | None = None
    key_bound: bool = False
    key_binding_claims: dict[str, Any] | None = None
    status: int | None = None
    status_skipped: bool = False
    type_metadata: Any = None
    type_metadata_skipped: BaseException | None = None

    # legacy dict-style access of the old verify_credential result
    def __getitem__(self, k: str) -> Any:
        return {"issuer": self.issuer or None, "vct": self.vct, "claims": self.claims, "key_bound": self.key_bound}[k]


def _reject(code: str, err: BaseException | str) -> DigitalCredentialError:
    return DigitalCredentialError(code, err)


def verify(c: Credential | None, issuers: Any, *opts: Any, ctx: Any = None) -> Result:
    """Check the credential, as received, against issuers and opts (draft 19 §2.4), and return its
    claims. In order, each step stopping at its first failure:

     1. the receiver, issuers and opts: ErrPolicy;
     2. the compact form (RFC 9901 §4) and the Issuer-signed JWT header: MALFORMED; typ dc+sd-jwt: TYP_INVALID;
     3. the key: iss is the one claim read before the signature, and only as a string. An iss that is
        not a string, one holding ":" that is not a URI, or a payload that is not one JSON object, is
        MALFORMED; iss may be absent ("" to the resolver). With with_accepted_issuers, an iss not in
        it: ISSUER_NOT_ACCEPTED. It goes to issuers, and select picks the key by kid:
        ISSUER_NOT_SUPPORTED, ISSUER_KEY_UNAVAILABLE, ISSUER_KEY_NOT_FOUND;
     4. the signature with with_allowed_algs: ALG_NOT_ALLOWED, SIGNATURE_INVALID; then the signed
        payload decoded in full: MALFORMED;
     5. the Disclosures (RFC 9901 §7.1 steps 3-5), and none of a claim §2.2.2.3 keeps out of them:
        DISCLOSURE_INVALID;
     6. exp, nbf and aud: EXPIRED, NOT_YET_VALID, AUDIENCE_MISMATCH;
     7. vct, aka_vcts, vct#integrity and the shape of status: MALFORMED; with with_accepted_vcts
        (without with_extended_vct_match), the types: VCT_NOT_ACCEPTED;
     8. Key Binding, per with_key_binding (RFC 9901 §7.3): the KB_ codes;
     9. with a Type Metadata option, Type Metadata (§5.7): the TYPE_METADATA_ codes; with
        with_extended_vct_match, the types: VCT_NOT_ACCEPTED;
    10. status last, unless without_status_check: the status codes, MALFORMED for an idx outside the list.

    Errors fall in classes; test them in this order: DigitalCredentialError (the token is rejected,
    `code` says why; the cause of a resolver, typemeta or status failure is reachable through
    errors_is); ErrPolicy (the caller's arguments, options or dependencies are at fault); anything
    else is a failure of a dependency that carries no Code.
    """
    if c is None or not c.compact:
        raise policy_err("Verify of a nil or zero Credential; make one with Parse")
    if issuers is None:
        raise policy_err("Verify needs an issuerkey Resolver for the issuers you accept")
    cfg = new_verify_config(opts)

    try:
        issuer_jwt, encoded, kb_jwt = split(c.compact)
    except Exception as e:
        raise _reject(E.MALFORMED, e) from e
    try:
        header = jose_jws.unverified_header(issuer_jwt)
    except jws_errors.ErrUnsupportedHeader as e:
        raise _reject(
            E.MALFORMED,
            combine(
                "the Issuer-signed JWT header uses crit or b64, which this SDK does not implement (RFC 7515 §4.1.11, RFC 7797 §3, §6)",
                jws_errors.ErrUnsupportedHeader,
            ),
        ) from e
    except Exception as e:
        raise _reject(E.MALFORMED, e) from e
    if not jose_jws.header_typ_is(header, TYP_DC_SD_JWT):
        if jose_jws.header_typ_is(header, "vc+sd-jwt"):
            raise _reject(
                E.TYP_INVALID,
                "typ is vc+sd-jwt, not dc+sd-jwt: a W3C VC secured with SD-JWT (verify it with credential/vc), or an "
                "SD-JWT VC from a draft before dc+sd-jwt, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 no longer allows "
                "(the issuer reissues it as dc+sd-jwt)",
            )
        raise _reject(E.TYP_INVALID, "typ is not dc+sd-jwt (draft-ietf-oauth-sd-jwt-vc-19 §2.2.1)")

    # draft 19 §2.5 leaves to the Verifier how the key is found. This SDK resolves iss through
    # issuers and never takes a key from the header (no x5c). Only a string iss is decoded before
    # the signature, so an unsigned payload, whatever its iss holds, costs a scan, not a decode.
    try:
        raw = jose_jws.unverified_payload(issuer_jwt)
    except Exception as e:
        raise _reject(E.MALFORMED, e) from e
    # RFC 7519 §4.1.1: iss is a StringOrURI, so a JSON string.
    try:
        iss, has_iss = jose_json.decode_json_string_member(raw, "iss")
    except Exception as e:
        raise _reject(E.MALFORMED, f"Issuer-signed JWT payload: {e}") from e
    # RFC 7519 §2: a StringOrURI holding ":" MUST be a URI; §4.1.1 leaves the reaction to the
    # application, and Verify refuses it. Neither the scheme nor the host is checked.
    if ":" in iss and not uri.valid(iss):
        raise _reject(E.MALFORMED, "the Issuer-signed JWT payload's iss is not a URI (RFC 3986)")
    if cfg.accepted_issuers is not None and iss not in cfg.accepted_issuers:
        raise _reject(E.ISSUER_NOT_ACCEPTED, "iss is not an issuer in with_accepted_issuers")
    try:
        keys = issuers.keys(iss)
    except Exception as e:
        if errors_is(e, ErrIssuerNotSupported):
            raise _reject(E.ISSUER_NOT_SUPPORTED, e) from e
        # A definite answer, like ErrIssuerNotSupported.
        if errors_is(e, ErrNoUsableKey):
            raise _reject(E.ISSUER_KEY_NOT_FOUND, e) from e
        # The resolver's wiring, such as a resolver not made by its constructor.
        if errors_is(e, ErrInvalidArgument):
            raise policy_err(f"the issuerkey Resolver: {e}") from None
        raise _reject(E.ISSUER_KEY_UNAVAILABLE, combine(f"the issuerkey Resolver could not return the issuer keys: {e}", type(e))) from e
    try:
        key = select(keys or [], header)
    except Exception as e:
        raise _reject(E.ISSUER_KEY_NOT_FOUND, e) from e
    try:
        _, signed = jose_jws.verify(issuer_jwt, key, cfg.algs)
    except Exception as e:
        # The resolver returned a key jws does not verify with: the caller's resolver, not the
        # token, so ErrPolicy, which keeps the key's class.
        ks = _key_sentinel(e)
        if ks is not None:
            raise combine(f"dc: invalid verify policy: dc: the issuerkey Resolver returned a key that cannot verify: {e}", ErrPolicy, ks) from e
        if isinstance(e, jws_errors.ErrAlgNotAllowed):
            raise _reject(E.ALG_NOT_ALLOWED, e) from e
        if isinstance(e, (jws_errors.ErrAlgKeyMismatch, jws_errors.ErrBadSignature)):
            raise _reject(E.SIGNATURE_INVALID, e) from e
        raise _reject(E.MALFORMED, e) from e
    try:
        payload = jose_json.decode_json_object(signed)
    except Exception as e:
        raise _reject(E.MALFORMED, f"Issuer-signed JWT payload: {e}") from e
    # The key was chosen for this iss; the full decode must read the same.
    if ("iss" in payload) != has_iss or ("iss" in payload and payload["iss"] != iss):
        raise _reject(E.MALFORMED, "the Issuer-signed JWT payload's iss differs from the one its key was resolved for")

    try:
        r = recreate(payload, [Disclosure(salt="", encoded=e) for e in encoded])
    except Exception as e:
        raise _reject(E.DISCLOSURE_INVALID, e) from e
    # draft 19 §2.2.2.3: these claims, "including any of their sub-claims", MUST NOT be included in
    # Disclosures. Checked before any is read.
    for name in NEVER_DISCLOSABLE_SORTED:
        if r.disclosed([name]):
            raise _reject(
                E.DISCLOSURE_INVALID,
                f'claim "{name}", or a sub-claim of it, came in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids',
            )
    claims = r.claims

    try:
        jose_jwt.check_exp_nbf(claims, cfg.now, cfg.skew.total_seconds())
    except jose_jwt.ErrExpired as e:
        raise _reject(E.EXPIRED, e) from e
    except jose_jwt.ErrNotYetValid as e:
        raise _reject(E.NOT_YET_VALID, e) from e
    except Exception as e:
        raise _reject(E.MALFORMED, e) from e
    try:
        jose_jwt.check_aud(claims, cfg.cred_audience)
    except jose_jwt.ErrAudience as e:
        raise _reject(E.AUDIENCE_MISMATCH, combine(f"with_credential_audience: {e}", type(e))) from e
    except Exception as e:
        raise _reject(E.MALFORMED, e) from e
    res = Result(claims=claims, issuer=iss)
    try:
        res.vct, res.aka_vcts = read_types(claims)
    except ValueError as e:
        raise _reject(E.MALFORMED, e) from None
    try:
        st = read_status(claims)
    except ValueError as e:
        raise _reject(E.MALFORMED, e) from None
    if cfg.accepted_vcts is not None and not cfg.extended_vct and not _type_accepted(cfg, res):
        raise _reject(E.VCT_NOT_ACCEPTED, "neither vct nor aka_vcts is a type in with_accepted_vcts")

    kb_claims = _check_key_binding(cfg, c.compact, kb_jwt, payload, r)
    res.key_binding_claims = kb_claims
    res.key_bound = kb_claims is not None

    _check_type_metadata(cfg, r, kb_jwt, res)
    if cfg.extended_vct and not _type_accepted(cfg, res):
        raise _reject(
            E.VCT_NOT_ACCEPTED,
            "neither vct, aka_vcts nor a type its Type Metadata extends is a type in with_accepted_vcts",
        )

    if not st.present:
        return res
    if cfg.skip_status:
        res.status_skipped = True
        return res
    v = _check_status(cfg, st, iss)
    if v in cfg.accepted_status:
        res.status = v
        return res
    # draft-ietf-oauth-status-list-21 §7.1: 0x01 INVALID, 0x02 SUSPENDED.
    if v == 0x01:
        raise _reject(E.REVOKED, "the issuer revoked the credential (status 0x01)")
    if v == 0x02:
        raise _reject(E.SUSPENDED, "the issuer suspended the credential (status 0x02)")
    raise _reject(E.STATUS_NOT_ACCEPTED, f"status 0x{v:02x} is not in with_accepted_status")


verify_credential = verify  # legacy name


def check_aka_vcts(v: Any, vct: str) -> str:
    """draft 19 §2.2.2.2: aka_vcts MUST be a non-empty array of strings and MUST NOT contain the
    value of vct, compared exactly. An empty string identifies no type (§2.2.1). v is a value as
    jose decodes it. Returns "" when fine, else the fault."""
    if not isinstance(v, list):
        return "is not an array"
    if len(v) == 0:
        return "is empty"
    for i, e in enumerate(v):
        if not is_str(e):
            return f"element {i} is not a string"
        if e == "":
            return f"element {i} is empty"
        if e == vct:
            return f"element {i} is the value of VCT"
    return ""


def read_types(claims: dict[str, Any]) -> tuple[str, list[str] | None]:
    """vct and aka_vcts from claims, the processed payload, and check that vct#integrity is
    integrity metadata (draft 19 §2.2.2.1-2.2.2.3, §5.3), as issue does. ValueError is a claim of the
    wrong shape."""
    vct = claims.get("vct")
    if not is_str(vct) or vct == "":
        raise ValueError(
            "vct is absent, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids, or not a non-empty string as §2.2.2.1 requires"
        )
    aka: list[str] | None = None
    if "aka_vcts" in claims:
        err = check_aka_vcts(claims["aka_vcts"], vct)
        if err:
            raise ValueError(f"aka_vcts {err} (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2)")
        aka = list(claims["aka_vcts"])
    if "vct#integrity" in claims:
        s = claims["vct#integrity"]
        if not is_str(s) or not sri.well_formed(s):
            raise ValueError(
                "vct#integrity is not integrity metadata (sha256-, sha384- or sha512- and base64, tokens separated by "
                "spaces; W3C SRI §3.5, draft-ietf-oauth-sd-jwt-vc-19 §5.3)"
            )
    return vct, aka


def _check_key_binding(
    cfg: VerifyConfig, compact: str, kb_jwt: str, payload: dict[str, Any], r: Any
) -> dict[str, Any] | None:
    """Apply the Key Binding mode to kb_jwt ("" when none came), for the credential compact with
    payload, its Issuer-signed JWT payload, and r recreated from it. Returns the claims of the Key
    Binding JWT it checked, None when it checked none. Its errors are DigitalCredentialError or ErrPolicy."""
    has_cnf = "cnf" in payload
    required = has_cnf
    if cfg.key_binding == KeyBindingMode.REQUIRED:
        required = True
    elif cfg.key_binding == KeyBindingMode.NOT_REQUIRED:
        required = False
    if not required:
        if kb_jwt == "" or cfg.ignore_unchecked_kb:
            return None
        if cfg.key_binding == KeyBindingMode.NOT_REQUIRED:
            raise _reject(
                E.KB_UNEXPECTED,
                "a Key Binding JWT came under KeyBindingNotRequired: a Holder (RFC 9901 §7.2) or a verifier expecting an "
                "SD-JWT (§4) MUST reject it; add with_ignore_unchecked_kb_jwt if this verifier only does not need it",
            )
        raise _reject(
            E.KB_UNEXPECTED,
            "a Key Binding JWT came with a credential that has no cnf claim, so no key checks it "
            "(draft-ietf-oauth-sd-jwt-vc-19 §2.4); add with_ignore_unchecked_kb_jwt to ignore it",
        )
    # The credential first: when its cnf gives no key, no presentation of it passes, so asking the
    # holder for a Key Binding JWT would not help.
    if not has_cnf:
        raise _reject(
            E.KB_UNSUPPORTED,
            "Key Binding is required (KeyBindingRequired) and the credential has no cnf claim, the key a Key Binding "
            "JWT is checked with (draft-ietf-oauth-sd-jwt-vc-19 §2.4)",
        )
    try:
        holder = holder_key(payload, r)
    except Exception as e:
        if errors_is(e, ErrKeyBindingUnsupported):
            raise _reject(E.KB_UNSUPPORTED, e) from e
        raise _reject(E.MALFORMED, e) from e
    if kb_jwt == "":
        if cfg.key_binding == KeyBindingMode.REQUIRED:
            raise _reject(
                E.KB_MISSING,
                "Key Binding is required (KeyBindingRequired) and no Key Binding JWT came: the holder must send an "
                "SD-JWT+KB (RFC 9901 §7.3 step 2)",
            )
        raise _reject(
            E.KB_MISSING,
            "the credential binds a holder key and no Key Binding JWT came: the holder must send an SD-JWT+KB, or pass "
            "with_key_binding(NOT_REQUIRED) if this verifier does not require Key Binding (RFC 9901 §7.3 step 2, §9.5)",
        )
    if cfg.audience == "" or cfg.nonce == "":
        raise policy_err(
            "this presentation has a Key Binding JWT: pass with_audience and with_nonce, or with_key_binding(NOT_REQUIRED) "
            "with with_ignore_unchecked_kb_jwt if this verifier does not check Key Binding (RFC 9901 §7.3 step 5f)"
        )
    try:
        return verify_kb_jwt(
            kb_jwt,
            holder,
            KBVerifyParams(
                audience=cfg.audience,
                nonce=cfg.nonce,
                # RFC 9901 §4.3.1: over the SD-JWT as received, up to the last ~.
                sd_hash=sd_hash(compact[: len(compact) - len(kb_jwt)]),
                now=cfg.now,
                max_age_seconds=cfg.max_kb_age.total_seconds(),
                clock_skew_seconds=cfg.skew.total_seconds(),
                allowed_algs=cfg.algs,
            ),
        )
    except Exception as e:
        if errors_is(e, ErrInvalidArgument):
            raise policy_err(f"checking the Key Binding JWT: {e}") from None
        if errors_is(e, sdjwt_kb.ErrKBAudience):
            raise _reject(E.KB_AUDIENCE_MISMATCH, e) from e
        if errors_is(e, sdjwt_kb.ErrKBNonce):
            raise _reject(E.KB_NONCE_MISMATCH, e) from e
        if errors_is(e, sdjwt_kb.ErrKBSDHash):
            raise _reject(E.KB_SD_HASH_MISMATCH, e) from e
        raise _reject(E.KB_INVALID, e) from e


def _check_type_metadata(cfg: VerifyConfig, r: Any, kb_jwt: str, res: Result) -> None:
    """Step 9: with a Type Metadata option, process the Type Metadata of res.vct (draft 19 §5.7) and
    check r, the payload as issued, against it (§5.6), setting res.type_metadata or, when
    with_optional_type_metadata skips it, res.type_metadata_skipped."""
    if cfg.types is None:
        return
    from digitalcredential import typemeta

    if cfg.all_disclosures and kb_jwt != "":
        raise policy_err(
            "with_all_disclosures with a presentation that has a Key Binding JWT: a Verifier is never sure to hold every "
            "Disclosure (draft-ietf-oauth-sd-jwt-vc-19 §5.6); drop with_all_disclosures"
        )
    integrity = res.claims.get("vct#integrity")  # step 7 checked its type
    integrity = integrity if is_str(integrity) else None
    m = None
    try:
        if integrity is not None and integrity == "":
            # §6: an integrity property that is present must be verified, and an empty one names no
            # hash, so the document cannot be accepted.
            raise combine(
                "dc: vct#integrity is present and empty, so no hash can check the Type Metadata document; the issuer "
                "writes typemeta.Integrity(doc) or leaves it out (draft-ietf-oauth-sd-jwt-vc-19 §6)",
                typemeta.ErrInvalid,
            )
        m = _tm_load(cfg.types, res.vct, integrity or "")
    except Exception as e:
        # The resolver's wiring, such as one not made by its constructor.
        if errors_is(e, ErrInvalidArgument):
            raise policy_err(f"the typemeta Resolver: {e}") from None
        # §5.7: claim metadata that cannot be processed MUST reject, whatever the policy; so must a cycle (§7.4).
        if errors_is(e, typemeta.ErrClaims, typemeta.ErrCycle):
            raise _reject(E.TYPE_METADATA_INVALID, e) from e
        if cfg.types_optional:
            res.type_metadata_skipped = e
            return
        if errors_is(e, typemeta.ErrNotFound):
            raise _reject(E.TYPE_METADATA_NOT_FOUND, e) from e
        if errors_is(e, typemeta.ErrInvalid):
            raise _reject(E.TYPE_METADATA_INVALID, e) from e
        raise _reject(
            E.TYPE_METADATA_UNAVAILABLE, combine(f"the typemeta Resolver could not return the Type Metadata: {e}", type(e))
        ) from e
    try:
        _tm_validate_claims(m, r, cfg.all_disclosures)
    except Exception as e:
        # ErrClaims: claim metadata the SDK cannot check on this payload.
        if errors_is(e, typemeta.ErrClaims):
            raise _reject(E.TYPE_METADATA_INVALID, e) from e
        raise _reject(E.TYPE_METADATA_VIOLATED, e) from e
    res.type_metadata = m


def _type_accepted(cfg: VerifyConfig, res: Result) -> bool:
    """Whether a type of res is in with_accepted_vcts: vct, aka_vcts and, with with_extended_vct_match,
    the extends chain of its Type Metadata (draft 19 §2.2.2.1, §2.2.2.2, §5.4), compared byte for byte."""
    types = [res.vct, *(res.aka_vcts or [])]
    if cfg.extended_vct and res.type_metadata is not None:  # None when skipped
        types.extend(_tm_chain(res.type_metadata))
    return any(t in cfg.accepted_vcts for t in types)


@dataclass
class StatusClaim:
    present: bool = False  # the credential has status
    list: bool = False  # status has status_list; ref is set
    ref: Any = None
    past_int: bool = False  # idx is an integer too large for an int; ref.index is 0


def read_status(claims: dict[str, Any]) -> StatusClaim:
    """The status claim (draft-ietf-oauth-status-list-21 §6.2). ValueError is a status of the wrong shape."""
    Ref = _ref_class()

    if "status" not in claims:
        return StatusClaim()
    v = claims["status"]
    # §6.2: a JSON object with at least one status mechanism.
    if not isinstance(v, dict) or len(v) == 0:
        raise ValueError("status is not a JSON object holding a status mechanism (draft-ietf-oauth-status-list-21 §6.2)")
    if "status_list" not in v:
        return StatusClaim(present=True)
    sl = v["status_list"]
    lst = sl if isinstance(sl, dict) else {}  # no uri, when not an object
    u = lst.get("uri")
    if not is_str(u):
        raise ValueError("status.status_list is not a JSON object with a string uri (draft-ietf-oauth-status-list-21 §6.2)")
    # §6.2: idx is a non-negative Integer, a value, so every RFC 8259 §6 form of it counts: 1.0,
    # 1e3 and -0 too. jsonint reads it exactly.
    n = lst.get("idx")
    st = StatusClaim(present=True, list=True)
    idx = 0
    try:
        if not isinstance(n, jose_json.JsonNumber):
            raise jsonint.ErrNotInteger  # any other type reads as "" and fails
        idx = jsonint.non_negative(str(n))
    except Exception as e:
        if errors_is(e, jsonint.ErrTooLarge):
            st.past_int, idx = True, 0
        else:
            raise ValueError(
                "status.status_list.idx is absent or not a non-negative integer (draft-ietf-oauth-status-list-21 §6.2)"
            ) from None
    st.ref = Ref(uri=u, index=idx)
    # The cause is the token's, so it must not match ErrInvalidArgument.
    try:
        st.ref.validate()
    except Exception as e:
        raise ValueError(f"status.status_list: {e}") from None
    return st


def _ref_class() -> Any:
    """statuslist.Ref (Go: statuslist.Ref), wherever the statuslist package keeps it."""
    try:
        from digitalcredential.statuslist import Ref
    except ImportError:
        from digitalcredential.statuslist.checker import Ref
    return Ref


def _check_status(cfg: VerifyConfig, st: StatusClaim, iss: str) -> int:
    """Ask the StatusChecker for the status st refers to. Its errors are DigitalCredentialError or ErrPolicy."""
    from digitalcredential.statuslist.errors import ErrIndexOutOfBounds

    if not st.list:
        raise _reject(
            E.STATUS_UNAVAILABLE,
            "status has no status_list, the one mechanism this SDK checks (draft-ietf-oauth-status-list-21 §8.3 step 1); "
            "without_status_check accepts it unchecked",
        )
    # No list holds more entries than an int counts.
    if st.past_int:
        raise _reject(E.MALFORMED, combine("status_list idx is past every status list", _oob_class(ErrIndexOutOfBounds)))
    if cfg.status is None:
        raise policy_err("the credential has a status_list: pass with_status, such as with a statuslist.Checker, or without_status_check")
    try:
        return cfg.status.status(st.ref, iss)
    except Exception as e:
        # A definite answer: §8.3 step 6 says MUST reject.
        if errors_is(e, ErrIndexOutOfBounds):
            raise _reject(E.MALFORMED, e) from e
        # Verify validated the Ref, so this is the checker's wiring, such as a statuslist.Checker
        # not made by its constructor, or one whose resolver returned a key it cannot verify with.
        if errors_is(e, ErrInvalidArgument):
            ks = _key_sentinel(e)
            raise policy_err(f"with_status: {e}", *([ks] if ks else [])) from None
        # Never by ErrMalformed: a fetch can fail with it too.
        raise _reject(E.STATUS_UNAVAILABLE, combine(f"StatusChecker: {e}", type(e))) from e


def _oob_class(sentinel: Any) -> type:
    # ErrIndexOutOfBounds may be an exception class or an instance.
    return sentinel if isinstance(sentinel, type) else type(sentinel)


def _key_sentinel(err: BaseException) -> type | None:
    """The class by which err says that jws.verify got a key it cannot verify with, or None."""
    for k in _KEY_SENTINELS:
        if errors_is(err, k):
            return k
    return None


# --- Type Metadata adapters (digitalcredential.typemeta is ported separately) ---------------------


def _tm_load(resolver: Any, vct: str, integrity: str) -> Any:
    from digitalcredential import typemeta

    return typemeta.Load(resolver, typemeta.Ref(vct=vct, integrity=integrity))


def _tm_validate_claims(m: Any, r: Any, all_disclosures: bool) -> None:
    from digitalcredential import typemeta

    typemeta.validate_claims_payload(m, r.issued, typemeta.ValidateOptions(all_disclosures=all_disclosures))


def _tm_chain(m: Any) -> list[str]:
    c = getattr(m, "chain", [])
    return list(c() if callable(c) else c)
