"""Reading the Holder key from cnf: RFC 7800 §3, §3.1, §3.2 and draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3."""

from __future__ import annotations

from typing import Any

from jose.errors import ErrMalformed, ErrUnsupportedKey
from jose.jwk import jwk as jose_jwk

from digitalcredential.claims import is_str
from digitalcredential.errors import ErrKeyBindingUnsupported, combine, errors_is


class ErrNoCnf(Exception):
    """The credential has no cnf claim, neither in the Issuer-signed JWT nor in a disclosure.

    Whether that is an error, and whose, is the caller's to say, so it is no
    DigitalCredentialError.
    """


err_no_cnf = ErrNoCnf("dc: the credential has no cnf claim")  # legacy name


def holder_key(payload: dict[str, Any], r: Any) -> Any:
    """The Holder's public key from cnf.jwk of payload, the Issuer-signed JWT payload, with r recreated from it.

    It is the one reader of cnf.jwk in this package, and its errors describe
    the credential:
      - no cnf at all: ErrNoCnf;
      - cnf, or a claim inside it, in a disclosure (draft 19 §2.2.2.3), or a
        cnf with more than one of jwk, jwe and jku (RFC 7800 §3.1): ErrMalformed;
      - a cnf without jwk, or a cnf.jwk of a key type or curve jose/jwk does not
        convert: ErrKeyBindingUnsupported, the second also ErrUnsupportedKey;
      - a cnf or cnf.jwk that is not an object, a symmetric cnf.jwk, or a key
        to_public_key refuses as broken: ErrMalformed and jwk ErrBadKey.
    """
    # draft 19 §2.2.2.3: cnf "including any of their sub-claims" MUST NOT be in
    # a Disclosure. Checked on what was recreated, so a disclosed member such
    # as jku cannot join a cnf.jwk the Issuer signed in plain.
    if r.disclosed(["cnf"]):
        raise ErrMalformed(
            "dc: the credential's cnf, or a claim inside it, is in a disclosure, which "
            "draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids; the Issuer must reissue it with all of cnf in the Issuer-signed JWT"
        )
    if "cnf" not in payload:
        raise err_no_cnf
    try:
        return cnf_key(payload["cnf"])
    except Exception as e:
        if errors_is(e, ErrMalformed):
            # Only here is the credential already issued; Issue reads cnf with
            # cnf_key before signing, when nothing is to be reissued.
            raise combine(f"{e}; the Issuer must reissue the credential", *_classes_of(e)) from e
        raise


def _classes_of(e: Exception) -> tuple[type, ...]:
    return (type(e),)


def cnf_key(cnf: Any) -> Any:
    """The Holder's public key from cnf, the value of a cnf claim as jose decodes it."""
    obj = cnf if isinstance(cnf, dict) else None
    if obj is not None:
        # RFC 7800 §3.1: cnf MUST represent a single proof-of-possession key,
        # so at most one of jwk, jwe and jku may be present.
        if sum(1 for m in ("jwk", "jwe", "jku") if m in obj) > 1:
            raise ErrMalformed("dc: cnf has more than one of jwk, jwe and jku, and RFC 7800 §3.1 allows one")
        if "jwk" not in obj:
            raise ErrKeyBindingUnsupported(
                "its cnf has no jwk member, and this SDK binds only to cnf.jwk holding an EC P-256 or secp256k1 key"
            )
    m = obj.get("jwk") if obj is not None else None
    if not isinstance(m, dict):
        raise combine("dc: cnf or cnf.jwk is not a JSON object (RFC 7800 §3, §3.2)", ErrMalformed, jose_jwk.ErrBadKey)
    # RFC 7800 §3.2: a symmetric key goes in jwk only when the JWT is
    # encrypted, and the Issuer-signed JWT of an SD-JWT is a JWS.
    kty = m.get("kty")
    if is_str(kty) and kty == "oct":
        raise combine(
            "dc: cnf.jwk is a symmetric key in a JWT that is not encrypted (RFC 7800 §3.2)", ErrMalformed, jose_jwk.ErrBadKey
        )
    try:
        return jose_jwk.to_public_key(m)
    except ErrUnsupportedKey as e:
        raise combine(f"its cnf.jwk holds a key this SDK does not bind ({e})", ErrKeyBindingUnsupported, ErrUnsupportedKey) from e
    except Exception as e:
        raise combine(f"dc: cnf.jwk is not a usable key: {e}", ErrMalformed, jose_jwk.ErrBadKey) from e
