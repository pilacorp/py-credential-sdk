from __future__ import annotations

import hashlib
from typing import Any

from credential.common.dto.proof import Proof
from credential.common.jwt.jwtutil import (
    b64url_decode,
    b64url_encode,
    check_time_claims,
    json_dumps,
    json_loads,
    set_issued_at,
)
from credential.common.jwt.signing_key import SigningKey, resolve_signing_key
from credential.common.jwt.verifier import JWTVerifier
from credential.common.sdjwt.helper import is_sd_jwt
from credential.vc.credential import TYPE_ENVELOPED_VC, TYPE_VC_JWT, TYPE_VC_SD_JWT
from credential.vp.jwt_presentation import reject_build_time_options
from credential.vp.presentation import (
    Presentation,
    PresentationContents,
    PresentationOpt,
    PresentationOptions,
    check_audience,
    get_options,
    is_jwt_presentation,
    refuse_overwrite,
    signing_options,
    with_verify_proof,
)
from credential.vp.presentation_helper import (
    CONTEXT_V2,
    PresentationData,
    check_expiration,
    extract_field_from_map,
    first_context,
    has_type,
    serialize_presentation_contents,
    verify_credentials,
)

TYPE_VP_JWT = "vp+jwt"
TYPE_JOSE = "JOSE"
TYPE_VERIFIABLE_PRESENTATION = "VerifiablePresentation"


def is_jose_presentation_typ(typ: str) -> bool:
    """vp+jwt in either media type spelling. jwt verifier's purpose_from_typ must know every value accepted here."""
    return typ in (TYPE_VP_JWT, "application/" + TYPE_VP_JWT)


def require_jose_presentation(m: PresentationData) -> None:
    """The payload really is the VC 2.0 presentation its vp+jwt media type claims."""
    first = first_context(m.get("@context"))
    if first != CONTEXT_V2:
        raise ValueError(f'{TYPE_VP_JWT} payload must name "{CONTEXT_V2}" first in @context, got "{first}"')
    if not has_type(m.get("type"), TYPE_VERIFIABLE_PRESENTATION):
        raise ValueError(f"{TYPE_VP_JWT} payload must have type {TYPE_VERIFIABLE_PRESENTATION}")


def require_enveloped_credentials(m: PresentationData) -> None:
    """vc-jose-cose 3.1.2: credentials inside a vp+jwt MUST be EnvelopedVerifiableCredential."""
    v = m.get("verifiableCredential")
    if v is None:
        return
    items = v if isinstance(v, list) else [v]
    for i, item in enumerate(items):
        if not isinstance(item, dict) or not has_type(item.get("type"), TYPE_ENVELOPED_VC):
            raise ValueError(
                f"credential at index {i} must be an {TYPE_ENVELOPED_VC}; a {TYPE_VP_JWT} carries credentials "
                "enveloped, not bare"
            )


def envelope_media_type(token: str) -> str:
    """Media type for the data: URL of an EnvelopedVerifiableCredential (SD-JWTs under their own)."""
    base = token.split("~", 1)[0]
    parts = base.split(".")
    if len(parts) != 3 or parts[2] == "":
        raise ValueError("credential is not signed; sign it before putting it in a presentation")
    return TYPE_VC_SD_JWT if is_sd_jwt(token) else TYPE_VC_JWT


class JOSEPresentation(Presentation):
    """W3C vc-jose-cose presentation (typ: vp+jwt); the payload is the flat unsecured VP."""

    def __init__(
        self,
        signing_input: str,
        payload_data: PresentationData,
        signature: str = "",
        signing_key: SigningKey | None = None,
    ) -> None:
        self.signing_input = signing_input
        self.payload_data = payload_data
        self.signature = signature
        self.signing_key = signing_key or SigningKey()

    @classmethod
    def create(cls, vpc: PresentationContents, *opts: PresentationOpt) -> JOSEPresentation:
        from credential.vc.jose_credential import JOSECredential

        if not vpc.context:
            vpc.context = [CONTEXT_V2]
        try:
            payload = serialize_presentation_contents(vpc)
        except ValueError as exc:
            raise ValueError(f"failed to serialize presentation contents: {exc}") from exc
        options = get_options(*opts)
        # refuse before signing what parse would refuse after
        require_jose_presentation(payload)

        if vpc.verifiable_credentials:
            enveloped = []
            for i, cred in enumerate(vpc.verifiable_credentials):
                if not isinstance(cred, JOSECredential):
                    raise ValueError(
                        f"credential at index {i} is {type(cred).__name__}: a vp+jwt presentation can only carry "
                        "enveloping-secured credentials; use a JSON presentation for Data Integrity credentials"
                    )
                try:
                    cred_str = cred.serialize()
                except Exception as exc:
                    raise ValueError(f"failed to serialize credential at index {i}: {exc}") from exc
                if not isinstance(cred_str, str):
                    raise ValueError(f"credential at index {i} serialized to {type(cred_str).__name__}, want a token string")
                try:
                    media = envelope_media_type(cred_str)
                except ValueError as exc:
                    raise ValueError(f"credential at index {i}: {exc}") from exc
                enveloped.append(
                    {
                        "@context": [CONTEXT_V2],
                        "type": [TYPE_ENVELOPED_VC],
                        "id": f"data:application/{media},{cred_str}",
                    }
                )
            payload["verifiableCredential"] = enveloped

        if options.challenge:
            payload["nonce"] = options.challenge
        if options.domain:
            payload["aud"] = options.domain
        payload.pop("vc", None)
        payload.pop("vp", None)
        # without iat the verifier has no signing time to compare a soft revocation against
        set_issued_at(payload)

        signing_key = resolve_signing_key(vpc.holder, "authentication", options.verification_method_key, options.resolver)
        header = {"typ": TYPE_VP_JWT, "alg": signing_key.alg, "kid": signing_key.id}
        signing_input = b64url_encode(json_dumps(header)) + "." + b64url_encode(json_dumps(payload))
        e = cls(signing_input, payload, "", signing_key)
        e._execute_options(*opts)
        return e

    @classmethod
    def parse(cls, raw: str, *opts: PresentationOpt) -> JOSEPresentation:
        raw = raw.strip().strip('"').strip()
        if not is_jwt_presentation(raw):
            raise ValueError("invalid JWT format")
        parts = raw.split(".")
        try:
            header = json_loads(b64url_decode(parts[0]))
        except ValueError as exc:
            raise ValueError(f"failed to decode header: {exc}") from exc
        if not isinstance(header, dict):
            raise ValueError("failed to unmarshal header: not a JSON object")
        typ = header.get("typ")
        typ = typ if isinstance(typ, str) else ""
        if not is_jose_presentation_typ(typ):
            raise ValueError(f'invalid typ header for JOSEPresentation: got "{typ}", want "{TYPE_VP_JWT}"')
        try:
            payload = json_loads(b64url_decode(parts[1]))
        except ValueError as exc:
            raise ValueError(f"failed to decode payload: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("failed to unmarshal payload: not a JSON object")
        if "vc" in payload:
            raise ValueError("invalid vc-jose-cose: 'vc' claim MUST NOT be present in payload")
        if "vp" in payload:
            raise ValueError("invalid vc-jose-cose: 'vp' claim MUST NOT be present in payload")
        # unconditional: decides whether this is a well-formed vp+jwt at all
        require_jose_presentation(payload)
        require_enveloped_credentials(payload)
        e = cls(parts[0] + "." + parts[1], payload, parts[2])
        e._execute_options(*opts)
        return e

    def add_proof(self, priv_hex: str, *opts: PresentationOpt) -> None:
        """Deprecated: prefer add_proof_by_provider."""
        from didv2.signer import DefaultProvider

        try:
            signer = DefaultProvider(priv_hex)
        except Exception as exc:
            raise ValueError(f"failed to create default signer: {exc}") from exc
        self.add_proof_by_provider(signer, *opts)

    def add_proof_by_provider(self, provider: Any, *opts: PresentationOpt) -> None:
        if provider is None:
            raise ValueError("signer provider cannot be nil")
        options = get_options(*opts)
        reject_build_time_options(options, False)
        refuse_overwrite(self.signature, options)
        payload, signing_input = self._pending_challenge_domain(options)
        try:
            raw = provider.sign(hashlib.sha256(signing_input.encode("utf-8")).digest())
        except Exception as exc:
            raise ValueError(f"failed to sign signing input: {exc}") from exc
        signature = self.signing_key.accept(signing_input, raw)
        # commit, and undo if the options reject what was produced
        prev = (self.payload_data, self.signing_input, self.signature)
        self.payload_data, self.signing_input, self.signature = payload, signing_input, signature
        try:
            self._execute_options(*signing_options(opts))
        except Exception:
            self.payload_data, self.signing_input, self.signature = prev
            raise

    def add_custom_proof(self, proof: Proof | None, *opts: PresentationOpt) -> None:
        if proof is None:
            raise ValueError("proof cannot be nil")
        if len(proof.signature) == 0:
            raise ValueError("proof signature cannot be empty")
        options = get_options(*opts)
        reject_build_time_options(options, True)
        refuse_overwrite(self.signature, options)
        self._execute_options(*signing_options(opts))
        self.signature = self.signing_key.accept(self.signing_input, proof.signature)

    def get_signing_input(self) -> bytes:
        return self.signing_input.encode("utf-8")

    def verify(self, *opts: PresentationOpt) -> None:
        self._execute_options(*opts, with_verify_proof())

    def serialize(self) -> str:
        return self.signing_input + "." + self.signature if self.signature else self.signing_input

    def hash(self) -> str:
        if self.signature == "":
            raise ValueError("presentation must be signed before hashing")
        return hashlib.sha256(self.serialize().encode("utf-8")).hexdigest()

    def get_contents(self) -> bytes:
        import json

        return json.dumps(self.payload_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def get_type(self) -> str:
        return TYPE_JOSE

    def extract_field(self, path: str) -> Any:
        if self.payload_data is None:
            return None
        return extract_field_from_map(self.payload_data, path)

    def _execute_options(self, *opts: PresentationOpt) -> None:
        options = get_options(*opts)
        errors: list[Exception] = []
        if options.is_validate_vc:
            try:
                verify_credentials(self.payload_data, options)
            except ValueError as exc:
                err = ValueError(f"verify credentials: {exc}")
                err.__cause__ = exc
                errors.append(err)
        if not errors and options.is_verify_proof:
            try:
                if self.signature == "":
                    raise ValueError("presentation is not signed")
                try:
                    JWTVerifier(options.resolver).verify_jwt(self.signing_input + "." + self.signature)
                    # exp and nbf bound the signature, not the presentation
                    check_time_claims(self.payload_data, options.leeway)
                    self._check_challenge_and_domain(options)
                except ValueError as exc:
                    raise ValueError(f"verify proof: {exc}") from exc
            except ValueError as exc:
                errors.append(exc)
        if errors:
            raise ValueError(f"presentation verification failed: {errors[0]}") from errors[0]
        if options.is_check_expiration:
            try:
                check_expiration(self.payload_data, options.leeway)
            except ValueError as exc:
                raise ValueError(f"failed to check expiration: {exc}") from exc

    def _pending_challenge_domain(self, options: PresentationOptions) -> tuple[PresentationData, str]:
        if not options.challenge and not options.domain:
            return self.payload_data, self.signing_input
        if self.payload_data is None:
            raise ValueError("presentation has no payload data to update")
        payload = dict(self.payload_data)
        if options.challenge:
            payload["nonce"] = options.challenge
        if options.domain:
            payload["aud"] = options.domain
        header = self.signing_input.split(".", 1)[0]
        return payload, header + "." + b64url_encode(json_dumps(payload))

    def _check_challenge_and_domain(self, options: PresentationOptions) -> None:
        if options.expected_challenge:
            nonce = self.payload_data.get("nonce")
            nonce = nonce if isinstance(nonce, str) else ""
            if nonce != options.expected_challenge:
                raise ValueError(f"nonce {nonce!r} does not match expected challenge {options.expected_challenge!r}")
        check_audience(self.payload_data.get("aud"), options)


def new_jose_presentation(vpc: PresentationContents, *opts: PresentationOpt) -> JOSEPresentation:
    return JOSEPresentation.create(vpc, *opts)


def parse_jose_presentation(raw: str, *opts: PresentationOpt) -> JOSEPresentation:
    return JOSEPresentation.parse(raw, *opts)
