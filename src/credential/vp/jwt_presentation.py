from __future__ import annotations

import hashlib
from typing import Any

from credential.common.jwt.jwtutil import (
    b64url_decode,
    b64url_encode,
    check_time_claims,
    json_dumps,
    json_loads,
)
from credential.common.jwt.signing_key import SigningKey, resolve_signing_key
from credential.common.jwt.verifier import JWTVerifier
from credential.common.dto.proof import Proof
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
    PresentationData,
    check_expiration,
    extract_field_from_map,
    serialize_presentation_contents,
    verify_credentials,
)


def reject_build_time_options(o: PresentationOptions, signed_outside: bool) -> None:
    """Options a signing call can no longer apply: kid always; nonce/aud when signed outside."""
    if o.verification_method_key:
        raise ValueError(
            "WithVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed "
            "when the token was built — pass the option to NewJWTPresentation"
        )
    if signed_outside and (o.challenge or o.domain):
        raise ValueError(
            "WithChallenge / WithDomain cannot be applied by AddCustomProof: the signature already covers "
            "the signing input — pass them to NewJWTPresentation before GetSigningInput, or sign with "
            "AddProofByProvider"
        )


class JWTPresentation(Presentation):
    """VC 1.1 style JWT presentation: the presentation sits under the ``vp`` claim."""

    def __init__(
        self,
        signing_input: str,
        payload_data: PresentationData,
        jwt_claims: dict[str, Any] | None = None,
        signature: str = "",
        signing_key: SigningKey | None = None,
    ) -> None:
        self.signing_input = signing_input
        self.payload_data = payload_data
        self.jwt_claims = jwt_claims
        self.signature = signature
        self.signing_key = signing_key or SigningKey()

    @classmethod
    def create(cls, vpc: PresentationContents, *opts: PresentationOpt) -> JWTPresentation:
        try:
            payload_data = serialize_presentation_contents(vpc)
        except ValueError as exc:
            raise ValueError(f"failed to serialize presentation contents: {exc}") from exc

        other: dict[str, Any] = {}
        if vpc.holder:
            other["iss"] = vpc.holder
            other["sub"] = vpc.holder
        if vpc.valid_until is not None:
            other["exp"] = int(vpc.valid_until.timestamp())
        if vpc.valid_from is not None:
            other["iat"] = int(vpc.valid_from.timestamp())
            other["nbf"] = int(vpc.valid_from.timestamp())
        if vpc.id:
            other["jti"] = vpc.id
        payload: dict[str, Any] = {"vp": payload_data, **other}

        options = get_options(*opts)
        # challenge/domain map to the standard JWT claims nonce and aud
        if options.challenge:
            payload["nonce"] = options.challenge
        if options.domain:
            payload["aud"] = options.domain

        signing_key = resolve_signing_key(vpc.holder, "authentication", options.verification_method_key, options.resolver)
        header = {"typ": "JWT", "alg": signing_key.alg, "kid": signing_key.id}
        signing_input = b64url_encode(json_dumps(header)) + "." + b64url_encode(json_dumps(payload))
        e = cls(signing_input, payload_data, payload, "", signing_key)
        e._execute_options(*opts)
        return e

    @classmethod
    def parse(cls, raw: str, *opts: PresentationOpt) -> JWTPresentation:
        if not is_jwt_presentation(raw):
            raise ValueError("invalid JWT format")
        raw = raw.strip('"')
        parts = raw.split(".")
        try:
            payload_map = json_loads(b64url_decode(parts[1]))
        except ValueError as exc:
            raise ValueError(f"failed to decode payload: {exc}") from exc
        if not isinstance(payload_map, dict):
            raise ValueError("failed to unmarshal payload: not a JSON object")
        if "vp" not in payload_map:
            raise ValueError("vp claim not found in JWT payload")
        vp_map = payload_map["vp"]
        if not isinstance(vp_map, dict):
            raise ValueError("vp claim is not a valid JSON object")
        e = cls(parts[0] + "." + parts[1], vp_map, payload_map, parts[2])
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
        o = get_options(*opts)
        reject_build_time_options(o, False)
        refuse_overwrite(self.signature, o)
        # worked out here, committed only once there is a signature to go with it
        claims, signing_input = self._pending_challenge_domain(o)
        self._execute_options(*signing_options(opts))
        try:
            raw = provider.sign(hashlib.sha256(signing_input.encode("utf-8")).digest())
        except Exception as exc:
            raise ValueError(f"failed to sign signing input: {exc}") from exc
        signature = self.signing_key.accept(signing_input, raw)
        self.jwt_claims, self.signing_input, self.signature = claims, signing_input, signature

    def get_signing_input(self) -> bytes:
        return self.signing_input.encode("utf-8")

    def add_custom_proof(self, proof: Proof | None, *opts: PresentationOpt) -> None:
        """Attach a signature made outside the SDK over get_signing_input()."""
        if proof is None:
            raise ValueError("proof cannot be nil")
        if len(proof.signature) == 0:
            raise ValueError("proof signature cannot be empty")
        o = get_options(*opts)
        reject_build_time_options(o, True)
        refuse_overwrite(self.signature, o)
        self._execute_options(*signing_options(opts))
        self.signature = self.signing_key.accept(self.signing_input, proof.signature)

    def verify(self, *opts: PresentationOpt) -> None:
        self._execute_options(*opts, with_verify_proof())

    def serialize(self) -> str:
        return self.signing_input + "." + self.signature if self.signature else self.signing_input

    def get_contents(self) -> bytes:
        import json

        return json.dumps(self.payload_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def get_type(self) -> str:
        return "JWT"

    def extract_field(self, path: str) -> Any:
        return extract_field_from_map(self.payload_data, path)

    def credentials(self) -> list[Any]:
        vcs = self.payload_data.get("verifiableCredential")
        return list(vcs) if isinstance(vcs, list) else ([] if vcs is None else [vcs])

    def _execute_options(self, *opts: PresentationOpt) -> None:
        options = get_options(*opts)
        if options.is_validate_vc:
            try:
                verify_credentials(self.payload_data, options)
            except ValueError as exc:
                raise ValueError(f"failed to verify presentation: {exc}") from exc
        if options.is_check_expiration:
            # validFrom/validUntil describe the presentation, exp/nbf the token: check both
            try:
                check_expiration(self.payload_data, options.leeway)
                check_time_claims(self.jwt_claims or {}, options.leeway)
            except ValueError as exc:
                raise ValueError(f"failed to check expiration: {exc}") from exc
        if options.is_verify_proof:
            if self.signature == "":
                raise ValueError("presentation is not signed")
            try:
                JWTVerifier(options.resolver).verify_jwt(self.signing_input + "." + self.signature)
            except ValueError as exc:
                raise ValueError(f"failed to verify presentation: {exc}") from exc
            try:
                self._check_challenge_and_domain(options)
            except ValueError as exc:
                raise ValueError(f"failed to verify presentation: {exc}") from exc

    def _pending_challenge_domain(self, options: PresentationOptions) -> tuple[dict[str, Any] | None, str]:
        """Claims and signing input this call's challenge/domain would produce, WITHOUT writing them into self."""
        if not options.challenge and not options.domain:
            return self.jwt_claims, self.signing_input
        if self.jwt_claims is None:
            raise ValueError("presentation has no JWT claims to update")
        claims = dict(self.jwt_claims)
        if options.challenge:
            claims["nonce"] = options.challenge
        if options.domain:
            claims["aud"] = options.domain
        header = self.signing_input.split(".", 1)[0]
        return claims, header + "." + b64url_encode(json_dumps(claims))

    def _check_challenge_and_domain(self, options: PresentationOptions) -> None:
        claims = self.jwt_claims or {}
        if options.expected_challenge:
            nonce = claims.get("nonce")
            nonce = nonce if isinstance(nonce, str) else ""
            if nonce != options.expected_challenge:
                raise ValueError(f"nonce {nonce!r} does not match expected challenge {options.expected_challenge!r}")
        check_audience(claims.get("aud"), options)


def new_jwt_presentation(vpc: PresentationContents, *opts: PresentationOpt) -> JWTPresentation:
    return JWTPresentation.create(vpc, *opts)


def parse_jwt_presentation(raw: str, *opts: PresentationOpt) -> JWTPresentation:
    return JWTPresentation.parse(raw, *opts)
