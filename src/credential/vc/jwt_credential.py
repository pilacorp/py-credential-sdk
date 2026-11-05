"""VC 1.1 JWT credential (typ "JWT", claims under ``vc``). Port of Go credential/vc/jwt_credential.go."""
from __future__ import annotations

import hashlib
from typing import Any

from credential.common.jwt import JWTVerifier, SigningKey, jwtutil, resolve_signing_key
from credential.common.sdjwt import DecodedDisclosure
from credential.vc import credential_helper as helper
from credential.vc._jose_checks import (
    SDJWT_REQUIRES_JOSE_MSG,
    carries_sdjwt,
    execute_common_options,
    is_jwt_credential,
    refuse_overwrite,
    reject_build_time_options,
)
from credential.vc.credential import (
    CredentialContents,
    CredentialOpt,
    get_options,
    signing_options,
    with_verify_proof,
)


class JWTCredential:
    def __init__(
        self,
        signing_input: str,
        payload_data: dict[str, Any],
        jwt_claims: dict[str, Any] | None = None,
        signature: str = "",
        signing_key: SigningKey | None = None,
    ) -> None:
        self.signing_input = signing_input
        self.payload_data = payload_data  # the vc claim
        self.jwt_claims = jwt_claims if jwt_claims is not None else {}  # iss, sub, exp, nbf, iat, jti
        self.signature = signature
        self.signing_key = signing_key or SigningKey()  # empty for a parsed credential

    # ---- construction -------------------------------------------------
    @classmethod
    def create(cls, vcc: CredentialContents, *opts: CredentialOpt) -> JWTCredential:
        options = get_options(*opts)
        if options.has_sd_options():
            raise ValueError(f"NewJWTCredential: {SDJWT_REQUIRES_JOSE_MSG}")
        try:
            m = helper.serialize_credential_contents(vcc)
        except ValueError as exc:
            raise ValueError(f"failed to serialize credential contents: {exc}") from exc
        vc_map = helper.normalize_map(m)
        if carries_sdjwt(vc_map):
            raise ValueError(f"NewJWTCredential: contents carry SD-JWT digests: {SDJWT_REQUIRES_JOSE_MSG}")

        other: dict[str, Any] = {}
        if vcc.issuer:
            other["iss"] = vcc.issuer
        if vcc.subject and vcc.subject[0].id:
            other["sub"] = vcc.subject[0].id
        if vcc.valid_until:
            other["exp"] = int(vcc.valid_until.timestamp())
        if vcc.valid_from:
            other["iat"] = int(vcc.valid_from.timestamp())
            other["nbf"] = int(vcc.valid_from.timestamp())
        if vcc.id:
            other["jti"] = vcc.id
        payload = {"vc": vc_map, **other}

        # Resolve the VM so alg reflects the key it holds and a bad kid fails here.
        key = resolve_signing_key(vcc.issuer, "assertionMethod", options.verification_method_key, options.resolver)
        header = {"typ": "JWT", "alg": key.alg, "kid": key.id}
        signing_input = (
            jwtutil.b64url_encode(jwtutil.json_dumps(header)) + "." + jwtutil.b64url_encode(jwtutil.json_dumps(payload))
        )
        cred = cls(signing_input, vc_map, other, "", key)
        cred._execute_options(*opts)
        return cred

    @classmethod
    def parse(cls, raw_jwt: str, *opts: CredentialOpt) -> JWTCredential:
        raw_jwt = raw_jwt.strip('"').strip()
        # base64url has no "~", so a "~" means the SD-JWT combined form.
        if "~" in raw_jwt:
            raise ValueError(f"ParseJWTCredential: token is in SD-JWT combined form: {SDJWT_REQUIRES_JOSE_MSG}")
        if not is_jwt_credential(raw_jwt):
            raise ValueError("invalid JWT format")
        parts = raw_jwt.split(".")
        try:
            payload_map = jwtutil.json_loads(jwtutil.b64url_decode(parts[1]))
        except ValueError as exc:
            raise ValueError(f"failed to decode payload: {exc}") from exc
        if not isinstance(payload_map, dict):
            raise ValueError("failed to unmarshal payload: not a JSON object")
        if carries_sdjwt(payload_map):
            raise ValueError(f"ParseJWTCredential: payload carries SD-JWT digests: {SDJWT_REQUIRES_JOSE_MSG}")
        if "vc" not in payload_map:
            raise ValueError("vc claim not found in JWT payload")
        vc_map = payload_map["vc"]
        if not isinstance(vc_map, dict):
            raise ValueError("vc claim is not a valid JSON object")
        cred = cls(parts[0] + "." + parts[1], vc_map, payload_map, parts[2])
        cred._execute_options(*opts)
        return cred

    # ---- signing ------------------------------------------------------
    def add_proof(self, priv: str, *opts: CredentialOpt) -> None:
        from didv2.signer import DefaultProvider

        try:
            provider = DefaultProvider(priv)
        except Exception as exc:
            raise ValueError(f"failed to create default signer: {exc}") from exc
        self.add_proof_by_provider(provider, *opts)

    def add_proof_by_provider(self, signer: Any, *opts: CredentialOpt) -> None:
        if signer is None:
            raise ValueError("signer provider cannot be nil")
        o = get_options(*opts)
        reject_build_time_options(o)
        refuse_overwrite(self.signature, o)
        self._execute_options(*signing_options(list(opts)))
        digest = hashlib.sha256(self.signing_input.encode()).digest()
        try:
            raw = signer.sign(digest)
        except Exception as exc:
            raise ValueError(f"failed to sign signing input: {exc}") from exc
        self.signature = self.signing_key.accept(self.signing_input, raw)

    def get_signing_input(self) -> bytes:
        return self.signing_input.encode()

    def add_custom_proof(self, proof: Any, *opts: CredentialOpt) -> None:
        if proof is None:
            raise ValueError("proof cannot be nil")
        if not proof.signature:
            raise ValueError("proof signature cannot be empty")
        o = get_options(*opts)
        reject_build_time_options(o)
        refuse_overwrite(self.signature, o)
        self._execute_options(*signing_options(list(opts)))
        self.signature = self.signing_key.accept(self.signing_input, proof.signature)

    # ---- reading ------------------------------------------------------
    def verify(self, *opts: CredentialOpt) -> None:
        self._execute_options(*opts, with_verify_proof())

    def serialize(self) -> str:
        return self.signing_input if self.signature == "" else self.signing_input + "." + self.signature

    def hash(self) -> str:
        if self.signature == "":
            raise ValueError("credential must be signed before hashing")
        return hashlib.sha256(self.serialize().encode()).hexdigest()

    def get_contents(self) -> bytes:
        return jwtutil.json_dumps(self.payload_data)

    def get_type(self) -> str:
        return "JWT"

    def extract_field(self, path: str) -> Any:
        if not self.payload_data:
            return None
        return helper.extract_field_from_map(self.payload_data, path)

    def decoded_disclosures(self) -> list[DecodedDisclosure]:
        """A VC 1.1 JWT carries none; always an empty list (deprecated, kept for callers)."""
        return []

    def present(self, selected_disclosures: list[str]) -> Any:
        raise ValueError(SDJWT_REQUIRES_JOSE_MSG)

    # ---- options ------------------------------------------------------
    def _execute_options(self, *opts: CredentialOpt) -> None:
        options = get_options(*opts)
        execute_common_options(self.payload_data, options)
        if options.is_verify_proof:
            if self.signature == "":
                raise ValueError("credential verification failed: credential is not signed")
            try:
                JWTVerifier(options.resolver).verify_jwt(self.signing_input + "." + self.signature)
            except Exception as exc:
                raise ValueError(f"credential verification failed: verify proof: {exc}") from exc
        if options.is_check_expiration:
            # validFrom/validUntil describe the credential; exp/nbf (top level) the token.
            try:
                helper.check_expiration(self.payload_data, options.leeway)
                jwtutil.check_time_claims(self.jwt_claims, options.leeway)
            except ValueError as exc:
                raise ValueError(f"failed to check expiration: {exc}") from exc


def new_jwt_credential(vcc: CredentialContents, *opts: CredentialOpt) -> JWTCredential:
    return JWTCredential.create(vcc, *opts)


def parse_jwt_credential(raw_jwt: str, *opts: CredentialOpt) -> JWTCredential:
    return JWTCredential.parse(raw_jwt, *opts)
