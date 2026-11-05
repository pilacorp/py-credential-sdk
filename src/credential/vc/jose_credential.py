"""W3C vc-jose-cose credential (typ vc+jwt / vc+sd-jwt). Port of Go credential/vc/jose_credential.go.

The unsecured VC is the flat JWS payload (no ``vc`` wrapper claim).
"""
from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

from credential.common import sdjwt
from credential.common.jwt import JWTVerifier, SigningKey, jwtutil, resolve_signing_key
from credential.vc import credential_helper as helper
from credential.vc._jose_checks import (
    CREDENTIALS_V2_CONTEXT,
    execute_common_options,
    is_jwt_credential,
    refuse_overwrite,
    reject_build_time_options,
    require_disclosable_at_top_level,
    require_jose_credential,
    require_secured_claims_signed,
    require_v2_context,
)
from credential.vc.credential import (
    TYPE_ENVELOPED_VC,
    TYPE_VC_JWT,
    TYPE_VC_SD_JWT,
    CredentialContents,
    CredentialOpt,
    get_options,
    signing_options,
    with_verify_proof,
)

TYPE_JOSE = "JOSE"  # what get_type reports


def is_jose_credential_typ(typ: str) -> bool:
    """vc+jwt / vc+sd-jwt, short or application/ spelling. jwt.verifier.purpose_from_typ must know every value."""
    return typ in (TYPE_VC_JWT, "application/" + TYPE_VC_JWT, TYPE_VC_SD_JWT, "application/" + TYPE_VC_SD_JWT)


class JOSECredential:
    def __init__(
        self,
        signing_input: str,
        payload_data: dict[str, Any],
        signature: str = "",
        disclosures: list[str] | None = None,
        disclosable: bool = False,
        signing_key: SigningKey | None = None,
    ) -> None:
        self.signing_input = signing_input
        self.payload_data = payload_data
        self.signature = signature
        self.disclosures = list(disclosures or [])
        self.disclosable = disclosable
        self.signing_key = signing_key or SigningKey()

    @classmethod
    def create(cls, vcc: CredentialContents, *opts: CredentialOpt) -> JOSECredential:
        # vc+jwt names version 2: default an empty context, refuse a v1 one.
        if not vcc.context:
            vcc = dataclasses.replace(vcc, context=[CREDENTIALS_V2_CONTEXT])
        else:
            require_v2_context(vcc.context)
        try:
            m = helper.serialize_credential_contents(vcc)
        except ValueError as exc:
            raise ValueError(f"failed to serialize credential contents: {exc}") from exc
        vc_map = helper.normalize_map(m)
        options = get_options(*opts)

        # Same check ParseJOSECredential runs, so the two ends cannot disagree.
        require_jose_credential(vc_map)

        try:
            result = sdjwt.build_disclosures(
                vc_map,
                options.sd_selective_paths,
                options.sd_alg,
                options.sd_shuffle,
                options.sd_decoys,
            )
        except ValueError as exc:
            raise ValueError(f"failed to build SD-JWT disclosures: {exc}") from exc
        vc_map = result["processed_vc"]
        disclosures = list(result["disclosures"]) + list(options.sd_disclosures)

        # Prebuilt disclosures need _sd_alg too: it marks the payload as SD (default sha-256).
        if options.sd_disclosures and "_sd_alg" not in vc_map:
            vc_map["_sd_alg"] = options.sd_alg or sdjwt.DEFAULT_HASH_ALGORITHM

        require_disclosable_at_top_level(vc_map, True)
        try:
            sdjwt.reconstruct(vc_map, disclosures, True)  # deep-copies; validates only
        except ValueError as exc:
            raise ValueError(f"invalid SD-JWT disclosures: {exc}") from exc

        disclosable = "_sd_alg" in vc_map

        # vc-jose-cose 1.1.2.1: vc and vp MUST NOT be present.
        vc_map.pop("vc", None)
        vc_map.pop("vp", None)
        # Without iat the verifier has no signing time for a soft-revocation check.
        jwtutil.set_issued_at(vc_map)

        key = resolve_signing_key(vcc.issuer, "assertionMethod", options.verification_method_key, options.resolver)
        header = {"typ": TYPE_VC_SD_JWT if disclosable else TYPE_VC_JWT, "alg": key.alg, "kid": key.id}
        signing_input = (
            jwtutil.b64url_encode(jwtutil.json_dumps(header)) + "." + jwtutil.b64url_encode(jwtutil.json_dumps(vc_map))
        )
        cred = cls(signing_input, vc_map, "", disclosures, disclosable, key)
        cred._execute_options(*opts)
        return cred

    @classmethod
    def parse(cls, raw_jwt: str, *opts: CredentialOpt) -> JOSECredential:
        raw_jwt = raw_jwt.strip('"').strip()
        disclosures: list[str] = []
        if sdjwt.is_sd_jwt(raw_jwt):
            try:
                parsed = sdjwt.parse(raw_jwt)
            except ValueError as exc:
                raise ValueError(f"failed to parse SD-JWT: {exc}") from exc
            issuer_jwt = parsed.base_jwt
            disclosures = parsed.disclosures
        else:
            if not is_jwt_credential(raw_jwt):
                raise ValueError("invalid JWT or SD-JWT format")
            issuer_jwt = raw_jwt

        parts = issuer_jwt.split(".")
        if len(parts) < 2:
            raise ValueError("invalid JWT or SD-JWT format")
        header_enc, payload_enc = parts[0], parts[1]
        signature = parts[2] if len(parts) == 3 else ""

        try:
            header = jwtutil.json_loads(jwtutil.b64url_decode(header_enc))
        except ValueError as exc:
            raise ValueError(f"failed to decode header: {exc}") from exc
        if not isinstance(header, dict):
            raise ValueError("failed to unmarshal header: not a JSON object")
        typ = header.get("typ") if isinstance(header.get("typ"), str) else ""
        if not is_jose_credential_typ(typ):
            raise ValueError(
                f'invalid typ header for JOSECredential: got "{typ}", want "{TYPE_VC_JWT}" or "{TYPE_VC_SD_JWT}"'
            )

        try:
            payload_map = jwtutil.json_loads(jwtutil.b64url_decode(payload_enc))
        except ValueError as exc:
            raise ValueError(f"failed to decode payload: {exc}") from exc
        if not isinstance(payload_map, dict):
            raise ValueError("failed to unmarshal payload: not a JSON object")

        if "vc" in payload_map:
            raise ValueError("invalid vc-jose-cose: 'vc' claim MUST NOT be present in payload")
        if "vp" in payload_map:
            raise ValueError("invalid vc-jose-cose: 'vp' claim MUST NOT be present in payload")

        # SD-ness is decided by the media type and the combined format (and _sd_alg as a third
        # signal), never by _sd_alg alone: RFC 9901 4.1.1 makes it optional.
        has_sd_alg = "_sd_alg" in payload_map
        declared_sd = typ.removeprefix("application/") == TYPE_VC_SD_JWT
        combined_sd = sdjwt.is_sd_jwt(raw_jwt)
        if not declared_sd and (combined_sd or has_sd_alg):
            raise ValueError(f'typ "{typ}" does not match the SD-JWT format')

        # Nothing outside credentialSubject may be disclosable; runs before reconstruct
        # because reconstruct removes the evidence.
        require_disclosable_at_top_level(payload_map, declared_sd)

        vc_map = payload_map
        disclosable = declared_sd or combined_sd or has_sd_alg
        if disclosable or disclosures:
            try:
                vc_map = sdjwt.reconstruct(vc_map, disclosures, True)
            except ValueError as exc:
                raise ValueError(f"failed to reconstruct SD-JWT payload: {exc}") from exc

        try:
            require_secured_claims_signed(payload_map, vc_map)
        except ValueError as exc:
            raise ValueError(f"invalid {typ} payload: {exc}") from exc

        # A signature proves who made the bytes, not that they are a credential.
        require_jose_credential(vc_map)

        cred = cls(header_enc + "." + payload_enc, vc_map, signature, disclosures, disclosable)
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
        # accept trims a recovery id, checks the shape and the key; assigned only after,
        # so a failed call cannot clear an existing signature.
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
        base = self.signing_input
        if self.signature != "":
            base += "." + self.signature
        if not self.disclosable:
            return base
        # Terminated even with no disclosure left: the payload still holds the digests.
        return base + "".join("~" + d for d in self.disclosures if d) + "~"

    def decoded_disclosures(self) -> list[sdjwt.DecodedDisclosure]:
        return sdjwt.decode_disclosures(self.disclosures)

    def present(self, selected_disclosures: list[str]) -> JOSECredential:
        """Same credential carrying only selected_disclosures; the signature still verifies."""
        if self.signature == "":
            raise ValueError("cannot present an unsigned credential")
        if not self.disclosable:
            raise ValueError("credential carries no disclosures; nothing to present selectively")
        return JOSECredential.parse(
            sdjwt.build_sd_jwt_presentation(self.signing_input + "." + self.signature, selected_disclosures)
        )

    def hash(self) -> str:
        if self.signature == "":
            raise ValueError("credential must be signed before hashing")
        return hashlib.sha256(self.serialize().encode()).hexdigest()

    def get_contents(self) -> bytes:
        return jwtutil.json_dumps(self.payload_data)

    def get_type(self) -> str:
        return TYPE_JOSE

    def extract_field(self, path: str) -> Any:
        if not self.payload_data:
            return None
        return helper.extract_field_from_map(self.payload_data, path)

    def _execute_options(self, *opts: CredentialOpt) -> None:
        options = get_options(*opts)
        execute_common_options(self.payload_data, options)
        if options.is_verify_proof:
            if self.signature == "":
                raise ValueError("credential verification failed: credential is not signed")
            try:
                # Verify the base JWS directly, ignoring disclosures / envelopes.
                JWTVerifier(options.resolver).verify_jwt(self.signing_input + "." + self.signature)
                # exp/nbf bound the signature, not the credential.
                jwtutil.check_time_claims(self.payload_data, options.leeway)
            except Exception as exc:
                raise ValueError(f"credential verification failed: verify proof: {exc}") from exc
        if options.is_check_expiration:
            try:
                helper.check_expiration(self.payload_data, options.leeway)
            except ValueError as exc:
                raise ValueError(f"failed to check expiration: {exc}") from exc


def new_jose_credential(vcc: CredentialContents, *opts: CredentialOpt) -> JOSECredential:
    return JOSECredential.create(vcc, *opts)


def parse_jose_credential(raw_jwt: str, *opts: CredentialOpt) -> JOSECredential:
    return JOSECredential.parse(raw_jwt, *opts)
