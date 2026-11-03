from __future__ import annotations

from typing import Any

from credential.common.jwt.signer import JWTSigner
from credential.vc.helper import serialize_credential_contents
from credential.vc.jwt_credential import JWTCredential


class JOSECredential:
    """W3C vc-jose-cose credential wrapper (typ: vc+jwt)."""

    def __init__(self, inner: JWTCredential) -> None:
        self._inner = inner

    @classmethod
    def create(cls, vcc: dict[str, Any], kid: str = "key-1") -> JOSECredential:
        contents = serialize_credential_contents(vcc)
        if not contents.get("@context"):
            contents["@context"] = ["https://www.w3.org/ns/credentials/v2"]
        flat = dict(contents)
        header = {
            "typ": "vc+jwt",
            "alg": "ES256K",
            "kid": f"{flat.get('issuer', '')}#{kid}",
        }
        import base64
        import json

        def b64(obj: dict[str, Any]) -> str:
            raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        signing_input = b64(header) + "." + b64(flat)
        inner = JWTCredential(signing_input, flat)
        return cls(inner)

    @classmethod
    def parse(cls, token: str) -> JOSECredential:
        return cls(JWTCredential.parse(token))

    def sign(self, signer: JWTSigner) -> None:
        from didv2.signer import DefaultProvider

        if isinstance(signer, JWTSigner):
            self._inner.add_proof(signer._signer)  # noqa: SLF001
        elif isinstance(signer, DefaultProvider):
            self._inner.add_proof(signer)
        else:
            raise TypeError("signer must be JWTSigner or DefaultProvider")

    def serialize(self) -> str:
        return self._inner.serialize()

    def payload(self) -> dict[str, Any]:
        return self._inner.payload()
