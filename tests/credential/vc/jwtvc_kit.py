"""Shared fixtures for the JWT / JOSE credential tests (mirrors Go vc_test helpers)."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.signer.p256 import P256Provider
from credential.common.verification_method import (
    StaticResolver,
    new_did_document,
    new_p256_vm,
    new_secp256k1_vm,
)
from credential.vc.credential import CredentialContents, Subject
from didv2.signer import DefaultProvider

SECP_PRIV = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
V2 = "https://www.w3.org/ns/credentials/v2"
V1 = "https://www.w3.org/2018/credentials/v1"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pub_hex(priv_hex: str = SECP_PRIV) -> str:
    return "04" + DefaultProvider(priv_hex)._key.public_key.to_bytes().hex()  # noqa: SLF001


def p256_pair() -> tuple[P256Provider, ec.EllipticCurvePublicKey]:
    prov = P256Provider()
    return prov, prov._key.public_key()  # noqa: SLF001


def p256_setup(did: str, fragment: str = "key-1"):
    prov, pub = p256_pair()
    vm = new_p256_vm(did, fragment, pub)
    return prov, vm, StaticResolver([new_did_document(did, [vm])])


def secp_setup(did: str, fragment: str = "key-1", priv: str = SECP_PRIV):
    vm = new_secp256k1_vm(did, fragment, pub_hex(priv))
    return DefaultProvider(priv), vm, StaticResolver([new_did_document(did, [vm])])


def jose_contents(issuer: str, **kw) -> CredentialContents:
    c = CredentialContents(
        context=[V2],
        id="urn:uuid:jose-test-001",
        types=["VerifiableCredential", "AlumniCredential"],
        issuer=issuer,
        valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
        subject=[Subject(id="did:example:subject", custom_fields={"name": "Nguyen Van A"})],
    )
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def vc11_contents(issuer: str) -> CredentialContents:
    c = jose_contents(issuer)
    c.context = [V1]
    return c


def token(header: dict, payload: dict, sig: str = "fakesig") -> str:
    return b64(json.dumps(header).encode()) + "." + b64(json.dumps(payload).encode()) + "." + sig


def signing_input(header: dict, payload: dict) -> str:
    return b64(json.dumps(header).encode()) + "." + b64(json.dumps(payload).encode())


def sign_input(provider, si: str) -> str:
    """Sign like the SDK's JWTSigner (sha256 + r||s, base64url)."""
    from credential.common.jwt import JWTSigner

    return JWTSigner(provider).sign_string(si)


def sign_outside(provider, si: bytes) -> bytes:
    return provider.sign(hashlib.sha256(si).digest())


def parts(tok: str) -> list[str]:
    return tok.split(".")


def header_of(tok: str) -> dict:
    return json.loads(unb64(parts(tok)[0]))


def payload_of(tok: str) -> dict:
    return json.loads(unb64(parts(tok)[1]))
