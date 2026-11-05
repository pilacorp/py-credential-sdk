"""Shared fixtures for the vp tests (Go: helpers spread over credential/vp/*_test.go and internal/jwttest)."""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from eth_keys import keys

from credential.common.dto.proof import Proof
from credential.common.jsonmap import JSONMap
from credential.common.jwt import JWTSigner, JWTVerifier
from credential.common.jwt.jwtutil import b64url_encode, json_dumps
from credential.common.signer.p256 import P256Provider
from credential.common.verification_method import (
    StaticResolver,
    new_did_document,
    new_p256_multikey_vm,
    new_p256_vm,
    new_secp256k1_vm,
)
from credential.vc import credential as vc
from credential.vp.presentation import PresentationContents
from didv2.signer import DefaultProvider

TEST_DID = "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce"
TEST_SECP_PRIV_HEX = "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
TEST_P256_PRIV_HEX = "1f2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff001"
HOLDER_SECP = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
JWS_HOLDER_DID = "did:example:vp-holder"
HOLDER_P256_PRIV = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
WRONG_P256_PRIV = "1111111111111111111111111111111111111111111111111111111111111111"
V2 = "https://www.w3.org/ns/credentials/v2"


def secp_pub_hex(priv_hex: str) -> str:
    """Uncompressed 04||X||Y hex, no 0x prefix (go-ethereum FromECDSAPub)."""
    return "04" + keys.PrivateKey(bytes.fromhex(priv_hex)).public_key.to_bytes().hex()


def default_signer(priv_hex: str = TEST_SECP_PRIV_HEX) -> DefaultProvider:
    return DefaultProvider(priv_hex)


def p256_from_hex(priv_hex: str = TEST_P256_PRIV_HEX) -> P256Provider:
    b = bytes.fromhex(priv_hex)
    return P256Provider(b.rjust(32, b"\x00"))


def p256_pub(prov: P256Provider) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), prov.public_key_uncompressed())


def p256_vm(did: str, frag: str, prov: P256Provider):
    return new_p256_vm(did, frag, p256_pub(prov))


def test_resolver() -> StaticResolver:
    """TEST_DID's document: key-1 secp256k1, key-2 P-256."""
    p = p256_from_hex()
    return StaticResolver(
        [
            new_did_document(
                TEST_DID,
                [new_secp256k1_vm(TEST_DID, "key-1", secp_pub_hex(TEST_SECP_PRIV_HEX)), p256_vm(TEST_DID, "key-2", p)],
            )
        ]
    )


test_resolver.__test__ = False  # not a pytest test


class RSAProvider:
    """RS256 signer over a SHA-256 digest (Go signer.NewRSAProvider)."""

    def __init__(self, key: rsa.RSAPrivateKey | None = None) -> None:
        self.key = key or rsa.generate_private_key(65537, 2048)

    def sign(self, digest: bytes) -> bytes:
        return self.key.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))

    def jose_algorithm(self) -> str:
        return "RS256"


class FailingSigner:
    def __init__(self, msg: str = "remote signer unavailable") -> None:
        self.msg = msg

    def sign(self, digest: bytes) -> bytes:
        raise RuntimeError(self.msg)


class CountingSigner:
    def __init__(self, inner) -> None:
        self.inner = inner
        self.calls = 0

    def sign(self, digest: bytes) -> bytes:
        self.calls += 1
        return self.inner.sign(digest)


def sign_externally(signer, data: str) -> bytes:
    """Sign the way a caller outside the SDK does: SHA-256 then the raw signer output."""
    return signer.sign(hashlib.sha256(data.encode()).digest())


def verify_by_hand(resolver, signing_input: str, sig: bytes) -> None:
    if len(sig) == 65:
        sig = sig[:64]
    JWTVerifier(resolver).verify_jwt(signing_input + "." + b64url_encode(sig))


def sign_compact(signer, kid: str, payload: dict, typ: str = "vp+jwt", alg: str = "ES256") -> str:
    header = {"typ": typ, "alg": alg, "kid": kid}
    signing_input = b64url_encode(json_dumps(header)) + "." + b64url_encode(json_dumps(payload))
    return signing_input + "." + JWTSigner(signer).sign_string(signing_input)


def jose_vp_contents(holder: str) -> PresentationContents:
    return PresentationContents(context=[V2], id="urn:uuid:jose-vp-001", types=["VerifiablePresentation"], holder=holder)


def jose_vp_fixture(did: str):
    prov = P256Provider()
    resolver = StaticResolver([new_did_document(did, [p256_vm(did, "key-1", prov)])])
    return resolver, prov


def jose_vp_credential_contents(issuer: str) -> vc.CredentialContents:
    return vc.CredentialContents(
        context=[V2],
        types=["VerifiableCredential"],
        issuer=issuer,
        valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
        subject=[vc.Subject(id="did:example:subject")],
    )


def vp_doc(holder: str) -> bytes:
    return (
        '{"@context": ["https://www.w3.org/ns/credentials/v2"],'
        '"id": "urn:uuid:vp-jws-001", "type": ["VerifiablePresentation"],'
        f'"holder": "{holder}", "verifiableCredential": []}}'
    ).encode()


def jwt_payload(token: str) -> dict:
    from credential.common.jwt.jwtutil import b64url_decode

    return json.loads(b64url_decode(token.split(".")[1]))


def jwt_header(token: str) -> dict:
    from credential.common.jwt.jwtutil import b64url_decode

    return json.loads(b64url_decode(token.split(".")[0]))


def err_chain_has(exc: BaseException, cls: type) -> bool:
    """errors.Is: does the cause chain contain an instance of cls."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, cls):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


def sign_via_jsonmap(pres, signer, vm_url: str, use_jws: bool):
    """Sign a copy through jsonmap, bypassing vp's VM selection (JWS2020/RSA, pinned rdfc)."""
    from credential.vp.json_presentation import JSONPresentation

    m = JSONMap(json.loads(pres.get_contents()))
    if use_jws:
        m.add_jws_proof(signer, vm_url, "authentication")
    else:
        m.add_ecdsa_proof(signer, vm_url, "authentication")
    return JSONPresentation.parse(json.dumps(m.data).encode())


def proof_from_json(raw) -> Proof:
    from credential.common.jsonmap import parse_raw_to_proof

    return parse_raw_to_proof(raw)
