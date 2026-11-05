from __future__ import annotations

import base64
from threading import RLock

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from credential.common.verification_method.key_material import encode_pub_multibase
from credential.common.verification_method.verification_method import (
    DIDDocument,
    JWK,
    VerificationMethodEntry,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class StaticResolver:
    """In-memory ResolverProvider over a fixed set of DID documents (no I/O)."""

    def __init__(self, docs: list[DIDDocument] | None = None) -> None:
        self._lock = RLock()
        self._docs: dict[str, DIDDocument] = {}
        for doc in docs or []:
            self.add(doc)

    def add(self, doc: DIDDocument | None) -> None:
        if doc is None or not doc.id:
            return
        with self._lock:
            self._docs[doc.id] = doc

    def resolve_document(self, did: str) -> DIDDocument:
        with self._lock:
            doc = self._docs.get(did)
        if doc is None:
            raise ValueError(f"static resolver: unknown did {did!r}")
        return doc


def new_did_document(did: str, vms: list[VerificationMethodEntry]) -> DIDDocument:
    """A document exposing vms under both assertionMethod and authentication."""
    ids = [vm.id for vm in vms]
    return DIDDocument(id=did, verification_method=list(vms), assertion_method=list(ids), authentication=list(ids))


def new_secp256k1_vm(did: str, fragment: str, pub_key_hex: str) -> VerificationMethodEntry:
    return VerificationMethodEntry(
        id=f"{did}#{fragment}",
        type="EcdsaSecp256k1VerificationKey2019",
        controller=did,
        public_key_hex=pub_key_hex,
    )


def new_rsa_vm(did: str, fragment: str, pub: rsa.RSAPublicKey) -> VerificationMethodEntry:
    nums = pub.public_numbers()
    return VerificationMethodEntry(
        id=f"{did}#{fragment}",
        type="JsonWebKey2020",
        controller=did,
        public_key_jwk=JWK(
            kty="RSA",
            n=_b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            e=_b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
        ),
    )


def new_p256_multikey_vm(did: str, fragment: str, pub: ec.EllipticCurvePublicKey) -> VerificationMethodEntry:
    if pub is None or not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("NewP256MultikeyVM requires a P-256 key")
    return VerificationMethodEntry(
        id=f"{did}#{fragment}",
        type="Multikey",
        controller=did,
        public_key_multibase=encode_pub_multibase(pub),
    )


def new_p256_vm(did: str, fragment: str, pub: ec.EllipticCurvePublicKey) -> VerificationMethodEntry:
    """JsonWebKey2020 VM from a P-256 public key."""
    if pub is None:
        raise ValueError("NewP256VM requires a non-nil public key")
    if not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("NewP256VM requires a P-256 key")
    nums = pub.public_numbers()
    return VerificationMethodEntry(
        id=f"{did}#{fragment}",
        type="JsonWebKey2020",
        controller=did,
        public_key_jwk=JWK(kty="EC", crv="P-256", x=_b64u(nums.x.to_bytes(32, "big")), y=_b64u(nums.y.to_bytes(32, "big"))),
    )
