from __future__ import annotations

from threading import RLock
from typing import Any

from credential.common.verification_method.key_material import encode_pub_multibase
from credential.common.verification_method.verification_method import (
    DIDDocument,
    JWK,
    VerificationMethodEntry,
)
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class StaticResolver:
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
    ids = [vm.id for vm in vms]
    return DIDDocument(
        id=did,
        verification_method=vms,
        assertion_method=ids,
        authentication=ids,
    )


def new_secp256k1_vm(did: str, fragment: str, pub_key_hex: str) -> VerificationMethodEntry:
    return VerificationMethodEntry(
        id=f"{did}#{fragment}",
        type="EcdsaSecp256k1VerificationKey2019",
        controller=did,
        public_key_hex=pub_key_hex,
    )


def new_rsa_vm(did: str, fragment: str, pub: rsa.RSAPublicKey) -> VerificationMethodEntry:
    import base64

    numbers = pub.public_numbers()
    return VerificationMethodEntry(
        id=f"{did}#{fragment}",
        type="JsonWebKey2020",
        controller=did,
        public_key_jwk=JWK(
            kty="RSA",
            n=base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).decode().rstrip("="),
            e=base64.urlsafe_b64encode(numbers.e.to_bytes(3, "big")).decode().rstrip("="),
        ),
    )


def new_p256_multikey_vm(did: str, fragment: str, pub: ec.EllipticCurvePublicKey) -> VerificationMethodEntry:
    mb = encode_pub_multibase(pub)
    return VerificationMethodEntry(
        id=f"{did}#{fragment}",
        type="Multikey",
        controller=did,
        public_key_multibase=mb,
    )
