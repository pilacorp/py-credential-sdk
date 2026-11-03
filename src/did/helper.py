from __future__ import annotations

import os
from typing import Any

from eth_keys import keys

from did.model import DIDDocument, DIDType, KeyPair, VerificationMethod
from didv2.hexutil import with_0x


def generate_ecdsa_did(method: str) -> KeyPair:
    private_key = keys.PrivateKey(os.urandom(32))
    address = with_0x(bytes(private_key.public_key.to_canonical_address())).lower()
    private_key_hex = with_0x(private_key.to_bytes()).lower()
    public_key_hex = with_0x(private_key.public_key.to_compressed_bytes()).lower()
    identifier = f"{method}:{address}".lower()
    return KeyPair(
        address=address,
        public_key=public_key_hex,
        private_key=private_key_hex,
        identifier=identifier,
    )


def generate_did_document(
    key_pair: KeyPair,
    did_type: DIDType | str,
    hash_: str,
    metadata: dict[str, Any] | None,
    signer_did: str,
) -> DIDDocument:
    doc_metadata: dict[str, Any] = dict(metadata or {})
    if did_type:
        doc_metadata["type"] = str(did_type)
    if hash_:
        doc_metadata["hash"] = hash_

    vm_id = f"{key_pair.identifier}#key-1"
    vm = VerificationMethod(
        id=vm_id,
        type="EcdsaSecp256k1VerificationKey2019",
        controller=key_pair.identifier,
        public_key_hex=key_pair.public_key,
    )
    return DIDDocument(
        context=[
            "https://w3id.org/security/v1",
            "https://www.w3.org/ns/did/v1",
        ],
        id=key_pair.identifier,
        controller=signer_did,
        verification_method=[vm],
        authentication=[vm_id],
        assertion_method=[vm_id],
        document_metadata=doc_metadata,
    )


def random_hex(length: int) -> str:
    return os.urandom(length).hex()
