from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.dto.proof import Proof, StringOrStrings
from credential.common.jsonmap import (
    JSONMap,
    add_ecdsa_proof,
    add_ecdsa_rdfc_proof,
    add_ecdsa_secp256k1_proof,
    ecdsa_hash_data,
    ecdsa_proof_config,
    ensure_data_integrity_context,
    has_multibase_proof,
    new_proof_options,
    parse_raw_to_proof,
    strict_purpose_check,
    verify_ecdsa_rdfc,
)
from credential.common.jsonmap._constants import (
    DATA_INTEGRITY_PROOF,
    DATA_INTEGRITY_V2_CONTEXT,
    ECDSA_RDFC_2019,
)
from credential.common.jsonmap._ecdsa_common import document_digest
from credential.common.jsonmap._multibase import decode_multibase_key, encode_multibase_key
from credential.common.jsonmap._secp256k1 import jose_secp256k1_signature
from credential.common.processor import canonicalize_document
from credential.common.signer.p256 import P256Provider
from credential.common.verification_method.revocation import REASON_KEY_COMPROMISE, REASON_SUPERSEDED
from credential.common.verification_method.verification_method import DIDDocument, VerificationMethodEntry
from eth_keys.constants import SECPK1_N

TEST_PRIV_HEX = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

FIXTURES = Path(__file__).resolve().parent / "testdata" / "w3c-rdfc-p256"


class _FixedSigner:
    def __init__(self, sig: bytes) -> None:
        self._sig = sig

    def sign(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise ValueError(f"hash payload must be 32 bytes, got {len(digest)}")
        return self._sig


def _test_credential() -> dict:
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            {"age": "https://schema.org/age", "name": "https://schema.org/name"},
        ],
        "id": "urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "issuanceDate": "2024-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:subject", "name": "Alice", "age": 30},
    }


def _p256_signer() -> tuple[P256Provider, ec.EllipticCurvePublicKey]:
    signer = P256Provider(bytes.fromhex(TEST_PRIV_HEX))
    return signer, signer._key.public_key()  # noqa: SLF001


def test_add_ecdsa_proof_accepts_64_byte_signature() -> None:
    m = _test_credential()
    sig64 = bytes([0xAB] * 64)
    add_ecdsa_proof(m, _FixedSigner(sig64), "did:example:issuer#key-1", "assertionMethod")
    pv = m["proof"]["proofValue"]
    raw = decode_multibase_key(pv)
    assert len(raw) == 64


def test_add_ecdsa_proof_rejects_65_byte_signature() -> None:
    m = _test_credential()
    with pytest.raises(ValueError, match="64-byte"):
        add_ecdsa_proof(m, _FixedSigner(bytes([0xCD] * 65)), "did:example:issuer#key-1", "assertionMethod")
    assert "proof" not in m


def test_add_ecdsa_proof_roundtrip() -> None:
    signer, pub = _p256_signer()
    m = _test_credential()
    add_ecdsa_rdfc_proof(m, signer, "did:example:issuer#key-1", "assertionMethod")
    proof = parse_raw_to_proof(m["proof"])
    assert proof.proof_value.startswith("z")
    assert verify_ecdsa_rdfc(m, pub, proof) is True


def test_ecdsa_proof_config_requires_context() -> None:
    proof = Proof(
        type=DATA_INTEGRITY_PROOF,
        cryptosuite=ECDSA_RDFC_2019,
        created="2024-01-01T00:00:00Z",
        verification_method="did:example:issuer#key-1",
        proof_purpose="assertionMethod",
    )
    with pytest.raises(ValueError):
        ecdsa_proof_config({}, proof)


def test_ecdsa_proof_config_excludes_proof_value_only() -> None:
    m = {"@context": "https://www.w3.org/ns/credentials/v2"}
    proof = Proof(
        type=DATA_INTEGRITY_PROOF,
        cryptosuite=ECDSA_RDFC_2019,
        created="2024-01-01T00:00:00Z",
        verification_method="did:example:issuer#key-1",
        proof_purpose="assertionMethod",
        proof_value="zSignatureThatMustNotBeHashed",
        jws="header..signature",
    )
    cfg = ecdsa_proof_config(m, proof)
    assert "proofValue" not in cfg
    assert cfg["jws"] == "header..signature"


def test_ensure_data_integrity_context_promotes_v1() -> None:
    m: dict = {"@context": "https://www.w3.org/2018/credentials/v1"}
    ensure_data_integrity_context(m)
    assert m["@context"] == ["https://www.w3.org/2018/credentials/v1", DATA_INTEGRITY_V2_CONTEXT]


def test_has_multibase_proof() -> None:
    m = _test_credential()
    m["proof"] = {"type": DATA_INTEGRITY_PROOF, "proofValue": "z3abc"}
    assert has_multibase_proof(m) is True
    m["proof"]["proofValue"] = "ab" * 64
    assert has_multibase_proof(m) is False


def test_strict_purpose_check_grants() -> None:
    vm = VerificationMethodEntry(
        id="did:example:purpose#key-1",
        type="Multikey",
        controller="did:example:purpose",
    )
    doc = DIDDocument(
        id="did:example:purpose",
        verification_method=[vm],
        assertion_method=["#key-1"],
    )
    strict_purpose_check(doc, vm, "assertionMethod", "2026-06-01T00:00:00Z")


def test_strict_purpose_check_rejects_wrong_purpose() -> None:
    vm = VerificationMethodEntry(
        id="did:example:purpose#key-1",
        type="Multikey",
        controller="did:example:purpose",
    )
    doc = DIDDocument(
        id="did:example:purpose",
        verification_method=[vm],
        authentication=["#key-1"],
    )
    with pytest.raises(ValueError, match="is not granted purpose"):
        strict_purpose_check(doc, vm, "assertionMethod", "2026-06-01T00:00:00Z")


def test_strict_purpose_check_hard_revocation() -> None:
    vm = VerificationMethodEntry(
        id="did:example:purpose#key-1",
        type="Multikey",
        controller="did:example:purpose",
        revocation_reason=REASON_KEY_COMPROMISE,
    )
    doc = DIDDocument(id="did:example:purpose", verification_method=[vm], assertion_method=["#key-1"])
    with pytest.raises(ValueError, match="keyCompromise"):
        strict_purpose_check(doc, vm, "assertionMethod", "2026-03-10T00:00:00Z")


def test_ecdsa_hash_data_document_half() -> None:
    m = _test_credential()
    ensure_data_integrity_context(m)
    proof = Proof(
        type=DATA_INTEGRITY_PROOF,
        cryptosuite=ECDSA_RDFC_2019,
        created="2024-01-01T00:00:00Z",
        verification_method="did:example:issuer#key-1",
        proof_purpose="assertionMethod",
    )
    hash_data = ecdsa_hash_data(m, proof)
    assert len(hash_data) == 64
    assert hash_data[32:] == document_digest(m)


def test_jose_secp256k1_signature_folds_high_s() -> None:
    sig = bytearray(64)
    sig[31] = 1
    (SECPK1_N - 1).to_bytes(32, "big")
    sig[32:] = (SECPK1_N - 1).to_bytes(32, "big")
    out = jose_secp256k1_signature(bytes(sig))
    assert int.from_bytes(out[32:], "big") == 1


def test_w3c_rdfc_phase4_hash_data() -> None:
    raw = (FIXTURES / "signedECDSAP256.json").read_text(encoding="utf-8")
    doc = json.loads(raw)
    proof_map = doc["proof"]
    proof = parse_raw_to_proof(proof_map)
    hash_data = ecdsa_hash_data(doc, proof)
    want = (FIXTURES / "combinedHashECDSAP256.txt").read_text(encoding="utf-8").strip()
    assert hash_data.hex() == want


def test_w3c_rdfc_phase1_canonicalize_document() -> None:
    raw = json.loads((FIXTURES / "signedECDSAP256.json").read_text(encoding="utf-8"))
    raw.pop("proof")
    got = canonicalize_document(raw)
    want = (FIXTURES / "canonDocECDSAP256.txt").read_bytes()
    assert got == want


def test_multibase_encode_roundtrip() -> None:
    sig = bytes.fromhex("11" * 32 + "22" * 32)
    enc = encode_multibase_key(sig)
    assert decode_multibase_key(enc) == sig


def test_add_ecdsa_with_challenge_domain() -> None:
    signer, pub = _p256_signer()
    m = _test_credential()
    add_ecdsa_proof(
        m,
        signer,
        "did:example:holder#key-1",
        "authentication",
        options=new_proof_options(challenge="nonce-123", domain="verifier.example"),
    )
    proof = parse_raw_to_proof(m["proof"])
    assert proof.challenge == "nonce-123"
    assert proof.domain == StringOrStrings(["verifier.example"])
    assert verify_ecdsa_rdfc(m, pub, proof) is True
