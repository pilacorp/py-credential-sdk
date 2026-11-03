from __future__ import annotations

import binascii
import json
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.ecdsasd import create_base_proof, derive_proof, verify_base_proof, verify_proof
from credential.common.ecdsasd.crypto_util import verify_p256
from credential.common.ecdsasd.disclose import create_disclosure_data
from credential.common.ecdsasd.hashes import hash_mandatory, hash_proof_config
from credential.common.ecdsasd.keys import (
    decode_p256_priv_multibase,
    encode_multibase_key,
    new_ephemeral_key,
)
from credential.common.ecdsasd.labelmap import canonicalize_and_group
from credential.common.ecdsasd.ld import canonicalize_with_id_map
from credential.common.ecdsasd.pointer import select_json_ld
from credential.common.ecdsasd.proofvalue import (
    SpecDerivedProof,
    parse_base_proof_value,
    serialize_base_proof_value,
    serialize_disclosure_proof_value,
)
from credential.common.ecdsasd.sign import create_base_proof_deterministic
from credential.common.ecdsasd.verify import verify_derived_proof
from credential.common.signer.p256 import P256Provider
from credential.common.verification_method.key_material import ec_pub_from_multibase

W3C_DIR = (
    Path(__file__).resolve().parents[3].parent
    / "go-credential-sdk"
    / "credential"
    / "common"
    / "ecdsasd"
    / "testdata"
    / "w3c"
)

TEST_PROOF_CONTEXT = "https://w3id.org/security/data-integrity/v2"
CRYPTOSUITE = "ecdsa-sd-2023"


def _w3c_read(name: str) -> bytes:
    return (W3C_DIR / name).read_bytes()


def _w3c_load_keys() -> dict:
    return json.loads(_w3c_read("keys.json"))


def _w3c_load_expected() -> dict:
    return json.loads(_w3c_read("expected.json"))


def _w3c_cred() -> dict:
    return json.loads(_w3c_read("credential.json"))


def _test_proof_config(context) -> dict:
    return {
        "@context": context,
        "type": "DataIntegrityProof",
        "cryptosuite": CRYPTOSUITE,
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": "did:example:issuer#key-1",
        "proofPurpose": "assertionMethod",
    }


def _w3c_proof_config(exp: dict, context) -> dict:
    return {
        "@context": context,
        "type": exp["proofConfig"]["type"],
        "cryptosuite": exp["proofConfig"]["cryptosuite"],
        "created": exp["proofConfig"]["created"],
        "verificationMethod": exp["proofConfig"]["verificationMethod"],
        "proofPurpose": exp["proofConfig"]["proofPurpose"],
    }


@pytest.fixture(scope="module")
def w3c_fixtures_present() -> None:
    if not W3C_DIR.is_dir():
        pytest.skip(f"W3C fixtures missing at {W3C_DIR}")


def test_ecdsa_sd_base_proof_roundtrip() -> None:
    signer = P256Provider()
    doc = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/data-integrity/v2",
            {"name": "http://schema.org/name"},
        ],
        "id": "urn:uuid:sd",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "credentialSubject": {"id": "did:example:subject", "name": "Ada"},
    }
    proof_cfg = _test_proof_config(doc["@context"])
    proof_value = create_base_proof(doc, proof_cfg, ["/credentialSubject/name"], signer)
    assert proof_value.startswith("u")
    assert verify_base_proof(doc, proof_cfg, proof_value, signer.public_key_uncompressed())


def test_hash_proof_config_rejects_config_that_canonicalizes_to_nothing() -> None:
    empty_hash = sha256(b"").digest()
    cases = [
        ("no context", None),
        ("context defining unrelated terms", {"name": "https://schema.org/name"}),
        ("context defining nothing", {}),
    ]
    for _name, context in cases:
        cfg = _test_proof_config(TEST_PROOF_CONTEXT)
        if context is None:
            del cfg["@context"]
        else:
            cfg["@context"] = context
        with pytest.raises(ValueError, match="hash proof config"):
            hash_proof_config(cfg)


def test_hash_proof_config_binds_every_proof_option() -> None:
    base = hash_proof_config(_test_proof_config(TEST_PROOF_CONTEXT))
    for field, tampered in {
        "proofPurpose": "authentication",
        "verificationMethod": "did:evil:attacker#key-9",
        "created": "2030-06-06T00:00:00Z",
    }.items():
        cfg = _test_proof_config(TEST_PROOF_CONTEXT)
        cfg[field] = tampered
        got = hash_proof_config(cfg)
        assert got != base


def test_hash_proof_config_does_not_mutate_caller() -> None:
    nested = {"@vocab": "https://example.org/v#"}
    cfg = _test_proof_config([TEST_PROOF_CONTEXT, nested])
    before = repr(cfg)
    hash_proof_config(cfg)
    assert repr(cfg) == before
    assert nested == {"@vocab": "https://example.org/v#"}


def test_ephemeral_key_sign_statement_low_s() -> None:
    eph = new_ephemeral_key()
    half = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 >> 1
    for i in range(500):
        stmt = f"<urn:s{i}> <urn:p> \"o\" ."
        sig = eph.sign_statement(stmt)
        assert len(sig) == 64
        s = int.from_bytes(sig[32:], "big")
        assert s <= half
        digest = sha256(stmt.encode()).digest()
        assert verify_p256(eph.priv.public_key(), digest, sig)


def test_verify_p256_accepts_high_s() -> None:
    eph = new_ephemeral_key()
    stmt = '<urn:s> <urn:p> "o" .'
    sig = eph.sign_statement(stmt)
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    s = int.from_bytes(sig[32:], "big")
    high_s = n - s
    flipped = sig[:32] + high_s.to_bytes(32, "big")
    digest = sha256(stmt.encode()).digest()
    pub = eph.priv.public_key()
    assert verify_p256(pub, digest, flipped)


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_vectors_fixtures_present() -> None:
    json.loads(_w3c_read("credential.json"))
    keys = _w3c_load_keys()
    assert keys["hmacKeyString"] and keys["baseKeyPair"]["secretKeyMultibase"]
    exp = _w3c_load_expected()
    for v in (exp["proofHash"], exp["mandatoryHash"], exp["baseProofValue"], exp["derived"]["derivedProofValue"]):
        assert v
    assert _w3c_read("canonical.nq")


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase0_canonicalize_with_id_map() -> None:
    cred = _w3c_cred()
    nquads, id_map = canonicalize_with_id_map(cred)
    assert "".join(nquads) == _w3c_read("canonical.nq").decode()
    keys = _w3c_load_keys()
    hmac_key = binascii.unhexlify(keys["hmacKeyString"])
    exp = _w3c_load_expected()
    import base64
    import hmac as hmac_mod

    seen: set[str] = set()
    for c14n in id_map.values():
        label = c14n.removeprefix("_:")
        if label in seen:
            continue
        seen.add(label)
        mac = hmac_mod.new(hmac_key, label.encode(), sha256).digest()
        hmac_label = "u" + base64.urlsafe_b64encode(mac).decode().rstrip("=")
        assert exp["hmacLabels"][label] == hmac_label
    assert len(seen) == len(exp["hmacLabels"])


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase1_multikey() -> None:
    keys = _w3c_load_keys()
    exp = _w3c_load_expected()
    from credential.common.ecdsasd.keys import decode_multibase_key

    proof_pub_raw = decode_multibase_key(keys["proofKeyPair"]["publicKeyMultibase"])
    assert encode_multibase_key(proof_pub_raw) == keys["proofKeyPair"]["publicKeyMultibase"]
    base_priv = decode_p256_priv_multibase(keys["baseKeyPair"]["secretKeyMultibase"])
    from credential.common.ecdsasd.keys import pub_to_multikey_bytes

    got = encode_multibase_key(pub_to_multikey_bytes(base_priv.public_key()))
    assert got == keys["baseKeyPair"]["publicKeyMultibase"]
    proof_hash = binascii.unhexlify(exp["proofHash"])
    mandatory_hash = binascii.unhexlify(exp["mandatoryHash"])
    sign_data = proof_hash + proof_pub_raw + mandatory_hash
    digest = sha256(sign_data).digest()
    sig = binascii.unhexlify(exp["baseSignature"])
    base_pub = ec_pub_from_multibase(keys["baseKeyPair"]["publicKeyMultibase"])
    assert verify_p256(base_pub, digest, sig)


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase2_select_json_ld() -> None:
    cred = _w3c_cred()
    ptr = json.loads(_w3c_read("pointers.json"))
    combined = ptr["mandatoryPointers"] + ptr["selectivePointers"]
    got = select_json_ld(cred, combined)
    want = json.loads(_w3c_read("reveal.json"))
    assert got == want


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase3_grouping() -> None:
    cred = _w3c_cred()
    hmac_key = binascii.unhexlify(_w3c_load_keys()["hmacKeyString"])
    grouped = canonicalize_and_group(cred, hmac_key, {"mandatory": ["/issuer"]})
    assert len(grouped.hmac_nquads) == 24
    mand = grouped.groups["mandatory"]
    got_mandatory = sorted(mand.matching.keys())
    assert got_mandatory == [0, 12, 13, 17]


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase4_hashes() -> None:
    cred = _w3c_cred()
    exp = _w3c_load_expected()
    hmac_key = binascii.unhexlify(_w3c_load_keys()["hmacKeyString"])
    ph = hash_proof_config(_w3c_proof_config(exp, cred["@context"]))
    assert ph.hex() == exp["proofHash"]
    grouped = canonicalize_and_group(cred, hmac_key, {"mandatory": ["/issuer"]})
    mh = hash_mandatory(grouped.groups["mandatory"].matching)
    assert mh.hex() == exp["mandatoryHash"]


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase5_round_trip() -> None:
    cred = _w3c_cred()
    exp = _w3c_load_expected()
    keys = _w3c_load_keys()
    issuer_priv = decode_p256_priv_multibase(keys["baseKeyPair"]["secretKeyMultibase"])
    issuer_signer = P256Provider(issuer_priv.private_numbers().private_value.to_bytes(32, "big"))
    base_pv = create_base_proof(cred, _w3c_proof_config(exp, cred["@context"]), ["/issuer"], issuer_signer)
    reveal, derived_pv = derive_proof(cred, base_pv, exp["derived"]["selectivePointers"])
    issuer_pub = ec_pub_from_multibase(keys["baseKeyPair"]["publicKeyMultibase"])
    verify_proof(reveal, _w3c_proof_config(exp, reveal["@context"]), derived_pv, issuer_pub)


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase5_byte_exact_issuance() -> None:
    cred = _w3c_cred()
    exp = _w3c_load_expected()
    keys = _w3c_load_keys()
    hmac_key = binascii.unhexlify(keys["hmacKeyString"])
    eph = decode_p256_priv_multibase(keys["proofKeyPair"]["secretKeyMultibase"])
    iss = decode_p256_priv_multibase(keys["baseKeyPair"]["secretKeyMultibase"])
    got = create_base_proof_deterministic(
        cred, _w3c_proof_config(exp, cred["@context"]), ["/issuer"], hmac_key, eph, iss
    )
    assert got == exp["baseProofValue"]


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase6_base_proof_value() -> None:
    exp = _w3c_load_expected()
    bp = parse_base_proof_value(exp["baseProofValue"])
    assert bp.base_signature.hex() == exp["baseSignature"]
    assert encode_multibase_key(bp.public_key) == exp["proofPublicKey"]
    assert bp.mandatory_pointers == ["/issuer"]
    from credential.common.ecdsasd.proofvalue import serialize_base_proof_value

    assert serialize_base_proof_value(bp) == exp["baseProofValue"]


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase7_derive() -> None:
    cred = _w3c_cred()
    exp = _w3c_load_expected()
    dd = create_disclosure_data(cred, exp["baseProofValue"], exp["derived"]["selectivePointers"])
    assert dd.mandatory_indexes == exp["derived"]["adjMandatoryIndexes"]
    assert dd.label_map == exp["derived"]["labelMap"]
    assert len(dd.signatures) == 6
    got = serialize_disclosure_proof_value(
        SpecDerivedProof(
            dd.base_signature,
            dd.public_key,
            dd.signatures,
            dd.label_map,
            dd.mandatory_indexes,
        )
    )
    assert got == exp["derived"]["derivedProofValue"]


@pytest.mark.usefixtures("w3c_fixtures_present")
def test_w3c_conformance_phase8_verify_derived() -> None:
    cred = _w3c_cred()
    exp = _w3c_load_expected()
    keys = _w3c_load_keys()
    dd = create_disclosure_data(cred, exp["baseProofValue"], exp["derived"]["selectivePointers"])
    derived_pv = serialize_disclosure_proof_value(
        SpecDerivedProof(
            dd.base_signature,
            dd.public_key,
            dd.signatures,
            dd.label_map,
            dd.mandatory_indexes,
        )
    )
    issuer_pub = ec_pub_from_multibase(keys["baseKeyPair"]["publicKeyMultibase"])
    verify_derived_proof(dd.reveal_doc, _w3c_proof_config(exp, dd.reveal_doc["@context"]), derived_pv, issuer_pub)
