from __future__ import annotations

from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.ecdsasd.crypto_util import verify_ecdsa, verify_p256
from credential.common.ecdsasd.hashes import hash_mandatory, hash_proof_config
from credential.common.ecdsasd.keys import ec_pub_from_multikey_bytes
from credential.common.ecdsasd.labelmap import canonicalize_and_group, relabel_blank_nodes, sorted_indexes
from credential.common.ecdsasd.ld import canonicalize_with_id_map
from credential.common.ecdsasd.proofvalue import parse_base_proof_value, parse_disclosure_proof_value
from credential.common.ecdsasd.sign import ordered_values


def verify_base_proof(
    document: dict[str, Any],
    proof_config: dict[str, Any],
    base_proof_value: str,
    issuer_pub: ec.EllipticCurvePublicKey,
) -> None:
    bp = parse_base_proof_value(base_proof_value)
    eph_pub = ec_pub_from_multikey_bytes(bp.public_key)

    grouped = canonicalize_and_group(document, bp.hmac_key, {"mandatory": bp.mandatory_pointers})
    mg = grouped.groups["mandatory"]
    non_mandatory = ordered_values(mg.non_matching)
    mandatory_hash = hash_mandatory(mg.matching)
    proof_hash = hash_proof_config(proof_config)

    sign_data = proof_hash + bp.public_key + mandatory_hash
    digest = sha256(sign_data).digest()
    if not verify_ecdsa(issuer_pub, digest, bp.base_signature):
        raise ValueError("ecdsasd: issuer base signature invalid")

    if len(bp.signatures) != len(non_mandatory):
        raise ValueError(
            f"ecdsasd: signature count {len(bp.signatures)} != non-mandatory quads {len(non_mandatory)}"
        )
    for i, nq in enumerate(non_mandatory):
        d = sha256(nq.encode("utf-8")).digest()
        if not verify_p256(eph_pub, d, bp.signatures[i]):
            raise ValueError(f"ecdsasd: non-mandatory statement signature invalid: {nq}")


def verify_derived_proof(
    reveal_doc: dict[str, Any],
    proof_config: dict[str, Any],
    derived_proof_value: str,
    issuer_pub: ec.EllipticCurvePublicKey,
) -> None:
    dp = parse_disclosure_proof_value(derived_proof_value)
    eph_pub = ec_pub_from_multikey_bytes(dp.public_key)

    canonical_nquads, _ = canonicalize_with_id_map(reveal_doc)
    relabeled = relabel_blank_nodes(canonical_nquads, dp.label_map)
    relabeled.sort()

    mandatory_set = set(dp.mandatory_indexes)
    mandatory: list[str] = []
    non_mandatory: list[str] = []
    for i, nq in enumerate(relabeled):
        if i in mandatory_set:
            mandatory.append(nq)
        else:
            non_mandatory.append(nq)

    proof_hash = hash_proof_config(proof_config)
    mandatory_hash_arr = sha256("".join(mandatory).encode("utf-8")).digest()

    sign_data = proof_hash + dp.public_key + mandatory_hash_arr
    digest = sha256(sign_data).digest()
    if not verify_ecdsa(issuer_pub, digest, dp.base_signature):
        raise ValueError("ecdsasd: issuer base signature invalid")

    if len(dp.signatures) != len(non_mandatory):
        raise ValueError(
            f"ecdsasd: signature count {len(dp.signatures)} != non-mandatory quads {len(non_mandatory)}"
        )
    for i, nq in enumerate(non_mandatory):
        d = sha256(nq.encode("utf-8")).digest()
        if not verify_p256(eph_pub, d, dp.signatures[i]):
            raise ValueError(f"ecdsasd: non-mandatory statement signature invalid: {nq}")
