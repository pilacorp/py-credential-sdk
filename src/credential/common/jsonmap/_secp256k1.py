from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys
from eth_keys.constants import SECPK1_N

from credential.common.crypto.ecdsa_rdfc import verify_ecdsa
from credential.common.dto.proof import Proof, StringOrStrings
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.common.verification_method.verification_method import DIDDocument

from credential.common.jsonmap._constants import ALG_ES256K, ECDSA_SECP256K1_SIGNATURE_2019
from credential.common.jsonmap._context import add_suite_context_without_changing_meaning, context_snapshot
from credential.common.jsonmap._ecdsa_common import ecdsa_hash_data
from credential.common.jsonmap._jws import (
    detached_jws_alg,
    encode_detached_jws_header,
    jws_signing_input,
    split_detached_jws,
)
from credential.common.jsonmap._options import ProofOptions, SignerProvider, domain_value, new_proof_options
from credential.common.jsonmap._proof_helpers import append_proof, strict_purpose_check, vm_entry_to_dict, vm_is_secp256k1
from didv2.did.verification_method_ops import find_verification_method


def signing_suite_for_key(kind: str) -> str:
    if kind == "p256":
        from credential.common.jsonmap._constants import DATA_INTEGRITY_PROOF

        return DATA_INTEGRITY_PROOF
    if kind == "secp256k1":
        return ECDSA_SECP256K1_SIGNATURE_2019
    raise ValueError(f"unsupported key kind {kind!r} for JSON-LD signing")


def normalize_low_s(curve_n: int, s: int) -> int:
    half = curve_n // 2
    return s if s <= half else curve_n - s


def jose_secp256k1_signature(sig: bytes) -> bytes:
    if len(sig) == 65:
        sig = sig[:64]
    elif len(sig) != 64:
        raise ValueError(
            f"{ECDSA_SECP256K1_SIGNATURE_2019} expects a 64-byte secp256k1 signature (r||s), got {len(sig)}; "
            "the signer does not match the verification method — pin the right VM with WithVerificationMethodKey"
        )
    s_int = int.from_bytes(sig[32:], "big")
    low_s = normalize_low_s(SECPK1_N, s_int)
    out = bytearray(64)
    out[:32] = sig[:32]
    out[32:] = low_s.to_bytes(32, "big")
    return bytes(out)


def add_ecdsa_secp256k1_proof(
    m: dict[str, Any],
    signer: SignerProvider,
    verification_method: str,
    proof_purpose: str,
    *,
    options: ProofOptions | None = None,
) -> None:
    if not verification_method:
        raise ValueError("jsonmap: verification method is required")
    if not proof_purpose:
        raise ValueError("jsonmap: proof purpose is required")

    restore = context_snapshot(m)
    try:
        add_suite_context_without_changing_meaning(m)
        opts = options or new_proof_options()
        if opts.vm_pub is not None:
            curve_order = getattr(opts.vm_pub.curve, "order", None)
            if curve_order != SECPK1_N:
                name = getattr(opts.vm_pub.curve, "name", str(opts.vm_pub.curve))
                raise ValueError(
                    f"jsonmap: {ECDSA_SECP256K1_SIGNATURE_2019} needs a secp256k1 key, but verification method "
                    f"{verification_method!r} holds a {name} key"
                )
        domain = domain_value(opts.domain)
        proof = Proof(
            type=ECDSA_SECP256K1_SIGNATURE_2019,
            created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            verification_method=verification_method,
            proof_purpose=proof_purpose,
            challenge=opts.challenge,
            domain=domain if domain is not None else StringOrStrings(),
        )
        enc_header = encode_detached_jws_header(ALG_ES256K)
        signing_input = secp256k1_signing_input(m, proof, enc_header)
        sign_digest = sha256(signing_input).digest()
        signature = signer.sign(sign_digest)
        signature = jose_secp256k1_signature(signature)
        if opts.vm_pub is not None and not verify_ecdsa(opts.vm_pub, sign_digest, signature):
            raise ValueError(
                f"jsonmap: the signature does not verify against verification method {verification_method!r}; "
                "the signer does not hold that key"
            )
        proof.jws = enc_header + ".." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
        append_proof(m, proof)
    except Exception:
        restore()
        raise


def secp256k1_signing_input(m: dict[str, Any], proof: Proof, enc_header: str) -> bytes:
    hash_data = ecdsa_hash_data(m, proof)
    return jws_signing_input(enc_header, hash_data)


def verify_ecdsa_secp256k1_proof(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    doc_dict = {
        "id": doc.id,
        "verificationMethod": [vm_entry_to_dict(v) for v in doc.verification_method],
    }
    vm_raw = find_verification_method(doc_dict, proof.verification_method)
    if vm_raw is None:
        raise ValueError(f"failed to resolve verification method: {proof.verification_method!r}")
    if not vm_is_secp256k1(vm_raw):
        raise ValueError(
            f"{ECDSA_SECP256K1_SIGNATURE_2019}: verification method {proof.verification_method!r} "
            "does not hold a secp256k1 key"
        )
    pub = ec_pub_from_vm(vm_raw)

    enc_header, enc_sig, ok = split_detached_jws(proof.jws)
    if not ok:
        raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019}: malformed detached JWS")
    alg = detached_jws_alg(enc_header)
    if alg != ALG_ES256K:
        raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019}: jws alg must be {ALG_ES256K}, got {alg!r}")

    try:
        signature = base64.urlsafe_b64decode(enc_sig + "=" * (-len(enc_sig) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"decode jws signature: {exc}") from exc
    if len(signature) != 64:
        raise ValueError(
            f"{ECDSA_SECP256K1_SIGNATURE_2019}: jws signature is {len(signature)} bytes, want 64 (r||s)"
        )
    half_n = SECPK1_N // 2
    if int.from_bytes(signature[32:], "big") > half_n:
        raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019}: jws signature is not low-S")

    signing_input = secp256k1_signing_input(m, proof, enc_header)
    digest = sha256(signing_input).digest()

    if isinstance(pub, keys.PublicKey):
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        try:
            sig = keys.Signature(vrs=(0, r, s))
            if not sig.verify_msg_hash(digest, pub):
                raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019} signature verification failed")
        except Exception as exc:
            raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019} signature verification failed") from exc
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        if not verify_ecdsa(pub, digest, signature):
            raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019} signature verification failed")
    else:
        raise ValueError("invalid public key")

    vm_entry = next(v for v in doc.verification_method if v.id == vm_raw.get("id"))
    strict_purpose_check(doc, vm_entry, proof.proof_purpose, proof.created)
    return True
