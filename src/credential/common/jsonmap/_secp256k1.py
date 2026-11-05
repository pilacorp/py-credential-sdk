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
from credential.common.jsonmap._proof_helpers import append_proof, strict_purpose_check
from credential.common.jsonmap._vm import curve_name, curve_order, find_vm_entry, pub_from_entry, vm_is_secp256k1
from credential.common.util.b64 import b64url_decode, b64url_encode


def signing_suite_for_key(kind: Any) -> str:
    """The proof suite to issue, decided by the key the VM holds (P-256 -> DataIntegrityProof,
    secp256k1 -> EcdsaSecp256k1Signature2019). ``kind`` is a ``KeyKind`` or its string value."""
    from credential.common.jsonmap._constants import DATA_INTEGRITY_PROOF

    k = getattr(kind, "value", kind)
    if k in ("p256", "P-256"):
        return DATA_INTEGRITY_PROOF
    if k == "secp256k1":
        return ECDSA_SECP256K1_SIGNATURE_2019
    raise ValueError(f"unsupported key kind {k} for JSON-LD signing")


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
    if signer is None:
        raise ValueError("jsonmap: signer provider cannot be nil")
    if not verification_method:
        raise ValueError("jsonmap: verification method is required")
    if not proof_purpose:
        raise ValueError("jsonmap: proof purpose is required")

    restore = context_snapshot(m)
    try:
        add_suite_context_without_changing_meaning(m)
        opts = options or new_proof_options()
        # Compared by the curve's order (not an object identity): every library's secp256k1 agrees on it.
        if opts.vm_pub is not None and curve_order(opts.vm_pub) != SECPK1_N:
            raise ValueError(
                f"jsonmap: {ECDSA_SECP256K1_SIGNATURE_2019} needs a secp256k1 key, but verification method "
                f"{verification_method!r} holds a {curve_name(opts.vm_pub)} key"
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
        proof.jws = enc_header + ".." + b64url_encode(signature)
        append_proof(m, proof)
    except Exception:
        restore()
        raise


def secp256k1_signing_input(m: dict[str, Any], proof: Proof, enc_header: str) -> bytes:
    hash_data = ecdsa_hash_data(m, proof)
    return jws_signing_input(enc_header, hash_data)


def verify_ecdsa_secp256k1_proof(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    try:
        vm = find_vm_entry(doc, proof.verification_method)
    except ValueError as exc:
        raise ValueError(f"failed to resolve verification method: {exc}") from exc
    # The suite binds to a secp256k1 key; a P-256 VM under this proof type means the issuer mixed suites.
    if not vm_is_secp256k1(vm):
        raise ValueError(
            f"{ECDSA_SECP256K1_SIGNATURE_2019}: verification method {proof.verification_method!r} "
            "does not hold a secp256k1 key"
        )
    try:
        pub = pub_from_entry(vm)
    except ValueError as exc:
        raise ValueError(f"invalid public key: {exc}") from exc

    enc_header, enc_sig, ok = split_detached_jws(proof.jws)
    if not ok:
        raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019}: malformed detached JWS")
    alg = detached_jws_alg(enc_header)
    if alg != ALG_ES256K:
        raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019}: jws alg must be {ALG_ES256K}, got {alg!r}")

    # Strict: the 64-byte signature's 86th char has 4 unused bits; reject non-zero ones, else one
    # signature would have 16 spellings that all verify while Hash() sees 16 different credentials.
    try:
        signature = b64url_decode(enc_sig, strict=True)
    except ValueError as exc:
        raise ValueError(f"decode jws signature: {exc}") from exc
    # RFC 8812 3.2: exactly 64 bytes.
    if len(signature) != 64:
        raise ValueError(
            f"{ECDSA_SECP256K1_SIGNATURE_2019}: jws signature is {len(signature)} bytes, want 64 (r||s)"
        )
    # (r, s) and (r, n-s) both verify; only the low-S form is accepted (BIP-62 / BIP-146).
    if int.from_bytes(signature[32:], "big") > curve_order(pub) >> 1:
        raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019}: jws signature is not low-S")

    # RFC 7797 signs the header that travels with the proof, so it is the jws's header (not a fresh one).
    signing_input = secp256k1_signing_input(m, proof, enc_header)
    digest = sha256(signing_input).digest()
    if not verify_ecdsa(pub, digest, signature):
        raise ValueError(f"{ECDSA_SECP256K1_SIGNATURE_2019} signature verification failed")

    strict_purpose_check(doc, vm, proof.proof_purpose, proof.created)
    return True
