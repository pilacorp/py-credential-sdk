from __future__ import annotations

import base64
import json
from hashlib import sha256, sha512
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.crypto.ecdsa_rdfc import verify_ecdsa
from credential.common.crypto.jws_2020 import verify_rsa_jws
from credential.common.dto.proof import Proof
from credential.common.verification_method.key_material import ec_pub_from_jwk, rsa_pub_from_jwk
from credential.common.verification_method.verification_method import DIDDocument, VerificationMethodEntry

from credential.common.jsonmap._constants import JSON_WEB_KEY_2020, JSON_WEB_SIGNATURE_2020
from credential.common.jsonmap._ecdsa_common import legacy_hex_canonicalize
from credential.common.jsonmap._options import SignerProvider, algorithm_of, new_proof_options
from credential.common.jsonmap._proof_helpers import append_proof, strict_purpose_check, vm_entry_to_dict
from didv2.did.verification_method_ops import find_verification_method


def encode_detached_jws_header(alg: str) -> str:
    header = {"alg": alg, "b64": False, "crit": ["b64"]}
    return base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).decode().rstrip("=")


def detached_jws_alg(enc_header: str) -> str:
    header_bytes = base64.urlsafe_b64decode(enc_header + "=" * (-len(enc_header) % 4))
    hdr = json.loads(header_bytes)
    b64 = hdr.get("b64")
    if not isinstance(b64, bool) or b64:
        raise ValueError("jws header b64 must be false")
    crit = hdr.get("crit") or []
    if "b64" not in crit:
        raise ValueError("jws header crit must include b64")
    alg = hdr.get("alg")
    if not isinstance(alg, str) or not alg:
        raise ValueError("jws header missing alg")
    return alg


def jws_signing_input(enc_header: str, payload: bytes) -> bytes:
    return enc_header.encode("ascii") + b"." + payload


def split_detached_jws(jws: str) -> tuple[str, str, bool]:
    idx = -1
    for i in range(len(jws) - 1):
        if jws[i] == "." and jws[i + 1] == ".":
            idx = i
            break
    if idx <= 0:
        return "", "", False
    header, sig = jws[:idx], jws[idx + 2 :]
    if not header or not sig:
        return "", "", False
    return header, sig, True


def hash_for_jws_alg(alg: str, data: bytes) -> bytes:
    if alg in ("ES256", "RS256", "PS256"):
        return sha256(data).digest()
    if alg in ("RS384", "PS384"):
        import hashlib

        return hashlib.sha384(data).digest()
    if alg in ("RS512", "PS512"):
        return sha512(data).digest()
    raise ValueError(f"unsupported JWS alg: {alg}")


def validate_jws_sig_shape(alg: str, n: int) -> None:
    if alg == "ES256":
        if n != 64:
            raise ValueError(
                "JsonWebSignature2020 ES256 expects a 64-byte ECDSA signature, got "
                f"{n}; the signer does not match the verification method — pin the right VM with WithVerificationMethodKey"
            )
        return
    if n in (64, 65):
        raise ValueError(
            f"JsonWebSignature2020 {alg} expects an RSA signature but the signer returned {n} bytes "
            "(an ECDSA signature); the signer does not match the RSA verification method — "
            "pin the right VM with WithVerificationMethodKey"
        )


def add_jws_proof(
    m: dict[str, Any],
    signer: SignerProvider,
    verification_method: str,
    proof_purpose: str,
) -> None:
    if not verification_method:
        raise ValueError("jsonmap: verification method is required")
    if not proof_purpose:
        raise ValueError("jsonmap: proof purpose is required")

    alg = algorithm_of(signer)
    from datetime import datetime, timezone

    proof = Proof(
        type=JSON_WEB_SIGNATURE_2020,
        created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        verification_method=verification_method,
        proof_purpose=proof_purpose,
    )

    payload = legacy_hex_canonicalize(m)
    enc_header = encode_detached_jws_header(alg)
    signing_input = jws_signing_input(enc_header, payload)
    digest = hash_for_jws_alg(alg, signing_input)
    sig = signer.sign(digest)
    validate_jws_sig_shape(alg, len(sig))
    proof.jws = enc_header + ".." + base64.urlsafe_b64encode(sig).decode().rstrip("=")
    append_proof(m, proof)


def verify_jws_proof(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    doc_dict = {
        "id": doc.id,
        "verificationMethod": [vm_entry_to_dict(v) for v in doc.verification_method],
    }
    vm_raw = find_verification_method(doc_dict, proof.verification_method)
    if vm_raw is None:
        raise ValueError(f"failed to resolve verification method: {proof.verification_method!r}")
    if vm_raw.get("type") != JSON_WEB_KEY_2020:
        raise ValueError(f"expected {JSON_WEB_KEY_2020} VM, got {vm_raw.get('type')}")
    jwk = vm_raw.get("publicKeyJwk")
    if not jwk:
        raise ValueError(f"verification method '{vm_raw.get('id')}' has no publicKeyJwk")

    enc_header, enc_sig, ok = split_detached_jws(proof.jws)
    if not ok:
        raise ValueError("malformed detached JWS")
    alg = detached_jws_alg(enc_header)
    payload = legacy_hex_canonicalize(m)
    signing_input = jws_signing_input(enc_header, payload)
    sig = base64.urlsafe_b64decode(enc_sig + "=" * (-len(enc_sig) % 4))

    if alg == "ES256":
        pub = ec_pub_from_jwk(jwk)
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise ValueError("parse P-256 jwk: not an EC key")
        digest = sha256(signing_input).digest()
        if not verify_ecdsa(pub, digest, sig):
            raise ValueError("JsonWebSignature2020 ES256 signature verification failed")
    elif alg in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
        pub = rsa_pub_from_jwk(jwk)
        verify_rsa_jws(alg, pub, signing_input, sig)
    else:
        raise ValueError(f"unsupported JsonWebSignature2020 alg: {alg!r}")

    vm_entry = _vm_dict_to_entry(vm_raw)
    strict_purpose_check(doc, vm_entry, proof.proof_purpose, proof.created)
    return True


def _vm_dict_to_entry(vm: dict[str, Any]) -> VerificationMethodEntry:
    from credential.common.verification_method.verification_method import JWK

    jwk_raw = vm.get("publicKeyJwk")
    jwk_obj = None
    if isinstance(jwk_raw, dict):
        jwk_obj = JWK(
            kty=str(jwk_raw.get("kty", "")),
            crv=str(jwk_raw.get("crv", "")),
            x=str(jwk_raw.get("x", "")),
            y=str(jwk_raw.get("y", "")),
            n=str(jwk_raw.get("n", "")),
            e=str(jwk_raw.get("e", "")),
        )
    return VerificationMethodEntry(
        id=str(vm.get("id", "")),
        type=str(vm.get("type", "")),
        controller=str(vm.get("controller", "")),
        public_key_hex=str(vm.get("publicKeyHex", "")),
        public_key_jwk=jwk_obj,
        public_key_multibase=str(vm.get("publicKeyMultibase", "")),
    )
