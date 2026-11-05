from __future__ import annotations

import base64
import json
from hashlib import sha256, sha512
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.crypto.ecdsa_rdfc import verify_p256 as verify_p256_key
from credential.common.util.b64 import b64url_decode, b64url_encode
from credential.common.crypto.jws_2020 import verify_rsa_jws
from credential.common.dto.proof import Proof
from credential.common.verification_method.key_material import ec_pub_from_jwk, rsa_pub_from_jwk
from credential.common.verification_method.verification_method import DIDDocument, VerificationMethodEntry

from credential.common.jsonmap._constants import JSON_WEB_KEY_2020, JSON_WEB_SIGNATURE_2020
from credential.common.jsonmap._ecdsa_common import legacy_hex_canonicalize
from credential.common.jsonmap._options import SignerProvider, algorithm_of, new_proof_options
from credential.common.jsonmap._proof_helpers import append_proof, strict_purpose_check
from credential.common.jsonmap._vm import find_vm_entry
from cryptography.exceptions import InvalidSignature


def encode_detached_jws_header(alg: str) -> str:
    header = {"alg": alg, "b64": False, "crit": ["b64"]}
    return b64url_encode(json.dumps(header, separators=(",", ":")).encode())


def detached_jws_alg(enc_header: str) -> str:
    """Decode the header, enforce b64:false + crit:[b64] and return alg (Go detachedJWSAlg)."""
    try:
        header_bytes = b64url_decode(enc_header)
    except ValueError as exc:
        raise ValueError(f"decode jws header: {exc}") from exc
    try:
        hdr = json.loads(header_bytes)
        if not isinstance(hdr, dict):
            raise ValueError("not an object")
        crit = hdr.get("crit")
        if crit is not None and not (isinstance(crit, list) and all(isinstance(c, str) for c in crit)):
            raise ValueError("crit must be an array of strings")
        alg = hdr.get("alg", "")
        if not isinstance(alg, str):
            raise ValueError("alg must be a string")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"parse jws header: {exc}") from exc
    b64 = hdr.get("b64")
    if not isinstance(b64, bool) or b64:
        raise ValueError("jws header b64 must be false")
    if "b64" not in (crit or []):
        raise ValueError("jws header crit must include b64")
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
    proof.jws = enc_header + ".." + b64url_encode(sig)
    append_proof(m, proof)


def verify_jws_proof(m: dict[str, Any], doc: DIDDocument, proof: Proof) -> bool:
    try:
        vm = find_vm_entry(doc, proof.verification_method)
    except ValueError as exc:
        raise ValueError(f"failed to resolve verification method: {exc}") from exc
    if vm.type != JSON_WEB_KEY_2020:
        raise ValueError(f"expected {JSON_WEB_KEY_2020} VM, got {vm.type}")
    jwk = vm.public_key_jwk
    if jwk is None:
        raise ValueError(f"verification method '{vm.id}' has no publicKeyJwk")

    enc_header, enc_sig, ok = split_detached_jws(proof.jws)
    if not ok:
        raise ValueError("malformed detached JWS")
    alg = detached_jws_alg(enc_header)
    try:
        payload = legacy_hex_canonicalize(m)
    except ValueError as exc:
        raise ValueError(f"canonicalize: {exc}") from exc
    signing_input = jws_signing_input(enc_header, payload)
    try:
        sig = b64url_decode(enc_sig)
    except ValueError as exc:
        raise ValueError(f"decode jws signature: {exc}") from exc

    jwk_dict = {"kty": jwk.kty, "crv": jwk.crv, "x": jwk.x, "y": jwk.y, "n": jwk.n, "e": jwk.e}
    if alg == "ES256":
        try:
            pub = ec_pub_from_jwk(jwk_dict)
        except Exception as exc:
            raise ValueError(f"parse P-256 jwk: {exc}") from exc
        if not (isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)):
            raise ValueError("parse P-256 jwk: not a P-256 key")
        if not verify_p256_key(pub, sha256(signing_input).digest(), sig):
            raise ValueError("JsonWebSignature2020 ES256 signature verification failed")
    elif alg in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
        try:
            pub = rsa_pub_from_jwk(jwk_dict)
        except Exception as exc:
            raise ValueError(f"parse RSA jwk: {exc}") from exc
        try:
            verify_rsa_jws(alg, pub, signing_input, sig)
        except InvalidSignature as exc:
            raise ValueError("crypto/rsa: verification error") from exc
    else:
        raise ValueError(f"unsupported JsonWebSignature2020 alg: {alg!r}")

    strict_purpose_check(doc, vm, proof.proof_purpose, proof.created)
    return True
