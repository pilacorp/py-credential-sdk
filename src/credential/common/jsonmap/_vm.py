"""Verification-method helpers for the proof verifiers (Go verificationmethod.FindVerificationMethod,
VMIsSecp256k1, VMIsP256, ECPubFromVM) that tolerate every public-key type the key-material layer returns."""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys as eth_keys_mod
from eth_keys.constants import SECPK1_N

from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.common.verification_method.verification_method import DIDDocument, VerificationMethodEntry

SECP256K1_N = SECPK1_N


def find_vm_entry(doc: DIDDocument, vm_url: str) -> VerificationMethodEntry:
    """Exact full-URL match (no fragment normalisation)."""
    if doc is None:
        raise ValueError("did document is nil")
    if not vm_url:
        raise ValueError("verification method is empty")
    for vm in doc.verification_method:
        if vm.id == vm_url:
            return vm
    raise ValueError(f"verification method '{vm_url}' not found in DID '{doc.id}' document")


def vm_is_secp256k1(vm: VerificationMethodEntry | None) -> bool:
    if vm is None:
        return False
    if vm.public_key_jwk is not None:
        return vm.public_key_jwk.kty == "EC" and vm.public_key_jwk.crv == "secp256k1"
    return vm.public_key_hex != ""


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pub_from_entry(vm: VerificationMethodEntry) -> Any:
    """Public key of a VM: a ``cryptography`` EC key (P-256/P-384) or ``eth_keys.PublicKey`` (secp256k1)."""
    if vm is None:
        raise ValueError("verification method is nil")
    jwk = vm.public_key_jwk
    if not vm.public_key_hex and jwk is not None and jwk.kty == "EC" and jwk.crv == "secp256k1":
        x, y = _b64u(jwk.x), _b64u(jwk.y)
        if len(x) > 32 or len(y) > 32:
            raise ValueError("jwk coordinates too long")
        try:
            return eth_keys_mod.PublicKey(x.rjust(32, b"\0") + y.rjust(32, b"\0"))
        except Exception as exc:
            raise ValueError(f"invalid secp256k1 public key: {exc}") from exc
    return ec_pub_from_vm(vm)


def curve_order(pub: Any) -> int:
    if isinstance(pub, eth_keys_mod.PublicKey):
        return SECP256K1_N
    c = pub.curve
    if isinstance(c, ec.SECP256K1):
        return SECP256K1_N
    if isinstance(c, ec.SECP256R1):
        return 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    if isinstance(c, ec.SECP384R1):
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    return 0


def curve_name(pub: Any) -> str:
    return "secp256k1" if isinstance(pub, eth_keys_mod.PublicKey) else pub.curve.name


def is_p256(pub: Any) -> bool:
    return isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)
