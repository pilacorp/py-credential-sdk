from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from credential.common.jwt.jwtutil import b64url_encode, trim_recovery_byte
from credential.common.jwt.signing_method import alg_for_key_kind, verify_ecdsa
from credential.common.verification_method.key_material import ec_pub_from_vm
from credential.common.verification_method.resolve import resolve_signing_vm
from credential.common.verification_method.selector import vm_key_kind


@dataclass
class SigningKey:
    """The verification method a JWT is issued under: the kid and alg its header
    carries, and the public key a fresh signature must verify against. The default
    (empty) value is a token that was parsed rather than built."""

    id: str = ""
    alg: str = ""
    public_key: Any = None

    def accept(self, signing_input: str, signature: bytes) -> str:
        """Check a raw signature over signing_input and return it base64url-encoded.

        A trailing recovery id is trimmed; anything but 64-byte r||s is a signer
        returning the wrong format. With no key (parsed token) only the shape is checked.
        """
        signature = trim_recovery_byte(bytes(signature))
        n = len(signature)
        if n != 64:
            raise ValueError(
                f"signature must be 64-byte r||s (65 with a trailing recovery id is trimmed), got {n} bytes: "
                "the signer returned another format, not a JWS signature"
            )
        if self.public_key is not None:
            try:
                verify_ecdsa(signing_input, signature, self.public_key)
            except ValueError as exc:
                raise ValueError(
                    f"the signature does not verify against verification method {self.id!r}: it was made by "
                    "another key or over data other than the signing input — to sign with another key, pass "
                    f"WithVerificationMethodKey to NewJWTCredential / NewJWTPresentation: {exc}"
                ) from exc
        return b64url_encode(signature)


def resolve_signing_key(did: str, purpose: str, pinned_key: str, resolver: Any) -> SigningKey:
    """Resolve the VM to sign with (pinned, or latest active for purpose) and derive the JOSE alg."""
    try:
        vm = resolve_signing_vm(did, purpose, pinned_key, resolver)
    except ValueError as exc:
        raise ValueError(f"resolve verification method: {exc}") from exc
    kind, ok = vm_key_kind(vm)
    if not ok:
        raise ValueError(f"verification method {vm.id!r} has an unrecognized key type")
    try:
        alg = alg_for_key_kind(kind)
        pub = ec_pub_from_vm(vm)
    except ValueError as exc:
        raise ValueError(f"verification method {vm.id!r}: {exc}") from exc
    return SigningKey(id=vm.id, alg=alg, public_key=pub)
