from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import ec

from credential.common.dto.proof import StringOrStrings


class SignerProvider(Protocol):
    def sign(self, digest: bytes) -> bytes: ...


class AlgorithmProvider(SignerProvider, Protocol):
    def jose_algorithm(self) -> str: ...


@dataclass
class ProofOptions:
    vm_pub: ec.EllipticCurvePublicKey | None = None
    challenge: str = ""
    domain: str = ""


def domain_value(domain: str) -> StringOrStrings | None:
    if not domain:
        return None
    return StringOrStrings([domain])


def new_proof_options(
    *,
    vm_pub: ec.EllipticCurvePublicKey | None = None,
    challenge: str = "",
    domain: str = "",
) -> ProofOptions:
    return ProofOptions(vm_pub=vm_pub, challenge=challenge, domain=domain)


def algorithm_of(signer: SignerProvider) -> str:
    if hasattr(signer, "jose_algorithm"):
        return signer.jose_algorithm()  # type: ignore[no-any-return]
    return "RS256"
