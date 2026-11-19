"""Issue and verify a JSON-LD VC (ecdsa-rdfc-2019), offline: the issuer's DID document is a StaticResolver."""
import json

from cryptography.hazmat.primitives.asymmetric import ec

from pila_credential.credential.common.signer.p256 import P256Provider
from pila_credential.credential.common.verification_method import StaticResolver, new_did_document, new_p256_vm
from pila_credential.credential.vc import credential as vc
from pila_credential.credential.vc.json_credential import JSONCredential

ISSUER = "did:example:issuer"


def main() -> None:
    signer = P256Provider.from_hex("1f2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff001")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), signer.public_key_uncompressed())
    resolver = StaticResolver([new_did_document(ISSUER, [new_p256_vm(ISSUER, "key-1", pub)])])

    doc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        "type": ["VerifiableCredential"],
        "issuer": ISSUER,
        "credentialSubject": {"id": "did:example:holder"},
    }
    cred = JSONCredential.parse(json.dumps(doc), vc.with_resolver(resolver))
    cred.add_proof_by_provider(signer, vc.with_resolver(resolver))
    wire = cred.to_json()  # what you send

    received = vc.parse_credential(wire, vc.with_resolver(resolver), vc.with_verify_proof())
    print("verified:", received.get_type())


if __name__ == "__main__":
    main()
