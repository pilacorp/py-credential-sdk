"""Create a DID with didv2: builds the document and the signed createDID transaction. Nothing is sent."""
from pila_credential.didv2 import DIDGenerator, DefaultProvider
from pila_credential.didv2.did.did import generate_ecdsa_key_pair


def main() -> None:
    issuer = DefaultProvider(generate_ecdsa_key_pair().get_private_key_hex())  # a DID issuer account
    gen = DIDGenerator(issuer_signer=issuer)
    res = gen.generate_did(1)  # did_type 1; per-call overrides: generate_did(1, nonce=5, enable_p256_vm=True)
    print(res["did"])
    print("tx:", res["transaction"].tx_hash if hasattr(res["transaction"], "tx_hash") else res["transaction"])
    assert "secret" in res  # keep res["secret"]["privateKeyHex"]; it is the DID's private key


if __name__ == "__main__":
    main()
