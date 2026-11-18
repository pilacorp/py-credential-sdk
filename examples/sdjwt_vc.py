"""Issue, present and verify an SD-JWT VC (digitalcredential), offline."""
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec

from pila_credential.digitalcredential import (
    IssueRequest,
    KeyBinding,
    PresentRequest,
    PublicKey,
    SigningKey,
    StaticResolver,
    issue,
    parse,
    with_audience,
    with_nonce,
)
from pila_credential.jose.jws import private_key_signer


def main() -> None:
    iss, verifier, nonce = "https://issuer.example", "https://verifier.example", "n-0S6_WzA2Mj"
    issuer_priv = ec.generate_private_key(ec.SECP256R1())
    holder_priv = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)

    cred = issue(
        IssueRequest(
            issuer=iss,
            vct="https://credentials.example/identity_credential",
            issued_at=now,
            expiry=now + timedelta(days=365),
            holder_key=holder_priv.public_key(),
            claims={"given_name": "Erika", "family_name": "Mustermann"},
            disclose=[["given_name"], ["family_name"]],
        ),
        SigningKey(signer=private_key_signer(issuer_priv), public=issuer_priv.public_key(), kid="key-1"),
    )
    presentation = parse(cred.serialize()).present(
        PresentRequest(
            reveal=[["given_name"]],
            key_binding=KeyBinding(signer=private_key_signer(holder_priv), audience=verifier, nonce=nonce, issued_at=now),
        )
    )
    res = parse(presentation.serialize()).verify(
        StaticResolver(iss, [PublicKey(issuer_priv.public_key(), "key-1")]), with_audience(verifier), with_nonce(nonce)
    )
    assert res.claims["given_name"] == "Erika" and "family_name" not in res.claims
    print("verified:", res.vct)


if __name__ == "__main__":
    main()
