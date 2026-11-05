"""Go: digitalcredential/example_test.go: the three roles of draft-ietf-oauth-sd-jwt-vc-19 in one run."""

from datetime import datetime, timedelta, timezone

from digitalcredential import (
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
from jose.jws import private_key_signer

from dc_helpers import new_key


def test_example():
    iss, verifier, nonce = "https://issuer.example", "https://verifier.example", "n-0S6_WzA2Mj"
    # Issuer.
    issuer_priv, holder_priv = new_key(), new_key()
    now = datetime.now(timezone.utc)
    cred = issue(
        IssueRequest(
            issuer=iss,
            vct="https://credentials.example/identity_credential",
            issued_at=now,
            expiry=now + timedelta(days=365),
            holder_key=holder_priv.public_key(),  # written as cnf.jwk
            claims={"given_name": "Erika", "family_name": "Mustermann", "birthdate": "1963-08-12"},
            disclose=[["given_name"], ["family_name"], ["birthdate"]],
        ),
        SigningKey(signer=private_key_signer(issuer_priv), public=issuer_priv.public_key(), kid="key-1"),
    )
    issued = cred.serialize()  # sent to the Holder
    # Holder: keeps the credential, then discloses only given_name, signing a Key Binding JWT.
    presentation = parse(issued).present(
        PresentRequest(
            reveal=[["given_name"]],
            key_binding=KeyBinding(signer=private_key_signer(holder_priv), audience=verifier, nonce=nonce, issued_at=now),
        )
    )
    # Verifier.
    received = parse(presentation.serialize())
    res = received.verify(StaticResolver(iss, [PublicKey(issuer_priv.public_key(), "key-1")]), with_audience(verifier), with_nonce(nonce))
    assert (res.issuer, res.vct) == (iss, "https://credentials.example/identity_credential")
    assert res.key_bound
    assert res.claims["given_name"] == "Erika"
    assert "family_name" not in res.claims
