from didv2.did.verification_method_ops import (
    add_verification_method,
    add_verification_method_purposes,
    find_verification_method,
    remove_verification_method_purposes,
    revoke_verification_method,
    rotate_verification_method,
)
from credential.common.verification_method import resolve_signing_vm

DID = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
PUB1 = "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"
PUB2 = "0x03eea1acf8f417b7825a00be2bf446ef87da146f58e664f36f85f91e74d4f79dc1"


def _doc() -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": DID,
        "controller": DID,
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": [],
    }


def test_add_rotate_revoke_purpose() -> None:
    doc = _doc()
    kid = add_verification_method(doc, {"publicKeyHex": PUB1}, ["authentication", "assertionMethod"])
    assert kid.endswith("#key-1")
    add_verification_method_purposes(doc, kid, ["authentication"])
    new_id = rotate_verification_method(doc, kid, {"publicKeyHex": PUB2})
    assert find_verification_method(doc, kid)["revoked"]
    revoke_verification_method(doc, new_id, "superseded")
    try:
        add_verification_method_purposes(doc, new_id, ["authentication"])
        raise AssertionError("expected revoked")
    except ValueError:
        pass
    remove_verification_method_purposes(doc, kid, ["authentication"])


def test_resolve_signing_vm_rejects_revoked() -> None:
    doc = _doc()
    kid = add_verification_method(doc, {"publicKeyHex": PUB1}, ["assertionMethod"])
    revoke_verification_method(doc, kid, "keyCompromise")
    try:
        resolve_signing_vm(DID, "assertionMethod", "key-1", doc)
        raise AssertionError("expected reject")
    except ValueError as exc:
        assert "revoked" in str(exc)
