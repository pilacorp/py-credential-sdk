from datetime import datetime, timezone

from credential.common.verification_method.selector import (
    select_default_signing_vm,
    select_latest_active_vm_for_purpose,
)
from credential.common.verification_method.resolve import resolve_signing_vm
from didv2.did.verification_method_ops import add_verification_method, revoke_verification_method

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


def test_latest_active_wins() -> None:
    doc = _doc()
    add_verification_method(doc, {"publicKeyHex": PUB1}, ["assertionMethod"])
    add_verification_method(doc, {"publicKeyHex": PUB2}, ["assertionMethod"])
    vm = select_latest_active_vm_for_purpose(doc, "assertionMethod")
    assert vm["id"].endswith("#key-2")


def test_single_vm_shortcut() -> None:
    doc = _doc()
    add_verification_method(doc, {"publicKeyHex": PUB1})
    vm = select_default_signing_vm(doc, "assertionMethod")
    assert vm["id"].endswith("#key-1")


def test_unknown_purpose_errors() -> None:
    doc = _doc()
    add_verification_method(doc, {"publicKeyHex": PUB1}, ["assertionMethod"])
    try:
        select_latest_active_vm_for_purpose(doc, "authenticaion")
        raise AssertionError("expected error")
    except ValueError as exc:
        assert "unsupported purpose" in str(exc)


def test_resolve_rejects_revoked_pinned() -> None:
    doc = _doc()
    kid = add_verification_method(doc, {"publicKeyHex": PUB1}, ["assertionMethod"])
    revoke_verification_method(doc, kid, "keyCompromise", datetime.now(timezone.utc))
    try:
        resolve_signing_vm(DID, "assertionMethod", "key-1", doc)
        raise AssertionError("expected reject")
    except ValueError as exc:
        assert "revoked" in str(exc)
