import json

from didv2.signer import DefaultProvider
from didv2.did.did import marshal_did_document
from didv2.subdid.document import doc_hash, sub_did_for
from didv2.subdid.generate import generate_sub_did
from didv2.model import DID_TYPE_PEOPLE

ROOT_R1 = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
SUB_IDS1 = "0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5"
ROW1_PUB = "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"
ROW1_DID = "did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071"
ROW1_PRIV = "46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8"
ROOT_PRIV = "11" * 32
CREATE_SIG = "0x73ffc216c50a9cbdf28d8eac72954f337974e390e83427abe79d3ed5bea8ee7e602b23159cf8ce401bf7e5fc2de553568e9c3a9359267fc393e5033f7fa59ce61b"
CREATE_HASH = "0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8"


def test_sub_did_for() -> None:
    assert sub_did_for(ROOT_R1, ROW1_PUB) == ROW1_DID


def test_generate_sub_did_vector() -> None:
    res = generate_sub_did(
        ROOT_R1,
        SUB_IDS1,
        ROW1_PUB,
        DID_TYPE_PEOPLE,
        None,
        DefaultProvider(ROOT_PRIV),
        DefaultProvider(ROW1_PRIV),
    )
    assert res["did"] == ROW1_DID
    assert res["type"] == "people"
    assert res["signature"] == CREATE_SIG
    assert marshal_did_document(res["document"]) == (
        '{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],'
        '"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071",'
        '"controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",'
        '"verificationMethod":[{"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1",'
        '"type":"EcdsaSecp256k1VerificationKey2019",'
        '"controller":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071",'
        '"publicKeyHex":"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"}],'
        '"authentication":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],'
        '"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],'
        '"didDocumentMetadata":{"rootConsent":"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c","subId":"0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5","type":"people"}}'
    )
    assert doc_hash(res["document"]) == CREATE_HASH
    json.loads(marshal_did_document(res["document"]))
