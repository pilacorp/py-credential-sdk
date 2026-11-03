from eth_account import Account
from eth_account.messages import encode_defunct

from didv2.config import DEFAULT_DID_SMC_ADDRESS
from didv2.didcontract import create_did_tx, has_role_selector, writer_anchor_topic0
from didv2.issuer import generate_cap_id, generate_issue_did_signature
from didv2.signer import DefaultProvider
from didv2.model import DID_TYPE_PEOPLE
from didv2.keccak import keccak256, keccak256_hex


def test_cap_id() -> None:
    cap = generate_cap_id()
    assert cap.startswith("0x") and len(cap) == 66


def test_issue_signature_recovers() -> None:
    issuer = DefaultProvider("11" * 32)
    cap = "0x" + "ab" * 32
    sig = generate_issue_did_signature(
        DEFAULT_DID_SMC_ADDRESS,
        issuer.get_address(),
        "0x86b2efd244acb31eb238a65ca05476ab42558071",
        DID_TYPE_PEOPLE,
        7,
        cap,
        issuer,
    )
    compact = sig["r"].to_bytes(32, "big") + sig["s"].to_bytes(32, "big") + bytes([sig["v"]])
    from didv2.issuer import build_issue_did_payload

    digest = keccak256(
        build_issue_did_payload(
            DEFAULT_DID_SMC_ADDRESS,
            issuer.get_address(),
            "0x86b2efd244acb31eb238a65ca05476ab42558071",
            DID_TYPE_PEOPLE,
            7,
            cap,
        )
    )
    recovered = Account._recover_hash(digest, vrs=(sig["v"], sig["r"], sig["s"]))
    assert recovered.lower() == issuer.get_address()
    assert len(compact) == 65


def test_create_did_tx_and_abi() -> None:
    issuer = DefaultProvider("11" * 32)
    did = DefaultProvider("22" * 32)
    cap = "0x" + "cd" * 32
    doc_hash = "0x" + "11" * 32
    sig = generate_issue_did_signature(
        DEFAULT_DID_SMC_ADDRESS,
        issuer.get_address(),
        did.get_address(),
        DID_TYPE_PEOPLE,
        0,
        cap,
        issuer,
    )
    tx = create_did_tx(issuer.get_address(), sig, doc_hash, cap, DID_TYPE_PEOPLE, 0, did)
    assert tx["txHex"]
    assert tx["txHash"].startswith("0x") and len(tx["txHash"]) == 66
    assert writer_anchor_topic0() == "0x39edf358809bd8ab55bfce6add00fc1843a5c6e38ca5257fe7fb98b8bb145469"
    assert has_role_selector() == "0x91d14854"
    keccak256_hex(b"unused")
    encode_defunct(text="x")
