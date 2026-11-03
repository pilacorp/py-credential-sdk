from __future__ import annotations

from typing import Any

import pytest
from eth_abi import encode
from eth_utils import to_checksum_address

from credential.vccontract.model import VerifyByTxRequest, VerifyRequest
from credential.vccontract.registry import (
    ERR_NO_CONTRACT,
    ERR_ROOT_NOT_ANCHORED,
    ERR_TX_NOT_FOUND,
    ERR_TX_REVERTED,
    ERR_UNTRUSTED,
    EVENT_TOPICS,
    CredentialRegistry,
    fold_proof,
    hash_pair,
)
from didv2.hexutil import with_0x

REGISTRY = "0x1111111111111111111111111111111111111111"
LEGACY = "0x2222222222222222222222222222222222222222"
ATTACKER = "0xdead00000000000000000000000000000000beef"
ISSUER = "0xabc0000000000000000000000000000000000001"
OTHER_ISSUER = "0xabc0000000000000000000000000000000000002"
LEGACY_TREE_INDEX = 7


def mk_leaf(byte: int) -> bytes:
    return bytes([byte]) * 32


def hex_of(raw: bytes) -> str:
    return with_0x(raw)


class FakeRpc:
    def __init__(
        self,
        receipt: dict[str, Any] | None = None,
        *,
        receipt_error: str | None = None,
        eth_call_result: str | None = None,
    ) -> None:
        self.receipt = receipt
        self.receipt_error = receipt_error
        self.eth_call_result = eth_call_result
        self.calls: list[tuple[str, list[Any]]] = []

    def call(self, method: str, params: list[Any]) -> Any:
        self.calls.append((method, params))
        if method == "eth_getTransactionReceipt":
            if self.receipt_error == "not_found":
                return None
            return self.receipt
        if method == "eth_call":
            return self.eth_call_result
        raise AssertionError(f"unexpected rpc method {method}")


def success_receipt(*logs: dict[str, Any] | None) -> dict[str, Any]:
    return {"status": "0x1", "logs": list(logs)}


def _pack_non_indexed(emitter: str, event_name: str, *args: Any) -> dict[str, Any]:
    signatures = {
        "BatchRootsAnchored": (["address[]", "bytes32[]"], args),
        "IssuerRootsAnchored": (["bytes32[]"], args),
        "BatchTreesUpdated": (["address[]", "uint256[]", "bytes32[]"], args),
        "TreeUpdated": (["bytes32"], args),
    }
    types, values = signatures[event_name]
    data = encode(types, values)
    return {
        "address": to_checksum_address(emitter),
        "topics": [EVENT_TOPICS[event_name]],
        "data": with_0x(data),
    }


def batch_log(emitter: str, issuers: list[str], roots: list[bytes]) -> dict[str, Any]:
    return _pack_non_indexed(
        emitter,
        "BatchRootsAnchored",
        [to_checksum_address(i) for i in issuers],
        roots,
    )


def single_log(emitter: str, issuer: str, root: bytes) -> dict[str, Any]:
    issuer_topic = with_0x(b"\x00" * 12 + hex_to_addr_bytes(issuer))
    return {
        "address": to_checksum_address(emitter),
        "topics": [EVENT_TOPICS["TreeRootAnchored"], issuer_topic, with_0x(root)],
        "data": "0x",
    }


def issuer_batch_log(emitter: str, issuer: str, roots: list[bytes]) -> dict[str, Any]:
    log = _pack_non_indexed(emitter, "IssuerRootsAnchored", roots)
    issuer_topic = with_0x(b"\x00" * 12 + hex_to_addr_bytes(issuer))
    log["topics"] = [EVENT_TOPICS["IssuerRootsAnchored"], issuer_topic]
    return log


def legacy_batch_log(emitter: str, issuers: list[str], roots: list[bytes]) -> dict[str, Any]:
    indices = [LEGACY_TREE_INDEX + i for i in range(len(roots))]
    return _pack_non_indexed(
        emitter,
        "BatchTreesUpdated",
        [to_checksum_address(i) for i in issuers],
        indices,
        roots,
    )


def legacy_single_log(emitter: str, issuer: str, root: bytes) -> dict[str, Any]:
    log = _pack_non_indexed(emitter, "TreeUpdated", root)
    issuer_topic = with_0x(b"\x00" * 12 + hex_to_addr_bytes(issuer))
    index_topic = with_0x((LEGACY_TREE_INDEX).to_bytes(32, "big"))
    log["topics"] = [EVENT_TOPICS["TreeUpdated"], issuer_topic, index_topic]
    return log


def hex_to_addr_bytes(addr: str) -> bytes:
    return bytes.fromhex(addr.removeprefix("0x"))


def registry_with(
    receipt: dict[str, Any] | None = None,
    *,
    receipt_error: str | None = None,
    also_trust: list[str] | None = None,
    contract: str = REGISTRY,
) -> CredentialRegistry:
    rpc = FakeRpc(receipt, receipt_error=receipt_error)
    trust = also_trust or []
    return CredentialRegistry("http://127.0.0.1:1", contract, trust, rpc=rpc)


def every_shape(emitter: str, issuer: str, root: bytes) -> list[tuple[str, dict[str, Any]]]:
    return [
        ("current single", single_log(emitter, issuer, root)),
        (
            "current cross-issuer batch",
            batch_log(emitter, [OTHER_ISSUER, issuer], [mk_leaf(0x01), root]),
        ),
        ("current issuer batch", issuer_batch_log(emitter, issuer, [mk_leaf(0x02), root])),
        ("legacy single", legacy_single_log(emitter, issuer, root)),
        (
            "legacy batch",
            legacy_batch_log(emitter, [OTHER_ISSUER, issuer], [mk_leaf(0x03), root]),
        ),
    ]


@pytest.mark.parametrize(
    "name,log",
    [
        (n, l)
        for n, l in every_shape(REGISTRY, ISSUER, mk_leaf(0xBB))
    ],
)
def test_is_root_anchored_reads_every_event_shape(name: str, log: dict[str, Any]) -> None:
    reg = registry_with(success_receipt(log))
    assert reg.is_root_anchored("0x" + "cd" * 32, ISSUER, mk_leaf(0xBB))


@pytest.mark.parametrize(
    "name,log",
    [(n, l) for n, l in every_shape(REGISTRY, ISSUER, mk_leaf(0xBB))],
)
def test_is_root_anchored_rejects_absent_root(name: str, log: dict[str, Any]) -> None:
    reg = registry_with(success_receipt(log))
    assert not reg.is_root_anchored("0x" + "cd" * 32, ISSUER, mk_leaf(0xCC))


@pytest.mark.parametrize(
    "name,log",
    [(n, l) for n, l in every_shape(REGISTRY, OTHER_ISSUER, mk_leaf(0xBB))],
)
def test_is_root_anchored_rejects_other_issuer(name: str, log: dict[str, Any]) -> None:
    reg = registry_with(success_receipt(log))
    assert not reg.is_root_anchored("0x" + "cd" * 32, ISSUER, mk_leaf(0xBB))


@pytest.mark.parametrize(
    "name,log",
    [(n, l) for n, l in every_shape(ATTACKER, ISSUER, mk_leaf(0xBB))],
)
def test_is_root_anchored_rejects_foreign_emitter(name: str, log: dict[str, Any]) -> None:
    reg = registry_with(success_receipt(log))
    assert not reg.is_root_anchored("0x" + "cd" * 32, ISSUER, mk_leaf(0xBB))


def test_is_root_anchored_trusts_legacy_deployment() -> None:
    want = mk_leaf(0xBB)
    reg = registry_with(
        success_receipt(legacy_batch_log(LEGACY, [ISSUER], [want])),
        also_trust=[LEGACY],
    )
    assert reg.is_root_anchored("0x" + "cd" * 32, ISSUER, want)


def test_is_root_anchored_mixed_logs() -> None:
    want = mk_leaf(0xBB)
    reg = registry_with(
        success_receipt(
            legacy_batch_log(LEGACY, [OTHER_ISSUER], [mk_leaf(0x01)]),
            batch_log(REGISTRY, [ISSUER], [want]),
        ),
        also_trust=[LEGACY],
    )
    assert reg.is_root_anchored("0x" + "cd" * 32, ISSUER, want)


def test_is_root_anchored_at_contract_pins_emitter() -> None:
    want = mk_leaf(0xBB)
    reg = registry_with(
        success_receipt(legacy_batch_log(LEGACY, [ISSUER], [want])),
        also_trust=[LEGACY],
    )
    assert reg.is_root_anchored_at_contract("0x" + "cd" * 32, ISSUER, want, LEGACY)
    assert not reg.is_root_anchored_at_contract("0x" + "cd" * 32, ISSUER, want, REGISTRY)


def test_is_root_anchored_at_contract_rejects_untrusted_pin() -> None:
    want = mk_leaf(0xBB)
    reg = registry_with(success_receipt(batch_log(REGISTRY, [ISSUER], [want])))
    with pytest.raises(ValueError, match=ERR_UNTRUSTED):
        reg.is_root_anchored_at_contract("0x" + "cd" * 32, ISSUER, want, ATTACKER)


def test_is_root_anchored_receipt_outcomes() -> None:
    reg = registry_with(receipt_error="not_found")
    with pytest.raises(ValueError, match=ERR_TX_NOT_FOUND):
        reg.is_root_anchored("0x" + "cd" * 32, ISSUER, mk_leaf(0xBB))

    reg = registry_with({"status": "0x0", "logs": []})
    with pytest.raises(ValueError, match=ERR_TX_REVERTED):
        reg.is_root_anchored("0x" + "cd" * 32, ISSUER, mk_leaf(0xBB))


def test_is_root_anchored_empty_root() -> None:
    reg = registry_with(success_receipt())
    assert not reg.is_root_anchored("0x" + "cd" * 32, ISSUER, b"\x00" * 32)
    assert reg.rpc.calls == []


def test_get_anchored_root_legacy() -> None:
    want = mk_leaf(0xBB)
    reg = registry_with(
        success_receipt(
            legacy_batch_log(REGISTRY, [OTHER_ISSUER, ISSUER], [mk_leaf(0x01), want]),
        ),
    )
    got = reg.get_anchored_root("0x" + "cd" * 32, ISSUER, LEGACY_TREE_INDEX + 1)
    assert got.lower() == hex_of(want).lower()


@pytest.mark.parametrize(
    "log",
    [
        single_log(REGISTRY, ISSUER, mk_leaf(0xBB)),
        batch_log(REGISTRY, [ISSUER], [mk_leaf(0xBB)]),
        issuer_batch_log(REGISTRY, ISSUER, [mk_leaf(0xBB)]),
    ],
)
def test_get_anchored_root_not_in_current_events(log: dict[str, Any]) -> None:
    reg = registry_with(success_receipt(log))
    with pytest.raises(ValueError, match=ERR_ROOT_NOT_ANCHORED):
        reg.get_anchored_root("0x" + "cd" * 32, ISSUER, LEGACY_TREE_INDEX)


def test_hash_pair_known_vector() -> None:
    a, b, c, d = mk_leaf(0x0A), mk_leaf(0x0B), mk_leaf(0x0C), mk_leaf(0x0D)
    assert hash_pair(a, b) == hash_pair(b, a)
    assert hash_pair(a, b).hex() == "0d0f9871649057367c9802ed72c3863f53b2d28ae3d10ece2d4ef0d2f9213784"
    root = hash_pair(hash_pair(a, b), hash_pair(c, d))
    assert root.hex() == "94d1872730575cc36cfe8dc134c661933532c76cacf4512666feeb402206ca29"
    assert fold_proof(a, [b, hash_pair(c, d)]) == root


def two_leaf_tree() -> tuple[bytes, bytes, bytes]:
    leaf, sibling = mk_leaf(0xA1), mk_leaf(0xB2)
    return leaf, sibling, hash_pair(leaf, sibling)


def test_verify_vc_hash_by_tx() -> None:
    leaf, sibling, root = two_leaf_tree()
    tx = hex_of(mk_leaf(0xCD))
    anchoring = batch_log(REGISTRY, [ISSUER], [root])

    def reg_for(receipt: dict[str, Any] | None, also: list[str] | None = None) -> CredentialRegistry:
        return registry_with(receipt, also_trust=also)

    assert reg_for(success_receipt(anchoring)).verify_vc_hash_by_tx(
        ISSUER, hex_of(leaf), [hex_of(sibling)], tx
    )

    assert not reg_for(success_receipt(anchoring)).verify_vc_hash_by_tx(
        ISSUER, hex_of(leaf), [hex_of(mk_leaf(0xEE))], tx
    )

    assert not reg_for(success_receipt(anchoring)).verify_vc_hash_by_tx(
        ISSUER, hex_of(mk_leaf(0xEF)), [hex_of(sibling)], tx
    )

    assert not reg_for(success_receipt(anchoring)).verify_vc_hash_by_tx(
        OTHER_ISSUER, hex_of(leaf), [hex_of(sibling)], tx
    )

    assert not reg_for({"status": "0x0", "logs": []}).verify_vc_hash_by_tx(
        ISSUER, hex_of(leaf), [hex_of(sibling)], tx
    )

    with pytest.raises(ValueError, match=ERR_TX_NOT_FOUND):
        registry_with(receipt_error="not_found").verify_vc_hash_by_tx(
            ISSUER, hex_of(leaf), [hex_of(sibling)], tx
        )

    legacy_single = legacy_single_log(LEGACY, ISSUER, root)
    assert reg_for(success_receipt(legacy_single), also=[LEGACY]).verify_vc_hash_by_tx(
        ISSUER, hex_of(leaf), [hex_of(sibling)], tx
    )

    legacy_batch = legacy_batch_log(LEGACY, [OTHER_ISSUER, ISSUER], [mk_leaf(0x01), root])
    assert reg_for(success_receipt(legacy_batch), also=[LEGACY]).verify_vc_hash_by_tx(
        ISSUER, hex_of(leaf), [hex_of(sibling)], tx
    )

    reg = reg_for(success_receipt(batch_log(LEGACY, [ISSUER], [root])), also=[LEGACY])
    assert reg.verify_vc_hash_by_tx(
        ISSUER,
        hex_of(leaf),
        [hex_of(sibling)],
        tx,
        contract_address=LEGACY,
    )
    assert not reg.verify_vc_hash_by_tx(
        ISSUER,
        hex_of(leaf),
        [hex_of(sibling)],
        tx,
        contract_address=REGISTRY,
    )

    with pytest.raises(ValueError, match=ERR_UNTRUSTED):
        reg_for(success_receipt(anchoring)).verify_vc_hash_by_tx(
            ISSUER,
            hex_of(leaf),
            [hex_of(sibling)],
            tx,
            contract_address=ATTACKER,
        )

    with pytest.raises(ValueError):
        reg_for(success_receipt(anchoring)).verify_vc_hash_by_tx(
            "not-an-address", hex_of(leaf), [hex_of(sibling)], tx
        )


def test_view_functions_need_contract_address() -> None:
    reg = registry_with(success_receipt(), contract="")
    leaf, sibling, _ = two_leaf_tree()
    req = VerifyRequest(ISSUER, 1, hex_of(leaf), [hex_of(sibling)])
    with pytest.raises(ValueError, match=ERR_NO_CONTRACT):
        reg.verify_vc_hash_on_chain(req)
    with pytest.raises(ValueError, match=ERR_NO_CONTRACT):
        reg.get_tree_root(ISSUER, 1)
    with pytest.raises(ValueError, match=ERR_NO_CONTRACT):
        reg.has_tree(ISSUER, 1)


def test_eth_call_view_functions() -> None:
    leaf, sibling, root = two_leaf_tree()
    rpc = FakeRpc(eth_call_result="0x" + "00" * 31 + "01")
    reg = CredentialRegistry("http://127.0.0.1:1", REGISTRY, rpc=rpc)
    assert reg.verify_vc_hash_on_chain(VerifyRequest(ISSUER, 0, hex_of(leaf), [hex_of(sibling)]))

    rpc.eth_call_result = with_0x(root)
    assert reg.get_tree_root(ISSUER, 0).lower() == hex_of(root).lower()

    rpc.eth_call_result = "0x" + "00" * 31 + "01"
    assert reg.has_tree(ISSUER, 0)


def test_constructor_rejects_zero_address() -> None:
    zero = "0x0000000000000000000000000000000000000000"
    with pytest.raises(ValueError):
        CredentialRegistry("http://127.0.0.1:1", zero, rpc=FakeRpc())
    with pytest.raises(ValueError):
        CredentialRegistry("http://127.0.0.1:1", REGISTRY, [zero], rpc=FakeRpc())


def test_verify_by_tx_request_validate() -> None:
    leaf, sibling, _ = two_leaf_tree()
    ok = VerifyByTxRequest(ISSUER, hex_of(leaf), [hex_of(sibling)], hex_of(mk_leaf(0x03)))
    ok.validate()
    bad = VerifyByTxRequest("nope", hex_of(leaf), [hex_of(sibling)], hex_of(mk_leaf(0x03)))
    with pytest.raises(ValueError):
        bad.validate()
