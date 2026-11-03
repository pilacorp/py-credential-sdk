from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from eth_abi import decode, encode
from eth_utils import to_checksum_address

from didv2.didcontract.contract import HAS_ROLE_SELECTOR, SUBTREE_WRITER_ROLE, writer_anchor_topic0

WRITER_ANCHOR_EVENT = "BatchSubtreesAnchoredByWriter"
HAS_ROLE_METHOD = "hasRole"


@dataclass
class WriterAnchor:
    writer: str
    did: str
    tree_index: int
    root: bytes


class ContractCaller(Protocol):
    def call_contract(self, to: str, data: bytes) -> bytes: ...


@dataclass
class ReceiptLog:
    address: str
    topics: list[str]
    data: bytes
    index: int = 0


@dataclass
class Receipt:
    status: int
    logs: list[ReceiptLog]


def decode_writer_anchors(receipt: Receipt | None, registry: str) -> list[WriterAnchor]:
    if receipt is None:
        raise ValueError("didcontract: receipt is nil")
    if not registry or registry == "0x" + "0" * 40:
        raise ValueError("didcontract: registry address is zero")

    registry = to_checksum_address(registry)
    topic0 = writer_anchor_topic0().lower()
    anchors: list[WriterAnchor] = []
    for log in receipt.logs or []:
        if log is None:
            continue
        if to_checksum_address(log.address) != registry:
            continue
        if not log.topics or log.topics[0].lower() != topic0:
            continue
        decoded = _decode_writer_log(log)
        anchors.extend(decoded)
    return anchors


def _decode_writer_log(log: ReceiptLog) -> list[WriterAnchor]:
    if len(log.topics) != 2:
        raise ValueError(f"{WRITER_ANCHOR_EVENT} has {len(log.topics)} topics, want 2")

    writer = to_checksum_address("0x" + log.topics[1][-40:])
    dids, tree_indexes, roots = decode(["address[]", "uint256[]", "bytes32[]"], log.data)
    if not (len(dids) == len(tree_indexes) == len(roots)):
        raise ValueError(
            f"{WRITER_ANCHOR_EVENT} arrays have lengths {len(dids)}, {len(tree_indexes)} and {len(roots)}"
        )

    out: list[WriterAnchor] = []
    for i, did in enumerate(dids):
        out.append(
            WriterAnchor(
                writer=to_checksum_address(writer),
                did=to_checksum_address(did),
                tree_index=int(tree_indexes[i]),
                root=roots[i],
            )
        )
    return out


def has_role(caller: ContractCaller, registry: str, role: bytes, account: str) -> bool:
    data = HAS_ROLE_SELECTOR + encode(["bytes32", "address"], [role, to_checksum_address(account)])
    out = caller.call_contract(to_checksum_address(registry), data)
    if len(out) != 32:
        raise ValueError(f"didcontract: {HAS_ROLE_METHOD} returned {len(out)} bytes, want 32")
    (is_member,) = decode(["bool"], out)
    return bool(is_member)


def subtree_writer_role() -> bytes:
    return SUBTREE_WRITER_ROLE


def pack_writer_log_data(dids: list[str], tree_indexes: list[int], roots: list[bytes]) -> bytes:
    return encode(
        ["address[]", "uint256[]", "bytes32[]"],
        [[to_checksum_address(d) for d in dids], tree_indexes, roots],
    )


def writer_log_topic0() -> str:
    return writer_anchor_topic0()


def writer_log_topic1(writer: str) -> str:
    addr = to_checksum_address(writer)[2:].lower()
    return "0x" + ("0" * 24) + addr
