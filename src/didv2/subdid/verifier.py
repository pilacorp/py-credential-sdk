from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Protocol

from didv2.didcontract.subtree_event import Receipt, WriterAnchor, decode_writer_anchors, has_role, subtree_writer_role
from didv2.subdid.document import check_did, did_address, did_prefix, validate_sub_did
from didv2.subdid.merkle import revoked_leaf, verify_proof
from didv2.subdid.proof import ProofResponse
from didv2.subdid.signature import verify_root_consent

STATUS_ACTIVATED = "activated"
STATUS_DEACTIVATED = "deactivated"

HASH32 = re.compile(r"^0x[0-9a-f]{64}$")


class Reason(str, Enum):
    RESPONSE_MISMATCH = "response_mismatch"
    ID_MISMATCH = "id_mismatch"
    CONSENT_INVALID = "consent_invalid"
    NO_ANCHOR = "no_anchor"
    ROOT_MISMATCH = "root_mismatch"
    WRITER_REVOKED = "writer_revoked"
    PROOF_MISMATCH = "proof_mismatch"


class Status(IntEnum):
    INVALID = 0
    ACTIVE = 1
    REVOKED = 2


class ErrNotAnchored(Exception):
    pass


class ErrDocumentRequired(Exception):
    pass


class ErrChainUnavailable(Exception):
    pass


class ErrChainMismatch(Exception):
    pass


class ChainClient(Protocol):
    def chain_id(self) -> int: ...

    def transaction_receipt(self, tx_hash: str) -> Receipt | None: ...

    def call_contract(self, to: str, data: bytes) -> bytes: ...


@dataclass
class Chain:
    code: str
    evm_chain_id: int
    did_registry: str
    client: ChainClient


@dataclass
class VerifyRequest:
    sub_did: str
    document: dict[str, Any] | None
    proof: ProofResponse | None
    chain: str


@dataclass
class Result:
    status: Status
    reason: Reason | None = None
    chain: str = ""
    tx_hash: str = ""


class Verifier:
    def __init__(self, chains: list[Chain]) -> None:
        if not chains:
            raise ValueError("subdid: a verifier needs at least one chain")
        by_code: dict[str, Chain] = {}
        for c in chains:
            if not c.code:
                raise ValueError("subdid: chain code is empty")
            if c.evm_chain_id <= 0:
                raise ValueError(f"subdid: chain {c.code}: EVM chain id must be positive")
            if not c.did_registry or c.did_registry == "0x" + "0" * 40:
                raise ValueError(f"subdid: chain {c.code}: DID registry address is zero")
            if c.client is None:
                raise ValueError(f"subdid: chain {c.code}: client is nil")
            if c.code in by_code:
                raise ValueError(f"subdid: chain {c.code} is configured twice")
            by_code[c.code] = c
        self._chains = by_code

    def verify_sub_did(self, req: VerifyRequest) -> Result:
        if req.proof is None:
            raise ValueError("subdid: proof is nil")
        check_did(req.sub_did)
        c = self._chains.get(req.chain)
        if c is None:
            raise ValueError(f'subdid: chain "{req.chain}" is not configured')

        proof = req.proof
        if not _consistent_proof(proof, req.sub_did):
            return Result(Status.INVALID, Reason.RESPONSE_MISMATCH, c.code)

        try:
            entry = _chain_entry(proof, c.code)
        except ErrNotAnchored:
            raise
        anchor = _parse_chain_proof(entry)
        if anchor is None:
            return Result(Status.INVALID, Reason.RESPONSE_MISMATCH, c.code)

        verdict = Status.ACTIVE
        if entry["status"] == STATUS_ACTIVATED:
            if req.document is None:
                raise ErrDocumentRequired()
            if req.document.get("id") != req.sub_did:
                return Result(Status.INVALID, Reason.ID_MISMATCH, c.code)
            try:
                validate_sub_did(req.document, proof["root_did"])
            except ValueError:
                return Result(Status.INVALID, Reason.ID_MISMATCH, c.code)
            try:
                verify_root_consent(req.document, proof["root_did"])
            except ValueError:
                return Result(Status.INVALID, Reason.CONSENT_INVALID, c.code)
            from didv2.subdid.document import doc_hash

            leaf = doc_hash(req.document)
        elif entry["status"] == STATUS_DEACTIVATED:
            leaf = revoked_leaf(did_address(req.sub_did))
            verdict = Status.REVOKED
        else:
            return Result(Status.INVALID, Reason.RESPONSE_MISMATCH, c.code)

        reason, err = _check_on_chain(c, proof, anchor, leaf)
        if err is not None:
            raise err
        if reason is not None:
            return Result(Status.INVALID, reason, c.code)

        return Result(verdict, None, c.code, anchor["tx_hash"])


def _consistent_proof(proof: ProofResponse, sub_did: str) -> bool:
    if proof["did"] != sub_did:
        return False
    try:
        check_did(proof["root_did"])
    except ValueError:
        return False
    if did_prefix(proof["root_did"]) != did_prefix(sub_did):
        return False
    if proof["root_did"] == sub_did:
        return False
    tree_index = proof.get("tree_index") or ""
    if HASH32.match(tree_index):
        return True
    return tree_index == "" and not proof.get("chains")


def _chain_entry(proof: ProofResponse, code: str) -> dict[str, Any]:
    for entry in proof.get("chains") or []:
        if entry["chain"] == code:
            return entry
    raise ErrNotAnchored(f"subdid: the chain has not anchored this Sub-DID yet: chain {code}")


def _parse_hash32(s: str) -> str | None:
    if not HASH32.match(s):
        return None
    return s


def _parse_chain_proof(entry: dict[str, Any]) -> dict[str, Any] | None:
    tx_hash = _parse_hash32(entry.get("tx_hash") or "")
    root = _parse_hash32(entry.get("root") or "")
    if not tx_hash or not root:
        return None
    path: list[str] = []
    for s in entry.get("path") or []:
        h = _parse_hash32(s)
        if not h:
            return None
        path.append(h)
    return {"tx_hash": tx_hash, "root": root, "path": path}


def _check_on_chain(
    c: Chain, proof: ProofResponse, anchor: dict[str, Any], leaf: str
) -> tuple[Reason | None, Exception | None]:
    if not verify_proof(leaf, anchor["path"], anchor["root"]):
        return Reason.PROOF_MISMATCH, None

    try:
        chain_id = c.client.chain_id()
    except Exception as exc:
        return None, ErrChainUnavailable(f"subdid: the chain could not be read: chain {c.code}: {exc}")

    if chain_id != c.evm_chain_id:
        return None, ErrChainMismatch(
            f"subdid: node reports another chain id: chain {c.code}: node reports {chain_id}, want {c.evm_chain_id}"
        )

    try:
        receipt = c.client.transaction_receipt(anchor["tx_hash"])
    except Exception as exc:
        return None, ErrChainUnavailable(
            f"subdid: the chain could not be read: chain {c.code}: receipt {anchor['tx_hash']}: {exc}"
        )

    if receipt is None:
        return None, ErrChainUnavailable(
            f"subdid: the chain could not be read: chain {c.code}: receipt {anchor['tx_hash']} is empty"
        )
    if receipt.status != 1:
        return Reason.NO_ANCHOR, None

    written = _last_writer_anchor(receipt, c.did_registry, proof)
    if written is None:
        return Reason.NO_ANCHOR, None
    if written.root != bytes.fromhex(anchor["root"][2:]):
        return Reason.ROOT_MISMATCH, None

    class _Caller:
        def call_contract(self, to: str, data: bytes) -> bytes:
            return c.client.call_contract(to, data)

    try:
        is_writer = has_role(_Caller(), c.did_registry, subtree_writer_role(), written.writer)
    except Exception as exc:
        return None, ErrChainUnavailable(f"subdid: the chain could not be read: chain {c.code}: {exc}")

    if not is_writer:
        return Reason.WRITER_REVOKED, None
    return None, None


def _last_writer_anchor(receipt: Receipt, registry: str, proof: ProofResponse) -> WriterAnchor | None:
    try:
        anchors = decode_writer_anchors(receipt, registry)
    except Exception:
        return None
    from eth_utils import to_checksum_address

    root_address = to_checksum_address(did_address(proof["root_did"]))
    tree_index = int(proof["tree_index"], 0)
    for anchor in reversed(anchors):
        if anchor.did.lower() == root_address.lower() and anchor.tree_index == tree_index:
            return anchor
    return None
