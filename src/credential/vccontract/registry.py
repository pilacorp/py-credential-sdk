from __future__ import annotations

from typing import Any

from eth_abi import decode, encode
from eth_utils import is_address, keccak, to_checksum_address
from credential.vcanchor.hash import normalize_hash32
from credential.vcanchor.merkle import merge_sorted
from credential.vccontract.model import VerifyByTxRequest, VerifyRequest
from credential.vccontract.rpc import JsonRpc
from didv2.hexutil import hex_to_bytes, with_0x

ERR_NO_CONTRACT = "no contract address configured"
ERR_TX_NOT_FOUND = "transaction not found"
ERR_TX_REVERTED = "transaction reverted"
ERR_UNTRUSTED = "contract address is not in this client's trusted set"
ERR_ROOT_NOT_ANCHORED = "transaction did not anchor a root for this issuer and tree index"

BATCH_ANCHORED = "BatchRootsAnchored"
SINGLE_ANCHORED = "TreeRootAnchored"
ISSUER_ANCHORED = "IssuerRootsAnchored"
LEGACY_BATCH = "BatchTreesUpdated"
LEGACY_SINGLE = "TreeUpdated"

SINGLE_ANCHORED_TOPIC_COUNT = 3
ISSUER_ANCHORED_TOPIC_COUNT = 2
LEGACY_SINGLE_TOPIC_COUNT = 3

ZERO32 = b"\x00" * 32


def _event_topic(signature: str) -> str:
    return with_0x(keccak(text=signature))


EVENT_TOPICS = {
    BATCH_ANCHORED: _event_topic("BatchRootsAnchored(address[],bytes32[])"),
    SINGLE_ANCHORED: _event_topic("TreeRootAnchored(address,bytes32)"),
    ISSUER_ANCHORED: _event_topic("IssuerRootsAnchored(address,bytes32[])"),
    LEGACY_BATCH: _event_topic("BatchTreesUpdated(address[],uint256[],bytes32[])"),
    LEGACY_SINGLE: _event_topic("TreeUpdated(address,uint256,bytes32)"),
}


def _parse_contract_address(value: str) -> str:
    if not is_address(value):
        raise ValueError(f"{value!r} is not a 20-byte hex address")
    addr = to_checksum_address(value)
    if addr.lower() == "0x0000000000000000000000000000000000000000":
        raise ValueError("the zero address names no deployment")
    return addr


def hash_pair(a: bytes, b: bytes) -> bytes:
    return merge_sorted(a, b)


def fold_proof(leaf: bytes, proof: list[bytes]) -> bytes:
    current = leaf
    for sibling in proof:
        current = hash_pair(current, sibling)
    return current


def _topic_address(topic: str) -> str:
    raw = hex_to_bytes(topic)
    if len(raw) != 32:
        return ""
    return to_checksum_address(raw[-20:])


def _decode_leaf_and_proof(leaf: str, proof: list[str]) -> tuple[bytes, list[bytes]]:
    _, leaf_raw = normalize_hash32(leaf)
    proof_raw = [normalize_hash32(p)[1] for p in proof]
    return leaf_raw, proof_raw


def _pair_present(issuers: list[str], roots: list[bytes], issuer: str, root: bytes) -> bool:
    if len(issuers) != len(roots):
        return False
    issuer_l = issuer.lower()
    for idx, item in enumerate(issuers):
        if to_checksum_address(item).lower() == issuer_l and roots[idx] == root:
            return True
    return False


def _contains_root(roots: list[bytes], root: bytes) -> bool:
    return root in roots


def _log_anchors(log: dict[str, Any], issuer: str, root: bytes) -> bool:
    topics = log.get("topics") or []
    if not topics:
        return False
    topic0 = topics[0].lower()
    issuer_l = to_checksum_address(issuer).lower()

    if topic0 == EVENT_TOPICS[SINGLE_ANCHORED].lower():
        if len(topics) != SINGLE_ANCHORED_TOPIC_COUNT:
            return False
        if _topic_address(topics[1]).lower() != issuer_l:
            return False
        return hex_to_bytes(topics[2]) == root

    data = hex_to_bytes(log.get("data") or "0x")

    if topic0 == EVENT_TOPICS[BATCH_ANCHORED].lower():
        try:
            issuers, roots = decode(["address[]", "bytes32[]"], data)
        except Exception:
            return False
        roots_b = [bytes(r) for r in roots]
        issuers_s = [to_checksum_address(a) for a in issuers]
        return _pair_present(issuers_s, roots_b, issuer, root)

    if topic0 == EVENT_TOPICS[ISSUER_ANCHORED].lower():
        if len(topics) != ISSUER_ANCHORED_TOPIC_COUNT:
            return False
        if _topic_address(topics[1]).lower() != issuer_l:
            return False
        try:
            (roots,) = decode(["bytes32[]"], data)
        except Exception:
            return False
        return _contains_root([bytes(r) for r in roots], root)

    if topic0 == EVENT_TOPICS[LEGACY_SINGLE].lower():
        if len(topics) != LEGACY_SINGLE_TOPIC_COUNT:
            return False
        if _topic_address(topics[1]).lower() != issuer_l:
            return False
        try:
            (new_root,) = decode(["bytes32"], data)
        except Exception:
            return False
        return bytes(new_root) == root

    if topic0 == EVENT_TOPICS[LEGACY_BATCH].lower():
        try:
            issuers, _indices, new_roots = decode(["address[]", "uint256[]", "bytes32[]"], data)
        except Exception:
            return False
        roots_b = [bytes(r) for r in new_roots]
        issuers_s = [to_checksum_address(a) for a in issuers]
        return _pair_present(issuers_s, roots_b, issuer, root)

    return False


class CredentialRegistry:
    def __init__(
        self,
        rpc_url: str,
        contract_address: str = "",
        also_trust: list[str] | None = None,
        *,
        rpc: JsonRpc | None = None,
    ) -> None:
        if rpc is None:
            self.rpc = JsonRpc(rpc_url)
        else:
            self.rpc = rpc

        self.address = ""
        trusted: set[str] = set()
        if contract_address:
            self.address = _parse_contract_address(contract_address)
            trusted.add(self.address.lower())
        for i, item in enumerate(also_trust or []):
            try:
                trusted.add(_parse_contract_address(item).lower())
            except ValueError as exc:
                raise ValueError(f"invalid contract address in alsoTrust at index {i}: {exc}") from exc
        self.trusted = trusted

    def trusts(self, address: str) -> bool:
        if not self.trusted:
            return True
        if not address:
            return False
        return to_checksum_address(address).lower() in self.trusted

    def _fetch_receipt(self, tx_hash: str) -> dict:
        rec = self.rpc.call("eth_getTransactionReceipt", [tx_hash])
        if rec is None:
            raise ValueError(ERR_TX_NOT_FOUND)
        if not isinstance(rec, dict):
            raise ValueError(f"receipt source returned no receipt and no error for tx {tx_hash}")
        return rec

    def transaction_receipt(self, tx_hash: str) -> dict:
        rec = self._fetch_receipt(tx_hash)
        if rec.get("status") in ("0x0", "0", 0):
            raise ValueError(ERR_TX_REVERTED)
        return rec

    def is_root_anchored(self, tx_hash: str, issuer_address: str, root: str | bytes) -> bool:
        root_raw = root if isinstance(root, (bytes, bytearray)) else normalize_hash32(root)[1]
        if root_raw == ZERO32:
            return False
        rec = self._fetch_receipt(tx_hash)
        if rec.get("status") in ("0x0", "0", 0):
            raise ValueError(ERR_TX_REVERTED)
        return self._root_in_receipt(rec, issuer_address, root_raw, emitter=None)

    def is_root_anchored_at_contract(
        self,
        tx_hash: str,
        issuer_address: str,
        root: str | bytes,
        contract_address: str,
    ) -> bool:
        if not self.trusts(contract_address):
            raise ValueError(f"{ERR_UNTRUSTED}: {to_checksum_address(contract_address)}")
        root_raw = root if isinstance(root, (bytes, bytearray)) else normalize_hash32(root)[1]
        if root_raw == ZERO32:
            return False
        rec = self._fetch_receipt(tx_hash)
        if rec.get("status") in ("0x0", "0", 0):
            raise ValueError(ERR_TX_REVERTED)
        emitter = to_checksum_address(contract_address)
        return self._root_in_receipt(rec, issuer_address, root_raw, emitter=emitter)

    def _root_in_receipt(
        self,
        rec: dict,
        issuer_address: str,
        root_raw: bytes,
        *,
        emitter: str | None,
    ) -> bool:
        for log in rec.get("logs") or []:
            if log is None:
                continue
            addr = log.get("address") or ""
            if emitter is not None:
                if to_checksum_address(addr).lower() != emitter.lower():
                    continue
            elif not self.trusts(addr):
                continue
            if _log_anchors(log, issuer_address, root_raw):
                return True
        return False

    def get_anchored_root(self, tx_hash: str, issuer_address: str, tree_index: int) -> str:
        rec = self._fetch_receipt(tx_hash)
        if rec.get("status") in ("0x0", "0", 0):
            raise ValueError(ERR_TX_REVERTED)
        event_id = EVENT_TOPICS[LEGACY_BATCH].lower()
        issuer_l = to_checksum_address(issuer_address).lower()
        for log in rec.get("logs") or []:
            if log is None:
                continue
            if not self.trusts(log.get("address") or ""):
                continue
            topics = log.get("topics") or []
            if not topics or topics[0].lower() != event_id:
                continue
            data = hex_to_bytes(log.get("data") or "0x")
            try:
                issuers, indices, new_roots = decode(["address[]", "uint256[]", "bytes32[]"], data)
            except Exception:
                continue
            if len(issuers) != len(indices) or len(issuers) != len(new_roots):
                continue
            for i, iss in enumerate(issuers):
                if to_checksum_address(iss).lower() != issuer_l:
                    continue
                if int(indices[i]) == tree_index:
                    return with_0x(bytes(new_roots[i]))
        raise ValueError(ERR_ROOT_NOT_ANCHORED)

    def verify_vc_hash_on_chain(self, req: VerifyRequest) -> bool:
        if not self.address:
            raise ValueError(
                f"{ERR_NO_CONTRACT}: verifyVC is a call on the contract that keeps roots in storage, "
                "so its address must be passed to NewCredentialRegistry"
            )
        req.validate()
        leaf_raw, proof_raw = _decode_leaf_and_proof(req.leaf, req.proof)
        data = self._encode_call(
            "verifyVC(address,uint256,bytes32,bytes32[])",
            [
                to_checksum_address(req.issuer_address),
                req.tree_index,
                leaf_raw,
                proof_raw,
            ],
        )
        out = self.eth_call(self.address, data)
        return self._decode_bool(out)

    def get_tree_root(self, issuer_address: str, tree_index: int) -> str:
        if not self.address:
            raise ValueError(
                f"{ERR_NO_CONTRACT}: getTreeRoot is a call on the contract that keeps roots in storage, "
                "so its address must be passed to NewCredentialRegistry"
            )
        if not is_address(issuer_address):
            raise ValueError(f"invalid issuer address: {issuer_address!r}")
        data = self._encode_call(
            "getTreeRoot(address,uint256)",
            [to_checksum_address(issuer_address), tree_index],
        )
        out = self.eth_call(self.address, data)
        raw = hex_to_bytes(out)
        if len(raw) != 32:
            raise ValueError("getTreeRoot returned unexpected data")
        return with_0x(raw)

    def has_tree(self, issuer_address: str, tree_index: int) -> bool:
        if not self.address:
            raise ValueError(
                f"{ERR_NO_CONTRACT}: treeExists is a call on the contract that keeps roots in storage, "
                "so its address must be passed to NewCredentialRegistry"
            )
        if not is_address(issuer_address):
            raise ValueError(f"invalid issuer address: {issuer_address!r}")
        data = self._encode_call(
            "treeExists(address,uint256)",
            [to_checksum_address(issuer_address), tree_index],
        )
        out = self.eth_call(self.address, data)
        return self._decode_bool(out)

    def verify_vc_hash_by_tx(
        self,
        issuer_address: str,
        leaf: str,
        proof: list[str],
        tx_hash: str,
        expected_root: str | None = None,
        *,
        contract_address: str = "",
    ) -> bool:
        req = VerifyByTxRequest(
            issuer_address=issuer_address,
            leaf=leaf,
            proof=proof,
            tx_hash=tx_hash,
            contract_address=contract_address,
        )
        try:
            req.validate()
        except ValueError:
            raise
        leaf_raw, proof_raw = _decode_leaf_and_proof(req.leaf, req.proof)
        folded = fold_proof(leaf_raw, proof_raw)
        if expected_root and normalize_hash32(expected_root)[1] != folded:
            return False
        try:
            if req.contract_address:
                return self.is_root_anchored_at_contract(
                    req.tx_hash,
                    req.issuer_address,
                    folded,
                    req.contract_address,
                )
            return self.is_root_anchored(req.tx_hash, req.issuer_address, folded)
        except ValueError as exc:
            if str(exc) == ERR_TX_REVERTED:
                return False
            raise

    def verify_vc_hash_by_tx_request(self, req: VerifyByTxRequest) -> bool:
        req.validate()
        leaf_raw, proof_raw = _decode_leaf_and_proof(req.leaf, req.proof)
        folded = fold_proof(leaf_raw, proof_raw)
        try:
            if req.contract_address:
                return self.is_root_anchored_at_contract(
                    req.tx_hash,
                    req.issuer_address,
                    folded,
                    req.contract_address,
                )
            return self.is_root_anchored(req.tx_hash, req.issuer_address, folded)
        except ValueError as exc:
            if str(exc) == ERR_TX_REVERTED:
                return False
            raise

    def eth_call(self, to: str, data: str) -> str:
        if not to:
            raise ValueError(ERR_NO_CONTRACT)
        result = self.rpc.call("eth_call", [{"to": to, "data": data}, "latest"])
        if result is None:
            raise ValueError("eth_call returned no data")
        return result

    def _encode_call(self, signature: str, args: list[Any]) -> str:
        selector = keccak(text=signature)[:4]
        types: list[str] = []
        if signature.startswith("verifyVC"):
            types = ["address", "uint256", "bytes32", "bytes32[]"]
        elif signature.startswith("getTreeRoot") or signature.startswith("treeExists"):
            types = ["address", "uint256"]
        else:
            raise ValueError(f"unsupported call signature: {signature}")
        encoded = encode(types, args)
        return with_0x(selector + encoded)

    @staticmethod
    def _decode_bool(data: str) -> bool:
        raw = hex_to_bytes(data)
        if not raw:
            raise ValueError("call returned no data")
        return int.from_bytes(raw[-32:], "big") != 0
