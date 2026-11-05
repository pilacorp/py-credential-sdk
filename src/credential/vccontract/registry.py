from __future__ import annotations

from typing import Any

from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address
from credential.vcanchor.merkle import merge_sorted
from credential.vccontract.model import VerifyByTxRequest, VerifyRequest, hex_to_bytes32
from credential.vccontract.rpc import JsonRpc
from didv2.hexutil import hex_to_bytes, is_hex_address, with_0x

ERR_NO_CONTRACT = "no contract address configured"
ERR_TX_NOT_FOUND = "transaction not found"
ERR_TX_REVERTED = "transaction reverted"
ERR_UNTRUSTED = "contract address is not in this client's trusted set"
ERR_ROOT_NOT_ANCHORED = "transaction did not anchor a root for this issuer and tree index"

class ErrNoContractAddress(ValueError):
    pass


class ErrTxNotFound(ValueError):
    pass


class ErrTxReverted(ValueError):
    pass


class ErrRootNotAnchored(ValueError):
    pass


class ErrUntrustedContract(ValueError):
    pass


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
    if not is_hex_address(value):
        raise ValueError(f"{value!r} is not a 20-byte hex address")
    addr = to_checksum_address(value)
    if addr.lower() == "0x0000000000000000000000000000000000000000":
        raise ValueError("the zero address names no deployment")
    return addr


def _require_success(rec: dict) -> None:
    """go-ethereum: anything but status 1 (including a missing status) is a failed transaction."""
    status = rec.get("status")
    try:
        ok = (int(status, 16) if isinstance(status, str) else int(status)) == 1
    except (TypeError, ValueError):
        ok = False
    if not ok:
        raise ErrTxReverted(ERR_TX_REVERTED)


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
    try:
        leaf_raw = hex_to_bytes32(leaf)
    except ValueError as exc:
        raise ValueError(f"invalid leaf: {exc}") from exc
    proof_raw = []
    for i, p in enumerate(proof):
        try:
            proof_raw.append(hex_to_bytes32(p))
        except ValueError as exc:
            raise ValueError(f"proof element {i}: {exc}") from exc
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
            raise ErrTxNotFound(ERR_TX_NOT_FOUND)
        if not isinstance(rec, dict):
            raise ValueError(f"receipt source returned no receipt and no error for tx {tx_hash}")
        return rec

    def transaction_receipt(self, tx_hash: str) -> dict:
        rec = self._fetch_receipt(tx_hash)
        _require_success(rec)
        return rec

    def is_root_anchored(self, tx_hash: str, issuer_address: str, root: str | bytes) -> bool:
        root_raw = bytes(root) if isinstance(root, (bytes, bytearray)) else hex_to_bytes32(root)
        if root_raw == ZERO32:
            return False
        rec = self._fetch_receipt(tx_hash)
        _require_success(rec)
        return self._root_in_receipt(rec, issuer_address, root_raw, emitter=None)

    def is_root_anchored_at_contract(
        self,
        tx_hash: str,
        issuer_address: str,
        root: str | bytes,
        contract_address: str,
    ) -> bool:
        if not self.trusts(contract_address):
            raise ErrUntrustedContract(f"{ERR_UNTRUSTED}: {to_checksum_address(contract_address)}")
        root_raw = bytes(root) if isinstance(root, (bytes, bytearray)) else hex_to_bytes32(root)
        if root_raw == ZERO32:
            return False
        rec = self._fetch_receipt(tx_hash)
        _require_success(rec)
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
        _require_success(rec)
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
        raise ErrRootNotAnchored(ERR_ROOT_NOT_ANCHORED)

    def verify_vc_hash_on_chain(self, req: VerifyRequest) -> bool:
        if not self.address:
            raise ErrNoContractAddress(
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
            raise ErrNoContractAddress(
                f"{ERR_NO_CONTRACT}: getTreeRoot is a call on the contract that keeps roots in storage, "
                "so its address must be passed to NewCredentialRegistry"
            )
        if not is_hex_address(issuer_address):
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
            raise ErrNoContractAddress(
                f"{ERR_NO_CONTRACT}: treeExists is a call on the contract that keeps roots in storage, "
                "so its address must be passed to NewCredentialRegistry"
            )
        if not is_hex_address(issuer_address):
            raise ValueError(f"invalid issuer address: {issuer_address!r}")
        data = self._encode_call(
            "treeExists(address,uint256)",
            [to_checksum_address(issuer_address), tree_index],
        )
        out = self.eth_call(self.address, data)
        return self._decode_bool(out)

    def verify_vc_hash_by_tx(
        self,
        issuer_address: str | VerifyByTxRequest,
        leaf: str = "",
        proof: list[str] | None = None,
        tx_hash: str = "",
        expected_root: str | None = None,
        *,
        contract_address: str = "",
    ) -> bool:
        """True when leaf+proof fold to a root that ``tx_hash`` anchored for the issuer.

        False with no error = the chain was asked and does not attest the leaf (a reverted tx
        included); an exception = nothing was established (bad input, RPC failure, ErrTxNotFound)."""
        if isinstance(issuer_address, VerifyByTxRequest):
            return self.verify_vc_hash_by_tx_request(issuer_address, expected_root=expected_root)
        return self.verify_vc_hash_by_tx_request(
            VerifyByTxRequest(
                issuer_address=issuer_address,
                leaf=leaf,
                proof=list(proof or []),
                tx_hash=tx_hash,
                contract_address=contract_address,
            ),
            expected_root=expected_root,
        )

    def verify_vc_hash_by_tx_request(self, req: VerifyByTxRequest, *, expected_root: str | None = None) -> bool:
        req.validate()
        leaf_raw, proof_raw = _decode_leaf_and_proof(req.leaf, req.proof)
        try:
            hex_to_bytes32(req.tx_hash)
        except ValueError as exc:
            raise ValueError(f"invalid tx hash: {exc}") from exc
        folded = fold_proof(leaf_raw, proof_raw)
        if expected_root and hex_to_bytes32(expected_root) != folded:
            return False
        try:
            if req.contract_address:
                return self.is_root_anchored_at_contract(
                    req.tx_hash, req.issuer_address, folded, req.contract_address
                )
            return self.is_root_anchored(req.tx_hash, req.issuer_address, folded)
        except ErrTxReverted:
            # a reverted tx ran and wrote nothing: a verdict ("does not attest"), not a failure to check
            return False

    def eth_call(self, to: str, data: str) -> str:
        if not to:
            raise ErrNoContractAddress(ERR_NO_CONTRACT)
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
        if len(raw) < 32:
            raise ValueError("call returned no data")
        word = int.from_bytes(raw[:32], "big")
        if word > 1:  # go-ethereum's ABI decoder refuses a bool word other than 0/1
            raise ValueError("abi: improperly encoded boolean value")
        return word == 1
