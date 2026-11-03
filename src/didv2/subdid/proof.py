from __future__ import annotations

from typing import Any, TypedDict


class ChainProof(TypedDict):
    chain: str
    tx_hash: str
    root: str
    path: list[str]
    status: str


class ProofResponse(TypedDict):
    did: str
    root_did: str
    tree_index: str
    chains: list[ChainProof]


def parse_proof_response(raw: dict[str, Any]) -> ProofResponse:
    return {
        "did": raw["did"],
        "root_did": raw["root_did"],
        "tree_index": str(raw["tree_index"]),
        "chains": [
            {
                "chain": c["chain"],
                "tx_hash": c["tx_hash"],
                "root": c["root"],
                "path": list(c.get("path") or []),
                "status": c["status"],
            }
            for c in raw.get("chains") or []
        ],
    }
