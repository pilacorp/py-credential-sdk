from __future__ import annotations

from dataclasses import dataclass

DEFAULT_RPC = "https://rpc-testnet.pila.vn"
DEFAULT_CHAIN_ID = 6789
DEFAULT_DID_ADDRESS = "0x0000000000000000000000000000000000018888"
DEFAULT_METHOD = "did:nda"


@dataclass
class Config:
    rpc: str = DEFAULT_RPC
    chain_id: int = DEFAULT_CHAIN_ID
    did_address: str = DEFAULT_DID_ADDRESS
    method: str = DEFAULT_METHOD


def new_config(cfg: Config | None = None) -> Config:
    base = Config()
    if cfg is None:
        return base
    if cfg.rpc:
        base.rpc = cfg.rpc
    if cfg.chain_id:
        base.chain_id = cfg.chain_id
    if cfg.did_address:
        base.did_address = cfg.did_address
    if cfg.method:
        base.method = cfg.method
    return base
