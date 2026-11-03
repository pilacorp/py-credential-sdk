from __future__ import annotations

from dataclasses import dataclass

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from did.blockchain.helper import ATTRIBUTE_NAME, parse_private_key, prepare_attribute_inputs
from didv2.hexutil import with_0x

SET_ATTRIBUTE_SELECTOR = keccak(text="setAttribute(address,bytes32,bytes,uint256)")[:4]


@dataclass
class SubmitDIDTX:
    tx_hex: str
    tx_hash: str


class EthereumDIDRegistry:
    def __init__(self, rpc_url: str, did_address: str, chain_id: int) -> None:
        if not did_address:
            raise ValueError("invalid configuration: RPC URL or DID address missing")
        self.rpc_url = rpc_url
        self.did_address = to_checksum_address(did_address)
        self.chain_id = chain_id

    def generate_set_attribute_tx(
        self,
        priv_key: str,
        address: str,
        value: str,
        *,
        nonce: int = 0,
        gas: int = 80_000,
        gas_price: int = 0,
    ) -> SubmitDIDTX:
        private_key = parse_private_key(priv_key)
        did_address, name_bytes, value_bytes, validity = prepare_attribute_inputs(
            address, ATTRIBUTE_NAME, value
        )
        data = SET_ATTRIBUTE_SELECTOR + encode(
            ["address", "bytes32", "bytes", "uint256"],
            [did_address, name_bytes, value_bytes, validity],
        )
        signed = Account.sign_transaction(
            {
                "nonce": nonce,
                "gasPrice": gas_price,
                "gas": gas,
                "to": self.did_address,
                "value": 0,
                "data": data,
                "chainId": self.chain_id,
            },
            private_key.to_bytes(),
        )
        raw = signed.raw_transaction.hex()
        if raw.startswith("0x"):
            raw = raw[2:]
        return SubmitDIDTX(tx_hex=raw, tx_hash=with_0x(signed.hash))
