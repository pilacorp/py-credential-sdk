from eth_abi import encode
from eth_utils import keccak, to_checksum_address

from credential.vccontract.rpc import JsonRpc
from didv2.config import DEFAULT_DID_SMC_ADDRESS, DEFAULT_RPC
from didv2.didcontract.contract import has_role_selector, subtree_writer_role
from didv2.hexutil import address_bytes, hex_to_bytes, is_hex_address, with_0x


class DIDChain:
    def __init__(self, rpc_url: str = DEFAULT_RPC, contract: str = DEFAULT_DID_SMC_ADDRESS) -> None:
        self.rpc = JsonRpc(rpc_url)
        self.contract = contract

    def chain_id(self) -> int:
        return int(self.rpc.call("eth_chainId", []), 16)

    def has_writer_role(self, account: str) -> bool:
        data = has_role_selector()[2:] + encode(
            ["bytes32", "address"],
            [hex_to_bytes(subtree_writer_role()), to_checksum_address(account)],
        ).hex()
        result = self.rpc.call("eth_call", [{"to": self.contract, "data": with_0x(bytes.fromhex(data))}, "latest"])
        return int(result, 16) != 0

    def get_capability_epoch(self, signer_addr: str) -> int:
        if not signer_addr:
            raise ValueError("signer address is required")
        if not is_hex_address(signer_addr):
            raise ValueError(f"invalid address: {signer_addr}")
        data = keccak(text="getCapabilityEpoch(address)")[:4] + encode(
            ["address"], ["0x" + address_bytes(signer_addr).hex()]
        )
        out = self.rpc.call("eth_call", [{"to": self.contract, "data": with_0x(data)}, "latest"])
        raw = hex_to_bytes(out or "0x")
        if not raw:
            raise ValueError("contract returned no data")
        return int.from_bytes(raw[-32:], "big")

    def get_nonce(self, address: str) -> int:
        if not is_hex_address(address):
            raise ValueError(f"invalid address: {address}")
        return int(self.rpc.call("eth_getTransactionCount", ["0x" + address_bytes(address).hex(), "pending"]), 16)
