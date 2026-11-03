from eth_abi import encode
from eth_utils import to_checksum_address

from credential.vccontract.rpc import JsonRpc
from didv2.config import DEFAULT_DID_SMC_ADDRESS, DEFAULT_RPC
from didv2.didcontract.contract import has_role_selector, subtree_writer_role
from didv2.hexutil import hex_to_bytes, with_0x


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
