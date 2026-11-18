# didv2

DID v2 documents, verification-method operations, issuer capability signatures and Sub-DIDs.

- **Entry points**: `DIDGenerator(cfg=None, chain=None, **overrides)` with `generate_did`, `generate_did_tx`, `generate_issuer_signature`, ...; `did.verification_method_ops` (`revoke_verification_method`, rotate, ...); `subdid`.
- **Overrides**: any `DIDConfig` field per call, e.g. `gen.generate_did(1, nonce=3, enable_p256_vm=True, add_vms=[...])`. `did_smc_addr` applies to both the issuer signature and the transaction.
- **Revocation**: a `superseded` method can still be revoked as `keyCompromise` (reason raised, first revoked time kept). `revoked` is stored as an RFC 3339 string.
- **Errors**: `ValueError`; Sub-DID verification has `ErrChainUnavailable` (parent of `ErrChainMismatch`), `ErrNotAnchored`, ...
- **Network**: `didv2.rpc.DIDChain` / `jsonrpc.JsonRpc` (no redirects, 30 s deadline, 16 MiB cap). Offline by default.
- Example: [`examples/didv2_create.py`](../../../examples/didv2_create.py).
