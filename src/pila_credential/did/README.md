# did

Legacy `did:nda` generation (registry contract).

- **Entry points**: `did.did_generator.DIDGenerator`: `generate_did(CreateDID(type=DIDType.PEOPLE))`, `regenerate_did_tx(priv_key, did_metadata)`.
- `didDocumentMetadata.type` and transactions carry the enum value (`people`, `issuer`, ...).
- `KeyPair` / `Secret` do not print private keys in `repr`.
- **Errors**: `ValueError`. **Network**: only when you submit via the configured RPC. For new work use `didv2`.
