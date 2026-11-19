# did

Legacy `did:nda` generation (registry contract).

- **Entry points**: `did.did_generator.DIDGenerator`: `generate_did(CreateDID(type=DIDType.PEOPLE))`, `regenerate_did_tx(priv_key, did_metadata)`.
- `didDocumentMetadata.type` and transactions carry the enum value (`item`, `people`, `location`, `activity`).
- `KeyPair` / `Secret` do not print private keys in `repr`.
- **Errors**: `ValueError`. **Network**: none (`rpc_url` is stored, never called). For new work use `didv2`.
