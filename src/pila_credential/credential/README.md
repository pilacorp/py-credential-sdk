# credential

W3C Verifiable Credentials / Presentations.

- **Entry points** (`credential.vc.credential`): `parse_credential(raw, *opts)` (auto-detects JSON-LD, JWT, JOSE/SD-JWT), `new_jwt_credential`, `new_jose_credential`, `JSONCredential`; presentations in `credential.vp`.
- **Options**: `with_verify_proof`, `with_resolver`, `with_check_expiration`, `with_leeway`, `with_check_revocation`, `with_status_client`, `with_schema_validation` + `with_schema_loader`, `with_base_url`, `with_verification_method_key`, `with_sd_*`.
- **Errors**: `ValueError` with a descriptive message (`credential verification failed: ...`).
- **Order of checks**: schema, proof, revocation, expiration. The status list is fetched only after the proof holds.
- **Status lists** (`common/credential_status`): Bitstring Status List, bit 0 = left-most bit; the list credential's proof is verified (the list's issuer may differ from the credential's; trusting it is the caller's call) and it must be ≥ 16 KB.
- **Network**: DID resolver (`with_base_url`), status list credential, unknown `@context` (https only, size-limited; bundled W3C contexts never fetch). Schemas are never fetched: pass a loader.
- **Limits**: JSON-LD canonicalization refuses documents with too many interchangeable blank nodes (`ErrBlankNodeWork`).
- Example: [`examples/jsonld_vc.py`](../../../examples/jsonld_vc.py).
