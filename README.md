# py-credential-sdk

Python port of [go-credential-sdk](https://github.com/pilacorp/go-credential-sdk). Install name `pila-credential-sdk`, import name `pila_credential`. Python ≥ 3.11.

```bash
pip install -e ".[dev]"     # from a checkout
pytest
```

## Packages

| Package | What it is | Go counterpart |
|---|---|---|
| [`pila_credential.credential`](src/pila_credential/credential/README.md) | W3C VC / VP: JSON-LD (Data Integrity), JWT, JOSE / SD-JWT; status lists, `vcanchor`, `vccontract` | `credential` |
| [`pila_credential.digitalcredential`](src/pila_credential/digitalcredential/README.md) | IETF SD-JWT VC: issue, present, verify, Type Metadata, Token Status List | `digitalcredential` |
| [`pila_credential.did`](src/pila_credential/did/README.md) | legacy DID (`did:nda`, ethr-style registry) | `did` |
| [`pila_credential.didv2`](src/pila_credential/didv2/README.md) | DID v2: documents, verification-method ops, issuer capability, Sub-DID | `didv2` |
| [`pila_credential.didcomm`](src/pila_credential/didcomm/README.md) | DIDComm JWE encrypt / decrypt | `didcomm` |
| [`pila_credential.jose`](src/pila_credential/jose/README.md) | JWK, JWS, JWT, SD-JWT primitives | `jose` |

Go parts with no Python package: none known; check against the Go tree when it changes.

## Minimal issue / verify

`examples/` holds runnable scripts (CI runs them): [`jsonld_vc.py`](examples/jsonld_vc.py) (issue + verify a JSON-LD VC), [`sdjwt_vc.py`](examples/sdjwt_vc.py) (issue, present, verify an SD-JWT VC), [`didv2_create.py`](examples/didv2_create.py) (create a DID).

## Differences from Go

- `snake_case` names; options are `with_*` functions passed positionally.
- Errors are raised exceptions, not returned values. `digitalcredential` raises `DigitalCredentialError` with a `.code`.
- `didv2.DIDGenerator` takes `**overrides` of `DIDConfig` fields per call (`did_smc_addr`, `chain_id`, `nonce`, ...). Overrides apply to both the issuer signature and the transaction.
- Bitstring Status List is read left-most-bit-first, the list credential's proof and issuer are verified, and the list must be ≥ 16 KB (Go#187 is still open upstream).
- `parse_credential_with_validation` needs a `schema_loader`; schema URLs from a credential are never fetched.
- A naive `datetime` is UTC everywhere.

## Network access

Only `digitalcredential` issuer metadata / status list / Type Metadata resolvers, status list credentials (`credential`), unknown JSON-LD `@context`s, `did`/`didv2` JSON-RPC and the DID resolver touch the network. Fetches of untrusted URLs go through `digitalcredential.internal.safehttp`: https only, no non-global addresses, bounded time, size and redirects.
