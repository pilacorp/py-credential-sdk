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

Go parts with no Python package: `digitalcredential/didresolver` (W3C DID Resolution client). Check against the Go tree when it changes.

## Minimal issue / verify

`examples/` holds runnable scripts (CI runs them): [`jsonld_vc.py`](examples/jsonld_vc.py) (issue + verify a JSON-LD VC), [`sdjwt_vc.py`](examples/sdjwt_vc.py) (issue, present, verify an SD-JWT VC), [`didv2_create.py`](examples/didv2_create.py) (create a DID).

## Differences from Go

- `snake_case` names; options are `with_*` functions passed positionally.
- Errors are raised exceptions, not returned values. `digitalcredential` raises `DigitalCredentialError` with a `.code`.
- `didv2.DIDGenerator` takes `**overrides` of `DIDConfig` fields per call (`did_smc_addr`, `chain_id`, `nonce`, ...). Overrides apply to both the issuer signature and the transaction.
- Bitstring Status List is read left-most-bit-first, the list credential's proof is verified (which issuers to trust is left to the caller), and the list must be ≥ 16 KB (Go#187 is still open upstream).
- `parse_credential_with_validation` needs a `schema_loader`; schema URLs from a credential are never fetched.
- A naive `datetime` is UTC everywhere.

## Network access

Network is touched by: the `digitalcredential` issuer metadata, status list and Type Metadata resolvers; status list credentials and the DID resolver in `credential`; unknown JSON-LD `@context`s; and `didv2` JSON-RPC. The legacy `did` package makes no network call. Fetches in `digitalcredential` and for unknown `@context`s go through `digitalcredential._internal.safehttp` (https only, no non-global addresses, one deadline for DNS, connect, TLS, headers and body, bounded size and redirects). Status list credentials for JSON-LD VCs are fetched with `urllib` (https/http only, size-capped, no address filter).
