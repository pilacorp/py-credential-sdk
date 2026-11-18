# jose

JOSE primitives used by the other packages: `jwk`, `jws`, `jwt`, `sdjwt` (conceal, recreate, disclosures, KB-JWT).

- **Errors**: `jose.errors` (`ErrInvalidArgument`, `ErrMalformed`, ...); test with `digitalcredential.errors.errors_is` where chains are wrapped.
- JSON decoding is strict (duplicate keys and excessive depth are refused).
- **Network**: none.
