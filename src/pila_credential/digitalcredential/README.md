# digitalcredential

IETF SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-19).

- **Entry points**: `issue(IssueRequest, SigningKey)`, `parse(str)`, `Credential.present(PresentRequest)`, `Credential.verify(resolver, *opts)`.
- **Verify options**: `with_audience`, `with_nonce`, `with_accepted_issuers`, `with_accepted_vcts`, `with_status`, `with_type_metadata`, `with_reject_future_iat`, `with_iat_check`, `with_now`, ...
- **Errors**: `DigitalCredentialError` (`.code`, e.g. `EXPIRED`, `SIGNATURE_INVALID`, `IAT_CHECK_FAILED`); `ErrPolicy` for caller mistakes; `jose.errors.ErrInvalidArgument` from `issue`/`present`.
- **Network**: `issuermeta.new_resolver` (JWT VC issuer metadata + JWKS), `statuslist.new_checker`, `typemeta.new_http_resolver`. All use `internal/safehttp` by default (https, no private addresses, whole-fetch timeout, size cap).
- **Type Metadata**: `typemeta.validate_issuance` runs inside `issue(type_metadata=...)`; verify checks the recreated payload.
- Example: [`examples/sdjwt_vc.py`](../../../examples/sdjwt_vc.py).
