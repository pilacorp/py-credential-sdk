from credential.common.verification_method.key_material import (
    decode_multibase_key,
    ec_pub_from_jwk,
    ec_pub_from_multibase,
    ec_pub_from_vm,
    encode_multibase_key,
    encode_pub_multibase,
    rsa_pub_from_jwk,
    secp256k1_pub_from_hex,
    verify_rs,
)
from credential.common.verification_method.provider import HTTPResolver, ResolverProvider
from credential.common.verification_method.resolve import (
    did_from_verification_method_url,
    find_verification_method,
    normalize_verification_method_url,
    resolve_signing_vm,
    resolve_verification_method_url_for_key,
)
from credential.common.verification_method.revocation import is_hard_revocation_reason
from credential.common.verification_method.selector import (
    KeyKind,
    ensure_vm_authorized_for_purpose,
    select_default_signing_vm,
    select_latest_active_vm_for_key,
    select_latest_active_vm_for_purpose,
    select_vm_for_purpose,
    vm_is_p256,
    vm_is_rsa,
    vm_is_secp256k1,
    vm_key_kind,
)
from credential.common.verification_method.static_resolver import (
    StaticResolver,
    new_did_document,
    new_p256_multikey_vm,
    new_p256_vm,
    new_rsa_vm,
    new_secp256k1_vm,
)
from credential.common.verification_method.verification_method import (
    DIDDocument,
    JWK,
    VerificationMethodEntry,
    did_document_from_dict,
    parse_rfc3339,
)

__all__ = [
    "DIDDocument", "HTTPResolver", "JWK", "KeyKind", "ResolverProvider", "StaticResolver",
    "VerificationMethodEntry", "decode_multibase_key", "did_document_from_dict",
    "did_from_verification_method_url", "ec_pub_from_jwk", "ec_pub_from_multibase", "ec_pub_from_vm",
    "encode_multibase_key", "encode_pub_multibase", "ensure_vm_authorized_for_purpose",
    "find_verification_method", "is_hard_revocation_reason", "new_did_document", "new_p256_multikey_vm",
    "new_p256_vm", "new_rsa_vm", "new_secp256k1_vm", "normalize_verification_method_url", "parse_rfc3339",
    "resolve_signing_vm", "resolve_verification_method_url_for_key", "rsa_pub_from_jwk",
    "secp256k1_pub_from_hex", "select_default_signing_vm", "select_latest_active_vm_for_key",
    "select_latest_active_vm_for_purpose", "select_vm_for_purpose", "verify_rs", "vm_is_p256", "vm_is_rsa",
    "vm_is_secp256k1", "vm_key_kind",
]
