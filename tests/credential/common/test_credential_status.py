from credential.common.credential_status.credential_status import is_revoked
from credential.common.credential_status.model import StatusListCredentialSubject
from credential.common.util.compress import compress_to_base64url


def test_is_revoked_reads_bitstring():
    raw = bytes([0b00000010])
    encoded = compress_to_base64url(raw)
    subject = StatusListCredentialSubject(
        encoded_list=encoded,
        id="https://example/status/1",
        status_purpose="revocation",
        type="StatusList2021",
    )
    assert is_revoked(1, subject) is True
    assert is_revoked(0, subject) is False
