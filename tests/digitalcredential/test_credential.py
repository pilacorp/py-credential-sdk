"""Go: digitalcredential/credential_test.go."""

import pytest

from digitalcredential.credential import Credential, parse
from digitalcredential.errors import MALFORMED, DigitalCredentialError, ErrPolicy, errors_is
from jose import base64 as jose_b64
from jose.errors import ErrInvalidArgument, ErrMalformed

from dc_helpers import KeysOf

# RFC 7515 Appendix A.3, and the same token with its signature's S replaced by n-S of P-256, which
# verifies too. Each hash is SHA-256 of the JWT's ASCII bytes, computed with shasum.
RFC7515_A3 = (
    "eyJhbGciOiJFUzI1NiJ9."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
    "pmWQxfKTUJqPP3-Kg6NU1Q"
)
RFC7515_A3_TWIN = (
    "eyJhbGciOiJFUzI1NiJ9."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmU69fgrc8OPGycO0lD3tat_"
    "FoFp57SETepkeks4eL_QfA"
)
HASH_A3 = "4634b4dcaca24964bce48e22146fb6e3933ad993e6f24f42575145a2133ae115"
HASH_TWIN = "d16175719f45a5fc088c1d95733040976389315a3f4739fea801a516234c51d1"


@pytest.mark.parametrize(
    "compact,want",
    [
        (RFC7515_A3 + "~", HASH_A3),
        (RFC7515_A3 + "~WyJhIl0~", HASH_A3),
        (RFC7515_A3 + "~WyJhIl0~" + RFC7515_A3_TWIN, HASH_A3),
        (RFC7515_A3_TWIN + "~", HASH_TWIN),  # S changed to n-S: another credential
    ],
    ids=["SD-JWT", "with a disclosure", "with a disclosure and a KB-JWT", "S changed to n-S"],
)
def test_hash_rfc7515_appendix_a3(compact, want):
    c = parse(compact)
    assert c.serialize() == compact
    assert c.hash() == want


def many_disclosures(n: int) -> str:
    return "".join(jose_b64.encode_segment(('["salt",%d]' % i).encode()) + "~" for i in range(n))


@pytest.mark.parametrize(
    "compact",
    [
        "",
        RFC7515_A3,
        RFC7515_A3 + "~" + "A" * (1 << 20) + "~",
        RFC7515_A3 + "~" + many_disclosures(1001),
    ],
    ids=["empty", "bare JWT without ~", "over 1 MiB", "over 1000 disclosures"],
)
def test_parse_refuses_malformed(compact):
    with pytest.raises(DigitalCredentialError) as ei:
        parse(compact)
    assert ei.value.code == MALFORMED
    assert errors_is(ei.value, ErrMalformed)


@pytest.mark.parametrize("c", [None, Credential()], ids=["nil", "zero"])
def test_zero_credential(c):
    if c is not None:
        assert c.serialize() == ""
        with pytest.raises(ErrInvalidArgument):
            c.hash()
        with pytest.raises(ErrInvalidArgument):
            c.present(None)
        with pytest.raises(ErrPolicy):
            c.verify(KeysOf({}))
        return
    from digitalcredential.present import present
    from digitalcredential.verify import verify

    with pytest.raises(ErrInvalidArgument):
        present(None, None)
    with pytest.raises(ErrPolicy):
        verify(None, KeysOf({}))
