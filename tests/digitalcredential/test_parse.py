from digitalcredential.credential import parse
from digitalcredential.split import split_sd_jwt


def test_split_sd_jwt() -> None:
    compact = "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQifQ.sig~disclosure~"
    parts = split_sd_jwt(compact)
    assert parts["issuer_jwt"].count(".") == 2
    assert parts["disclosures"] == ["disclosure"]
    assert parts["kb_jwt"] == ""
    cred = parse(compact)
    assert cred.serialize() == compact
    assert len(cred.hash()) == 64


def test_split_requires_tilde() -> None:
    try:
        split_sd_jwt("eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQifQ.sig")
        raise AssertionError("expected error")
    except ValueError:
        pass
