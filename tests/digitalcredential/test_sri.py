import hashlib

from digitalcredential.internal import sri


def test_sri_check_figure30_sha256() -> None:
    data = b'{"vct":"https://example.com/t"}'
    digest = hashlib.sha256(data).digest()
    import base64

    integrity = "sha256-" + base64.standard_b64encode(digest).decode("ascii")
    sri.check(data, integrity)
    try:
        sri.check(b"other", integrity)
        raise AssertionError("expected mismatch")
    except ValueError:
        pass
