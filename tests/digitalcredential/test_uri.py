from digitalcredential.internal import uri


def test_uri_check_examples() -> None:
    ok = [
        "ftp://ftp.is.co.za/rfc/rfc1808.txt",
        "http://www.ietf.org/rfc/rfc2396.txt",
        "ldap://[2001:db8::7]/c=GB?objectClass?one",
        "mailto:John.Doe@example.com",
        "news:comp.infosystems.www.servers.unix",
        "tel:+1-816-555-1212",
        "telnet://192.0.2.16:80/",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        "https://%CF%83.example.com/root",
        "did:example:123",
    ]
    bad = [
        "",
        "1http://example.com",
        "https://bücher.example/x",
        "https://example.com/a b",
        "https://example.com/%zz",
        "https://example.com?q=<x>",
        "https://example.com#f#g",
        "https://example.com:8x/",
        "https://[fe80::1%25eth0]/",
        "https://[::1/",
        "https:///issuer",
        "https:issuer",
        "HTTP://user@:443/",
    ]
    for s in ok:
        uri.check(s)
    for s in bad:
        try:
            uri.check(s)
            raise AssertionError(f"expected error for {s!r}")
        except ValueError:
            pass
