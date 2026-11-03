import json

from digitalcredential.issuermeta import metadata_url, new_resolver, ResolverConfig


def test_metadata_url() -> None:
    cases = {
        "https://example.com": "https://example.com/.well-known/jwt-vc-issuer",
        "https://example.com/tenant/1234": "https://example.com/.well-known/jwt-vc-issuer/tenant/1234",
        "https://example.com/": "https://example.com/.well-known/jwt-vc-issuer",
    }
    for iss, want in cases.items():
        assert metadata_url(iss) == want


def test_fetching_resolver_inline_jwks() -> None:
    jwks = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs352LiPiUqW2VKbwiiI2gYs4M",
                "y": "11YXWTbI6CYYAs8S9TvwxwM9iKX1L1pX0hHQKzR93OM",
                "kid": "doc-signer",
            }
        ]
    }
    meta = json.dumps({"issuer": "https://example.com", "jwks": jwks}).encode()
    calls: list[str] = []

    def fetch(url: str) -> tuple[bytes, dict[str, str]]:
        calls.append(url)
        return meta, {"content-type": "application/json", "cache-control": "max-age=3600"}

    r = new_resolver(ResolverConfig(trusted_issuer_origins=["https://example.com"], fetch=fetch))
    keys1 = r.keys("https://example.com")
    keys2 = r.keys("https://example.com")
    assert len(keys1) == 1 and keys1[0].kid == "doc-signer"
    assert len(keys2) == 1
    assert len(calls) == 1
