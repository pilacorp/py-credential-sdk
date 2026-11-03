from __future__ import annotations

from jose.sdjwt.conceal import ConcealOptions, conceal
from jose.sdjwt.recreate import recreate


def test_conceal_recreate_round_trip() -> None:
    claims = {
        "iss": "https://issuer.example",
        "given_name": "Ana",
        "address": {"street": "1 Main St", "locality": "Hanoi"},
        "nationalities": ["VN", "FR"],
    }
    paths = [["given_name"], ["address"], ["address", "locality"], ["nationalities", 1]]
    payload, disclosures = conceal(claims, paths, ConcealOptions(min_digests=0))
    assert payload.get("_sd_alg") == "sha-256"
    r = recreate(payload, disclosures)
    assert r.claims["given_name"] == "Ana"
    assert r.claims["address"]["locality"] == "Hanoi"
    assert r.claims["nationalities"] == ["VN", "FR"]
