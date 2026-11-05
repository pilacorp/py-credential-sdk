"""Port of go-credential-sdk/credential/common/sdjwt/decoy_test.go."""
from credential.common.sdjwt import DecoyConfig, build_disclosures
from credential.common.sdjwt.disclosure import _process_decoys


def test_array_decoy():
    vc = {"credentialSubject": {"name": "John", "emails": ["john@example.com", "john.doe@work.com"]}}
    r = build_disclosures(vc, ["credentialSubject.name"], decoys=[DecoyConfig("credentialSubject.emails", 2)])
    emails = r["processed_vc"]["credentialSubject"]["emails"]
    assert len(emails) == 4
    assert all(isinstance(e, str) for e in emails[:2])
    assert all(isinstance(e, dict) and "..." in e for e in emails[2:])


def test_array_decoy_with_empty_path():
    vc = {"credentialSubject": {"name": "John"}}
    r = build_disclosures(vc, ["credentialSubject.name"], decoys=[DecoyConfig("", 3)])
    assert len(r["processed_vc"]["_sd"]) == 3


def test_object_decoy_path():
    vc = {"credentialSubject": {"name": "John", "age": 30, "email": "john@example.com"}}
    r = build_disclosures(vc, ["credentialSubject.name"], decoys=[DecoyConfig("credentialSubject", 2)])
    sd = r["processed_vc"]["credentialSubject"]["_sd"]
    assert len(sd) == 3  # 1 field + 2 decoys
    assert any(isinstance(s, str) and s for s in sd)


def test_multiple_decoys():
    vc = {"credentialSubject": {"name": "John", "age": 30, "emails": ["john@example.com"]}}
    r = build_disclosures(
        vc,
        ["credentialSubject.name"],
        decoys=[
            DecoyConfig("", 2),
            DecoyConfig("credentialSubject", 3),
            DecoyConfig("credentialSubject.emails", 1),
        ],
    )
    out = r["processed_vc"]
    assert len(out["_sd"]) == 2
    cs = out["credentialSubject"]
    assert len(cs["_sd"]) == 4
    assert len(cs["emails"]) == 2
    assert isinstance(cs["emails"][0], str)
    assert "..." in cs["emails"][1]


def test_nested_array_element():
    vc = {
        "credentialSubject": {
            "name": "John",
            "addresses": [{"city": "NYC", "zip": "10001"}, {"city": "LA", "zip": "90001"}],
        }
    }
    r = build_disclosures(vc, ["credentialSubject.addresses[0].city"])
    addrs = r["processed_vc"]["credentialSubject"]["addresses"]
    assert "_sd" in addrs[0]
    assert "_sd" not in addrs[1] and addrs[1]["city"] == "LA"


def test_selective_with_decoys():
    vc = {"credentialSubject": {"name": "John", "email": "john@example.com", "phone": "1234567890"}}
    r = build_disclosures(
        vc, ["credentialSubject.name"], decoys=[DecoyConfig("credentialSubject", 2)], shuffle=True
    )
    cs = r["processed_vc"]["credentialSubject"]
    assert len(cs["_sd"]) == 3
    assert "name" not in cs
    assert cs["email"] == "john@example.com"


def test_empty_disclosures():
    vc = {"credentialSubject": {"name": "John", "age": 30}}
    r = build_disclosures(vc, [])
    cs = r["processed_vc"]["credentialSubject"]
    assert cs["name"] == "John" and "_sd" not in cs
    assert "_sd_alg" not in r["processed_vc"] and r["disclosures"] == []


def test_apply_decoy_array_element_write_back():
    vc = {"credentialSubject": {"emails": ["a@example.com", "b@example.com"]}}
    # DecoyConfig drives hashes randomly; call the internal path with a fixed hash via the public API
    r = build_disclosures(vc, None, decoys=[DecoyConfig("credentialSubject.emails[1]", 1)])
    cs = r["processed_vc"]["credentialSubject"]
    assert len(cs["emails"]) == 3 and "..." in cs["emails"][2]
    assert "credentialSubject" not in cs


def test_empty_selective_paths_with_decoys():
    vc = {"credentialSubject": {"name": "John"}}
    r = build_disclosures(vc, [], decoys=[DecoyConfig("credentialSubject", 2)])
    assert "_sd" in r["processed_vc"]["credentialSubject"]
    assert r["processed_vc"]["_sd_alg"] == "sha-256"  # decoys need _sd_alg
    assert r["disclosures"] == []


def test_decoy_missing_path_is_ignored_and_nonpositive_count_skipped():
    vc = {"a": {"b": 1}}
    r = build_disclosures(vc, [], decoys=[DecoyConfig("nope", 2), DecoyConfig("a", 0)])
    assert r["processed_vc"]["a"] == {"b": 1}
    _process_decoys(vc, [DecoyConfig("a", -1)], "sha-256")
    assert vc == {"a": {"b": 1}}
