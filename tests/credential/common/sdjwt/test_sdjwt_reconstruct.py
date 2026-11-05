"""Port of go-credential-sdk/credential/common/sdjwt/reconstruct_test.go."""
import base64
import hashlib
import json

import pytest

from credential.common.sdjwt import DecoyConfig, build_disclosures, hash_disclosure, parse, reconstruct
from credential.common.sdjwt.reconstruct import build_disclosure_map, process_node, validate_and_get_algorithm
from credential.common.sdjwt.helper import parse_disclosure

SHA256, SHA384, SHA512 = "sha-256", "sha-384", "sha-512"


def enc(arr) -> str:
    return base64.urlsafe_b64encode(json.dumps(arr, separators=(",", ":")).encode()).decode().rstrip("=")


def hash_and_parse(alg, arr):
    disc = enc(arr)
    return hash_disclosure(alg, disc), parse_disclosure(disc)


def digest_for(disclosure: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(disclosure.encode()).digest()).decode().rstrip("=")


def disc_for(salt, name, value) -> str:
    return enc([salt, name, value])


@pytest.mark.parametrize(
    "vc,validate,want_alg,want_err",
    [
        ({}, True, SHA256, None),
        ({"_sd_alg": SHA512}, True, SHA512, None),
        ({"_sd_alg": "sha-999"}, True, None, "unsupported _sd_alg"),
        ({"_sd_alg": "sha-999"}, False, "sha-999", None),
    ],
)
def test_validate_and_get_algorithm(vc, validate, want_alg, want_err):
    if want_err:
        with pytest.raises(ValueError, match=want_err):
            validate_and_get_algorithm(vc, validate)
    else:
        assert validate_and_get_algorithm(vc, validate) == want_alg


def test_build_disclosure_map_skip_empty_and_parse():
    valid = enc(["salt", "name", "Alice"])
    assert len(build_disclosure_map(["", valid], SHA256)) == 1


def test_build_disclosure_map_invalid_disclosure():
    with pytest.raises(ValueError, match="failed to decode disclosure"):
        build_disclosure_map(["bad@@@"], SHA256)


def test_process_node_object_context_rejects_array_disclosure():
    h, info = hash_and_parse(SHA256, ["salt-x", "array-value"])
    with pytest.raises(ValueError, match="array element disclosure used in object context"):
        process_node({"_sd": [h]}, {h: info}, set())


def test_process_node_array_context_rejects_object_disclosure():
    h, info = hash_and_parse(SHA256, ["salt-x", "name", "Alice"])
    with pytest.raises(ValueError, match="object field disclosure used in array context"):
        process_node([{"...": h}], {h: info}, set())


def test_process_node_duplicate_field_after_reconstruct():
    h, info = hash_and_parse(SHA256, ["salt-x", "name", "Alice"])
    with pytest.raises(ValueError, match="duplicate field"):
        process_node({"name": "already-exists", "_sd": [h]}, {h: info}, set())


def test_reconstruct_array_placeholder():
    d = enc(["salt123", "Item1"])
    h = hash_disclosure(SHA256, d)
    out = reconstruct({"items": [{"...": h}]}, [d], True)
    assert out["items"] == ["Item1"]


COMPACT = (
    "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiYkRUUnZtNS1Zbi1IRzdjcXBWUjVPVlJJWHNTYUJrNTdKZ2lPcV9qMVZJNCIsImV0M1VmUnlsd1ZyZlhkUEt6Zzc5aGNqRDFJdHpvUTlvQm9YUkd0TW9zRmsiLCJ6V2ZaTlMxOUF0YlJTVGJvN3NKUm4wQlpRdldSZGNob0M3VVphYkZyalk4Il0sIl9zZF9hbGciOiJzaGEtMjU2In0.n27NCtnuwytlBYtUNjgkesDP_7gN7bhaLhWNL4SWT6MaHsOjZ2ZMp987GgQRL6ZkLbJ7Cd3hlePHS84GBXPuvg~WyI1ZWI4Yzg2MjM0MDJjZjJlIiwiZmlyc3RuYW1lIiwiSm9obiJd~WyJjNWMzMWY2ZWYzNTg4MWJjIiwibGFzdG5hbWUiLCJEb2UiXQ~WyJmYTlkYTUzZWJjOTk3OThlIiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MTAwNjk3MjIsImF1ZCI6ImRpZDpleGFtcGxlOjEyMyIsIm5vbmNlIjoiazh2ZGYwbmQ2Iiwic2RfaGFzaCI6Il8tTmJWSzNmczl3VzNHaDNOUktSNEt1NmZDMUwzN0R2MFFfalBXd0ppRkUifQ.pqw2OB5IA5ya9Mxf60hE3nr2gsJEIoIlnuCa4qIisijHbwg3WzTDFmW2SuNvK_ORN0WU6RoGbJx5uYZh8k4EbA"
)


def test_reconstruct_real_example_from_compact():
    # ends in a key binding JWT: refused until the binding is verified
    with pytest.raises(ValueError, match="key binding JWT"):
        parse(COMPACT)
    without_kb = COMPACT[: COMPACT.rindex("~") + 1]
    parsed = parse(without_kb)
    parts = parsed.base_jwt.split(".")
    assert len(parts) == 3
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    out = reconstruct(payload, parsed.disclosures, True)
    assert out["id"] == "1234"
    assert out["firstname"] == "John" and out["lastname"] == "Doe" and out["ssn"] == "123-45-6789"
    assert "_sd" not in out and "_sd_alg" not in out


def test_validation_duplicate_digest_in_array():
    d1 = enc(["salt1", "value1"])
    h1 = hash_disclosure(SHA256, d1)
    with pytest.raises(ValueError, match="duplicate digest"):
        reconstruct({"items": [{"...": h1}, {"...": h1}]}, [d1], True)


def test_build_and_reconstruct_object_field():
    original = {"name": "Alice", "age": 30.0}
    r = build_disclosures(original, ["name"])
    processed = r["processed_vc"]
    assert "name" not in processed and processed["age"] == 30.0
    assert processed["_sd_alg"] == SHA256
    assert len(processed["_sd"]) == 1 and len(r["disclosures"]) == 1
    out = reconstruct(processed, r["disclosures"], True)
    assert out == {"name": "Alice", "age": 30.0}
    assert original == {"name": "Alice", "age": 30.0}  # input not mutated


def test_build_and_reconstruct_array_element_path():
    r = build_disclosures({"tags": ["public", "email", "phone"], "note": "test"}, ["tags[1]"])
    p = r["processed_vc"]
    assert p["_sd_alg"] == SHA256
    assert len(p["tags"]) == 3 and list(p["tags"][1].keys()) == ["..."]
    assert len(r["disclosures"]) == 1
    out = reconstruct(p, r["disclosures"], True)
    assert out["tags"] == ["public", "email", "phone"]
    assert "_sd" not in out and "_sd_alg" not in out


def test_build_and_reconstruct_recursive_object_path():
    original = {"id": "1234", "person": {"profile": {"name": "Alice", "age": 30.0}}}
    r = build_disclosures(original, ["person.profile.name"])
    p = r["processed_vc"]
    assert p["_sd_alg"] == SHA256 and "_sd" not in p
    prof = p["person"]["profile"]
    assert "name" not in prof and prof["age"] == 30.0 and len(prof["_sd"]) == 1
    out = reconstruct(p, r["disclosures"], True)
    assert out["person"]["profile"] == {"name": "Alice", "age": 30.0}
    assert "_sd_alg" not in out


def test_build_disclosures_recursive_parent_and_child_paths():
    orig = {"id": "1234", "person": {"profile": {"name": "Alice", "age": 30.0}}}
    with pytest.raises(ValueError, match=r'path "person.profile.name" not found'):
        build_disclosures(orig, ["person.profile", "person.profile.name"])
    orig2 = {"id": "1234", "person": {"profile": {"name": "Alice", "age": 30.0}}}
    r = build_disclosures(orig2, ["person.profile.name", "person.profile"])
    assert len(r["disclosures"]) == 2
    out = reconstruct(r["processed_vc"], r["disclosures"], True)
    assert out["id"] == "1234"
    assert out["person"]["profile"] == {"name": "Alice", "age": 30.0}


def test_build_disclosures_array_parent_and_child_paths():
    with pytest.raises(ValueError, match=r'path "tags\[1\]" not found'):
        build_disclosures({"tags": ["public", "email", "phone"], "note": "test"}, ["tags", "tags[1]"])
    r = build_disclosures({"tags": ["public", "email", "phone"], "note": "test"}, ["tags[1]", "tags"])
    assert len(r["disclosures"]) == 2
    out = reconstruct(r["processed_vc"], r["disclosures"], True)
    assert out["tags"] == ["public", "email", "phone"] and out["note"] == "test"
    assert "_sd" not in out and "_sd_alg" not in out


def test_build_disclosures_with_options():
    original = {"name": "Alice", "age": 30.0, "city": "NYC"}
    r = build_disclosures(original, ["name", "age"], hash_algorithm=SHA384)
    assert r["processed_vc"]["_sd_alg"] == SHA384
    out = reconstruct(r["processed_vc"], r["disclosures"], True)
    assert out["name"] == "Alice" and out["age"] == 30.0

    build_disclosures(original, ["name", "age"], shuffle=True)

    r3 = build_disclosures(original, ["name"], decoys=[DecoyConfig("", 2)])
    assert len(r3["processed_vc"]["_sd"]) == 3 and len(r3["disclosures"]) == 1
    assert reconstruct(r3["processed_vc"], r3["disclosures"], True)["name"] == "Alice"

    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        build_disclosures(original, ["name"], hash_algorithm="md5")
    with pytest.raises(ValueError, match="empty path"):
        build_disclosures(original, ["  "])


def test_validation_digest_referenced_twice_across_objects():
    d = enc(["salt1", "secret", "VALUE"])
    h = hash_disclosure(SHA256, d)
    vc = {"_sd_alg": SHA256, "a": {"_sd": [h]}, "b": {"_sd": [h]}}
    with pytest.raises(ValueError, match="referenced more than once"):
        reconstruct(vc, [d], True)


def test_validation_sd_must_be_an_array():
    vc = {"_sd_alg": SHA256, "x": {"_sd": "not-an-array", "k": 1}}
    with pytest.raises(ValueError, match="_sd must be an array"):
        reconstruct(vc, None, True)


DISCLOSURE = disc_for("c2FsdDAxc2FsdDAxc2FsdDAx", "secret", "x")
H = digest_for(DISCLOSURE)


@pytest.mark.parametrize(
    "vc,disclosures",
    [
        ({"_sd_alg": SHA256, "a": {"_sd": [H]}, "b": {"_sd": [H]}}, []),
        ({"_sd_alg": SHA256, "a": {"_sd": [H]}, "b": {"_sd": [H]}}, [DISCLOSURE]),
        ({"_sd_alg": SHA256, "a": [{"...": H}], "b": [{"...": H}]}, []),
        ({"_sd_alg": SHA256, "a": {"_sd": [H]}, "b": [{"...": H}]}, []),
    ],
    ids=["unrevealed 2 objects", "revealed 2 objects", "placeholder 2 arrays", "object + placeholder"],
)
def test_digest_uniqueness_ignores_whether_it_was_revealed(vc, disclosures):
    with pytest.raises(ValueError, match="referenced more than once in the payload"):
        reconstruct(vc, disclosures, True)


@pytest.mark.parametrize("ds", [[], [DISCLOSURE]])
def test_single_occurrence_is_untouched(ds):
    out = reconstruct({"_sd_alg": SHA256, "a": {"_sd": [H]}}, ds, True)
    assert "_sd" not in out["a"]
    if ds:
        assert out["a"]["secret"] == "x"


# --- extra negatives the Go code enforces (RFC 9901 §7.1), exercised end to end ---
def test_unused_disclosure_rejected():
    r = build_disclosures({"a": 1, "b": 2}, ["a"])
    extra = disc_for("c2FsdA", "zzz", "fabricated")
    with pytest.raises(ValueError, match="matches nothing in the payload"):
        reconstruct(r["processed_vc"], r["disclosures"] + [extra], True)


def test_duplicate_disclosure_rejected():
    r = build_disclosures({"a": 1}, ["a"])
    with pytest.raises(ValueError, match="sent more than once"):
        reconstruct(r["processed_vc"], r["disclosures"] * 2, True)


def test_tampered_disclosure_rejected():
    r = build_disclosures({"a": 1}, ["a"])
    forged = disc_for("c2FsdA", "a", 999)
    with pytest.raises(ValueError, match="matches nothing in the payload"):
        reconstruct(r["processed_vc"], [forged], True)


def test_non_string_sd_alg_falls_back_to_sha256_like_go():
    assert validate_and_get_algorithm({"_sd_alg": 5}, True) == SHA256


def test_deeply_nested_payload_is_a_value_error_not_a_crash():
    import sys

    old = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)  # other suites raise it; pin it so 5000 levels overflow
    try:
        node = leaf = {}
        for _ in range(5000):
            leaf["x"] = {}
            leaf = leaf["x"]
        with pytest.raises(ValueError):
            reconstruct(node, [], True)
    finally:
        sys.setrecursionlimit(old)
