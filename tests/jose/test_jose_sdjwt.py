"""Port of jose/sdjwt/{conceal,disclosure,split,recreate}_test.go."""

import base64
import hashlib
import json
import pathlib

import pytest

from jose import ErrInvalidArgument, ErrMalformed, JsonNumber, decode_json, decode_json_object, decode_segment
from jose.sdjwt import ConcealOptions, Disclosure, conceal, parse_disclosure, recreate, split
from jose.sdjwt.limits import MAX_DISCLOSURES
from jose.sdjwt.path import Path, compare_paths

TESTDATA = pathlib.Path(__file__).parent / "testdata" / "rfc9901-examples.json"


def round_trip_claims():
    return {
        "iss": "https://issuer.example",
        "given_name": "Ana",
        "address": {"street": "1 Main St", "locality": "Hanoi"},
        "nationalities": ["VN", "FR"],
        "place_of_birth": {"country": "VN"},
    }


def _placeholder(el):
    return isinstance(el, dict) and len(el) == 1 and isinstance(el.get("..."), str)


@pytest.mark.parametrize("opts,placeholders", [(ConcealOptions(min_digests=3), 3), (ConcealOptions(min_digests=3, no_array_decoys=True), 1)])
def test_conceal_round_trip(opts, placeholders):
    claims = round_trip_claims()
    paths = [["given_name"], ["address"], ["address", "locality"], ["nationalities", 1]]
    payload, ds = conceal(claims, paths, opts)
    assert claims == round_trip_claims()  # the caller's map is left as it was
    assert len(ds) == len(paths)
    assert payload["_sd_alg"] == "sha-256"

    # Every object holds max(concealed, 3) digests in _sd, sorted; every array max(concealed, 3)
    # placeholders, or only the concealed ones without array decoys.
    sd_lens, placeholder_lens = [], []

    def walk(v):
        if isinstance(v, dict):
            sd = v.get("_sd", [])
            assert sd == sorted(sd), f"_sd not sorted: {sd}"
            sd_lens.append(len(sd))
            for k, child in v.items():
                if k != "_sd":
                    walk(child)
        elif isinstance(v, list):
            n = 0
            for el in v:
                if _placeholder(el):
                    n += 1
                else:
                    walk(el)
            placeholder_lens.append(n)

    walk(payload)
    for d in ds:
        walk(d.value)
    assert sd_lens == [3, 3, 3] and placeholder_lens == [placeholders]

    r = recreate(payload, ds)
    assert r.claims == round_trip_claims()


def test_conceal_rejects():
    wide = [{} for _ in range(19)]  # 21 objects and arrays (the claims, "a" and 19 elements) x 1000 decoys
    many = {str(i): i for i in range(1001)}
    many_paths = [[str(i)] for i in range(1001)]
    cases = {
        "_sd in claims": ({"a": {"_sd": ["x"]}}, [], ConcealOptions()),
        "... in claims": ({"a": [{"...": "x"}]}, [], ConcealOptions()),
        "_sd_alg in claims": ({"_sd_alg": "sha-256"}, [], ConcealOptions()),
        "MinDigests 1001": ({"a": 1}, [], ConcealOptions(min_digests=1001)),
        "MinDigests -1": ({"a": 1}, [], ConcealOptions(min_digests=-1)),
        "21 containers x MinDigests 1000": ({"a": wide}, [], ConcealOptions(min_digests=1000)),
        "1001 paths": (many, many_paths, ConcealOptions()),
        # {"A"} goes first and gives the claims object an _sd, which {"_sd"} must not then conceal.
        "path to an _sd Conceal made": ({"A": 1}, [["A"], ["_sd"]], ConcealOptions()),
        "path given twice": ({"A": 1}, [["A"], ["A"]], ConcealOptions()),
        "path missing": ({"A": 1}, [["B"]], ConcealOptions()),
        "empty path": ({"A": 1}, [[]], ConcealOptions()),
        "negative index": ({"A": [1]}, [["A", -1]], ConcealOptions()),
        "bool is not an index": ({"A": [1]}, [["A", True]], ConcealOptions()),
        "float is not an index": ({"A": [1]}, [["A", 0.0]], ConcealOptions()),
        "unencodable": ({"A": object()}, [], ConcealOptions()),
        "too deep": ({"a": json.loads("[" * 70 + "]" * 70)}, [], ConcealOptions()),
    }
    for name, (claims, paths, opts) in cases.items():
        with pytest.raises(ErrInvalidArgument):
            conceal(claims, paths, opts)


def test_conceal_orders_disclosures_deepest_first_and_nested_value_is_complete():
    payload, ds = conceal({"a": {"b": "x"}, "c": [1, 2, 3]}, [["a"], ["a", "b"], ["c", 0], ["c", 2]], ConcealOptions())
    # deeper paths first, then names before indices, indices by value
    assert [(d.name, d.array_element) for d in ds] == [("b", False), ("", True), ("", True), ("a", False)]
    r = recreate(payload, ds)
    assert r.claims == {"a": {"b": "x"}, "c": [JsonNumber("1"), JsonNumber("2"), JsonNumber("3")]}  # numbers come back as JsonNumber, as in Go
    # a nested concealed claim lives inside the parent's disclosure
    outer = [d for d in ds if d.name == "a"][0]
    assert "_sd" in outer.value and "b" not in outer.value


def test_conceal_none_claims_and_no_paths():
    payload, ds = conceal(None, [], ConcealOptions())
    assert payload == {} and ds == []
    payload, ds = conceal({"a": 1}, [])
    assert payload == {"a": JsonNumber("1")} and "_sd_alg" not in payload
    payload, ds = conceal({"a": 1}, [], ConcealOptions(min_digests=2))
    assert payload["_sd_alg"] == "sha-256" and len(payload["_sd"]) == 2


def test_conceal_keeps_json_numbers():
    payload, ds = conceal({"n": JsonNumber("1.50"), "m": 12345678901234567890123}, [["n"], ["m"]])
    r = recreate(payload, ds)
    assert r.claims["n"] == JsonNumber("1.50") and r.claims["m"] == JsonNumber("12345678901234567890123")


# RFC 9901 §4.2.1 builds this disclosure from ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"],
# and §4.2.3 gives its digest.
def test_parse_disclosure_rfc_example():
    d = parse_disclosure("WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")
    assert d.digest == "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
    assert (d.salt, d.name, d.value, d.array_element) == ("_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius", False)


def disclose(json_text):
    encoded = base64.urlsafe_b64encode(json_text.encode()).decode().rstrip("=")
    digest = base64.urlsafe_b64encode(hashlib.sha256(encoded.encode()).digest()).decode().rstrip("=")
    return encoded, digest


def test_parse_disclosure_rejections():
    for text in (
        '["s","_sd","x"]',
        '["s","...","x"]',
        '["s","_sd_alg","x"]',
        '["s"]',
        '["s","a","b","c"]',
        '[1,"a","b"]',
        '["s",1,"b"]',
        '{"a":1}',
        '["s","a","b"] x',
        '["s","a","b","c"',
        '["s","a",{"x":1,"x":2}]',
    ):
        with pytest.raises(ErrMalformed):
            parse_disclosure(disclose(text)[0])
    for bad in ("QR", "!!!", "QQ==", "a\nb"):
        with pytest.raises(ErrMalformed):
            parse_disclosure(bad)
    # an array element disclosure may carry any value, even one named like a reserved word
    assert parse_disclosure(disclose('["s","_sd"]')[0]).array_element


def test_split_limits():
    jwt = "eyJh.eyJw.c2ln"

    def sized(n):  # an SD-JWT of n bytes: the JWT and one disclosure, no KB-JWT
        return jwt + "~" + "A" * (n - len(jwt) - 2) + "~"

    split(sized(1 << 20))  # exactly 1 MiB is accepted
    distinct = "".join(f"~d{i}" for i in range(1001))
    for compact in (sized((1 << 20) + 1), jwt + distinct + "~"):
        with pytest.raises(ErrMalformed):
            split(compact)


def test_split_shapes():
    jwt, kb = "aa.bb.cc", "dd.ee.ff"
    assert split(f"{jwt}~") == (jwt, [], "")
    assert split(f"{jwt}~d1~d2~") == (jwt, ["d1", "d2"], "")
    assert split(f"{jwt}~d1~{kb}") == (jwt, ["d1"], kb)
    assert split(f"{jwt}~{kb}") == (jwt, [], kb)
    for bad in (jwt, "a.b~", ".b.c~", "a..c~", "a.b.~", "a.b.c.d~", f"{jwt}~d1", f"{jwt}~~", f"{jwt}~d1~d1~"):
        with pytest.raises(ErrMalformed):
            split(bad)


# --- recreate_test.go -----------------------------------------------------------


def decode_payload(compact):
    parts = compact.split(".")
    assert len(parts) == 3
    return decode_json_object(decode_segment(parts[1]))


def test_recreate_rfc_examples():
    # Each presentation of RFC 9901 §5.2 and Appendix A.1 to A.4, as printed there, recreates exactly
    # the Processed SD-JWT Payload printed after it.
    examples = decode_json(TESTDATA.read_bytes())
    assert len(examples) >= 5
    for ex in examples:
        issuer_jwt, encoded, _ = split(ex["presentation"])
        r = recreate(decode_payload(issuer_jwt), [Disclosure(encoded=s) for s in encoded])
        assert r.claims == ex["processed_payload"], ex["source"]


def test_recreate_rejects():
    given, given_digest = disclose('["s1","given_name","A"]')
    elem, elem_digest = disclose('["s2","VN"]')
    dots, dots_digest = disclose('["s3","...","x"]')
    many, many_digests = [], []
    for i in range(1001):
        e, d = disclose(f'["s{i}","c{i}",{i}]')
        many.append(Disclosure(encoded=e))
        many_digests.append(json.dumps(d))
    D = Disclosure
    cases = [
        # §7.1 step 4: a digest value encountered more than once.
        ("digest twice", f'{{"_sd":["{given_digest}"],"x":{{"_sd":["{given_digest}"]}}}}', [D(encoded=given)], ""),
        ("same disclosure twice", "{}", [D(encoded=given), D(encoded=given)], "given twice"),
        # §7.1 step 5.
        ("unreferenced disclosure", '{"iss":"x"}', [D(encoded=given)], ""),
        # §7.1 step 5 whatever the disclosure holds: it is only hashed.
        ("unreferenced disclosure, not base64url", '{"iss":"x"}', [D(encoded="!!!")], "no digest references"),
        # §4.2.4.2: {"...": d} stands only for an array element.
        ("... outside an array", f'{{"a":{{"...":"{elem_digest}"}}}}', [], ""),
        ("... with another key in an array", f'{{"a":[{{"...":"{elem_digest}","x":1}}]}}', [], ""),
        # §4.2.1, §7.1 step 3c.ii.2: ... is never a claim name.
        ("disclosure named ...", f'{{"_sd":["{dots_digest}"]}}', [D(encoded=dots)], ""),
        # §4.1.1, §7.1 step 2d: only sha-256 is supported.
        ("_sd_alg sha-512", '{"_sd_alg":"sha-512"}', [], ""),
        ("_sd_alg number", '{"_sd_alg":1}', [], ""),
        ("_sd_alg below the top level", '{"a":{"_sd_alg":"sha-256"}}', [], "_sd_alg below"),
        # §4.2.4.1: _sd is an array of strings; null is not "absent".
        ("_sd null", '{"_sd":null}', [], "not an array"),
        ("_sd object", '{"_sd":{}}', [], "not an array"),
        ("_sd holding a number", '{"_sd":[1]}', [], "not a string"),
        # §7.1 step 3c.ii.1: a digest in _sd needs a [salt, name, value] disclosure.
        ("_sd references [salt, value]", f'{{"_sd":["{elem_digest}"]}}', [D(encoded=elem)], ""),
        # §7.1 step 3c.iii.1: an array element needs a [salt, value] disclosure.
        ("array element references [salt, name, value]", f'{{"a":[{{"...":"{given_digest}"}}]}}', [D(encoded=given)], ""),
        # §7.1 step 3c.ii.3.
        ("claim name exists", f'{{"given_name":"X","_sd":["{given_digest}"]}}', [D(encoded=given)], ""),
        ("1001 disclosures", '{"_sd":[' + ",".join(many_digests) + "]}", many, ""),
        # The payload object is level 1: 33 levels in all.
        ("depth 33", '{"a":' + "[" * 32 + "]" * 32 + "}", [], "nesting deeper"),
    ]
    for name, payload, ds, text in cases:
        with pytest.raises(ErrMalformed) as e:
            recreate(decode_json_object(payload.encode()), ds)
        assert text in str(e.value), name
    # depth 32 is fine
    recreate(decode_json_object(('{"a":' + "[" * 31 + "]" * 31 + "}").encode()), [])


def test_disclosures_select_only_the_path():
    # RFC 9901 §4.2.6: a path selects its concealed ancestors and its own disclosure, nothing else,
    # even when another concealed claim shares a name with an element of the path.
    claims = {"x": {"y": "1"}, "y": "2", "a": {"y": "3"}}
    payload, ds = conceal(claims, [["y"], ["a"], ["a", "y"]], ConcealOptions())
    names = {d.encoded: f"{d.name}={d.value}" for d in ds}
    r = recreate(payload, ds)
    for path, ok, want in (
        (["x", "y"], True, []),
        (["y"], True, ["y=2"]),
        (["a", "y"], True, ["a", "y=3"]),
        (["a", "zz"], False, []),
        ([], False, []),
        (["a", True], False, []),
    ):
        got, found = r.disclosures(path)
        got_names = ["a" if d.name == "a" else names[d.encoded] for d in got]
        assert found is ok and (not ok or got_names == want), path


def test_disclosed():
    # A claim is disclosed when it, an ancestor or a descendant came from a disclosure.
    claims = {"a": {"b": "1"}, "c": {"d": "2"}, "e": "3"}
    payload, ds = conceal(claims, [["a"], ["c", "d"]], ConcealOptions())
    r = recreate(payload, ds)
    assert r.disclosed(["a", "b"]) is True  # inside a concealed object
    assert r.disclosed(["c"]) is True  # holds a concealed claim
    assert r.disclosed(["e"]) is False
    assert r.disclosed(["missing"]) is False and r.disclosed([]) is False


def test_issued_keeps_array_places_and_hidden_fields():
    first, first_digest = disclose('["s1","VN"]')
    _, hidden_digest = disclose('["s2","FR"]')
    given, given_digest = disclose('["s3","given_name","Ana"]')
    _, family_digest = disclose('["s4","family_name","Le"]')
    payload = {
        "_sd": [given_digest, family_digest],
        "nationalities": [{"...": first_digest}, {"...": hidden_digest}, "DE"],
        "iss": "https://issuer.example",
    }
    r = recreate(payload, [Disclosure(encoded=first), Disclosure(encoded=given)])
    root = r.issued
    assert root.hidden_fields == 1 and len(root.fields) == 3 and not root.disclosed
    assert root.fields["given_name"].disclosed and not root.fields["iss"].disclosed
    elems = root.fields["nationalities"].elems
    assert len(elems) == 3
    assert elems[0].disclosed and elems[0].value == "VN"
    assert elems[1].hidden and elems[1].value is None
    assert not elems[2].disclosed and elems[2].value == "DE"
    assert root.fields["nationalities"].value == ["VN", "DE"]


def test_compare_paths_orders_longer_first_names_before_indices():
    paths = [["b"], ["a", 1], ["a", "z"], ["a", 0], ["a"], ["a", "b", "c"]]
    from functools import cmp_to_key

    assert sorted(paths, key=cmp_to_key(compare_paths)) == [["a", "b", "c"], ["a", "z"], ["a", 0], ["a", 1], ["a"], ["b"]]
