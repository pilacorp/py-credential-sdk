"""Port of go-credential-sdk/credential/common/sdjwt/path_test.go."""
import pytest

from credential.common.sdjwt.disclosure import TARGET_ARRAY_ELEM, parse_path, resolve_path


def test_parse_path():
    segs = parse_path("credentialSubject.emails[1].city")
    assert [(s.key, s.index) for s in segs] == [("credentialSubject", None), ("emails", 1), ("city", None)]


@pytest.mark.parametrize(
    "path,want",
    [
        ("emails[", "invalid array segment"),
        ("emails[]", "empty index"),
        ("emails[*]", "wildcard index"),
        ("emails[abc]", "invalid index"),
    ],
)
def test_parse_path_invalid_cases(path, want):
    with pytest.raises(ValueError, match=want):
        parse_path(path)


def test_resolve_path_array_element_metadata():
    vc = {"credentialSubject": {"emails": ["a@example.com", "b@example.com"]}}
    resolved = resolve_path(vc, "credentialSubject.emails[1]")
    assert resolved is not None
    assert resolved.kind == TARGET_ARRAY_ELEM
    assert resolved.parent_key == "emails"
    assert resolved.parent_map is not None and "emails" in resolved.parent_map


def test_resolve_path_array_index_out_of_range():
    with pytest.raises(ValueError, match="out of range"):
        resolve_path({"credentialSubject": {"emails": ["a@example.com"]}}, "credentialSubject.emails[2]")


def test_resolve_path_segment_type_mismatch():
    with pytest.raises(ValueError, match="expects array"):
        resolve_path({"credentialSubject": {"emails": "not-an-array"}}, "credentialSubject.emails[0]")
