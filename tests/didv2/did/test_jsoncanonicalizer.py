from didv2.did.jsoncanonicalizer import transform


def test_object_key_order() -> None:
    assert transform('{"b":1,"a":2}') == b'{"a":2,"b":1}'


def test_depth_limit() -> None:
    nested: dict = {}
    cur = nested
    for _ in range(300):
        nxt: dict = {}
        cur["n"] = nxt
        cur = nxt
    try:
        transform(nested)
        raise AssertionError("expected depth error")
    except ValueError:
        pass


def test_lone_surrogate_rejected_with_clear_error() -> None:
    for value in ('{"a":"\\ud800"}', {"a": "\ud800"}, {"\udfff": 1}, ["x\ud800y"]):
        try:
            transform(value)
            raise AssertionError("expected lone surrogate error")
        except ValueError as exc:
            assert "lone surrogate" in str(exc)


def test_surrogate_pair_escape_is_kept() -> None:
    assert transform('{"a":"\\ud83d\\ude00"}') == '{"a":"😀"}'.encode()


def test_deep_text_is_value_error_not_recursion_error() -> None:
    for text in ("[" * 100_000 + "]" * 100_000, '{"a":' * 100_000 + "1" + "}" * 100_000):
        try:
            transform(text)
            raise AssertionError("expected depth error")
        except ValueError as exc:
            assert "nesting exceeds maximum depth" in str(exc)
