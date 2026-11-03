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
