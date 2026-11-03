from didv2.subdid.key import derive_sub_did_key

SUB_IDS1 = "0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5"


def test_kdf_row1() -> None:
    r1 = "11" * 32
    key = derive_sub_did_key(r1, SUB_IDS1)
    assert key["privateKeyHex"] == "0x46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8"
    assert key["publicKeyHex"] == "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"
    assert key["p256X"] + key["p256Y"] == (
        "1073cf0910ef789f09d6e2aba3c17fa51465b3b65730dd733dcb1f9a090bd8f72232ca28606fda872acc3dc833ab910cf94956654bac5c8c31dd5f3ff88099a9"
    )


def test_refuses_short_root() -> None:
    try:
        derive_sub_did_key("22" * 31, SUB_IDS1)
        raise AssertionError("expected error")
    except ValueError:
        pass
