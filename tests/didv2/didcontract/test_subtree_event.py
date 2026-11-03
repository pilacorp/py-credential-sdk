from didv2.didcontract.subtree_event import Receipt, ReceiptLog, decode_writer_anchors, pack_writer_log_data, writer_log_topic1

REGISTRY = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a"
WRITER = "0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3"
ROOT = bytes.fromhex("740265369adf60c8f89f0a3b1f92feb3643c702d228a8894c900006384e59a9f")


def test_decode_writer_anchors_from_receipt_log():
    from didv2.didcontract.contract import writer_anchor_topic0

    data = pack_writer_log_data(
        ["0x2222222222222222222222222222222222222222"],
        [0xDD],
        [ROOT],
    )
    receipt = Receipt(
        status=1,
        logs=[
            ReceiptLog(
                address=REGISTRY,
                topics=[writer_anchor_topic0(), writer_log_topic1(WRITER)],
                data=data,
            )
        ],
    )
    anchors = decode_writer_anchors(receipt, REGISTRY)
    assert len(anchors) == 1
    assert anchors[0].writer.lower() == WRITER.lower()
    assert anchors[0].root == ROOT
