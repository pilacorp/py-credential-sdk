from credential.common.util.compress import compress, decompress


def test_gzip_roundtrip():
    data = b"status-list-payload"
    assert decompress(compress(data)) == data
