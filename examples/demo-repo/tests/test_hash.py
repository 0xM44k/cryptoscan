import hashlib
def test_sha256():
    assert hashlib.sha256(b"a").hexdigest()
