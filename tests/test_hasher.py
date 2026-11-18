import hashlib

from scanner.hasher import sha256_file


def test_sha256_matches_hashlib(tmp_path):
    f = tmp_path / "a.bin"
    data = b"abc" * 100_000  # 比讀取區塊大，確認分段讀取正確
    f.write_bytes(data)
    assert sha256_file(f) == hashlib.sha256(data).hexdigest()


def test_empty_file(tmp_path):
    f = tmp_path / "empty"
    f.write_bytes(b"")
    assert sha256_file(f) == hashlib.sha256(b"").hexdigest()
