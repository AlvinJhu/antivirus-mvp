import pytest

from scanner.quarantine import Quarantine
from conftest import FAKE_MALWARE


@pytest.fixture
def q(tmp_path):
    return Quarantine(tmp_path / "quarantine")


def test_quarantine_moves_and_obfuscates(tmp_path, q):
    f = tmp_path / "bad.exe"
    f.write_bytes(FAKE_MALWARE)
    item = q.add(f, "Test.FakeMalware")
    assert not f.exists()
    stored = q.dir / f"{item.id}.quar"
    assert stored.exists() and stored.read_bytes() != FAKE_MALWARE  # 內容已混淆，無法直接執行
    assert [i.id for i in q.list()] == [item.id]
    assert q.list()[0].original_path == f and q.list()[0].threat == "Test.FakeMalware"


def test_restore_returns_original_bytes(tmp_path, q):
    f = tmp_path / "bad.exe"
    f.write_bytes(FAKE_MALWARE)
    item = q.add(f, "T")
    restored = q.restore(item.id)
    assert restored == f and f.read_bytes() == FAKE_MALWARE
    assert q.list() == []


def test_restore_does_not_overwrite_existing(tmp_path, q):
    f = tmp_path / "bad.exe"
    f.write_bytes(FAKE_MALWARE)
    item = q.add(f, "T")
    f.write_bytes(b"new file with same name")
    restored = q.restore(item.id)
    assert restored != f and restored.read_bytes() == FAKE_MALWARE
    assert f.read_bytes() == b"new file with same name"


def test_delete_removes_permanently(tmp_path, q):
    f = tmp_path / "bad.exe"
    f.write_bytes(FAKE_MALWARE)
    item = q.add(f, "T")
    q.delete(item.id)
    assert q.list() == [] and not any(q.dir.glob("*.quar"))


def test_index_survives_reload(tmp_path, q):
    f = tmp_path / "bad.exe"
    f.write_bytes(FAKE_MALWARE)
    item = q.add(f, "T")
    assert [i.id for i in Quarantine(q.dir).list()] == [item.id]
