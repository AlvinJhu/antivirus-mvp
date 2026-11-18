from pathlib import Path

from scanner.engine import ScanResult
from scanner.history import History


def test_record_and_recent(tmp_path):
    h = History(tmp_path / "h.db")
    h.record("C:/a", [ScanResult(Path("x"), True, "T"), ScanResult(Path("y")), ScanResult(Path("z"), error="e")])
    h.record("C:/b", [])
    rows = h.recent()
    assert [r.target for r in rows] == ["C:/b", "C:/a"]  # 最新的在前
    assert (rows[1].files, rows[1].threats, rows[1].errors) == (3, 1, 1)
    assert rows[1].threat_names == ["x: T"]


def test_persists(tmp_path):
    History(tmp_path / "h.db").record("t", [])
    assert len(History(tmp_path / "h.db").recent()) == 1
