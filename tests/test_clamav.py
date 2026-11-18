import subprocess
from pathlib import Path

import pytest

from scanner.clamav import ClamAV, ClamAVError, parse_clamscan_output


def test_parse_handles_windows_paths_and_found():
    out = (
        "C:\\Users\\a\\Downloads\\x.exe: Win.Test.EICAR_HDB-1 FOUND\n"
        "C:\\Users\\a\\Downloads\\ok.txt: OK\n"
        "C:\\locked.bin: Access denied ERROR\n"
    )
    found, errors = parse_clamscan_output(out)
    assert found == {Path("C:\\Users\\a\\Downloads\\x.exe"): "Win.Test.EICAR_HDB-1"}
    assert errors == {Path("C:\\locked.bin"): "Access denied"}


def _fake_clam(tmp_path):
    clam_dir = tmp_path / "clam"
    clam_dir.mkdir()
    (clam_dir / "clamscan.exe").write_bytes(b"")
    (clam_dir / "freshclam.exe").write_bytes(b"")
    db = tmp_path / "db"
    db.mkdir()
    return ClamAV(clam_dir, db)


def test_not_available_without_database(tmp_path):
    clam = _fake_clam(tmp_path)
    assert clam.installed and not clam.has_database and not clam.available
    (clam.db_dir / "daily.cvd").write_bytes(b"x")
    assert clam.available


def test_scan_builds_command_and_parses(tmp_path, monkeypatch):
    clam = _fake_clam(tmp_path)
    (clam.db_dir / "main.cvd").write_bytes(b"x")
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        list_arg = next(a for a in cmd if a.startswith("--file-list="))
        seen["list"] = Path(list_arg.split("=", 1)[1]).read_text(encoding="utf-8").splitlines()
        return subprocess.CompletedProcess(cmd, 1, stdout="/f/a: Eicar FOUND\n/f/b: OK\n", stderr="")

    monkeypatch.setattr("scanner.clamav.subprocess.run", fake_run)
    found, errors = clam.scan([Path("/f/a"), Path("/f/b")])
    assert found == {Path("/f/a"): "Eicar"} and errors == {}
    assert f"--database={clam.db_dir}" in seen["cmd"]
    assert "--no-summary" in seen["cmd"]
    assert seen["list"] == [str(Path("/f/a")), str(Path("/f/b"))]


def test_scan_raises_on_engine_error(tmp_path, monkeypatch):
    clam = _fake_clam(tmp_path)
    (clam.db_dir / "main.cvd").write_bytes(b"x")
    monkeypatch.setattr(
        "scanner.clamav.subprocess.run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 2, stdout="", stderr="LibClamAV Error: boom"),
    )
    with pytest.raises(ClamAVError, match="boom"):
        clam.scan([Path("/f/a")])


def test_freshclam_conf_points_to_db(tmp_path):
    clam = _fake_clam(tmp_path)
    conf = clam.write_freshclam_conf()
    text = conf.read_text(encoding="utf-8")
    assert f"DatabaseDirectory {clam.db_dir}" in text
    assert "DatabaseMirror database.clamav.net" in text
    assert "\nExample" not in text
