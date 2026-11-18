from scanner.config import AppPaths


def test_paths_under_home_override(tmp_path, monkeypatch):
    monkeypatch.setenv("AVMVP_HOME", str(tmp_path / "home"))
    p = AppPaths.default()
    p.ensure()
    assert p.data_dir == tmp_path / "home"
    for d in (p.quarantine_dir, p.clamav_db_dir):
        assert d.is_dir() and d.parent == p.data_dir
    assert p.history_db.parent == p.data_dir


def test_clamav_dir_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("AVMVP_HOME", str(tmp_path))
    monkeypatch.setenv("AVMVP_CLAMAV_DIR", str(tmp_path / "clam"))
    assert AppPaths.default().clamav_dir == tmp_path / "clam"
