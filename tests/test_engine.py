from scanner.engine import scan_path
from scanner.signatures import load_signatures

from conftest import FAKE_THREAT


def test_scan_folder_finds_only_fake_malware(sample_dir, test_signatures):
    results = scan_path(sample_dir, load_signatures(test_signatures))
    infected = [r for r in results if r.infected]
    assert len(results) == 2
    assert [r.path.name for r in infected] == ["fake_malware.bin"]
    assert infected[0].threat == FAKE_THREAT


def test_scan_single_file(sample_dir, test_signatures):
    results = scan_path(sample_dir / "clean.txt", load_signatures(test_signatures))
    assert len(results) == 1 and not results[0].infected


def test_unreadable_file_reported_not_crash(tmp_path, monkeypatch):
    f = tmp_path / "locked.bin"
    f.write_bytes(b"x")

    def boom(_):
        raise PermissionError("locked")

    monkeypatch.setattr("scanner.engine.sha256_file", boom)
    results = scan_path(f, {})
    assert results[0].error and not results[0].infected
