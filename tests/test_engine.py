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


class FakeClam:
    available = True

    def __init__(self, hits):
        self.hits = hits
        self.calls = []

    def scan(self, paths):
        self.calls.append(list(paths))
        return {p: self.hits[p.name] for p in paths if p.name in self.hits}, {}


def test_clamav_runs_on_files_not_caught_by_hash(sample_dir, test_signatures):
    clam = FakeClam({"clean.txt": "Clam.Detected"})
    results = scan_path(sample_dir, load_signatures(test_signatures), clamav=clam)
    by_name = {r.path.name: r for r in results}
    assert by_name["clean.txt"].threat == "Clam.Detected"
    assert by_name["fake_malware.bin"].threat == FAKE_THREAT
    # 已被雜湊抓到的檔案不再送 ClamAV
    assert [p.name for p in clam.calls[0]] == ["clean.txt"]


def test_progress_callback(sample_dir, test_signatures):
    seen = []
    scan_path(sample_dir, load_signatures(test_signatures), progress=lambda done, total: seen.append((done, total)))
    assert seen[-1] == (2, 2)
