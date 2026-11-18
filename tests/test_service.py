import pytest

from scanner.config import AppPaths
from scanner.service import AppService
from conftest import FAKE_MALWARE, FAKE_THREAT


@pytest.fixture
def svc(tmp_path, test_signatures):
    paths = AppPaths(data_dir=tmp_path / "data", clamav_dir=tmp_path / "no-clamav")
    return AppService(paths, signatures_file=test_signatures)


def test_scan_records_history_and_quarantines(svc, sample_dir):
    results = svc.scan(sample_dir)
    infected = [r for r in results if r.infected]
    assert infected and infected[0].threat == FAKE_THREAT
    assert svc.history.recent()[0].threats == 1

    moved = svc.quarantine_results(infected)
    assert moved == 1 and not infected[0].path.exists()
    assert svc.quarantine.list()[0].threat == FAKE_THREAT


def test_auto_quarantine_on_monitored_file(svc, tmp_path):
    f = tmp_path / "dl.bin"
    f.write_bytes(FAKE_MALWARE)
    events = []
    svc.handle_new_file(f, notify=events.append)
    assert not f.exists() and len(svc.quarantine.list()) == 1
    assert FAKE_THREAT in events[0]


def test_clean_monitored_file_untouched(svc, tmp_path):
    f = tmp_path / "ok.txt"
    f.write_text("ok", encoding="utf-8")
    events = []
    svc.handle_new_file(f, notify=events.append)
    assert f.exists() and events == []


def test_settings_roundtrip(svc, tmp_path, test_signatures):
    svc.settings["safe_browsing_key"] = "abc"
    svc.save_settings()
    again = AppService(svc.paths, signatures_file=test_signatures)
    assert again.settings["safe_browsing_key"] == "abc"


def test_engine_status_without_clamav(svc):
    assert "ClamAV" in svc.engine_status() and not svc.clamav.available
