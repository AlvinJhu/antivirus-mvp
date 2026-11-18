import threading

from scanner.monitor import FolderMonitor


def test_new_file_triggers_callback(tmp_path):
    got = []
    done = threading.Event()

    def on_file(p):
        got.append(p)
        done.set()

    m = FolderMonitor(tmp_path, on_file, settle_seconds=0.2)
    m.start()
    try:
        (tmp_path / "new.bin").write_bytes(b"data")
        assert done.wait(5), "沒有偵測到新檔案"
    finally:
        m.stop()
    assert got[0].name == "new.bin"


def test_ignores_partial_download_files(tmp_path):
    got = []
    m = FolderMonitor(tmp_path, got.append, settle_seconds=0.1)
    m.start()
    try:
        (tmp_path / "file.crdownload").write_bytes(b"x")
        (tmp_path / "ok.txt").write_bytes(b"x")
        import time

        for _ in range(50):
            if got:
                break
            time.sleep(0.1)
        time.sleep(0.3)
    finally:
        m.stop()
    assert [p.name for p in got] == ["ok.txt"]
