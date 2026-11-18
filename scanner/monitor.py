"""監控資料夾：有新檔案出現就交給回呼函式（通常是掃描）。"""
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# 瀏覽器下載中的暫存檔，等下載完成改名後再掃
PARTIAL_SUFFIXES = {".crdownload", ".part", ".partial", ".download", ".tmp"}


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor: "FolderMonitor"):
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.monitor._schedule(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self.monitor._schedule(Path(event.dest_path))


class FolderMonitor:
    def __init__(self, folder: Path, on_file, settle_seconds: float = 2.0):
        self.folder = Path(folder)
        self.on_file = on_file
        self.settle = settle_seconds
        self._observer = None
        self._pending: dict[Path, threading.Timer] = {}
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._observer is not None

    def _schedule(self, path: Path):
        if path.suffix.lower() in PARTIAL_SUFFIXES:
            return
        with self._lock:  # 同一個檔案短時間內多次事件只處理一次
            if path in self._pending:
                self._pending[path].cancel()
            t = threading.Timer(self.settle, self._fire, args=(path,))
            t.daemon = True
            self._pending[path] = t
            t.start()

    def _fire(self, path: Path):
        with self._lock:
            self._pending.pop(path, None)
        # 等檔案大小穩定（寫入完成）再處理
        last = -1
        for _ in range(30):
            try:
                size = path.stat().st_size
            except OSError:
                return
            if size == last:
                break
            last = size
            time.sleep(self.settle)
        self.on_file(path)

    def start(self):
        if self._observer:
            return
        self._observer = Observer()
        self._observer.schedule(_Handler(self), str(self.folder), recursive=False)
        self._observer.start()

    def stop(self):
        if not self._observer:
            return
        self._observer.stop()
        self._observer.join(timeout=5)
        self._observer = None
        with self._lock:
            for t in self._pending.values():
                t.cancel()
            self._pending.clear()
