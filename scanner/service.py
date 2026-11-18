"""把各模組串起來，給視窗介面使用。這一層不碰任何視窗元件，方便測試。"""
import json
from pathlib import Path

from scanner.clamav import ClamAV
from scanner.config import AppPaths
from scanner.engine import scan_path
from scanner.history import History
from scanner.quarantine import Quarantine
from scanner.signatures import DEFAULT_SIGNATURES, load_signatures
from scanner.url_check import check_url

DEFAULT_SETTINGS = {"safe_browsing_key": "", "monitor_folder": str(Path.home() / "Downloads"), "monitor_on_start": False}


class AppService:
    def __init__(self, paths: AppPaths | None = None, signatures_file: Path = DEFAULT_SIGNATURES):
        self.paths = paths or AppPaths.default()
        self.paths.ensure()
        self.signatures = load_signatures(signatures_file)
        self.clamav = ClamAV(self.paths.clamav_dir, self.paths.clamav_db_dir)
        self.quarantine = Quarantine(self.paths.quarantine_dir)
        self.history = History(self.paths.history_db)
        self.settings = dict(DEFAULT_SETTINGS)
        if self.paths.settings_file.exists():
            self.settings.update(json.loads(self.paths.settings_file.read_text(encoding="utf-8")))

    def save_settings(self):
        self.paths.settings_file.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")

    def engine_status(self) -> str:
        if not self.clamav.installed:
            return f"雜湊比對：{len(self.signatures)} 筆｜ClamAV：未安裝"
        if not self.clamav.has_database:
            return f"雜湊比對：{len(self.signatures)} 筆｜ClamAV：尚未下載病毒碼（請到設定按「更新病毒碼」）"
        return f"雜湊比對：{len(self.signatures)} 筆｜ClamAV：可使用"

    def scan(self, target: Path, progress=None):
        results = scan_path(Path(target), self.signatures, clamav=self.clamav, progress=progress)
        self.history.record(str(target), results)
        return results

    def quarantine_results(self, results) -> int:
        moved = 0
        for r in results:
            if r.infected and r.path.exists():
                self.quarantine.add(r.path, r.threat)
                moved += 1
        return moved

    def handle_new_file(self, path: Path, notify):
        """監控到新檔案：掃描，有威脅就自動隔離並通知。"""
        results = self.scan(path)
        infected = [r for r in results if r.infected]
        if infected:
            self.quarantine_results(infected)
            notify(f"已自動隔離：{path.name}（{infected[0].threat}）")

    def check_url(self, url: str):
        return check_url(url, self.settings.get("safe_browsing_key") or None)

    def update_database(self) -> str:
        return self.clamav.update()
