"""程式使用的資料夾位置。

資料放在 %LOCALAPPDATA%\\AntivirusMVP（不需要系統管理員權限）。
測試時可用環境變數 AVMVP_HOME、AVMVP_CLAMAV_DIR 改位置。
"""
import os
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "AntivirusMVP"


def _app_dir() -> Path:
    # 打包成 .exe 後，程式所在資料夾；開發時是專案根目錄
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


@dataclass
class AppPaths:
    data_dir: Path
    clamav_dir: Path

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def clamav_db_dir(self) -> Path:
        return self.data_dir / "clamav-db"

    @property
    def history_db(self) -> Path:
        return self.data_dir / "history.db"

    @property
    def settings_file(self) -> Path:
        return self.data_dir / "settings.json"

    @classmethod
    def default(cls) -> "AppPaths":
        home = os.environ.get("AVMVP_HOME")
        if home:
            data = Path(home)
        else:
            base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
            data = Path(base) / APP_NAME
        clam = os.environ.get("AVMVP_CLAMAV_DIR")
        return cls(data_dir=data, clamav_dir=Path(clam) if clam else _app_dir() / "clamav")

    def ensure(self) -> None:
        for d in (self.data_dir, self.quarantine_dir, self.clamav_db_dir):
            d.mkdir(parents=True, exist_ok=True)
