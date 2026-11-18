"""呼叫 ClamAV（clamscan / freshclam）。

以「外部程式」方式執行，不連結 libclamav 函式庫。
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class ClamAVError(RuntimeError):
    pass


# Windows 上執行時不要跳出黑色主控台視窗
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def parse_clamscan_output(text: str):
    """解析 clamscan 每行「路徑: 結果」。用最後一個「: 」切開，避免 C:\\ 被切錯。"""
    found, errors = {}, {}
    for line in text.splitlines():
        path, sep, status = line.rpartition(": ")
        if not sep:
            continue
        if status.endswith(" FOUND"):
            found[Path(path)] = status[: -len(" FOUND")]
        elif status.endswith(" ERROR"):
            errors[Path(path)] = status[: -len(" ERROR")]
    return found, errors


class ClamAV:
    def __init__(self, clamav_dir: Path, db_dir: Path):
        self.dir = Path(clamav_dir)
        self.db_dir = Path(db_dir)

    def _exe(self, name: str) -> Path:
        for candidate in (self.dir / f"{name}.exe", self.dir / name):
            if candidate.exists():
                return candidate
        return self.dir / f"{name}.exe"

    @property
    def installed(self) -> bool:
        return self._exe("clamscan").exists()

    @property
    def has_database(self) -> bool:
        return self.db_dir.is_dir() and any(
            p.suffix in (".cvd", ".cld") for p in self.db_dir.iterdir()
        )

    @property
    def available(self) -> bool:
        return self.installed and self.has_database

    def scan(self, paths, timeout: int = 3600):
        paths = [str(p) for p in paths]
        if not paths:
            return {}, {}
        # 檔案清單寫進暫存檔，避免 Windows 命令列長度上限（約 32,000 字元）
        fd, list_file = tempfile.mkstemp(suffix=".txt", prefix="avmvp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(paths))
            cmd = [str(self._exe("clamscan")), f"--database={self.db_dir}", "--no-summary",
                   "--stdout", f"--file-list={list_file}"]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, creationflags=_NO_WINDOW,
            )
        finally:
            os.unlink(list_file)
        if proc.returncode not in (0, 1):  # 0 = 乾淨，1 = 有發現，其他 = 引擎錯誤
            raise ClamAVError((proc.stderr or proc.stdout).strip() or f"clamscan 結束代碼 {proc.returncode}")
        return parse_clamscan_output(proc.stdout)

    def write_freshclam_conf(self) -> Path:
        self.db_dir.mkdir(parents=True, exist_ok=True)
        conf = self.db_dir / "freshclam.conf"
        conf.write_text(
            f"DatabaseDirectory {self.db_dir}\n"
            "DatabaseMirror database.clamav.net\n"
            "Checks 12\n",
            encoding="utf-8",
        )
        return conf

    def update(self, timeout: int = 1800) -> str:
        """下載或更新病毒碼，回傳 freshclam 的輸出。"""
        conf = self.write_freshclam_conf()
        proc = subprocess.run(
            [str(self._exe("freshclam")), f"--config-file={conf}", f"--datadir={self.db_dir}", "--stdout"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, creationflags=_NO_WINDOW,
        )
        if proc.returncode != 0:
            raise ClamAVError((proc.stderr or proc.stdout).strip()[-2000:])
        return proc.stdout
