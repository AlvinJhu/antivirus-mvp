"""掃描單一檔案或整個資料夾。"""
from dataclasses import dataclass
from pathlib import Path

from scanner.hasher import sha256_file


@dataclass
class ScanResult:
    path: Path
    infected: bool = False
    threat: str | None = None
    error: str | None = None


def _iter_files(target: Path):
    if target.is_file():
        yield target
    else:
        yield from sorted(p for p in target.rglob("*") if p.is_file())


def scan_path(target: Path, signatures: dict[str, str]) -> list[ScanResult]:
    results = []
    for f in _iter_files(Path(target)):
        try:
            digest = sha256_file(f)
        except OSError as e:  # 檔案被鎖住或沒有權限：記錄下來，繼續掃下一個
            results.append(ScanResult(f, error=str(e)))
            continue
        threat = signatures.get(digest)
        results.append(ScanResult(f, infected=threat is not None, threat=threat))
    return results
