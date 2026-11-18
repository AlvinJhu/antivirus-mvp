"""掃描單一檔案或整個資料夾：先比對雜湊，再交給 ClamAV（若可用）。"""
from dataclasses import dataclass
from pathlib import Path

from scanner.hasher import sha256_file


@dataclass
class ScanResult:
    path: Path
    infected: bool = False
    threat: str | None = None
    error: str | None = None


def iter_files(target: Path):
    target = Path(target)
    if target.is_file():
        yield target
    else:
        yield from sorted(p for p in target.rglob("*") if p.is_file())


def scan_path(target: Path, signatures: dict[str, str], clamav=None, progress=None) -> list[ScanResult]:
    files = list(iter_files(target))
    results: list[ScanResult] = []
    for i, f in enumerate(files, 1):
        try:
            digest = sha256_file(f)
        except OSError as e:  # 檔案被鎖住或沒有權限：記錄下來，繼續掃下一個
            results.append(ScanResult(f, error=str(e)))
        else:
            threat = signatures.get(digest)
            results.append(ScanResult(f, infected=threat is not None, threat=threat))
        if progress:
            progress(i, len(files))

    if clamav is not None and getattr(clamav, "available", False):
        pending = [r for r in results if not r.infected and not r.error]
        if pending:
            found, errors = clamav.scan([r.path for r in pending])
            for r in pending:
                if r.path in found:
                    r.infected, r.threat = True, found[r.path]
                elif r.path in errors:
                    r.error = errors[r.path]
    return results
