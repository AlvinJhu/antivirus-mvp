"""載入已知惡意檔案的雜湊清單。

清單格式：每行「SHA-256  威脅名稱」，# 開頭為註解。
"""
from pathlib import Path

DEFAULT_SIGNATURES = Path(__file__).resolve().parent.parent / "signatures" / "known_bad.txt"


def load_signatures(path: Path) -> dict[str, str]:
    sigs: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition(" ")
        sigs[digest.lower()] = name.strip() or "Unknown"
    return sigs
