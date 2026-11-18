"""計算檔案的 SHA-256 雜湊值。"""
import hashlib
from pathlib import Path

CHUNK_SIZE = 64 * 1024  # 每次讀 64KB，大檔案也不會吃光記憶體


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()
