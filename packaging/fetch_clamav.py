"""下載官方 ClamAV Windows 版，驗證 SHA-256，只取出執行需要的檔案。

用法：python packaging/fetch_clamav.py <輸出資料夾>
"""
import hashlib
import sys
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1.5.4"
URL = f"https://github.com/Cisco-Talos/clamav/releases/download/clamav-{VERSION}/clamav-{VERSION}.win.x64.zip"
SHA256 = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395"
KEEP_EXE = {"clamscan.exe", "freshclam.exe", "sigtool.exe"}


def keep(name: str) -> bool:
    parts = name.split("/", 1)
    if len(parts) < 2 or not parts[1] or name.endswith("/"):
        return False
    rel = parts[1]
    if rel.startswith(("COPYING", "certs/")) or rel in ("README.md", "NEWS.md"):
        return True
    return "/" not in rel and (rel.endswith(".dll") or rel in KEEP_EXE)


def main(out: Path) -> None:
    zip_path = out.parent / f"clamav-{VERSION}.zip"
    out.parent.mkdir(parents=True, exist_ok=True)
    if not zip_path.exists():
        print("下載", URL)
        urllib.request.urlretrieve(URL, zip_path)
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    if digest != SHA256:
        sys.exit(f"SHA-256 不符：{digest}")
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            if keep(info.filename):
                target = out / info.filename.split("/", 1)[1]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(info))
    (out / "SOURCE.txt").write_text(
        f"ClamAV {VERSION} 由 Cisco Talos 以 GNU GPL v2 授權發佈。\n"
        f"原始碼：https://github.com/Cisco-Talos/clamav/tree/clamav-{VERSION}\n"
        "授權條款見 COPYING.txt 與 COPYING 資料夾。\n",
        encoding="utf-8",
    )
    print("完成：", sorted(p.name for p in out.iterdir()))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
