"""命令列用法：python -m scanner <檔案或資料夾>

結束代碼：0 = 乾淨，1 = 發現威脅，2 = 參數錯誤。
"""
import argparse
import sys
from pathlib import Path

from scanner.engine import scan_path
from scanner.signatures import DEFAULT_SIGNATURES, load_signatures


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="scanner", description="雜湊比對掃描器")
    parser.add_argument("target", help="要掃描的檔案或資料夾")
    parser.add_argument("--signatures", default=DEFAULT_SIGNATURES, help="惡意雜湊清單路徑")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"找不到：{target}", file=sys.stderr)
        return 2

    results = scan_path(target, load_signatures(args.signatures))
    infected = [r for r in results if r.infected]
    errors = [r for r in results if r.error]

    for r in infected:
        print(f"[威脅] {r.path}  ->  {r.threat}")
    for r in errors:
        print(f"[略過] {r.path}  ({r.error})")
    print(f"\n共掃描 {len(results)} 個檔案，發現 {len(infected)} 個威脅，略過 {len(errors)} 個。")
    return 1 if infected else 0


if __name__ == "__main__":
    sys.exit(main())
