"""隔離區：把可疑檔案移走並混淆內容，避免被誤開啟。"""
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

_KEY = 0xA5  # 簡單 XOR 混淆：檔案無法直接執行，也不會被其他防毒軟體重複偵測


def _xor(data: bytes) -> bytes:
    return bytes(b ^ _KEY for b in data)


@dataclass
class QuarantineItem:
    id: str
    original_path: Path
    threat: str
    quarantined_at: str


class Quarantine:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._index = self.dir / "index.json"

    def _load(self) -> dict:
        if not self._index.exists():
            return {}
        return json.loads(self._index.read_text(encoding="utf-8"))

    def _save(self, data: dict) -> None:
        tmp = self._index.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self._index)

    def list(self) -> list[QuarantineItem]:
        return [
            QuarantineItem(i, Path(v["original_path"]), v["threat"], v["quarantined_at"])
            for i, v in self._load().items()
        ]

    def add(self, path: Path, threat: str) -> QuarantineItem:
        path = Path(path)
        item = QuarantineItem(uuid.uuid4().hex, path, threat, datetime.now().isoformat(timespec="seconds"))
        (self.dir / f"{item.id}.quar").write_bytes(_xor(path.read_bytes()))
        path.unlink()
        data = self._load()
        rec = asdict(item)
        rec["original_path"] = str(path)
        data[item.id] = rec
        self._save(data)
        return item

    def restore(self, item_id: str) -> Path:
        data = self._load()
        target = Path(data[item_id]["original_path"])
        if target.exists():  # 不覆蓋同名檔案
            n = 1
            while (candidate := target.with_name(f"{target.stem}.restored{n}{target.suffix}")).exists():
                n += 1
            target = candidate
        target.parent.mkdir(parents=True, exist_ok=True)
        stored = self.dir / f"{item_id}.quar"
        target.write_bytes(_xor(stored.read_bytes()))
        stored.unlink()
        del data[item_id]
        self._save(data)
        return target

    def delete(self, item_id: str) -> None:
        data = self._load()
        (self.dir / f"{item_id}.quar").unlink(missing_ok=True)
        data.pop(item_id, None)
        self._save(data)
