"""掃描紀錄（SQLite）。"""
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class HistoryRow:
    when: str
    target: str
    files: int
    threats: int
    errors: int
    threat_names: list[str]


class History:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, at TEXT, target TEXT,"
                " files INTEGER, threats INTEGER, errors INTEGER, details TEXT)"
            )

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def record(self, target: str, results) -> None:
        names = [f"{r.path.name}: {r.threat}" for r in results if r.infected]
        with self._conn() as c:
            c.execute(
                "INSERT INTO scans (at, target, files, threats, errors, details) VALUES (?,?,?,?,?,?)",
                (
                    datetime.now().isoformat(sep=" ", timespec="seconds"),
                    str(target),
                    len(results),
                    len(names),
                    sum(1 for r in results if r.error),
                    json.dumps(names, ensure_ascii=False),
                ),
            )

    def recent(self, limit: int = 100) -> list[HistoryRow]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT at, target, files, threats, errors, details FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [HistoryRow(a, t, f, th, e, json.loads(d)) for a, t, f, th, e, d in rows]
