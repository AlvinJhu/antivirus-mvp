import hashlib

import pytest

# EICAR 標準測試字串，分段組合，避免原始碼檔本身被防毒軟體刪除。
# 只在記憶體中使用：寫到硬碟會被 Windows Defender 立刻刪掉。
_EICAR_PARTS = [
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
    "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
    "$H+H*",
]

# 落地測試用的「假惡意檔」：內容無害，只是把它的雜湊放進測試用清單。
FAKE_MALWARE = b"harmless fake malware sample for unit tests"
FAKE_THREAT = "Test.FakeMalware"


@pytest.fixture
def eicar_bytes():
    return "".join(_EICAR_PARTS).encode("ascii")


@pytest.fixture
def test_signatures(tmp_path):
    """測試用的雜湊清單，只包含假惡意檔。"""
    f = tmp_path / "test_sigs.txt"
    f.write_text(f"{hashlib.sha256(FAKE_MALWARE).hexdigest()}  {FAKE_THREAT}\n", encoding="utf-8")
    return f


@pytest.fixture
def sample_dir(tmp_path):
    """建立測試資料夾：一個乾淨檔、一個假惡意檔（放在子資料夾）。"""
    root = tmp_path / "samples"
    root.mkdir()
    (root / "clean.txt").write_text("hello", encoding="utf-8")
    sub = root / "sub"
    sub.mkdir()
    (sub / "fake_malware.bin").write_bytes(FAKE_MALWARE)
    return root
