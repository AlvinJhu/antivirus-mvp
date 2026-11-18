import pytest

# EICAR 標準測試字串，分段組合，避免原始碼檔本身被防毒軟體刪除。
_EICAR_PARTS = [
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
    "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
    "$H+H*",
]


@pytest.fixture
def eicar_bytes():
    return "".join(_EICAR_PARTS).encode("ascii")


@pytest.fixture
def sample_dir(tmp_path, eicar_bytes):
    """建立測試資料夾：一個乾淨檔、一個 EICAR 檔（放在子資料夾）。"""
    (tmp_path / "clean.txt").write_text("hello", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "eicar.com").write_bytes(eicar_bytes)
    return tmp_path
