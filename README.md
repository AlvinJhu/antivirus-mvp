# 防毒測試（自用學習版）

Windows 11 桌面防毒工具，Python 撰寫。目前完成**階段 1：命令列雜湊掃描器**。

## 安裝（只需一次）

1. 安裝 Python 3.12 以上（安裝時勾選 *Add python.exe to PATH*）
2. 在本資料夾開啟終端機，執行：

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 使用

```
python -m scanner C:\要掃描的資料夾
```

結束代碼：0 = 乾淨，1 = 發現威脅，2 = 參數錯誤。

## 測試

```
python -m pytest
```

測試只使用 EICAR 標準測試字串（無害），執行時才組合出來，不會在硬碟留下測試檔。

## 結構

| 檔案 | 用途 |
| --- | --- |
| `scanner/hasher.py` | 計算 SHA-256 |
| `scanner/signatures.py` | 載入惡意雜湊清單 |
| `scanner/engine.py` | 掃描檔案或資料夾 |
| `scanner/__main__.py` | 命令列介面 |
| `signatures/known_bad.txt` | 惡意雜湊清單（目前只有 EICAR） |
