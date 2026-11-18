# AntivirusMVP 防毒

Windows 10／11 桌面防毒工具（學習專案），Python 撰寫，搭配開源 ClamAV 引擎。
屬於「按需掃描」，可以和 Windows Defender 同時使用，不會衝突。

## 功能

| 分頁 | 功能 |
| --- | --- |
| 掃描 | 掃描檔案或資料夾：先比對 SHA-256 雜湊，再交給 ClamAV |
| 隔離區 | 中毒檔移入隔離區（內容混淆，無法執行），可還原或永久刪除 |
| 自動監控 | 監控資料夾（預設「下載」），新檔案自動掃描，有威脅就自動隔離 |
| 網址檢查 | 本機規則（IP 網址、Punycode、@ 偽裝、非 HTTPS）＋ Google Safe Browsing（選填金鑰） |
| 紀錄 | 每次掃描的時間、檔案數、威脅數 |
| 設定 | 更新病毒碼、Safe Browsing 金鑰 |

## 下載安裝程式

GitHub 的 Windows 主機會自動測試並打包：

1. 到 [Actions](https://github.com/AlvinJhu/antivirus-mvp/actions) 點最新一次成功的「測試與打包」
2. 在頁面下方 **Artifacts** 下載 `AntivirusMVP-Setup`，解壓縮後執行 `AntivirusMVP-Setup-x.y.z.exe`
3. 推送 `v0.1.0` 這類標籤時，安裝程式也會放到 [Releases](https://github.com/AlvinJhu/antivirus-mvp/releases)

安裝程式不需要系統管理員權限，安裝到 `%LOCALAPPDATA%\Programs\AntivirusMVP`。
第一次開啟會自動下載 ClamAV 病毒碼（數百 MB，需要幾分鐘）。

> 安裝程式尚未做程式碼簽章，Windows 會顯示「Windows 已保護您的電腦」，點「其他資訊 → 仍要執行」即可。

### 釘選到工作列

Windows 不允許安裝程式自動釘選工作列。安裝後在「開始」功能表找到 **AntivirusMVP 防毒**，按右鍵 →「釘選到工作列」。

## 開發

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m pytest            # 單元測試
python antivirus_mvp.py     # 開啟視窗（沒有 ClamAV 時只用雜湊比對）
python -m scanner <路徑>     # 命令列掃描
```

測試只用無害的假樣本；EICAR 測試字串只在記憶體中使用，不寫入硬碟，避免被 Windows Defender 刪除。

## 結構

| 檔案 | 用途 |
| --- | --- |
| `scanner/hasher.py`、`signatures.py` | SHA-256 計算、惡意雜湊清單 |
| `scanner/clamav.py` | 呼叫 clamscan／freshclam（外部程式，不連結 libclamav） |
| `scanner/engine.py` | 掃描流程：雜湊 → ClamAV |
| `scanner/quarantine.py` | 隔離區 |
| `scanner/monitor.py` | 資料夾監控（watchdog） |
| `scanner/url_check.py` | 網址檢查 |
| `scanner/history.py` | 掃描紀錄（SQLite） |
| `scanner/service.py` | 串接各模組，給視窗使用 |
| `scanner/app.py` | 桌面視窗（tkinter） |
| `packaging/` | 下載 ClamAV、Inno Setup 安裝腳本、第三方授權說明 |
| `.github/workflows/build.yml` | 在 Windows 主機測試、打包、製作與實測安裝程式 |

## 授權

本專案為免費開源軟體，以 [GNU GPL v2](LICENSE) 授權：任何人都可以免費使用、修改、散布，但散布修改版時也必須公開原始碼並採用相同授權。
內含的 ClamAV 同樣以 GNU GPL v2 授權，說明見 `packaging/THIRD_PARTY_NOTICES.txt`。
Google Safe Browsing API 僅限非商業用途。
