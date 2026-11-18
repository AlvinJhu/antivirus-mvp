"""桌面視窗（tkinter，Python 內建，不需另外安裝）。

耗時的工作（掃描、更新病毒碼、網址查詢）都丟到背景執行緒，
結果透過 queue 回到主執行緒更新畫面，視窗才不會卡住。
"""
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from scanner.monitor import FolderMonitor
from scanner.service import AppService

APP_TITLE = "AntivirusMVP 防毒"


class App:
    def __init__(self, root: tk.Tk, service: AppService | None = None):
        self.root = root
        self.svc = service or AppService()
        self.events: queue.Queue = queue.Queue()
        self.last_results = []
        self.monitor: FolderMonitor | None = None

        root.title(APP_TITLE)
        root.geometry("860x560")
        root.minsize(640, 420)

        self.status = tk.StringVar(value=self.svc.engine_status())
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        ttk.Label(root, textvariable=self.status, anchor="w").pack(fill="x", padx=10, pady=6)

        self._build_scan_tab(nb)
        self._build_quarantine_tab(nb)
        self._build_monitor_tab(nb)
        self._build_url_tab(nb)
        self._build_history_tab(nb)
        self._build_settings_tab(nb)

        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self._drain_events)
        if self.svc.settings.get("monitor_on_start"):
            self.toggle_monitor()
        if self.svc.clamav.installed and not self.svc.clamav.has_database:
            # 第一次開啟：自動下載病毒碼
            root.after(500, self.update_db)

    # ---------- 共用 ----------
    def _run_bg(self, work, done, error_title="發生錯誤"):
        def runner():
            try:
                result = work()
            except Exception as e:  # 背景錯誤送回主執行緒顯示
                msg = str(e) or type(e).__name__
                self.events.put(lambda: messagebox.showerror(error_title, msg))
                self.events.put(lambda: self.status.set(self.svc.engine_status()))
            else:
                self.events.put(lambda: done(result))

        threading.Thread(target=runner, daemon=True).start()

    def _drain_events(self):
        try:
            while True:
                self.events.get_nowait()()
        except queue.Empty:
            pass
        self.root.after(100, self._drain_events)

    @staticmethod
    def _tree(parent, columns, widths):
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=[c for c, _ in columns], show="headings")
        for (key, title), w in zip(columns, widths):
            tree.heading(key, text=title)
            tree.column(key, width=w, anchor="w")
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        tree.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        return frame, tree

    # ---------- 掃描 ----------
    def _build_scan_tab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="掃描")
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.scan_folder_btn = ttk.Button(bar, text="掃描資料夾…", command=self.pick_folder)
        self.scan_folder_btn.pack(side="left")
        self.scan_file_btn = ttk.Button(bar, text="掃描檔案…", command=self.pick_file)
        self.scan_file_btn.pack(side="left", padx=6)
        self.quarantine_btn = ttk.Button(bar, text="隔離所有威脅", command=self.quarantine_found, state="disabled")
        self.quarantine_btn.pack(side="right")
        self.progress = ttk.Progressbar(tab, mode="determinate")
        self.progress.pack(fill="x", pady=6)
        frame, self.scan_tree = self._tree(tab, [("result", "結果"), ("path", "檔案")], [200, 600])
        frame.pack(fill="both", expand=True)

    def pick_folder(self):
        d = filedialog.askdirectory(title="選擇要掃描的資料夾")
        if d:
            self.start_scan(Path(d))

    def pick_file(self):
        f = filedialog.askopenfilename(title="選擇要掃描的檔案")
        if f:
            self.start_scan(Path(f))

    def start_scan(self, target: Path):
        for b in (self.scan_folder_btn, self.scan_file_btn, self.quarantine_btn):
            b.configure(state="disabled")
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.progress.configure(value=0, maximum=1)
        self.status.set(f"掃描中：{target}")

        def progress(done, total):
            self.events.put(lambda: self.progress.configure(value=done, maximum=max(total, 1)))

        self._run_bg(lambda: self.svc.scan(target, progress=progress), self._scan_done, "掃描失敗")

    def _scan_done(self, results):
        self.last_results = results
        infected = [r for r in results if r.infected]
        for r in sorted(results, key=lambda r: (not r.infected, r.error is None)):
            if r.infected:
                label = f"威脅：{r.threat}"
            elif r.error:
                label = "略過（無法讀取）"
            else:
                label = "乾淨"
            self.scan_tree.insert("", "end", values=(label, str(r.path)))
        self.scan_folder_btn.configure(state="normal")
        self.scan_file_btn.configure(state="normal")
        self.quarantine_btn.configure(state="normal" if infected else "disabled")
        self.status.set(f"完成：掃描 {len(results)} 個檔案，發現 {len(infected)} 個威脅｜{self.svc.engine_status()}")
        self.refresh_history()

    def quarantine_found(self):
        n = self.svc.quarantine_results(self.last_results)
        self.quarantine_btn.configure(state="disabled")
        self.status.set(f"已隔離 {n} 個檔案")
        self.refresh_quarantine()

    # ---------- 隔離區 ----------
    def _build_quarantine_tab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="隔離區")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="還原", command=self.restore_selected).pack(side="left")
        ttk.Button(bar, text="永久刪除", command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(bar, text="重新整理", command=self.refresh_quarantine).pack(side="right")
        frame, self.q_tree = self._tree(
            tab, [("when", "時間"), ("threat", "威脅"), ("path", "原始位置")], [150, 200, 450]
        )
        frame.pack(fill="both", expand=True)
        self.refresh_quarantine()

    def refresh_quarantine(self):
        self.q_tree.delete(*self.q_tree.get_children())
        for item in self.svc.quarantine.list():
            self.q_tree.insert("", "end", iid=item.id, values=(item.quarantined_at, item.threat, str(item.original_path)))

    def restore_selected(self):
        sel = self.q_tree.selection()
        if sel and messagebox.askyesno("還原", f"確定要還原 {len(sel)} 個檔案？還原後檔案可能有害。"):
            for i in sel:
                self.svc.quarantine.restore(i)
            self.refresh_quarantine()

    def delete_selected(self):
        sel = self.q_tree.selection()
        if sel and messagebox.askyesno("永久刪除", f"確定要永久刪除 {len(sel)} 個檔案？無法復原。"):
            for i in sel:
                self.svc.quarantine.delete(i)
            self.refresh_quarantine()

    # ---------- 監控 ----------
    def _build_monitor_tab(self, nb):
        tab = ttk.Frame(nb, padding=12)
        nb.add(tab, text="自動監控")
        ttk.Label(tab, text="監控資料夾中出現的新檔案，發現威脅會自動隔離。").pack(anchor="w")
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=8)
        self.monitor_folder = tk.StringVar(value=self.svc.settings.get("monitor_folder", ""))
        ttk.Entry(row, textvariable=self.monitor_folder).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="選擇…", command=self._pick_monitor_folder).pack(side="left", padx=6)
        self.monitor_btn = ttk.Button(tab, text="開始監控", command=self.toggle_monitor)
        self.monitor_btn.pack(anchor="w")
        self.monitor_on_start = tk.BooleanVar(value=bool(self.svc.settings.get("monitor_on_start")))
        ttk.Checkbutton(tab, text="開啟程式時自動開始監控", variable=self.monitor_on_start,
                        command=self._save_monitor_settings).pack(anchor="w", pady=6)
        self.monitor_log = tk.Listbox(tab, height=12)
        self.monitor_log.pack(fill="both", expand=True, pady=(6, 0))

    def _pick_monitor_folder(self):
        d = filedialog.askdirectory(title="選擇要監控的資料夾")
        if d:
            self.monitor_folder.set(d)
            self._save_monitor_settings()

    def _save_monitor_settings(self):
        self.svc.settings["monitor_folder"] = self.monitor_folder.get()
        self.svc.settings["monitor_on_start"] = self.monitor_on_start.get()
        self.svc.save_settings()

    def _log(self, text):
        self.monitor_log.insert(0, text)

    def toggle_monitor(self):
        if self.monitor and self.monitor.running:
            self.monitor.stop()
            self.monitor_btn.configure(text="開始監控")
            self._log("已停止監控")
            return
        folder = Path(self.monitor_folder.get())
        if not folder.is_dir():
            messagebox.showwarning("自動監控", f"找不到資料夾：{folder}")
            return
        self._save_monitor_settings()

        def on_file(path):
            def notify(msg):
                self.events.put(lambda: (self._log(msg), self.refresh_quarantine()))
            try:
                self.svc.handle_new_file(path, notify)
                self.events.put(lambda: (self._log(f"已檢查：{path.name}"), self.refresh_history()))
            except Exception as e:
                msg = f"無法檢查 {path.name}：{e}"
                self.events.put(lambda: self._log(msg))

        self.monitor = FolderMonitor(folder, on_file)
        self.monitor.start()
        self.monitor_btn.configure(text="停止監控")
        self._log(f"開始監控：{folder}")

    # ---------- 網址 ----------
    def _build_url_tab(self, nb):
        tab = ttk.Frame(nb, padding=12)
        nb.add(tab, text="網址檢查")
        row = ttk.Frame(tab)
        row.pack(fill="x")
        self.url_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.url_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self.check_url())
        ttk.Button(row, text="檢查", command=self.check_url).pack(side="left", padx=6)
        self.url_result = tk.Text(tab, height=12, wrap="word", state="disabled")
        self.url_result.pack(fill="both", expand=True, pady=8)

    def _show_url(self, text):
        self.url_result.configure(state="normal")
        self.url_result.delete("1.0", "end")
        self.url_result.insert("1.0", text)
        self.url_result.configure(state="disabled")

    def check_url(self):
        url = self.url_var.get().strip()
        if not url:
            return
        self._show_url("檢查中…")

        def done(v):
            lines = [v.url, ""]
            if v.threats:
                lines.append("危險！Google Safe Browsing 回報：" + "、".join(v.threats))
            elif v.checked_online:
                lines.append("Google Safe Browsing：沒有已知威脅")
            else:
                lines.append("未設定 Safe Browsing API 金鑰，只做本機規則檢查（可在「設定」填入）")
            if v.warnings:
                lines += ["", "注意事項："] + [f"• {w}" for w in v.warnings]
            lines += ["", "結論：" + ("看起來安全" if v.safe else "不建議開啟")]
            self._show_url("\n".join(lines))

        self._run_bg(lambda: self.svc.check_url(url), done, "網址檢查失敗")

    # ---------- 紀錄 ----------
    def _build_history_tab(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="紀錄")
        frame, self.h_tree = self._tree(
            tab,
            [("when", "時間"), ("files", "檔案數"), ("threats", "威脅"), ("target", "掃描目標")],
            [150, 70, 70, 500],
        )
        frame.pack(fill="both", expand=True)
        self.refresh_history()

    def refresh_history(self):
        self.h_tree.delete(*self.h_tree.get_children())
        for r in self.svc.history.recent():
            self.h_tree.insert("", "end", values=(r.when, r.files, r.threats, r.target))

    # ---------- 設定 ----------
    def _build_settings_tab(self, nb):
        tab = ttk.Frame(nb, padding=12)
        nb.add(tab, text="設定")
        ttk.Label(tab, text="病毒碼（ClamAV）").pack(anchor="w")
        self.update_btn = ttk.Button(tab, text="更新病毒碼", command=self.update_db)
        self.update_btn.pack(anchor="w", pady=(4, 14))
        ttk.Label(tab, text="Google Safe Browsing API 金鑰（選填，僅限非商業用途）").pack(anchor="w")
        self.key_var = tk.StringVar(value=self.svc.settings.get("safe_browsing_key", ""))
        ttk.Entry(tab, textvariable=self.key_var, show="•", width=50).pack(anchor="w", pady=4)
        ttk.Button(tab, text="儲存", command=self._save_key).pack(anchor="w")
        ttk.Label(tab, text=f"資料位置：{self.svc.paths.data_dir}", foreground="gray").pack(anchor="w", pady=(18, 0))

    def _save_key(self):
        self.svc.settings["safe_browsing_key"] = self.key_var.get().strip()
        self.svc.save_settings()
        self.status.set("設定已儲存")

    def update_db(self):
        if not self.svc.clamav.installed:
            messagebox.showwarning("更新病毒碼", "找不到 ClamAV 引擎，請重新安裝本程式。")
            return
        self.update_btn.configure(state="disabled")
        self.status.set("正在下載病毒碼，第一次約需數分鐘…")

        def done(_out):
            self.update_btn.configure(state="normal")
            self.status.set("病毒碼已更新｜" + self.svc.engine_status())

        def work():
            try:
                return self.svc.update_database()
            finally:
                self.events.put(lambda: self.update_btn.configure(state="normal"))

        self._run_bg(work, done, "更新病毒碼失敗")

    def close(self):
        if self.monitor:
            self.monitor.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
