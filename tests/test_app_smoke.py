"""視窗冒煙測試：確認視窗能建立、主要流程能跑。沒有圖形環境時自動略過。"""
import pytest

tk = pytest.importorskip("tkinter")

from scanner.config import AppPaths
from scanner.service import AppService


@pytest.fixture
def app(tmp_path, test_signatures):
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("沒有圖形環境")
    root.withdraw()
    from scanner.app import App

    svc = AppService(AppPaths(tmp_path / "data", tmp_path / "no-clamav"), signatures_file=test_signatures)
    a = App(root, svc)
    yield a
    a.close()


def test_scan_flow_updates_tree_and_quarantine(app, sample_dir):
    results = app.svc.scan(sample_dir)
    app._scan_done(results)
    rows = [app.scan_tree.item(i)["values"] for i in app.scan_tree.get_children()]
    assert rows[0][0].startswith("威脅") and len(rows) == 2
    assert str(app.quarantine_btn["state"]) == "normal"
    app.quarantine_found()
    assert len(app.q_tree.get_children()) == 1
    assert len(app.h_tree.get_children()) == 1


def test_all_tabs_built(app):
    app.root.update()
    nb = app.root.winfo_children()[0]
    assert [nb.tab(t, "text") for t in nb.tabs()] == ["掃描", "隔離區", "自動監控", "網址檢查", "紀錄", "設定"]
