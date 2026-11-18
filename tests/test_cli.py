from scanner.__main__ import main

from conftest import FAKE_THREAT


def test_cli_exit_code_1_when_infected(sample_dir, test_signatures, capsys):
    code = main([str(sample_dir), "--signatures", str(test_signatures)])
    out = capsys.readouterr().out
    assert code == 1
    assert "fake_malware.bin" in out and FAKE_THREAT in out


def test_cli_exit_code_0_when_clean(tmp_path, test_signatures, capsys):
    (tmp_path / "ok.txt").write_text("ok", encoding="utf-8")
    assert main([str(tmp_path / "ok.txt"), "--signatures", str(test_signatures)]) == 0


def test_cli_exit_code_2_when_missing(tmp_path):
    assert main([str(tmp_path / "nope")]) == 2
