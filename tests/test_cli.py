from scanner.__main__ import main


def test_cli_exit_code_1_when_infected(sample_dir, capsys):
    code = main([str(sample_dir)])
    out = capsys.readouterr().out
    assert code == 1
    assert "eicar.com" in out and "EICAR-Test-File" in out


def test_cli_exit_code_0_when_clean(tmp_path, capsys):
    (tmp_path / "ok.txt").write_text("ok", encoding="utf-8")
    assert main([str(tmp_path)]) == 0
