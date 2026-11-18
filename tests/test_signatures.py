from scanner.signatures import load_signatures, DEFAULT_SIGNATURES

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_load_ignores_comments_and_blank_lines(tmp_path):
    f = tmp_path / "sigs.txt"
    f.write_text(
        "# 註解\n\n" + EICAR_SHA256.upper() + "  EICAR-Test-File\n",
        encoding="utf-8",
    )
    sigs = load_signatures(f)
    assert sigs == {EICAR_SHA256: "EICAR-Test-File"}


def test_default_list_contains_eicar():
    assert EICAR_SHA256 in load_signatures(DEFAULT_SIGNATURES)
