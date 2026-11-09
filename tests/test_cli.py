"""AC-1 and AC-7: CLI behaviour and exit codes."""

import io

import pytest

from known_secret_guard.cli import main
from known_secret_guard.demo import samples


def test_demo_scorecard(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("[practice mode]")
    last = out.strip().splitlines()[-1]
    assert "caught 48/48" in last and "negative 3/3 clean" in last and "secret values printed: 0" in last


def test_scan_exit_codes(tmp_path, env_file, capsys, monkeypatch):
    sample_dir = tmp_path / "s"
    assert main(["demo", "--write-samples", str(sample_dir)]) == 0
    capsys.readouterr()
    leaky = str(sample_dir / "generic__b64_std_offset1.txt")

    assert main(["scan", "--env-file", env_file, leaky]) == 1
    assert capsys.readouterr().out.strip() == f"LEAK {leaky} FAKE_API_KEY:B64_STD_K1"

    clean = tmp_path / "clean.txt"
    clean.write_text("nothing to see here\n", encoding="utf-8")
    assert main(["scan", "--env-file", env_file, str(clean)]) == 0
    assert capsys.readouterr().out.strip() == f"clean {clean}"

    # configuration errors -> 2
    assert main(["scan", "--env", "KSG_SURELY_UNSET_VAR", str(clean)]) == 2
    assert "no secrets registered" in capsys.readouterr().err
    assert main(["scan", "--env-file", env_file, str(tmp_path / "missing.txt")]) == 2
    assert "cannot read" in capsys.readouterr().err
    assert main(["scan", "--env-file", str(tmp_path / "nope.env"), str(clean)]) == 2
    capsys.readouterr()

    # stdin
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"token=" + b"x" * 3)))
    assert main(["scan", "--env-file", env_file]) == 0
    capsys.readouterr()

    # json output
    assert main(["scan", "--json", "--env-file", env_file, leaky]) == 1
    assert '"clean": false' in capsys.readouterr().out


def test_scan_all_samples_leak(tmp_path, env_file, capsys):
    sample_dir = tmp_path / "s"
    main(["demo", "--write-samples", str(sample_dir)])
    capsys.readouterr()
    files = sorted(str(p) for p in sample_dir.glob("*.txt"))
    assert len(files) == len(list(samples())) == 48
    assert main(["scan", "--env-file", env_file, *files]) == 1
    lines = capsys.readouterr().out.strip().splitlines()
    assert all(line.startswith("LEAK ") for line in lines) and len(lines) == 48


def test_variants_table_and_warning(tmp_path, capsys):
    env = tmp_path / "e.env"
    env.write_text("LONG_ONE=abcdefghijklmnopqrstuvwxyz\nSHORT=abc\n", encoding="utf-8")
    assert main(["variants", "--env-file", str(env)]) == 0
    cap = capsys.readouterr()
    assert "LONG_ONE" in cap.out and "RAW" in cap.out and "SHORT" not in cap.out
    assert "SHORT" in cap.err


def test_argparse_errors_exit_2():
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2


def test_env_pattern_option(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("KSG_TEST_TOKEN", "pattern-token-value-123")
    f = tmp_path / "f.txt"
    f.write_text("x pattern-token-value-123 y", encoding="utf-8")
    assert main(["scan", "--env-pattern", "KSG_TEST_*", str(f)]) == 1
    assert "KSG_TEST_TOKEN:RAW" in capsys.readouterr().out
    assert main(["scan", "--env-pattern", "KSG_TEST_*", "--exclude", "KSG_TEST_TOKEN", str(f)]) == 2
