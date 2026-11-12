"""Regression: trailing comments in .env lines must not become part of the secret."""

import _lang  # noqa: F401  (pins the output language to English)

from known_secret_guard.cli import main
from known_secret_guard.sources import parse_env_text

C = "Mm4Nn5Oo6Pp7Qq8R"
D = "Ww3Ee4Rr5Tt6Yy7U"


def test_unquoted_trailing_comment():  # AC1
    assert parse_env_text(f"C_KEY={C} # comment") == {"C_KEY": C}
    assert parse_env_text(f"C_KEY={C}\t# comment  ") == {"C_KEY": C}
    assert parse_env_text("K=abc#def") == {"K": "abc#def"}


def test_quoted_trailing_comment():  # AC2
    assert parse_env_text(f'D_KEY="{D}" # rotated monthly') == {"D_KEY": D}
    assert parse_env_text(f"D_KEY='{D}'  # x") == {"D_KEY": D}
    assert parse_env_text('K="a # b"') == {"K": "a # b"}
    assert parse_env_text('K="a # b" # c') == {"K": "a # b"}


def test_existing_behaviour_kept():  # AC3
    text = '# top\nexport A="quoted"\nB=\nC=plain\n\nnoequals\n'
    assert parse_env_text(text) == {"A": "quoted", "C": "plain"}


def _scan(tmp_path, env_text, payload):
    env = tmp_path / "e.env"
    env.write_text(env_text, encoding="utf-8")
    f = tmp_path / "in.txt"
    f.write_text(payload, encoding="utf-8")
    return main(["scan", "--env-file", str(env), str(f)])


def test_cli_catches_encoded_leaks(tmp_path, capsys):  # AC4
    c_env = f"C_KEY={C} # comment\n"
    assert _scan(tmp_path, c_env, "data=TW00Tm41T282UHA3UXE4Ug==") == 1
    assert _scan(tmp_path, c_env, "data=4d6d344e6e354f6f3650703751713852") == 1
    assert _scan(tmp_path, f'D_KEY="{D}" # rotated monthly\n', "data=V3czRWU0UnI1VHQ2WXk3VQ==") == 1
    env = tmp_path / "e.env"
    env.write_text(c_env, encoding="utf-8")
    capsys.readouterr()
    assert main(["variants", "--env-file", str(env)]) == 0
    raw = [ln for ln in capsys.readouterr().out.splitlines() if "RAW" in ln and "C_KEY" in ln]
    assert raw and "16" in raw[0]
