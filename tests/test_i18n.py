"""Language selection (--lang > KNOWN_SECRET_GUARD_LANG > LC_ALL > LC_MESSAGES > LANG) and message tables."""

import _lang  # noqa: F401  (pins the output language to English)

import json
import os
import string

import pytest

from known_secret_guard import i18n
from known_secret_guard.cli import main
from known_secret_guard.findings import GuardConfigError
from known_secret_guard.guard import Guard
from known_secret_guard.i18n import MESSAGES, resolve_lang

HANGUL = range(0xAC00, 0xD7A4)


def _has_hangul(text: str) -> bool:
    return any(ord(c) in HANGUL for c in text)


def _fields(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def test_tables_have_same_keys_and_placeholders():
    assert set(MESSAGES["en"]) == set(MESSAGES["ko"])
    for key in MESSAGES["en"]:
        assert _fields(MESSAGES["en"][key]) == _fields(MESSAGES["ko"][key]), key


def test_korean_table_is_korean_and_polite_formal():
    # Every Korean sentence is Hangul-bearing except the bracket-free tokens below.
    for key, text in MESSAGES["ko"].items():
        assert _has_hangul(text), key
        # one speech level only: no haeyo-style endings ("-해요", "-세요", "-어요")
        assert "해요" not in text and "세요" not in text and "에요" not in text, key


@pytest.mark.parametrize(
    ("argv_lang", "env", "expected"),
    [
        ("ko", {"KNOWN_SECRET_GUARD_LANG": "en", "LANG": "en_US.UTF-8"}, "ko"),
        ("en", {"KNOWN_SECRET_GUARD_LANG": "ko"}, "en"),
        (None, {"KNOWN_SECRET_GUARD_LANG": "ko", "LC_ALL": "en_US.UTF-8"}, "ko"),
        (None, {"KNOWN_SECRET_GUARD_LANG": "en", "LC_ALL": "ko_KR.UTF-8"}, "en"),
        (None, {"LC_ALL": "ko_KR.UTF-8", "LC_MESSAGES": "en_US.UTF-8", "LANG": "en_US.UTF-8"}, "ko"),
        (None, {"LC_MESSAGES": "ko_KR.UTF-8", "LANG": "en_US.UTF-8"}, "ko"),
        (None, {"LC_MESSAGES": "en_US.UTF-8", "LANG": "ko_KR.UTF-8"}, "en"),
        (None, {"LANG": "ko_KR.UTF-8"}, "ko"),
        (None, {"LANG": "C"}, "en"),
        (None, {"LANG": "fr_FR.UTF-8"}, "en"),
        (None, {}, "en"),
    ],
)
def test_resolve_lang_priority(argv_lang, env, expected):
    assert resolve_lang(argv_lang, env) == expected


def test_lang_from_argv_before_and_after_subcommand():
    assert i18n.lang_from_argv(["--lang", "ko", "demo"]) == "ko"
    assert i18n.lang_from_argv(["demo", "--lang=ko"]) == "ko"
    assert i18n.lang_from_argv(["demo", "--lang", "fr"]) is None
    assert i18n.lang_from_argv(["demo"]) is None


@pytest.fixture()
def clean_lang_env(monkeypatch):
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("KNOWN_SECRET_GUARD_LANG", "en")


def test_demo_summary_switches_language(clean_lang_env, capsys):
    assert main(["demo"]) == 0
    en = capsys.readouterr().out
    assert "caught 48/48" in en and not _has_hangul(en)
    assert main(["--lang", "ko", "demo"]) == 0
    ko = capsys.readouterr().out
    assert "탐지 48/48" in ko and "[연습 모드]" in ko
    # result tokens stay untranslated
    assert "FAKE_GH_TOKEN:RAW" in ko and "clean" in ko


def test_env_var_and_locale_select_korean(clean_lang_env, monkeypatch, capsys):
    monkeypatch.delenv("KNOWN_SECRET_GUARD_LANG")
    monkeypatch.setenv("LANG", "ko_KR.UTF-8")
    main(["demo"])
    assert "탐지 48/48" in capsys.readouterr().out
    monkeypatch.setenv("KNOWN_SECRET_GUARD_LANG", "en")
    main(["demo"])
    assert "caught 48/48" in capsys.readouterr().out


def test_errors_and_warnings_in_korean(clean_lang_env, tmp_path, capsys):
    env = tmp_path / "e.env"
    env.write_text("LONG_ONE=abcdefghijklmnopqrstuvwxyz\nSHORT=abc\n", encoding="utf-8")
    assert main(["variants", "--lang", "ko", "--env-file", str(env)]) == 0
    cap = capsys.readouterr()
    assert "경고" in cap.err and "SHORT" in cap.err and "비밀값" in cap.out and "RAW" in cap.out

    assert main(["scan", "--lang", "ko", "--env", "KSG_SURELY_UNSET_VAR"]) == 2
    assert "오류" in capsys.readouterr().err
    assert main(["scan", "--lang", "ko", "--env-file", str(env), str(tmp_path / "missing.txt")]) == 2
    assert "읽을 수 없습니다" in capsys.readouterr().err
    assert main(["scan", "--lang", "ko", "--env-file", str(tmp_path / "nope.env")]) == 2
    assert "env 파일" in capsys.readouterr().err


def test_argparse_usage_errors_and_help_localized(clean_lang_env, capsys):
    with pytest.raises(SystemExit) as info:
        main(["--lang", "ko"])
    assert info.value.code == 2
    err = capsys.readouterr().err
    assert "사용법:" in err and "오류:" in err and "다음 인자가 필요합니다" in err

    with pytest.raises(SystemExit) as info:
        main(["scan", "--lang", "ko", "--min-length", "q"])
    assert info.value.code == 2
    assert "올바르지 않은 int 값" in capsys.readouterr().err

    with pytest.raises(SystemExit) as info:
        main(["scan", "--lang", "ko", "--help"])
    assert info.value.code == 0
    out = capsys.readouterr().out
    assert "사용법:" in out and "옵션:" in out and "도움말을 표시하고 종료합니다" in out

    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "usage:" in out and "options:" in out and not _has_hangul(out)


def test_invalid_lang_reports_choices(clean_lang_env, capsys):
    with pytest.raises(SystemExit):
        main(["--lang", "xx", "demo"])
    err = capsys.readouterr().err
    assert "invalid choice" in err and "'en'" in err and "'ko'" in err


def test_machine_output_is_language_independent(clean_lang_env, tmp_path, env_file, capsys, monkeypatch):
    sample_dir = tmp_path / "s"
    main(["demo", "--write-samples", str(sample_dir)])
    capsys.readouterr()
    leaky = str(sample_dir / "generic__b64_std_offset1.txt")

    outputs = {}
    for lang in ("en", "ko"):
        assert main(["scan", "--lang", lang, "--env-file", env_file, leaky]) == 1
        line = capsys.readouterr().out
        assert main(["scan", "--lang", lang, "--json", "--env-file", env_file, leaky]) == 1
        doc = capsys.readouterr().out
        outputs[lang] = (line, doc)
    assert outputs["en"] == outputs["ko"]
    assert outputs["ko"][0].strip() == f"LEAK {leaky} FAKE_API_KEY:B64_STD_K1"
    assert json.loads(outputs["ko"][1])["files"][0]["findings"][0]["variant"] == "B64_STD_K1"


def test_hook_deny_json_same_and_stderr_localized(clean_lang_env, env_file, capsys, monkeypatch, secrets):
    import io

    from known_secret_guard.demo import exfil_command

    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": exfil_command()}})
    outs = []
    for lang in ("en", "ko"):
        monkeypatch.setattr("sys.stdin", io.StringIO(payload))
        assert main(["hook", "pretooluse", "--lang", lang, "--env-file", env_file]) == 0
        outs.append(capsys.readouterr().out)
    assert outs[0] == outs[1]
    assert json.loads(outs[0])["hookSpecificOutput"]["permissionDecisionReason"].startswith("known-secret-guard: ")

    monkeypatch.setattr("sys.stdin", io.StringIO("{not json"))
    assert main(["hook", "pretooluse", "--lang", "ko", "--env-file", env_file]) == 2
    cap = capsys.readouterr()
    assert cap.out == "" and "올바른 JSON이 아닙니다" in cap.err
    monkeypatch.setattr("sys.stdin", io.StringIO("[1]"))
    assert main(["hook", "pretooluse", "--lang", "ko", "--env-file", env_file]) == 2
    assert "JSON 객체" in capsys.readouterr().err


def test_library_errors_follow_environment_language(monkeypatch):
    monkeypatch.setenv("KNOWN_SECRET_GUARD_LANG", "ko")
    with pytest.raises(GuardConfigError, match="min_length"):
        Guard({"A": "x" * 10}, min_length=0)
    with pytest.raises(GuardConfigError, match="1 이상"):
        Guard({"A": "x" * 10}, min_length=0)
    with pytest.raises(GuardConfigError, match="등록된 비밀값이 없습니다"):
        Guard({}).scan("x")
    monkeypatch.setenv("KNOWN_SECRET_GUARD_LANG", "en")
    with pytest.raises(GuardConfigError, match="no secrets registered"):
        Guard({}).scan("x")


def test_language_is_reset_after_main(clean_lang_env, monkeypatch, capsys):
    main(["--lang", "ko", "demo"])
    capsys.readouterr()
    assert i18n.current_lang() == "en"  # env says en; the --lang choice did not stick


# --- examples/agent_exfil_sim.py follows the same language rule -------------------------

def _run_sim(args, env_extra):
    import pathlib
    import subprocess
    import sys

    script = pathlib.Path(__file__).resolve().parent.parent / "examples" / "agent_exfil_sim.py"
    env = {k: v for k, v in os.environ.items() if k not in ("KNOWN_SECRET_GUARD_LANG", "LC_ALL", "LC_MESSAGES", "LANG")}
    env.update(env_extra)
    return subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True, env=env, timeout=60)


def test_agent_sim_english_default():
    r = _run_sim([], {})
    assert r.returncode == 0
    assert "[practice mode]" in r.stdout and "BLOCKED" in r.stdout
    assert "연습" not in r.stdout


def test_agent_sim_korean_by_flag_env_and_locale():
    for args, env in ((["--lang", "ko"], {}), ([], {"KNOWN_SECRET_GUARD_LANG": "ko"}), ([], {"LANG": "ko_KR.UTF-8"})):
        r = _run_sim(args, env)
        assert r.returncode == 0
        assert "[연습 모드]" in r.stdout and "차단" in r.stdout
        assert "BLOCKED" not in r.stdout
        assert "LEAK tool_input.command FAKE_API_KEY:" in r.stdout  # machine-style finding line is untranslated


def test_agent_sim_flag_beats_env():
    r = _run_sim(["--lang", "en"], {"KNOWN_SECRET_GUARD_LANG": "ko"})
    assert "[practice mode]" in r.stdout
