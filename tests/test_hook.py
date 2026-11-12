"""AC-8: PreToolUse hook decisions."""

import _lang  # noqa: F401  (pins the output language to English)

import io
import json

from known_secret_guard.cli import main
from known_secret_guard.demo import exfil_command


def _run(monkeypatch, capsys, env_file, payload, *extra):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    code = main(["hook", "pretooluse", "--env-file", env_file, *extra])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_pretooluse_decisions(monkeypatch, capsys, env_file):
    # 1. leak -> deny JSON, exit 0, reason has name/code/field only
    leak = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": exfil_command()}}
    code, out, _ = _run(monkeypatch, capsys, env_file, leak)
    assert code == 0
    decision = json.loads(out)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "FAKE_API_KEY:B64_STD_K0 at tool_input.command" in decision["permissionDecisionReason"]

    # 2. clean -> silent, exit 0
    clean = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
    assert _run(monkeypatch, capsys, env_file, clean) == (0, "", "")

    # 3. broken input -> exit 2 (fail closed), reason on stderr
    code, out, err = _run(monkeypatch, capsys, env_file, "{not json")
    assert code == 2 and out == "" and "blocking" in err
    code, _, err = _run(monkeypatch, capsys, env_file, "[1, 2]")
    assert code == 2

    # 4. env references: allowed by default, denied with --deny-env-refs
    ref = {"tool_name": "Bash", "tool_input": {"command": "echo $FAKE_API_KEY | base64"}}
    assert _run(monkeypatch, capsys, env_file, ref)[:2] == (0, "")
    code, out, _ = _run(monkeypatch, capsys, env_file, ref, "--deny-env-refs")
    assert code == 0 and "FAKE_API_KEY:ENV_REF at tool_input.command" in out
    for cmd in ("echo ${FAKE_API_KEY}", "printenv FAKE_API_KEY", "printenv -0 FAKE_API_KEY"):
        _, out, _ = _run(monkeypatch, capsys, env_file, {"tool_input": {"command": cmd}}, "--deny-env-refs")
        assert "ENV_REF" in out, cmd
    # a longer variable name that merely starts with the registered one is not a reference
    _, out, _ = _run(monkeypatch, capsys, env_file, {"tool_input": {"command": "echo $FAKE_API_KEY_OTHER"}},
                     "--deny-env-refs")
    assert out == ""


def test_hook_nested_input_and_missing_tool_input(monkeypatch, capsys, env_file, secrets):
    nested = {"tool_name": "mcp__x__post", "tool_input": {"body": {"items": [{"text": "t=" + secrets["FAKE_GH_TOKEN"]}]}}}
    _, out, _ = _run(monkeypatch, capsys, env_file, nested)
    assert "FAKE_GH_TOKEN:RAW at tool_input.body.items[0].text" in out
    assert _run(monkeypatch, capsys, env_file, {"hook_event_name": "Stop"}) == (0, "", "")


def test_hook_without_secrets_fails_closed(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert main(["hook", "pretooluse", "--env", "KSG_SURELY_UNSET_VAR"]) == 2
    assert "no secrets registered" in capsys.readouterr().err


def test_unexpected_errors_fail_closed(monkeypatch, capsys, env_file):
    # Q-1: deeply nested input must block (exit 2), never crash with exit 1,
    # and stderr must name only the exception class, not any value.
    deep = '{"tool_input": ' + "[" * 100000 + "1" + "]" * 100000 + "}"
    code, out, err = _run(monkeypatch, capsys, env_file, deep)
    assert code == 2 and out == "" and "blocking" in err

    # nesting that parses but breaks the scan/traversal is blocked too
    nested: object = "x"
    for _ in range(900):
        nested = [nested]
    code, out, err = _run(monkeypatch, capsys, env_file, {"tool_input": nested})
    assert code in (0, 2) and out == ""

    # a scan that raises unexpectedly is blocked
    def boom(*_a, **_k):
        raise ValueError("value-should-not-leak")

    monkeypatch.setattr("known_secret_guard.guard.Guard.scan", boom)
    code, out, err = _run(monkeypatch, capsys, env_file, {"tool_input": {"command": "ls"}})
    assert code == 2 and "ValueError" in err and "value-should-not-leak" not in err
