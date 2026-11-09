"""AC-6: no output path ever contains a secret value or a variant string."""

import io
import json

import pytest

from known_secret_guard import Guard, LeakDetected
from known_secret_guard.cli import main
from known_secret_guard.demo import exfil_command, samples
from known_secret_guard.variants import build_variants


def _forbidden(secrets):
    bad = set()
    for value in secrets.values():
        bad.add(value)
        bad.update(text for _code, text in build_variants(value))
    return bad


def test_outputs_never_contain_secret_or_variants(secrets, env_file, tmp_path, capsys, monkeypatch):
    bad = _forbidden(secrets)
    assert len(bad) > 30
    outputs: list[str] = []
    guard = Guard(secrets)

    for _name, _stem, _d, text in samples():
        for f in guard.scan(text):
            outputs += [str(f), repr(f)]
        try:
            guard.check({"nested": [text]})
        except LeakDetected as exc:
            outputs.append(str(exc))
    # a leaking dict key must not show up in the path
    for f in guard.scan({secrets["FAKE_API_KEY"]: secrets["FAKE_GH_TOKEN"]}):
        outputs.append(str(f))
    assert any("<key#0>" in o for o in outputs)

    sample_dir = tmp_path / "s"
    main(["demo", "--write-samples", str(sample_dir)])
    outputs.append(capsys.readouterr().out)
    files = sorted(str(p) for p in sample_dir.glob("*.txt"))
    for extra in ([], ["--json"]):
        main(["scan", "--env-file", env_file, *extra, *files])
        cap = capsys.readouterr()
        outputs += [cap.out, cap.err]
    main(["variants", "--env-file", env_file])
    cap = capsys.readouterr()
    outputs += [cap.out, cap.err]

    for payload in ({"tool_input": {"command": exfil_command()}},
                    {"tool_input": {secrets["FAKE_API_KEY"]: "$FAKE_API_KEY and " + secrets["FAKE_GH_TOKEN"]}}):
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
        main(["hook", "pretooluse", "--env-file", env_file, "--deny-env-refs"])
        cap = capsys.readouterr()
        outputs += [cap.out, cap.err]
        assert "deny" in cap.out
    monkeypatch.setattr("sys.stdin", io.StringIO("{broken " + secrets["FAKE_API_KEY"]))
    main(["hook", "pretooluse", "--env-file", env_file])
    cap = capsys.readouterr()
    outputs += [cap.out, cap.err]

    assert len(outputs) > 100
    for out in outputs:
        for needle in bad:
            assert needle not in out, "a secret value or variant leaked into a report"


@pytest.mark.parametrize("code", ["RAW", "B64_STD_K0"])
def test_finding_repr_shape(code):
    from known_secret_guard import Finding
    f = Finding("NAME", code, "a.b[2].c", 5)
    assert str(f) == repr(f) == f"LEAK a.b[2].c NAME:{code}"
