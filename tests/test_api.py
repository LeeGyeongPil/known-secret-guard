"""AC-9: library API."""

import pytest

from known_secret_guard import Finding, Guard, GuardConfigError, LeakDetected, VARIANT_CODES


def test_public_api(secrets, monkeypatch, env_file):
    guard = Guard(secrets)
    key = secrets["FAKE_API_KEY"]
    data = {"url": "https://x.invalid", "body": {"messages": [{"content": "ok"}, {"content": "k=" + key}]},
            "list": ["a", ["b", b"raw " + key.encode()]]}
    found = guard.scan(data)
    paths = sorted(f.field_path for f in found)
    assert paths == ["body.messages[1].content", "list[1][1]"]
    assert all(isinstance(f, Finding) and f.secret_name == "FAKE_API_KEY" and f.variant == "RAW" for f in found)
    with pytest.raises(LeakDetected) as info:
        guard.check(data)
    assert len(info.value.findings) == 2
    assert "body.messages[1].content" in str(info.value)
    guard.check({"harmless": "text"})  # no exception
    assert guard.scan("x " + key, field="msg")[0].field_path == "msg"

    # key that leaks is reported by position, never by value
    leaky_key = guard.scan({key: "v"})
    assert leaky_key[0].field_path == "<key#0>"

    # sources
    monkeypatch.setenv("MY_TOKEN", secrets["FAKE_GH_TOKEN"])
    monkeypatch.setenv("MY_KEY", key)
    monkeypatch.delenv("NOPE_NOT_SET", raising=False)
    assert Guard.from_env(["MY_TOKEN", "NOPE_NOT_SET"]).names == ["MY_TOKEN"]
    with pytest.raises(GuardConfigError, match="NOPE_NOT_SET"):
        Guard.from_env(["NOPE_NOT_SET"], missing="error")
    pattern_guard = Guard.from_env_patterns(["MY_*"])
    assert sorted(pattern_guard.names) == ["MY_KEY", "MY_TOKEN"]
    file_guard = Guard.from_env_file(env_file)
    assert sorted(file_guard.names) == sorted(secrets)
    assert file_guard.scan("t=" + secrets["FAKE_PASSWORD"])[0].secret_name == "FAKE_PASSWORD"


def test_config_errors(tmp_path):
    with pytest.raises(GuardConfigError, match="no secrets registered"):
        Guard().scan("anything")
    with pytest.raises(GuardConfigError, match="cannot read env file"):
        Guard.from_env_file(tmp_path / "missing.env")
    with pytest.raises(GuardConfigError):
        Guard({"A": 123})  # type: ignore[dict-item]
    with pytest.raises(GuardConfigError):
        Guard({"": "longenoughvalue"})
    with pytest.raises(GuardConfigError, match="min_length"):
        Guard({"A": "longenoughvalue"}, min_length=0)


def test_env_file_parsing(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# c\nexport A_KEY='quoted-value-1'\nB_KEY=\"dq-value-22\"\nC=plain=with=equals\nbroken\n",
                    encoding="utf-8")
    guard = Guard.from_env_file(path, min_length=4)
    assert guard.scan("quoted-value-1")[0].secret_name == "A_KEY"
    assert guard.scan("dq-value-22")[0].secret_name == "B_KEY"
    assert guard.scan("plain=with=equals")[0].secret_name == "C"


def test_variant_codes_documented(secrets):
    guard = Guard(secrets)
    assert {code for _n, code, _l in guard.variant_summary()} <= set(VARIANT_CODES)


def test_deep_and_odd_inputs(secrets):
    guard = Guard(secrets)
    nested: object = secrets["FAKE_API_KEY"]
    for _ in range(200):
        nested = [nested]
    assert guard.scan(nested)  # deeper than the walk limit: scanned through repr()
    assert guard.scan(None) == [] and guard.scan(12345) == [] and guard.scan(True) == []
