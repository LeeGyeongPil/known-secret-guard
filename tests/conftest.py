import sys

sys.dont_write_bytecode = True  # keep run-time-assembled fake tokens out of .pyc files

"""Shared fixtures. All secrets are FAKE and assembled at run time."""

import pytest

from known_secret_guard.demo import fake_secrets


@pytest.fixture()
def secrets() -> dict[str, str]:
    return fake_secrets()


@pytest.fixture()
def env_file(tmp_path, secrets):
    path = tmp_path / "fake.env"
    path.write_text("# fake values\n" + "".join(f"{k}={v}\n" for k, v in secrets.items()), encoding="utf-8")
    return str(path)
