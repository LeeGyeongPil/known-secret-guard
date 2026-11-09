"""Where secrets come from: environment variable names, globs, ``.env`` files."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterable, Mapping

from .findings import GuardConfigError


def from_env_names(names: Iterable[str], *, missing: str = "skip",
                   environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Read the named environment variables; ``missing`` is ``"skip"`` or ``"error"``."""
    if missing not in ("skip", "error"):
        raise GuardConfigError(f"missing must be 'skip' or 'error', got {missing!r}")
    env = os.environ if environ is None else environ
    out: dict[str, str] = {}
    absent: list[str] = []
    for name in names:
        name = name.strip()
        if not name:
            continue
        value = env.get(name)
        if value is None or value == "":
            absent.append(name)
        else:
            out[name] = value
    if absent and missing == "error":
        raise GuardConfigError(
            "environment variable(s) not set or empty: " + ", ".join(absent)
            + ". Export them before starting, or pass missing='skip'."
        )
    return out


def from_env_globs(patterns: Iterable[str], *, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Select environment variables whose *names* match any ``fnmatch`` glob."""
    env = os.environ if environ is None else environ
    pats = [p.strip() for p in patterns if p.strip()]
    return {
        name: value
        for name, value in env.items()
        if value and any(fnmatch.fnmatchcase(name, p) for p in pats)
    }


def parse_env_text(text: str) -> dict[str, str]:
    """Parse ``NAME=value`` lines. ``#`` comments, ``export`` prefix, matching quotes stripped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        name, value = line.split("=", 1)
        name = name.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name and value:
            out[name] = value
    return out


def from_env_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Load a ``.env``-style file. Raises :class:`GuardConfigError` if unreadable."""
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_env_text(fh.read())
    except OSError as exc:
        raise GuardConfigError(f"cannot read env file {os.fspath(path)!r}: {exc.strerror}. "
                               "Check the path and permissions.") from exc
    except UnicodeDecodeError as exc:
        raise GuardConfigError(f"env file {os.fspath(path)!r} is not valid UTF-8.") from exc
