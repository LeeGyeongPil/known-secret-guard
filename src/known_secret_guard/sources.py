"""Where secrets come from: environment variable names, globs, ``.env`` files."""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable, Mapping

from .findings import GuardConfigError
from .i18n import t


def from_env_names(names: Iterable[str], *, missing: str = "skip",
                   environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Read the named environment variables; ``missing`` is ``"skip"`` or ``"error"``."""
    if missing not in ("skip", "error"):
        raise GuardConfigError(t("missing_arg", value=repr(missing)))
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
        raise GuardConfigError(t("env_unset", names=", ".join(absent)))
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


def _clean_value(raw: str) -> str:
    """Strip quotes and a trailing ``# comment`` from the text after ``=``."""
    value = raw.strip()
    if value[:1] in ("\"", "'"):
        close = value.find(value[0], 1)  # closing quote matching the opening one
        if close != -1:
            return value[1:close]  # anything after the closing quote is dropped
    # Unquoted: a '#' only starts a comment when preceded by whitespace.
    match = re.search(r"\s#", value)
    if match:
        value = value[:match.start()]
    return value.rstrip()


def parse_env_text(text: str) -> dict[str, str]:
    """Parse ``NAME=value`` lines. Full-line and trailing ``#`` comments, ``export`` prefix, matching quotes stripped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        name, value = line.split("=", 1)
        name = name.strip()
        value = _clean_value(value)
        if name and value:
            out[name] = value
    return out


def from_env_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Load a ``.env``-style file. Raises :class:`GuardConfigError` if unreadable."""
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_env_text(fh.read())
    except OSError as exc:
        raise GuardConfigError(
            t("env_file_unreadable", path=repr(os.fspath(path)), reason=exc.strerror)) from exc
    except UnicodeDecodeError as exc:
        raise GuardConfigError(t("env_file_not_utf8", path=repr(os.fspath(path)))) from exc
