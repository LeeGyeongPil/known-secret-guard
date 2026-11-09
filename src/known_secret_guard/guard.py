"""The :class:`Guard`: register known secrets, then scan outgoing data."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from . import sources
from .findings import Finding, GuardConfigError, LeakDetected
from .normalize import normalize
from .variants import build_variants

_MAX_DEPTH = 64  # deeper structures are scanned through repr() instead of walked


@dataclass(frozen=True)
class _Entry:
    name: str
    variants: tuple[tuple[str, str], ...]          # (code, text)
    normalized: tuple[tuple[str, str], ...]        # (code, text), already normalised


class Guard:
    """Checks outgoing data for the *known* values you registered, in any variant.

    ``secrets`` maps a name to its value. Values shorter than ``min_length`` are
    not registered (too short to match without false positives); their names
    are listed in :attr:`skipped`. Names in ``exclude`` are ignored entirely.
    """

    def __init__(self, secrets: Mapping[str, str] | None = None, *, min_length: int = 8,
                 exclude: Iterable[str] = ()) -> None:
        if min_length < 1:
            raise GuardConfigError("min_length must be >= 1")
        self.min_length = min_length
        self._exclude = frozenset(exclude)
        self._entries: dict[str, _Entry] = {}
        self._skipped: list[str] = []
        for name, value in (secrets or {}).items():
            self.add(name, value)

    # ----- registration -------------------------------------------------
    @classmethod
    def from_env(cls, names: Iterable[str], *, missing: str = "skip", min_length: int = 8,
                 exclude: Iterable[str] = ()) -> Guard:
        """Register environment variables by name."""
        return cls(sources.from_env_names(names, missing=missing), min_length=min_length, exclude=exclude)

    @classmethod
    def from_env_patterns(cls, globs: Iterable[str], *, min_length: int = 8,
                          exclude: Iterable[str] = ()) -> Guard:
        """Register environment variables whose names match ``fnmatch`` globs."""
        return cls(sources.from_env_globs(globs), min_length=min_length, exclude=exclude)

    @classmethod
    def from_env_file(cls, path: str | os.PathLike[str], *, min_length: int = 8,
                      exclude: Iterable[str] = ()) -> Guard:
        """Register the ``NAME=value`` entries of a ``.env`` file."""
        return cls(sources.from_env_file(path), min_length=min_length, exclude=exclude)

    def add(self, name: str, value: str) -> None:
        """Register one more secret."""
        if not isinstance(name, str) or not name:
            raise GuardConfigError("secret name must be a non-empty string")
        if not isinstance(value, str):
            raise GuardConfigError(f"value of {name!r} must be str, got {type(value).__name__}")
        if name in self._exclude:
            return
        if len(value) < self.min_length:
            if name not in self._skipped:
                self._skipped.append(name)
            return
        variants = tuple(build_variants(value, min_length=self.min_length))
        folded = normalize(value)
        half = len(folded) // 2
        norm = tuple(
            (code, text)
            for code, text in (("NORM_RAW", folded), ("NORM_HALF_HEAD", folded[:half]),
                               ("NORM_HALF_TAIL", folded[half:]))
            if len(text) >= self.min_length
        )
        self._entries[name] = _Entry(name, variants, norm)

    @property
    def names(self) -> list[str]:
        """Names of registered secrets."""
        return list(self._entries)

    @property
    def skipped(self) -> list[str]:
        """Names not registered because the value was shorter than ``min_length``."""
        return list(self._skipped)

    def variant_summary(self) -> list[tuple[str, str, int]]:
        """``(name, code, length)`` for every variant. Contains no values."""
        return [(e.name, code, len(text)) for e in self._entries.values() for code, text in e.variants]

    # ----- scanning -----------------------------------------------------
    def scan(self, data: Any, *, field: str = "") -> list[Finding]:
        """Return findings for ``str``, ``bytes`` or nested ``dict``/``list`` data."""
        if not self._entries:
            raise GuardConfigError(
                "no secrets registered: pass names that exist in the environment, "
                "an env file, or Guard({'NAME': 'value'})."
            )
        findings: list[Finding] = []
        self._walk(data, field, findings, 0)
        return findings

    def check(self, data: Any, *, field: str = "") -> None:
        """Raise :class:`LeakDetected` if :meth:`scan` finds anything."""
        findings = self.scan(data, field=field)
        if findings:
            raise LeakDetected(findings)

    def _walk(self, data: Any, path: str, out: list[Finding], depth: int) -> None:
        if isinstance(data, str):
            out.extend(self._scan_text(data, path))
        elif isinstance(data, (bytes, bytearray)):
            out.extend(self._scan_text(bytes(data).decode("utf-8", errors="replace"), path))
        elif depth >= _MAX_DEPTH:
            out.extend(self._scan_text(repr(data), path))
        elif isinstance(data, Mapping):
            for i, (key, value) in enumerate(data.items()):
                key_text = key if isinstance(key, str) else str(key)
                key_findings = self._scan_text(key_text, _join(path, f"<key#{i}>"))
                out.extend(key_findings)
                # a key that leaks must not appear in the reported path
                segment = f"<key#{i}>" if key_findings else key_text
                self._walk(value, _join(path, segment), out, depth + 1)
        elif isinstance(data, (list, tuple, set, frozenset)):
            for i, item in enumerate(data):
                self._walk(item, f"{path}[{i}]", out, depth + 1)
        elif data is None or isinstance(data, bool):
            return
        else:
            out.extend(self._scan_text(str(data), path))

    def _scan_text(self, text: str, path: str) -> list[Finding]:
        findings: list[Finding] = []
        folded: str | None = None
        for entry in self._entries.values():
            hit = False
            for code, variant in entry.variants:
                idx = text.find(variant)
                if idx >= 0:
                    findings.append(Finding(entry.name, code, path, idx))
                    hit = True
                    break  # one finding per secret per field: the first, most direct disguise
            if hit or not entry.normalized:
                continue
            if folded is None:
                folded = normalize(text)
            for code, variant in entry.normalized:
                if variant in folded:
                    findings.append(Finding(entry.name, code, path, None))
                    break
        return findings


def _join(path: str, segment: str) -> str:
    return f"{path}.{segment}" if path else segment
