"""Value-free reporting types.

Nothing in this module ever receives a secret value, a variant string or the
text around a match. A report is the secret *name*, the variant *code* and the
field *path* only, because a report that echoes the value is itself a leak.
"""

from __future__ import annotations

from dataclasses import dataclass


class GuardConfigError(ValueError):
    """The guard is misconfigured (no secrets registered, bad file, ...)."""


@dataclass(frozen=True)
class Finding:
    """One known secret found in one field, in one variant."""

    secret_name: str
    variant: str
    field_path: str = ""
    offset: int | None = None  # None for matches found after normalisation

    def __str__(self) -> str:
        where = self.field_path or "<input>"
        return f"LEAK {where} {self.secret_name}:{self.variant}"

    __repr__ = __str__


class LeakDetected(Exception):
    """Raised by :meth:`Guard.check`. The message has names, codes, fields only."""

    def __init__(self, findings: list[Finding]):
        self.findings = list(findings)
        parts = [f"{f.secret_name}:{f.variant} at {f.field_path or '<input>'}" for f in self.findings]
        super().__init__("known secret(s) in outgoing data: " + "; ".join(parts))
