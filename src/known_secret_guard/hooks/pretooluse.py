"""Agent ``PreToolUse`` hook.

Reads the hook JSON from stdin, scans ``tool_input`` and either prints a
``deny`` decision (exit 0) or stays silent (exit 0). Broken input or a broken
configuration exits 2, which the host treats as a blocking error (fail
closed). Output never contains secret values.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any, TextIO

from ..guard import Guard
from ..i18n import t

_MAX_DEPTH = 64


def _strings(data: Any, path: str, guard: Guard, depth: int = 0) -> Iterator[tuple[str, str]]:
    """Yield ``(field_path, text)`` for every string value in ``data``.

    A dict key that itself contains a secret is replaced by ``<key#N>`` in the path.
    """
    if isinstance(data, str):
        yield path, data
    elif depth >= _MAX_DEPTH:
        yield path, repr(data)
    elif isinstance(data, dict):
        for i, (key, value) in enumerate(data.items()):
            seg = f"<key#{i}>" if guard.scan(str(key)) else str(key)
            yield from _strings(value, f"{path}.{seg}", guard, depth + 1)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            yield from _strings(item, f"{path}[{i}]", guard, depth + 1)


def env_ref_reasons(guard: Guard, tool_input: Any) -> list[str]:
    """Find ``$NAME``, ``${NAME}`` and ``printenv NAME`` references to registered names."""
    reasons: list[str] = []
    patterns = {
        name: re.compile(
            rf"\$\{{?{re.escape(name)}(?![A-Za-z0-9_])|\bprintenv\s+(?:-\S+\s+)*{re.escape(name)}(?![A-Za-z0-9_])"
        )
        for name in guard.names
    }
    for path, text in _strings(tool_input, "tool_input", guard):
        for name, pat in patterns.items():
            if pat.search(text):
                reasons.append(f"{name}:ENV_REF at {path}")
    return reasons


def run(stdin: TextIO, stdout: TextIO, stderr: TextIO, guard: Guard, *, deny_env_refs: bool = False) -> int:
    """Process one hook call. Returns the process exit code (0 or 2).

    Any unexpected error blocks (exit 2) and only the exception class name is written.
    """
    try:
        return _run(stdin, stdout, stderr, guard, deny_env_refs)
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all for fail closed
        stderr.write(t("hook_failed", cls=exc.__class__.__name__) + "\n")
        return 2


def _run(stdin: TextIO, stdout: TextIO, stderr: TextIO, guard: Guard, deny_env_refs: bool) -> int:
    try:
        payload = json.load(stdin)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        stderr.write(t("hook_bad_json", cls=exc.__class__.__name__) + "\n")
        return 2
    if not isinstance(payload, dict):
        stderr.write(t("hook_not_object") + "\n")
        return 2
    tool_input = payload.get("tool_input")
    if tool_input is None:
        return 0
    reasons = [f"{f.secret_name}:{f.variant} at {f.field_path}"
               for f in guard.scan(tool_input, field="tool_input")]
    if deny_env_refs:
        reasons.extend(env_ref_reasons(guard, tool_input))
    if not reasons:
        return 0
    decision = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "known-secret-guard: " + "; ".join(reasons),
        }
    }
    stdout.write(json.dumps(decision) + "\n")
    return 0
