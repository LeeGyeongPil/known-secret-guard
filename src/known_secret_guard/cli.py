"""Command line: ``scan``, ``variants``, ``hook pretooluse``, ``demo``.

Exit codes: 0 clean, 1 leak found, 2 configuration or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__, sources
from . import demo as demo_mod
from .findings import GuardConfigError
from .guard import Guard
from .hooks import pretooluse


def _split(csv: str | None) -> list[str]:
    return [p.strip() for p in (csv or "").split(",") if p.strip()]


def _add_registration(p: argparse.ArgumentParser) -> None:
    p.add_argument("--env", metavar="NAMES", help="comma-separated environment variable names")
    p.add_argument("--env-pattern", metavar="GLOBS", help="comma-separated globs on variable names, e.g. '*_TOKEN,*_KEY'")
    p.add_argument("--env-file", metavar="PATH", help=".env-style file with NAME=value lines")
    p.add_argument("--min-length", type=int, default=8, metavar="N", help="ignore values shorter than N (default 8)")
    p.add_argument("--exclude", metavar="NAMES", help="comma-separated names never to guard")


def _build_guard(args: argparse.Namespace) -> Guard:
    secrets: dict[str, str] = {}
    if args.env:
        secrets.update(sources.from_env_names(_split(args.env)))
    if args.env_pattern:
        secrets.update(sources.from_env_globs(_split(args.env_pattern)))
    if args.env_file:
        secrets.update(sources.from_env_file(args.env_file))
    guard = Guard(secrets, min_length=args.min_length, exclude=_split(args.exclude))
    if not guard.names:
        raise GuardConfigError(
            "no secrets registered. Use --env NAME1,NAME2, --env-pattern '*_TOKEN' or --env-file PATH "
            "and make sure the variables exist in this process."
        )
    if guard.skipped:
        print("known-secret-guard: warning: too short to guard (names only): " + ", ".join(guard.skipped),
              file=sys.stderr)
    return guard


def _read_target(target: str) -> bytes:
    try:
        if target == "-":
            return sys.stdin.buffer.read()
        with open(target, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise GuardConfigError(f"cannot read {target!r}: {exc.strerror}") from exc


def _cmd_scan(args: argparse.Namespace) -> int:
    guard = _build_guard(args)
    results = []
    leaked = False
    for target in args.files or ["-"]:
        findings = guard.scan(_read_target(target))
        leaked = leaked or bool(findings)
        results.append((target, findings))
    if args.json:
        doc = {"clean": not leaked, "files": [
            {"file": t, "findings": [{"secret": f.secret_name, "variant": f.variant} for f in fs]}
            for t, fs in results]}
        print(json.dumps(doc))
    else:
        for target, findings in results:
            if findings:
                print(f"LEAK {target} " + ",".join(f"{f.secret_name}:{f.variant}" for f in findings))
            else:
                print(f"clean {target}")
    return 1 if leaked else 0


def _cmd_variants(args: argparse.Namespace) -> int:
    guard = _build_guard(args)
    print(f"{'secret':<24} {'variant':<16} length")
    for name, code, length in guard.variant_summary():
        print(f"{name:<24} {code:<16} {length}")
    return 0


def _cmd_hook(args: argparse.Namespace) -> int:
    # Fail closed: any unexpected error (even RecursionError) must exit 2, because
    # exit 1 is a non-blocking error for the host and the tool call would run.
    try:
        guard = _build_guard(args)
        return pretooluse.run(sys.stdin, sys.stdout, sys.stderr, guard, deny_env_refs=args.deny_env_refs)
    except GuardConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all for fail closed
        print(f"known-secret-guard: hook failed ({exc.__class__.__name__}); blocking.", file=sys.stderr)
        return 2


def _cmd_demo(args: argparse.Namespace) -> int:
    lines, ok = demo_mod.run_demo()
    print("\n".join(lines))
    if args.write_samples:
        count = demo_mod.write_samples(args.write_samples)
        print(f"wrote {count} sample files + fake.env + hook inputs to {args.write_samples}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (exposed for tests)."""
    parser = argparse.ArgumentParser(
        prog="known-secret-guard",
        description="Block outgoing text that contains a known secret, however it was disguised.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan files (or stdin) for known secrets")
    _add_registration(scan)
    scan.add_argument("--json", action="store_true", help="machine-readable output (no values)")
    scan.add_argument("files", nargs="*", help="files to scan; '-' or none reads stdin")
    scan.set_defaults(func=_cmd_scan)

    var = sub.add_parser("variants", help="list variant codes and lengths per secret (no values)")
    _add_registration(var)
    var.set_defaults(func=_cmd_variants)

    hook = sub.add_parser("hook", help="host integrations")
    hook_sub = hook.add_subparsers(dest="host", required=True)
    cc = hook_sub.add_parser("pretooluse", help="Agent PreToolUse hook (reads JSON on stdin)")
    _add_registration(cc)
    cc.add_argument("--deny-env-refs", action="store_true",
                    help="also deny commands that reference registered variable names ($NAME, printenv NAME)")
    cc.set_defaults(func=_cmd_hook)

    dm = sub.add_parser("demo", help="practice run with fake secrets: 16 disguises x 3 secrets")
    dm.add_argument("--write-samples", metavar="DIR", help="also write the sample files, fake.env and hook inputs")
    dm.set_defaults(func=_cmd_demo)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``known-secret-guard`` command."""
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except GuardConfigError as exc:
        print(f"known-secret-guard: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
