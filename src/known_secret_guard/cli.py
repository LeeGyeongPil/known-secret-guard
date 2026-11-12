"""Command line: ``scan``, ``variants``, ``hook pretooluse``, ``demo``.

Exit codes: 0 clean, 1 leak found, 2 configuration or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import NoReturn

from . import __version__, sources
from . import demo as demo_mod
from .findings import GuardConfigError
from .guard import Guard
from .hooks import pretooluse
from .i18n import (ENV_VAR, LANGUAGES, lang_from_argv, pad, resolve_lang, set_lang, t,
                   translate_argparse_error)


class _Formatter(argparse.HelpFormatter):
    """Help formatter whose ``usage:`` prefix follows the chosen language."""

    def add_usage(self, usage, actions, groups, prefix=None):  # type: ignore[no-untyped-def]
        return super().add_usage(usage, actions, groups, t("usage") if prefix is None else prefix)


class _Parser(argparse.ArgumentParser):
    """ArgumentParser with localized group titles and error line (no gettext catalogs)."""

    def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs.setdefault("formatter_class", _Formatter)
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self._positionals.title = t("positionals")
        self._optionals.title = t("options")
        self.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help=t("help_help"))

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: {t('error_word')}: {translate_argparse_error(message)}\n")


def _lang_parent() -> argparse.ArgumentParser:
    """Shared ``--lang`` option; accepted before or after any subcommand."""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--lang", choices=LANGUAGES, default=argparse.SUPPRESS, metavar="{en,ko}",
                        help=t("lang_help", env=ENV_VAR))
    return parent


def _split(csv: str | None) -> list[str]:
    return [p.strip() for p in (csv or "").split(",") if p.strip()]


def _add_registration(p: argparse.ArgumentParser) -> None:
    p.add_argument("--env", metavar="NAMES", help=t("opt_env"))
    p.add_argument("--env-pattern", metavar="GLOBS", help=t("opt_env_pattern"))
    p.add_argument("--env-file", metavar="PATH", help=t("opt_env_file"))
    p.add_argument("--min-length", type=int, default=8, metavar="N", help=t("opt_min_length"))
    p.add_argument("--exclude", metavar="NAMES", help=t("opt_exclude"))


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
        raise GuardConfigError(t("no_secrets_cli"))
    if guard.skipped:
        print(t("warn_short", names=", ".join(guard.skipped)), file=sys.stderr)
    return guard


def _read_target(target: str) -> bytes:
    try:
        if target == "-":
            return sys.stdin.buffer.read()
        with open(target, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise GuardConfigError(t("cannot_read", target=repr(target), reason=exc.strerror)) from exc


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
    print(f"{pad(t('col_secret'), 24)} {pad(t('col_variant'), 16)} {t('col_length')}")
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
        print(t("hook_failed", cls=exc.__class__.__name__), file=sys.stderr)
        return 2


def _cmd_demo(args: argparse.Namespace) -> int:
    lines, ok = demo_mod.run_demo()
    print("\n".join(lines))
    if args.write_samples:
        count = demo_mod.write_samples(args.write_samples)
        print(t("demo_wrote", count=count, dir=args.write_samples))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (exposed for tests)."""
    lang = [_lang_parent()]
    parser = _Parser(prog="known-secret-guard", description=t("parser_description"), parents=lang)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}", help=t("version_help"))
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help=t("scan_help"), parents=lang)
    _add_registration(scan)
    scan.add_argument("--json", action="store_true", help=t("opt_json"))
    scan.add_argument("files", nargs="*", help=t("opt_files"))
    scan.set_defaults(func=_cmd_scan)

    var = sub.add_parser("variants", help=t("variants_help"), parents=lang)
    _add_registration(var)
    var.set_defaults(func=_cmd_variants)

    hook = sub.add_parser("hook", help=t("hook_help"), parents=lang)
    hook_sub = hook.add_subparsers(dest="host", required=True)
    cc = hook_sub.add_parser("pretooluse", help=t("pretooluse_help"), parents=lang)
    _add_registration(cc)
    cc.add_argument("--deny-env-refs", action="store_true",
                    help=t("opt_deny_env_refs"))
    cc.set_defaults(func=_cmd_hook)

    dm = sub.add_parser("demo", help=t("demo_help"), parents=lang)
    dm.add_argument("--write-samples", metavar="DIR", help=t("opt_write_samples"))
    dm.set_defaults(func=_cmd_demo)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``known-secret-guard`` command."""
    arg_list = sys.argv[1:] if argv is None else list(argv)
    # Decide the language first so --help and usage errors are already localized.
    set_lang(resolve_lang(lang_from_argv(arg_list)))
    try:
        args = build_parser().parse_args(arg_list)
        try:
            return int(args.func(args))
        except GuardConfigError as exc:
            print(t("err_prefix", msg=exc), file=sys.stderr)
            return 2
    finally:
        set_lang(None)


if __name__ == "__main__":
    sys.exit(main())
