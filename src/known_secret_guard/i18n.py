"""Human-readable messages in English and Korean (one table, stdlib only).

Language order: ``--lang en|ko`` > ``KNOWN_SECRET_GUARD_LANG`` > ``LC_ALL`` >
``LC_MESSAGES`` > ``LANG``. A value that does not start with ``ko`` means English.
Machine-readable output (``--json``, ``LEAK``/``clean`` lines, hook deny JSON,
variant codes) is never translated.
"""

from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Mapping, Sequence

LANGUAGES = ("en", "ko")
ENV_VAR = "KNOWN_SECRET_GUARD_LANG"

MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        # argparse chrome
        "usage": "usage: ",
        "error_word": "error",
        "positionals": "positional arguments",
        "options": "options",
        "help_help": "show this help message and exit",
        "version_help": "show the version number and exit",
        "lang_help": "output language: en or ko (default: {env}, then LC_ALL/LC_MESSAGES/LANG, else en)",
        "parser_description": "Block outgoing text that contains a known secret, however it was disguised.",
        "scan_help": "scan files (or stdin) for known secrets",
        "variants_help": "list variant codes and lengths per secret (no values)",
        "hook_help": "host integrations",
        "pretooluse_help": "Agent PreToolUse hook (reads JSON on stdin)",
        "demo_help": "practice run with fake secrets: 16 disguises x 3 secrets",
        "opt_env": "comma-separated environment variable names",
        "opt_env_pattern": "comma-separated globs on variable names, e.g. '*_TOKEN,*_KEY'",
        "opt_env_file": ".env-style file with NAME=value lines",
        "opt_min_length": "ignore values shorter than N (default 8)",
        "opt_exclude": "comma-separated names never to guard",
        "opt_json": "machine-readable output (no values)",
        "opt_files": "files to scan; '-' or none reads stdin",
        "opt_deny_env_refs": "also deny commands that reference registered variable names ($NAME, printenv NAME)",
        "opt_write_samples": "also write the sample files, fake.env and hook inputs",
        # argparse generated errors (translated from the stock English text)
        "ap_required": "the following arguments are required: {names}",
        "ap_invalid_choice": "argument {arg}: invalid choice: {value} (choose from {choices})",
        "ap_invalid_value": "argument {arg}: invalid {kind} value: {value}",
        "ap_expected_one": "argument {arg}: expected one argument",
        "ap_unrecognized": "unrecognized arguments: {args}",
        # cli
        "err_prefix": "known-secret-guard: error: {msg}",
        "no_secrets_cli": ("no secrets registered. Use --env NAME1,NAME2, --env-pattern '*_TOKEN' or "
                           "--env-file PATH and make sure the variables exist in this process."),
        "warn_short": "known-secret-guard: warning: too short to guard (names only): {names}",
        "cannot_read": "cannot read {target}: {reason}",
        "hook_failed": "known-secret-guard: hook failed ({cls}); blocking.",
        "demo_wrote": "wrote {count} sample files + fake.env + hook inputs to {dir}",
        "col_secret": "secret",
        "col_variant": "variant",
        "col_length": "length",
        # hook
        "hook_bad_json": "known-secret-guard: hook input is not valid JSON ({cls}); blocking.",
        "hook_not_object": "known-secret-guard: hook input must be a JSON object; blocking.",
        # sources / guard (GuardConfigError details)
        "missing_arg": "missing must be 'skip' or 'error', got {value}",
        "env_unset": "environment variable(s) not set or empty: {names}. Export them before starting, or pass missing='skip'.",
        "env_file_unreadable": "cannot read env file {path}: {reason}. Check the path and permissions.",
        "env_file_not_utf8": "env file {path} is not valid UTF-8.",
        "min_length_bad": "min_length must be >= 1",
        "name_bad": "secret name must be a non-empty string",
        "value_bad": "value of {name} must be str, got {type}",
        "no_secrets_api": ("no secrets registered: pass names that exist in the environment, "
                           "an env file, or Guard({{'NAME': 'value'}})."),
        # demo
        "banner": "[practice mode] fake secrets built at run time, real matching code, no LLM involved",
        "demo_col_sample": "sample",
        "demo_col_hidden": "hidden as",
        "demo_col_result": "result",
        "demo_must_clean": "(must stay clean)",
        "demo_summary": "caught {caught}/{total} · negative {neg}/{neg_total} clean · secret values printed: {printed}",
        # examples/agent_exfil_sim.py
        "sim_wants": "agent wants to run a {tool} call ({chars} chars)",
        "sim_naive_label": "pattern-only check ",
        "sim_naive_blocked": "blocked",
        "sim_naive_passed": "PASSED (leak goes through)",
        "sim_guard_label": "known-secret-guard ",
        "sim_guard_blocked": "BLOCKED -> {finding}",
        "sim_guard_unexpected": "passed (unexpected)",
    },
    "ko": {
        "usage": "사용법: ",
        "error_word": "오류",
        "positionals": "위치 인자",
        "options": "옵션",
        "help_help": "도움말을 표시하고 종료합니다",
        "version_help": "버전을 표시하고 종료합니다",
        "lang_help": "출력 언어: en 또는 ko (기본값: {env}, 다음 LC_ALL/LC_MESSAGES/LANG, 없으면 en)",
        "parser_description": "알고 있는 비밀값이 어떤 모습으로 위장되어 있더라도 찾아내어 나가는 텍스트를 막습니다.",
        "scan_help": "파일(또는 표준 입력)에서 알려진 비밀값을 검사합니다",
        "variants_help": "비밀값별 변형 코드와 길이를 나열합니다(값은 출력하지 않습니다)",
        "hook_help": "호스트 연동",
        "pretooluse_help": "에이전트 PreToolUse 훅(표준 입력으로 JSON을 읽습니다)",
        "demo_help": "가짜 비밀값으로 하는 연습 실행: 비밀값 3개 x 위장 16가지",
        "opt_env": "쉼표로 구분한 환경 변수 이름",
        "opt_env_pattern": "변수 이름에 적용할 쉼표 구분 글롭, 예: '*_TOKEN,*_KEY'",
        "opt_env_file": "NAME=value 줄로 된 .env 형식 파일",
        "opt_min_length": "N보다 짧은 값은 무시합니다(기본값 8)",
        "opt_exclude": "보호 대상에서 제외할 이름(쉼표로 구분)",
        "opt_json": "기계가 읽는 출력(값은 포함하지 않습니다)",
        "opt_files": "검사할 파일. '-'를 주거나 생략하면 표준 입력을 읽습니다",
        "opt_deny_env_refs": "등록된 변수 이름을 참조하는 명령($NAME, printenv NAME)도 차단합니다",
        "opt_write_samples": "샘플 파일, fake.env, 훅 입력 파일도 함께 씁니다",
        "ap_required": "다음 인자가 필요합니다: {names}",
        "ap_invalid_choice": "인자 {arg}: 올바르지 않은 선택입니다: {value} (선택 가능: {choices})",
        "ap_invalid_value": "인자 {arg}: 올바르지 않은 {kind} 값입니다: {value}",
        "ap_expected_one": "인자 {arg}: 값이 하나 필요합니다",
        "ap_unrecognized": "알 수 없는 인자입니다: {args}",
        "err_prefix": "known-secret-guard: 오류: {msg}",
        "no_secrets_cli": ("등록된 비밀값이 없습니다. --env NAME1,NAME2, --env-pattern '*_TOKEN' 또는 "
                           "--env-file PATH 를 사용하고, 해당 변수가 이 프로세스에 있는지 확인하십시오."),
        "warn_short": "known-secret-guard: 경고: 너무 짧아 보호하지 않습니다(이름만 표시): {names}",
        "cannot_read": "{target} 을(를) 읽을 수 없습니다: {reason}",
        "hook_failed": "known-secret-guard: 훅이 실패했습니다({cls}). 차단합니다.",
        "demo_wrote": "샘플 파일 {count}개와 fake.env, 훅 입력 파일을 {dir} 에 썼습니다",
        "col_secret": "비밀값",
        "col_variant": "변형",
        "col_length": "길이",
        "hook_bad_json": "known-secret-guard: 훅 입력이 올바른 JSON이 아닙니다({cls}). 차단합니다.",
        "hook_not_object": "known-secret-guard: 훅 입력은 JSON 객체여야 합니다. 차단합니다.",
        "missing_arg": "missing 은 'skip' 또는 'error' 여야 하는데 {value} 이(가) 주어졌습니다",
        "env_unset": "환경 변수가 설정되어 있지 않거나 비어 있습니다: {names}. 시작하기 전에 export 하거나 missing='skip' 을 지정하십시오.",
        "env_file_unreadable": "env 파일 {path} 을(를) 읽을 수 없습니다: {reason}. 경로와 권한을 확인하십시오.",
        "env_file_not_utf8": "env 파일 {path} 은(는) 올바른 UTF-8 이 아닙니다.",
        "min_length_bad": "min_length 는 1 이상이어야 합니다",
        "name_bad": "비밀값 이름은 비어 있지 않은 문자열이어야 합니다",
        "value_bad": "{name} 의 값은 str 이어야 하는데 {type} 이(가) 주어졌습니다",
        "no_secrets_api": ("등록된 비밀값이 없습니다. 환경에 있는 이름, env 파일, "
                           "또는 Guard({{'NAME': 'value'}}) 를 전달하십시오."),
        "banner": "[연습 모드] 실행 시점에 만든 가짜 비밀값, 실제 대조 코드, LLM 없음",
        "demo_col_sample": "표본",
        "demo_col_hidden": "위장 방식",
        "demo_col_result": "결과",
        "demo_must_clean": "(깨끗해야 함)",
        "demo_summary": "탐지 {caught}/{total} · 음성 {neg}/{neg_total} 정상 · 출력된 비밀값: {printed}",
        "sim_wants": "에이전트가 {tool} 호출을 실행하려 합니다({chars}자)",
        "sim_naive_label": "패턴만 보는 검사 ",
        "sim_naive_blocked": "차단",
        "sim_naive_passed": "통과(유출이 그대로 나갑니다)",
        "sim_guard_label": "known-secret-guard 검사 ",
        "sim_guard_blocked": "차단 -> {finding}",
        "sim_guard_unexpected": "통과(예상 밖)",
    },
}

_current: str | None = None


def _from_value(value: str | None) -> str | None:
    if not value:
        return None
    return "ko" if value.strip().lower().startswith("ko") else "en"


def resolve_lang(argv_lang: str | None = None, environ: Mapping[str, str] | None = None) -> str:
    """Pick ``"en"`` or ``"ko"``: ``--lang`` > tool env var > LC_ALL > LC_MESSAGES > LANG."""
    env = os.environ if environ is None else environ
    for value in (argv_lang, env.get(ENV_VAR), env.get("LC_ALL"), env.get("LC_MESSAGES"), env.get("LANG")):
        picked = _from_value(value)
        if picked:
            return picked
    return "en"


def lang_from_argv(argv: Sequence[str]) -> str | None:
    """Read ``--lang X`` / ``--lang=X`` before parsing (so help text follows it). Invalid -> None."""
    for i, arg in enumerate(argv):
        if arg == "--":
            break
        value = None
        if arg == "--lang" and i + 1 < len(argv):
            value = argv[i + 1]
        elif arg.startswith("--lang="):
            value = arg[len("--lang="):]
        if value is not None:
            return value if value in LANGUAGES else None
    return None


def set_lang(lang: str | None) -> None:
    """Fix the language for this process (``None`` = decide from the environment on each call)."""
    global _current
    _current = lang if lang in LANGUAGES else None


def current_lang() -> str:
    return _current or resolve_lang()


def t(key: str, **kw: object) -> str:
    """Look up message ``key`` in the current language and fill ``{placeholders}``."""
    text = MESSAGES[current_lang()][key]
    return text.format(**kw) if kw else text.replace("{{", "{").replace("}}", "}")


def width(text: str) -> int:
    """Terminal columns of ``text`` (Korean letters take two)."""
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def pad(text: str, cols: int) -> str:
    """Left-align ``text`` in ``cols`` terminal columns."""
    return text + " " * max(0, cols - width(text))


_RULES = (
    (re.compile(r"^the following arguments are required: (?P<names>.+)$"), "ap_required"),
    (re.compile(r"^argument (?P<arg>.+?): invalid choice: (?P<value>.+?) \(choose from (?P<choices>.+)\)$"),
     "ap_invalid_choice"),
    (re.compile(r"^argument (?P<arg>.+?): invalid (?P<kind>\S+) value: (?P<value>.+)$"), "ap_invalid_value"),
    (re.compile(r"^argument (?P<arg>.+?): expected one argument$"), "ap_expected_one"),
    (re.compile(r"^unrecognized arguments: (?P<args>.+)$"), "ap_unrecognized"),
)


def translate_argparse_error(message: str) -> str:
    """Translate argparse's stock English error text; unknown texts pass through unchanged."""
    if current_lang() == "en":
        return message
    for pattern, key in _RULES:
        match = pattern.match(message)
        if match:
            return t(key, **match.groupdict())
    return message
