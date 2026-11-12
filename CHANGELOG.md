# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-12

### Added
- English and Korean output. Choose with `--lang en|ko` (accepted before or after any subcommand), then the `KNOWN_SECRET_GUARD_LANG` environment variable, then `LC_ALL`, `LC_MESSAGES`, `LANG`; anything that does not start with `ko` means English.
- All human-readable text is translated: help, usage errors, warnings, errors, hook stderr messages, the demo table and summary, and `GuardConfigError` details.
- New module `known_secret_guard.i18n` with a single message table (standard library only).

### Changed
- Users with a Korean locale (`LANG=ko_KR.UTF-8`) now see Korean text by default. Set `KNOWN_SECRET_GUARD_LANG=en` or pass `--lang en` to keep English. `GuardConfigError` messages raised by the library API also follow the environment language.
- Machine-readable output is unchanged in every language: `--json`, `LEAK`/`clean` lines, variant codes, the hook's stdout deny JSON (including the `known-secret-guard: NAME:VARIANT at <path>` reason), and exit codes.

## [0.1.3] - 2026-11-10

### Fixed
- Build no longer warns about the deprecated PEP 639 license classifier; the redundant `License :: OSI Approved :: MIT License` classifier was removed (license metadata stays in `License-Expression: MIT`).

## [0.1.2] - 2026-11-10

### Fixed
- `.env` parsing: a trailing `# comment` after a value (quoted or not) is no longer registered as part of the secret, so encoded leaks of the real value are caught.

## [0.1.1] - 2026-11-10

### Changed
- README: replace the tool comparison table with a short when-to-use section.

## [0.1.0] - 2026-11-09

### Added
- `Guard` with registration from a dict, environment variable names, name globs and `.env` files; minimum length and exclude list.
- Variant set per secret: raw, URL, form-URL, JSON, repr, hex, HTML entities, base64 (standard and URL-safe, three alignments, stable segments only), split halves.
- Normalised re-check (HTML/URL un-escape, tag and zero-width removal, whitespace, casefold) applied to both the secret and the outgoing text.
- Scanning of `str`, `bytes` and nested `dict`/`list` with field paths; dict keys that leak are reported by position.
- Value-free reporting: `Finding`, `LeakDetected` and every CLI/hook output carry names, variant codes and field paths only.
- CLI: `scan`, `variants`, `hook pretooluse` (with `--deny-env-refs`), `demo`.
- Agent `PreToolUse` hook that denies on a hit and exits 2 (fail closed) on broken input or configuration.
- Examples: `quickstart.py`, `agent_exfil_sim.py` (scripted agent, no LLM), `pretooluse-settings.json`.
