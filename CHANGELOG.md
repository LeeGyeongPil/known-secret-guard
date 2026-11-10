# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
