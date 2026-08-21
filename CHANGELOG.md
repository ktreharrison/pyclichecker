# Changelog

## 2.3.0 - 2026-08-21

- Added `SLP009` for unchecked `subprocess.run` outcomes.
- Added `SLP010` for synchronous network calls that omit a timeout or set it to
  `None`.
- Added `SLP011` for HTTP responses consumed without a success check.
- Added `SLP012` for hardcoded paths tied to a user's home directory.
- Added `SLP014` for tests that can pass without an explicit result or
  expected-failure oracle.
- Expanded `SLP006` to inspect environment defaults, mappings, keyword
  arguments, and function defaults.
- Added import-alias, shadowing, delegation, suppression, and false-positive
  coverage for the new checks.
- Added a version-pinned Agent Skill and portable `AGENTS.md` workflow for
  running strict changed-file and repository gates through `uvx`.
- Added MIT licensing, public project metadata, contribution guidance, and
  pinned GitHub Actions validation.

## 2.2.0 - 2026-08-21

- Converted the standalone script into a Python 3.14 `uv` package with a
  `pyclichecker` console command.
- Added locked development tooling, module and console entry points, structured
  modules, and a 26-test suite.
- Preserved all ten existing rules, including `SLP013` diagnostics for known
  blocking calls inside async functions.
- Made suppressions token-aware so directive-like strings no longer hide
  findings.
- Required explicit `SLP` codes for inline `noqa` suppression.
- Made zero-file scans return operational exit code `2`.

## 2.1.0

- This version number came from the original standalone script. No earlier
  release notes were available in the source folder.
