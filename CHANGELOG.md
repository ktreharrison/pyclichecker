# Changelog

## 2.4.2 - 2026-08-21

- Added Ubuntu, macOS, and Windows CI coverage for tests, static checks,
  package builds, and installed-wheel smoke tests.
- Made release retries duplicate-aware by checking PyPI before uploading an
  immutable distribution file.
- Updated the bundled Agent Skill and documentation to pin version 2.4.2.

## 2.4.1 - 2026-08-21

- Calibrated `SLP015` to report overridable constructor dispatch only while
  definitely initialized instance state is still pending.
- Reduced `SLP016` false positives for `hasattr()` guards, test-and-set
  initialization, and explicit `AttributeError` fallback.
- Exempted test modules from `SLP017`, where shared mutable containers are
  commonly intentional recorders and fixtures.
- Added PyPI Trusted Publishing and documented the short
  `uvx pyclichecker .` command.
- Updated the bundled Agent Skill to use the pinned PyPI release.

## 2.4.0 - 2026-08-21

- Added `SLP015` for constructor calls that dispatch to overridable same-class
  methods before initialization is complete.
- Added `SLP016` for instance attributes that are initialized on only some
  successful constructor paths and later read without a local assignment.
- Added `SLP017` for instance methods that mutate mutable list, dictionary, or
  set state inherited from the class.
- Added conservative exemptions for final and private methods, class fallbacks,
  dynamic attributes, `ClassVar`, per-instance initialization, explicit class
  mutation, and nested scopes.
- Added positive, corrected, false-positive, and inline-suppression coverage
  for all three class-correctness rules.

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
