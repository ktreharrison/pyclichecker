# Changelog

## Unreleased

- `SLP018`, `SLP009` and `SLP011` now check class bodies, which run once at
  class definition. A status, result or response bound to a class-level name is
  a class attribute and counts as observed. Lambda bodies stay out of these
  flow-based rules: a lambda runs later, outside the handlers around its
  definition (and `SLP018` cannot fire in a lambda, which has no statements).
  An HTTP call used as a method's default argument is now reported like one in
  a module-level default.

- Class bodies resolve names like Python does: a class-level import or
  assignment inside a class defined in a function now applies to that class body,
  and a nested class no longer sees names bound in the class it is nested in.
  This found missed `SLP018` findings and removed a false one.
- A command status, subprocess result or HTTP response bound in a class body
  and read later in that same body is checked like module-level code
  (`SLP009`/`SLP018`/`SLP011`); only results left as class attributes count as
  observed. Chained assignments (`a = b = subprocess.run(...)`) count as bindings.

## 2.6.0 - 2026-11-14

- `SLP020` no longer treats pytest markers (`@pytest.mark.*`, also via `from pytest import mark`) as registering decorators, so a marker-decorated stub stays an `SLP001` error; `@pytest.fixture` stubs remain `SLP020`.
- README: a Test code section on `SLP009` volume in tests and the existing
  `--exclude`, `--ignore` and `--baseline` options (#13). Rule severity is
  unchanged.
- `SLP004` no longer reports a nested `async def` that is passed, returned or
  stored, or a function registered through a decorator: the caller requires the
  async signature (#12). pytest markers do not count. Async comprehensions now
  count as async behavior; they were false positives. On httpx b5addb6, SLP004
  went from 40 to 10.
- Added `SLP020` (low confidence). `SLP001` placeholders that show a sign of intent (a class method that raises `NotImplementedError`, a docstring describing a subclass hook, or a nested function that is passed or returned) are reported as `SLP020` instead of `SLP001`. Existing `# noqa: SLP001` comments and baselines still apply to them, `--select SLP001` still reports them, and `--ignore SLP001` still hides them.
- `SLP020` docstring signals (subclass, override, hook, by default, no-op) now match
  whole words. A substring test read "webhook" as "hook" and reported a concrete
  stub as a warning instead of an `SLP001` error, so `--fail-on error` passed it.
  Inflected forms such as "overridden" and "hooks" now also count.
- A nested function passed on through a conditional or boolean expression
  (`register(cb if flag else None)`, `cb or default`) now counts as escaping.
- A file too deeply nested to analyze (`RecursionError`, `MemoryError`) is now
  reported as an operational error (exit 2) instead of crashing with exit 1, and
  the other files' findings are still reported.
- `--ignore` with only separators (for example `","`) no longer ignores every rule.
- `SLP010` no longer reports a missing timeout when the call passes `**options`
  that may carry it; a `**{...}` dict literal is still checked.
- An unreadable subdirectory is now an operational error (exit 2); it was skipped
  silently and the incomplete scan reported as clean.
- `SLP000` now reports code that parses but does not compile (`return` outside a
  function, `break` outside a loop, duplicate parameters, top-level `await`).
- `SLP019` and `SLP010` now check class bodies, decorators, default arguments and
  lambda bodies, which run at definition time and were skipped.
- `SLP018` now follows every name in `a = b = os.system(...)` and a bare
  `(status := os.system(...))`; both were treated as observed without a read.
- Diagnostic columns count characters, not UTF-8 bytes; a non-ASCII character
  earlier on the line moved the reported column right. Fingerprints are unchanged.
- `SLP014` counts a test oracle evaluated in a loop's iterable
  (`for _ in [pytest.fail(...)]`), which runs even when the body does not.
- `SLP010` reads a `**{...}` dict literal to the end, so a later duplicate `timeout`
  key or `**entry` decides the effective timeout.
- `SLP020` no longer treats a nested callback as escaping when it is only called
  (`(cb if flag else other)()`) or only truth-tested (`cb and x`).
- A compile-time `SLP000` honors an explicit `# noqa: SLP000`, and compiling no
  longer races on the process-wide warning filters when linting from threads.
- Comprehension targets shadow imported modules of the same name for `SLP010` and
  `SLP019` (`[tempfile.mktemp() for tempfile in values]` is not a tempfile call).

## 2.5.0 - 2026-10-11

- Expanded Python runtime and syntax compatibility to Python >=3.12, including
  Python 3.12 and 3.13 classifiers and configuration.
- Added evidence-rich JSON findings with confidence, related locations, and
  line-independent content fingerprints.
- Added `--baseline` support so established repositories can report and fail
  only on findings absent from a prior JSON result.
- Added `SLP018` for discarded return statuses from `os.system` and
  `subprocess.call`.
- Added `SLP019` for insecure temporary file creation via `tempfile.mktemp`.
- Added an executable differential corpus for Ruff, Pyright, ty, and
  pyclichecker, plus explicit source-encoding regression coverage.
- Documented pyclichecker's place beside formatters, general linters, type
  checkers, tests, and the internal flow-analysis model.
- Added a post-publish, no-cache public PyPI installation verification.

## 2.4.3 - 2026-09-19

- Tightened suppression parsing so prose cannot masquerade as a directive,
  while preserving code-specific suppressions with trailing reasons, adjacent
  type-ignore directives, and multiline-call closing lines.
- Improved alias and shadowing handling for protocols, abstract methods,
  overloads, and test oracles, including contract imports inside module and
  class control flow and stricter recognition of attribute-style assertions.
- Made broad-exception, subprocess, HTTP-response, constructor-loop, and
  standard-input analysis follow the relevant control flow more accurately.
- Corrected nested re-raise classification, exceptional result abandonment,
  guaranteed loop checks, status-constant aliases, derived HTTP predicates, and
  inverted predicate polarity in subprocess and HTTP flow analysis.
- Indexed operational-result uses so stricter subprocess and HTTP validation
  remains fast on functions with many calls.
- Added strict mypy, branch coverage, Ruff
  security/datetime/complexity/performance rules, Bandit, and pip-audit to the
  locked development and CI gates.
- Documented review coverage, agentic handoff expectations, and the explicit
  limit that pyclichecker does not infer formal time complexity.

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
