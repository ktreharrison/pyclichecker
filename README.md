# pyclichecker

[![CI](https://github.com/ktreharrison/pyclichecker/actions/workflows/ci.yml/badge.svg)](https://github.com/ktreharrison/pyclichecker/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pyclichecker.svg)](https://pypi.org/project/pyclichecker/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**High-signal behavioral linting for Python.**

`pyclichecker` is a read-only Python linter for high-signal defects and
maintainability smells that often appear in rushed or generated code. It parses
source with Python's AST and token APIs and has no runtime dependencies.

It is a code-quality tool, not an AI-authorship detector. The same finding can
occur in human-written code, and every finding should be judged in context.

## Quick start

The project requires Python 3.14. Run it directly without installing:

```bash
uvx pyclichecker .
```

For a persistent command, install it with `uv`:

```bash
uv tool install pyclichecker
pyclichecker .
```

It can lint one file, consume standard input, emit JSON for an agent, or emit
GitHub workflow annotations:

```bash
pyclichecker app.py
printf 'def unfinished():\n    pass\n' | pyclichecker -
pyclichecker . --format json
pyclichecker . --format github
```

Pin a release when reproducibility matters:

```bash
uvx pyclichecker@2.4.3 .
```

## Reading a result

Text diagnostics use the conventional `path:line:column: code message` shape:

```text
app.py:8:1: SLP001 `load_config` is a concrete placeholder implementation
Found 1 issue(s) in 1 file(s).
```

A practical review loop is:

1. Open the reported file and line.
2. Decide whether the behavior is intentional.
3. Fix the implementation, error handling, or structure.
4. Run the same command again.
5. Suppress only the specific rule when the code is intentionally exceptional.

## Rules

`pyclichecker --list-rules` reports these rules:

| Code | Severity | Check | Typical correction |
|---|---|---|---|
| `SLP000` | error | Invalid Python syntax | Correct the reported syntax before trusting the rest of the scan. |
| `SLP001` | error | Placeholder implementation | Implement the function, remove it, or make the contract explicitly abstract. |
| `SLP002` | error | Silently swallowed exception | Handle, record, or re-raise the failure. |
| `SLP003` | warning | Broad exception converted to fallback behavior | Catch the failures you expect and preserve unexpected ones. |
| `SLP004` | warning | Async function with no async behavior | Make it synchronous or perform the intended awaited operation. |
| `SLP005` | warning | Duplicate implementation in the same file | Extract shared behavior so copies cannot drift. |
| `SLP006` | error | Obvious placeholder in configuration | Require a real configured value instead of shipping a dummy fallback. |
| `SLP007` | warning | Cluster of narrating comments | Remove narration or replace it with the reason behind non-obvious code. |
| `SLP008` | warning | Oversized function | Split distinct responsibilities and test them independently. |
| `SLP009` | warning | Unchecked `subprocess.run` result | Use `check=True`, validate `returncode` before reading output, or deliberately return the complete result. |
| `SLP010` | warning | Synchronous network call omits a timeout or sets it to `None` | Pass an explicit timeout appropriate for the operation. |
| `SLP011` | warning | HTTP response consumed without a success check | Call `raise_for_status()` or validate the status on every path before using the body. |
| `SLP012` | warning | Path tied to one user's home directory | Use `Path.home()`, a project-relative path, or configuration. |
| `SLP013` | warning | Known blocking API called inside async code | Use an async API or move the blocking call to a worker thread. |
| `SLP014` | warning | Test has no explicit result or failure oracle | Use an assertion, a recognized test-framework oracle, or an expected-failure declaration. Arbitrary `assert_*` helper names are not trusted automatically. |
| `SLP015` | warning | Overridable method called before constructor state is initialized | Initialize state before dispatch, or make the hook private or final. |
| `SLP016` | warning | Instance state initialized on only some constructor paths | Initialize the attribute unconditionally before other methods can read it. |
| `SLP017` | warning | Shared mutable class state changed through an instance in production code | Initialize it per instance or mark intentional shared state as `ClassVar`. |

Rule selection accepts exact codes or prefixes:

```bash
pyclichecker . --select SLP001,SLP002
pyclichecker . --ignore SLP004,SLP008
```

Thresholds for function size, comment clusters, and duplicate bodies are
exposed as command-line options. Run `pyclichecker --help` for their names and
defaults.

For a first pass, fix `error` findings before reviewing `warning` findings.
Warnings are prompts for engineering judgment, not proof that the code is
wrong.

## Review coverage and performance

`pyclichecker` complements, rather than replaces, general-purpose quality
tools. This repository also gates changes with Ruff, strict mypy, Bandit,
pip-audit, unit tests, and branch coverage. See
[Review coverage and limits](https://github.com/ktreharrison/pyclichecker/blob/main/docs/review-coverage.md)
for the mapping to the Real Python review and agentic-engineering workflows.

Performance coverage is deliberately narrow. `SLP013` catches selected
blocking calls in async code, and Ruff's `PERF` rules catch known local
performance anti-patterns. `pyclichecker` does not infer Big-O complexity,
detect general N+1 behavior, or replace benchmarks and profiling.

## Suppressions

Inline suppression requires an explicit pyclichecker rule code:

```python
def intentional_stub():  # noqa: SLP001
    pass


def another_stub():  # slop: ignore [SLP001]
    pass
```

Bare `# noqa` and unrelated codes such as `# noqa: F401` do not suppress
pyclichecker. A code-specific directive may include a trailing reason and may
follow a `# type: ignore[...]` directive on the same line. Directive-like prose
and text inside a string are ignored.

To suppress an entire file, place this real comment within its first five
lines:

```python
# slop: ignore-file
```

## Exit codes

- `0`: no finding met `--fail-on`, and the run had no operational error.
- `1`: at least one finding met the configured failure severity.
- `2`: the scan could not run completely, including missing paths, unreadable
  files, unsupported inputs, or no discovered Python files.

`--fail-on warning` is the default. `--fail-on error` reports warnings without
failing, and `--fail-on never` reports all findings without failing.

## Agent use

The repository includes a reusable
[`pyclichecker` Agent Skill](skills/pyclichecker/SKILL.md). Skill-aware agents
can load that folder and run the linter through `uvx` without permanently
installing the package.

Agents should use the pinned release and JSON output for stable results:

```bash
uvx pyclichecker@2.4.3 changed_file.py --format json
```

JSON output contains the package version, number of files checked, findings,
and operational errors. Each finding includes path, line, column, code,
severity, and message.

Treat exit `1` as work to review and exit `2` as a broken or incomplete scan.
Fix findings before adding suppressions, and keep every suppression scoped to
one explicit rule.

An agent should finish only after the same command returns `0`, or after it
records why each remaining finding is intentional. It should never treat exit
`2` as a clean result.

For agents that do not load skills, add this portable contract to the
project's `AGENTS.md`:

```markdown
## Python quality gate

After creating or changing Python code:

1. Run pyclichecker on every changed Python file:
   `uvx pyclichecker@2.4.3 changed_file.py --format json`
2. Treat exit 1 as findings to fix and exit 2 as an incomplete scan.
3. Fix findings and rerun relevant tests. Do not add broad suppressions.
4. Run the final repository gate with the same command, replacing
   `changed_file.py` with `.`, and finish only when it exits 0.
```

## Development

The locked development environment contains Ruff and uses the standard-library
`unittest` runner. It also includes strict typing, branch coverage, security,
and dependency-audit gates:

```bash
uv sync --locked
uv run python -m unittest discover -v
uv run coverage erase
uv run coverage run -m unittest discover -v
uv run coverage report
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run bandit -q -r src
uv export --quiet --locked --all-groups --no-emit-project --format requirements.txt --output-file .audit-requirements.txt
uv run pip-audit --strict --requirement .audit-requirements.txt
uv run pyclichecker src tests
uv build
uvx --from . pyclichecker --version
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for rule and pull-request requirements.

The implementation has been exercised on macOS with CPython 3.14. The GitHub
Actions workflow is configured to run the complete validation suite on Linux.

## License

Released under the [MIT License](LICENSE).
