# AGENTS.md

## Purpose

This repository builds the `pyclichecker` command, a read-only AST linter for
Python quality defects associated with rushed or generated code.

## Runtime

- The project requires Python 3.14.
- Package and environment operations use `uv`.
- Runtime code has no third-party dependencies.
- MUST NOT add a runtime dependency when the standard library provides a clear implementation.
- MUST keep source under `src/pyclichecker/` and tests under `tests/`.

## Rule changes

- MUST give each new rule a permanent `SLP` code, severity, title, and actionable description.
- MUST NOT reuse or silently change the meaning of an existing code.
- MUST favor behavioral defects and high-signal maintainability risks over style checks already handled by Ruff.
- MUST add a positive test, a negative test, and relevant false-positive tests for every rule.
- MUST keep output deterministic by sorting diagnostics by path, line, column, and code.
- SHOULD explain the concrete risk and a practical correction in each diagnostic.

## Suppressions

- MUST parse suppression directives from comment tokens, not source substrings.
- MUST require an explicit `SLP` code for inline suppression.
- MUST NOT make bare `# noqa` suppress pyclichecker.
- SHOULD fix a finding before adding a suppression.

## CLI compatibility

- Exit `0` means a complete run with no finding at the configured failure
  threshold.
- Exit `1` means findings met the configured failure threshold.
- Exit `2` means the scan was incomplete or could not operate.
- MUST preserve text, JSON, and GitHub output modes.
- MUST treat operational errors as exit `2`, even when findings are also present.

## Testing

Run every check from the repository root.

### Unit tests

```bash
uv run python -m unittest discover -v
```

Every changed rule MUST have:

- A source example that reports the rule.
- A corrected example that does not report it.
- False-positive coverage for aliases, shadowing, delegation, test fixtures, or suppressions when relevant.

### Static checks

```bash
uv run ruff check .
uv run ruff format --check .
```

### Self-lint

```bash
uv run pyclichecker src tests
```

### Package build

```bash
uv build
```

### Built archive inspection

```bash
for archive in dist/*.whl; do
    uv run python -m zipfile -l "$archive"
done
for archive in dist/*.tar.gz; do
    tar -tzf "$archive"
done
```

### Installed CLI smoke tests

```bash
uvx --from . pyclichecker --version
uvx --from . pyclichecker --list-rules
uvx --from . pyclichecker src tests
```

### Fresh-directory package smoke test

Run the built wheel away from the repository so imports cannot accidentally resolve from the checkout:

```bash
repo_root="$PWD"
version="$(uv run python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
wheel="$repo_root/dist/pyclichecker-$version-py3-none-any.whl"
scratch="$(mktemp -d)"
(
    cd "$scratch"
    uvx --from "$wheel" pyclichecker --version
    uvx --from "$wheel" pyclichecker --list-rules
    uvx --from "$wheel" pyclichecker "$repo_root/src" "$repo_root/tests"
)
```

## Release changes

- MUST keep the project version and `CHANGELOG.md` aligned.
- MUST inspect both wheel and source archive contents before release.
- MUST run the built wheel from a fresh directory using only documented commands.
- MUST preserve the approved MIT license in package metadata and release
  archives.
- MUST scan for credentials, personal paths, and internal references before a
  public push.
