# Contributing

Contributions that improve signal, reduce false positives, or make the command
easier to use are welcome.

## Development setup

The project requires Python 3.14 and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/ktreharrison/pyclichecker.git
cd pyclichecker
uv sync --locked
```

## Validation

Run the core quality checks before opening a pull request:

```bash
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
```

Then run the built-archive inspection, installed-CLI smoke tests, and
fresh-directory wheel test documented in [AGENTS.md](AGENTS.md).

## Rule changes

Every new rule needs a permanent `SLP` code, an actionable diagnostic, and
tests for:

- Code that must produce the finding.
- Corrected code that must not produce the finding.
- Relevant false-positive cases, including aliases, shadowing, delegation,
  fixtures, and suppressions.

Prefer behavioral defects and high-signal maintainability risks over formatting
or style checks already covered by Ruff.

## Reporting a false positive

Open an issue with the rule code, a minimal source example, the actual result,
and the result you expected. Remove credentials and proprietary code before
posting.

## Maintainer releases

1. Update the version in `pyproject.toml`, refresh `uv.lock`, and add the
   matching `CHANGELOG.md` entry.
2. Run every validation and package inspection command in `AGENTS.md`.
3. Merge the release commit to `main` and create a GitHub release tagged
   `v<version>`.
4. The `publish.yml` workflow verifies the tag, rebuilds and smoke-tests the
   archives, checks PyPI for matching immutable files, then publishes any new
   files through Trusted Publishing.

The publishing job uses GitHub's short-lived OIDC identity. Do not add a PyPI
API token to repository secrets.
