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

Run every check before opening a pull request:

```bash
uv run python -m unittest discover -v
uv run ruff check .
uv run ruff format --check .
uv run pyclichecker src tests
uv build
```

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
   archives, then publishes them to PyPI through Trusted Publishing.

The publishing job uses GitHub's short-lived OIDC identity. Do not add a PyPI
API token to repository secrets.
