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
