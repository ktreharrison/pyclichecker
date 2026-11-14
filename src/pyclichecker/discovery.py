"""File discovery and source loading."""

import fnmatch
import os
import sys
import tokenize
from collections.abc import Iterable, Sequence
from pathlib import Path

from pyclichecker.config import LintConfig
from pyclichecker.diagnostics import Finding
from pyclichecker.rules import lint_source

DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "venv",
    }
)


def _matches_exclude(relative_path: Path, patterns: Sequence[str]) -> bool:
    value = relative_path.as_posix()
    return any(
        fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch(relative_path.name, pattern)
        for pattern in patterns
    )


def _python_files_in_directory(
    root: Path,
    *,
    exclude_patterns: Sequence[str],
    errors: list[str],
) -> Iterable[Path]:
    def record(error: OSError) -> None:
        # os.walk skips unreadable directories silently by default, which
        # reported an incomplete scan as clean (exit 0). An unread directory
        # is an operational error.
        errors.append(f"cannot read directory {error.filename}: {error.strerror}")

    for current, directories, files in os.walk(root, onerror=record):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in DEFAULT_EXCLUDED_DIRECTORIES
            and not _matches_exclude(relative_current / directory, exclude_patterns)
        )
        for filename in sorted(files):
            if not filename.endswith(".py"):
                continue
            path = current_path / filename
            relative_path = path.relative_to(root)
            if not _matches_exclude(relative_path, exclude_patterns):
                yield path


def discover_python_files(
    inputs: Sequence[str],
    *,
    exclude_patterns: Sequence[str] = (),
) -> tuple[list[Path], bool, list[str]]:
    """Resolve CLI inputs into unique Python files, stdin, and errors."""

    files: list[Path] = []
    use_stdin = False
    errors: list[str] = []
    seen: set[Path] = set()

    for raw_input in inputs or (".",):
        if raw_input == "-":
            use_stdin = True
            continue

        path = Path(raw_input).expanduser()
        if not path.exists():
            errors.append(f"path does not exist: {raw_input}")
            continue
        candidates: Iterable[Path]
        if path.is_file():
            if path.suffix != ".py":
                errors.append(f"not a Python file: {raw_input}")
                continue
            candidates = (path,)
        elif path.is_dir():
            candidates = _python_files_in_directory(
                path,
                exclude_patterns=exclude_patterns,
                errors=errors,
            )
        else:
            errors.append(f"unsupported path type: {raw_input}")
            continue

        for candidate in candidates:
            identity = candidate.resolve()
            if identity not in seen:
                seen.add(identity)
                files.append(candidate)

    return sorted(files, key=lambda item: item.as_posix()), use_stdin, errors


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(path)


def _lint_one(
    source: str,
    display_path: str,
    config: LintConfig,
    findings: list[Finding],
    errors: list[str],
) -> bool:
    """Lint one source, recording resource exhaustion as an operational error.

    Deeply nested expressions exhaust the parser or the recursive visitors.
    Letting that escape gave a traceback and exit 1 (the "findings" code)
    and dropped every other file's findings, including JSON output.
    """

    try:
        file_findings = lint_source(source, path=display_path, config=config)
    except (RecursionError, MemoryError) as error:
        errors.append(
            f"{display_path}: too deeply nested to analyze ({type(error).__name__})"
        )
        return False
    findings.extend(file_findings)
    return True


def lint_files(
    files: Sequence[Path],
    *,
    use_stdin: bool,
    config: LintConfig,
) -> tuple[list[Finding], int, list[str]]:
    """Load and lint discovered files and optional standard input."""

    findings: list[Finding] = []
    errors: list[str] = []
    files_checked = 0

    if use_stdin:
        try:
            source = sys.stdin.read()
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"<stdin>: {error}")
        else:
            if _lint_one(source, "<stdin>", config, findings, errors):
                files_checked += 1

    for path in files:
        display_path = _display_path(path)
        try:
            with tokenize.open(path) as source_file:
                source = source_file.read()
        except (OSError, SyntaxError, UnicodeError) as error:
            errors.append(f"{display_path}: {error}")
            continue
        if _lint_one(source, display_path, config, findings, errors):
            files_checked += 1

    return (
        sorted(
            findings,
            key=lambda item: (item.path, item.line, item.column, item.code),
        ),
        files_checked,
        errors,
    )
