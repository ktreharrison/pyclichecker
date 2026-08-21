"""Public API for pyclichecker."""

from pyclichecker._version import VERSION, __version__
from pyclichecker.cli import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_OPERATIONAL_ERROR,
    main,
)
from pyclichecker.config import LintConfig
from pyclichecker.diagnostics import RULES, Finding, Rule
from pyclichecker.discovery import discover_python_files, lint_files
from pyclichecker.rules import lint_source

__all__ = [
    "RULES",
    "VERSION",
    "EXIT_CLEAN",
    "EXIT_FINDINGS",
    "EXIT_OPERATIONAL_ERROR",
    "Finding",
    "LintConfig",
    "Rule",
    "__version__",
    "discover_python_files",
    "lint_files",
    "lint_source",
    "main",
]
