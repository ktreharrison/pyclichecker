"""Configuration for lint rules."""

import re
from dataclasses import dataclass

from pyclichecker.diagnostics import RULES


@dataclass(frozen=True, slots=True)
class LintConfig:
    """Resolved configuration for one lint run."""

    enabled_codes: frozenset[str] = frozenset(RULES)
    max_function_lines: int = 80
    narrating_comment_threshold: int = 3
    duplicate_min_statements: int = 4
    duplicate_min_lines: int = 6


def parse_rule_codes(value: str) -> set[str]:
    """Parse a comma- or whitespace-separated list of rule codes."""

    return {item.strip().upper() for item in re.split(r"[,\s]+", value) if item.strip()}
