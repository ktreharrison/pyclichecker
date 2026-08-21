"""Command-line interface for pyclichecker."""

import argparse
import json
import sys
from collections.abc import Sequence

from pyclichecker._version import VERSION
from pyclichecker.config import LintConfig, parse_rule_codes
from pyclichecker.diagnostics import RULES, Finding
from pyclichecker.discovery import discover_python_files, lint_files

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_OPERATIONAL_ERROR = 2


def _expand_codes(value: str, parser: argparse.ArgumentParser) -> set[str]:
    requested = parse_rule_codes(value)
    if not requested or "ALL" in requested:
        return set(RULES)

    expanded: set[str] = set()
    unknown: list[str] = []
    for item in sorted(requested):
        matches = {code for code in RULES if code == item or code.startswith(item)}
        if matches:
            expanded.update(matches)
        else:
            unknown.append(item)
    if unknown:
        parser.error(f"unknown rule code or prefix: {', '.join(unknown)}")
    return expanded


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def _add_threshold_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-function-lines",
        type=_positive_int,
        default=80,
        metavar="N",
        help="SLP008 threshold; zero disables the rule (default: 80)",
    )
    parser.add_argument(
        "--narrating-comments",
        type=_positive_int,
        default=3,
        metavar="N",
        help="SLP007 threshold; zero disables the rule (default: 3)",
    )
    parser.add_argument(
        "--duplicate-min-statements",
        type=_positive_int,
        default=4,
        metavar="N",
        help="minimum statements for SLP005 (default: 4)",
    )
    parser.add_argument(
        "--duplicate-min-lines",
        type=_positive_int,
        default=6,
        metavar="N",
        help="minimum function lines for SLP005 (default: 6)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""

    parser = argparse.ArgumentParser(
        prog="pyclichecker",
        description="Read-only linter for high-signal AI-generated Python code smells.",
        epilog=(
            "Examples:\n"
            "  pyclichecker .\n"
            "  pyclichecker src tests --ignore SLP004,SLP008\n"
            "  pyclichecker app.py --format json\n"
            "Inline suppression: # noqa: SLP003"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Python files or directories (default: .)",
    )
    parser.add_argument(
        "--select",
        default="ALL",
        help="comma-separated rule codes or prefixes (default: ALL)",
    )
    parser.add_argument(
        "--ignore",
        default="",
        help="comma-separated rule codes or prefixes to ignore",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="exclude a relative path glob; may be repeated",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "github"),
        default="text",
        help="diagnostic output format",
    )
    parser.add_argument(
        "--fail-on",
        choices=("warning", "error", "never"),
        default="warning",
        help="minimum severity that produces exit 1",
    )
    _add_threshold_arguments(parser)
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="list rules and exit",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def _print_rules() -> None:
    for rule in RULES.values():
        print(f"{rule.code} {rule.severity:<7} {rule.title}: {rule.description}")


def _render_text(
    findings: Sequence[Finding],
    *,
    files_checked: int,
    errors: Sequence[str],
) -> None:
    for finding in findings:
        print(
            f"{finding.path}:{finding.line}:{finding.column}: "
            f"{finding.code} {finding.message}"
        )
    for error in errors:
        print(f"pyclichecker: {error}", file=sys.stderr)

    if findings:
        print(f"Found {len(findings)} issue(s) in {files_checked} file(s).")
    elif not errors:
        print(f"No AI-slop findings in {files_checked} file(s).")


def _render_json(
    findings: Sequence[Finding],
    *,
    files_checked: int,
    errors: Sequence[str],
) -> None:
    print(
        json.dumps(
            {
                "version": VERSION,
                "files_checked": files_checked,
                "findings": [finding.as_dict() for finding in findings],
                "errors": list(errors),
            },
            indent=2,
            sort_keys=True,
        )
    )


def _github_property(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _github_message(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _render_github(
    findings: Sequence[Finding],
    *,
    errors: Sequence[str],
) -> None:
    for finding in findings:
        message = _github_message(f"{finding.code} {finding.message}")
        path = _github_property(finding.path)
        print(
            f"::{finding.severity} file={path},line={finding.line},"
            f"col={finding.column}::{message}"
        )
    for error in errors:
        print(f"::error title=pyclichecker::{_github_message(error)}")


def _findings_fail(findings: Sequence[Finding], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if fail_on == "warning":
        return bool(findings)
    return any(finding.severity == "error" for finding in findings)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface and return its process exit code."""

    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.list_rules:
        _print_rules()
        return EXIT_CLEAN

    selected = _expand_codes(arguments.select, parser)
    ignored = _expand_codes(arguments.ignore, parser) if arguments.ignore else set()
    config = LintConfig(
        enabled_codes=frozenset(selected - ignored),
        max_function_lines=arguments.max_function_lines,
        narrating_comment_threshold=arguments.narrating_comments,
        duplicate_min_statements=arguments.duplicate_min_statements,
        duplicate_min_lines=arguments.duplicate_min_lines,
    )
    files, use_stdin, discovery_errors = discover_python_files(
        arguments.paths,
        exclude_patterns=arguments.exclude,
    )
    if not files and not use_stdin and not discovery_errors:
        discovery_errors.append("no Python files found in the requested paths")

    findings, files_checked, read_errors = lint_files(
        files,
        use_stdin=use_stdin,
        config=config,
    )
    errors = [*discovery_errors, *read_errors]

    if arguments.format == "json":
        _render_json(findings, files_checked=files_checked, errors=errors)
    elif arguments.format == "github":
        _render_github(findings, errors=errors)
    else:
        _render_text(findings, files_checked=files_checked, errors=errors)

    if errors:
        return EXIT_OPERATIONAL_ERROR
    if _findings_fail(findings, arguments.fail_on):
        return EXIT_FINDINGS
    return EXIT_CLEAN
