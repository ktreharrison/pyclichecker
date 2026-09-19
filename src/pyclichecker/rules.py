"""AST-based checks for high-signal Python code smells."""

import ast
import builtins
import io
import re
import tokenize
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Literal, cast

from pyclichecker.config import LintConfig, parse_rule_codes
from pyclichecker.diagnostics import Finding

CONFIG_NAME_RE = re.compile(
    r"(?:api_?key|(?:access_?|auth_?)?token|secret|password|passwd|endpoint|"
    r"(?:base_?|service_?)?url|webhook|host)",
    re.IGNORECASE,
)
PLACEHOLDER_VALUE_RE = re.compile(
    r"(?:"
    r"\b(?:todo|tbd|placeholder|change[-_ ]?me|replace[-_ ]?me|dummy|xxx+)\b"
    r"|your(?:[-_ ][a-z0-9]+){1,8}(?:[-_ ]here)?"
    r"|<[^>]*(?:key|token|secret|password|url|host)[^>]*>"
    r"|example\.(?:com|org|net)"
    r")",
    re.IGNORECASE,
)
NARRATING_COMMENT_RE = re.compile(
    r"^\s*#\s*(?:"
    r"step\s+\d+|first|next|then|finally|"
    r"initialize|set|check|loop|iterate|return|create|call|print|"
    r"open|close|read|write|convert|calculate|define|assign|"
    r"increment|decrement"
    r")\b",
    re.IGNORECASE,
)
RULE_CODE_LIST_PATTERN = r"[A-Z]+\d+(?:(?:\s*,\s*|\s+)[A-Z]+\d+)*"
NOQA_RE = re.compile(
    rf"noqa\s*:\s*({RULE_CODE_LIST_PATTERN})(?=$|[^A-Z0-9_])",
    re.IGNORECASE,
)
SLOP_IGNORE_RE = re.compile(
    rf"slop:\s*ignore\s*\[\s*({RULE_CODE_LIST_PATTERN})\s*\]",
    re.IGNORECASE,
)
TYPE_IGNORE_RE = re.compile(
    r"type:\s*ignore(?:\[[^\]\r\n]*\])?",
    re.IGNORECASE,
)
SLOP_IGNORE_FILE_RE = re.compile(
    r"#\s*slop:\s*ignore-file\s*",
    re.IGNORECASE,
)
BLOCKING_HTTP_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "request", "stream"}
)
BLOCKING_SUBPROCESS_CALLS = frozenset(
    {"Popen", "call", "check_call", "check_output", "run"}
)
HTTP_CALL_MODULES = frozenset({"httpx", "requests"})
HTTP_STATUS_ATTRIBUTES = frozenset({"is_success", "ok", "status_code"})
HTTP_STATUS_NAME_VALUES = {
    name.lower(): member.value for name, member in HTTPStatus.__members__.items()
}
SUBPROCESS_CHECK_EXCEPTION_NAMES = frozenset(
    {"subprocess.CalledProcessError", "subprocess.SubprocessError"}
)
SUBPROCESS_CHECK_BUILTIN_CATCHERS: frozenset[type[BaseException]] = frozenset(
    {BaseException, Exception}
)
HTTPX_CHECK_EXCEPTION_NAMES = frozenset(
    {
        "httpx.HTTPError",
        "httpx.HTTPStatusError",
    }
)
REQUESTS_CHECK_EXCEPTION_NAMES = frozenset(
    {
        "requests.HTTPError",
        "requests.RequestException",
        "requests.exceptions.HTTPError",
        "requests.exceptions.RequestException",
    }
)
HTTP_CHECK_EXCEPTION_NAMES = (
    HTTPX_CHECK_EXCEPTION_NAMES | REQUESTS_CHECK_EXCEPTION_NAMES
)
HTTPX_CHECK_BUILTIN_CATCHERS: frozenset[type[BaseException]] = frozenset(
    {BaseException, Exception}
)
REQUESTS_CHECK_BUILTIN_CATCHERS: frozenset[type[BaseException]] = frozenset(
    {BaseException, Exception, OSError}
)
HTTP_CHECK_BUILTIN_CATCHERS: frozenset[type[BaseException]] = frozenset(
    {BaseException, Exception, OSError}
)
KNOWN_VALIDATION_EXCEPTION_NAMES = (
    SUBPROCESS_CHECK_EXCEPTION_NAMES | HTTP_CHECK_EXCEPTION_NAMES
)
PERSONAL_HOME_RE = re.compile(
    r"(?:"
    r"/(?:Users|home)/(?P<unix_user>[^/\\\s<>{}$%]+)/"
    r"|[A-Za-z]:[\\/]+Users[\\/]+"
    r"(?P<windows_user>[^/\\\s<>{}$%]+)[\\/]"
    r")",
    re.IGNORECASE,
)
REMOTE_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
TEST_OUTCOME_DECORATORS = frozenset(
    {
        "pytest.mark.skip",
        "pytest.mark.skipif",
        "pytest.mark.xfail",
        "unittest.expectedFailure",
        "unittest.skip",
        "unittest.skipIf",
        "unittest.skipUnless",
    }
)
PYTEST_TERMINAL_ORACLES = frozenset({"pytest.fail", "pytest.skip", "pytest.xfail"})
PYTEST_CONTEXT_ORACLES = frozenset(
    {"pytest.deprecated_call", "pytest.raises", "pytest.warns"}
)
IMPORTED_ASSERTION_MODULES = frozenset({"numpy.testing", "pandas.testing"})
UNITTEST_CASE_BASES = frozenset(
    {"unittest.IsolatedAsyncioTestCase", "unittest.TestCase"}
)
DEFINITION_ALIAS_CANONICAL_NAMES = {
    "typing_extensions.ClassVar": "typing.ClassVar",
    "typing_extensions.Protocol": "typing.Protocol",
    "typing_extensions.final": "typing.final",
    "typing_extensions.overload": "typing.overload",
}
LOCAL_BINDING_ALIAS_PREFIX = "pyclichecker.local"
MOCK_ASSERTION_METHODS = frozenset(
    {
        "assert_any_await",
        "assert_any_call",
        "assert_awaited",
        "assert_awaited_once",
        "assert_awaited_once_with",
        "assert_awaited_with",
        "assert_called",
        "assert_called_once",
        "assert_called_once_with",
        "assert_called_with",
        "assert_has_awaits",
        "assert_has_calls",
        "assert_not_awaited",
        "assert_not_called",
    }
)
MUTATING_CONTAINER_METHODS = frozenset(
    {
        "__delitem__",
        "__iadd__",
        "__imul__",
        "__ior__",
        "__isub__",
        "__ixor__",
        "__setitem__",
        "add",
        "append",
        "clear",
        "difference_update",
        "discard",
        "extend",
        "insert",
        "intersection_update",
        "pop",
        "popitem",
        "remove",
        "reverse",
        "setdefault",
        "sort",
        "symmetric_difference_update",
        "update",
    }
)

type ObservationKind = Literal["boolean", "http-status", "returncode"]
type PendingExit = Literal["break", "continue", "raise", "return"] | None
type FlowState = tuple[int, int, PendingExit, bool]
type FlowContinuation = tuple[tuple[int, int] | None, PendingExit]
type ResultChecker = Callable[[ast.stmt, str, dict[str, str], bool], bool]
type ResultHandlingState = Literal["continues", "handled", "unsafe"]
type ObservationAssignment = Callable[
    [ast.stmt, str, dict[str, str]],
    "ResultObservation | None",
]


@dataclass(frozen=True, slots=True)
class Comment:
    """A comment token and its source line."""

    line: int
    text: str


@dataclass(frozen=True, slots=True)
class FunctionRecord:
    """Function metadata used by checks that run after traversal."""

    node: ast.FunctionDef | ast.AsyncFunctionDef
    qualified_name: str
    effective_body: tuple[ast.stmt, ...]
    exempt: bool

    @property
    def line_count(self) -> int:
        end_line = self.node.end_lineno or self.node.lineno
        return end_line - self.node.lineno + 1


@dataclass(frozen=True, slots=True)
class BlockingCall:
    """A known blocking call found inside an async function."""

    node: ast.Call
    qualified_name: str
    guidance: str


@dataclass(frozen=True, slots=True)
class OperationalCall:
    """A subprocess or HTTP call that needs a postcondition check."""

    node: ast.Call
    qualified_name: str
    aliases: dict[str, str]


@dataclass(frozen=True, slots=True)
class ResultObservation:
    """A named subprocess or HTTP result observation."""

    name: str
    kind: ObservationKind
    truthy_is_success: bool | None = None


@dataclass(frozen=True, slots=True)
class AttributeFlow:
    """Definitely assigned attributes at each reachable control-flow exit."""

    fallthrough: frozenset[str] | None
    returns: frozenset[str] | None
    breaks: frozenset[str] | None = None
    continues: frozenset[str] | None = None
    raises: frozenset[str] | None = None


@dataclass(slots=True)
class _DefinitionLoopExitStates:
    break_aliases: list[dict[str, str]]
    break_cases: list[set[str]]
    continue_aliases: list[dict[str, str]]
    continue_cases: list[set[str]]


def _comment_suppression_codes(comment: str) -> set[str]:
    codes: set[str] = set()
    for segment in comment.split("#"):
        directive = segment.strip()
        if not directive:
            continue
        noqa = NOQA_RE.match(directive)
        if noqa:
            codes.update(parse_rule_codes(noqa.group(1)))
            continue
        slop_ignore = SLOP_IGNORE_RE.match(directive)
        if slop_ignore:
            codes.update(parse_rule_codes(slop_ignore.group(1)))
            continue
        if TYPE_IGNORE_RE.fullmatch(directive):
            continue
        break
    return codes


def _expression_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _expression_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return _expression_name(node.value)
    if isinstance(node, ast.Call):
        return _expression_name(node.func)
    return ""


def _effective_body(body: Sequence[ast.stmt]) -> tuple[ast.stmt, ...]:
    result = tuple(body)
    if (
        result
        and isinstance(result[0], ast.Expr)
        and isinstance(result[0].value, ast.Constant)
        and isinstance(result[0].value.value, str)
    ):
        return result[1:]
    return result


def _is_placeholder_body(body: Sequence[ast.stmt]) -> bool:
    if len(body) != 1:
        return False

    statement = body[0]
    if isinstance(statement, ast.Pass):
        return True
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    ):
        return True
    if isinstance(statement, ast.Raise):
        return _expression_name(statement.exc).split(".")[-1] == "NotImplementedError"
    return False


class _AsyncBehaviorVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.found = False

    def visit_Await(self, node: ast.Await) -> None:
        self.found = True

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.found = True

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.found = True

    def visit_Yield(self, node: ast.Yield) -> None:
        self.found = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.found = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


def _contains_async_behavior(body: Sequence[ast.stmt]) -> bool:
    visitor = _AsyncBehaviorVisitor()
    for statement in body:
        visitor.visit(statement)
        if visitor.found:
            return True
    return False


def _match_pattern_is_irrefutable(pattern: ast.pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _match_pattern_is_irrefutable(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_match_pattern_is_irrefutable(item) for item in pattern.patterns)
    return False


def _match_case_is_irrefutable(case: ast.match_case) -> bool:
    guard_truth = True if case.guard is None else _constant_truth_value(case.guard)
    return guard_truth is True and _match_pattern_is_irrefutable(case.pattern)


def _match_exit_kinds(node: ast.Match, aliases: dict[str, str]) -> set[str]:
    outcomes: set[str] = set()
    exhaustive = False
    for case in node.cases:
        if case.guard is not None and _constant_truth_value(case.guard) is False:
            continue
        outcomes.update(_block_exit_kinds(case.body, aliases))
        if _match_case_is_irrefutable(case):
            exhaustive = True
            break
    if not exhaustive:
        outcomes.add("fallthrough")
    return outcomes


def _literal_comparison_value(node: ast.AST) -> tuple[bool, object]:
    try:
        value: object = ast.literal_eval(node)
    except MemoryError, RecursionError, SyntaxError, TypeError, ValueError:
        return False, None
    return True, value


def _literal_comparison_result(
    left: object,
    comparison: ast.cmpop,
    right: object,
) -> bool | None:
    left_value: Any = left
    right_value: Any = right
    try:
        if isinstance(comparison, ast.Eq):
            return bool(left_value == right_value)
        if isinstance(comparison, ast.NotEq):
            return bool(left_value != right_value)
        if isinstance(comparison, ast.Lt):
            return bool(left_value < right_value)
        if isinstance(comparison, ast.LtE):
            return bool(left_value <= right_value)
        if isinstance(comparison, ast.Gt):
            return bool(left_value > right_value)
        if isinstance(comparison, ast.GtE):
            return bool(left_value >= right_value)
        if isinstance(comparison, ast.In):
            return bool(left_value in right_value)
        if isinstance(comparison, ast.NotIn):
            return bool(left_value not in right_value)
        singleton_types = (type(None), bool, type(Ellipsis))
        if type(left) in singleton_types and type(right) in singleton_types:
            if isinstance(comparison, ast.Is):
                return left is right
            if isinstance(comparison, ast.IsNot):
                return left is not right
    except TypeError, ValueError:
        return None
    return None


def _constant_compare_truth_value(node: ast.Compare) -> bool | None:
    available, left = _literal_comparison_value(node.left)
    if not available:
        return None
    for comparison, comparator in zip(
        node.ops,
        node.comparators,
        strict=True,
    ):
        available, right = _literal_comparison_value(comparator)
        if not available:
            return None
        result = _literal_comparison_result(left, comparison, right)
        if result is None:
            return None
        if not result:
            return False
        left = right
    return True


def _constant_truth_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        if any(isinstance(element, ast.Starred) for element in node.elts):
            return None
        return bool(node.elts)
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            return None
        return bool(node.keys)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _constant_truth_value(node.operand)
        return None if value is None else not value
    if isinstance(node, ast.Compare):
        return _constant_compare_truth_value(node)
    if isinstance(node, ast.BoolOp):
        values = tuple(_constant_truth_value(value) for value in node.values)
        if isinstance(node.op, ast.And):
            if False in values:
                return False
            return True if values and None not in values else None
        if True in values:
            return True
        return False if values and None not in values else None
    return None


def _is_builtin_range_call(
    node: ast.AST,
    aliases: dict[str, str] | None = None,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    active_aliases = aliases or {}
    raw_name = _expression_name(node.func)
    resolved_name = _resolve_imported_name(raw_name, active_aliases)
    return resolved_name == "builtins.range" or (
        raw_name == "range"
        and not resolved_name
        and not _name_shadows_builtin(node.func, "range")
    )


def _literal_iterable_is_empty(
    node: ast.AST,
    aliases: dict[str, str] | None = None,
) -> bool | None:
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        if any(isinstance(element, ast.Starred) for element in node.elts):
            return None
        return not node.elts
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            return None
        return not node.keys
    if isinstance(node, ast.Constant) and isinstance(
        node.value,
        (bytes, str),
    ):
        return not node.value
    if isinstance(node, ast.Call) and not node.keywords:
        if (
            _is_builtin_range_call(node, aliases)
            and 1 <= len(node.args) <= 3
            and all(
                isinstance(argument, ast.Constant) and type(argument.value) is int
                for argument in node.args
            )
        ):
            values = tuple(
                cast(int, argument.value)
                for argument in node.args
                if isinstance(argument, ast.Constant)
            )
            return len(range(*values)) == 0
    return None


def _statement_sole_explicit_raise(
    statement: ast.stmt,
    aliases: dict[str, str],
) -> ast.Raise | None:
    if isinstance(statement, ast.Raise) and statement.exc is not None:
        return statement
    if isinstance(statement, ast.If):
        truth = _constant_truth_value(statement.test)
        if truth is not None:
            return _sole_explicit_raise(
                statement.body if truth else statement.orelse,
                aliases,
            )
    return None


def _sole_explicit_raise(
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
) -> ast.Raise | None:
    for statement in body:
        if _statement_may_raise_implicitly(statement):
            return None
        outcomes = _statement_exit_kinds(statement, aliases)
        if "raise" in outcomes:
            if outcomes == {"raise"}:
                explicit_raise = _statement_sole_explicit_raise(statement, aliases)
                if explicit_raise is None or any(
                    _raise_expression_may_raise_implicitly(expression, aliases)
                    for expression in (explicit_raise.exc, explicit_raise.cause)
                ):
                    return None
                return explicit_raise
            return None
        if "fallthrough" not in outcomes:
            return None
    return None


def _loop_exit_kinds(
    node: ast.For | ast.AsyncFor | ast.While,
    aliases: dict[str, str],
) -> set[str]:
    if isinstance(node, ast.While) and _constant_truth_value(node.test) is False:
        return (
            _block_exit_kinds(node.orelse, aliases) if node.orelse else {"fallthrough"}
        )
    body_outcomes = _block_exit_kinds(node.body, aliases)
    propagated = body_outcomes - {"break", "continue", "fallthrough"}
    repeats_forever = (
        isinstance(node, ast.While) and _constant_truth_value(node.test) is True
    )
    if repeats_forever:
        if "break" in body_outcomes:
            propagated.add("fallthrough")
        if {"continue", "fallthrough"} & body_outcomes:
            propagated.add("nontermination")
        return propagated

    alternative = (
        _block_exit_kinds(node.orelse, aliases) if node.orelse else {"fallthrough"}
    )
    outcomes = propagated | alternative
    if "break" in body_outcomes:
        outcomes.add("fallthrough")
    return outcomes


def _try_pre_final_exit_kinds(
    node: ast.Try | ast.TryStar,
    aliases: dict[str, str],
) -> set[str]:
    body_outcomes = _block_exit_kinds(node.body, aliases)
    outcomes = body_outcomes - {"fallthrough"}
    if "fallthrough" in body_outcomes:
        outcomes.update(
            _block_exit_kinds(node.orelse, aliases) if node.orelse else {"fallthrough"}
        )
    explicit_raise = (
        _sole_explicit_raise(node.body, aliases) if isinstance(node, ast.Try) else None
    )
    if explicit_raise is not None:
        handlers, definitely_caught = _potential_handlers_for_raise(
            node.handlers,
            explicit_raise,
            aliases,
        )
        if definitely_caught:
            outcomes.discard("raise")
        for handler in handlers:
            outcomes.update(_block_exit_kinds(handler.body, aliases))
        return outcomes
    if _block_may_raise(node.body, aliases):
        for handler in node.handlers:
            outcomes.update(_block_exit_kinds(handler.body, aliases))
    return outcomes


def _try_exit_kinds(
    node: ast.Try | ast.TryStar,
    aliases: dict[str, str],
) -> set[str]:
    outcomes = _try_pre_final_exit_kinds(node, aliases)
    if node.finalbody:
        final_outcomes = _block_exit_kinds(node.finalbody, aliases)
        if "fallthrough" not in final_outcomes:
            return final_outcomes
        outcomes.update(final_outcomes - {"fallthrough"})
    return outcomes


def _context_items_may_suppress(
    items: Sequence[ast.withitem],
    aliases: dict[str, str],
) -> bool:
    return any(
        isinstance(item.context_expr, ast.Call)
        and bool(item.context_expr.args)
        and _resolve_imported_name(
            _expression_name(item.context_expr.func),
            aliases,
        )
        == "contextlib.suppress"
        for item in items
    )


def _context_manager_may_suppress(
    node: ast.With | ast.AsyncWith,
    aliases: dict[str, str],
) -> bool:
    return _context_items_may_suppress(node.items, aliases)


def _context_manager_suppresses_all_raises(
    node: ast.With | ast.AsyncWith,
    aliases: dict[str, str],
) -> bool:
    for item in node.items:
        context = item.context_expr
        if (
            not isinstance(context, ast.Call)
            or _resolve_imported_name(
                _expression_name(context.func),
                aliases,
            )
            != "contextlib.suppress"
        ):
            continue
        if any(
            BaseException in _builtin_exception_types(argument, aliases)
            for argument in context.args
        ):
            return True
    return False


def _context_manager_suppresses_raise(
    node: ast.With | ast.AsyncWith,
    statement: ast.Raise,
    aliases: dict[str, str],
) -> bool | None:
    has_unknown_match = False
    found_suppressor = False
    for item in node.items:
        context = item.context_expr
        if (
            not isinstance(context, ast.Call)
            or _resolve_imported_name(
                _expression_name(context.func),
                aliases,
            )
            != "contextlib.suppress"
        ):
            continue
        found_suppressor = True
        for argument in context.args:
            match = _exception_handler_match(
                ast.ExceptHandler(type=argument, name=None, body=[]),
                statement,
                aliases,
            )
            if match is True:
                return True
            has_unknown_match |= match is None
    if has_unknown_match:
        return None
    return False if found_suppressor else None


def _raise_escapes_enclosing_suppressors(
    statement: ast.Raise,
    aliases: dict[str, str],
) -> bool:
    current: ast.AST = statement
    parent = _parent_node(current)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
        if (
            isinstance(parent, (ast.With, ast.AsyncWith))
            and isinstance(current, ast.stmt)
            and current in parent.body
            and _context_manager_may_suppress(parent, aliases)
            and _context_manager_suppresses_raise(parent, statement, aliases)
            is not False
        ):
            return False
        current = parent
        parent = _parent_node(current)
    return True


def _exception_type_may_catch_validation_error(
    node: ast.AST | None,
    aliases: dict[str, str],
    *,
    exception_names: frozenset[str],
    builtin_catchers: frozenset[type[BaseException]],
) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Tuple):
        return any(
            _exception_type_may_catch_validation_error(
                element,
                aliases,
                exception_names=exception_names,
                builtin_catchers=builtin_catchers,
            )
            for element in node.elts
        )
    exception_type_names = _exception_type_names(node, aliases)
    if exception_type_names & exception_names:
        return True
    if exception_type_names & KNOWN_VALIDATION_EXCEPTION_NAMES:
        return False
    builtin_types = _builtin_exception_types(node, aliases)
    if builtin_types:
        return bool(builtin_types & builtin_catchers)
    return True


def _validation_error_handlers(
    handlers: Sequence[ast.ExceptHandler],
    aliases: dict[str, str],
    *,
    exception_names: frozenset[str],
    builtin_catchers: frozenset[type[BaseException]],
) -> tuple[ast.ExceptHandler, ...]:
    selected: list[ast.ExceptHandler] = []
    for handler in handlers:
        if _exception_type_may_catch_validation_error(
            handler.type,
            aliases,
            exception_names=exception_names,
            builtin_catchers=builtin_catchers,
        ):
            selected.append(handler)
        if handler.type is None:
            break
        builtin_types = _builtin_exception_types(handler.type, aliases)
        if (
            _exception_type_names(handler.type, aliases) & exception_names
            or builtin_types & builtin_catchers
        ):
            break
    return tuple(selected)


def _context_manager_preserves_validation_errors(
    node: ast.With | ast.AsyncWith,
    aliases: dict[str, str],
    *,
    exception_names: frozenset[str],
    builtin_catchers: frozenset[type[BaseException]],
) -> bool:
    for item in node.items:
        context = item.context_expr
        if (
            not isinstance(context, ast.Call)
            or _resolve_imported_name(
                _expression_name(context.func),
                aliases,
            )
            != "contextlib.suppress"
        ):
            continue
        for argument in context.args:
            if _exception_type_may_catch_validation_error(
                argument,
                aliases,
                exception_names=exception_names,
                builtin_catchers=builtin_catchers,
            ):
                return False
    return True


def _validation_errors_escape_enclosing_suppressors(
    node: ast.AST,
    aliases: dict[str, str],
    *,
    exception_names: frozenset[str],
    builtin_catchers: frozenset[type[BaseException]],
    result_name: str | None = None,
    checker: ResultChecker | None = None,
) -> bool:
    current: ast.AST = node
    parent = _parent_node(current)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
        if (
            isinstance(parent, (ast.With, ast.AsyncWith))
            and isinstance(current, ast.stmt)
            and current in parent.body
        ):
            if not _context_manager_preserves_validation_errors(
                parent,
                aliases,
                exception_names=exception_names,
                builtin_catchers=builtin_catchers,
            ):
                return False
        if isinstance(parent, (ast.Try, ast.TryStar)):
            in_body = isinstance(current, ast.stmt) and current in parent.body
            in_protected_suite = (
                in_body
                or (isinstance(current, ast.stmt) and current in parent.orelse)
                or (
                    isinstance(current, ast.ExceptHandler)
                    and current in parent.handlers
                )
            )
            if in_body:
                handlers = _validation_error_handlers(
                    parent.handlers,
                    aliases,
                    exception_names=exception_names,
                    builtin_catchers=builtin_catchers,
                )
                if any(
                    not _failure_branch_handles_result(
                        handler.body,
                        result_name=result_name,
                        checker=checker,
                        aliases=aliases,
                    )
                    for handler in handlers
                ):
                    return False
            if in_protected_suite:
                final_exits = _block_exit_kinds(parent.finalbody, aliases)
                if final_exits & {"return", "break", "continue"}:
                    return False
                if (
                    "raise" in final_exits
                    and _block_explicit_raises_escape(parent.finalbody, aliases)
                    is False
                ):
                    return False
        current = parent
        parent = _parent_node(current)
    return True


def _with_exit_kinds(
    node: ast.With | ast.AsyncWith,
    aliases: dict[str, str],
) -> set[str]:
    outcomes = _block_exit_kinds(node.body, aliases)
    if "raise" not in outcomes or not _context_manager_may_suppress(node, aliases):
        return outcomes
    explicit_raise = _sole_explicit_raise(node.body, aliases)
    suppression = (
        _context_manager_suppresses_raise(node, explicit_raise, aliases)
        if explicit_raise is not None
        else None
    )
    if suppression is not False:
        outcomes.add("fallthrough")
    if suppression is True or (
        explicit_raise is None and _context_manager_suppresses_all_raises(node, aliases)
    ):
        outcomes.remove("raise")
    return outcomes


def _statement_exit_kinds(node: ast.stmt, aliases: dict[str, str]) -> set[str]:
    if isinstance(node, ast.Raise):
        return {"raise"}
    if isinstance(node, ast.Return):
        return {"return"}
    if isinstance(node, ast.Break):
        return {"break"}
    if isinstance(node, ast.Continue):
        return {"continue"}
    if isinstance(node, ast.If):
        truth = _constant_truth_value(node.test)
        if truth is True:
            return _block_exit_kinds(node.body, aliases)
        if truth is False:
            return (
                _block_exit_kinds(node.orelse, aliases)
                if node.orelse
                else {"fallthrough"}
            )
        alternative = (
            _block_exit_kinds(node.orelse, aliases) if node.orelse else {"fallthrough"}
        )
        return _block_exit_kinds(node.body, aliases) | alternative
    if isinstance(node, ast.Match):
        return _match_exit_kinds(node, aliases)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return _with_exit_kinds(node, aliases)
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        return _loop_exit_kinds(node, aliases)
    if isinstance(node, (ast.Try, ast.TryStar)):
        return _try_exit_kinds(node, aliases)
    return {"fallthrough"}


def _block_exit_kinds(
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
) -> set[str]:
    outcomes = {"fallthrough"}
    for statement in body:
        if "fallthrough" not in outcomes:
            break
        outcomes.remove("fallthrough")
        outcomes.update(_statement_exit_kinds(statement, aliases))
    return outcomes


def _block_may_raise(
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
) -> bool:
    for statement in body:
        exit_kinds = _statement_exit_kinds(statement, aliases)
        if _statement_may_raise_implicitly(statement) or "raise" in exit_kinds:
            return True
        if "fallthrough" not in exit_kinds:
            return False
    return False


def _handler_always_raises(
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
) -> bool:
    return _block_exit_kinds(body, aliases) == {"raise"}


def _is_empty_handler(body: Sequence[ast.stmt]) -> bool:
    return bool(body) and all(
        isinstance(statement, ast.Pass)
        or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
        )
        for statement in body
    )


def _is_broad_exception(
    node: ast.AST | None,
    aliases: dict[str, str],
) -> bool:
    if node is None:
        return True
    return bool(
        _builtin_exception_types(node, aliases)
        & {
            BaseException,
            Exception,
        }
    )


def _exception_type_names(
    node: ast.AST | None,
    aliases: dict[str, str],
) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.Tuple):
        return {
            name
            for element in node.elts
            for name in _exception_type_names(element, aliases)
        }
    expression = node.func if isinstance(node, ast.Call) else node
    raw_name = _expression_name(expression)
    if not raw_name:
        return set()
    resolved_name = _resolve_imported_name(raw_name, aliases)
    return {resolved_name or raw_name}


def _builtin_exception_types(
    node: ast.AST | None,
    aliases: dict[str, str],
) -> set[type[BaseException]]:
    if node is None:
        return set()
    if isinstance(node, ast.Tuple):
        return {
            exception_type
            for element in node.elts
            for exception_type in _builtin_exception_types(element, aliases)
        }
    expression = node.func if isinstance(node, ast.Call) else node
    raw_name = _expression_name(expression)
    if not raw_name:
        return set()
    resolved_name = _resolve_imported_name(raw_name, aliases)
    if (
        not resolved_name
        and "." not in raw_name
        and _name_shadows_builtin(expression, raw_name)
    ):
        return set()
    qualified_name = resolved_name or raw_name
    if "." in qualified_name and not qualified_name.startswith("builtins."):
        return set()
    exception_type = getattr(builtins, qualified_name.rsplit(".", 1)[-1], None)
    if not (
        isinstance(exception_type, type) and issubclass(exception_type, BaseException)
    ):
        return set()
    return {exception_type}


def _name_shadows_builtin(node: ast.AST, name: str) -> bool:
    current = _parent_node(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if name in _collect_local_bindings(current, current.body):
                return True
        elif isinstance(current, ast.Module):
            return False
        current = _parent_node(current)
    return False


def _exception_handler_match(
    handler: ast.ExceptHandler,
    statement: ast.Raise,
    aliases: dict[str, str],
) -> bool | None:
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Tuple):
        matches = tuple(
            _exception_handler_match(
                ast.ExceptHandler(type=element, name=None, body=[]),
                statement,
                aliases,
            )
            for element in handler.type.elts
        )
        if True in matches:
            return True
        return None if None in matches else False
    raised_names = _exception_type_names(statement.exc, aliases)
    if not raised_names:
        return None
    handled_names = _exception_type_names(handler.type, aliases)
    if raised_names & handled_names:
        return True
    raised_types = _builtin_exception_types(statement.exc, aliases)
    handled_types = _builtin_exception_types(handler.type, aliases)
    if BaseException in handled_types:
        return True
    if raised_types and handled_types:
        return any(
            issubclass(raised_type, handled_type)
            for raised_type in raised_types
            for handled_type in handled_types
        )
    return None


def _handler_catches_raise(
    handler: ast.ExceptHandler,
    statement: ast.Raise,
    aliases: dict[str, str],
) -> bool:
    return _exception_handler_match(handler, statement, aliases) is True


def _potential_handlers_for_raise(
    handlers: Sequence[ast.ExceptHandler],
    statement: ast.Raise,
    aliases: dict[str, str],
) -> tuple[tuple[ast.ExceptHandler, ...], bool]:
    potential: list[ast.ExceptHandler] = []
    for handler in handlers:
        match = _exception_handler_match(handler, statement, aliases)
        if match is False:
            continue
        potential.append(handler)
        if match is True:
            return tuple(potential), True
    return tuple(potential), False


def _handler_catches_all_raises(
    handler: ast.ExceptHandler,
    aliases: dict[str, str],
) -> bool:
    return handler.type is None or BaseException in _builtin_exception_types(
        handler.type,
        aliases,
    )


def _reachable_exception_handlers(
    handlers: Sequence[ast.ExceptHandler],
    aliases: dict[str, str],
) -> tuple[ast.ExceptHandler, ...]:
    reachable: list[ast.ExceptHandler] = []
    prior_builtin_types: set[type[BaseException]] = set()
    for handler in handlers:
        if handler.type is None:
            reachable.append(handler)
            break
        builtin_types = _builtin_exception_types(handler.type, aliases)
        if builtin_types and all(
            any(
                issubclass(exception_type, prior_type)
                for prior_type in prior_builtin_types
            )
            for exception_type in builtin_types
        ):
            continue
        reachable.append(handler)
        prior_builtin_types.update(builtin_types)
    return tuple(reachable)


def _assigned_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in node.elts:
            names.extend(_assigned_names(element))
        return names
    return []


def _is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    return (
        "/tests/" in f"/{normalized}/"
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _parent_node(node: ast.AST) -> ast.AST | None:
    parent = node.__dict__.get("_pyclichecker_parent")
    return parent if isinstance(parent, ast.AST) else None


def _is_docstring_constant(node: ast.Constant) -> bool:
    expression = _parent_node(node)
    owner = _parent_node(expression) if isinstance(expression, ast.Expr) else None
    return bool(
        isinstance(
            owner, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        )
        and owner.body
        and owner.body[0] is expression
    )


def _find_placeholder_constant(
    value: ast.AST | None,
    *,
    ignored: set[int],
) -> ast.Constant | None:
    if value is None:
        return None
    for candidate in ast.walk(value):
        if (
            isinstance(candidate, ast.Constant)
            and isinstance(candidate.value, str)
            and id(candidate) not in ignored
            and PLACEHOLDER_VALUE_RE.search(candidate.value)
        ):
            return candidate
    return None


def _is_assertion_callable_name(name: str) -> bool:
    return name.startswith("assert_") or (
        name.startswith("assert")
        and len(name) > len("assert")
        and name[len("assert")].isupper()
    )


class _TestOracleVisitor(ast.NodeVisitor):
    def __init__(
        self,
        aliases: dict[str, str],
        *,
        test_case_receiver: str | None,
    ) -> None:
        self.aliases = dict(aliases)
        self.test_case_receiver = test_case_receiver
        self.found = False

    def _shadow_bindings(self, node: ast.AST) -> None:
        for name in _class_scope_bindings(node):
            self.aliases[name] = f"{LOCAL_BINDING_ALIAS_PREFIX}.{name}"

    def _visit_reachable_body(self, body: Sequence[ast.stmt]) -> None:
        for statement in body:
            self.visit(statement)
            if self.found or "fallthrough" not in _statement_exit_kinds(
                statement, self.aliases
            ):
                return

    def visit_Assert(self, node: ast.Assert) -> None:
        self.found = _assertion_failure_escapes(node, self.aliases)

    def visit_Call(self, node: ast.Call) -> None:
        raw_name = _expression_name(node.func)
        qualified_name = _resolve_imported_name(raw_name, self.aliases)
        if qualified_name in PYTEST_TERMINAL_ORACLES:
            self.found = True
            return
        if qualified_name in PYTEST_CONTEXT_ORACLES:
            parent = _parent_node(node)
            used_as_context = bool(
                isinstance(parent, ast.withitem) and parent.context_expr is node
            )
            callable_arg_count = 1 if qualified_name == "pytest.deprecated_call" else 2
            used_as_callable = len(node.args) >= callable_arg_count or any(
                keyword.arg == "func" for keyword in node.keywords
            )
            if used_as_context or used_as_callable:
                self.found = True
                return
        module_name, separator, callable_name = qualified_name.rpartition(".")
        if (
            separator
            and module_name in IMPORTED_ASSERTION_MODULES
            and _is_assertion_callable_name(callable_name)
        ):
            self.found = True
            return
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            receiver_name = _expression_name(node.func.value)
            test_case_oracle = receiver_name == self.test_case_receiver and (
                _is_assertion_callable_name(method_name)
                or method_name in {"fail", "skipTest"}
            )
            if test_case_oracle or method_name in MOCK_ASSERTION_METHODS:
                self.found = True
                return
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        self.aliases.update(_collect_import_aliases((node,)))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.aliases.update(_collect_import_aliases((node,)))

    def visit_Assign(self, node: ast.Assign) -> None:
        alias_binding = _definition_alias_binding(node, self.aliases)
        self.visit(node.value)
        if self.found:
            return
        for target in node.targets:
            self.visit(target)
        self._shadow_bindings(node)
        if alias_binding is not None:
            self.aliases[alias_binding[0]] = alias_binding[1]

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        alias_binding = _definition_alias_binding(node, self.aliases)
        if node.value is not None:
            self.visit(node.value)
            if self.found:
                return
        self.visit(node.target)
        if node.value is not None:
            self._shadow_bindings(node)
        if alias_binding is not None:
            self.aliases[alias_binding[0]] = alias_binding[1]

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        if not self.found:
            self.visit(node.value)
        self._shadow_bindings(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        if not self.found:
            self._shadow_bindings(node.target)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        if self.found:
            return
        truth = _constant_truth_value(node.test)
        branches = (
            (node.body,)
            if truth is True
            else (node.orelse,)
            if truth is False
            else (node.body, node.orelse)
        )
        for branch in branches:
            self._visit_reachable_body(branch)
            if self.found:
                return

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        if self.found:
            return
        truth = _constant_truth_value(node.test)
        if truth is True:
            self.visit(node.body)
        elif truth is False:
            self.visit(node.orelse)
        else:
            self.visit(node.body)
            if not self.found:
                self.visit(node.orelse)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for value in node.values:
            self.visit(value)
            if self.found:
                return
            truth = _constant_truth_value(value)
            if isinstance(node.op, ast.And) and truth is False:
                return
            if isinstance(node.op, ast.Or) and truth is True:
                return

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        if self.found:
            return
        truth = _constant_truth_value(node.test)
        if truth is False:
            self._visit_reachable_body(node.orelse)
            return
        branches = (node.body,) if truth is True else (node.body, node.orelse)
        for branch in branches:
            self._visit_reachable_body(branch)
            if self.found:
                return

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if self.found:
                return
        self._visit_reachable_body(node.body)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)

    def _visit_try(self, node: ast.Try | ast.TryStar) -> None:
        body_may_raise = _block_may_raise(node.body, self.aliases)
        explicit_raise = (
            _sole_explicit_raise(node.body, self.aliases)
            if isinstance(node, ast.Try)
            else None
        )
        self._visit_reachable_body(node.body)
        if self.found:
            return
        if body_may_raise:
            handlers: Sequence[ast.ExceptHandler] = _reachable_exception_handlers(
                node.handlers,
                self.aliases,
            )
            if explicit_raise is not None:
                handlers, _ = _potential_handlers_for_raise(
                    handlers,
                    explicit_raise,
                    self.aliases,
                )
            for handler in handlers:
                self._visit_reachable_body(handler.body)
                if self.found:
                    return
        if "fallthrough" in _block_exit_kinds(node.body, self.aliases):
            self._visit_reachable_body(node.orelse)
            if self.found:
                return
        self._visit_reachable_body(node.finalbody)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        if self.found:
            return
        for case in node.cases:
            if case.guard is not None:
                self.visit(case.guard)
                if self.found:
                    return
                if _constant_truth_value(case.guard) is False:
                    continue
            self._visit_reachable_body(case.body)
            if self.found:
                return
            if _match_case_is_irrefutable(case):
                return

    def _visit_for(self, node: ast.For | ast.AsyncFor) -> None:
        empty = _literal_iterable_is_empty(node.iter, self.aliases)
        branches = (node.orelse,) if empty is True else (node.body, node.orelse)
        for branch in branches:
            self._visit_reachable_body(branch)
            if self.found:
                return

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _contains_test_oracle(
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
    *,
    test_case_receiver: str | None,
) -> bool:
    visitor = _TestOracleVisitor(
        aliases,
        test_case_receiver=test_case_receiver,
    )
    visitor._visit_reachable_body(body)
    return visitor.found


def _has_test_outcome_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
) -> bool:
    for decorator in node.decorator_list:
        qualified_name = _resolve_imported_name(
            _expression_name(_decorator_expression(decorator)),
            aliases,
        )
        if qualified_name not in TEST_OUTCOME_DECORATORS:
            continue
        if qualified_name not in {
            "pytest.mark.skipif",
            "pytest.mark.xfail",
            "unittest.skipIf",
            "unittest.skipUnless",
        }:
            return True
        if not isinstance(decorator, ast.Call):
            continue
        condition = (
            decorator.args[0]
            if decorator.args
            else _keyword_value(decorator, "condition")
        )
        if qualified_name == "pytest.mark.xfail" and condition is None:
            return True
        if (
            qualified_name.startswith("pytest.")
            and isinstance(condition, ast.Constant)
            and isinstance(condition.value, str)
        ):
            try:
                condition = ast.parse(condition.value, mode="eval").body
            except SyntaxError:
                condition = None
        truth = _constant_truth_value(condition) if condition is not None else None
        if qualified_name == "unittest.skipUnless":
            if truth is False:
                return True
        elif truth is True:
            return True
    return False


def _has_pytest_fixture_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
) -> bool:
    return any(
        _resolve_imported_name(
            _expression_name(_decorator_expression(decorator)),
            aliases,
        )
        == "pytest.fixture"
        for decorator in node.decorator_list
    )


def _is_contract_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
    *,
    in_protocol: bool,
) -> bool:
    decorator_names = {
        _resolve_imported_name(
            _expression_name(_decorator_expression(decorator)),
            aliases,
        )
        for decorator in node.decorator_list
    }
    return in_protocol or bool(
        decorator_names.intersection(
            {
                "abc.abstractmethod",
                "typing.overload",
                "typing_extensions.overload",
            }
        )
    )


class _ImportAliasVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            qualified_name = alias.name if alias.asname else local_name
            self.aliases[local_name] = qualified_name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            self.aliases[local_name] = f"{node.module}.{alias.name}"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


class _LocalBindingVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        return

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        return

    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_names.update(node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.names.add(node.name)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.names.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.names.add(node.rest)
        for pattern in node.patterns:
            self.visit(pattern)

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
    ) -> None:
        for generator in node.generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)


class _ClassScopeBindingVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(
            alias.asname or alias.name.split(".", 1)[0] for alias in node.names
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(
            alias.asname or alias.name for alias in node.names if alias.name != "*"
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ListComp(self, node: ast.ListComp) -> None:
        return

    def visit_SetComp(self, node: ast.SetComp) -> None:
        return

    def visit_DictComp(self, node: ast.DictComp) -> None:
        return

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        return

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)


def _aliases_for_scope_snapshot(
    aliases: dict[str, str],
    snapshot: dict[str, str] | None,
    local_names: set[str] | None,
) -> dict[str, str]:
    if snapshot is None:
        return aliases
    if local_names is None:
        return snapshot
    active = dict(aliases)
    for name in local_names:
        if name in snapshot:
            active[name] = snapshot[name]
        else:
            active.pop(name, None)
    return active


class _BlockingCallVisitor(ast.NodeVisitor):
    def __init__(
        self,
        aliases: dict[str, str],
        alias_snapshots: dict[int, dict[str, str]],
        local_names: set[str],
    ) -> None:
        self.aliases = aliases
        self.alias_snapshots = alias_snapshots
        self.local_names = local_names
        self.calls: list[BlockingCall] = []

    def visit_Call(self, node: ast.Call) -> None:
        aliases = _aliases_for_scope_snapshot(
            self.aliases,
            self.alias_snapshots.get(id(node)),
            self.local_names,
        )
        raw_name = _expression_name(node.func)
        qualified_name = _resolve_imported_name(raw_name, aliases)
        guidance = _blocking_call_guidance(qualified_name)
        if guidance:
            self.calls.append(BlockingCall(node, qualified_name, guidance))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _direct_result_names(node: ast.AST | None) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Starred):
        return _direct_result_names(node.value)
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        names: set[str] = set()
        for element in node.elts:
            names.update(_direct_result_names(element))
        return names
    return set()


class _ReferencedNamesVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class _ImplicitRaiseVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.found = False

    def visit_Call(self, node: ast.Call) -> None:
        self.found = True

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if (
            isinstance(node.left, ast.Constant)
            and isinstance(node.right, ast.Constant)
            and type(node.left.value) in {int, float, complex}
            and type(node.right.value) in {int, float, complex}
            and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult))
        ):
            return
        self.found = True

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            self.found = True

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.found = True

    def visit_Import(self, node: ast.Import) -> None:
        self.found = True

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.found = True

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for value in node.values:
            self.visit(value)
            if self.found:
                return
            truth = _constant_truth_value(value)
            if isinstance(node.op, ast.And) and truth is False:
                return
            if isinstance(node.op, ast.Or) and truth is True:
                return

    def visit_Raise(self, node: ast.Raise) -> None:
        return

    def _visit_body(self, body: Sequence[ast.stmt]) -> None:
        for statement in body:
            self.visit(statement)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        truth = _constant_truth_value(node.test)
        if truth is not False:
            self._visit_body(node.body)
        if truth is not True:
            self._visit_body(node.orelse)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        truth = _constant_truth_value(node.test)
        if truth is False:
            self._visit_body(node.orelse)
            return
        self._visit_body(node.body)
        if truth is None:
            self._visit_body(node.orelse)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        truth = _constant_truth_value(node.test)
        if truth is not False:
            self.visit(node.body)
        if truth is not True:
            self.visit(node.orelse)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class _ReachableExplicitRaiseVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.raises: list[ast.Raise] = []

    def _visit_body(self, body: Sequence[ast.stmt]) -> None:
        for statement in body:
            self.visit(statement)

    def visit_Raise(self, node: ast.Raise) -> None:
        self.raises.append(node)

    def visit_If(self, node: ast.If) -> None:
        truth = _constant_truth_value(node.test)
        if truth is not False:
            self._visit_body(node.body)
        if truth is not True:
            self._visit_body(node.orelse)

    def visit_While(self, node: ast.While) -> None:
        truth = _constant_truth_value(node.test)
        if truth is False:
            self._visit_body(node.orelse)
            return
        self._visit_body(node.body)
        if truth is None:
            self._visit_body(node.orelse)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _block_explicit_raises_escape(
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
) -> bool | None:
    visitor = _ReachableExplicitRaiseVisitor()
    visitor._visit_body(body)
    if not visitor.raises:
        return None
    return all(
        _raise_escapes_enclosing_suppressors(statement, aliases)
        for statement in visitor.raises
    )


def _raise_failure_signal_escapes(
    statement: ast.Raise,
    aliases: dict[str, str],
) -> bool:
    if not _raise_escapes_enclosing_suppressors(statement, aliases):
        return False
    current: ast.AST = statement
    parent = _parent_node(current)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
        if (
            isinstance(parent, ast.Try)
            and isinstance(current, ast.stmt)
            and current in parent.body
        ):
            handlers, definitely_caught = _potential_handlers_for_raise(
                parent.handlers,
                statement,
                aliases,
            )
            handler_paths = []
            for handler in handlers:
                path = tuple(handler.body)
                if "fallthrough" in _block_exit_kinds(path, aliases):
                    path = (
                        *path,
                        *parent.finalbody,
                        *_following_execution_statements(parent),
                    )
                handler_paths.append(path)
            if any(
                not _failure_branch_handles_result(
                    path,
                    result_name=None,
                    checker=None,
                    aliases=aliases,
                )
                for path in handler_paths
            ):
                return False
            if definitely_caught:
                return True
        current = parent
        parent = _parent_node(current)
    return True


def _assertion_failure_escapes(
    statement: ast.Assert,
    aliases: dict[str, str],
) -> bool:
    assertion_error = ast.Raise(
        exc=ast.Name(id="AssertionError", ctx=ast.Load()),
        cause=None,
    )
    current: ast.AST = statement
    parent = _parent_node(current)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
        if (
            isinstance(parent, (ast.With, ast.AsyncWith))
            and isinstance(current, ast.stmt)
            and current in parent.body
            and not _context_manager_preserves_validation_errors(
                parent,
                aliases,
                exception_names=frozenset(
                    {"AssertionError", "builtins.AssertionError"}
                ),
                builtin_catchers=frozenset({AssertionError, BaseException, Exception}),
            )
        ):
            return False
        if (
            isinstance(parent, ast.Try)
            and isinstance(current, ast.stmt)
            and current in parent.body
        ):
            handlers, definitely_caught = _potential_handlers_for_raise(
                parent.handlers,
                assertion_error,
                aliases,
            )
            for handler in handlers:
                path = tuple(handler.body)
                if "fallthrough" in _block_exit_kinds(path, aliases):
                    path = (
                        *path,
                        *parent.finalbody,
                        *_following_execution_statements(parent),
                    )
                if not _failure_branch_handles_result(
                    path,
                    result_name=None,
                    checker=None,
                    aliases=aliases,
                ):
                    return False
            if definitely_caught:
                return True
        current = parent
        parent = _parent_node(current)
    return True


def _block_failure_signals_escape(
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
) -> bool | None:
    visitor = _ReachableExplicitRaiseVisitor()
    visitor._visit_body(body)
    if not visitor.raises:
        return None
    return all(
        _raise_failure_signal_escapes(statement, aliases)
        for statement in visitor.raises
    )


def _node_may_raise_implicitly(node: ast.AST | None) -> bool:
    if node is None:
        return False
    visitor = _ImplicitRaiseVisitor()
    visitor.visit(node)
    return visitor.found


def _raise_expression_may_raise_implicitly(
    node: ast.AST | None,
    aliases: dict[str, str],
) -> bool:
    if not isinstance(node, ast.Call) or not _builtin_exception_types(node, aliases):
        return _node_may_raise_implicitly(node)
    return any(
        isinstance(argument, ast.Starred) or _node_may_raise_implicitly(argument)
        for argument in node.args
    ) or any(
        keyword.arg is None or _node_may_raise_implicitly(keyword.value)
        for keyword in node.keywords
    )


def _statement_may_raise_implicitly(statement: ast.stmt) -> bool:
    return _node_may_raise_implicitly(statement)


class _NamedAttributeVisitor(ast.NodeVisitor):
    def __init__(self, name: str, attributes: frozenset[str]) -> None:
        self.name = name
        self.attributes = attributes
        self.found = False

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == self.name
            and node.attr in self.attributes
        ):
            self.found = True
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class _OperationalCallVisitor(ast.NodeVisitor):
    def __init__(
        self,
        aliases: dict[str, str],
        alias_snapshots: dict[int, dict[str, str]],
        local_names: set[str] | None,
    ) -> None:
        self.aliases = aliases
        self.alias_snapshots = alias_snapshots
        self.local_names = local_names
        self.subprocess_calls: list[OperationalCall] = []
        self.network_calls: list[OperationalCall] = []
        self.http_calls: list[OperationalCall] = []

    def visit_Call(self, node: ast.Call) -> None:
        aliases = _aliases_for_scope_snapshot(
            self.aliases,
            self.alias_snapshots.get(id(node)),
            self.local_names,
        )
        raw_name = _expression_name(node.func)
        qualified_name = _resolve_imported_name(raw_name, aliases)
        if qualified_name == "subprocess.run":
            self.subprocess_calls.append(OperationalCall(node, qualified_name, aliases))
        if _is_timeout_call(qualified_name):
            self.network_calls.append(OperationalCall(node, qualified_name, aliases))
        if _is_http_call(qualified_name):
            self.http_calls.append(OperationalCall(node, qualified_name, aliases))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _collect_import_aliases(body: Sequence[ast.stmt]) -> dict[str, str]:
    visitor = _ImportAliasVisitor()
    for statement in body:
        visitor.visit(statement)
    return visitor.aliases


def _collect_local_bindings(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    body: Sequence[ast.stmt],
) -> set[str]:
    names = {
        argument.arg
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
    }
    if node.args.vararg:
        names.add(node.args.vararg.arg)
    if node.args.kwarg:
        names.add(node.args.kwarg.arg)

    visitor = _LocalBindingVisitor()
    for statement in body:
        visitor.visit(statement)
    return (names | visitor.names) - visitor.global_names - visitor.nonlocal_names


def _collect_body_bindings(body: Sequence[ast.stmt]) -> set[str]:
    visitor = _LocalBindingVisitor()
    for statement in body:
        visitor.visit(statement)
    return visitor.names - visitor.global_names - visitor.nonlocal_names


def _class_scope_bindings(node: ast.AST) -> set[str]:
    visitor = _ClassScopeBindingVisitor()
    visitor.visit(node)
    return visitor.names


def _merge_definition_aliases(
    states: Sequence[dict[str, str]],
) -> dict[str, str]:
    if not states:
        return {}
    common_names = set(states[0])
    for state in states[1:]:
        common_names.intersection_update(state)
    merged: dict[str, str] = {}
    for name in common_names:
        values = {
            DEFINITION_ALIAS_CANONICAL_NAMES.get(state[name], state[name])
            for state in states
        }
        if len(values) == 1:
            merged[name] = values.pop()
    return merged


def _loop_definition_reachability(
    node: ast.For | ast.AsyncFor | ast.While,
    aliases: dict[str, str] | None = None,
) -> tuple[bool, bool, bool]:
    if isinstance(node, (ast.For, ast.AsyncFor)):
        empty = _literal_iterable_is_empty(node.iter, aliases)
        return empty is not True, empty is not False, True
    truth = _constant_truth_value(node.test)
    return truth is not False, truth is not True, truth is not True


def _match_pattern_bindings(pattern: ast.pattern) -> set[str]:
    names: set[str] = set()
    for candidate in ast.walk(pattern):
        if isinstance(candidate, (ast.MatchAs, ast.MatchStar)) and candidate.name:
            names.add(candidate.name)
        elif isinstance(candidate, ast.MatchMapping) and candidate.rest:
            names.add(candidate.rest)
    return names


def _function_aliases(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    body: Sequence[ast.stmt],
    module_aliases: dict[str, str],
) -> dict[str, str]:
    local_aliases = _collect_import_aliases(body)
    shadowed_names = _collect_local_bindings(node, body)
    aliases = {
        name: qualified_name
        for name, qualified_name in module_aliases.items()
        if name not in shadowed_names
    }
    aliases.update(
        (name, qualified_name)
        for name, qualified_name in local_aliases.items()
        if name not in shadowed_names
    )
    return aliases


def _function_entry_aliases(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    body: Sequence[ast.stmt],
    outer_aliases: dict[str, str],
) -> dict[str, str]:
    local_names = _collect_local_bindings(node, body) | set(
        _collect_import_aliases(body)
    )
    return {
        name: qualified_name
        for name, qualified_name in outer_aliases.items()
        if name not in local_names
    }


def _function_prefix_aliases(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    body: Sequence[ast.stmt],
    outer_aliases: dict[str, str],
) -> dict[str, str]:
    aliases = _function_entry_aliases(node, body, outer_aliases)
    compound_statements = (
        ast.AsyncFor,
        ast.AsyncWith,
        ast.For,
        ast.If,
        ast.Match,
        ast.Try,
        ast.TryStar,
        ast.While,
        ast.With,
    )
    for statement in body:
        if isinstance(statement, compound_statements):
            break
        for name in _class_scope_bindings(statement):
            aliases[name] = f"{LOCAL_BINDING_ALIAS_PREFIX}.{name}"
        aliases.update(_collect_import_aliases((statement,)))
        if _statement_exit_kinds(statement, aliases) != {"fallthrough"}:
            break
    for name in _collect_body_bindings(body):
        aliases.pop(name, None)
    return aliases


def _resolve_imported_name(name: str, aliases: dict[str, str]) -> str:
    root, separator, remainder = name.partition(".")
    if root not in aliases:
        return ""
    qualified_root = aliases[root]
    return f"{qualified_root}.{remainder}" if separator else qualified_root


def _is_http_call(qualified_name: str) -> bool:
    module, separator, function = qualified_name.rpartition(".")
    return bool(
        separator
        and module != "httpx.AsyncClient"
        and module.split(".", 1)[0] in HTTP_CALL_MODULES
        and function in BLOCKING_HTTP_METHODS
    )


def _is_timeout_call(qualified_name: str) -> bool:
    return qualified_name == "urllib.request.urlopen" or _is_http_call(qualified_name)


def _call_result_name(node: ast.Call) -> str | None:
    current: ast.AST = node
    parent = _parent_node(current)
    while isinstance(parent, ast.Await):
        current = parent
        parent = _parent_node(current)

    if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        value = parent.value
        if value is current:
            targets = (
                parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            )
            names = [name for target in targets for name in _assigned_names(target)]
            return names[0] if len(names) == 1 else None

    if isinstance(parent, ast.withitem) and parent.context_expr is current:
        names = _assigned_names(parent.optional_vars) if parent.optional_vars else []
        return names[0] if len(names) == 1 else None
    return None


def _call_is_returned(node: ast.Call) -> bool:
    current: ast.AST = node
    parent = _parent_node(current)
    while isinstance(parent, ast.Await):
        current = parent
        parent = _parent_node(current)
    return isinstance(parent, (ast.Return, ast.Yield))


def _containing_statement(node: ast.AST) -> ast.stmt | None:
    current: ast.AST | None = node
    while current is not None and not isinstance(current, ast.stmt):
        current = _parent_node(current)
    return current


def _referenced_names(node: ast.AST) -> set[str]:
    visitor = _ReferencedNamesVisitor()
    visitor.visit(node)
    return visitor.names


def _statement_blocks_operational_scan(
    statement: ast.stmt,
    aliases: dict[str, str],
) -> bool:
    exit_kinds = _statement_exit_kinds(statement, aliases)
    return (
        "raise" in exit_kinds
        or "fallthrough" not in exit_kinds
        or not exit_kinds
        <= {
            "fallthrough",
            "raise",
        }
    )


class _OperationalFlowIndex:
    def __init__(
        self,
        body: Sequence[ast.stmt],
        aliases: dict[str, str],
        alias_snapshots: dict[int, dict[str, str]],
    ) -> None:
        self.aliases = aliases
        self.alias_snapshots = alias_snapshots
        self.blocks: list[tuple[ast.stmt, ...]] = []
        self.locations: dict[int, tuple[int, int]] = {}
        self.mentions: dict[tuple[int, str], list[int]] = {}
        self.barriers: list[tuple[int, ...]] = []
        self.implicit_raises: list[tuple[int, ...]] = []
        self.block_owners: list[tuple[ast.AST, str] | None] = []
        self.owned_blocks: dict[tuple[int, str], int] = {}
        self._index_block(body, owner=None)

    def aliases_for(self, node: ast.AST) -> dict[str, str]:
        current: ast.AST | None = node
        while current is not None:
            aliases = self.alias_snapshots.get(id(current))
            if aliases is not None:
                return aliases
            current = _parent_node(current)
        return self.aliases

    def _index_block(
        self,
        body: Sequence[ast.stmt],
        *,
        owner: tuple[ast.AST, str] | None,
    ) -> None:
        block_id = len(self.blocks)
        statements = tuple(body)
        self.blocks.append(statements)
        self.block_owners.append(owner)
        if owner is not None:
            owner_node, field = owner
            self.owned_blocks[(id(owner_node), field)] = block_id
        self.barriers.append(
            tuple(
                index
                for index, statement in enumerate(statements)
                if _statement_blocks_operational_scan(
                    statement,
                    self.aliases_for(statement),
                )
            )
        )
        self.implicit_raises.append(
            tuple(
                index
                for index, statement in enumerate(statements)
                if _statement_may_raise_implicitly(statement)
            )
        )
        for index, statement in enumerate(statements):
            self.locations[id(statement)] = (block_id, index)
            for name in _referenced_names(statement):
                self.mentions.setdefault((block_id, name), []).append(index)
        for statement in statements:
            self._index_nested_blocks(statement)

    def _index_nested_blocks(self, node: ast.AST) -> None:
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            return
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                statements = tuple(item for item in value if isinstance(item, ast.stmt))
                if statements:
                    self._index_block(statements, owner=(node, field))
                    continue
                for item in value:
                    if isinstance(item, ast.AST):
                        self._index_nested_blocks(item)
            elif isinstance(value, ast.AST):
                self._index_nested_blocks(value)

    def _owner_position(self, owner: ast.AST) -> tuple[int, int] | None:
        statement = _containing_statement(owner)
        return self.locations.get(id(statement)) if statement is not None else None

    def _block_start(self, owner: ast.AST, field: str) -> tuple[int, int] | None:
        block_id = self.owned_blocks.get((id(owner), field))
        return (block_id, -1) if block_id is not None else None

    def _try_continuation(
        self,
        owner: ast.Try | ast.TryStar,
        field: str,
    ) -> tuple[int, int] | None:
        if field == "body":
            alternative = self._block_start(owner, "orelse")
            if alternative is not None:
                return alternative
        if field in {"body", "orelse"}:
            final = self._block_start(owner, "finalbody")
            if final is not None:
                return final
        if field in {"body", "orelse"}:
            return self._owner_position(owner)
        if field == "finalbody" and "fallthrough" in _try_pre_final_exit_kinds(
            owner,
            self.aliases_for(owner),
        ):
            return self._owner_position(owner)
        return None

    def _continuation_after_block(self, block_id: int) -> tuple[int, int] | None:
        owner = self.block_owners[block_id]
        if owner is None:
            return None
        owner_node, field = owner
        if isinstance(owner_node, ast.If):
            return (
                self._owner_position(owner_node)
                if field in {"body", "orelse"}
                else None
            )
        if isinstance(owner_node, (ast.With, ast.AsyncWith)):
            return self._owner_position(owner_node) if field == "body" else None
        if isinstance(owner_node, ast.match_case):
            return self._owner_position(owner_node) if field == "body" else None
        if isinstance(owner_node, (ast.Try, ast.TryStar)):
            return self._try_continuation(owner_node, field)
        if isinstance(owner_node, ast.ExceptHandler):
            try_node = _parent_node(owner_node)
            if not isinstance(try_node, (ast.Try, ast.TryStar)):
                return None
            final = self._block_start(try_node, "finalbody")
            return final if final is not None else self._owner_position(try_node)
        if isinstance(owner_node, (ast.For, ast.AsyncFor, ast.While)):
            return self._owner_position(owner_node) if field == "orelse" else None
        return None

    def _enclosing_try_body(
        self,
        block_id: int,
    ) -> ast.Try | ast.TryStar | None:
        current_block_id = block_id
        visited: set[int] = set()
        while current_block_id not in visited:
            visited.add(current_block_id)
            owner = self.block_owners[current_block_id]
            if owner is None:
                return None
            owner_node, field = owner
            if isinstance(owner_node, (ast.Try, ast.TryStar)):
                if field == "body":
                    return owner_node
            owner_position = self._owner_position(owner_node)
            if owner_position is None:
                return None
            current_block_id = owner_position[0]
        return None

    def _outer_enclosing_try(
        self,
        node: ast.Try | ast.TryStar,
    ) -> ast.Try | ast.TryStar | None:
        location = self.locations.get(id(node))
        if location is None:
            return None
        return self._enclosing_try_body(location[0])

    def _uncaught_raise_continuations(
        self,
        try_node: ast.Try | ast.TryStar,
    ) -> tuple[FlowContinuation, ...]:
        final = self._block_start(try_node, "finalbody")
        if final is not None:
            return ((final, "raise"),)
        outer_try = self._outer_enclosing_try(try_node)
        if outer_try is None:
            return ((None, "raise"),)
        return self._unknown_raise_continuations(outer_try)

    def _unknown_raise_continuations(
        self,
        try_node: ast.Try | ast.TryStar,
    ) -> tuple[FlowContinuation, ...]:
        continuations: list[FlowContinuation] = []
        definitely_caught = False
        for handler in try_node.handlers:
            continuations.append((self._block_start(handler, "body"), None))
            if _handler_catches_all_raises(
                handler,
                self.aliases_for(handler),
            ):
                definitely_caught = True
                break
        if not definitely_caught:
            continuations.extend(self._uncaught_raise_continuations(try_node))
        return tuple(continuations)

    def _implicit_raise_continuations(
        self,
        block_id: int,
    ) -> tuple[FlowContinuation, ...] | None:
        try_node = self._enclosing_try_body(block_id)
        if try_node is None:
            return None
        return self._unknown_raise_continuations(try_node)

    def _next_implicit_raise(
        self,
        block_id: int,
        statement_index: int,
    ) -> tuple[int, tuple[FlowContinuation, ...]] | None:
        implicit_raise_index = self._next_index_after(
            self.implicit_raises[block_id],
            statement_index,
        )
        if implicit_raise_index is None:
            return None
        continuations = self._implicit_raise_continuations(block_id)
        if continuations is None:
            return None
        return implicit_raise_index, continuations

    @staticmethod
    def _enqueue_flow_continuations(
        states: list[FlowState],
        outcomes: list[tuple[ast.stmt | None, bool]],
        continuations: tuple[FlowContinuation, ...],
    ) -> None:
        for raise_target, target_pending_exit in continuations:
            if raise_target is None:
                outcomes.append((None, True))
                continue
            states.append(
                (
                    raise_target[0],
                    raise_target[1],
                    target_pending_exit,
                    True,
                )
            )

    @classmethod
    def _enqueue_implicit_raise(
        cls,
        states: list[FlowState],
        outcomes: list[tuple[ast.stmt | None, bool]],
        *,
        block_id: int,
        implicit_raise_index: int,
        pending_exit: PendingExit,
        exceptional_path: bool,
        continuations: tuple[FlowContinuation, ...],
    ) -> None:
        states.append(
            (
                block_id,
                implicit_raise_index,
                pending_exit,
                exceptional_path,
            )
        )
        cls._enqueue_flow_continuations(states, outcomes, continuations)

    def _raise_continuations(
        self,
        block_id: int,
        statement_index: int,
    ) -> tuple[FlowContinuation, ...] | None:
        statement = self.blocks[block_id][statement_index]
        visitor = _ReachableExplicitRaiseVisitor()
        visitor.visit(statement)
        if not visitor.raises:
            return None
        try_node = self._enclosing_try_body(block_id)
        if try_node is None:
            return ((None, "raise"),)
        continuations: list[FlowContinuation] = []
        for explicit_raise in visitor.raises:
            aliases = self.aliases_for(explicit_raise)
            handlers, definitely_caught = _potential_handlers_for_raise(
                try_node.handlers,
                explicit_raise,
                aliases,
            )
            for handler in handlers:
                handler_start = self._block_start(handler, "body")
                continuations.append((handler_start, None))
            if not definitely_caught:
                continuations.extend(self._uncaught_raise_continuations(try_node))
        unique: dict[FlowContinuation, None] = {}
        for flow_continuation in continuations:
            unique.setdefault(flow_continuation, None)
        return tuple(unique)

    def _enclosing_loop(
        self,
        block_id: int,
    ) -> ast.For | ast.AsyncFor | ast.While | None:
        current_block_id = block_id
        visited: set[int] = set()
        while current_block_id not in visited:
            visited.add(current_block_id)
            owner = self.block_owners[current_block_id]
            if owner is None:
                return None
            owner_node, field = owner
            if isinstance(owner_node, (ast.For, ast.AsyncFor, ast.While)):
                return owner_node if field == "body" else None
            owner_position = self._owner_position(owner_node)
            if owner_position is None:
                return None
            current_block_id = owner_position[0]
        return None

    def _break_continuation(self, block_id: int) -> tuple[int, int] | None:
        loop = self._enclosing_loop(block_id)
        return self._owner_position(loop) if loop is not None else None

    def _pending_raise_continuations(
        self,
        block_id: int,
    ) -> tuple[FlowContinuation, ...] | None:
        owner = self.block_owners[block_id]
        if owner is None:
            return None
        owner_node, field = owner
        if not isinstance(owner_node, (ast.Try, ast.TryStar)) or field != "finalbody":
            return None
        outer_try = self._outer_enclosing_try(owner_node)
        if outer_try is None:
            return ((None, "raise"),)
        return self._unknown_raise_continuations(outer_try)

    def _enclosing_finally_for_exit(
        self,
        block_id: int,
    ) -> ast.Try | ast.TryStar | None:
        current_block_id = block_id
        visited: set[int] = set()
        while current_block_id not in visited:
            visited.add(current_block_id)
            owner = self.block_owners[current_block_id]
            if owner is None:
                return None
            owner_node, field = owner
            if (
                isinstance(owner_node, (ast.Try, ast.TryStar))
                and field in {"body", "orelse"}
                and owner_node.finalbody
            ):
                return owner_node
            if isinstance(owner_node, ast.ExceptHandler):
                try_node = _parent_node(owner_node)
                if isinstance(try_node, (ast.Try, ast.TryStar)) and try_node.finalbody:
                    return try_node
            owner_position = self._owner_position(owner_node)
            if owner_position is None:
                return None
            current_block_id = owner_position[0]
        return None

    def _enqueue_abrupt_exit(
        self,
        states: list[FlowState],
        outcomes: list[tuple[ast.stmt | None, bool]],
        *,
        block_id: int,
        exit_kind: Literal["break", "continue", "return"],
        exceptional_path: bool,
    ) -> None:
        try_node = self._enclosing_finally_for_exit(block_id)
        if try_node is not None:
            final = self._block_start(try_node, "finalbody")
            if final is not None:
                states.append((final[0], final[1], exit_kind, exceptional_path))
                return
        if exit_kind == "break":
            continuation = self._break_continuation(block_id)
            if continuation is not None:
                states.append(
                    (
                        continuation[0],
                        continuation[1],
                        None,
                        exceptional_path,
                    )
                )
                return
        outcomes.append((None, exceptional_path))

    def _follow_barrier(
        self,
        states: list[FlowState],
        outcomes: list[tuple[ast.stmt | None, bool]],
        block_id: int,
        barrier_index: int,
        pending_exit: PendingExit,
        exceptional_path: bool,
    ) -> None:
        barrier = self.blocks[block_id][barrier_index]
        exit_kinds = _statement_exit_kinds(
            barrier,
            self.aliases_for(barrier),
        )
        continuations = self._raise_continuations(block_id, barrier_index)
        if continuations is not None:
            if "fallthrough" in exit_kinds:
                states.append(
                    (
                        block_id,
                        barrier_index,
                        pending_exit,
                        exceptional_path,
                    )
                )
            self._enqueue_flow_continuations(states, outcomes, continuations)
            return
        if exit_kinds == {"raise"}:
            exceptional = self._implicit_raise_continuations(block_id)
            if exceptional is not None:
                self._enqueue_flow_continuations(states, outcomes, exceptional)
                return
        exit_kind: Literal["break", "continue", "return"] | None = None
        if exit_kinds == {"break"}:
            exit_kind = "break"
        elif exit_kinds == {"continue"}:
            exit_kind = "continue"
        elif exit_kinds == {"return"}:
            exit_kind = "return"
        if exit_kind is not None:
            self._enqueue_abrupt_exit(
                states,
                outcomes,
                block_id=block_id,
                exit_kind=exit_kind,
                exceptional_path=exceptional_path,
            )
            return
        outcomes.append(
            (
                None,
                exceptional_path or pending_exit == "raise" or exit_kinds == {"raise"},
            )
        )

    def _follow_block_end(
        self,
        states: list[FlowState],
        outcomes: list[tuple[ast.stmt | None, bool]],
        block_id: int,
        pending_exit: PendingExit,
        exceptional_path: bool,
    ) -> None:
        if pending_exit == "raise":
            continuations = self._pending_raise_continuations(block_id)
            if continuations is not None:
                self._enqueue_flow_continuations(states, outcomes, continuations)
                return
        if pending_exit in {"break", "continue", "return"}:
            self._enqueue_abrupt_exit(
                states,
                outcomes,
                block_id=block_id,
                exit_kind=pending_exit,
                exceptional_path=exceptional_path,
            )
            return
        continuation = self._continuation_after_block(block_id)
        if continuation is None:
            outcomes.append((None, pending_exit == "raise" or exceptional_path))
            return
        states.append(
            (
                continuation[0],
                continuation[1],
                pending_exit,
                exceptional_path,
            )
        )

    @staticmethod
    def _next_index_after(indices: Sequence[int], current: int) -> int | None:
        position = bisect_right(indices, current)
        return indices[position] if position < len(indices) else None

    @staticmethod
    def _unique_flow_outcomes(
        outcomes: Sequence[tuple[ast.stmt | None, bool]],
    ) -> tuple[tuple[ast.stmt | None, bool], ...]:
        unique: dict[tuple[int | None, bool], tuple[ast.stmt | None, bool]] = {}
        for outcome, terminates_safely in outcomes:
            key = (id(outcome) if outcome is not None else None, terminates_safely)
            unique.setdefault(key, (outcome, terminates_safely))
        return tuple(unique.values())

    def _follow_state_until_mention(
        self,
        states: list[FlowState],
        outcomes: list[tuple[ast.stmt | None, bool]],
        *,
        block_id: int,
        statement_index: int,
        pending_exit: PendingExit,
        exceptional_path: bool,
        name: str,
    ) -> None:
        mention_index = self._next_index_after(
            self.mentions.get((block_id, name), ()),
            statement_index,
        )
        barrier_index = self._next_index_after(
            self.barriers[block_id],
            statement_index,
        )
        implicit_raise = self._next_implicit_raise(block_id, statement_index)
        implicit_raise_index = implicit_raise[0] if implicit_raise is not None else None
        if (
            mention_index is not None
            and (barrier_index is None or mention_index <= barrier_index)
            and (implicit_raise_index is None or mention_index <= implicit_raise_index)
        ):
            outcomes.append((self.blocks[block_id][mention_index], False))
            return
        if implicit_raise is not None and (
            barrier_index is None or implicit_raise[0] < barrier_index
        ):
            self._enqueue_implicit_raise(
                states,
                outcomes,
                block_id=block_id,
                implicit_raise_index=implicit_raise[0],
                pending_exit=pending_exit,
                exceptional_path=exceptional_path,
                continuations=implicit_raise[1],
            )
            return
        if barrier_index is not None:
            self._follow_barrier(
                states,
                outcomes,
                block_id,
                barrier_index,
                pending_exit,
                exceptional_path,
            )
            return
        self._follow_block_end(
            states,
            outcomes,
            block_id,
            pending_exit,
            exceptional_path,
        )

    def next_statements_mentioning(
        self,
        node: ast.AST,
        name: str,
    ) -> tuple[tuple[ast.stmt | None, bool], ...]:
        statement = _containing_statement(node)
        if statement is None:
            return ((None, False),)
        location = self.locations.get(id(statement))
        if location is None:
            return ((None, False),)
        states: list[FlowState] = [(location[0], location[1], None, False)]
        outcomes: list[tuple[ast.stmt | None, bool]] = []
        visited: set[FlowState] = set()
        state_index = 0
        while state_index < len(states):
            (
                block_id,
                statement_index,
                pending_exit,
                exceptional_path,
            ) = states[state_index]
            state_index += 1
            state = (
                block_id,
                statement_index,
                pending_exit,
                exceptional_path,
            )
            if state in visited:
                continue
            visited.add(state)
            self._follow_state_until_mention(
                states,
                outcomes,
                block_id=block_id,
                statement_index=statement_index,
                pending_exit=pending_exit,
                exceptional_path=exceptional_path,
                name=name,
            )
        return self._unique_flow_outcomes(outcomes)


def _node_contains_named_attribute(
    node: ast.AST,
    name: str,
    attributes: frozenset[str],
) -> bool:
    visitor = _NamedAttributeVisitor(name, attributes)
    visitor.visit(node)
    return visitor.found


def _direct_method_call(
    statement: ast.stmt,
    name: str,
    method: str,
    *,
    raises_before_validation_are_safe: bool = True,
) -> bool:
    value: ast.AST | None = None
    if isinstance(statement, (ast.Expr, ast.Return, ast.Assign)):
        value = statement.value
    elif isinstance(statement, ast.AnnAssign):
        value = statement.value
    return _expression_reaches_direct_method_call(
        value,
        name,
        method,
        raises_before_validation_are_safe=raises_before_validation_are_safe,
    )


def _expression_reaches_direct_method_call(
    node: ast.AST | None,
    name: str,
    method: str,
    *,
    raises_before_validation_are_safe: bool = True,
) -> bool:
    if isinstance(node, ast.Call):
        function = node.func
        direct = bool(
            isinstance(function, ast.Attribute)
            and function.attr == method
            and isinstance(function.value, ast.Name)
            and function.value.id == name
        )
        if direct:
            arguments = (
                *node.args,
                *(keyword.value for keyword in node.keywords),
            )
            return not any(
                name in _referenced_names(argument)
                or (
                    not raises_before_validation_are_safe
                    and _node_may_raise_implicitly(argument)
                )
                for argument in arguments
            )
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        elements: tuple[ast.AST, ...] = tuple(
            element.value if isinstance(element, ast.Starred) else element
            for element in node.elts
        )
    elif isinstance(node, ast.Dict):
        elements = tuple(
            expression
            for key, value in zip(node.keys, node.values, strict=True)
            for expression in ((key, value) if key is not None else (value,))
        )
    elif isinstance(node, ast.Call):
        elements = (
            node.func,
            *node.args,
            *(keyword.value for keyword in node.keywords),
        )
    elif isinstance(node, ast.Compare) and len(node.ops) == 1:
        elements = (node.left, node.comparators[0])
    elif isinstance(node, ast.NamedExpr):
        elements = (node.value,)
    else:
        return False
    for element in elements:
        if _expression_reaches_direct_method_call(
            element,
            name,
            method,
            raises_before_validation_are_safe=raises_before_validation_are_safe,
        ):
            return True
        if name in _referenced_names(element) or (
            not raises_before_validation_are_safe
            and _node_may_raise_implicitly(element)
        ):
            return False
    return False


def _delegated_expression(statement: ast.stmt) -> ast.AST | None:
    if isinstance(statement, ast.Return):
        return statement.value
    if isinstance(statement, ast.Expr) and isinstance(
        statement.value, (ast.Yield, ast.YieldFrom)
    ):
        return statement.value.value
    return None


def _statement_delegates_result(statement: ast.stmt, name: str) -> bool:
    return name in _direct_result_names(_delegated_expression(statement))


def _single_assignment(
    statement: ast.stmt,
) -> tuple[str, ast.AST] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    if (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and statement.value is not None
    ):
        return statement.target.id, statement.value
    return None


def _definition_alias_binding(
    statement: ast.stmt,
    aliases: dict[str, str],
) -> tuple[str, str] | None:
    assignment = _single_assignment(statement)
    if assignment is None:
        return None
    name, expression = assignment
    if not isinstance(expression, (ast.Attribute, ast.Name)):
        return None
    raw_name = _expression_name(expression)
    qualified_name = _resolve_imported_name(raw_name, aliases)
    if qualified_name:
        if qualified_name.startswith(f"{LOCAL_BINDING_ALIAS_PREFIX}."):
            return None
        return name, qualified_name
    if (
        "." not in raw_name
        and hasattr(builtins, raw_name)
        and not _name_shadows_builtin(expression, raw_name)
    ):
        return name, f"builtins.{raw_name}"
    return None


def _is_direct_named_attribute(
    node: ast.AST | None,
    name: str,
    attributes: frozenset[str],
) -> bool:
    return bool(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == name
        and node.attr in attributes
    )


def _block_guarantees_result_handled(
    body: Sequence[ast.stmt],
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool = True,
) -> bool:
    return (
        _block_result_handling_state(
            body,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
        )
        == "handled"
    )


def _match_reaches_direct_validation_before_other_raise(
    statement: ast.Match,
    following: Sequence[ast.stmt],
    name: str,
    method: str,
    aliases: dict[str, str],
) -> bool:
    if name in _referenced_names(statement.subject) or _node_may_raise_implicitly(
        statement.subject
    ):
        return False
    paths: list[tuple[ast.stmt, ...]] = []
    exhaustive = False
    for case in statement.cases:
        if case.guard is not None and _constant_truth_value(case.guard) is False:
            continue
        if (
            name in _match_pattern_bindings(case.pattern)
            or case.guard is not None
            or _node_may_raise_implicitly(case.pattern)
        ):
            return False
        paths.append((*case.body, *following))
        if _match_case_is_irrefutable(case):
            exhaustive = True
            break
    if not exhaustive:
        paths.append(tuple(following))
    return bool(paths) and all(
        _body_reaches_direct_validation_before_other_raise(
            path,
            name,
            method,
            aliases,
        )
        for path in paths
    )


def _body_reaches_direct_validation_before_other_raise(
    body: Sequence[ast.stmt],
    name: str,
    method: str,
    aliases: dict[str, str],
) -> bool:
    statements = tuple(body)
    for index, statement in enumerate(statements):
        following = statements[index + 1 :]
        if _direct_method_call(
            statement,
            name,
            method,
            raises_before_validation_are_safe=False,
        ):
            return True
        if isinstance(statement, ast.If):
            if name in _referenced_names(statement.test) or _node_may_raise_implicitly(
                statement.test
            ):
                return False
            truth = _constant_truth_value(statement.test)
            branches = (
                (statement.body,)
                if truth is True
                else (statement.orelse,)
                if truth is False
                else (statement.body, statement.orelse)
            )
            return all(
                _body_reaches_direct_validation_before_other_raise(
                    (*branch, *following),
                    name,
                    method,
                    aliases,
                )
                for branch in branches
            )
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            if any(
                _node_may_raise_implicitly(item.context_expr)
                for item in statement.items
            ):
                return False
            return _body_reaches_direct_validation_before_other_raise(
                (*statement.body, *following),
                name,
                method,
                aliases,
            )
        if isinstance(statement, ast.Match):
            return _match_reaches_direct_validation_before_other_raise(
                statement,
                following,
                name,
                method,
                aliases,
            )
        if (
            name in _referenced_names(statement)
            or _statement_may_raise_implicitly(statement)
            or _statement_exit_kinds(statement, aliases) != {"fallthrough"}
        ):
            return False
    return False


def _try_finally_handles_result(
    statement: ast.Try | ast.TryStar,
    handlers: Sequence[ast.ExceptHandler],
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool | None:
    if not statement.finalbody:
        return None
    final_state = _block_result_handling_state(
        statement.finalbody,
        name,
        checker,
        aliases,
        raises_are_safe=raises_are_safe,
        delegation_is_safe=False,
    )
    if final_state == "unsafe":
        return False
    if final_state != "handled":
        return None
    pre_final_blocks = (
        statement.body,
        statement.orelse,
        *(handler.body for handler in handlers),
    )
    return all(
        _block_result_handling_state(
            block,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
            delegation_is_safe=False,
            terminal_returns_are_safe=True,
            terminal_loop_exits_are_safe=True,
        )
        != "unsafe"
        for block in pre_final_blocks
    )


def _try_guarantees_result_handled(
    statement: ast.Try | ast.TryStar,
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool = True,
    validation_method: str,
    validation_exception_names: frozenset[str],
    validation_builtin_catchers: frozenset[type[BaseException]],
) -> bool:
    handlers: Sequence[ast.ExceptHandler] = statement.handlers
    if isinstance(statement, ast.Try):
        explicit_raise = _sole_explicit_raise(statement.body, aliases)
        if explicit_raise is not None:
            handlers, _ = _potential_handlers_for_raise(
                statement.handlers,
                explicit_raise,
                aliases,
            )

    final_result = _try_finally_handles_result(
        statement,
        handlers,
        name,
        checker,
        aliases,
        raises_are_safe=raises_are_safe,
    )
    if final_result is not None:
        return final_result

    if not _block_guarantees_result_handled(
        statement.body,
        name,
        checker,
        aliases,
        raises_are_safe=raises_are_safe,
    ):
        return False
    if _body_reaches_direct_validation_before_other_raise(
        statement.body,
        name,
        validation_method,
        aliases,
    ):
        handlers = _validation_error_handlers(
            handlers,
            aliases,
            exception_names=validation_exception_names,
            builtin_catchers=validation_builtin_catchers,
        )
    return all(
        _failure_branch_handles_result(
            handler.body,
            result_name=name,
            checker=checker,
            aliases=aliases,
            raises_are_safe=raises_are_safe,
        )
        for handler in handlers
    )


def _expression_binds_name(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(candidate, ast.NamedExpr)
        and name in _assigned_names(candidate.target)
        for candidate in ast.walk(node)
    )


def _boolean_success_polarity(
    node: ast.AST,
    atomic_polarity: Callable[[ast.AST], bool | None],
    unsafe_before_check: Callable[[ast.AST], bool] | None = None,
) -> bool | None:
    polarity = atomic_polarity(node)
    if polarity is not None:
        return polarity
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand_polarity = _boolean_success_polarity(
            node.operand,
            atomic_polarity,
            unsafe_before_check,
        )
        return None if operand_polarity is None else not operand_polarity
    if isinstance(node, ast.NamedExpr):
        return _boolean_success_polarity(
            node.value,
            atomic_polarity,
            unsafe_before_check,
        )
    if isinstance(node, ast.BoolOp):
        unsafe_seen = False
        for value in node.values:
            item_polarity = _boolean_success_polarity(
                value,
                atomic_polarity,
                unsafe_before_check,
            )
            guarantees_success = isinstance(node.op, ast.And) and item_polarity is True
            guarantees_failure = isinstance(node.op, ast.Or) and item_polarity is False
            if guarantees_success or guarantees_failure:
                return None if unsafe_seen else item_polarity
            if unsafe_before_check is not None and unsafe_before_check(value):
                unsafe_seen = True
        return None
    if isinstance(node, ast.IfExp):
        body_polarity = _boolean_success_polarity(
            node.body,
            atomic_polarity,
            unsafe_before_check,
        )
        alternative_polarity = _boolean_success_polarity(
            node.orelse,
            atomic_polarity,
            unsafe_before_check,
        )
        if body_polarity == alternative_polarity:
            return body_polarity
    return None


class _NamedResultUseVisitor(ast.NodeVisitor):
    def __init__(self, name: str, allowed_attributes: frozenset[str]) -> None:
        self.name = name
        self.allowed_attributes = allowed_attributes
        self.found = False

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == self.name:
            if node.attr not in self.allowed_attributes:
                self.found = True
            return
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == self.name:
            self.found = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _node_uses_named_result_outside_attributes(
    node: ast.AST,
    name: str,
    allowed_attributes: frozenset[str],
) -> bool:
    visitor = _NamedResultUseVisitor(name, allowed_attributes)
    visitor.visit(node)
    return visitor.found


def _subprocess_comparison_success_polarity(
    node: ast.Compare,
    name: str,
) -> bool | None:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = node.left
    right = node.comparators[0]
    left_is_returncode = _is_direct_named_attribute(
        left,
        name,
        frozenset({"returncode"}),
    )
    right_is_returncode = _is_direct_named_attribute(
        right,
        name,
        frozenset({"returncode"}),
    )
    if left_is_returncode == right_is_returncode:
        return None
    other = right if left_is_returncode else left
    if not (
        (isinstance(other, ast.Constant) and type(other.value) is int)
        or isinstance(other, (ast.Name, ast.Attribute))
    ):
        return None
    operator = node.ops[0]
    if isinstance(operator, ast.Eq):
        return True
    if isinstance(operator, ast.NotEq):
        return False
    return None


def _subprocess_predicate_success_polarity(
    node: ast.AST,
    name: str,
) -> bool | None:
    def atomic_polarity(candidate: ast.AST) -> bool | None:
        if _is_direct_named_attribute(
            candidate,
            name,
            frozenset({"returncode"}),
        ):
            return False
        if isinstance(candidate, ast.Compare):
            return _subprocess_comparison_success_polarity(candidate, name)
        return None

    return _boolean_success_polarity(
        node,
        atomic_polarity,
        lambda candidate: _node_uses_named_result_outside_attributes(
            candidate,
            name,
            frozenset({"returncode"}),
        ),
    )


def _subprocess_expression_validates_returncode(node: ast.AST, name: str) -> bool:
    return _subprocess_predicate_success_polarity(node, name) is not None


def _following_execution_statements(
    statement: ast.stmt,
) -> tuple[ast.stmt, ...]:
    parent = _parent_node(statement)
    if parent is None:
        return ()
    field_name = ""
    siblings: tuple[ast.stmt, ...] = ()
    for field, value in ast.iter_fields(parent):
        if not isinstance(value, list) or statement not in value:
            continue
        index = value.index(statement)
        following = value[index + 1 :]
        if all(isinstance(candidate, ast.stmt) for candidate in following):
            field_name = field
            siblings = tuple(following)
            break

    continuation: tuple[ast.stmt, ...] = ()
    if isinstance(parent, (ast.If, ast.With, ast.AsyncWith)):
        continuation = _following_execution_statements(parent)
    elif isinstance(parent, (ast.Try, ast.TryStar)):
        if field_name == "body":
            continuation = (
                *parent.orelse,
                *parent.finalbody,
                *_following_execution_statements(parent),
            )
        elif field_name == "orelse":
            continuation = (
                *parent.finalbody,
                *_following_execution_statements(parent),
            )
        elif field_name == "finalbody":
            continuation = _following_execution_statements(parent)
    elif isinstance(parent, ast.ExceptHandler):
        try_node = _parent_node(parent)
        if isinstance(try_node, (ast.Try, ast.TryStar)):
            continuation = (
                *try_node.finalbody,
                *_following_execution_statements(try_node),
            )
    elif isinstance(parent, ast.match_case):
        match_node = _parent_node(parent)
        if isinstance(match_node, ast.Match):
            continuation = _following_execution_statements(match_node)
    return (*siblings, *continuation)


def _continued_branch_statements(
    body: Sequence[ast.stmt],
    owner: ast.stmt,
    aliases: dict[str, str],
) -> tuple[ast.stmt, ...]:
    if "fallthrough" not in _block_exit_kinds(body, aliases):
        return tuple(body)
    return (*body, *_following_execution_statements(owner))


def _failure_path_statements(
    statement: ast.If,
    polarity: bool,
    aliases: dict[str, str],
) -> tuple[ast.stmt, ...]:
    body = statement.orelse if polarity else statement.body
    return _continued_branch_statements(body, statement, aliases)


def _subprocess_failure_branch_is_handled(
    statement: ast.If,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool | None:
    polarity = _subprocess_predicate_success_polarity(statement.test, name)
    if polarity is None:
        return None
    return _failure_branch_handles_result(
        _failure_path_statements(statement, polarity, aliases),
        result_name=name,
        checker=_subprocess_statement_checks_result,
        aliases=aliases,
        raises_are_safe=raises_are_safe,
    )


def _subprocess_asserts_success(statement: ast.Assert, name: str) -> bool:
    return _subprocess_predicate_success_polarity(statement.test, name) is True


def _subprocess_while_checks_result(
    statement: ast.While,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool:
    if _constant_truth_value(
        statement.test
    ) is True and _block_guarantees_result_handled(
        statement.body,
        name,
        _subprocess_statement_checks_result,
        aliases,
        raises_are_safe=raises_are_safe,
    ):
        return True
    return False


def _for_guarantees_result_handled(
    statement: ast.For,
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool:
    return bool(
        name not in _bound_target_names(statement.target)
        and _literal_iterable_is_empty(statement.iter, aliases) is False
        and _block_guarantees_result_handled(
            statement.body,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    )


def _subprocess_if_checks_result(
    statement: ast.If,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool:
    predicate_result = _subprocess_failure_branch_is_handled(
        statement,
        name,
        aliases,
        raises_are_safe=raises_are_safe,
    )
    if predicate_result is not None:
        return predicate_result
    if name in _referenced_names(statement.test) and not _expression_binds_name(
        statement.test, name
    ):
        return False
    return _block_guarantees_result_handled(
        statement.body,
        name,
        _subprocess_statement_checks_result,
        aliases,
        raises_are_safe=raises_are_safe,
    ) and _block_guarantees_result_handled(
        statement.orelse,
        name,
        _subprocess_statement_checks_result,
        aliases,
        raises_are_safe=raises_are_safe,
    )


def _subprocess_with_checks_result(
    statement: ast.With | ast.AsyncWith,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool:
    if any(
        item.optional_vars is not None
        and name in _bound_target_names(item.optional_vars)
        for item in statement.items
    ):
        return False
    nested_raises_are_safe = (
        raises_are_safe
        and _context_manager_preserves_validation_errors(
            statement,
            aliases,
            exception_names=SUBPROCESS_CHECK_EXCEPTION_NAMES,
            builtin_catchers=SUBPROCESS_CHECK_BUILTIN_CATCHERS,
        )
    )
    return _block_guarantees_result_handled(
        statement.body,
        name,
        _subprocess_statement_checks_result,
        aliases,
        raises_are_safe=nested_raises_are_safe,
    )


def _match_cases_handle_result(
    statement: ast.Match,
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool:
    paths: list[tuple[ast.stmt, ...]] = []
    exhaustive = False
    for case in statement.cases:
        if case.guard is not None and _constant_truth_value(case.guard) is False:
            continue
        if (
            not paths
            and case.guard is not None
            and _match_pattern_is_irrefutable(case.pattern)
            and checker(
                ast.Expr(value=case.guard),
                name,
                aliases,
                raises_are_safe,
            )
        ):
            return True
        if name in _match_pattern_bindings(case.pattern):
            return False
        if case.guard is not None and name in _referenced_names(case.guard):
            return False
        paths.append(
            _continued_branch_statements(
                case.body,
                statement,
                aliases,
            )
        )
        if _match_case_is_irrefutable(case):
            exhaustive = True
            break
    if not exhaustive:
        paths.append(_following_execution_statements(statement))
    return bool(paths) and all(
        _failure_branch_handles_result(
            path,
            result_name=name,
            checker=checker,
            aliases=aliases,
            raises_are_safe=raises_are_safe,
        )
        for path in paths
    )


def _subprocess_match_checks_result(
    statement: ast.Match,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool:
    if _is_direct_named_attribute(
        statement.subject,
        name,
        frozenset({"returncode"}),
    ):
        return _match_guarantees_observation_success(
            statement,
            ResultObservation(name, "returncode"),
            aliases,
            _subprocess_statement_checks_result,
            raises_are_safe=raises_are_safe,
        )
    if name in _referenced_names(statement.subject):
        return False
    return _match_cases_handle_result(
        statement,
        name,
        _subprocess_statement_checks_result,
        aliases,
        raises_are_safe=raises_are_safe,
    )


def _subprocess_statement_checks_result(
    statement: ast.stmt,
    name: str,
    aliases: dict[str, str],
    raises_are_safe: bool = True,
) -> bool:
    if _direct_method_call(statement, name, "check_returncode"):
        return raises_are_safe
    expression: ast.AST | None = None
    if isinstance(statement, ast.If):
        return _subprocess_if_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    if isinstance(statement, (ast.Try, ast.TryStar)):
        return _try_guarantees_result_handled(
            statement,
            name,
            _subprocess_statement_checks_result,
            aliases,
            raises_are_safe=raises_are_safe,
            validation_method="check_returncode",
            validation_exception_names=SUBPROCESS_CHECK_EXCEPTION_NAMES,
            validation_builtin_catchers=SUBPROCESS_CHECK_BUILTIN_CATCHERS,
        )
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return _subprocess_with_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    if isinstance(statement, ast.While):
        return _subprocess_while_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    if isinstance(statement, ast.For):
        return _for_guarantees_result_handled(
            statement,
            name,
            _subprocess_statement_checks_result,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    if isinstance(statement, ast.Assert):
        return _subprocess_asserts_success(statement, name)
    if isinstance(statement, ast.Match):
        return _subprocess_match_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    if isinstance(statement, ast.Return):
        expression = statement.value
    if isinstance(statement, ast.Expr):
        expression = statement.value
    return bool(
        expression is not None
        and _subprocess_expression_validates_returncode(expression, name)
    )


def _comparison_zero_success_polarity(
    node: ast.Compare,
    contains_value: Callable[[ast.AST], bool],
) -> bool | None:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = node.left
    right = node.comparators[0]
    left_contains = contains_value(left)
    right_contains = contains_value(right)
    if left_contains == right_contains:
        return None
    other = right if left_contains else left
    if not (
        (isinstance(other, ast.Constant) and type(other.value) is int)
        or isinstance(other, (ast.Name, ast.Attribute))
    ):
        return None
    operator = node.ops[0]
    if isinstance(operator, ast.Eq):
        return True
    if isinstance(operator, ast.NotEq):
        return False
    return None


def _subprocess_observation_assignment(
    statement: ast.stmt,
    name: str,
    aliases: dict[str, str],
) -> ResultObservation | None:
    del aliases
    assignment = _single_assignment(statement)
    if assignment is None:
        return None
    observed_name, expression = assignment
    if isinstance(expression, ast.Compare):
        polarity = _comparison_zero_success_polarity(
            expression,
            lambda operand: _is_direct_named_attribute(
                operand,
                name,
                frozenset({"returncode"}),
            ),
        )
        if polarity is not None:
            return ResultObservation(observed_name, "boolean", polarity)
        return None
    if not _is_direct_named_attribute(
        expression,
        name,
        frozenset({"returncode"}),
    ):
        return None
    return ResultObservation(observed_name, "returncode")


def _is_http_status_scalar(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, int) and not isinstance(node.value, bool)
    return isinstance(node, (ast.Name, ast.Attribute))


def _is_http_status_collection(
    node: ast.AST,
    aliases: dict[str, str] | None = None,
) -> bool:
    if (
        isinstance(node, ast.Call)
        and _is_builtin_range_call(node, aliases)
        and 1 <= len(node.args) <= 3
        and not node.keywords
    ):
        return all(_is_http_status_scalar(argument) for argument in node.args)
    return bool(
        isinstance(node, (ast.List, ast.Set, ast.Tuple))
        and node.elts
        and all(_is_http_status_scalar(element) for element in node.elts)
    )


def _http_status_value(
    node: ast.AST,
    aliases: dict[str, str],
) -> int | None:
    if isinstance(node, ast.Constant):
        return node.value if type(node.value) is int else None
    raw_name = _expression_name(node)
    if not raw_name:
        return None
    qualified_name = _resolve_imported_name(raw_name, aliases)
    if not qualified_name:
        return None
    if qualified_name.startswith("http.HTTPStatus."):
        member_name = qualified_name.rsplit(".", 1)[-1].lower()
        return HTTP_STATUS_NAME_VALUES.get(member_name)
    module, separator, member_name = qualified_name.rpartition(".codes.")
    if separator and module in HTTP_CALL_MODULES:
        return HTTP_STATUS_NAME_VALUES.get(member_name.lower())
    return None


def _uses_http_status_constant_namespace(
    node: ast.AST,
    aliases: dict[str, str],
) -> bool:
    raw_name = _expression_name(node)
    if not raw_name:
        return False
    qualified_name = _resolve_imported_name(raw_name, aliases)
    for candidate in (qualified_name, raw_name):
        if candidate.startswith("http.HTTPStatus."):
            return True
        module, separator, _ = candidate.rpartition(".codes.")
        if separator and module in HTTP_CALL_MODULES:
            return True
    return False


def _http_status_is_success(status: int) -> bool:
    return 100 <= status < 400


def _http_status_collection_is_successful(
    node: ast.AST,
    aliases: dict[str, str],
) -> bool:
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)) and node.elts:
        literal_values = tuple(
            _http_status_value(element, aliases) for element in node.elts
        )
        return all(
            value is not None and _http_status_is_success(value)
            for value in literal_values
        )
    if not (
        isinstance(node, ast.Call)
        and _is_builtin_range_call(node, aliases)
        and 1 <= len(node.args) <= 3
        and not node.keywords
    ):
        return False
    arguments: list[int] = []
    for argument in node.args:
        value = _http_status_value(argument, aliases)
        if value is None:
            return False
        arguments.append(value)
    try:
        status_range = range(*arguments)
    except TypeError, ValueError:
        return False
    if not status_range:
        return False
    return _http_status_is_success(status_range[0]) and _http_status_is_success(
        status_range[-1]
    )


def _normalized_status_operator(
    operator: ast.cmpop,
    reverse: bool,
) -> ast.cmpop:
    if not reverse:
        return operator
    reversed_operators: dict[type[ast.cmpop], ast.cmpop] = {
        ast.Lt: ast.Gt(),
        ast.LtE: ast.GtE(),
        ast.Gt: ast.Lt(),
        ast.GtE: ast.LtE(),
    }
    return reversed_operators.get(type(operator), operator)


def _comparison_validates_http_status(
    node: ast.Compare,
    attribute: str,
    contains_attribute: Callable[[ast.AST], bool],
) -> bool:
    operands = (node.left, *node.comparators)
    for left, operator, right in zip(
        operands[:-1],
        node.ops,
        operands[1:],
        strict=True,
    ):
        left_contains = contains_attribute(left)
        right_contains = contains_attribute(right)
        if left_contains == right_contains:
            continue
        other = right if left_contains else left
        if attribute in {"is_success", "ok"}:
            if isinstance(operator, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) and (
                isinstance(other, ast.Constant) and isinstance(other.value, bool)
            ):
                return True
            continue
        if isinstance(operator, (ast.In, ast.NotIn)):
            if left_contains and _is_http_status_collection(other):
                return True
            continue
        if isinstance(operator, (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            if _is_http_status_scalar(other):
                return True
    return False


def _comparison_http_boolean_polarity(
    node: ast.Compare,
    contains_attribute: Callable[[ast.AST], bool],
) -> bool | None:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    operands = (node.left, *node.comparators)
    for left, operator, right in zip(
        operands[:-1],
        node.ops,
        operands[1:],
        strict=True,
    ):
        left_contains = contains_attribute(left)
        right_contains = contains_attribute(right)
        if left_contains == right_contains:
            continue
        other = right if left_contains else left
        if not (
            isinstance(operator, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot))
            and isinstance(other, ast.Constant)
            and isinstance(other.value, bool)
        ):
            continue
        if isinstance(operator, (ast.Eq, ast.Is)):
            return other.value
        return not other.value
    return None


def _comparison_http_status_success_polarity(
    node: ast.Compare,
    contains_attribute: Callable[[ast.AST], bool],
    aliases: dict[str, str],
) -> bool | None:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = node.left
    right = node.comparators[0]
    operator = node.ops[0]
    left_contains = contains_attribute(left)
    right_contains = contains_attribute(right)
    if left_contains == right_contains:
        return None
    other = right if left_contains else left
    if isinstance(operator, (ast.In, ast.NotIn)):
        if left_contains and _http_status_collection_is_successful(other, aliases):
            return isinstance(operator, ast.In)
        return None
    status = _http_status_value(other, aliases)
    if status is None:
        return None
    if isinstance(operator, (ast.Eq, ast.NotEq)):
        if not _http_status_is_success(status):
            return None
        return isinstance(operator, ast.Eq)
    status_operator = _normalized_status_operator(operator, right_contains)
    if isinstance(status_operator, ast.Lt) and 100 < status <= 400:
        return True
    if isinstance(status_operator, ast.LtE) and 100 <= status < 400:
        return True
    if isinstance(status_operator, ast.GtE) and 100 < status <= 400:
        return False
    if isinstance(status_operator, ast.Gt) and 100 <= status < 400:
        return False
    return None


def _http_boolean_predicate_polarity(
    node: ast.AST,
    is_attribute: Callable[[ast.AST], bool],
    contains_attribute: Callable[[ast.AST], bool],
    unsafe_before_check: Callable[[ast.AST], bool] | None = None,
) -> bool | None:
    def atomic_polarity(candidate: ast.AST) -> bool | None:
        if is_attribute(candidate):
            return True
        if isinstance(candidate, ast.Compare):
            return _comparison_http_boolean_polarity(
                candidate,
                contains_attribute,
            )
        return None

    return _boolean_success_polarity(
        node,
        atomic_polarity,
        unsafe_before_check,
    )


def _http_status_collection_has_resolved_failure(
    node: ast.AST,
    aliases: dict[str, str],
) -> bool:
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return any(
            not _http_status_is_success(value)
            for element in node.elts
            if (value := _http_status_value(element, aliases)) is not None
        )
    if not (isinstance(node, ast.Call) and _is_builtin_range_call(node, aliases)):
        return False
    return any(
        not _http_status_is_success(value)
        for argument in node.args
        if (value := _http_status_value(argument, aliases)) is not None
    )


def _comparison_selected_http_status_polarity(
    node: ast.Compare,
    is_status_attribute: Callable[[ast.AST], bool],
    aliases: dict[str, str],
) -> bool | None:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = node.left
    right = node.comparators[0]
    left_is_status = is_status_attribute(left)
    right_is_status = is_status_attribute(right)
    if left_is_status == right_is_status:
        return None
    other = right if left_is_status else left
    operator = node.ops[0]
    if isinstance(operator, (ast.In, ast.NotIn)):
        if left_is_status and _is_http_status_collection(other, aliases):
            if _http_status_collection_has_resolved_failure(other, aliases):
                return None
            return isinstance(operator, ast.In)
        return None
    if not (
        isinstance(operator, (ast.Eq, ast.NotEq)) and _is_http_status_scalar(other)
    ):
        return None
    status = _http_status_value(other, aliases)
    if status is None and _uses_http_status_constant_namespace(other, aliases):
        return None
    if status is not None and not _http_status_is_success(status):
        return None
    return isinstance(operator, ast.Eq)


def _http_atomic_success_polarity(
    candidate: ast.AST,
    is_boolean_attribute: Callable[[ast.AST], bool],
    is_status_attribute: Callable[[ast.AST], bool],
    aliases: dict[str, str],
) -> bool | None:
    if is_boolean_attribute(candidate):
        return True
    if not isinstance(candidate, ast.Compare):
        return None
    boolean_polarity = _comparison_http_boolean_polarity(
        candidate,
        is_boolean_attribute,
    )
    if boolean_polarity is not None:
        return boolean_polarity
    status_polarity = _comparison_http_status_success_polarity(
        candidate,
        is_status_attribute,
        aliases,
    )
    if status_polarity is not None:
        return status_polarity
    return _comparison_selected_http_status_polarity(
        candidate,
        is_status_attribute,
        aliases,
    )


def _http_predicate_success_polarity(
    node: ast.AST,
    name: str,
    aliases: dict[str, str],
) -> bool | None:
    def is_boolean_attribute(candidate: ast.AST) -> bool:
        return _is_direct_named_attribute(
            candidate,
            name,
            frozenset({"is_success", "ok"}),
        )

    def is_status_attribute(candidate: ast.AST) -> bool:
        return _is_direct_named_attribute(
            candidate,
            name,
            frozenset({"status_code"}),
        )

    return _boolean_success_polarity(
        node,
        lambda candidate: _http_atomic_success_polarity(
            candidate,
            is_boolean_attribute,
            is_status_attribute,
            aliases,
        ),
        lambda candidate: _node_uses_named_result_outside_attributes(
            candidate,
            name,
            HTTP_STATUS_ATTRIBUTES,
        ),
    )


def _named_attribute_matcher(
    name: str,
    attribute: str,
) -> Callable[[ast.AST], bool]:
    def contains_attribute(node: ast.AST) -> bool:
        return _node_contains_named_attribute(
            node,
            name,
            frozenset({attribute}),
        )

    return contains_attribute


def _http_expression_validates_status(
    node: ast.AST,
    name: str,
    aliases: dict[str, str],
) -> bool:
    return _http_predicate_success_polarity(node, name, aliases) is not None


def _http_observation_assignment(
    statement: ast.stmt,
    name: str,
    aliases: dict[str, str],
) -> ResultObservation | None:
    assignment = _single_assignment(statement)
    if assignment is None:
        return None
    observed_name, expression = assignment
    polarity = _http_boolean_predicate_polarity(
        expression,
        lambda node: _is_direct_named_attribute(
            node,
            name,
            frozenset({"is_success", "ok"}),
        ),
        _named_attribute_matcher(name, "ok"),
        lambda candidate: _node_uses_named_result_outside_attributes(
            candidate,
            name,
            HTTP_STATUS_ATTRIBUTES,
        ),
    )
    if polarity is None:
        polarity = _http_boolean_predicate_polarity(
            expression,
            lambda node: _is_direct_named_attribute(
                node,
                name,
                frozenset({"is_success"}),
            ),
            _named_attribute_matcher(name, "is_success"),
            lambda candidate: _node_uses_named_result_outside_attributes(
                candidate,
                name,
                HTTP_STATUS_ATTRIBUTES,
            ),
        )
    if polarity is not None:
        return ResultObservation(observed_name, "boolean", polarity)
    if isinstance(expression, ast.Compare):
        contains_status = _named_attribute_matcher(name, "status_code")
        status_polarity = _comparison_http_status_success_polarity(
            expression,
            contains_status,
            aliases,
        )
        if status_polarity is None:
            status_polarity = _comparison_selected_http_status_polarity(
                expression,
                contains_status,
                aliases,
            )
        if status_polarity is not None:
            return ResultObservation(observed_name, "boolean", status_polarity)
    if _is_direct_named_attribute(
        expression,
        name,
        frozenset({"status_code"}),
    ):
        return ResultObservation(observed_name, "http-status")
    return None


def _match_pattern_guarantees_observation_success(
    pattern: ast.pattern,
    observation: ResultObservation,
    aliases: dict[str, str],
) -> bool:
    if isinstance(pattern, ast.MatchOr):
        return bool(pattern.patterns) and all(
            _match_pattern_guarantees_observation_success(
                item,
                observation,
                aliases,
            )
            for item in pattern.patterns
        )
    if observation.kind == "boolean":
        return bool(
            isinstance(pattern, ast.MatchSingleton)
            and pattern.value is observation.truthy_is_success
        )
    if observation.kind == "returncode":
        return bool(
            isinstance(pattern, ast.MatchValue)
            and isinstance(pattern.value, ast.Constant)
            and type(pattern.value.value) is int
            and pattern.value.value == 0
        )
    return bool(
        isinstance(pattern, ast.MatchValue)
        and (status := _http_status_value(pattern.value, aliases)) is not None
        and _http_status_is_success(status)
    )


def _boolean_pattern_values(pattern: ast.pattern) -> set[bool]:
    if isinstance(pattern, ast.MatchSingleton) and isinstance(pattern.value, bool):
        return {pattern.value}
    if isinstance(pattern, ast.MatchOr):
        values: set[bool] = set()
        for item in pattern.patterns:
            values.update(_boolean_pattern_values(item))
        return values
    return set()


def _match_guarantees_observation_success(
    statement: ast.Match,
    observation: ResultObservation,
    aliases: dict[str, str],
    checker: ResultChecker | None = None,
    *,
    result_name: str | None = None,
    raises_are_safe: bool = True,
) -> bool:
    has_success_case = False
    exhaustive = False
    boolean_values: set[bool] = set()
    for case in statement.cases:
        if case.guard is not None and _constant_truth_value(case.guard) is False:
            continue
        success_case = _match_pattern_guarantees_observation_success(
            case.pattern,
            observation,
            aliases,
        )
        has_success_case |= success_case
        irrefutable = _match_case_is_irrefutable(case)
        if irrefutable:
            exhaustive = True
        if case.guard is None:
            if observation.kind == "boolean":
                boolean_values.update(_boolean_pattern_values(case.pattern))
        if success_case:
            if irrefutable:
                break
            continue
        failure_path = _continued_branch_statements(
            case.body,
            statement,
            aliases,
        )
        if _failure_branch_handles_result(
            failure_path,
            result_name=(
                result_name or observation.name if checker is not None else None
            ),
            checker=checker,
            aliases=aliases,
            raises_are_safe=raises_are_safe,
        ):
            if irrefutable:
                break
            continue
        return False
    if observation.kind == "boolean" and boolean_values == {False, True}:
        exhaustive = True
    return has_success_case and exhaustive


def _http_match_checks_result(
    statement: ast.Match,
    name: str,
    aliases: dict[str, str],
    raises_are_safe: bool,
    checker: ResultChecker,
) -> bool:
    if _is_direct_named_attribute(
        statement.subject,
        name,
        frozenset({"is_success", "ok"}),
    ):
        observation = ResultObservation(name, "boolean", True)
    elif _is_direct_named_attribute(
        statement.subject,
        name,
        frozenset({"status_code"}),
    ):
        observation = ResultObservation(name, "http-status")
    else:
        if name in _referenced_names(statement.subject):
            return False
        return _match_cases_handle_result(
            statement,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    return _match_guarantees_observation_success(
        statement,
        observation,
        aliases,
        checker,
        raises_are_safe=raises_are_safe,
    )


def _http_if_checks_result(
    statement: ast.If,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
    checker: ResultChecker,
) -> bool:
    polarity = _http_predicate_success_polarity(
        statement.test,
        name,
        aliases,
    )
    if polarity is not None:
        return _failure_branch_handles_result(
            _failure_path_statements(statement, polarity, aliases),
            result_name=name,
            checker=checker,
            aliases=aliases,
            raises_are_safe=raises_are_safe,
        )
    if name in _referenced_names(statement.test) and not _expression_binds_name(
        statement.test, name
    ):
        return False
    return _block_guarantees_result_handled(
        statement.body,
        name,
        checker,
        aliases,
        raises_are_safe=raises_are_safe,
    ) and _block_guarantees_result_handled(
        statement.orelse,
        name,
        checker,
        aliases,
        raises_are_safe=raises_are_safe,
    )


def _http_with_checks_result(
    statement: ast.With | ast.AsyncWith,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
    checker: ResultChecker,
    validation_exception_names: frozenset[str],
    validation_builtin_catchers: frozenset[type[BaseException]],
) -> bool:
    if any(
        item.optional_vars is not None
        and name in _bound_target_names(item.optional_vars)
        for item in statement.items
    ):
        return False
    nested_raises_are_safe = (
        raises_are_safe
        and _context_manager_preserves_validation_errors(
            statement,
            aliases,
            exception_names=validation_exception_names,
            builtin_catchers=validation_builtin_catchers,
        )
    )
    return _block_guarantees_result_handled(
        statement.body,
        name,
        checker,
        aliases,
        raises_are_safe=nested_raises_are_safe,
    )


def _http_while_checks_result(
    statement: ast.While,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
    checker: ResultChecker,
) -> bool:
    return bool(
        _constant_truth_value(statement.test) is True
        and _block_guarantees_result_handled(
            statement.body,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    )


def _http_exception_scope_checks_result(
    statement: ast.stmt,
    name: str,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
    checker: ResultChecker,
    validation_exception_names: frozenset[str],
    validation_builtin_catchers: frozenset[type[BaseException]],
) -> bool | None:
    if isinstance(statement, (ast.Try, ast.TryStar)):
        return _try_guarantees_result_handled(
            statement,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
            validation_method="raise_for_status",
            validation_exception_names=validation_exception_names,
            validation_builtin_catchers=validation_builtin_catchers,
        )
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return _http_with_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe=raises_are_safe,
            checker=checker,
            validation_exception_names=validation_exception_names,
            validation_builtin_catchers=validation_builtin_catchers,
        )
    return None


def _http_statement_checks_result(
    statement: ast.stmt,
    name: str,
    aliases: dict[str, str],
    raises_are_safe: bool = True,
    *,
    checker: ResultChecker | None = None,
    validation_exception_names: frozenset[str] = HTTP_CHECK_EXCEPTION_NAMES,
    validation_builtin_catchers: frozenset[
        type[BaseException]
    ] = HTTP_CHECK_BUILTIN_CATCHERS,
) -> bool:
    active_checker = checker or _http_statement_checks_result
    if _direct_method_call(statement, name, "raise_for_status"):
        return raises_are_safe
    delegated = _delegated_expression(statement)
    if _is_direct_named_attribute(delegated, name, HTTP_STATUS_ATTRIBUTES):
        return True
    expression: ast.AST | None = None
    exception_scope_result = _http_exception_scope_checks_result(
        statement,
        name,
        aliases,
        raises_are_safe=raises_are_safe,
        checker=active_checker,
        validation_exception_names=validation_exception_names,
        validation_builtin_catchers=validation_builtin_catchers,
    )
    if exception_scope_result is not None:
        return exception_scope_result
    if isinstance(statement, ast.If):
        return _http_if_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe=raises_are_safe,
            checker=active_checker,
        )
    if isinstance(statement, ast.While):
        return _http_while_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe=raises_are_safe,
            checker=active_checker,
        )
    if isinstance(statement, ast.For):
        return _for_guarantees_result_handled(
            statement,
            name,
            active_checker,
            aliases,
            raises_are_safe=raises_are_safe,
        )
    if isinstance(statement, ast.Assert):
        return (
            _http_predicate_success_polarity(
                statement.test,
                name,
                aliases,
            )
            is True
        )
    if isinstance(statement, ast.Match):
        return _http_match_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe,
            active_checker,
        )
    if delegated is not None:
        expression = delegated
    return bool(
        expression is not None
        and _http_expression_validates_status(expression, name, aliases)
    )


def _http_validation_exception_profile(
    qualified_name: str,
) -> tuple[frozenset[str], frozenset[type[BaseException]]]:
    module = qualified_name.split(".", 1)[0]
    if module == "httpx":
        return HTTPX_CHECK_EXCEPTION_NAMES, HTTPX_CHECK_BUILTIN_CATCHERS
    if module == "requests":
        return REQUESTS_CHECK_EXCEPTION_NAMES, REQUESTS_CHECK_BUILTIN_CATCHERS
    return HTTP_CHECK_EXCEPTION_NAMES, HTTP_CHECK_BUILTIN_CATCHERS


def _http_result_checker(qualified_name: str) -> ResultChecker:
    exception_names, builtin_catchers = _http_validation_exception_profile(
        qualified_name
    )

    def check(
        statement: ast.stmt,
        name: str,
        aliases: dict[str, str],
        raises_are_safe: bool,
    ) -> bool:
        return _http_statement_checks_result(
            statement,
            name,
            aliases,
            raises_are_safe,
            checker=check,
            validation_exception_names=exception_names,
            validation_builtin_catchers=builtin_catchers,
        )

    return check


def _boolean_name_polarity(node: ast.AST, name: str) -> bool | None:
    def is_name(candidate: ast.AST) -> bool:
        return isinstance(candidate, ast.Name) and candidate.id == name

    def atomic_polarity(candidate: ast.AST) -> bool | None:
        if is_name(candidate):
            return True
        if isinstance(candidate, ast.Compare):
            return _comparison_http_boolean_polarity(candidate, is_name)
        return None

    return _boolean_success_polarity(node, atomic_polarity)


def _returncode_name_polarity(node: ast.AST, name: str) -> bool | None:
    def atomic_polarity(candidate: ast.AST) -> bool | None:
        if isinstance(candidate, ast.Name) and candidate.id == name:
            return False
        if not (
            isinstance(candidate, ast.Compare)
            and len(candidate.ops) == 1
            and len(candidate.comparators) == 1
        ):
            return None
        left = candidate.left
        right = candidate.comparators[0]
        left_is_name = isinstance(left, ast.Name) and left.id == name
        right_is_name = isinstance(right, ast.Name) and right.id == name
        if left_is_name == right_is_name:
            return None
        other = right if left_is_name else left
        if not (
            (isinstance(other, ast.Constant) and type(other.value) is int)
            or isinstance(other, (ast.Name, ast.Attribute))
        ):
            return None
        operator = candidate.ops[0]
        if isinstance(operator, ast.Eq):
            return True
        if isinstance(operator, ast.NotEq):
            return False
        return None

    return _boolean_success_polarity(node, atomic_polarity)


class _LoadedNameVisitor(ast.NodeVisitor):
    def __init__(self, name: str) -> None:
        self.name = name
        self.found = False

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == self.name and isinstance(node.ctx, ast.Load):
            self.found = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _node_loads_name(node: ast.AST, name: str) -> bool:
    visitor = _LoadedNameVisitor(name)
    visitor.visit(node)
    return visitor.found


class _LoopExitVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.exits: list[ast.Break | ast.Continue] = []

    def visit_Break(self, node: ast.Break) -> None:
        self.exits.append(node)

    def visit_Continue(self, node: ast.Continue) -> None:
        self.exits.append(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _enclosing_loop_node(
    node: ast.AST,
) -> ast.For | ast.AsyncFor | ast.While | None:
    parent = _parent_node(node)
    while parent is not None:
        if isinstance(parent, (ast.For, ast.AsyncFor, ast.While)):
            return parent
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return None
        parent = _parent_node(parent)
    return None


def _statement_rebinds_name_without_read(
    statement: ast.stmt,
    name: str,
) -> bool:
    if isinstance(statement, ast.Assign):
        binds = any(name in _assigned_names(target) for target in statement.targets)
        return binds and not _node_loads_name(statement.value, name)
    if isinstance(statement, ast.AnnAssign) and statement.value is not None:
        return bool(
            name in _assigned_names(statement.target)
            and not _node_loads_name(statement.value, name)
        )
    return False


def _continued_iteration_rebinds_before_read(
    loop: ast.For | ast.AsyncFor | ast.While,
    name: str,
    aliases: dict[str, str],
) -> bool:
    for statement in loop.body:
        if _node_loads_name(statement, name):
            return False
        if _statement_rebinds_name_without_read(statement, name):
            return True
        if _statement_may_raise_implicitly(statement) or _statement_exit_kinds(
            statement, aliases
        ) != {"fallthrough"}:
            return False
    return False


def _post_loop_result_is_safe(
    loop: ast.For | ast.AsyncFor | ast.While,
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
) -> bool:
    continuation = _following_execution_statements(loop)
    if not any(_node_loads_name(statement, name) for statement in continuation):
        return True
    return (
        _block_result_handling_state(
            continuation,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
            terminal_returns_are_safe=True,
            terminal_loop_exits_are_safe=True,
        )
        == "handled"
    )


def _loop_exits_handle_result(
    body: Sequence[ast.stmt],
    *,
    result_name: str | None,
    checker: ResultChecker | None,
    aliases: dict[str, str],
    raises_are_safe: bool,
) -> bool:
    visitor = _LoopExitVisitor()
    for statement in body:
        visitor.visit(statement)
    if not visitor.exits:
        return False
    if result_name is None or checker is None:
        return True
    for exit_node in visitor.exits:
        loop = _enclosing_loop_node(exit_node)
        if loop is None or not _post_loop_result_is_safe(
            loop,
            result_name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
        ):
            return False
        if isinstance(
            exit_node,
            ast.Continue,
        ) and not _continued_iteration_rebinds_before_read(
            loop,
            result_name,
            aliases,
        ):
            return False
    return True


def _http_status_name_polarity(
    node: ast.AST,
    name: str,
    aliases: dict[str, str],
) -> bool | None:
    def is_name(candidate: ast.AST) -> bool:
        return isinstance(candidate, ast.Name) and candidate.id == name

    def atomic_polarity(candidate: ast.AST) -> bool | None:
        if not isinstance(candidate, ast.Compare):
            return None
        polarity = _comparison_http_status_success_polarity(
            candidate,
            is_name,
            aliases,
        )
        if polarity is not None:
            return polarity
        return _comparison_selected_http_status_polarity(
            candidate,
            is_name,
            aliases,
        )

    return _boolean_success_polarity(node, atomic_polarity)


def _failure_branch_handles_result(
    body: Sequence[ast.stmt],
    *,
    result_name: str | None,
    checker: ResultChecker | None,
    aliases: dict[str, str],
    raises_are_safe: bool = True,
) -> bool:
    loop_exits_are_safe = _loop_exits_handle_result(
        body,
        result_name=result_name,
        checker=checker,
        aliases=aliases,
        raises_are_safe=raises_are_safe,
    )
    if result_name is None or checker is None:
        exit_kinds = _block_exit_kinds(body, aliases)
        if "fallthrough" in exit_kinds or (
            exit_kinds & {"break", "continue"} and not loop_exits_are_safe
        ):
            return False
        if "raise" not in exit_kinds:
            return True
        explicit_raises_escape = _block_failure_signals_escape(body, aliases)
        if explicit_raises_escape is not None:
            return explicit_raises_escape
        return raises_are_safe
    return (
        _block_result_handling_state(
            body,
            result_name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
            terminal_returns_are_safe=True,
            terminal_loop_exits_are_safe=loop_exits_are_safe,
        )
        == "handled"
    )


def _observation_is_checked(
    statement: ast.stmt,
    observation: ResultObservation,
    aliases: dict[str, str],
    *,
    result_name: str | None = None,
    checker: ResultChecker | None = None,
) -> bool:
    name = observation.name
    if _statement_delegates_result(statement, name):
        return True
    expression: ast.AST | None = None
    if isinstance(statement, (ast.If, ast.While, ast.Assert)):
        expression = statement.test
    elif isinstance(statement, ast.Match):
        return bool(
            name in _referenced_names(statement.subject)
            and _match_guarantees_observation_success(
                statement,
                observation,
                aliases,
                checker,
                result_name=result_name,
            )
        )
    if expression is None or name not in _referenced_names(expression):
        return False
    if observation.kind == "boolean":
        polarity = _boolean_name_polarity(expression, name)
        if polarity is not None and observation.truthy_is_success is not None:
            polarity = polarity is observation.truthy_is_success
        else:
            polarity = None
    elif observation.kind == "returncode":
        polarity = _returncode_name_polarity(expression, name)
    else:
        polarity = _http_status_name_polarity(expression, name, aliases)
    if polarity is None:
        return False
    if isinstance(statement, ast.Assert):
        return polarity is True
    if not isinstance(statement, ast.If):
        return False
    return _failure_branch_handles_result(
        _failure_path_statements(statement, polarity, aliases),
        result_name=result_name,
        checker=checker,
        aliases=aliases,
    )


def _observation_is_handled_after(
    node: ast.AST,
    observation: ResultObservation,
    flow_index: _OperationalFlowIndex,
    *,
    result_name: str | None = None,
    checker: ResultChecker | None = None,
) -> bool:
    outcomes = flow_index.next_statements_mentioning(
        node,
        observation.name,
    )
    return bool(outcomes) and all(
        terminates_safely
        or (
            use is not None
            and _observation_is_checked(
                use,
                observation,
                flow_index.aliases_for(use),
                result_name=result_name,
                checker=checker,
            )
        )
        for use, terminates_safely in outcomes
    )


def _if_result_handling_state(
    statement: ast.If,
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool,
    delegation_is_safe: bool,
    terminal_returns_are_safe: bool,
    terminal_loop_exits_are_safe: bool,
) -> ResultHandlingState:
    if name in _referenced_names(statement.test) and not _expression_binds_name(
        statement.test, name
    ):
        return "unsafe"
    truth = _constant_truth_value(statement.test)
    branches: tuple[Sequence[ast.stmt], ...]
    if truth is True:
        branches = (statement.body,)
    elif truth is False:
        branches = (statement.orelse,)
    else:
        branches = (statement.body, statement.orelse)
    branch_states = {
        _block_result_handling_state(
            branch,
            name,
            checker,
            aliases,
            raises_are_safe=raises_are_safe,
            delegation_is_safe=delegation_is_safe,
            terminal_returns_are_safe=terminal_returns_are_safe,
            terminal_loop_exits_are_safe=terminal_loop_exits_are_safe,
        )
        for branch in branches
    }
    if "unsafe" in branch_states:
        return "unsafe"
    return "continues" if "continues" in branch_states else "handled"


def _block_result_handling_state(
    body: Sequence[ast.stmt],
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
    *,
    raises_are_safe: bool = True,
    delegation_is_safe: bool = True,
    terminal_returns_are_safe: bool = False,
    terminal_loop_exits_are_safe: bool = False,
) -> ResultHandlingState:
    for statement in body:
        if (
            delegation_is_safe and _statement_delegates_result(statement, name)
        ) or checker(
            statement,
            name,
            aliases,
            raises_are_safe,
        ):
            return "handled"
        if (
            isinstance(statement, ast.While)
            and _constant_truth_value(statement.test) is False
        ):
            state = _block_result_handling_state(
                statement.orelse,
                name,
                checker,
                aliases,
                raises_are_safe=raises_are_safe,
                delegation_is_safe=delegation_is_safe,
                terminal_returns_are_safe=terminal_returns_are_safe,
                terminal_loop_exits_are_safe=terminal_loop_exits_are_safe,
            )
            if state == "handled":
                return "handled"
            if state == "unsafe":
                return "unsafe"
            continue
        if isinstance(statement, ast.If):
            state = _if_result_handling_state(
                statement,
                name,
                checker,
                aliases,
                raises_are_safe=raises_are_safe,
                delegation_is_safe=delegation_is_safe,
                terminal_returns_are_safe=terminal_returns_are_safe,
                terminal_loop_exits_are_safe=terminal_loop_exits_are_safe,
            )
            if state == "continues":
                continue
            return state
        if name in _referenced_names(statement):
            return "unsafe"
        exit_kinds = _statement_exit_kinds(statement, aliases)
        if isinstance(
            statement, ast.Raise
        ) and not _raise_escapes_enclosing_suppressors(
            statement,
            aliases,
        ):
            return "unsafe"
        if "return" in exit_kinds:
            return "handled" if terminal_returns_are_safe else "unsafe"
        if exit_kinds & {"break", "continue"}:
            return "handled" if terminal_loop_exits_are_safe else "unsafe"
        if "raise" in exit_kinds and not raises_are_safe:
            return "handled" if terminal_returns_are_safe else "unsafe"
        if exit_kinds == {"raise"}:
            return "handled"
    return "continues"


def _binding_statement_handling_state(
    node: ast.Call,
    containing_statement: ast.stmt | None,
    name: str,
    checker: ResultChecker,
    aliases: dict[str, str],
) -> ResultHandlingState | None:
    current: ast.AST = node
    parent = _parent_node(current)
    while isinstance(parent, ast.Await):
        current = parent
        parent = _parent_node(current)
    if containing_statement is None:
        return None
    if isinstance(parent, ast.NamedExpr) and parent.value is current:
        return _block_result_handling_state(
            (containing_statement,),
            name,
            checker,
            aliases,
        )
    if not isinstance(containing_statement, (ast.With, ast.AsyncWith)):
        return None
    name_bindings = [
        item
        for item in containing_statement.items
        if item.optional_vars is not None
        and name in _bound_target_names(item.optional_vars)
    ]
    if len(name_bindings) != 1 or name_bindings[0].context_expr is not current:
        return None
    return _block_result_handling_state(
        containing_statement.body,
        name,
        checker,
        aliases,
    )


def _all_result_paths_are_handled(
    cursor: ast.AST,
    name: str,
    checker: ResultChecker,
    flow_index: _OperationalFlowIndex,
    observation_assignment: ObservationAssignment | None,
    visited: frozenset[int],
) -> bool:
    outcomes = flow_index.next_statements_mentioning(cursor, name)
    if not outcomes:
        return False
    for statement, terminates_safely in outcomes:
        if terminates_safely:
            continue
        if statement is None:
            return False
        statement_aliases = flow_index.aliases_for(statement)
        if _statement_delegates_result(statement, name) or checker(
            statement,
            name,
            statement_aliases,
            True,
        ):
            continue
        if observation_assignment is not None:
            observation = observation_assignment(
                statement,
                name,
                statement_aliases,
            )
            if observation is not None and _observation_is_handled_after(
                statement,
                observation,
                flow_index,
                result_name=name,
                checker=checker,
            ):
                continue
        if (
            id(statement) in visited
            or _block_result_handling_state(
                (statement,),
                name,
                checker,
                statement_aliases,
            )
            != "continues"
            or not _all_result_paths_are_handled(
                statement,
                name,
                checker,
                flow_index,
                observation_assignment,
                visited | {id(statement)},
            )
        ):
            return False
    return True


def _result_is_handled_after_assignment(
    node: ast.Call,
    name: str,
    checker: ResultChecker,
    flow_index: _OperationalFlowIndex,
    observation_assignment: ObservationAssignment | None = None,
) -> bool:
    containing_statement = _containing_statement(node)
    containing_aliases = (
        flow_index.aliases_for(containing_statement)
        if containing_statement is not None
        else flow_index.aliases
    )
    if _call_result_is_used_after_binding(node):
        return False
    if containing_statement is not None and (
        _statement_delegates_result(containing_statement, name)
        or checker(containing_statement, name, containing_aliases, True)
    ):
        return True
    initial_state = _binding_statement_handling_state(
        node,
        containing_statement,
        name,
        checker,
        containing_aliases,
    )
    if initial_state is not None and initial_state != "continues":
        return initial_state == "handled"
    return _all_result_paths_are_handled(
        node,
        name,
        checker,
        flow_index,
        observation_assignment,
        frozenset(),
    )


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _subprocess_checks_failure(
    node: ast.Call,
    aliases: dict[str, str],
) -> bool:
    check = _keyword_value(node, "check")
    return bool(
        isinstance(check, ast.Constant)
        and check.value is True
        and _validation_errors_escape_enclosing_suppressors(
            node,
            aliases,
            exception_names=SUBPROCESS_CHECK_EXCEPTION_NAMES,
            builtin_catchers=SUBPROCESS_CHECK_BUILTIN_CATCHERS,
        )
    )


def _inline_result_attribute(node: ast.Call) -> ast.Attribute | None:
    current: ast.AST = node
    parent = _parent_node(current)
    while isinstance(parent, ast.NamedExpr) and parent.value is current:
        current = parent
        parent = _parent_node(current)
    if isinstance(parent, ast.Attribute) and parent.value is current:
        return parent
    return None


def _call_result_is_used_after_binding(node: ast.Call) -> bool:
    parent = _parent_node(node)
    if not isinstance(parent, ast.NamedExpr) or parent.value is not node:
        return False
    current: ast.AST = parent
    parent = _parent_node(current)
    if isinstance(parent, ast.Attribute):
        return parent.value is current
    if isinstance(parent, ast.Subscript):
        return parent.value is current
    if isinstance(parent, ast.Call):
        return bool(
            parent.func is current
            or current in parent.args
            or any(keyword.value is current for keyword in parent.keywords)
        )
    return False


def _inline_subprocess_predicate_success_polarity(
    node: ast.AST,
    attribute: ast.Attribute,
) -> bool | None:
    def atomic_polarity(candidate: ast.AST) -> bool | None:
        if candidate is attribute:
            return False
        if not (
            isinstance(candidate, ast.Compare)
            and len(candidate.ops) == 1
            and len(candidate.comparators) == 1
        ):
            return None
        left = candidate.left
        right = candidate.comparators[0]
        left_is_returncode = left is attribute
        right_is_returncode = right is attribute
        if left_is_returncode == right_is_returncode:
            return None
        other = right if left_is_returncode else left
        if not (
            (isinstance(other, ast.Constant) and type(other.value) is int)
            or isinstance(other, (ast.Name, ast.Attribute))
        ):
            return None
        operator = candidate.ops[0]
        if isinstance(operator, ast.Eq):
            return True
        if isinstance(operator, ast.NotEq):
            return False
        return None

    return _boolean_success_polarity(node, atomic_polarity)


def _subprocess_checked_inline(
    node: ast.Call,
    aliases: dict[str, str],
) -> bool:
    attribute = _inline_result_attribute(node)
    if attribute is None:
        return False
    parent = _parent_node(attribute)
    if attribute.attr == "check_returncode":
        result_name = _call_result_name(node)
        return bool(
            isinstance(parent, ast.Call)
            and parent.func is attribute
            and _validation_errors_escape_enclosing_suppressors(
                parent,
                aliases,
                exception_names=SUBPROCESS_CHECK_EXCEPTION_NAMES,
                builtin_catchers=SUBPROCESS_CHECK_BUILTIN_CATCHERS,
                result_name=result_name,
                checker=(
                    _subprocess_statement_checks_result
                    if result_name is not None
                    else None
                ),
            )
        )
    if attribute.attr != "returncode":
        return False

    statement = _containing_statement(attribute)
    if statement is None:
        return False
    if isinstance(statement, ast.Match) and statement.subject is attribute:
        return _match_guarantees_observation_success(
            statement,
            ResultObservation("", "returncode"),
            aliases,
        )
    if isinstance(statement, ast.If) and _contains_node(statement.test, attribute):
        polarity = _inline_subprocess_predicate_success_polarity(
            statement.test,
            attribute,
        )
        if polarity is None:
            return False
        result_name = _call_result_name(node)
        return _failure_branch_handles_result(
            _failure_path_statements(statement, polarity, aliases),
            result_name=result_name,
            checker=(
                _subprocess_statement_checks_result if result_name is not None else None
            ),
            aliases=aliases,
        )
    if isinstance(statement, ast.Assert):
        return (
            _inline_subprocess_predicate_success_polarity(
                statement.test,
                attribute,
            )
            is True
        )
    delegated = _delegated_expression(statement)
    return bool(
        delegated is not None
        and (
            delegated is attribute
            or _inline_subprocess_predicate_success_polarity(
                delegated,
                attribute,
            )
            is not None
        )
    )


def _inline_http_predicate_success_polarity(
    node: ast.AST,
    attribute: ast.Attribute,
    aliases: dict[str, str],
) -> bool | None:
    def is_boolean_attribute(candidate: ast.AST) -> bool:
        return candidate is attribute and attribute.attr in {"is_success", "ok"}

    def is_status_attribute(candidate: ast.AST) -> bool:
        return candidate is attribute and attribute.attr == "status_code"

    return _boolean_success_polarity(
        node,
        lambda candidate: _http_atomic_success_polarity(
            candidate,
            is_boolean_attribute,
            is_status_attribute,
            aliases,
        ),
    )


def _http_checked_inline(
    node: ast.Call,
    aliases: dict[str, str],
    *,
    exception_names: frozenset[str],
    builtin_catchers: frozenset[type[BaseException]],
    checker: ResultChecker,
) -> bool:
    attribute = _inline_result_attribute(node)
    if attribute is None:
        return False
    if attribute.attr == "raise_for_status":
        parent = _parent_node(attribute)
        result_name = _call_result_name(node)
        return bool(
            isinstance(parent, ast.Call)
            and parent.func is attribute
            and _validation_errors_escape_enclosing_suppressors(
                parent,
                aliases,
                exception_names=exception_names,
                builtin_catchers=builtin_catchers,
                result_name=result_name,
                checker=checker if result_name is not None else None,
            )
        )
    if attribute.attr not in HTTP_STATUS_ATTRIBUTES:
        return False

    statement = _containing_statement(attribute)
    if statement is None:
        return False
    if isinstance(statement, ast.Match) and statement.subject is attribute:
        observation = ResultObservation(
            "",
            "boolean" if attribute.attr in {"is_success", "ok"} else "http-status",
            True if attribute.attr in {"is_success", "ok"} else None,
        )
        return _match_guarantees_observation_success(
            statement,
            observation,
            aliases,
        )
    if isinstance(statement, ast.If) and _contains_node(statement.test, attribute):
        polarity = _inline_http_predicate_success_polarity(
            statement.test,
            attribute,
            aliases,
        )
        if polarity is None:
            return False
        result_name = _call_result_name(node)
        return _failure_branch_handles_result(
            _failure_path_statements(statement, polarity, aliases),
            result_name=result_name,
            checker=checker if result_name is not None else None,
            aliases=aliases,
        )
    if isinstance(statement, ast.Assert):
        return (
            _inline_http_predicate_success_polarity(
                statement.test,
                attribute,
                aliases,
            )
            is True
        )
    delegated = _delegated_expression(statement)
    return bool(
        delegated is not None
        and (
            delegated is attribute
            or _inline_http_predicate_success_polarity(
                delegated,
                attribute,
                aliases,
            )
            is not None
        )
    )


def _subprocess_inline_observation(node: ast.Call) -> ResultObservation | None:
    attribute = _parent_node(node)
    if (
        not isinstance(attribute, ast.Attribute)
        or attribute.value is not node
        or attribute.attr != "returncode"
    ):
        return None
    statement = _containing_statement(attribute)
    if statement is None:
        return None
    assignment = _single_assignment(statement)
    if assignment is None:
        return None
    observed_name, expression = assignment
    if expression is attribute:
        return ResultObservation(observed_name, "returncode")
    polarity = _inline_subprocess_predicate_success_polarity(
        expression,
        attribute,
    )
    if polarity is not None:
        return ResultObservation(observed_name, "boolean", polarity)
    return None


def _contains_node(root: ast.AST, target: ast.AST) -> bool:
    return any(candidate is target for candidate in ast.walk(root))


def _http_inline_observation(
    node: ast.Call,
    aliases: dict[str, str],
) -> ResultObservation | None:
    attribute = _parent_node(node)
    if (
        not isinstance(attribute, ast.Attribute)
        or attribute.value is not node
        or attribute.attr not in HTTP_STATUS_ATTRIBUTES
    ):
        return None
    statement = _containing_statement(attribute)
    if statement is None:
        return None
    assignment = _single_assignment(statement)
    if assignment is None:
        return None
    observed_name, expression = assignment
    if attribute.attr in {"is_success", "ok"}:
        polarity = _http_boolean_predicate_polarity(
            expression,
            lambda candidate: candidate is attribute,
            lambda candidate: _contains_node(candidate, attribute),
        )
        if polarity is not None:
            return ResultObservation(observed_name, "boolean", polarity)
    if attribute.attr == "status_code" and isinstance(expression, ast.Compare):
        polarity = _comparison_http_status_success_polarity(
            expression,
            lambda candidate: _contains_node(candidate, attribute),
            aliases,
        )
        if polarity is not None:
            return ResultObservation(observed_name, "boolean", polarity)
    if expression is attribute and attribute.attr == "status_code":
        return ResultObservation(observed_name, "http-status")
    return None


def _http_result_is_handled(
    call: OperationalCall,
    flow_index: _OperationalFlowIndex,
) -> bool:
    node = call.node
    exception_names, builtin_catchers = _http_validation_exception_profile(
        call.qualified_name
    )
    checker = _http_result_checker(call.qualified_name)
    if _http_checked_inline(
        node,
        flow_index.aliases,
        exception_names=exception_names,
        builtin_catchers=builtin_catchers,
        checker=checker,
    ) or _call_is_returned(node):
        return True
    inline_observation = _http_inline_observation(node, flow_index.aliases)
    if inline_observation is not None and _observation_is_handled_after(
        node,
        inline_observation,
        flow_index,
    ):
        return True
    result_name = _call_result_name(node)
    return bool(
        result_name is not None
        and _result_is_handled_after_assignment(
            node,
            result_name,
            checker,
            flow_index,
            _http_observation_assignment,
        )
    )


def _call_has_timeout(node: ast.Call, qualified_name: str) -> bool:
    timeout = _keyword_value(node, "timeout")
    if timeout is not None:
        return not (isinstance(timeout, ast.Constant) and timeout.value is None)
    if qualified_name == "urllib.request.urlopen" and len(node.args) >= 3:
        positional_timeout = node.args[2]
        return not (
            isinstance(positional_timeout, ast.Constant)
            and positional_timeout.value is None
        )
    return False


def _blocking_call_guidance(qualified_name: str) -> str:
    if qualified_name == "time.sleep":
        return "use `await asyncio.sleep(...)`"
    if qualified_name == "os.system":
        return "use `asyncio.create_subprocess_shell(...)`"
    if qualified_name == "socket.getaddrinfo":
        return "use the event loop resolver or `asyncio.to_thread(...)`"
    if qualified_name == "urllib.request.urlopen":
        return "use an async HTTP client or `asyncio.to_thread(...)`"

    module, separator, function = qualified_name.rpartition(".")
    if not separator:
        return ""
    if module in {"requests", "httpx"} and function in BLOCKING_HTTP_METHODS:
        return "use an async HTTP client or `asyncio.to_thread(...)`"
    if module == "subprocess" and function in BLOCKING_SUBPROCESS_CALLS:
        return "use `asyncio.create_subprocess_exec(...)` or its shell variant"
    return ""


def _find_blocking_calls(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    body: Sequence[ast.stmt],
    aliases: dict[str, str],
    alias_snapshots: dict[int, dict[str, str]],
) -> list[BlockingCall]:
    local_names = _collect_local_bindings(node, body) | set(
        _collect_import_aliases(body)
    )
    visitor = _BlockingCallVisitor(
        aliases,
        alias_snapshots,
        local_names,
    )
    for statement in body:
        visitor.visit(statement)
    return visitor.calls


def _first_positional_parameter(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    positional = (*node.args.posonlyargs, *node.args.args)
    return positional[0].arg if positional else None


def _decorator_expression(node: ast.expr) -> ast.expr:
    return node.func if isinstance(node, ast.Call) else node


def _has_decorator(
    node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
    aliases: dict[str, str],
) -> bool:
    for decorator in node.decorator_list:
        raw_name = _expression_name(_decorator_expression(decorator))
        qualified_name = _resolve_imported_name(raw_name, aliases)
        if raw_name.split(".")[-1] == name or qualified_name == f"typing.{name}":
            return True
    return False


def _is_instance_method(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
) -> bool:
    return bool(
        _first_positional_parameter(node)
        and not _has_decorator(node, "staticmethod", aliases)
        and not _has_decorator(node, "classmethod", aliases)
    )


def _assigned_instance_attributes(target: ast.AST, instance: str) -> set[str]:
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == instance
    ):
        return {target.attr}
    if isinstance(target, ast.Starred):
        return _assigned_instance_attributes(target.value, instance)
    if isinstance(target, (ast.List, ast.Tuple)):
        assigned: set[str] = set()
        for element in target.elts:
            assigned.update(_assigned_instance_attributes(element, instance))
        return assigned
    return set()


def _eager_comprehension_assignments(
    node: ast.AST | None,
    instance: str,
    aliases: dict[str, str],
) -> set[str]:
    if not isinstance(node, (ast.DictComp, ast.ListComp, ast.SetComp)):
        return set()
    assigned: set[str] = set()
    reaches_generator = True
    for generator in node.generators:
        if not reaches_generator:
            break
        if _literal_iterable_is_empty(generator.iter, aliases) is not False:
            break
        assigned.update(_assigned_instance_attributes(generator.target, instance))
        reaches_generator = all(
            _constant_truth_value(condition) is True for condition in generator.ifs
        )
    return assigned


def _merge_attribute_states(
    *states: frozenset[str] | None,
) -> frozenset[str] | None:
    reachable = [state for state in states if state is not None]
    if not reachable:
        return None
    merged = set(reachable[0])
    for state in reachable[1:]:
        merged.intersection_update(state)
    return frozenset(merged)


def _root_instance_attribute(node: ast.AST, instance: str) -> str | None:
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        if (
            isinstance(current, ast.Attribute)
            and isinstance(current.value, ast.Name)
            and current.value.id == instance
        ):
            return current.attr
        current = current.value
    return None


def _is_hasattr_check(
    node: ast.AST,
    instance: str,
    attribute: str,
    aliases: dict[str, str],
) -> bool:
    raw_name = _expression_name(node.func) if isinstance(node, ast.Call) else ""
    resolved_name = _resolve_imported_name(raw_name, aliases)
    return bool(
        isinstance(node, ast.Call)
        and (
            resolved_name == "builtins.hasattr"
            or (
                raw_name == "hasattr"
                and not resolved_name
                and not _name_shadows_builtin(node.func, "hasattr")
            )
        )
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == instance
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == attribute
    )


def _condition_guarantees_attribute(
    node: ast.AST,
    *,
    instance: str,
    attribute: str,
    truth: bool,
    aliases: dict[str, str],
) -> bool:
    if _is_hasattr_check(node, instance, attribute, aliases):
        return truth
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_guarantees_attribute(
            node.operand,
            instance=instance,
            attribute=attribute,
            truth=not truth,
            aliases=aliases,
        )
    if isinstance(node, ast.BoolOp):
        values_have_fixed_truth = truth if isinstance(node.op, ast.And) else not truth
        if values_have_fixed_truth:
            return any(
                _condition_guarantees_attribute(
                    value,
                    instance=instance,
                    attribute=attribute,
                    truth=truth,
                    aliases=aliases,
                )
                for value in node.values
            )
    return False


def _handler_catches_attribute_error(
    node: ast.ExceptHandler,
    aliases: dict[str, str],
) -> bool:
    return AttributeError in _builtin_exception_types(
        node.type,
        aliases,
    )


def _attribute_read_is_guarded(
    node: ast.Attribute,
    *,
    instance: str,
    attribute: str,
    aliases: dict[str, str],
    trust_hasattr: bool,
    trust_attribute_error: bool,
) -> bool:
    current: ast.AST = node
    parent = _parent_node(current)
    while parent is not None:
        if trust_hasattr and isinstance(parent, (ast.If, ast.While)):
            if current in parent.body and _condition_guarantees_attribute(
                parent.test,
                instance=instance,
                attribute=attribute,
                truth=True,
                aliases=aliases,
            ):
                return True
            if (
                isinstance(parent, ast.If)
                and current in parent.orelse
                and _condition_guarantees_attribute(
                    parent.test,
                    instance=instance,
                    attribute=attribute,
                    truth=False,
                    aliases=aliases,
                )
            ):
                return True
        if trust_hasattr and isinstance(parent, ast.IfExp):
            if current is parent.body and _condition_guarantees_attribute(
                parent.test,
                instance=instance,
                attribute=attribute,
                truth=True,
                aliases=aliases,
            ):
                return True
            if current is parent.orelse and _condition_guarantees_attribute(
                parent.test,
                instance=instance,
                attribute=attribute,
                truth=False,
                aliases=aliases,
            ):
                return True
        if (
            trust_attribute_error
            and isinstance(parent, (ast.Try, ast.TryStar))
            and current in parent.body
            and any(
                _handler_catches_attribute_error(item, aliases)
                for item in parent.handlers
            )
        ):
            return True
        current = parent
        parent = _parent_node(current)
    return False


class _InstanceAssignmentCollector(ast.NodeVisitor):
    def __init__(self, instance: str) -> None:
        self.instance = instance
        self.nodes: dict[str, ast.AST] = {}

    def _record(self, target: ast.AST, node: ast.AST) -> None:
        for name in _assigned_instance_attributes(target, self.instance):
            self.nodes.setdefault(name, node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._record(target, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record(node.target, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._record(node.target, node)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._record(node.target, node)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._record(node.target, node)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._record(item.optional_vars, node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._record(item.optional_vars, node)
        self.generic_visit(node)

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
    ) -> None:
        for generator in node.generators:
            self._record(generator.target, node)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class _ConstructorDispatchVisitor(ast.NodeVisitor):
    def __init__(self, instance: str, methods: set[str]) -> None:
        self.instance = instance
        self.methods = methods
        self.calls: list[tuple[ast.Call, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        function = node.func
        if (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id == self.instance
            and function.attr in self.methods
        ):
            self.calls.append((node, function.attr))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class _AttributeExpressionVisitor(ast.NodeVisitor):
    def __init__(
        self,
        *,
        instance: str,
        assigned: frozenset[str],
        read_candidates: set[str],
        shared_mutables: set[str],
        first_reads: dict[str, ast.Attribute],
        mutations: list[tuple[ast.AST, str]],
        aliases: dict[str, str],
        trust_hasattr: bool,
        trust_attribute_error: bool,
    ) -> None:
        self.instance = instance
        self.assigned = assigned
        self.read_candidates = read_candidates
        self.shared_mutables = shared_mutables
        self.first_reads = first_reads
        self.mutations = mutations
        self.aliases = aliases
        self.trust_hasattr = trust_hasattr
        self.trust_attribute_error = trust_attribute_error

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Name)
            and node.value.id == self.instance
            and node.attr in self.read_candidates
            and node.attr not in self.assigned
            and not _attribute_read_is_guarded(
                node,
                instance=self.instance,
                attribute=node.attr,
                aliases=self.aliases,
                trust_hasattr=self.trust_hasattr,
                trust_attribute_error=self.trust_attribute_error,
            )
        ):
            self.first_reads.setdefault(node.attr, node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            root = _root_instance_attribute(node.func.value, self.instance)
            if (
                root in self.shared_mutables
                and root not in self.assigned
                and node.func.attr in MUTATING_CONTAINER_METHODS
            ):
                self.mutations.append((node, root))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class _AttributeFlowAnalyzer:
    def __init__(
        self,
        *,
        instance: str,
        aliases: dict[str, str] | None = None,
        read_candidates: set[str] | None = None,
        shared_mutables: set[str] | None = None,
        trust_hasattr: bool = False,
        trust_attribute_error: bool = False,
        non_none_returns_fail: bool = False,
    ) -> None:
        self.instance = instance
        self.aliases = aliases or {}
        self.read_candidates = read_candidates or set()
        self.shared_mutables = shared_mutables or set()
        self.trust_hasattr = trust_hasattr
        self.trust_attribute_error = trust_attribute_error
        self.non_none_returns_fail = non_none_returns_fail
        self.first_reads: dict[str, ast.Attribute] = {}
        self.mutations: list[tuple[ast.AST, str]] = []

    @staticmethod
    def _with_additional_raises(
        flow: AttributeFlow,
        raises: frozenset[str] | None,
    ) -> AttributeFlow:
        if raises is None:
            return flow
        return AttributeFlow(
            flow.fallthrough,
            flow.returns,
            flow.breaks,
            flow.continues,
            _merge_attribute_states(flow.raises, raises),
        )

    def analyze(
        self,
        body: Sequence[ast.stmt],
        assigned: frozenset[str] = frozenset(),
    ) -> AttributeFlow:
        current: frozenset[str] | None = assigned
        returns: frozenset[str] | None = None
        breaks: frozenset[str] | None = None
        continues: frozenset[str] | None = None
        raises: frozenset[str] | None = None
        for statement in body:
            if current is None:
                break
            incoming = current
            flow = self._statement(statement, incoming)
            if not isinstance(
                statement,
                (
                    ast.AsyncFor,
                    ast.AsyncWith,
                    ast.For,
                    ast.If,
                    ast.Match,
                    ast.Raise,
                    ast.Try,
                    ast.TryStar,
                    ast.While,
                    ast.With,
                ),
            ) and _statement_may_raise_implicitly(statement):
                flow = AttributeFlow(
                    flow.fallthrough,
                    flow.returns,
                    flow.breaks,
                    flow.continues,
                    _merge_attribute_states(flow.raises, incoming),
                )
            returns = _merge_attribute_states(returns, flow.returns)
            breaks = _merge_attribute_states(breaks, flow.breaks)
            continues = _merge_attribute_states(continues, flow.continues)
            raises = _merge_attribute_states(raises, flow.raises)
            current = flow.fallthrough
        return AttributeFlow(current, returns, breaks, continues, raises)

    def _inspect(self, node: ast.AST | None, assigned: frozenset[str]) -> None:
        if node is None:
            return
        visitor = _AttributeExpressionVisitor(
            instance=self.instance,
            assigned=assigned,
            read_candidates=self.read_candidates,
            shared_mutables=self.shared_mutables,
            first_reads=self.first_reads,
            mutations=self.mutations,
            aliases=self.aliases,
            trust_hasattr=self.trust_hasattr,
            trust_attribute_error=self.trust_attribute_error,
        )
        visitor.visit(node)

    def _record_direct_read(
        self,
        target: ast.AST,
        assigned: frozenset[str],
    ) -> None:
        if not isinstance(target, ast.Attribute):
            return
        names = _assigned_instance_attributes(target, self.instance)
        for name in names & self.read_candidates - set(assigned):
            self.first_reads.setdefault(name, target)

    def _record_target_mutation(
        self,
        target: ast.AST,
        assigned: frozenset[str],
        node: ast.AST,
    ) -> None:
        if isinstance(target, ast.Starred):
            self._record_target_mutation(target.value, assigned, node)
            return
        if isinstance(target, (ast.List, ast.Tuple)):
            for element in target.elts:
                self._record_target_mutation(element, assigned, node)
            return
        if not isinstance(target, ast.Subscript):
            return
        root = _root_instance_attribute(target, self.instance)
        if root in self.shared_mutables and root not in assigned:
            self.mutations.append((node, root))

    def _assignment_flow(
        self,
        node: ast.Assign,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        self._inspect(node.value, assigned)
        current = assigned | frozenset(
            _eager_comprehension_assignments(
                node.value,
                self.instance,
                self.aliases,
            )
        )
        for target in node.targets:
            self._inspect(target, current)
            self._record_target_mutation(target, current, node)
            current |= _assigned_instance_attributes(target, self.instance)
        return AttributeFlow(current, None)

    def _annotated_assignment_flow(
        self,
        node: ast.AnnAssign,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        self._inspect(node.value, assigned)
        self._inspect(node.target, assigned)
        if node.value is None:
            return AttributeFlow(assigned, None)
        self._record_target_mutation(node.target, assigned, node)
        updated = (
            assigned
            | frozenset(
                _eager_comprehension_assignments(
                    node.value,
                    self.instance,
                    self.aliases,
                )
            )
            | _assigned_instance_attributes(node.target, self.instance)
        )
        return AttributeFlow(updated, None)

    def _augmented_assignment_flow(
        self,
        node: ast.AugAssign,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        self._record_direct_read(node.target, assigned)
        self._inspect(node.target, assigned)
        self._inspect(node.value, assigned)
        root = _root_instance_attribute(node.target, self.instance)
        if root in self.shared_mutables and root not in assigned:
            self.mutations.append((node, root))
        updated = (
            assigned
            | frozenset(
                _eager_comprehension_assignments(
                    node.value,
                    self.instance,
                    self.aliases,
                )
            )
            | _assigned_instance_attributes(node.target, self.instance)
        )
        return AttributeFlow(updated, None)

    def _delete_flow(
        self,
        node: ast.Delete,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        updated = set(assigned)
        for target in node.targets:
            self._record_direct_read(target, assigned)
            self._inspect(target, assigned)
            self._record_target_mutation(target, assigned, node)
            updated.difference_update(
                _assigned_instance_attributes(target, self.instance)
            )
        return AttributeFlow(frozenset(updated), None)

    def _if_flow(
        self,
        node: ast.If,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        self._inspect(node.test, assigned)
        header_raises = assigned if _node_may_raise_implicitly(node.test) else None
        truth = _constant_truth_value(node.test)
        if truth is True:
            return self._with_additional_raises(
                self.analyze(node.body, assigned),
                header_raises,
            )
        if truth is False:
            return self._with_additional_raises(
                self.analyze(node.orelse, assigned),
                header_raises,
            )
        body_known = frozenset(
            name
            for name in self.read_candidates
            if self.trust_hasattr
            and _condition_guarantees_attribute(
                node.test,
                instance=self.instance,
                attribute=name,
                truth=True,
                aliases=self.aliases,
            )
        )
        alternative_known = frozenset(
            name
            for name in self.read_candidates
            if self.trust_hasattr
            and _condition_guarantees_attribute(
                node.test,
                instance=self.instance,
                attribute=name,
                truth=False,
                aliases=self.aliases,
            )
        )
        body = self.analyze(node.body, assigned | body_known)
        alternative = self.analyze(node.orelse, assigned | alternative_known)
        return self._with_additional_raises(
            AttributeFlow(
                _merge_attribute_states(body.fallthrough, alternative.fallthrough),
                _merge_attribute_states(body.returns, alternative.returns),
                _merge_attribute_states(body.breaks, alternative.breaks),
                _merge_attribute_states(body.continues, alternative.continues),
                _merge_attribute_states(body.raises, alternative.raises),
            ),
            header_raises,
        )

    def _match_flow(
        self,
        node: ast.Match,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        self._inspect(node.subject, assigned)
        header_raises = assigned if _node_may_raise_implicitly(node.subject) else None
        flows: list[AttributeFlow] = []
        exhaustive = False
        for case in node.cases:
            self._inspect(case.guard, assigned)
            if _node_may_raise_implicitly(case.guard):
                header_raises = _merge_attribute_states(
                    header_raises,
                    assigned,
                )
            if case.guard is not None and _constant_truth_value(case.guard) is False:
                continue
            flows.append(self.analyze(case.body, assigned))
            if _match_case_is_irrefutable(case):
                exhaustive = True
                break
        if not exhaustive:
            flows.append(AttributeFlow(assigned, None))
        return self._with_additional_raises(
            AttributeFlow(
                _merge_attribute_states(*(flow.fallthrough for flow in flows)),
                _merge_attribute_states(*(flow.returns for flow in flows)),
                _merge_attribute_states(*(flow.breaks for flow in flows)),
                _merge_attribute_states(*(flow.continues for flow in flows)),
                _merge_attribute_states(*(flow.raises for flow in flows)),
            ),
            header_raises,
        )

    def _with_flow(
        self,
        node: ast.With | ast.AsyncWith,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        current = assigned
        header_raises: frozenset[str] | None = None
        suppressed_header_fallthrough: frozenset[str] | None = None
        entered_items: list[ast.withitem] = []
        for item in node.items:
            self._inspect(item.context_expr, current)
            header_raises = _merge_attribute_states(
                header_raises,
                current,
            )
            if _context_items_may_suppress(entered_items, self.aliases):
                suppressed_header_fallthrough = _merge_attribute_states(
                    suppressed_header_fallthrough,
                    current,
                )
            if item.optional_vars is not None:
                self._inspect(item.optional_vars, current)
                current |= _assigned_instance_attributes(
                    item.optional_vars,
                    self.instance,
                )
            entered_items.append(item)
        flow = self.analyze(node.body, current)
        flow = AttributeFlow(
            _merge_attribute_states(
                flow.fallthrough,
                suppressed_header_fallthrough,
            ),
            flow.returns,
            flow.breaks,
            flow.continues,
            flow.raises,
        )
        if flow.raises is None or not _context_manager_may_suppress(
            node,
            self.aliases,
        ):
            return self._with_additional_raises(flow, header_raises)
        explicit_raise = _sole_explicit_raise(node.body, self.aliases)
        suppression = (
            _context_manager_suppresses_raise(
                node,
                explicit_raise,
                self.aliases,
            )
            if explicit_raise is not None
            else None
        )
        if suppression is False:
            return self._with_additional_raises(flow, header_raises)
        explicit_raises_escape = _block_explicit_raises_escape(
            node.body,
            self.aliases,
        )
        if explicit_raises_escape is True and not any(
            _statement_may_raise_implicitly(statement) for statement in node.body
        ):
            return self._with_additional_raises(flow, header_raises)
        fallthrough = _merge_attribute_states(flow.fallthrough, flow.raises)
        raises: frozenset[str] | None = flow.raises
        if suppression is True or (
            explicit_raise is None
            and _context_manager_suppresses_all_raises(node, self.aliases)
        ):
            raises = None
        return self._with_additional_raises(
            AttributeFlow(
                fallthrough,
                flow.returns,
                flow.breaks,
                flow.continues,
                raises,
            ),
            header_raises,
        )

    def _loop_flow(
        self,
        node: ast.For | ast.AsyncFor | ast.While,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        body_state = assigned
        header_expression = (
            node.iter if isinstance(node, (ast.For, ast.AsyncFor)) else node.test
        )
        header_raises = (
            assigned if _node_may_raise_implicitly(header_expression) else None
        )
        target_attributes = frozenset[str]()
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self._inspect(node.iter, assigned)
            self._inspect(node.target, assigned)
            self._record_target_mutation(node.target, assigned, node)
            target_attributes = frozenset(
                _assigned_instance_attributes(node.target, self.instance)
            )
            body_state |= target_attributes
        else:
            if _constant_truth_value(node.test) is False:
                self._inspect(node.test, assigned)
                return self._with_additional_raises(
                    self.analyze(node.orelse, assigned),
                    header_raises,
                )

        entry_state = body_state
        while True:
            if isinstance(node, ast.While):
                self._inspect(node.test, entry_state)
            body = self.analyze(node.body, entry_state)
            carried = _merge_attribute_states(
                body.fallthrough,
                body.continues,
            )
            if carried is None:
                break
            next_entry = _merge_attribute_states(
                body_state,
                carried | target_attributes,
            )
            if next_entry == entry_state:
                break
            entry_state = next_entry or frozenset()

        body_can_run, body_may_be_skipped, can_exhaust_normally = (
            _loop_definition_reachability(node, self.aliases)
        )
        normal_states: list[frozenset[str] | None] = []
        if body_may_be_skipped:
            normal_states.append(assigned)
        if body_can_run and can_exhaust_normally:
            normal_states.extend((body.fallthrough, body.continues))
        normal_exit = _merge_attribute_states(*normal_states)
        alternative = (
            self.analyze(node.orelse, normal_exit)
            if normal_exit is not None
            else AttributeFlow(None, None)
        )
        return self._with_additional_raises(
            AttributeFlow(
                _merge_attribute_states(alternative.fallthrough, body.breaks),
                _merge_attribute_states(body.returns, alternative.returns),
                alternative.breaks,
                alternative.continues,
                _merge_attribute_states(body.raises, alternative.raises),
            ),
            header_raises,
        )

    def _apply_finally(
        self,
        body: Sequence[ast.stmt],
        incoming: AttributeFlow,
    ) -> AttributeFlow:
        fallthrough: frozenset[str] | None = None
        returns: frozenset[str] | None = None
        breaks: frozenset[str] | None = None
        continues: frozenset[str] | None = None
        raises: frozenset[str] | None = None
        incoming_states = (
            ("fallthrough", incoming.fallthrough),
            ("returns", incoming.returns),
            ("breaks", incoming.breaks),
            ("continues", incoming.continues),
            ("raises", incoming.raises),
        )
        for exit_kind, state in incoming_states:
            if state is None:
                continue
            final = self.analyze(body, state)
            if final.fallthrough is not None:
                if exit_kind == "fallthrough":
                    fallthrough = _merge_attribute_states(
                        fallthrough,
                        final.fallthrough,
                    )
                elif exit_kind == "returns":
                    returns = _merge_attribute_states(returns, final.fallthrough)
                elif exit_kind == "breaks":
                    breaks = _merge_attribute_states(breaks, final.fallthrough)
                elif exit_kind == "continues":
                    continues = _merge_attribute_states(
                        continues,
                        final.fallthrough,
                    )
                else:
                    raises = _merge_attribute_states(raises, final.fallthrough)
            returns = _merge_attribute_states(returns, final.returns)
            breaks = _merge_attribute_states(breaks, final.breaks)
            continues = _merge_attribute_states(continues, final.continues)
            raises = _merge_attribute_states(raises, final.raises)
        return AttributeFlow(fallthrough, returns, breaks, continues, raises)

    def _explicit_raise_paths(
        self,
        body: Sequence[ast.stmt],
        states: Sequence[frozenset[str]],
    ) -> (
        tuple[
            list[tuple[ast.Raise, frozenset[str]]],
            list[frozenset[str]],
        ]
        | None
    ):
        current = list(states)
        raises: list[tuple[ast.Raise, frozenset[str]]] = []
        for statement in body:
            next_states: list[frozenset[str]] = []
            for state in current:
                if isinstance(statement, ast.Raise):
                    raises.append((statement, state))
                    continue
                if isinstance(statement, ast.If):
                    truth = _constant_truth_value(statement.test)
                    branches = (
                        (statement.body,)
                        if truth is True
                        else (statement.orelse,)
                        if truth is False
                        else (statement.body, statement.orelse)
                    )
                    for branch in branches:
                        result = self._explicit_raise_paths(branch, (state,))
                        if result is None:
                            return None
                        branch_raises, branch_fallthrough = result
                        raises.extend(branch_raises)
                        next_states.extend(branch_fallthrough)
                    continue
                if "raise" in _statement_exit_kinds(statement, self.aliases):
                    return None
                flow = self._statement(statement, state)
                if flow.fallthrough is not None:
                    next_states.append(flow.fallthrough)
            current = next_states
            if not current:
                break
        return raises, current

    def _typed_exception_handler_flows(
        self,
        node: ast.Try,
        assigned: frozenset[str],
    ) -> tuple[list[AttributeFlow], frozenset[str] | None] | None:
        if any(_statement_may_raise_implicitly(statement) for statement in node.body):
            return None
        state_analyzer = _AttributeFlowAnalyzer(
            instance=self.instance,
            aliases=self.aliases,
            non_none_returns_fail=self.non_none_returns_fail,
        )
        result = state_analyzer._explicit_raise_paths(node.body, (assigned,))
        if result is None:
            return None
        remaining, _ = result
        if not remaining:
            return None
        handlers: list[AttributeFlow] = []
        for handler in node.handlers:
            matched_states: list[frozenset[str]] = []
            unmatched: list[tuple[ast.Raise, frozenset[str]]] = []
            for statement, state in remaining:
                match = _exception_handler_match(
                    handler,
                    statement,
                    self.aliases,
                )
                if match is not False:
                    matched_states.append(state)
                if match is not True:
                    unmatched.append((statement, state))
            if matched_states:
                self._inspect(handler.type, assigned)
                handler_state = _merge_attribute_states(*matched_states)
                if handler_state is not None:
                    handlers.append(self.analyze(handler.body, handler_state))
            remaining = unmatched
            if not remaining:
                break
        uncaught = _merge_attribute_states(*(state for _, state in remaining))
        return handlers, uncaught

    def _try_flow(
        self,
        node: ast.Try | ast.TryStar,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        body = self.analyze(node.body, assigned)
        normal = (
            self.analyze(node.orelse, body.fallthrough)
            if body.fallthrough is not None
            else AttributeFlow(None, None)
        )
        typed_handlers = (
            self._typed_exception_handler_flows(node, assigned)
            if isinstance(node, ast.Try)
            else None
        )
        handlers: list[AttributeFlow] = []
        explicit_raise = (
            _sole_explicit_raise(node.body, self.aliases)
            if isinstance(node, ast.Try)
            else None
        )
        if typed_handlers is not None:
            handlers, uncaught_raises = typed_handlers
            definitely_caught = uncaught_raises is None
        else:
            reachable_handlers: Sequence[ast.ExceptHandler] = node.handlers
            definitely_caught = any(
                _handler_catches_all_raises(handler, self.aliases)
                for handler in node.handlers
            )
            if explicit_raise is not None:
                reachable_handlers, definitely_caught = _potential_handlers_for_raise(
                    node.handlers,
                    explicit_raise,
                    self.aliases,
                )
            handler_state = body.raises if body.raises is not None else assigned
            for handler in reachable_handlers:
                self._inspect(handler.type, assigned)
                handlers.append(self.analyze(handler.body, handler_state))
            uncaught_raises = body.raises

        fallthrough = _merge_attribute_states(
            normal.fallthrough,
            *(handler.fallthrough for handler in handlers),
        )
        returns = _merge_attribute_states(
            body.returns,
            normal.returns,
            *(handler.returns for handler in handlers),
        )
        breaks = _merge_attribute_states(
            body.breaks,
            normal.breaks,
            *(handler.breaks for handler in handlers),
        )
        continues = _merge_attribute_states(
            body.continues,
            normal.continues,
            *(handler.continues for handler in handlers),
        )
        raises = _merge_attribute_states(
            None if definitely_caught else uncaught_raises,
            normal.raises,
            *(handler.raises for handler in handlers),
        )
        combined = AttributeFlow(fallthrough, returns, breaks, continues, raises)
        if not node.finalbody:
            return combined
        return self._apply_finally(node.finalbody, combined)

    def _simple_statement_flow(
        self,
        node: ast.stmt,
        assigned: frozenset[str],
    ) -> AttributeFlow | None:
        if isinstance(node, ast.Assign):
            return self._assignment_flow(node, assigned)
        if isinstance(node, ast.AnnAssign):
            return self._annotated_assignment_flow(node, assigned)
        if isinstance(node, ast.AugAssign):
            return self._augmented_assignment_flow(node, assigned)
        if isinstance(node, ast.Delete):
            return self._delete_flow(node, assigned)
        if isinstance(node, ast.Expr):
            self._inspect(node.value, assigned)
            updated = assigned | frozenset(
                _eager_comprehension_assignments(
                    node.value,
                    self.instance,
                    self.aliases,
                )
            )
            return AttributeFlow(updated, None)
        if isinstance(node, ast.Return):
            self._inspect(node.value, assigned)
            updated = assigned | frozenset(
                _eager_comprehension_assignments(
                    node.value,
                    self.instance,
                    self.aliases,
                )
            )
            literal, value = (
                _literal_comparison_value(node.value)
                if node.value is not None
                else (True, None)
            )
            if self.non_none_returns_fail and literal and value is not None:
                return AttributeFlow(None, None, None, None, updated)
            return AttributeFlow(None, updated)
        if isinstance(node, ast.Raise):
            self._inspect(node.exc, assigned)
            self._inspect(node.cause, assigned)
            return AttributeFlow(None, None, None, None, assigned)
        if isinstance(node, ast.Break):
            return AttributeFlow(None, None, assigned)
        if isinstance(node, ast.Continue):
            return AttributeFlow(None, None, None, assigned)
        return None

    def _statement(
        self,
        node: ast.stmt,
        assigned: frozenset[str],
    ) -> AttributeFlow:
        simple = self._simple_statement_flow(node, assigned)
        if simple is not None:
            return simple
        if isinstance(node, ast.If):
            return self._if_flow(node, assigned)
        if isinstance(node, ast.Match):
            return self._match_flow(node, assigned)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            return self._with_flow(node, assigned)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self._loop_flow(node, assigned)
        if isinstance(node, (ast.Try, ast.TryStar)):
            return self._try_flow(node, assigned)
        self._inspect(node, assigned)
        return AttributeFlow(assigned, None)


class _ConstructorDispatchAnalyzer(_AttributeFlowAnalyzer):
    def __init__(self, *, instance: str, methods: set[str]) -> None:
        super().__init__(instance=instance)
        self.methods = methods
        self.calls: list[tuple[ast.Call, str, frozenset[str]]] = []

    def _inspect(self, node: ast.AST | None, assigned: frozenset[str]) -> None:
        if node is None:
            return
        visitor = _ConstructorDispatchVisitor(self.instance, self.methods)
        visitor.visit(node)
        for call, method_name in visitor.calls:
            self.calls.append((call, method_name, assigned))


def _bound_target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Starred):
        return _bound_target_names(target.value)
    if isinstance(target, (ast.List, ast.Tuple)):
        names: set[str] = set()
        for element in target.elts:
            names.update(_bound_target_names(element))
        return names
    return set()


def _class_statement_bindings(node: ast.stmt) -> set[str]:
    if isinstance(node, ast.Assign):
        return {name for target in node.targets for name in _bound_target_names(target)}
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return _bound_target_names(node.target)
    if isinstance(node, ast.AugAssign):
        return _bound_target_names(node.target)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name.split(".", 1)[0] for alias in node.names}
    if isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names}
    return set()


def _class_namespace_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for statement in node.body:
        names.update(_class_statement_bindings(statement))
        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                names.difference_update(_bound_target_names(target))
    return names


def _class_methods(
    node: ast.ClassDef,
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for statement in node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods[statement.name] = statement
            continue
        for name in _class_statement_bindings(statement):
            methods.pop(name, None)
        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                for name in _bound_target_names(target):
                    methods.pop(name, None)
    return methods


def _classvar_names(
    node: ast.ClassDef,
    aliases: dict[str, str],
) -> set[str]:
    names: set[str] = set()
    for statement in node.body:
        if not isinstance(statement, ast.AnnAssign):
            continue
        annotation = statement.annotation
        target = (
            annotation.value if isinstance(annotation, ast.Subscript) else annotation
        )
        raw_name = _expression_name(target)
        qualified_name = _resolve_imported_name(raw_name, aliases)
        if raw_name.split(".")[-1] == "ClassVar" or qualified_name == "typing.ClassVar":
            names.update(_assigned_names(statement.target))
    return names


def _class_attribute_values(node: ast.ClassDef) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}
    for statement in node.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                for name in _bound_target_names(target):
                    values[name] = statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            for name in _bound_target_names(statement.target):
                values[name] = statement.value
        elif isinstance(
            statement,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.Import,
                ast.ImportFrom,
            ),
        ):
            for name in _class_statement_bindings(statement):
                values.pop(name, None)
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                for name in _bound_target_names(target):
                    values.pop(name, None)
    return values


def _mutable_container_kind(
    node: ast.AST,
    shadowed_names: set[str] | frozenset[str] = frozenset(),
) -> str | None:
    if isinstance(node, (ast.List, ast.ListComp)):
        return "list"
    if isinstance(node, (ast.Dict, ast.DictComp)):
        return "dict"
    if isinstance(node, (ast.Set, ast.SetComp)):
        return "set"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"dict", "list", "set"}
        and node.func.id not in shadowed_names
    ):
        return node.func.id
    return None


def _analyze_constructor(
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    aliases: dict[str, str],
) -> tuple[
    ast.FunctionDef | ast.AsyncFunctionDef | None,
    str | None,
    dict[str, ast.AST],
    frozenset[str] | None,
]:
    constructor = methods.get("__init__")
    if constructor is None or not _is_instance_method(constructor, aliases):
        return constructor, None, {}, frozenset()
    instance = _first_positional_parameter(constructor)
    if instance is None:
        return constructor, None, {}, frozenset()

    collector = _InstanceAssignmentCollector(instance)
    for statement in constructor.body:
        collector.visit(statement)
    flow = _AttributeFlowAnalyzer(
        instance=instance,
        aliases=aliases,
        non_none_returns_fail=True,
    ).analyze(constructor.body)
    initialized = _merge_attribute_states(flow.fallthrough, flow.returns)
    return constructor, instance, collector.nodes, initialized


class SlopVisitor(ast.NodeVisitor):
    """Collect pyclichecker findings from a parsed module."""

    def __init__(
        self,
        *,
        path: str,
        comments: Sequence[Comment],
        config: LintConfig,
        module_body: Sequence[ast.stmt],
        module_aliases: dict[str, str],
        header_suppression_lines: dict[int, set[int]],
    ) -> None:
        self.path = path
        self.comments = comments
        self.config = config
        self.module_body = tuple(module_body)
        self.module_aliases = module_aliases
        self.header_suppression_lines = header_suppression_lines
        module_bindings = _collect_body_bindings(module_body)
        self.module_bindings = module_bindings
        self.shadowed_container_names = {
            name
            for name in {"dict", "list", "set"}
            if name in module_bindings
            or (name in module_aliases and module_aliases[name] != f"builtins.{name}")
        }
        self.findings: list[Finding] = []
        self.functions: list[FunctionRecord] = []
        self.scope: list[str] = []
        self.protocol_stack: list[bool] = []
        self.unittest_case_stack: list[bool] = []
        self.unittest_case_classes: set[str] = set()
        self.alias_stack: list[dict[str, str]] = [{}]
        self.node_aliases: dict[int, dict[str, str]] = {}
        self.definition_loop_exit_stack: list[_DefinitionLoopExitStates] = []
        self.capture_definition_loop_exits = True
        self.reported_placeholder_nodes: set[int] = set()
        self.comments_by_line: dict[int, list[str]] = {}
        for comment in comments:
            self.comments_by_line.setdefault(comment.line, []).append(comment.text)
        self.ignore_file = any(
            comment.line <= 5
            and SLOP_IGNORE_FILE_RE.fullmatch(comment.text.strip()) is not None
            for comment in comments
        )

    def add_finding(
        self,
        node: ast.AST,
        code: str,
        message: str,
        *,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        if code not in self.config.enabled_codes or self.ignore_file:
            return

        finding_line = line if line is not None else getattr(node, "lineno", 1)
        finding_column = (
            column if column is not None else getattr(node, "col_offset", 0) + 1
        )
        suppression_lines = {finding_line}
        suppression_lines.update(self.header_suppression_lines.get(id(node), ()))
        containing_statement = _containing_statement(node)
        if isinstance(
            containing_statement,
            (
                ast.AnnAssign,
                ast.Assert,
                ast.Assign,
                ast.AugAssign,
                ast.Expr,
                ast.Raise,
                ast.Return,
            ),
        ):
            statement_end = containing_statement.end_lineno
            if statement_end is not None:
                suppression_lines.add(statement_end)
        if any(self._is_suppressed(candidate, code) for candidate in suppression_lines):
            return

        self.findings.append(
            Finding(
                path=self.path,
                line=finding_line,
                column=finding_column,
                code=code,
                message=message,
            )
        )

    def _is_suppressed(self, line: int, code: str) -> bool:
        for comment in self.comments_by_line.get(line, ()):
            if code in _comment_suppression_codes(comment):
                return True
        return False

    @staticmethod
    def _replace_definition_aliases(
        aliases: dict[str, str],
        replacement: dict[str, str],
    ) -> None:
        aliases.clear()
        aliases.update(replacement)

    def _replace_unittest_case_classes(self, replacement: set[str]) -> None:
        self.unittest_case_classes.clear()
        self.unittest_case_classes.update(replacement)

    @staticmethod
    def _merge_unittest_case_states(states: Sequence[set[str]]) -> set[str]:
        if not states:
            return set()
        return set.intersection(*(set(state) for state in states))

    @staticmethod
    def _discard_definition_bindings(
        node: ast.AST,
        aliases: dict[str, str],
    ) -> None:
        bindings = _class_scope_bindings(node)
        if isinstance(node, ast.AnnAssign) and node.value is None:
            bindings.difference_update(_bound_target_names(node.target))
        for name in bindings:
            aliases[name] = f"{LOCAL_BINDING_ALIAS_PREFIX}.{name}"

    def _discard_unittest_case_bindings(self, node: ast.AST) -> None:
        if isinstance(node, ast.ClassDef):
            return
        bindings = _class_scope_bindings(node)
        if isinstance(node, ast.AnnAssign) and node.value is None:
            bindings.difference_update(_bound_target_names(node.target))
        if isinstance(node, ast.Delete):
            bindings.update(
                name for target in node.targets for name in _bound_target_names(target)
            )
        for name in bindings:
            qualified_name = ".".join((*self.scope, name))
            self.unittest_case_classes.discard(qualified_name)

    def _unittest_case_alias_binding(
        self,
        statement: ast.stmt,
        aliases: dict[str, str],
    ) -> str | None:
        assignment = _single_assignment(statement)
        if assignment is None:
            return None
        name, expression = assignment
        if not isinstance(expression, (ast.Attribute, ast.Name)):
            return None
        if not self._base_is_unittest_case(expression, aliases):
            return None
        return ".".join((*self.scope, name))

    def _visit_definition_expression(
        self,
        node: ast.AST | None,
        aliases: dict[str, str],
    ) -> None:
        if node is None:
            return
        self.visit(node)
        self._discard_definition_bindings(node, aliases)

    def _visit_definition_block(
        self,
        body: Sequence[ast.stmt],
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None = None,
    ) -> None:
        previous_aliases = self.alias_stack[-1]
        self.alias_stack[-1] = aliases
        try:
            for statement in body:
                self._visit_definition_statement(
                    statement,
                    aliases,
                    fallback_aliases=fallback_aliases,
                )
        finally:
            self.alias_stack[-1] = previous_aliases

    def _visit_simple_definition_statement(
        self,
        statement: ast.stmt,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        imports = _collect_import_aliases((statement,))
        alias_binding = _definition_alias_binding(statement, aliases)
        unittest_case_alias = self._unittest_case_alias_binding(
            statement,
            aliases,
        )
        if self.definition_loop_exit_stack and self.capture_definition_loop_exits:
            loop_exits = self.definition_loop_exit_stack[-1]
            if isinstance(statement, ast.Break):
                loop_exits.break_aliases.append(dict(aliases))
                loop_exits.break_cases.append(set(self.unittest_case_classes))
            elif isinstance(statement, ast.Continue):
                loop_exits.continue_aliases.append(dict(aliases))
                loop_exits.continue_cases.append(set(self.unittest_case_classes))
        self.visit(statement)
        self._discard_unittest_case_bindings(statement)
        if unittest_case_alias is not None:
            self.unittest_case_classes.add(unittest_case_alias)
        self._discard_definition_bindings(statement, aliases)
        if alias_binding is not None:
            aliases[alias_binding[0]] = alias_binding[1]
        aliases.update(imports)
        if not isinstance(statement, ast.Delete):
            return
        for target in statement.targets:
            for name in _bound_target_names(target):
                if fallback_aliases is not None and name in fallback_aliases:
                    aliases[name] = fallback_aliases[name]
                else:
                    aliases.pop(name, None)

    def _visit_definition_branch(
        self,
        body: Sequence[ast.stmt],
        aliases: dict[str, str],
        entry_cases: set[str],
        *,
        fallback_aliases: dict[str, str] | None,
        capture_loop_exits: bool,
    ) -> set[str]:
        self._replace_unittest_case_classes(entry_cases)
        previous_capture = self.capture_definition_loop_exits
        self.capture_definition_loop_exits = previous_capture and capture_loop_exits
        try:
            self._visit_definition_block(
                body,
                aliases,
                fallback_aliases=fallback_aliases,
            )
        finally:
            self.capture_definition_loop_exits = previous_capture
        return set(self.unittest_case_classes)

    def _visit_if_definition_statement(
        self,
        statement: ast.If,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        self._visit_definition_expression(statement.test, aliases)
        entry_aliases = dict(aliases)
        entry_cases = set(self.unittest_case_classes)
        body_aliases = dict(entry_aliases)
        alternative_aliases = dict(entry_aliases)
        truth = _constant_truth_value(statement.test)
        body_cases = self._visit_definition_branch(
            statement.body,
            body_aliases,
            entry_cases,
            fallback_aliases=fallback_aliases,
            capture_loop_exits=truth is not False,
        )
        alternative_cases = self._visit_definition_branch(
            statement.orelse,
            alternative_aliases,
            entry_cases,
            fallback_aliases=fallback_aliases,
            capture_loop_exits=truth is not True,
        )
        if truth is True:
            path_aliases = (
                [body_aliases]
                if "fallthrough" in _block_exit_kinds(statement.body, body_aliases)
                else []
            )
            path_cases = (
                [body_cases]
                if "fallthrough" in _block_exit_kinds(statement.body, body_aliases)
                else []
            )
        elif truth is False:
            path_aliases = (
                [alternative_aliases]
                if "fallthrough"
                in _block_exit_kinds(statement.orelse, alternative_aliases)
                else []
            )
            path_cases = (
                [alternative_cases]
                if "fallthrough"
                in _block_exit_kinds(statement.orelse, alternative_aliases)
                else []
            )
        else:
            path_aliases = []
            path_cases = []
            if "fallthrough" in _block_exit_kinds(statement.body, body_aliases):
                path_aliases.append(body_aliases)
                path_cases.append(body_cases)
            if "fallthrough" in _block_exit_kinds(
                statement.orelse,
                alternative_aliases,
            ):
                path_aliases.append(alternative_aliases)
                path_cases.append(alternative_cases)
        self._replace_definition_aliases(
            aliases,
            _merge_definition_aliases(path_aliases),
        )
        merged_cases = (
            set.intersection(*(set(state) for state in path_cases))
            if path_cases
            else set()
        )
        self.unittest_case_classes.clear()
        self.unittest_case_classes.update(merged_cases)

    def _visit_try_handler_definitions(
        self,
        handler: ast.ExceptHandler,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> dict[str, str]:
        handler_aliases = dict(aliases)
        self.node_aliases[id(handler)] = dict(handler_aliases)
        self._check_exception_handler(handler, handler_aliases)
        previous_aliases = self.alias_stack[-1]
        self.alias_stack[-1] = handler_aliases
        try:
            self._visit_definition_expression(handler.type, handler_aliases)
            if handler.name:
                handler_aliases.pop(handler.name, None)
            self._visit_definition_block(
                handler.body,
                handler_aliases,
                fallback_aliases=fallback_aliases,
            )
        finally:
            self.alias_stack[-1] = previous_aliases
        if handler.name:
            handler_aliases.pop(handler.name, None)
        return handler_aliases

    def _try_handler_entry_aliases(
        self,
        handler: ast.ExceptHandler,
        body: Sequence[ast.stmt],
        entry_aliases: dict[str, str],
    ) -> dict[str, str]:
        visitor = _ReachableExplicitRaiseVisitor()
        visitor._visit_body(body)
        matching_states: list[dict[str, str]] = []
        for statement in visitor.raises:
            raise_aliases = self.node_aliases.get(id(statement), entry_aliases)
            if (
                _exception_handler_match(
                    handler,
                    statement,
                    raise_aliases,
                )
                is not False
            ):
                matching_states.append(raise_aliases)
        return (
            _merge_definition_aliases(matching_states)
            if matching_states
            else dict(entry_aliases)
        )

    def _definition_state_after_block(
        self,
        body: Sequence[ast.stmt],
        aliases: dict[str, str],
        cases: set[str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> set[str]:
        saved_findings = self.findings
        saved_functions = self.functions
        saved_node_aliases = self.node_aliases
        saved_reported_placeholders = self.reported_placeholder_nodes
        saved_loop_stack = self.definition_loop_exit_stack
        saved_capture = self.capture_definition_loop_exits
        saved_cases = set(self.unittest_case_classes)
        self.findings = []
        self.functions = []
        self.node_aliases = {}
        self.reported_placeholder_nodes = set()
        self.definition_loop_exit_stack = []
        self.capture_definition_loop_exits = True
        self._replace_unittest_case_classes(cases)
        try:
            self._visit_definition_block(
                body,
                aliases,
                fallback_aliases=fallback_aliases,
            )
            return set(self.unittest_case_classes)
        finally:
            self.findings = saved_findings
            self.functions = saved_functions
            self.node_aliases = saved_node_aliases
            self.reported_placeholder_nodes = saved_reported_placeholders
            self.definition_loop_exit_stack = saved_loop_stack
            self.capture_definition_loop_exits = saved_capture
            self._replace_unittest_case_classes(saved_cases)

    def _apply_finally_to_definition_loop_exits(
        self,
        body: Sequence[ast.stmt],
        loop_exits: _DefinitionLoopExitStates,
        break_start: int,
        break_end: int,
        continue_start: int,
        continue_end: int,
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        def transform(
            alias_states: list[dict[str, str]],
            case_states: list[set[str]],
            start: int,
            end: int,
        ) -> None:
            transformed_aliases: list[dict[str, str]] = []
            transformed_cases: list[set[str]] = []
            for path_aliases, path_cases in zip(
                alias_states[start:end],
                case_states[start:end],
                strict=True,
            ):
                updated_aliases = dict(path_aliases)
                updated_cases = self._definition_state_after_block(
                    body,
                    updated_aliases,
                    path_cases,
                    fallback_aliases=fallback_aliases,
                )
                if "fallthrough" in _block_exit_kinds(body, updated_aliases):
                    transformed_aliases.append(updated_aliases)
                    transformed_cases.append(updated_cases)
            alias_states[start:end] = transformed_aliases
            case_states[start:end] = transformed_cases

        transform(
            loop_exits.break_aliases,
            loop_exits.break_cases,
            break_start,
            break_end,
        )
        transform(
            loop_exits.continue_aliases,
            loop_exits.continue_cases,
            continue_start,
            continue_end,
        )

    def _try_definition_handler_paths(
        self,
        statement: ast.Try | ast.TryStar,
        entry_aliases: dict[str, str],
        entry_cases: set[str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> tuple[
        list[dict[str, str]],
        list[set[str]],
        list[dict[str, str]],
        list[set[str]],
    ]:
        reachable_handlers = (
            _reachable_exception_handlers(statement.handlers, entry_aliases)
            if _block_may_raise(statement.body, entry_aliases)
            else ()
        )
        explicit_raise = (
            _sole_explicit_raise(statement.body, entry_aliases)
            if isinstance(statement, ast.Try)
            else None
        )
        if explicit_raise is not None:
            reachable_handlers, _ = _potential_handlers_for_raise(
                reachable_handlers,
                explicit_raise,
                self.node_aliases.get(id(explicit_raise), entry_aliases),
            )
        all_aliases: list[dict[str, str]] = []
        all_cases: list[set[str]] = []
        path_aliases: list[dict[str, str]] = []
        path_cases: list[set[str]] = []
        for handler in reachable_handlers:
            self._replace_unittest_case_classes(entry_cases)
            handler_entry_aliases = self._try_handler_entry_aliases(
                handler,
                statement.body,
                entry_aliases,
            )
            handler_aliases = self._visit_try_handler_definitions(
                handler,
                handler_entry_aliases,
                fallback_aliases=fallback_aliases,
            )
            handler_cases = set(self.unittest_case_classes)
            all_aliases.append(handler_aliases)
            all_cases.append(handler_cases)
            if "fallthrough" in _block_exit_kinds(
                handler.body,
                handler_aliases,
            ):
                path_aliases.append(handler_aliases)
                path_cases.append(handler_cases)
        return all_aliases, all_cases, path_aliases, path_cases

    def _finish_try_definition_paths(
        self,
        aliases: dict[str, str],
        path_aliases: Sequence[dict[str, str]],
        path_cases: Sequence[set[str]],
        pre_final_aliases: Sequence[dict[str, str]],
        pre_final_cases: Sequence[set[str]],
        finalbody: Sequence[ast.stmt],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        has_fallthrough_path = bool(path_aliases)
        selected_aliases = path_aliases if has_fallthrough_path else pre_final_aliases
        selected_cases = path_cases if has_fallthrough_path else pre_final_cases
        self._replace_definition_aliases(
            aliases,
            _merge_definition_aliases(selected_aliases),
        )
        self._replace_unittest_case_classes(
            self._merge_unittest_case_states(selected_cases)
        )
        self._visit_definition_block(
            finalbody,
            aliases,
            fallback_aliases=fallback_aliases,
        )
        if not has_fallthrough_path or "fallthrough" not in _block_exit_kinds(
            finalbody,
            aliases,
        ):
            aliases.clear()
            self.unittest_case_classes.clear()

    def _visit_try_definition_statement(
        self,
        statement: ast.Try | ast.TryStar,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        entry_aliases = dict(aliases)
        entry_cases = set(self.unittest_case_classes)
        active_loop_exits = (
            self.definition_loop_exit_stack[-1]
            if self.definition_loop_exit_stack and self.capture_definition_loop_exits
            else None
        )
        break_start = (
            len(active_loop_exits.break_aliases) if active_loop_exits is not None else 0
        )
        continue_start = (
            len(active_loop_exits.continue_aliases)
            if active_loop_exits is not None
            else 0
        )
        body_aliases = dict(entry_aliases)
        self._replace_unittest_case_classes(entry_cases)
        self._visit_definition_block(
            statement.body,
            body_aliases,
            fallback_aliases=fallback_aliases,
        )
        normal_aliases = dict(body_aliases)
        self._visit_definition_block(
            statement.orelse,
            normal_aliases,
            fallback_aliases=fallback_aliases,
        )
        normal_cases = set(self.unittest_case_classes)
        path_aliases: list[dict[str, str]] = []
        path_cases: list[set[str]] = []
        pre_final_aliases = [normal_aliases]
        pre_final_cases = [normal_cases]
        if "fallthrough" in _block_exit_kinds(
            statement.body, normal_aliases
        ) and "fallthrough" in _block_exit_kinds(statement.orelse, normal_aliases):
            path_aliases.append(normal_aliases)
            path_cases.append(normal_cases)
        (
            handler_aliases,
            handler_cases,
            handler_path_aliases,
            handler_path_cases,
        ) = self._try_definition_handler_paths(
            statement,
            entry_aliases,
            entry_cases,
            fallback_aliases=fallback_aliases,
        )
        pre_final_aliases.extend(handler_aliases)
        pre_final_cases.extend(handler_cases)
        path_aliases.extend(handler_path_aliases)
        path_cases.extend(handler_path_cases)
        if active_loop_exits is not None and statement.finalbody:
            self._apply_finally_to_definition_loop_exits(
                statement.finalbody,
                active_loop_exits,
                break_start,
                len(active_loop_exits.break_aliases),
                continue_start,
                len(active_loop_exits.continue_aliases),
                fallback_aliases=fallback_aliases,
            )
        self._finish_try_definition_paths(
            aliases,
            path_aliases,
            path_cases,
            pre_final_aliases,
            pre_final_cases,
            statement.finalbody,
            fallback_aliases=fallback_aliases,
        )

    def _visit_with_definition_statement(
        self,
        statement: ast.With | ast.AsyncWith,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        for item in statement.items:
            self._visit_definition_expression(item.context_expr, aliases)
            if item.optional_vars is not None:
                self._discard_definition_bindings(item.optional_vars, aliases)
        entry_aliases = dict(aliases)
        entry_cases = set(self.unittest_case_classes)
        body_aliases = dict(entry_aliases)
        self._replace_unittest_case_classes(entry_cases)
        self._visit_definition_block(
            statement.body,
            body_aliases,
            fallback_aliases=fallback_aliases,
        )
        body_cases = set(self.unittest_case_classes)
        self._replace_definition_aliases(
            aliases,
            _merge_definition_aliases((entry_aliases, body_aliases)),
        )
        self._replace_unittest_case_classes(
            self._merge_unittest_case_states((entry_cases, body_cases))
        )

    def _visit_loop_definition_statement(
        self,
        statement: ast.For | ast.AsyncFor | ast.While,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        body_can_run, body_may_be_skipped, can_exhaust_normally = (
            _loop_definition_reachability(statement, aliases)
        )
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            self._visit_definition_expression(statement.iter, aliases)
        else:
            self._visit_definition_expression(statement.test, aliases)
        entry_aliases = dict(aliases)
        entry_cases = set(self.unittest_case_classes)
        body_aliases = dict(entry_aliases)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            self._discard_definition_bindings(statement.target, body_aliases)
        self._replace_unittest_case_classes(entry_cases)
        loop_exits = _DefinitionLoopExitStates([], [], [], [])
        self.definition_loop_exit_stack.append(loop_exits)
        try:
            self._visit_definition_block(
                statement.body,
                body_aliases,
                fallback_aliases=fallback_aliases,
            )
        finally:
            self.definition_loop_exit_stack.pop()
        body_cases = set(self.unittest_case_classes)
        body_exit_kinds = _block_exit_kinds(statement.body, body_aliases)
        normal_alias_states: list[dict[str, str]] = []
        normal_case_states: list[set[str]] = []
        if body_may_be_skipped:
            normal_alias_states.append(entry_aliases)
            normal_case_states.append(entry_cases)
        if body_can_run and can_exhaust_normally:
            if "fallthrough" in body_exit_kinds:
                normal_alias_states.append(body_aliases)
                normal_case_states.append(body_cases)
            normal_alias_states.extend(loop_exits.continue_aliases)
            normal_case_states.extend(loop_exits.continue_cases)
        normal_reachable = bool(normal_alias_states)
        alternative_aliases = (
            _merge_definition_aliases(normal_alias_states)
            if normal_reachable
            else dict(entry_aliases)
        )
        alternative_cases = (
            self._merge_unittest_case_states(normal_case_states)
            if normal_reachable
            else set(entry_cases)
        )
        self._replace_unittest_case_classes(alternative_cases)
        self._visit_definition_block(
            statement.orelse,
            alternative_aliases,
            fallback_aliases=fallback_aliases,
        )
        final_alternative_cases = set(self.unittest_case_classes)
        reaching_alias_states: list[dict[str, str]] = []
        reaching_case_states: list[set[str]] = []
        if normal_reachable and "fallthrough" in _block_exit_kinds(
            statement.orelse,
            alternative_aliases,
        ):
            reaching_alias_states.append(alternative_aliases)
            reaching_case_states.append(final_alternative_cases)
        if body_can_run:
            reaching_alias_states.extend(loop_exits.break_aliases)
            reaching_case_states.extend(loop_exits.break_cases)
        self._replace_definition_aliases(
            aliases,
            _merge_definition_aliases(reaching_alias_states),
        )
        self._replace_unittest_case_classes(
            self._merge_unittest_case_states(reaching_case_states)
        )

    def _visit_match_case_definitions(
        self,
        case: ast.match_case,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> dict[str, str]:
        case_aliases = dict(aliases)
        for name in _match_pattern_bindings(case.pattern):
            case_aliases.pop(name, None)
        previous_aliases = self.alias_stack[-1]
        self.alias_stack[-1] = case_aliases
        try:
            self.visit(case.pattern)
            self._visit_definition_expression(case.guard, case_aliases)
            self._visit_definition_block(
                case.body,
                case_aliases,
                fallback_aliases=fallback_aliases,
            )
        finally:
            self.alias_stack[-1] = previous_aliases
        return case_aliases

    def _visit_match_definition_statement(
        self,
        statement: ast.Match,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        self._visit_definition_expression(statement.subject, aliases)
        entry_aliases = dict(aliases)
        entry_cases = set(self.unittest_case_classes)
        path_aliases: list[dict[str, str]] = []
        path_cases: list[set[str]] = []
        exhaustive = False
        for case in statement.cases:
            self._replace_unittest_case_classes(entry_cases)
            guard_truth = (
                None if case.guard is None else _constant_truth_value(case.guard)
            )
            previous_capture = self.capture_definition_loop_exits
            self.capture_definition_loop_exits = (
                previous_capture and guard_truth is not False
            )
            try:
                case_aliases = self._visit_match_case_definitions(
                    case,
                    entry_aliases,
                    fallback_aliases=fallback_aliases,
                )
            finally:
                self.capture_definition_loop_exits = previous_capture
            case_classes = set(self.unittest_case_classes)
            if guard_truth is False:
                continue
            if "fallthrough" in _block_exit_kinds(case.body, case_aliases):
                path_aliases.append(case_aliases)
                path_cases.append(case_classes)
            if _match_case_is_irrefutable(case):
                exhaustive = True
                break
        if not exhaustive:
            path_aliases.append(entry_aliases)
            path_cases.append(entry_cases)
        self._replace_definition_aliases(
            aliases,
            _merge_definition_aliases(path_aliases),
        )
        self._replace_unittest_case_classes(
            self._merge_unittest_case_states(path_cases)
        )

    def _visit_definition_statement(
        self,
        statement: ast.stmt,
        aliases: dict[str, str],
        *,
        fallback_aliases: dict[str, str] | None,
    ) -> None:
        self.node_aliases[id(statement)] = dict(aliases)
        if isinstance(statement, ast.If):
            self._visit_if_definition_statement(
                statement,
                aliases,
                fallback_aliases=fallback_aliases,
            )
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            self._visit_try_definition_statement(
                statement,
                aliases,
                fallback_aliases=fallback_aliases,
            )
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            self._visit_with_definition_statement(
                statement,
                aliases,
                fallback_aliases=fallback_aliases,
            )
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            self._visit_loop_definition_statement(
                statement,
                aliases,
                fallback_aliases=fallback_aliases,
            )
        elif isinstance(statement, ast.Match):
            self._visit_match_definition_statement(
                statement,
                aliases,
                fallback_aliases=fallback_aliases,
            )
        else:
            self._visit_simple_definition_statement(
                statement,
                aliases,
                fallback_aliases=fallback_aliases,
            )

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_definition_block(node.body, self.alias_stack[-1])
        self.module_aliases.clear()
        self.module_aliases.update(self.alias_stack[-1])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        outer_aliases = self.alias_stack[-1]
        class_name = ".".join((*self.scope, node.name))
        is_unittest_case = any(
            self._base_is_unittest_case(base, outer_aliases) for base in node.bases
        )
        self.unittest_case_classes.discard(class_name)
        if is_unittest_case:
            self.unittest_case_classes.add(class_name)
        is_protocol = any(
            _resolve_imported_name(_expression_name(base), outer_aliases)
            in {"typing.Protocol", "typing_extensions.Protocol"}
            for base in node.bases
        )
        if not is_protocol:
            self._check_class_correctness(node)
        self.scope.append(node.name)
        self.protocol_stack.append(is_protocol)
        self.unittest_case_stack.append(is_unittest_case)
        class_aliases = dict(outer_aliases)
        self.alias_stack.append(class_aliases)

        body_nodes = {id(statement) for statement in node.body}
        for child in ast.iter_child_nodes(node):
            if id(child) not in body_nodes:
                self.visit(child)

        self._visit_definition_block(
            node.body,
            class_aliases,
            fallback_aliases=outer_aliases,
        )

        self.alias_stack.pop()
        self.unittest_case_stack.pop()
        self.protocol_stack.pop()
        self.scope.pop()

    def _base_is_unittest_case(
        self,
        base: ast.AST,
        aliases: dict[str, str],
    ) -> bool:
        raw_name = _expression_name(base)
        if _resolve_imported_name(raw_name, aliases) in UNITTEST_CASE_BASES:
            return True
        if not raw_name:
            return False
        candidates = {raw_name}
        for depth in range(len(self.scope), -1, -1):
            candidates.add(".".join((*self.scope[:depth], raw_name)))
        return bool(candidates & self.unittest_case_classes)

    def _check_class_correctness(self, node: ast.ClassDef) -> None:
        methods = _class_methods(node)
        constructor, instance, assignments, initialized = _analyze_constructor(
            methods,
            self.alias_stack[-1],
        )
        class_name = ".".join((*self.scope, node.name))
        self._check_overridable_init_calls(
            node,
            methods,
            constructor,
            instance,
            initialized,
            class_name,
        )
        self._check_conditional_instance_state(
            node,
            methods,
            constructor,
            instance,
            assignments,
            initialized,
            class_name,
        )
        self._check_shared_mutable_class_state(
            node,
            methods,
            constructor,
            initialized,
            class_name,
        )

    def _check_overridable_init_calls(
        self,
        class_node: ast.ClassDef,
        methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        constructor: ast.FunctionDef | ast.AsyncFunctionDef | None,
        instance: str | None,
        initialized: frozenset[str] | None,
        class_name: str,
    ) -> None:
        if (
            constructor is None
            or instance is None
            or not initialized
            or _has_decorator(class_node, "final", self.alias_stack[-1])
        ):
            return
        overridable = {
            name
            for name, method in methods.items()
            if not name.startswith("__")
            and not _has_decorator(method, "final", self.alias_stack[-1])
        }
        analyzer = _ConstructorDispatchAnalyzer(
            instance=instance,
            methods=overridable,
        )
        analyzer.analyze(constructor.body)
        reported: set[int] = set()
        for call, method_name, assigned in analyzer.calls:
            if initialized <= assigned or id(call) in reported:
                continue
            reported.add(id(call))
            self.add_finding(
                call,
                "SLP015",
                f"`{class_name}.__init__` calls overridable `{method_name}` "
                "before initialization completes; initialize state before "
                "dispatch or make the method private or final",
            )

    def _constructor_available_attributes(
        self,
        constructor: ast.FunctionDef | ast.AsyncFunctionDef,
        instance: str,
        assignments: dict[str, ast.AST],
        initialized: frozenset[str],
    ) -> frozenset[str] | None:
        constructor_bindings = _collect_local_bindings(
            constructor,
            constructor.body,
        )
        if "hasattr" in constructor_bindings or "hasattr" in self.module_bindings:
            return initialized
        analyzer = _AttributeFlowAnalyzer(
            instance=instance,
            aliases=self.alias_stack[-1],
            read_candidates=set(assignments),
            trust_hasattr=True,
            non_none_returns_fail=True,
        )
        flow = analyzer.analyze(constructor.body)
        return _merge_attribute_states(
            flow.fallthrough,
            flow.returns,
        )

    def _check_conditional_instance_state(
        self,
        class_node: ast.ClassDef,
        methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        constructor: ast.FunctionDef | ast.AsyncFunctionDef | None,
        instance: str | None,
        assignments: dict[str, ast.AST],
        initialized: frozenset[str] | None,
        class_name: str,
    ) -> None:
        if constructor is None or instance is None or initialized is None:
            return
        if {"__getattr__", "__getattribute__"} & methods.keys():
            return
        fallbacks = _class_namespace_names(class_node)
        available = self._constructor_available_attributes(
            constructor,
            instance,
            assignments,
            initialized,
        )
        candidates = set(assignments) - set(available or ()) - fallbacks
        if not candidates:
            return

        first_reads: dict[str, ast.Attribute] = {}
        for method in sorted(methods.values(), key=lambda item: item.lineno):
            if method is constructor or not _is_instance_method(
                method,
                self.alias_stack[-1],
            ):
                continue
            method_instance = _first_positional_parameter(method)
            if method_instance is None:
                continue
            local_bindings = _collect_local_bindings(method, method.body)
            trust_hasattr = (
                "hasattr" not in local_bindings
                and "hasattr" not in self.module_bindings
            )
            trust_attribute_error = (
                "AttributeError" not in local_bindings
                and "AttributeError" not in self.module_bindings
            )
            method_aliases = _function_prefix_aliases(
                method,
                method.body,
                self.alias_stack[-1],
            )
            analyzer = _AttributeFlowAnalyzer(
                instance=method_instance,
                aliases=method_aliases,
                read_candidates=candidates,
                trust_hasattr=trust_hasattr,
                trust_attribute_error=trust_attribute_error,
            )
            analyzer.analyze(method.body)
            for name, read in analyzer.first_reads.items():
                if not self._is_suppressed(read.lineno, "SLP016"):
                    first_reads.setdefault(name, read)

        for name, read in sorted(
            first_reads.items(),
            key=lambda item: (item[1].lineno, item[1].col_offset, item[0]),
        ):
            self.add_finding(
                read,
                "SLP016",
                f"`{class_name}.{name}` may be missing because `__init__` does "
                "not assign it on every successful path; initialize it unconditionally",
            )

    def _check_shared_mutable_class_state(
        self,
        class_node: ast.ClassDef,
        methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        constructor: ast.FunctionDef | ast.AsyncFunctionDef | None,
        initialized: frozenset[str] | None,
        class_name: str,
    ) -> None:
        if _is_test_path(self.path) or (
            constructor is not None and initialized is None
        ):
            return
        classvars = _classvar_names(class_node, self.alias_stack[-1])
        shadowed_names = self.shadowed_container_names | (
            _class_namespace_names(class_node) & {"dict", "list", "set"}
        )
        shared_mutables = {
            name
            for name, value in _class_attribute_values(class_node).items()
            if name not in classvars
            and _mutable_container_kind(value, shadowed_names) is not None
        }
        if not shared_mutables or "__getattribute__" in methods:
            return

        for method in sorted(methods.values(), key=lambda item: item.lineno):
            if not _is_instance_method(method, self.alias_stack[-1]):
                continue
            method_instance = _first_positional_parameter(method)
            if method_instance is None:
                continue
            initial = (
                frozenset() if method is constructor else initialized or frozenset()
            )
            analyzer = _AttributeFlowAnalyzer(
                instance=method_instance,
                aliases=self.alias_stack[-1],
                shared_mutables=shared_mutables,
            )
            analyzer.analyze(method.body, initial)
            reported: set[tuple[int, str]] = set()
            for mutation, name in analyzer.mutations:
                key = (id(mutation), name)
                if key in reported:
                    continue
                reported.add(key)
                self.add_finding(
                    mutation,
                    "SLP017",
                    f"`{class_name}.{name}` is shared mutable class state mutated "
                    "through an instance; initialize it in `__init__` or mark "
                    "intentional shared state as `ClassVar`",
                )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, is_async=True)

    def _check_function_definition(
        self,
        record: FunctionRecord,
        *,
        is_async: bool,
        placeholder: bool,
        function_entry_aliases: dict[str, str],
        decorator_aliases: dict[str, str],
    ) -> None:
        if placeholder and not record.exempt:
            self.add_finding(
                record.node,
                "SLP001",
                f"`{record.qualified_name}` is a concrete placeholder implementation",
            )
        self._check_test_function(
            record,
            placeholder=placeholder,
            aliases=function_entry_aliases,
            decorator_aliases=decorator_aliases,
        )
        self._check_function_defaults(record.node)
        if (
            is_async
            and record.effective_body
            and not placeholder
            and not record.exempt
            and not _contains_async_behavior(record.effective_body)
        ):
            self.add_finding(
                record.node,
                "SLP004",
                f"`{record.qualified_name}` is async but performs no async operation",
            )
        if (
            self.config.max_function_lines > 0
            and record.line_count > self.config.max_function_lines
            and not record.exempt
        ):
            self.add_finding(
                record.node,
                "SLP008",
                f"`{record.qualified_name}` spans {record.line_count} lines "
                f"(limit: {self.config.max_function_lines})",
            )

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        outer_aliases = self.alias_stack[-1]
        exempt = _is_contract_function(
            node,
            outer_aliases,
            in_protocol=bool(self.protocol_stack and self.protocol_stack[-1]),
        )
        body = _effective_body(node.body)
        function_aliases = _function_aliases(node, body, outer_aliases)
        function_entry_aliases = _function_entry_aliases(
            node,
            body,
            outer_aliases,
        )
        qualified_name = ".".join((*self.scope, node.name))
        record = FunctionRecord(node, qualified_name, body, exempt)
        self.functions.append(record)

        placeholder = _is_placeholder_body(body)
        self._check_function_definition(
            record,
            is_async=is_async,
            placeholder=placeholder,
            function_entry_aliases=function_entry_aliases,
            decorator_aliases=self.alias_stack[-1],
        )

        body_nodes = {id(statement) for statement in node.body}
        for child in ast.iter_child_nodes(node):
            if id(child) not in body_nodes:
                self.visit(child)

        self.scope.append(node.name)
        self.alias_stack.append(function_entry_aliases)
        self._visit_definition_block(
            node.body,
            function_entry_aliases,
            fallback_aliases=outer_aliases,
        )
        if is_async and body and not exempt:
            for blocking_call in _find_blocking_calls(
                node,
                body,
                function_aliases,
                self.node_aliases,
            ):
                self.add_finding(
                    blocking_call.node,
                    "SLP013",
                    f"`{blocking_call.qualified_name}` blocks inside async "
                    f"`{qualified_name}`; {blocking_call.guidance}",
                )
        self.alias_stack.pop()
        self.scope.pop()

    def _check_test_function(
        self,
        record: FunctionRecord,
        *,
        placeholder: bool,
        aliases: dict[str, str],
        decorator_aliases: dict[str, str],
    ) -> None:
        node = record.node
        if (
            not _is_test_path(self.path)
            or not node.name.startswith("test")
            or not record.effective_body
            or placeholder
            or record.exempt
            or _has_pytest_fixture_decorator(node, decorator_aliases)
            or _has_test_outcome_decorator(node, decorator_aliases)
            or _contains_test_oracle(
                record.effective_body,
                aliases,
                test_case_receiver=(
                    _first_positional_parameter(node)
                    if self.unittest_case_stack and self.unittest_case_stack[-1]
                    else None
                ),
            )
        ):
            return
        self.add_finding(
            node,
            "SLP014",
            f"`{record.qualified_name}` has no explicit assertion or expected failure; "
            "assert an observable result",
        )

    def _check_exception_handler(
        self,
        node: ast.ExceptHandler,
        aliases: dict[str, str],
    ) -> None:
        if _is_empty_handler(node.body):
            self.add_finding(
                node,
                "SLP002",
                "exception is silently discarded",
            )
        elif _is_broad_exception(
            node.type,
            aliases,
        ) and not _handler_always_raises(
            node.body,
            aliases,
        ):
            self.add_finding(
                node,
                "SLP003",
                "broad exception is converted into fallback behavior without re-raising",
            )

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._check_exception_handler(node, self.alias_stack[-1])
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        names: list[str] = []
        for target in node.targets:
            names.extend(_assigned_names(target))
        self._check_placeholder_value(node, names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_placeholder_value(
            node,
            _assigned_names(node.target),
            node.value,
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.node_aliases[id(node)] = dict(self.alias_stack[-1])
        if not _is_test_path(self.path):
            qualified_name = _resolve_imported_name(
                _expression_name(node.func),
                self.alias_stack[-1],
            )
            if qualified_name in {"os.environ.get", "os.getenv"}:
                environment_name = (
                    node.args[0] if node.args else _keyword_value(node, "key")
                )
                default = (
                    node.args[1]
                    if len(node.args) >= 2
                    else _keyword_value(node, "default")
                )
                if (
                    isinstance(environment_name, ast.Constant)
                    and isinstance(environment_name.value, str)
                    and CONFIG_NAME_RE.search(environment_name.value)
                ):
                    self._report_placeholder(
                        node,
                        environment_name.value,
                        default,
                    )

            for keyword in node.keywords:
                if keyword.arg and CONFIG_NAME_RE.search(keyword.arg):
                    self._report_placeholder(node, keyword.arg, keyword.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._discard_unittest_case_bindings(node.target)
        self._discard_definition_bindings(node.target, self.alias_stack[-1])

    def visit_Dict(self, node: ast.Dict) -> None:
        if not _is_test_path(self.path):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and CONFIG_NAME_RE.search(key.value)
                ):
                    self._report_placeholder(value, key.value, value)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if (
            isinstance(node.value, str)
            and not _is_docstring_constant(node)
            and (
                not REMOTE_URL_RE.match(node.value)
                or node.value.lower().startswith("file://")
            )
            and PERSONAL_HOME_RE.search(node.value)
        ):
            self.add_finding(
                node,
                "SLP012",
                "hardcoded user-home path is environment-specific; "
                "use `Path.home()` or configuration",
            )

    def _check_function_defaults(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        positional = [*node.args.posonlyargs, *node.args.args]
        if node.args.defaults:
            default_arguments = positional[-len(node.args.defaults) :]
            for argument, default in zip(
                default_arguments,
                node.args.defaults,
                strict=True,
            ):
                if CONFIG_NAME_RE.search(argument.arg):
                    self._report_placeholder(default, argument.arg, default)

        for argument, keyword_default in zip(
            node.args.kwonlyargs,
            node.args.kw_defaults,
            strict=True,
        ):
            if keyword_default is not None and CONFIG_NAME_RE.search(argument.arg):
                self._report_placeholder(
                    keyword_default,
                    argument.arg,
                    keyword_default,
                )

    def _check_placeholder_value(
        self,
        node: ast.AST,
        names: Sequence[str],
        value: ast.AST | None,
    ) -> None:
        matching_names = [name for name in names if CONFIG_NAME_RE.search(name)]
        if matching_names:
            self._report_placeholder(node, matching_names[0], value)

    def _report_placeholder(
        self,
        node: ast.AST,
        display_name: str,
        value: ast.AST | None,
    ) -> None:
        if _is_test_path(self.path):
            return
        placeholder = _find_placeholder_constant(
            value,
            ignored=self.reported_placeholder_nodes,
        )
        if placeholder is None:
            return
        self.reported_placeholder_nodes.add(id(placeholder))
        self.add_finding(
            node,
            "SLP006",
            f"`{display_name}` contains an obvious placeholder value",
        )

    def finalize(self) -> None:
        self._find_operational_defects()
        self._find_duplicate_implementations()
        self._find_narrating_comment_clusters()

    def _find_operational_defects(self) -> None:
        self._check_operational_scope(self.module_body, self.module_aliases)
        for record in self.functions:
            if record.exempt:
                continue
            aliases = _function_aliases(
                record.node,
                record.effective_body,
                self.module_aliases,
            )
            local_names = _collect_local_bindings(
                record.node,
                record.effective_body,
            ) | set(_collect_import_aliases(record.effective_body))
            self._check_operational_scope(
                record.effective_body,
                aliases,
                local_names=local_names,
            )

    def _check_subprocess_call(
        self,
        call: OperationalCall,
        flow_index: _OperationalFlowIndex,
    ) -> None:
        result_name = _call_result_name(call.node)
        inline_observation = _subprocess_inline_observation(call.node)
        if (
            _subprocess_checks_failure(call.node, call.aliases)
            or _subprocess_checked_inline(call.node, call.aliases)
            or _call_is_returned(call.node)
            or (
                inline_observation is not None
                and _observation_is_handled_after(
                    call.node,
                    inline_observation,
                    flow_index,
                )
            )
            or (
                result_name is not None
                and _result_is_handled_after_assignment(
                    call.node,
                    result_name,
                    _subprocess_statement_checks_result,
                    flow_index,
                    _subprocess_observation_assignment,
                )
            )
        ):
            return
        self.add_finding(
            call.node,
            "SLP009",
            "`subprocess.run` can fail silently here; use `check=True`, "
            "validate `returncode` before reading output, or deliberately "
            "return the complete result",
        )

    def _check_operational_scope(
        self,
        body: Sequence[ast.stmt],
        aliases: dict[str, str],
        *,
        local_names: set[str] | None = None,
    ) -> None:
        visitor = _OperationalCallVisitor(
            aliases,
            self.node_aliases,
            local_names,
        )
        for statement in body:
            visitor.visit(statement)
        flow_indexes: dict[tuple[tuple[str, str], ...], _OperationalFlowIndex] = {}

        def flow_index_for(call: OperationalCall) -> _OperationalFlowIndex:
            key = tuple(sorted(call.aliases.items()))
            flow_index = flow_indexes.get(key)
            if flow_index is None:
                flow_index = _OperationalFlowIndex(
                    body,
                    call.aliases,
                    self.node_aliases,
                )
                flow_indexes[key] = flow_index
            return flow_index

        for call in visitor.subprocess_calls:
            self._check_subprocess_call(call, flow_index_for(call))

        for call in visitor.network_calls:
            if _call_has_timeout(call.node, call.qualified_name):
                continue
            self.add_finding(
                call.node,
                "SLP010",
                f"`{call.qualified_name}` omits a timeout or sets it to None; "
                "pass `timeout=...`",
            )

        for call in visitor.http_calls:
            if _http_result_is_handled(call, flow_index_for(call)):
                continue
            self.add_finding(
                call.node,
                "SLP011",
                f"`{call.qualified_name}` response may be consumed before HTTP "
                "success is established; call `raise_for_status()` or validate "
                "`status_code` on every path before reading the body",
            )

    def _find_duplicate_implementations(self) -> None:
        groups: dict[str, list[FunctionRecord]] = {}
        for record in self.functions:
            if record.exempt or _is_placeholder_body(record.effective_body):
                continue
            if len(record.effective_body) < self.config.duplicate_min_statements:
                continue
            if record.line_count < self.config.duplicate_min_lines:
                continue

            module = ast.Module(body=list(record.effective_body), type_ignores=[])
            fingerprint = ast.dump(module, include_attributes=False)
            groups.setdefault(fingerprint, []).append(record)

        for records in groups.values():
            if len(records) < 2:
                continue
            original = records[0]
            for duplicate in records[1:]:
                self.add_finding(
                    duplicate.node,
                    "SLP005",
                    f"`{duplicate.qualified_name}` duplicates "
                    f"`{original.qualified_name}` from line {original.node.lineno}",
                )

    def _find_narrating_comment_clusters(self) -> None:
        if self.config.narrating_comment_threshold <= 0:
            return

        counts: dict[FunctionRecord, int] = {}
        for comment in self.comments:
            if not NARRATING_COMMENT_RE.search(comment.text):
                continue

            candidates = [
                record
                for record in self.functions
                if record.node.lineno
                <= comment.line
                <= (record.node.end_lineno or record.node.lineno)
            ]
            if not candidates:
                continue
            owner = min(candidates, key=lambda record: record.line_count)
            counts[owner] = counts.get(owner, 0) + 1

        for record, count in counts.items():
            if count < self.config.narrating_comment_threshold:
                continue
            self.add_finding(
                record.node,
                "SLP007",
                f"`{record.qualified_name}` contains {count} narrating comments "
                f"(limit: {self.config.narrating_comment_threshold - 1})",
            )


def collect_comments(source: str) -> list[Comment]:
    """Collect real comment tokens while ignoring comment-like string content."""

    comments: list[Comment] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        comments.extend(
            Comment(token.start[0], token.string)
            for token in tokens
            if token.type == tokenize.COMMENT
        )
    except tokenize.TokenError:
        return comments
    except IndentationError:
        return comments
    return comments


def _compound_header_roots(node: ast.AST) -> tuple[ast.AST, ...]:
    if isinstance(node, ast.match_case):
        case_roots: list[ast.AST] = [node.pattern]
        if node.guard is not None:
            case_roots.append(node.guard)
        return tuple(case_roots)
    roots: list[ast.AST] = []
    if isinstance(node, (ast.If, ast.While)):
        roots.append(node.test)
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        roots.extend((node.target, node.iter))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            roots.append(item.context_expr)
            if item.optional_vars is not None:
                roots.append(item.optional_vars)
    elif isinstance(node, ast.ExceptHandler):
        if node.type is not None:
            roots.append(node.type)
    elif isinstance(node, ast.Match):
        roots.append(node.subject)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        roots.extend((*node.decorator_list, node.args))
        if node.returns is not None:
            roots.append(node.returns)
        roots.extend(getattr(node, "type_params", ()))
    elif isinstance(node, ast.ClassDef):
        roots.extend((*node.decorator_list, *node.bases))
        roots.extend(keyword.value for keyword in node.keywords)
        roots.extend(getattr(node, "type_params", ()))
    return tuple(roots)


def _compound_header_end_line(
    node: ast.AST,
    tokens: Sequence[tokenize.TokenInfo],
    token_starts: Sequence[tuple[int, int]],
) -> int | None:
    if isinstance(node, ast.Match):
        if not node.cases:
            return None
        stop_node: ast.AST = node.cases[0].pattern
    else:
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body or not isinstance(body[0], ast.stmt):
            return None
        stop_node = body[0]
    start_node = node.pattern if isinstance(node, ast.match_case) else node
    start_line = getattr(start_node, "lineno", None)
    start_column = getattr(start_node, "col_offset", None)
    stop_line = getattr(stop_node, "lineno", None)
    stop_column = getattr(stop_node, "col_offset", None)
    if (
        not isinstance(start_line, int)
        or not isinstance(start_column, int)
        or not isinstance(stop_line, int)
        or not isinstance(stop_column, int)
    ):
        return None
    stop = (stop_line, stop_column)
    start = (start_line, start_column)
    depth = 0
    end_line: int | None = None
    token_index = bisect_left(token_starts, start)
    for token in tokens[token_index:]:
        if token.start >= stop:
            break
        if token.type != tokenize.OP:
            continue
        if token.string in {"(", "[", "{"}:
            depth += 1
        elif token.string in {")", "]", "}"}:
            depth = max(0, depth - 1)
        elif token.string == ":" and depth == 0:
            end_line = token.start[0]
    return end_line


def _collect_header_suppression_lines(
    source: str,
    tree: ast.Module,
) -> dict[int, set[int]]:
    try:
        tokens = tuple(tokenize.generate_tokens(io.StringIO(source).readline))
    except IndentationError, tokenize.TokenError:
        return {}
    token_starts = tuple(token.start for token in tokens)
    compound_types = (
        ast.AsyncFor,
        ast.AsyncFunctionDef,
        ast.AsyncWith,
        ast.ClassDef,
        ast.ExceptHandler,
        ast.For,
        ast.FunctionDef,
        ast.If,
        ast.Match,
        ast.match_case,
        ast.While,
        ast.With,
    )
    suppression_lines: dict[int, set[int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, compound_types):
            continue
        end_line = _compound_header_end_line(node, tokens, token_starts)
        if end_line is None:
            continue
        suppression_lines.setdefault(id(node), set()).add(end_line)
        for root in _compound_header_roots(node):
            for candidate in ast.walk(root):
                suppression_lines.setdefault(id(candidate), set()).add(end_line)
    return suppression_lines


def lint_source(
    source: str,
    *,
    path: str = "<memory>",
    config: LintConfig | None = None,
) -> list[Finding]:
    """Lint one Python source string."""

    active_config = config or LintConfig()
    try:
        tree = ast.parse(source, filename=path, type_comments=True)
    except SyntaxError as error:
        if "SLP000" not in active_config.enabled_codes:
            return []
        message = error.msg or "invalid Python syntax"
        return [
            Finding(
                path=path,
                line=error.lineno or 1,
                column=error.offset or 1,
                code="SLP000",
                message=message,
            )
        ]

    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.__dict__["_pyclichecker_parent"] = parent

    module_aliases = {
        name: qualified_name
        for name, qualified_name in _collect_import_aliases(tree.body).items()
        if name not in _collect_body_bindings(tree.body)
    }
    visitor = SlopVisitor(
        path=path,
        comments=collect_comments(source),
        config=active_config,
        module_body=tree.body,
        module_aliases=module_aliases,
        header_suppression_lines=_collect_header_suppression_lines(source, tree),
    )
    visitor.visit(tree)
    visitor.finalize()
    return sorted(
        visitor.findings,
        key=lambda item: (item.path, item.line, item.column, item.code),
    )
