"""AST-based checks for high-signal Python code smells."""

import ast
import io
import re
import tokenize
from collections.abc import Sequence
from dataclasses import dataclass

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
NOQA_RE = re.compile(
    r"#\s*noqa\s*:\s*([A-Z0-9_,\s-]+)",
    re.IGNORECASE,
)
SLOP_IGNORE_RE = re.compile(
    r"#\s*slop:\s*ignore\s*\[([A-Z0-9_,\s-]+)\]",
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
    {"expectedFailure", "skip", "skipIf", "skipUnless", "skipif", "xfail"}
)


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


class _RaiseVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.found = False

    def visit_Raise(self, node: ast.Raise) -> None:
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


def _contains_raise(body: Sequence[ast.stmt]) -> bool:
    visitor = _RaiseVisitor()
    for statement in body:
        visitor.visit(statement)
        if visitor.found:
            return True
    return False


def _is_empty_handler(body: Sequence[ast.stmt]) -> bool:
    return bool(body) and all(
        isinstance(statement, ast.Pass)
        or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
        )
        for statement in body
    )


def _is_broad_exception(node: ast.AST | None) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Tuple):
        return any(_is_broad_exception(element) for element in node.elts)
    return _expression_name(node).split(".")[-1] in {"Exception", "BaseException"}


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
    return getattr(node, "_pyclichecker_parent", None)


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


class _TestOracleVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.found = False

    def visit_Assert(self, node: ast.Assert) -> None:
        self.found = True

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _expression_name(node.func).split(".")[-1]
        if call_name.startswith("assert") or call_name in {
            "deprecated_call",
            "fail",
            "raises",
            "skip",
            "skipTest",
            "warns",
        }:
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


def _contains_test_oracle(body: Sequence[ast.stmt]) -> bool:
    visitor = _TestOracleVisitor()
    for statement in body:
        visitor.visit(statement)
        if visitor.found:
            return True
    return False


def _has_test_outcome_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    return any(
        _expression_name(decorator).split(".")[-1] in TEST_OUTCOME_DECORATORS
        for decorator in node.decorator_list
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

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        return

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        return

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


class _BlockingCallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str]) -> None:
        self.aliases = aliases
        self.calls: list[BlockingCall] = []

    def visit_Call(self, node: ast.Call) -> None:
        raw_name = _expression_name(node.func)
        qualified_name = _resolve_imported_name(raw_name, self.aliases)
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


def _status_attribute_is_checked(node: ast.Attribute) -> bool:
    current: ast.AST = node
    parent = _parent_node(current)
    while parent is not None:
        if isinstance(parent, (ast.Assert, ast.Compare, ast.Return, ast.Yield)):
            return True
        if (
            isinstance(parent, (ast.If, ast.IfExp, ast.While))
            and parent.test is current
        ):
            return True
        if isinstance(parent, ast.Match) and parent.subject is current:
            return True
        if isinstance(parent, ast.stmt):
            return False
        current = parent
        parent = _parent_node(current)
    return False


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


class _OperationalCallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str]) -> None:
        self.aliases = aliases
        self.subprocess_calls: list[OperationalCall] = []
        self.network_calls: list[OperationalCall] = []
        self.http_calls: list[OperationalCall] = []
        self.observed_subprocess_names: set[str] = set()
        self.checked_http_names: set[str] = set()
        self.returned_names: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        raw_name = _expression_name(node.func)
        qualified_name = _resolve_imported_name(raw_name, self.aliases)
        if qualified_name == "subprocess.run":
            self.subprocess_calls.append(OperationalCall(node, qualified_name))
        if _is_timeout_call(qualified_name):
            self.network_calls.append(OperationalCall(node, qualified_name))
        if _is_http_call(qualified_name):
            self.http_calls.append(OperationalCall(node, qualified_name))

        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            result_name = node.func.value.id
            if node.func.attr == "check_returncode":
                self.observed_subprocess_names.add(result_name)
            elif node.func.attr == "raise_for_status":
                self.checked_http_names.add(result_name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name):
            if node.attr == "returncode":
                self.observed_subprocess_names.add(node.value.id)
            elif node.attr in HTTP_STATUS_ATTRIBUTES and _status_attribute_is_checked(
                node
            ):
                self.checked_http_names.add(node.value.id)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        self.returned_names.update(_direct_result_names(node.value))
        self.generic_visit(node)

    def visit_Yield(self, node: ast.Yield) -> None:
        self.returned_names.update(_direct_result_names(node.value))
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
    return names | visitor.names


def _collect_body_bindings(body: Sequence[ast.stmt]) -> set[str]:
    visitor = _LocalBindingVisitor()
    for statement in body:
        visitor.visit(statement)
    return visitor.names


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


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _subprocess_checks_failure(node: ast.Call) -> bool:
    check = _keyword_value(node, "check")
    return isinstance(check, ast.Constant) and check.value is True


def _subprocess_checked_inline(node: ast.Call) -> bool:
    attribute = _parent_node(node)
    if not isinstance(attribute, ast.Attribute) or attribute.value is not node:
        return False
    if attribute.attr == "returncode":
        return True
    parent = _parent_node(attribute)
    return bool(
        attribute.attr == "check_returncode"
        and isinstance(parent, ast.Call)
        and parent.func is attribute
    )


def _http_checked_inline(node: ast.Call) -> bool:
    attribute = _parent_node(node)
    if not isinstance(attribute, ast.Attribute) or attribute.value is not node:
        return False
    if attribute.attr == "raise_for_status":
        parent = _parent_node(attribute)
        return isinstance(parent, ast.Call) and parent.func is attribute
    return attribute.attr in HTTP_STATUS_ATTRIBUTES and _status_attribute_is_checked(
        attribute
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
    module_aliases: dict[str, str],
) -> list[BlockingCall]:
    visitor = _BlockingCallVisitor(_function_aliases(node, body, module_aliases))
    for statement in body:
        visitor.visit(statement)
    return visitor.calls


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
    ) -> None:
        self.path = path
        self.comments = comments
        self.config = config
        self.module_body = tuple(module_body)
        self.module_aliases = module_aliases
        self.findings: list[Finding] = []
        self.functions: list[FunctionRecord] = []
        self.scope: list[str] = []
        self.protocol_stack: list[bool] = []
        self.alias_stack = [module_aliases]
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
        if self._is_suppressed(finding_line, code):
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
            noqa = NOQA_RE.search(comment)
            if noqa and code in parse_rule_codes(noqa.group(1)):
                return True

            slop_ignore = SLOP_IGNORE_RE.search(comment)
            if slop_ignore and code in parse_rule_codes(slop_ignore.group(1)):
                return True
        return False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        is_protocol = any(
            _expression_name(base).split(".")[-1] == "Protocol" for base in node.bases
        )
        self.scope.append(node.name)
        self.protocol_stack.append(is_protocol)
        self.generic_visit(node)
        self.protocol_stack.pop()
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, is_async=True)

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        decorator_names = {
            _expression_name(decorator).split(".")[-1]
            for decorator in node.decorator_list
        }
        exempt = bool(
            decorator_names.intersection({"abstractmethod", "overload"})
            or (self.protocol_stack and self.protocol_stack[-1])
        )
        body = _effective_body(node.body)
        qualified_name = ".".join((*self.scope, node.name))
        record = FunctionRecord(node, qualified_name, body, exempt)
        self.functions.append(record)

        placeholder = _is_placeholder_body(body)
        if placeholder and not exempt:
            self.add_finding(
                node,
                "SLP001",
                f"`{qualified_name}` is a concrete placeholder implementation",
            )

        self._check_test_function(record, placeholder=placeholder)
        self._check_function_defaults(node)

        if (
            is_async
            and body
            and not placeholder
            and not exempt
            and not _contains_async_behavior(body)
        ):
            self.add_finding(
                node,
                "SLP004",
                f"`{qualified_name}` is async but performs no async operation",
            )

        if is_async and body and not exempt:
            for blocking_call in _find_blocking_calls(
                node,
                body,
                self.module_aliases,
            ):
                self.add_finding(
                    blocking_call.node,
                    "SLP013",
                    f"`{blocking_call.qualified_name}` blocks inside async "
                    f"`{qualified_name}`; {blocking_call.guidance}",
                )

        if (
            self.config.max_function_lines > 0
            and record.line_count > self.config.max_function_lines
            and not exempt
        ):
            self.add_finding(
                node,
                "SLP008",
                f"`{qualified_name}` spans {record.line_count} lines "
                f"(limit: {self.config.max_function_lines})",
            )

        function_aliases = _function_aliases(node, body, self.module_aliases)
        self.scope.append(node.name)
        self.alias_stack.append(function_aliases)
        self.generic_visit(node)
        self.alias_stack.pop()
        self.scope.pop()

    def _check_test_function(
        self,
        record: FunctionRecord,
        *,
        placeholder: bool,
    ) -> None:
        node = record.node
        if (
            not _is_test_path(self.path)
            or not node.name.startswith("test")
            or not record.effective_body
            or placeholder
            or record.exempt
            or _has_test_outcome_decorator(node)
            or _contains_test_oracle(record.effective_body)
        ):
            return
        self.add_finding(
            node,
            "SLP014",
            f"`{record.qualified_name}` has no explicit assertion or expected failure; "
            "assert an observable result",
        )

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if _is_empty_handler(node.body):
            self.add_finding(
                node,
                "SLP002",
                "exception is silently discarded",
            )
        elif _is_broad_exception(node.type) and not _contains_raise(node.body):
            self.add_finding(
                node,
                "SLP003",
                "broad exception is converted into fallback behavior without re-raising",
            )
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

        for argument, default in zip(
            node.args.kwonlyargs,
            node.args.kw_defaults,
            strict=True,
        ):
            if default is not None and CONFIG_NAME_RE.search(argument.arg):
                self._report_placeholder(default, argument.arg, default)

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
            self._check_operational_scope(record.effective_body, aliases)

    def _check_operational_scope(
        self,
        body: Sequence[ast.stmt],
        aliases: dict[str, str],
    ) -> None:
        visitor = _OperationalCallVisitor(aliases)
        for statement in body:
            visitor.visit(statement)

        for call in visitor.subprocess_calls:
            result_name = _call_result_name(call.node)
            if (
                _subprocess_checks_failure(call.node)
                or _subprocess_checked_inline(call.node)
                or _call_is_returned(call.node)
                or (
                    result_name is not None
                    and result_name
                    in (visitor.observed_subprocess_names | visitor.returned_names)
                )
            ):
                continue
            self.add_finding(
                call.node,
                "SLP009",
                "`subprocess.run` can fail silently here; use `check=True` "
                "or inspect `returncode`",
            )

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
            result_name = _call_result_name(call.node)
            if (
                _http_checked_inline(call.node)
                or _call_is_returned(call.node)
                or (
                    result_name is not None
                    and result_name
                    in (visitor.checked_http_names | visitor.returned_names)
                )
            ):
                continue
            self.add_finding(
                call.node,
                "SLP011",
                f"`{call.qualified_name}` response is used without checking "
                "HTTP success; call `raise_for_status()` or inspect `status_code`",
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
        for token in tokens:
            if token.type == tokenize.COMMENT:
                comments.append(Comment(token.start[0], token.string))
    except tokenize.TokenError, IndentationError:
        return comments
    return comments


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
            child._pyclichecker_parent = parent

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
    )
    visitor.visit(tree)
    visitor.finalize()
    return sorted(
        visitor.findings,
        key=lambda item: (item.path, item.line, item.column, item.code),
    )
