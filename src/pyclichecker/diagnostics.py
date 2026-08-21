"""Rule metadata and diagnostics."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Rule:
    """Metadata for one lint rule."""

    code: str
    severity: str
    title: str
    description: str


RULES = {
    rule.code: rule
    for rule in (
        Rule("SLP000", "error", "invalid-python", "Python source cannot be parsed."),
        Rule(
            "SLP001",
            "error",
            "placeholder-implementation",
            "Concrete function contains only pass, ellipsis, or NotImplementedError.",
        ),
        Rule(
            "SLP002",
            "error",
            "swallowed-exception",
            "Exception handler silently discards an exception.",
        ),
        Rule(
            "SLP003",
            "warning",
            "broad-exception-fallback",
            "Broad exception handler converts unexpected failures into fallback behavior.",
        ),
        Rule(
            "SLP004",
            "warning",
            "fake-async",
            "Async function contains no await, async iteration, async context, or yield.",
        ),
        Rule(
            "SLP005",
            "warning",
            "duplicate-implementation",
            "Function body duplicates another implementation in the same file.",
        ),
        Rule(
            "SLP006",
            "error",
            "placeholder-configuration",
            "Configuration-like variable contains an obvious placeholder value.",
        ),
        Rule(
            "SLP007",
            "warning",
            "narrating-comments",
            "Function contains a cluster of comments that merely narrate operations.",
        ),
        Rule(
            "SLP008",
            "warning",
            "oversized-function",
            "Function is large enough to warrant decomposition or focused review.",
        ),
        Rule(
            "SLP009",
            "warning",
            "unchecked-subprocess",
            "subprocess.run can fail without its outcome being observed.",
        ),
        Rule(
            "SLP010",
            "warning",
            "missing-network-timeout",
            "Synchronous network call omits its timeout or sets it to None.",
        ),
        Rule(
            "SLP011",
            "warning",
            "unchecked-http-response",
            "HTTP response is consumed without checking whether the request succeeded.",
        ),
        Rule(
            "SLP012",
            "warning",
            "environment-specific-path",
            "Source contains an absolute path tied to one user's home directory.",
        ),
        Rule(
            "SLP013",
            "warning",
            "blocking-in-async",
            "Async function directly calls a known blocking API.",
        ),
        Rule(
            "SLP014",
            "warning",
            "assertion-free-test",
            "Test function has no explicit result or expected-failure oracle.",
        ),
        Rule(
            "SLP015",
            "warning",
            "overridable-init-call",
            "Constructor calls a same-class method that subclasses can override.",
        ),
        Rule(
            "SLP016",
            "warning",
            "conditional-instance-state",
            "Instance attribute is not initialized on every successful constructor path.",
        ),
        Rule(
            "SLP017",
            "warning",
            "shared-mutable-class-state",
            "Instance method mutates mutable state inherited from the class.",
        ),
    )
}


@dataclass(frozen=True, slots=True)
class Finding:
    """One source-level lint diagnostic."""

    path: str
    line: int
    column: int
    code: str
    message: str

    @property
    def severity(self) -> str:
        return RULES[self.code].severity

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
