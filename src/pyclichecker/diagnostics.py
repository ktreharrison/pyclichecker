"""Rule metadata and diagnostics."""

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

type Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class Rule:
    """Metadata for one lint rule."""

    code: str
    severity: str
    title: str
    description: str
    confidence: Confidence = "high"


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
            "medium",
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
            "medium",
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
            "Constructor dispatches to an overridable same-class method before "
            "instance state initialization is complete.",
            "medium",
        ),
        Rule(
            "SLP016",
            "warning",
            "conditional-instance-state",
            "Instance attribute is not initialized on every successful constructor path.",
            "medium",
        ),
        Rule(
            "SLP017",
            "warning",
            "shared-mutable-class-state",
            "Instance method mutates mutable state inherited from the class.",
        ),
        Rule(
            "SLP018",
            "warning",
            "ignored-command-status",
            "os.system or subprocess.call return status is discarded.",
        ),
    )
}


def make_fingerprint(path: str, code: str, semantic_identity: str) -> str:
    """Build a line-independent fingerprint for one finding."""

    normalized_path = path.replace("\\", "/")
    payload = "\0".join((code, normalized_path, semantic_identity))
    return f"v1:{sha256(payload.encode()).hexdigest()}"


@dataclass(frozen=True, slots=True)
class RelatedLocation:
    """A source location that helps explain one finding."""

    path: str
    line: int
    column: int
    message: str

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """One source-level lint diagnostic."""

    path: str
    line: int
    column: int
    code: str
    message: str
    evidence: tuple[str, ...] = ()
    related_locations: tuple[RelatedLocation, ...] = ()
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                make_fingerprint(self.path, self.code, self.message),
            )

    @property
    def severity(self) -> str:
        return RULES[self.code].severity

    @property
    def confidence(self) -> Confidence:
        return RULES[self.code].confidence

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "code": self.code,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "evidence": list(self.evidence),
            "related_locations": [
                location.as_dict() for location in self.related_locations
            ],
            "fingerprint": self.fingerprint,
        }
