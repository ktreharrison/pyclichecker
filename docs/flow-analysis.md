# Flow analysis

## Analysis pipeline

`pyclichecker` parses each source file with Python's AST parser and
collects real comments with the tokenizer. Parent references are attached to
AST nodes so later checks can move from an expression to its containing
statement and enclosing scopes.

Import aliases are resolved at the point where a call appears.
Function-local bindings and later rebinding can shadow imported names, so a
local object named `subprocess` is not automatically treated as the standard
library module.

Findings are sorted by path, line, column, and rule code before they
are returned. This keeps output deterministic even when checks discover nodes
through different analysis passes.

## Operational-result flow

`SLP009` and `SLP011` build a per-scope flow index for subprocess and
HTTP results. The index records statement blocks, nested-block ownership,
references to result names, control-flow barriers, and expressions that may
raise.

The analyzer follows normal continuation, branch continuation,
loops, `match` cases, `try` handlers, `finally` blocks, returns, raises, breaks,
and continues. A subprocess or HTTP result is accepted only when every relevant
continuation validates or deliberately delegates it before unsafe consumption.

Exception routing distinguishes recognized validation exceptions
from unrelated exceptions. It also models selected `contextlib.suppress`
patterns and checks whether a validation failure can be swallowed by an
enclosing handler.

`SLP018` has a narrower contract. It reports a status returned by
`os.system` or `subprocess.call` when the value is used as a standalone
statement or is assigned without an observable consumer on every normal
continuation. It does not claim that every observed status is handled
correctly.

## Constructor and class state

`SLP015` tracks attributes that are definitely initialized when a
constructor dispatches to an overridable method. It reports the call when known
constructor state is still pending.

`SLP016` merges constructor exit states by intersection. An
attribute is considered definitely initialized only when it exists on every
successful constructor path. Reads protected by recognized `hasattr` or
`AttributeError` patterns receive separate handling.

`SLP017` identifies mutable containers created in the class
namespace and tracks instance-method mutations. Per-instance initialization,
`ClassVar`, test fixtures, and shadowed container constructors are considered
before reporting.

## Evidence and baselines

Every finding carries rule-level confidence, evidence statements,
optional related locations, and a fingerprint. Related locations currently
connect findings such as duplicate implementations and class-state defects to
the source location that explains the relationship.

AST-backed fingerprints contain the rule code, normalized path,
enclosing named scopes, and an AST dump without source coordinates. Syntax
errors use the parser message and offending source line because no valid AST is
available. Baseline matching uses occurrence counts, so one recorded finding
cannot hide a newly added identical finding.

## Deliberate limits

The analysis is intra-file and primarily intra-scope. It does not
execute code, infer arbitrary library behavior, prove application intent, or
compute asymptotic time complexity.

Dynamic imports, monkey-patching, reflective attribute access, and
unknown helper semantics can exceed what the static model can establish.
Rules therefore use explicit recognized patterns and conservative exemptions
instead of treating every suggestive name as authoritative.
