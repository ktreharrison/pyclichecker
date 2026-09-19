# Review coverage and limits

Evidence labels in this document describe how each statement was established:
`[VERIFIED]` means it was checked against repository behavior or configuration,
while `[INFERRED]` marks engineering judgment rather than measured behavior.

This document maps `pyclichecker` and its repository gates to the review
workflow described in Real Python's
[How to Review AI-Generated Python Code](https://realpython.com/review-ai-generated-code/)
and
[Agentic Engineering With Python and AI](https://realpython.com/agentic-engineering/).

## Coverage map

| Review area | Automated coverage in this repository | Still requires judgment or measurement |
|---|---|---|
| Parsing and basic quality | [VERIFIED] `SLP000` rejects invalid syntax, while Ruff checks lint, import, modernization, bug-risk, datetime, security, cyclomatic-complexity, and performance-pattern rule families. | [VERIFIED] Formatting or lint success does not establish correct behavior. |
| Types and interfaces | [VERIFIED] Strict mypy checks every module under `src/pyclichecker`. | [INFERRED] Runtime contracts, external payloads, and deliberately dynamic code may need targeted tests beyond static types. |
| Security | [VERIFIED] Ruff `S`, Bandit, and pip-audit run in CI. `SLP006`, `SLP009`, `SLP010`, `SLP011`, `SLP012`, and `SLP013` cover selected configuration, process, network, path, and async hazards. | [VERIFIED] Threat modeling, authorization design, secret handling outside Python source, and deployment configuration are outside this linter. |
| Tests | [VERIFIED] `SLP014` reports tests without a recognized result or failure oracle. The repository runs unit tests with branch coverage and enforces an 80 percent total threshold. | [INFERRED] Test quality still depends on meaningful inputs, boundary cases, and assertions that match the intended behavior. |
| Maintainability | [VERIFIED] `SLP001`, `SLP002`, `SLP003`, `SLP005`, `SLP007`, `SLP008`, `SLP015`, `SLP016`, and `SLP017` cover selected placeholder, exception, duplication, narration, size, and class-state risks. | [VERIFIED] Architecture, naming quality, domain fit, and whether an abstraction should exist remain review decisions. |
| Performance | [VERIFIED] `SLP013` catches selected blocking calls in async code, and Ruff `PERF` catches known local performance anti-patterns. | [VERIFIED] The repository does not claim formal Big-O analysis, N+1 detection, database query planning, memory profiling, or workload-level latency validation. Use benchmarks, profiles, traces, and production-representative tests. |
| Functional correctness | [VERIFIED] Several rules catch narrow behavioral defects, including swallowed failures, unchecked process results, missing network timeouts, and response use before status validation. | [VERIFIED] Only requirements, acceptance tests, and human review can establish that the code solves the intended problem. |

## Relationship to the articles

[VERIFIED] The code-review article recommends automated filters for linting,
type checking, security, tests, coverage, and dependency auditing before a
manual review. This repository now runs Ruff, strict mypy, Bandit, unit tests
with branch coverage, and pip-audit as companion gates. `pyclichecker` adds
project-specific AST checks that those general-purpose tools do not target.

[VERIFIED] The agentic-engineering article emphasizes bounded tasks, explicit
acceptance criteria, tests, integration checks, and human review.
The bundled Agent Skill now asks an agent to preserve the user's working tree,
state the scope and success criteria, run the repository's own gates, inspect
the final diff, disclose remaining risks, provide a practical rollback path,
and hand the result back for human review.

## Representative probes

| Probe | Configured result |
|---|---|
| Broad exception converted to a fallback | [VERIFIED] `pyclichecker` reports `SLP003`. |
| Blocking synchronous HTTP inside an async function | [VERIFIED] `pyclichecker` reports `SLP004`, `SLP010`, `SLP011`, and `SLP013`. |
| Placeholder helper body | [VERIFIED] `pyclichecker` reports `SLP001`. |
| Hardcoded password assignment | [VERIFIED] Ruff reports `S105`. |
| SQL built with string interpolation | [VERIFIED] Ruff reports `S608`. |
| Misspelled method on a typed object | [VERIFIED] Strict mypy reports `attr-defined`. |
| Off-by-one range bound | [VERIFIED] The configured static gates do not report the representative probe. |
| Repository lookup inside a comprehension | [VERIFIED] The configured static gates do not identify the representative probe as N+1 behavior. |
| Nested traversal of one collection | [VERIFIED] Ruff `PERF` and `pyclichecker` do not report the representative quadratic probe. |

## Time complexity

[VERIFIED] `pyclichecker` has no rule that infers an algorithm's asymptotic time
complexity.

[INFERRED] A broad Big-O rule would be low signal in a Python AST linter because
runtime cost depends on input sizes, concrete container types, dynamic
dispatch, I/O behavior, database access, caching, and library implementations.
Cyclomatic complexity and function length also measure structure, not runtime
growth.

[INFERRED] Future performance rules should be narrow and corpus-tested. Possible
candidates include a database or network call inside a loop, repeated linear
membership checks against a list, or clearly nested traversal of the same
collection. Each candidate needs positive, corrected, alias, shadowing, and
false-positive tests before receiving a permanent `SLP` code.

## Repository gate

Run the core local quality stack from the repository root:

```bash
uv sync --locked
uv run python -m unittest discover -v
uv run coverage erase
uv run coverage run -m unittest discover -v
uv run coverage report
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run bandit -q -r src
uv export --quiet --locked --all-groups --no-emit-project --format requirements.txt --output-file .audit-requirements.txt
uv run pip-audit --strict --requirement .audit-requirements.txt
uv run pyclichecker src tests
uv build
```

Then run the built-archive inspection, installed-CLI smoke tests, and
fresh-directory wheel test in [AGENTS.md](../AGENTS.md) to complete package
validation.

[VERIFIED] Exit success from the core stack and the package checks means the
configured automated gates passed. It does not mean the implementation's
intent, architecture, operational behavior, or time complexity has been
proven.
