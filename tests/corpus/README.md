# Differential corpus

The corpus provides executable comparison evidence for `pyclichecker`, Ruff,
Pyright, and ty.

Each fixture is classified as:

- `true-positive`: a defect or risk that one tool should identify.
- `false-positive-guard`: corrected code that must remain clean for the rule
  being evaluated.
- `overlap`: more than one tool reports the example, potentially for different
  reasons.

Fixtures use the `.py.fixture` suffix so intentional defects are not included
in the repository's normal Python self-scan. The runner materializes temporary
`.py` files before invoking each tool.

Rule-addressed directories use `positive.py.fixture`,
`corrected.py.fixture`, and `false_positive.py.fixture` where the rule is being
introduced or recalibrated. General comparison probes live under
`comparison/`.

Run the complete comparison from the repository root:

```bash
uv run python -m tests.corpus_runner
```

The checked-in manifest records exact expected diagnostic codes. A tool update
that changes behavior must either fix a regression or update the expectation
with a reviewed explanation.
