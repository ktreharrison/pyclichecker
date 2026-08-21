---
name: pyclichecker
description: Run pyclichecker as a strict Python quality gate after creating, editing, refactoring, or reviewing Python code, especially agent-generated code. Use to scan changed Python files and the full repository, interpret JSON findings and exit codes, fix high-signal defects, and justify only narrow suppressions. Runs through uvx without permanent installation.
---

# Pyclichecker

Use the pinned release for reproducible results:

```bash
uvx --from git+https://github.com/ktreharrison/pyclichecker.git@v2.3.0 \
  pyclichecker changed_file.py --format json
```

Keep `v2.3.0` pinned. Do not silently switch the skill to `main`.

## Workflow

1. Verify that `uv` is available with `uv --version`. If it is unavailable,
   report the missing prerequisite and stop.
2. Identify every added or modified `.py` file in the current task. Exclude
   deleted files. If version-control metadata is unavailable, use the files
   edited during the task.
3. Run the pinned command against those files with `--format json`. Quote paths
   that contain spaces. Do not hide the exit status with `|| true`.
4. Read each finding in source context. Fix concrete defects with the smallest
   behavior-preserving change, then run relevant project tests.
5. Repeat the changed-file scan until it exits `0`.
6. From the repository root, run the final gate:

   ```bash
   uvx --from git+https://github.com/ktreharrison/pyclichecker.git@v2.3.0 \
     pyclichecker . --format json
   ```

7. Finish only after the final gate exits `0`. If unrelated pre-existing
   findings prevent that, report them explicitly instead of changing unrelated
   behavior or claiming a clean result.

## Interpret Results

- Exit `0`: the scan completed and no warning-or-higher finding remains.
- Exit `1`: findings remain. Fix them and rerun the same scope.
- Exit `2`: the scan was incomplete. Resolve missing paths, unreadable files,
  invalid invocation, or discovery errors before evaluating code quality.

Parse JSON from standard output. Treat setup and build messages on standard
error as command diagnostics, not JSON.

Prioritize `error` findings, then resolve every `warning`. Do not weaken the
gate with `--fail-on error` or `--fail-on never`.

## Suppress Deliberately

Fix a finding before considering suppression. When behavior is intentionally
exceptional:

1. Confirm the rule does not indicate a real defect.
2. Add the narrowest inline suppression with the exact `SLP` code.
3. Record the reason in the code or task report.
4. Rerun the changed-file and final repository gates.

Never use bare `# noqa`, broad `--ignore` lists, or file-wide suppression merely
to make the command pass.

## Report Completion

Report the scopes scanned, fixes made, tests run, final exit status, and any
intentional suppression. Describe findings as code-quality risks, not evidence
that AI authored the code.
