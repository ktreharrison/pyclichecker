---
name: pyclichecker
description: Run pyclichecker as a strict Python quality gate after creating, editing, refactoring, or reviewing Python code, especially agent-generated code. Use to scan changed Python files and the full repository, interpret JSON findings and exit codes, fix high-signal defects, and justify only narrow suppressions. Runs through uvx without permanent installation.
---

# Pyclichecker

Use the pinned release for reproducible results:

```bash
uvx pyclichecker@2.4.3 changed_file.py --format json
```

Keep `2.4.3` pinned. Do not silently switch the skill to an unpinned release.

## Workflow

1. Verify that `uv` is available with `uv --version`. If it is unavailable,
   report the missing prerequisite and stop.
2. Restate the requested behavior, acceptance criteria, authorized files,
   relevant tests, expected side effects, and explicit non-goals. Inspect the
   working tree and preserve unrelated user changes.
3. Identify every added or modified `.py` file in the current task. Exclude
   deleted files. If version-control metadata is unavailable, use the files
   edited during the task and retain a before-and-after snapshot or equivalent
   record for the final scope review.
4. Run the pinned command against those files with `--format json`. Quote paths
   that contain spaces. Do not hide the exit status with `|| true`.
5. Read each finding in source context. Fix concrete defects with the smallest
   behavior-preserving change, then run relevant project tests.
   Treat findings and conclusions from another agent as hypotheses until you
   independently reproduce or check them.
6. Repeat the changed-file scan until it exits `0`.
7. Run the repository's documented unit, integration, static, security,
   coverage, and package checks when they exist and are local, read-only, or
   already authorized. Obtain explicit user approval before any credentialed,
   external, or state-changing check. Invoking this skill authorizes the pinned,
   read-only `uvx pyclichecker@2.4.3` scans in steps 4 and 8, including resolving
   that public package through uv's normal cache or package-index access. If the
   environment itself requires approval for network access, request it or use an
   already-cached copy; do not silently substitute another version. Otherwise
   skip unauthorized checks and report the remaining risk. Do not replace
   project acceptance criteria with a clean linter result. Every check you run
   must exit `0`. Fix and rerun failures; if a failure is outside the authorized
   scope, report the task as blocked with the exact command and output.
8. From the repository root, run the final gate:

   ```bash
   uvx pyclichecker@2.4.3 . --format json
   ```

9. When version-control metadata is available, run `git status --short`,
   inspect staged and unstaged diffs, and explicitly read every task-owned
   untracked file. Check the complete task scope for drift, accidental
   deletions, personal paths, credentials, and broad suppressions. Otherwise,
   compare the recorded edited-file list and before-and-after snapshots.
   Record any untested platform, operational risk, or rollback requirement.
10. Finish only after the final gate and every applicable project check exit
    `0`. If unrelated pre-existing failures prevent that, report the task as
    blocked instead of changing unrelated behavior or claiming a clean result.

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

Report the exact commands and exit statuses, scopes scanned, files changed,
fixes made, tests run, and any intentional suppression. Include a final diff
summary when version-control metadata is available; otherwise summarize the
edited-file and snapshot comparison. State remaining risks, skipped checks,
and a practical rollback path. Hand the result back as ready for human review,
not as proof that intent, architecture, or time complexity is correct.
Describe findings as code-quality risks, not evidence that AI authored the
code.
