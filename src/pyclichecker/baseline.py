"""Finding-baseline loading and matching."""

import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from pyclichecker.diagnostics import Finding

type FingerprintCounts = Counter[str]


def load_baseline(path: Path) -> tuple[FingerprintCounts | None, str | None]:
    """Load fingerprints from a prior JSON pyclichecker result."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"cannot read baseline {path}: {error}"

    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        return None, f"invalid baseline {path}: expected an object with a findings list"

    fingerprints: list[str] = []
    for index, finding in enumerate(payload["findings"]):
        if not isinstance(finding, dict):
            return (
                None,
                f"invalid baseline {path}: finding {index} is not an object",
            )
        fingerprint = finding.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            return (
                None,
                f"invalid baseline {path}: finding {index} has no fingerprint",
            )
        fingerprints.append(fingerprint)
    return Counter(fingerprints), None


def apply_baseline(
    findings: Sequence[Finding],
    fingerprints: FingerprintCounts,
) -> tuple[list[Finding], int]:
    """Remove the number of finding occurrences recorded in a baseline."""

    remaining = fingerprints.copy()
    new_findings: list[Finding] = []
    matched = 0
    for finding in findings:
        if remaining[finding.fingerprint] > 0:
            remaining[finding.fingerprint] -= 1
            matched += 1
        else:
            new_findings.append(finding)
    return new_findings, matched
