"""Execute the differential quality-tool corpus."""

import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pyclichecker

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "corpus"
MANIFEST = CORPUS / "manifest.json"
TY_CODE_RE = re.compile(r"\b(?:error|warning)\[([^\]]+)\]")

type CodeRunner = Callable[[Path, dict[str, Any]], list[str]]


def load_manifest() -> dict[str, Any]:
    """Load the checked-in differential expectations."""

    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("cases"), list):
        raise ValueError("unsupported differential corpus manifest")
    return payload


def pyclichecker_codes(path: Path, manifest: dict[str, Any]) -> list[str]:
    """Return pyclichecker codes for one materialized corpus file."""

    del manifest
    source = path.read_text(encoding="utf-8")
    return sorted(
        finding.code for finding in pyclichecker.lint_source(source, path=path.name)
    )


def _capture_command(
    command: list[str],
    *,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - commands come from the checked-in runners
        command,
        cwd=cwd,
        capture_output=True,
        check=False,
        text=True,
    )


def _run_command(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    result = _capture_command(command, cwd=cwd)
    if result.returncode not in {0, 1}:
        raise RuntimeError(
            f"{command[0]} failed with exit {result.returncode}\n"
            f"stdout:\n{result.stdout[-2000:]}\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )
    return result


def ruff_codes(path: Path, manifest: dict[str, Any]) -> list[str]:
    """Return Ruff codes for one corpus file."""

    selected = ",".join(manifest["ruff_select"])
    result = _run_command(
        [
            "ruff",
            "check",
            "--isolated",
            "--no-cache",
            "--select",
            selected,
            "--output-format",
            "json",
            path.name,
        ],
        cwd=path.parent,
    )
    return sorted(item["code"] for item in json.loads(result.stdout))


def pyright_codes(path: Path, manifest: dict[str, Any]) -> list[str]:
    """Return Pyright rule names for one corpus file."""

    del manifest
    result = _run_command(
        [
            "pyright",
            "--outputjson",
            "--pythonversion",
            "3.14",
            path.name,
        ],
        cwd=path.parent,
    )
    payload = json.loads(result.stdout)
    return sorted(
        diagnostic["rule"]
        for diagnostic in payload["generalDiagnostics"]
        if diagnostic.get("rule")
    )


def ty_codes(path: Path, manifest: dict[str, Any]) -> list[str]:
    """Return ty rule names for one corpus file."""

    del manifest
    result = _run_command(
        [
            "ty",
            "check",
            "--python-version",
            "3.14",
            "--output-format",
            "concise",
            "--no-progress",
            path.name,
        ],
        cwd=path.parent,
    )
    return sorted(TY_CODE_RE.findall(f"{result.stdout}\n{result.stderr}"))


RUNNERS: dict[str, CodeRunner] = {
    "pyclichecker": pyclichecker_codes,
    "ruff": ruff_codes,
    "pyright": pyright_codes,
    "ty": ty_codes,
}


def main() -> int:
    """Run every corpus case and compare observed diagnostics to the manifest."""

    manifest = load_manifest()
    mismatches: list[str] = []
    with tempfile.TemporaryDirectory(prefix="pyclichecker-corpus-") as directory:
        scratch = Path(directory)
        for case in manifest["cases"]:
            fixture = CORPUS / case["source"]
            materialized = scratch / fixture.name.removesuffix(".fixture")
            materialized.write_text(
                fixture.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            observations = {
                tool: runner(materialized, manifest) for tool, runner in RUNNERS.items()
            }
            print(
                f"{case['id']}: "
                + ", ".join(
                    f"{tool}={codes or ['clean']}"
                    for tool, codes in observations.items()
                )
            )
            for tool, actual in observations.items():
                expected = sorted(case["expected"][tool])
                if actual != expected:
                    mismatches.append(
                        f"{case['id']} {tool}: expected {expected}, observed {actual}"
                    )

    if mismatches:
        print("\n".join(mismatches), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
