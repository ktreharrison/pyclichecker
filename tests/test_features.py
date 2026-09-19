import io
import json
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pyclichecker


class FeatureRuleTests(unittest.TestCase):
    def lint(
        self,
        source: str,
        *,
        path: str = "app.py",
    ) -> list[pyclichecker.Finding]:
        return pyclichecker.lint_source(textwrap.dedent(source), path=path)

    def test_ignored_command_status_reports_discarded_results(self) -> None:
        findings = self.lint("""
            import os
            import subprocess

            def discarded():
                os.system("refresh")
                subprocess.call(["refresh"])

            def assigned_but_unused():
                status = subprocess.call(["refresh"])
                log("finished")

            def observed_on_only_one_path(verbose):
                status = os.system("refresh")
                if verbose:
                    print(status)
        """)

        status_findings = [item for item in findings if item.code == "SLP018"]
        self.assertEqual(len(status_findings), 4)
        self.assertEqual([item.line for item in status_findings], [6, 7, 10, 14])

    def test_ignored_command_status_accepts_observed_and_delegated_results(
        self,
    ) -> None:
        findings = self.lint("""
            import os
            import subprocess

            def checked():
                status = os.system("refresh")
                if status:
                    raise RuntimeError("refresh failed")

            def logged():
                status = subprocess.call(["refresh"])
                print(status)

            def delegated():
                return subprocess.call(["refresh"])

            def inline_observation():
                if os.system("refresh"):
                    raise RuntimeError("refresh failed")

            def raising_api():
                subprocess.check_call(["refresh"])
        """)

        self.assertNotIn("SLP018", [item.code for item in findings])

    def test_ignored_command_status_resolves_aliases_and_shadowing(self) -> None:
        findings = self.lint("""
            import os as operating_system
            from subprocess import call as invoke

            def aliases():
                operating_system.system("refresh")
                invoke(["refresh"])

            def shadowed(operating_system, invoke):
                operating_system.system("refresh")
                invoke(["refresh"])
        """)

        status_findings = [item for item in findings if item.code == "SLP018"]
        self.assertEqual(len(status_findings), 2)
        self.assertEqual([item.line for item in status_findings], [6, 7])

    def test_ignored_command_status_supports_inline_suppression(self) -> None:
        findings = self.lint("""
            import os
            import subprocess

            os.system("best effort")  # noqa: SLP018
            subprocess.call(["best effort"])  # slop: ignore [SLP018]
        """)

        self.assertNotIn("SLP018", [item.code for item in findings])

    def test_finding_evidence_and_fingerprint_are_structured(self) -> None:
        original = self.lint("""
            import subprocess

            def deploy():
                completed = subprocess.run(["deploy"], capture_output=True)
                return completed.stdout
        """)
        shifted = self.lint("""


            import subprocess

            def deploy():
                completed = subprocess.run(["deploy"], capture_output=True)
                return completed.stdout
        """)

        finding = next(item for item in original if item.code == "SLP009")
        shifted_finding = next(item for item in shifted if item.code == "SLP009")
        payload = finding.as_dict()

        self.assertEqual(payload["confidence"], "high")
        self.assertEqual(len(payload["evidence"]), 2)
        self.assertEqual(payload["related_locations"], [])
        self.assertTrue(str(payload["fingerprint"]).startswith("v1:"))
        self.assertEqual(finding.fingerprint, shifted_finding.fingerprint)

    def test_related_locations_explain_duplicate_implementations(self) -> None:
        findings = self.lint("""
            def first(value):
                value += 1
                value *= 2
                value -= 3
                value //= 4
                return value

            def second(value):
                value += 1
                value *= 2
                value -= 3
                value //= 4
                return value
        """)

        duplicate = next(item for item in findings if item.code == "SLP005")
        self.assertEqual(len(duplicate.related_locations), 1)
        self.assertEqual(duplicate.related_locations[0].line, 2)
        self.assertIn("first", duplicate.related_locations[0].message)


class BaselineTests(unittest.TestCase):
    def run_main(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = pyclichecker.main(arguments)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_baseline_filters_line_shifts_and_keeps_new_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.py"
            baseline = root / "baseline.json"
            source.write_text(
                "def pending():\n    pass\n",
                encoding="utf-8",
            )
            initial_exit, initial_output, _ = self.run_main(
                [str(source), "--format", "json", "--fail-on", "never"]
            )
            baseline.write_text(initial_output, encoding="utf-8")
            source.write_text(
                "\n\ndef pending():\n    pass\n\n"
                "async def fake_async():\n    return 1\n",
                encoding="utf-8",
            )

            exit_code, output, error = self.run_main(
                [
                    str(source),
                    "--format",
                    "json",
                    "--baseline",
                    str(baseline),
                ]
            )
            payload = json.loads(output)

        self.assertEqual(initial_exit, pyclichecker.EXIT_CLEAN)
        self.assertEqual(exit_code, pyclichecker.EXIT_FINDINGS)
        self.assertEqual(error, "")
        self.assertEqual([item["code"] for item in payload["findings"]], ["SLP004"])
        self.assertEqual(payload["baseline"]["matched"], 1)

    def test_baseline_preserves_duplicate_occurrence_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.py"
            baseline = root / "baseline.json"
            source.write_text("def pending():\n    pass\n", encoding="utf-8")
            _, initial_output, _ = self.run_main(
                [str(source), "--format", "json", "--fail-on", "never"]
            )
            baseline.write_text(initial_output, encoding="utf-8")
            source.write_text(
                "def pending():\n    pass\n\ndef pending():\n    pass\n",
                encoding="utf-8",
            )

            exit_code, output, _ = self.run_main(
                [
                    str(source),
                    "--format",
                    "json",
                    "--baseline",
                    str(baseline),
                ]
            )
            payload = json.loads(output)

        self.assertEqual(exit_code, pyclichecker.EXIT_FINDINGS)
        self.assertEqual([item["code"] for item in payload["findings"]], ["SLP001"])
        self.assertEqual(payload["baseline"]["matched"], 1)

    def test_invalid_baseline_is_an_operational_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.py"
            baseline = root / "baseline.json"
            source.write_text("value = 1\n", encoding="utf-8")
            baseline.write_text('{"findings": [{}]}', encoding="utf-8")

            exit_code, output, error = self.run_main(
                [
                    str(source),
                    "--format",
                    "json",
                    "--baseline",
                    str(baseline),
                ]
            )
            payload = json.loads(output)

        self.assertEqual(exit_code, pyclichecker.EXIT_OPERATIONAL_ERROR)
        self.assertEqual(error, "")
        self.assertIn("has no fingerprint", payload["errors"][0])
        self.assertIsNone(payload["baseline"])


class SourceEncodingTests(unittest.TestCase):
    def test_source_encoding_cookie_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "latin1.py"
            source.write_bytes(
                "# -*- coding: latin-1 -*-\ndef café():\n    pass\n".encode("latin-1")
            )

            findings, files_checked, errors = pyclichecker.lint_files(
                [source],
                use_stdin=False,
                config=pyclichecker.LintConfig(),
            )

        self.assertEqual(files_checked, 1)
        self.assertEqual(errors, [])
        self.assertEqual([item.code for item in findings], ["SLP001"])
        self.assertIn("café", findings[0].message)


if __name__ == "__main__":
    unittest.main()
