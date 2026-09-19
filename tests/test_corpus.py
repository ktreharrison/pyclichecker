import unittest
from pathlib import Path

import pyclichecker
from tests.corpus_runner import CORPUS, load_manifest


class DifferentialCorpusTests(unittest.TestCase):
    def test_manifest_tracks_required_evidence_kinds(self) -> None:
        manifest = load_manifest()
        kinds = {case["kind"] for case in manifest["cases"]}

        self.assertIn("true-positive", kinds)
        self.assertIn("false-positive-guard", kinds)
        self.assertIn("overlap", kinds)

    def test_pyclichecker_expectations_match_each_fixture(self) -> None:
        manifest = load_manifest()
        for case in manifest["cases"]:
            with self.subTest(case=case["id"]):
                source = (CORPUS / case["source"]).read_text(encoding="utf-8")
                path = Path(case["source"]).name.removesuffix(".fixture")
                actual = sorted(
                    finding.code
                    for finding in pyclichecker.lint_source(source, path=path)
                )
                self.assertEqual(actual, sorted(case["expected"]["pyclichecker"]))

    def test_new_rule_has_positive_corrected_and_false_positive_fixtures(
        self,
    ) -> None:
        manifest = load_manifest()
        variants = {
            case.get("variant")
            for case in manifest["cases"]
            if case.get("rule") == "SLP018"
        }

        self.assertEqual(variants, {"positive", "corrected", "false_positive"})


if __name__ == "__main__":
    unittest.main()
