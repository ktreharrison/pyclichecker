import io
import json
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from importlib.metadata import metadata, version
from pathlib import Path
from unittest.mock import patch

import pyclichecker


class RuleTests(unittest.TestCase):
    def lint(
        self,
        source: str,
        *,
        path: str = "app.py",
        **config_overrides: object,
    ) -> list[pyclichecker.Finding]:
        config = replace(pyclichecker.LintConfig(), **config_overrides)
        return pyclichecker.lint_source(
            textwrap.dedent(source),
            path=path,
            config=config,
        )

    def assert_codes(
        self,
        findings: list[pyclichecker.Finding],
        expected: list[str],
    ) -> None:
        self.assertEqual([finding.code for finding in findings], expected)

    def test_placeholder_rule_exempts_abstract_and_protocol_contracts(self) -> None:
        findings = self.lint("""
            from abc import abstractmethod
            from typing import Protocol, TypeVar

            T = TypeVar("T")

            def concrete():
                pass

            class Abstract:
                @abstractmethod
                def required(self):
                    ...

            class Contract(Protocol):
                def required(self):
                    ...

            class GenericContract(Protocol[T]):
                def required(self):
                    ...
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertIn("concrete", findings[0].message)

    def test_exception_rules_distinguish_empty_broad_and_reraised(self) -> None:
        findings = self.lint("""
            def process(value):
                try:
                    return int(value)
                except ValueError:
                    pass

            def fallback(value):
                try:
                    return int(value)
                except Exception:
                    return 0

            def preserve_failure(value):
                try:
                    return int(value)
                except Exception:
                    raise
            """)

        self.assert_codes(findings, ["SLP002", "SLP003"])

    def test_fake_async_rule_requires_async_behavior(self) -> None:
        findings = self.lint("""
            async def fake(value):
                return value

            async def real(client):
                return await client.fetch()
            """)

        self.assert_codes(findings, ["SLP004"])
        self.assertIn("fake", findings[0].message)

    def test_blocking_async_rule_handles_direct_and_aliased_calls(self) -> None:
        findings = self.lint("""
            import asyncio
            import subprocess
            import time as clock
            from requests import get as fetch

            async def load(url):
                await asyncio.sleep(0)
                clock.sleep(0.1)
                response = fetch(url)
                subprocess.run(["worker"])
                return response
            """)

        blocking_findings = [
            finding for finding in findings if finding.code == "SLP013"
        ]
        self.assertEqual(len(blocking_findings), 3)
        self.assertIn("time.sleep", blocking_findings[0].message)
        self.assertIn("requests.get", blocking_findings[1].message)
        self.assertIn("subprocess.run", blocking_findings[2].message)

    def test_blocking_async_rule_ignores_safe_and_shadowed_calls(self) -> None:
        findings = self.lint("""
            import asyncio
            import requests
            import time

            def synchronous():
                time.sleep(0.1)

            async def safe(time):
                await asyncio.sleep(0.1)
                await asyncio.to_thread(requests.get, "https://example.com")

                def nested():
                    requests.get("https://example.com")

                return time.sleep()
            """)

        self.assertNotIn("SLP013", [finding.code for finding in findings])

    def test_blocking_async_rule_supports_inline_suppression(self) -> None:
        findings = self.lint("""
            import asyncio
            import time

            async def throttled():
                await asyncio.sleep(0)
                time.sleep(0.1)  # noqa: SLP013
            """)

        self.assertNotIn("SLP013", [finding.code for finding in findings])

    def test_duplicate_rule_reports_later_implementation(self) -> None:
        findings = self.lint("""
            def first(value):
                normalized = value.strip()
                pieces = normalized.split(",")
                cleaned = [piece.strip() for piece in pieces]
                result = [piece for piece in cleaned if piece]
                return result

            def second(value):
                normalized = value.strip()
                pieces = normalized.split(",")
                cleaned = [piece.strip() for piece in pieces]
                result = [piece for piece in cleaned if piece]
                return result
            """)

        self.assert_codes(findings, ["SLP005"])
        self.assertIn("second", findings[0].message)
        self.assertIn("first", findings[0].message)

    def test_placeholder_configuration_ignores_test_fixtures(self) -> None:
        source = 'API_KEY = "your-api-key-here"\n'

        production_findings = self.lint(source, path="settings.py")
        test_findings = self.lint(source, path="tests/test_settings.py")

        self.assert_codes(production_findings, ["SLP006"])
        self.assert_codes(test_findings, [])

    def test_placeholder_configuration_checks_nested_sources(self) -> None:
        source = """
            import os

            API_TOKEN = os.getenv("API_TOKEN", "your-token-here")
            SETTINGS = {"service_url": "https://example.com"}
            client = Client(api_key="replace-me")

            def connect(password="change-me"):
                return password
        """

        production_findings = self.lint(source, path="settings.py")
        test_findings = self.lint(source, path="tests/test_settings.py")

        self.assert_codes(production_findings, ["SLP006"] * 4)
        self.assert_codes(test_findings, [])

    def test_placeholder_configuration_accepts_resolved_values(self) -> None:
        findings = self.lint("""
            import os

            API_TOKEN = os.environ["API_TOKEN"]
            SETTINGS = {"service_url": configured_url}
            client = Client(api_key=resolved_key)

            def connect(password=None):
                return password
            """)

        self.assertNotIn("SLP006", [finding.code for finding in findings])

    def test_unchecked_subprocess_rule_finds_ignored_and_output_only_calls(
        self,
    ) -> None:
        findings = self.lint("""
            import subprocess as process
            from subprocess import run as launch

            def ignored():
                process.run(["worker"])

            def output_only():
                completed = launch(["worker"], check=False, capture_output=True)
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP009", "SLP009"])

    def test_unchecked_subprocess_rule_accepts_observed_and_delegated_results(
        self,
    ) -> None:
        findings = self.lint("""
            import subprocess as process
            from subprocess import run as launch

            def checked():
                process.run(["worker"], check=True)

            def inspected():
                completed = launch(["worker"])
                if completed.returncode:
                    raise RuntimeError("worker failed")

            def checked_later():
                completed = launch(["worker"])
                completed.check_returncode()

            def delegated():
                return launch(["worker"])

            def shadowed(process):
                return process.run(["worker"])
            """)

        self.assertNotIn("SLP009", [finding.code for finding in findings])

    def test_network_rules_find_missing_timeout_and_unchecked_status(self) -> None:
        findings = self.lint("""
            import requests as req
            from httpx import get as fetch
            from urllib.request import urlopen as open_url

            def load():
                response = req.get("https://service.test", timeout=None)
                document = fetch("https://service.test").json()
                raw = open_url("https://service.test")
                return response.text, document, raw
            """)

        self.assert_codes(
            findings,
            ["SLP010", "SLP011", "SLP010", "SLP011", "SLP010"],
        )
        self.assertIn("sets it to None", findings[0].message)

    def test_network_rules_accept_bounded_checked_and_delegated_calls(self) -> None:
        findings = self.lint("""
            import requests as req
            from httpx import post
            from urllib.request import urlopen as open_url

            DEFAULT_TIMEOUT = 10

            def load():
                response = req.get("https://service.test", timeout=5)
                response.raise_for_status()

                other = post("https://service.test", timeout=DEFAULT_TIMEOUT)
                if other.status_code >= 400:
                    raise RuntimeError("request failed")

                with open_url("https://service.test", None, 5) as stream:
                    return stream.read()

            def delegated():
                return req.get("https://service.test", timeout=5)

            def shadowed(req):
                return req.get("https://service.test")
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP010", codes)
        self.assertNotIn("SLP011", codes)

    def test_network_rules_ignore_async_httpx_client(self) -> None:
        findings = self.lint("""
            import httpx

            async def load():
                response = await httpx.AsyncClient().get("https://service.test")
                return response.json()
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP010", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_ignore_shadowed_imports(self) -> None:
        findings = self.lint("""
            import requests

            requests = LocalClient()
            requests.get("https://service.test")

            def load():
                import requests as client

                client = LocalClient()
                return client.get("https://service.test")
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP010", codes)
        self.assertNotIn("SLP011", codes)

    def test_http_status_rule_does_not_treat_printing_status_as_validation(
        self,
    ) -> None:
        findings = self.lint("""
            import requests

            response = requests.post("https://service.test", timeout=5)
            print(response.status_code)
            """)

        self.assert_codes(findings, ["SLP011"])

    def test_operational_rules_support_inline_suppression(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            subprocess.run(["best-effort"])  # noqa: SLP009
            requests.get("https://service.test", timeout=5)  # noqa: SLP011
            """)

        self.assert_codes(findings, [])

    def test_environment_path_rule_finds_unix_and_windows_user_paths(self) -> None:
        unix_path = "/Users/" + "alice/tool/cache.db"
        windows_path = "C:\\Users\\" + "alice\\tool\\cache.db"
        source = f"CACHE = {unix_path!r}\nDATA = {windows_path!r}\n"

        findings = self.lint(source)

        self.assert_codes(findings, ["SLP012", "SLP012"])

    def test_environment_path_rule_ignores_docs_and_portable_paths(self) -> None:
        documentation_path = "/Users/" + "alice/tool/cache.db"
        source = (
            f'"""{documentation_path} is an example path."""\n'  # noqa: SLP012
            "from pathlib import Path\n"
            'CACHE = Path.home() / "tool" / "cache.db"\n'
            'TEMPLATE = "/Users/{username}/tool/cache.db"\n'
            'SHELL_PATH = "/home/$USER/tool/cache.db"\n'
            'REMOTE = "https://example.test/home/alice/settings"\n'
        )

        findings = self.lint(source)

        self.assertNotIn("SLP012", [finding.code for finding in findings])

    def test_environment_path_rule_checks_local_file_urls(self) -> None:
        local_file = "file:///Users/" + "alice/tool/cache.db"

        findings = self.lint(f"CACHE = {local_file!r}\n")

        self.assert_codes(findings, ["SLP012"])

    def test_assertion_free_test_rule_requires_an_observable_oracle(self) -> None:
        findings = self.lint(
            """
            def test_smoke():
                run_workflow()

            def test_returning_a_value():
                return calculate()
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014"])

    def test_assertion_free_test_rule_accepts_common_test_oracles(self) -> None:
        findings = self.lint(
            """
            import pytest

            def test_value():
                assert calculate() == 42

            def test_failure():
                with pytest.raises(ValueError):
                    calculate("bad")

            def test_mock(mock):
                run_workflow(mock)
                mock.assert_called_once_with("done")
            """,
            path="tests/test_workflow.py",
        )

        self.assertNotIn("SLP014", [finding.code for finding in findings])

    def test_assertion_free_test_rule_accepts_outcome_decorators(self) -> None:
        findings = self.lint(
            """
            import pytest
            import unittest

            @unittest.expectedFailure
            def test_known_bug():
                run_workflow()

            @pytest.mark.xfail(reason="known bug")
            def test_other_known_bug():
                run_workflow()

            @unittest.skip("not supported")
            def test_skipped():
                run_workflow()
            """,
            path="tests/test_workflow.py",
        )

        self.assertNotIn("SLP014", [finding.code for finding in findings])

    def test_assertion_free_test_rule_ignores_non_test_modules_and_stubs(
        self,
    ) -> None:
        production = self.lint("""
            def test_named_helper():
                run_workflow()
            """)
        stub = self.lint(
            """
            def test_pending():
                pass
            """,
            path="tests/test_workflow.py",
        )

        self.assertNotIn("SLP014", [finding.code for finding in production])
        self.assert_codes(stub, ["SLP001"])

    def test_overridable_init_call_reports_same_class_dispatch(self) -> None:
        findings = self.lint("""
            class Loader:
                def __init__(instance):
                    instance.configure()

                def configure(instance):
                    instance.ready = True

            class InheritedHook:
                def __init__(self):
                    self.configure()
            """)

        dispatch = [finding for finding in findings if finding.code == "SLP015"]
        self.assertEqual(len(dispatch), 1)
        self.assertIn("Loader.__init__", dispatch[0].message)
        self.assertIn("configure", dispatch[0].message)

    def test_overridable_init_call_accepts_non_overridable_and_deferred_calls(
        self,
    ) -> None:
        findings = self.lint("""
            from typing import final as sealed

            def replacement(instance):
                instance.ready = True

            @sealed
            class Closed:
                def __init__(self):
                    self.prepare()

                def prepare(self):
                    self.ready = True

            class FixedHook:
                def __init__(self):
                    self.prepare()

                @sealed
                def prepare(self):
                    self.ready = True

            class PrivateHook:
                def __init__(owner):
                    owner.__prepare()
                    owner.__repr__()

                def __prepare(owner):
                    owner.ready = True

                def __repr__(owner):
                    return "PrivateHook"

            class DeferredHook:
                def __init__(self):
                    def later():
                        self.prepare()

                    self.later = later

                def prepare(self):
                    self.ready = True

            class ReboundHook:
                def __init__(self):
                    self.prepare()

                def prepare(self):
                    self.ready = True

                prepare = replacement
            """)

        self.assertNotIn("SLP015", [finding.code for finding in findings])

    def test_overridable_init_call_supports_inline_suppression(self) -> None:
        findings = self.lint("""
            class FrameworkBase:
                def __init__(self):
                    self.register()  # noqa: SLP015

                def register(self):
                    self.ready = True
            """)

        self.assertNotIn("SLP015", [finding.code for finding in findings])

    def test_conditional_instance_state_reports_readable_missing_state(self) -> None:
        findings = self.lint("""
            class Connection:
                def __init__(owner, connected, skip):
                    if skip:
                        return
                    if connected:
                        owner.session = "ready"

                def send(owner):
                    return owner.session

            class RequiredState:
                def __init__(self, enabled):
                    if not enabled:
                        raise ValueError("disabled")
                    self.value = 1

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("Connection.session", state_findings[0].message)

    def test_conditional_instance_state_accepts_safe_initialization_patterns(
        self,
    ) -> None:
        findings = self.lint("""
            class CompleteBranches:
                def __init__(self, active):
                    if active:
                        self.state = "active"
                    else:
                        self.state = "idle"

                def read(self):
                    return self.state

            class DefaultFirst:
                def __init__(self, failed):
                    self.error = None
                    if failed:
                        self.error = "failed"

                def read(self):
                    return self.error

            class ClassFallback:
                label = "unknown"

                def __init__(self, label):
                    if label:
                        self.label = label

                def read(self):
                    return self.label

            class LocalInitialization:
                def __init__(self, seed):
                    if seed:
                        self.cache = {"seed": seed}

                def rebuild(self):
                    self.cache = {}
                    return self.cache

            class DefensiveLookup:
                def __init__(self, supplied):
                    if supplied:
                        self.optional = supplied

                def read(self):
                    if hasattr(self, "optional"):
                        return getattr(self, "optional")
                    return None

            class DynamicAttributes:
                def __init__(self, supplied):
                    if supplied:
                        self.dynamic = supplied

                def __getattr__(self, name):
                    return None

                def read(self):
                    return self.dynamic

            class ExhaustiveMatch:
                def __init__(self, mode):
                    match mode:
                        case "fast":
                            self.kind = "fast"
                        case _:
                            self.kind = "safe"

                def read(self):
                    return self.kind
            """)

        self.assertNotIn("SLP016", [finding.code for finding in findings])

    def test_conditional_instance_state_handles_returning_try(self) -> None:
        findings = self.lint("""
            class ReturningTry:
                def __init__(self):
                    try:
                        self.value = 1
                        return
                    finally:
                        audit()

                def read(self):
                    return self.value
            """)

        self.assertNotIn("SLP016", [finding.code for finding in findings])

    def test_conditional_instance_state_accepts_method_fallback(self) -> None:
        findings = self.lint("""
            class Handler:
                def __init__(self, replacement):
                    if replacement is not None:
                        self.handle = replacement

                def handle(self, value):
                    return value

                def run(self, value):
                    return self.handle(value)
            """)

        self.assertNotIn("SLP016", [finding.code for finding in findings])

    def test_conditional_instance_state_supports_inline_suppression(self) -> None:
        findings = self.lint("""
            class ExternalHydration:
                def __init__(self, hydrated):
                    if hydrated:
                        self.value = hydrated

                def read(self):
                    return self.value  # noqa: SLP016
            """)

        self.assertNotIn("SLP016", [finding.code for finding in findings])

    def test_conditional_instance_state_suppression_is_line_scoped(self) -> None:
        findings = self.lint("""
            class ExternalHydration:
                def __init__(self, hydrated):
                    if hydrated:
                        self.value = hydrated

                def optional_read(self):
                    return self.value  # noqa: SLP016

                def required_read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertEqual(state_findings[0].line, 11)

    def test_shared_mutable_class_state_reports_instance_mutations(self) -> None:
        findings = self.lint("""
            class Registry:
                entries = []
                cache = {}
                flags = set()

                def add(owner, item):
                    owner.entries.append(item)
                    owner.cache[item] = True
                    owner.flags |= {item}

            class SometimesLocal:
                values = []

                def __init__(self, isolated):
                    if isolated:
                        self.values = []

                def add(self, value):
                    self.values.append(value)
            """)

        mutations = [finding for finding in findings if finding.code == "SLP017"]
        self.assertEqual(len(mutations), 4)
        self.assertTrue(
            all("shared mutable class state" in item.message for item in mutations)
        )

    def test_shared_mutable_class_state_accepts_intentional_and_local_state(
        self,
    ) -> None:
        findings = self.lint("""
            from typing import ClassVar as Shared

            class Registry:
                global_entries: Shared[list[str]] = []
                entries = []
                cache = {}
                flags = set()

                def __init__(owner):
                    owner.entries = []
                    owner.cache = {}
                    owner.flags = set()

                def add(owner, item):
                    owner.global_entries.append(item)
                    owner.entries.append(item)
                    owner.cache[item] = True
                    owner.flags.add(item)

            class ExplicitClassMutation:
                entries = []

                def add(self, item):
                    ExplicitClassMutation.entries.append(item)

            class LocalReset:
                entries = []

                def rebuild(self, item):
                    self.entries = []
                    self.entries.append(item)

            class ReboundContainer:
                entries = []
                entries = Bucket()

                def add(self, item):
                    self.entries.append(item)

            class ExternalBinding:
                target.entries = []

                def add(self, item):
                    self.entries.append(item)
            """)

        self.assertNotIn("SLP017", [finding.code for finding in findings])

    def test_shared_mutable_class_state_supports_inline_suppression(self) -> None:
        findings = self.lint("""
            class LegacyRegistry:
                entries = []

                def add(self, item):
                    self.entries.append(item)  # noqa: SLP017
            """)

        self.assertNotIn("SLP017", [finding.code for finding in findings])

    def test_shared_mutable_class_state_deduplicates_finally_paths(self) -> None:
        findings = self.lint("""
            class AuditLog:
                entries = []

                def record(self, item, early):
                    try:
                        if early:
                            return
                    finally:
                        self.entries.append(item)
            """)

        mutations = [finding for finding in findings if finding.code == "SLP017"]
        self.assertEqual(len(mutations), 1)

    def test_shared_mutable_class_state_ignores_shadowed_constructors(self) -> None:
        findings = self.lint("""
            from custom_containers import list

            class ImportedFactory:
                entries = list()

                def add(self, item):
                    self.entries.append(item)

            class LocalFactory:
                def set():
                    return Bucket()

                entries = set()

                def add(self, item):
                    self.entries.add(item)
            """)

        self.assertNotIn("SLP017", [finding.code for finding in findings])

    def test_class_rules_resolve_enclosing_function_aliases(self) -> None:
        findings = self.lint("""
            def build_types():
                from typing import ClassVar as Shared
                from typing import final as sealed

                @sealed
                class Closed:
                    def __init__(self):
                        self.prepare()

                    def prepare(self):
                        self.ready = True

                class Registry:
                    entries: Shared[list[str]] = []

                    def add(self, item):
                        self.entries.append(item)

                return Closed, Registry
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP015", codes)
        self.assertNotIn("SLP017", codes)

    def test_narrating_comment_cluster_is_reported_once(self) -> None:
        findings = self.lint("""
            def normalize(items):
                # Initialize the result list
                result = []
                # Loop through each item
                for item in items:
                    result.append(item.strip())
                # Return the result
                return result
            """)

        self.assert_codes(findings, ["SLP007"])
        self.assertIn("3 narrating comments", findings[0].message)

    def test_oversized_function_uses_configured_threshold(self) -> None:
        findings = self.lint(
            """
            def calculate(value):
                first = value + 1
                second = first * 2
                third = second - 3
                return third
            """,
            max_function_lines=4,
        )

        self.assert_codes(findings, ["SLP008"])

    def test_explicit_inline_and_file_suppressions(self) -> None:
        inline = self.lint("""
            def pending():  # noqa: SLP001
                pass
            """)
        slop_inline = self.lint("""
            def pending():  # slop: ignore [SLP001]
                pass
            """)
        whole_file = self.lint("""
            # slop: ignore-file
            def pending():
                pass
            """)

        self.assert_codes(inline, [])
        self.assert_codes(slop_inline, [])
        self.assert_codes(whole_file, [])

    def test_bare_noqa_does_not_suppress_a_finding(self) -> None:
        findings = self.lint("""
            def pending():  # noqa
                pass
            """)

        self.assert_codes(findings, ["SLP001"])

    def test_unrelated_noqa_code_does_not_suppress_a_finding(self) -> None:
        findings = self.lint("""
            def pending():  # noqa: F401
                pass
            """)

        self.assert_codes(findings, ["SLP001"])

    def test_comment_text_inside_string_does_not_suppress_a_finding(self) -> None:
        findings = self.lint("""
            def pending(note="# noqa: SLP001"):
                pass
            """)

        self.assert_codes(findings, ["SLP001"])

    def test_ignore_file_text_inside_string_does_not_suppress_findings(self) -> None:
        findings = self.lint("""
            BANNER = "# slop: ignore-file"

            def pending():
                pass
            """)

        self.assert_codes(findings, ["SLP001"])

    def test_ignore_file_directive_must_be_in_first_five_lines(self) -> None:
        findings = self.lint("""
            # header 1
            # header 2
            # header 3
            # header 4
            # header 5
            # slop: ignore-file
            def pending():
                pass
            """)

        self.assert_codes(findings, ["SLP001"])

    def test_syntax_errors_are_findings(self) -> None:
        findings = self.lint("def broken(:\n")

        self.assert_codes(findings, ["SLP000"])
        self.assertEqual(findings[0].severity, "error")


class DiscoveryTests(unittest.TestCase):
    def test_directory_discovery_handles_spaces_and_exclusions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pyclichecker test ") as directory:
            root = Path(directory)
            source = root / "source dir"
            source.mkdir()
            (source / "included.py").write_text("value = 1\n", encoding="utf-8")
            (source / "skip_generated.py").write_text(
                "value = 1\n",
                encoding="utf-8",
            )
            venv = source / ".venv"
            venv.mkdir()
            (venv / "ignored.py").write_text("value = 1\n", encoding="utf-8")

            files, use_stdin, errors = pyclichecker.discover_python_files(
                [str(source)],
                exclude_patterns=("*generated.py",),
            )

        self.assertEqual([path.name for path in files], ["included.py"])
        self.assertFalse(use_stdin)
        self.assertEqual(errors, [])

    def test_duplicate_inputs_are_checked_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.py"
            source.write_text("value = 1\n", encoding="utf-8")

            files, use_stdin, errors = pyclichecker.discover_python_files(
                [str(source), str(root)],
            )

        self.assertEqual(files, [source])
        self.assertFalse(use_stdin)
        self.assertEqual(errors, [])

    def test_missing_and_non_python_paths_are_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            text_file = Path(directory) / "notes.txt"
            text_file.write_text("not Python\n", encoding="utf-8")
            files, use_stdin, errors = pyclichecker.discover_python_files(
                [str(text_file), str(Path(directory) / "missing.py")]
            )

        self.assertEqual(files, [])
        self.assertFalse(use_stdin)
        self.assertEqual(len(errors), 2)


class CliTests(unittest.TestCase):
    def run_main(
        self,
        arguments: list[str],
        *,
        stdin: str | None = None,
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        input_stream = io.StringIO(stdin) if stdin is not None else None
        with (
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            patch("sys.stdin", input_stream) if input_stream else patch("sys.stdin"),
        ):
            exit_code = pyclichecker.main(arguments)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_cli_exit_codes_for_clean_findings_and_operational_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = root / "clean.py"
            dirty = root / "dirty.py"
            clean.write_text(
                "def identity(value):\n    return value\n",
                encoding="utf-8",
            )
            dirty.write_text("def unfinished():\n    pass\n", encoding="utf-8")

            clean_result = self.run_main([str(clean)])
            dirty_result = self.run_main([str(dirty)])
            missing_result = self.run_main([str(root / "missing.py")])

        self.assertEqual(clean_result[0], pyclichecker.EXIT_CLEAN)
        self.assertEqual(dirty_result[0], pyclichecker.EXIT_FINDINGS)
        self.assertIn("SLP001", dirty_result[1])
        self.assertEqual(missing_result[0], pyclichecker.EXIT_OPERATIONAL_ERROR)
        self.assertIn("path does not exist", missing_result[2])

    def test_empty_directory_is_an_operational_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exit_code, output, error = self.run_main([directory])

        self.assertEqual(exit_code, pyclichecker.EXIT_OPERATIONAL_ERROR)
        self.assertEqual(output, "")
        self.assertIn("no Python files found", error)

    def test_json_output_is_structured_and_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pyclichecker json ") as directory:
            path = Path(directory) / "sample file.py"
            path.write_text("async def fake():\n    return 1\n", encoding="utf-8")

            exit_code, output, error = self.run_main([str(path), "--format", "json"])
            payload = json.loads(output)

        self.assertEqual(exit_code, pyclichecker.EXIT_FINDINGS)
        self.assertEqual(error, "")
        self.assertEqual(payload["version"], pyclichecker.VERSION)
        self.assertEqual(payload["files_checked"], 1)
        self.assertEqual(payload["findings"][0]["code"], "SLP004")
        self.assertEqual(payload["errors"], [])

    def test_fail_on_error_allows_warning_only_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.py"
            path.write_text("async def fake():\n    return 1\n", encoding="utf-8")

            exit_code, output, error = self.run_main([str(path), "--fail-on", "error"])

        self.assertEqual(exit_code, pyclichecker.EXIT_CLEAN)
        self.assertIn("SLP004", output)
        self.assertEqual(error, "")

    def test_standard_input_is_linted_without_files(self) -> None:
        exit_code, output, error = self.run_main(
            ["-"],
            stdin="def pending():\n    pass\n",
        )

        self.assertEqual(exit_code, pyclichecker.EXIT_FINDINGS)
        self.assertIn("<stdin>:1:1: SLP001", output)
        self.assertEqual(error, "")

    def test_package_version_matches_distribution_metadata(self) -> None:
        self.assertEqual(pyclichecker.VERSION, version("pyclichecker"))

    def test_distribution_metadata_is_public_ready(self) -> None:
        package_metadata = metadata("pyclichecker")

        self.assertEqual(package_metadata["License-Expression"], "MIT")
        self.assertIn("LICENSE", package_metadata.get_all("License-File", []))
        self.assertEqual(package_metadata["Author"], "Ken Harrison")
        self.assertIn(
            "Repository, https://github.com/ktreharrison/pyclichecker",
            package_metadata.get_all("Project-URL", []),
        )


if __name__ == "__main__":
    unittest.main()
