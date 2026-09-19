import io
import json
import re
import tempfile
import textwrap
import tomllib
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

    def test_placeholder_rule_resolves_aliased_contract_declarations(self) -> None:
        findings = self.lint("""
            import abc as contracts
            import typing as types
            from abc import abstractmethod as required
            from typing import Protocol as Contract

            class Abstract:
                @required
                def first(self):
                    ...

                @contracts.abstractmethod
                def second(self):
                    pass

                @types.overload
                def overloaded(self, value: int) -> int:
                    ...

            class Interface(Contract):
                def execute(self):
                    pass
            """)

        self.assertNotIn("SLP001", [finding.code for finding in findings])

    def test_placeholder_rule_does_not_trust_shadowed_protocol_names(self) -> None:
        findings = self.lint("""
            class Protocol:
                pass

            class Concrete(Protocol):
                def unfinished(self):
                    pass
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertIn("Concrete.unfinished", findings[0].message)

    def test_placeholder_rule_tracks_class_scope_decorator_aliases(self) -> None:
        findings = self.lint("""
            from abc import abstractmethod as contract
            from typing import Protocol

            class Abstract:
                from abc import abstractmethod as local_contract

                @local_contract
                def required(self):
                    pass

            class Concrete:
                contract = lambda function: function

                @contract
                def unfinished(self):
                    pass

            class SameName:
                @contract
                def contract(self):
                    pass

            class Outer:
                class Protocol(Protocol):
                    def required(self):
                        pass
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertIn("Concrete.unfinished", findings[0].message)

    def test_placeholder_rule_tracks_bindings_inside_class_control_flow(
        self,
    ) -> None:
        findings = self.lint("""
            from abc import abstractmethod as contract

            class Conditional:
                if True:
                    contract = lambda function: function

                @contract
                def unfinished(self):
                    pass

            class NestedScope:
                class Inner:
                    contract = lambda function: function

                @contract
                def required(self):
                    pass
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertIn("Conditional.unfinished", findings[0].message)

    def test_placeholder_rule_tracks_module_aliases_in_definition_order(
        self,
    ) -> None:
        findings = self.lint("""
            from abc import abstractmethod
            from typing import Protocol

            class EarlyContract(Protocol):
                def required(self):
                    pass

            class EarlyAbstract:
                @abstractmethod
                def required(self):
                    pass

            Protocol = object
            abstractmethod = lambda function: function

            class LateContract(Protocol):
                def required(self):
                    pass

            class LateConcrete:
                @abstractmethod
                def required(self):
                    pass
            """)

        self.assert_codes(findings, ["SLP001", "SLP001"])
        self.assertIn("LateContract.required", findings[0].message)
        self.assertIn("LateConcrete.required", findings[1].message)

    def test_placeholder_rule_resolves_contract_imports_inside_control_flow(
        self,
    ) -> None:
        findings = self.lint("""
            try:
                from typing import Protocol
            except ImportError:
                from typing_extensions import Protocol

            class Interface(Protocol):
                def required(self):
                    pass

            class Abstract:
                try:
                    from abc import abstractmethod as contract
                except ImportError:
                    contract = lambda function: function

                @contract
                def required(self):
                    pass
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertIn("Abstract.required", findings[0].message)

    def test_placeholder_rule_tracks_branch_local_contract_imports(self) -> None:
        findings = self.lint("""
            if module_contracts_enabled:
                from typing import Protocol

                class ModuleContract(Protocol):
                    def required(self):
                        pass

            class Container:
                if class_contracts_enabled:
                    from abc import abstractmethod as contract

                    @contract
                    def required(self):
                        pass
            """)

        self.assertNotIn("SLP001", [finding.code for finding in findings])

    def test_placeholder_rule_rejects_conflicting_branch_bindings(self) -> None:
        findings = self.lint("""
            if contracts_enabled:
                from typing import Protocol as Base
            else:
                class Base:
                    pass

            class Concrete(Base):
                def required(self):
                    pass
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertIn("Concrete.required", findings[0].message)

    def test_placeholder_rule_preserves_annotation_only_contract_aliases(self) -> None:
        findings = self.lint("""
            from abc import abstractmethod
            from typing import Protocol

            Protocol: type

            class Interface(Protocol):
                def required(self):
                    pass

            class Abstract:
                abstractmethod: object

                @abstractmethod
                def required(self):
                    pass
            """)

        self.assertNotIn("SLP001", [finding.code for finding in findings])

    def test_placeholder_rule_merges_custom_context_manager_paths(self) -> None:
        findings = self.lint("""
            with custom_manager():
                from typing import Protocol

            class ConditionalContract(Protocol):
                def required(self):
                    pass
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertEqual(findings[0].line, 6)
        self.assertIn("ConditionalContract.required", findings[0].message)

    def test_placeholder_rule_excludes_terminal_alias_paths(self) -> None:
        findings = self.lint("""
            if enabled:
                from typing import Protocol
            else:
                raise RuntimeError("disabled")

            class IfContract(Protocol):
                def required(self):
                    pass

            try:
                from abc import abstractmethod
            except ImportError:
                raise

            class TryContract:
                @abstractmethod
                def required(self):
                    pass

            match mode:
                case "enabled":
                    from typing import Protocol as MatchProtocol
                case _:
                    raise RuntimeError("disabled")

            class MatchContract(MatchProtocol):
                def required(self):
                    pass
            """)

        self.assertNotIn("SLP001", [finding.code for finding in findings])

    def test_placeholder_rule_tracks_irrefutable_match_aliases(self) -> None:
        findings = self.lint("""
            match value:
                case _ if True:
                    from typing import Protocol as Contract
                case _:
                    Contract = object

            class Service(Contract):
                def run(self):
                    pass
            """)

        self.assertNotIn("SLP001", [finding.code for finding in findings])

    def test_placeholder_rule_tracks_guaranteed_loop_aliases(self) -> None:
        findings = self.lint("""
            while True:
                from typing import Protocol as WhileContract
                break

            for marker in [1]:
                from typing import Protocol as ForContract

            for marker in maybe_empty:
                from typing import Protocol as MaybeContract

            class WhileService(WhileContract):
                def run(self):
                    pass

            class ForService(ForContract):
                def run(self):
                    pass

            class MaybeService(MaybeContract):
                def run(self):
                    pass
            """)

        self.assert_codes(findings, ["SLP001"])
        self.assertIn("MaybeService.run", findings[0].message)

    def test_placeholder_rule_keeps_loop_exit_alias_states_separate(self) -> None:
        findings = self.lint("""
            WhileContract = object
            while True:
                if enabled:
                    break
                from typing import Protocol as WhileContract
                break

            ContinueContract = object
            for marker in [1]:
                if enabled:
                    continue
                from typing import Protocol as ContinueContract

            while True:
                if False:
                    break
                from typing import Protocol as SafeContract
                break

            class WhileService(WhileContract):
                def run(self):
                    pass

            class ContinueService(ContinueContract):
                def run(self):
                    pass

            class SafeService(SafeContract):
                def run(self):
                    pass
            """)

        placeholder_findings = [
            finding for finding in findings if finding.code == "SLP001"
        ]
        self.assertEqual(len(placeholder_findings), 2)
        self.assertEqual(
            {
                name
                for name in (
                    "ContinueService.run",
                    "SafeService.run",
                    "WhileService.run",
                )
                if any(name in finding.message for finding in placeholder_findings)
            },
            {"ContinueService.run", "WhileService.run"},
        )

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

    def test_broad_exception_rule_resolves_builtin_identity(self) -> None:
        findings = self.lint("""
            from builtins import Exception as BroadFailure
            from custom_errors import Exception as CustomFailure

            class Exception:
                pass

            try:
                risky()
            except BroadFailure:
                recover()

            try:
                risky()
            except CustomFailure:
                recover()

            try:
                risky()
            except Exception:
                recover()
            """)

        broad_findings = [finding for finding in findings if finding.code == "SLP003"]
        self.assertEqual(len(broad_findings), 1)
        self.assertEqual(broad_findings[0].line, 10)

    def test_broad_exception_rule_requires_every_path_to_reraise(self) -> None:
        findings = self.lint("""
            def partial(value, preserve):
                try:
                    return int(value)
                except Exception:
                    if preserve:
                        raise
                    return 0

            def complete(value, preserve):
                try:
                    return int(value)
                except Exception:
                    if preserve:
                        raise
                    else:
                        raise RuntimeError("conversion failed")

            def nested(value):
                try:
                    return int(value)
                except Exception:
                    try:
                        raise
                    finally:
                        record_failure()
            """)

        self.assert_codes(findings, ["SLP003"])

    def test_broad_exception_rule_preserves_nested_handler_reraises(self) -> None:
        findings = self.lint("""
            def preserve(value):
                try:
                    return int(value)
                except Exception as error:
                    try:
                        raise ValueError(str(error))
                    except ValueError as converted:
                        record_failure(converted)
                        raise RuntimeError("conversion failed") from converted

            def fallback(value):
                try:
                    return int(value)
                except Exception as error:
                    try:
                        raise ValueError(str(error))
                    except ValueError:
                        return 0
            """)

        self.assert_codes(findings, ["SLP003"])
        self.assertIn("fallback", findings[0].message)

    def test_broad_exception_rule_folds_constant_truthiness(self) -> None:
        findings = self.lint("""
            def always_reraise(value):
                try:
                    return int(value)
                except Exception:
                    if 1:
                        raise
                    return 0

            def never_reraise(value):
                try:
                    return int(value)
                except Exception:
                    if 0:
                        raise
                    return 0
            """)

        self.assert_codes(findings, ["SLP003"])

    def test_broad_exception_rule_ignores_false_loop_bodies(self) -> None:
        findings = self.lint("""
            def preserve_failure(value):
                try:
                    return int(value)
                except Exception:
                    while 0:
                        return 0
                    raise
            """)

        self.assertNotIn("SLP003", [finding.code for finding in findings])

    def test_broad_exception_rule_filters_unreachable_handlers(self) -> None:
        findings = self.lint("""
            def preserves_failure(value):
                try:
                    return int(value)
                except Exception:
                    try:
                        raise TypeError("stop")
                    except ValueError:
                        return 0

            def converts_failure(value):
                try:
                    return int(value)
                except Exception:
                    try:
                        raise ValueError("fallback")
                    except ValueError:
                        return 0
            """)

        self.assert_codes(findings, ["SLP003"])

    def test_broad_exception_rule_tracks_reachable_match_cases(self) -> None:
        findings = self.lint("""
            def false_guard(value):
                try:
                    risky()
                except Exception:
                    match value:
                        case _ if False:
                            return
                        case _:
                            raise

            def captured_wildcard(value):
                try:
                    risky()
                except Exception:
                    match value:
                        case _ as captured:
                            raise

            def true_guard(value):
                try:
                    risky()
                except Exception:
                    match value:
                        case _ if True:
                            raise
                        case _:
                            return

            def conditional_guard(value, preserve):
                try:
                    risky()
                except Exception:
                    match value:
                        case _ if preserve:
                            raise
                        case _:
                            return
            """)

        self.assert_codes(findings, ["SLP003"])
        self.assertEqual(findings[0].line, 33)

    def test_broad_exception_rule_consumes_loop_local_exits(self) -> None:
        findings = self.lint("""
            def continue_then_raise(value):
                try:
                    return int(value)
                except Exception:
                    for item in [value]:
                        continue
                    raise

            def break_then_raise(value):
                try:
                    return int(value)
                except Exception:
                    while value:
                        break
                    raise
            """)

        self.assertNotIn("SLP003", [finding.code for finding in findings])

    def test_broad_exception_rule_models_contextlib_suppress(self) -> None:
        findings = self.lint("""
            import contextlib as contexts
            from contextlib import suppress as ignore

            def suppress_module_alias(value):
                try:
                    return int(value)
                except Exception:
                    with contexts.suppress(Exception):
                        raise

            def suppress_import_alias(value):
                try:
                    return int(value)
                except Exception:
                    with ignore(Exception):
                        raise

            def ordinary_context(value, lock):
                try:
                    return int(value)
                except Exception:
                    with lock:
                        raise

            def shadowed_suppress(value, ignore):
                try:
                    return int(value)
                except Exception:
                    with ignore(Exception):
                        raise
            """)

        self.assert_codes(findings, ["SLP003", "SLP003"])

    def test_broad_exception_rule_respects_suppressed_exception_types(self) -> None:
        preserved = self.lint("""
            import contextlib

            def preserved():
                try:
                    work()
                except Exception:
                    with contextlib.suppress(ValueError):
                        raise TypeError("preserved")
            """)
        swallowed = self.lint("""
            import contextlib

            def swallowed():
                try:
                    work()
                except Exception:
                    with contextlib.suppress(Exception):
                        raise TypeError("swallowed")
            """)

        self.assertNotIn("SLP003", [finding.code for finding in preserved])
        self.assert_codes(swallowed, ["SLP003"])
        self.assertEqual(swallowed[0].line, 7)

    def test_broad_exception_rule_propagates_loop_else_control(self) -> None:
        findings = self.lint("""
            def fallback(value):
                try:
                    return int(value)
                except Exception:
                    while True:
                        for item in []:
                            pass
                        else:
                            break
                        raise
                    return 0
            """)

        self.assert_codes(findings, ["SLP003"])

    def test_empty_exception_rule_includes_constant_only_handlers(self) -> None:
        findings = self.lint("""
            def ignored(value):
                try:
                    return int(value)
                except ValueError:
                    "ignored"
            """)

        self.assert_codes(findings, ["SLP002"])

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

            def checked_after_context(lock):
                with lock:
                    completed = launch(["worker"])
                completed.check_returncode()
                return completed.stdout

            def checked_through_alias():
                completed = launch(["worker"])
                returncode = completed.returncode
                if returncode:
                    raise RuntimeError("worker failed")
                return completed.stdout

            def checked_in_every_branch(strict):
                completed = launch(["worker"], capture_output=True)
                if strict:
                    completed.check_returncode()
                else:
                    completed.check_returncode()
                return completed.stdout

            def delegated():
                return launch(["worker"])

            def shadowed(process):
                return process.run(["worker"])
            """)

        self.assertNotIn("SLP009", [finding.code for finding in findings])

    def test_unchecked_subprocess_rule_rejects_conditional_or_late_checks(
        self,
    ) -> None:
        findings = self.lint("""
            import subprocess

            def conditional(strict):
                completed = subprocess.run(["worker"])
                if strict:
                    completed.check_returncode()

            def consumed_first():
                completed = subprocess.run(["worker"], capture_output=True)
                print(completed.stdout)
                completed.check_returncode()

            def ignored_observation():
                completed = subprocess.run(["worker"], capture_output=True)
                returncode = completed.returncode
                return completed.stdout

            def checked_after_loop(values):
                for value in values:
                    completed = subprocess.run([value], capture_output=True)
                completed.check_returncode()
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP009", "SLP009", "SLP009", "SLP009"])

    def test_unchecked_subprocess_rule_rejects_unchecked_terminal_paths(
        self,
    ) -> None:
        findings = self.lint("""
            import contextlib as contexts
            import subprocess

            def suppressed_raise(strict):
                completed = subprocess.run(["worker"])
                if strict:
                    completed.check_returncode()
                else:
                    with contexts.suppress(Exception):
                        raise RuntimeError("ignored")
                return completed.stdout

            def early_return(strict):
                completed = subprocess.run(["worker"])
                if strict:
                    completed.check_returncode()
                else:
                    return None
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP009", "SLP009"])

    def test_unchecked_subprocess_rule_accepts_checked_or_raising_paths(
        self,
    ) -> None:
        findings = self.lint("""
            import subprocess

            def checked_or_raising(strict):
                completed = subprocess.run(["worker"])
                if strict:
                    completed.check_returncode()
                else:
                    raise RuntimeError("aborted")
                return completed.stdout
            """)

        self.assertNotIn("SLP009", [finding.code for finding in findings])

    def test_subprocess_rule_models_nested_suppressed_raises(self) -> None:
        findings = self.lint("""
            import contextlib
            import subprocess

            def unchecked(strict):
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(Exception):
                    if strict:
                        completed.check_returncode()
                    else:
                        raise RuntimeError("ignored")
                return completed.stdout

            def checked(strict):
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(Exception):
                    if strict:
                        completed.check_returncode()
                    else:
                        completed.check_returncode()
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP009", "SLP009"])
        self.assertEqual([finding.line for finding in findings], [6, 15])

    def test_subprocess_rule_accepts_numeric_returncode_matches(self) -> None:
        findings = self.lint("""
            import subprocess
            import settings

            def matched():
                completed = subprocess.run(["worker"], capture_output=True)
                returncode = completed.returncode
                match returncode:
                    case 0:
                        pass
                    case _:
                        raise RuntimeError("worker failed")
                return completed.stdout

            def compared():
                completed = subprocess.run(["worker"], capture_output=True)
                returncode = completed.returncode
                if returncode != 0:
                    raise RuntimeError("worker failed")
                return completed.stdout

            def configured_success():
                completed = subprocess.run(["worker"], capture_output=True)
                if completed.returncode != settings.SUCCESS:
                    raise RuntimeError("worker failed")
                return completed.stdout

            def derived_configured_success():
                completed = subprocess.run(["worker"], capture_output=True)
                success = completed.returncode == settings.SUCCESS
                if not success:
                    raise RuntimeError("worker failed")
                return completed.stdout
            """)

        self.assertNotIn("SLP009", [finding.code for finding in findings])

    def test_subprocess_rule_rejects_boolean_returncode_matches(self) -> None:
        findings = self.lint("""
            import subprocess

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                returncode = completed.returncode
                match returncode:
                    case True:
                        pass
                    case False:
                        raise RuntimeError("worker failed")
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP009"])

    def test_subprocess_rule_rejects_nonsemantic_returncode_checks(self) -> None:
        findings = self.lint("""
            import subprocess

            def existence_check():
                completed = subprocess.run(["worker"], capture_output=True)
                if completed.returncode is not None:
                    return completed.stdout

            def printed_check():
                completed = subprocess.run(["worker"], capture_output=True)
                print(completed.returncode)
                return completed.stdout

            def wildcard_match():
                completed = subprocess.run(["worker"], capture_output=True)
                match completed.returncode:
                    case _:
                        pass
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP009", "SLP009", "SLP009"])

    def test_subprocess_rule_preserves_derived_returncode_polarity(self) -> None:
        handled = self.lint("""
            import subprocess

            def checked_success():
                completed = subprocess.run(["worker"], capture_output=True)
                success = completed.returncode == 0
                if not success:
                    raise RuntimeError("worker failed")
                return completed.stdout

            def checked_failure():
                completed = subprocess.run(["worker"], capture_output=True)
                failed = completed.returncode != 0
                if failed:
                    raise RuntimeError("worker failed")
                return completed.stdout
            """)
        unsafe = self.lint("""
            import subprocess

            def inverted():
                completed = subprocess.run(["worker"], capture_output=True)
                success = completed.returncode == 0
                if success:
                    raise RuntimeError("wrong branch")
                return completed.stdout

            def transformed():
                completed = subprocess.run(["worker"], capture_output=True)
                shifted = completed.returncode + 1
                if shifted:
                    raise RuntimeError("not a status check")
                return completed.stdout
            """)

        self.assertNotIn("SLP009", [finding.code for finding in handled])
        self.assert_codes(unsafe, ["SLP009", "SLP009"])
        self.assertEqual([finding.line for finding in unsafe], [5, 12])

    def test_subprocess_rule_requires_success_only_continuation(self) -> None:
        handled = self.lint("""
            import subprocess

            def branch():
                completed = subprocess.run(["worker"], capture_output=True)
                if completed.returncode:
                    raise RuntimeError("worker failed")
                return completed.stdout

            def assertion():
                completed = subprocess.run(["worker"], capture_output=True)
                assert completed.returncode == 0
                return completed.stdout

            def inline_branch():
                if subprocess.run(["worker"]).returncode:
                    raise RuntimeError("worker failed")
            """)
        unsafe = self.lint("""
            import subprocess

            def no_op_branch():
                completed = subprocess.run(["worker"], capture_output=True)
                if completed.returncode == 0:
                    log("ok")
                return completed.stdout

            def inverted_assertion():
                completed = subprocess.run(["worker"], capture_output=True)
                assert completed.returncode != 0
                return completed.stdout

            def aliased_no_op_branch():
                completed = subprocess.run(["worker"], capture_output=True)
                returncode = completed.returncode
                if returncode == 0:
                    log("ok")
                return completed.stdout

            def inline_no_op_branch():
                if subprocess.run(["worker"]).returncode == 0:
                    log("ok")
            """)

        self.assertNotIn("SLP009", [finding.code for finding in handled])
        self.assert_codes(unsafe, ["SLP009", "SLP009", "SLP009", "SLP009"])
        self.assertEqual([finding.line for finding in unsafe], [5, 11, 16, 23])

    def test_operational_checks_reject_swallowed_validation_errors(self) -> None:
        preserved = self.lint("""
            import contextlib
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(ValueError):
                    response.raise_for_status()
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(ValueError):
                    completed.check_returncode()
                return completed.stdout
            """)
        swallowed = self.lint("""
            import contextlib
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(requests.RequestException):
                    response.raise_for_status()
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(subprocess.SubprocessError):
                    completed.check_returncode()
                return completed.stdout
            """)

        preserved_codes = [finding.code for finding in preserved]
        self.assertNotIn("SLP009", preserved_codes)
        self.assertNotIn("SLP011", preserved_codes)
        self.assert_codes(swallowed, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in swallowed], [7, 13])

    def test_operational_try_handlers_match_validation_errors(self) -> None:
        unrelated = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except ValueError:
                    log()
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    completed.check_returncode()
                except ValueError:
                    log()
                return completed.stdout
            """)
        swallowed = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except requests.RequestException:
                    log()
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    completed.check_returncode()
                except subprocess.SubprocessError:
                    log()
                return completed.stdout
            """)
        terminated = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except requests.RequestException:
                    return None
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    completed.check_returncode()
                except subprocess.SubprocessError:
                    return None
                return completed.stdout
            """)

        for findings in (unrelated, terminated):
            codes = [finding.code for finding in findings]
            self.assertNotIn("SLP009", codes)
            self.assertNotIn("SLP011", codes)
        self.assert_codes(swallowed, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in swallowed], [6, 14])

    def test_inline_validation_checks_follow_try_handlers(self) -> None:
        unrelated = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    requests.get(
                        "https://service.test",
                        timeout=5,
                    ).raise_for_status()
                except ValueError:
                    log()

            def run():
                try:
                    subprocess.run(["worker"]).check_returncode()
                except ValueError:
                    log()
            """)
        swallowed = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    requests.get(
                        "https://service.test",
                        timeout=5,
                    ).raise_for_status()
                except requests.RequestException:
                    log()

            def run():
                try:
                    subprocess.run(["worker"]).check_returncode()
                except subprocess.SubprocessError:
                    log()
            """)

        unrelated_codes = [finding.code for finding in unrelated]
        self.assertNotIn("SLP009", unrelated_codes)
        self.assertNotIn("SLP011", unrelated_codes)
        self.assert_codes(swallowed, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in swallowed], [7, 16])

    def test_operational_failure_branches_reject_suppressed_raises(self) -> None:
        preserved = self.lint("""
            import contextlib
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(ValueError):
                    if not response.ok:
                        raise RuntimeError("request failed")
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(ValueError):
                    if completed.returncode:
                        raise RuntimeError("worker failed")
                return completed.stdout

            def inline_fetch():
                with contextlib.suppress(ValueError):
                    if not requests.get("https://service.test", timeout=5).ok:
                        raise RuntimeError("request failed")

            def inline_run():
                with contextlib.suppress(ValueError):
                    if subprocess.run(["worker"]).returncode:
                        raise RuntimeError("worker failed")
            """)
        swallowed = self.lint("""
            import contextlib
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(ValueError):
                    if not response.ok:
                        raise ValueError("ignored")
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(ValueError):
                    if completed.returncode:
                        raise ValueError("ignored")
                return completed.stdout

            def inline_fetch():
                with contextlib.suppress(ValueError):
                    if not requests.get("https://service.test", timeout=5).ok:
                        raise ValueError("ignored")

            def inline_run():
                with contextlib.suppress(ValueError):
                    if subprocess.run(["worker"]).returncode:
                        raise ValueError("ignored")
            """)

        preserved_codes = [finding.code for finding in preserved]
        self.assertNotIn("SLP009", preserved_codes)
        self.assertNotIn("SLP011", preserved_codes)
        self.assert_codes(
            swallowed,
            ["SLP011", "SLP009", "SLP011", "SLP009"],
        )
        self.assertEqual(
            [finding.line for finding in swallowed],
            [7, 14, 22, 27],
        )

    def test_operational_matches_reject_suppressed_failure_raises(self) -> None:
        preserved = self.lint("""
            import contextlib
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(ValueError):
                    match response.ok:
                        case True:
                            pass
                        case False:
                            raise RuntimeError("request failed")
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(ValueError):
                    match completed.returncode:
                        case 0:
                            pass
                        case _:
                            raise RuntimeError("worker failed")
                return completed.stdout
            """)
        swallowed = self.lint("""
            import contextlib
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(ValueError):
                    match response.ok:
                        case True:
                            pass
                        case False:
                            raise ValueError("ignored")
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                with contextlib.suppress(ValueError):
                    match completed.returncode:
                        case 0:
                            pass
                        case _:
                            raise ValueError("ignored")
                return completed.stdout
            """)

        preserved_codes = [finding.code for finding in preserved]
        self.assertNotIn("SLP009", preserved_codes)
        self.assertNotIn("SLP011", preserved_codes)
        self.assert_codes(swallowed, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in swallowed], [7, 17])

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

    def test_http_status_rule_accepts_checks_after_nested_control_flow(
        self,
    ) -> None:
        findings = self.lint("""
            import contextlib
            import requests as req

            def checked_after_context(lock):
                with lock:
                    response = req.get("https://service.test", timeout=5)
                response.raise_for_status()
                return response.text

            def checked_after_branch(use_primary):
                if use_primary:
                    response = req.get("https://primary.test", timeout=5)
                else:
                    response = req.get("https://backup.test", timeout=5)
                response.raise_for_status()
                return response.text

            def checked_after_try(use_primary):
                try:
                    if not use_primary:
                        raise RuntimeError("use fallback")
                    response = req.get("https://primary.test", timeout=5)
                except RuntimeError:
                    response = req.get("https://backup.test", timeout=5)
                response.raise_for_status()
                return response.text

            def checked_after_finally():
                try:
                    response = req.get("https://service.test", timeout=5)
                finally:
                    audit_request()
                response.raise_for_status()
                return response.text

            def checked_after_suppressed_raise():
                response = req.get("https://service.test", timeout=5)
                with contextlib.suppress(Exception):
                    raise RuntimeError("ignored")
                response.raise_for_status()
                return response.text

            def checked_in_every_branch(strict):
                response = req.get("https://service.test", timeout=5)
                if strict:
                    response.raise_for_status()
                else:
                    response.raise_for_status()
                return response.text

            def checked_inside_try():
                response = req.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except RuntimeError:
                    raise
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in findings])

    def test_operational_rules_continue_after_raise_only_branches(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch(abort):
                response = requests.get("https://service.test", timeout=5)
                if abort:
                    raise RuntimeError("aborted")
                response.raise_for_status()
                return response.text

            def run(abort):
                completed = subprocess.run(["worker"])
                if abort:
                    raise RuntimeError("aborted")
                completed.check_returncode()
                return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_follow_matching_exception_handlers(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    raise RuntimeError("inspect")
                except RuntimeError:
                    response.raise_for_status()
                return response.text

            def run():
                try:
                    completed = subprocess.run(["worker"])
                    raise RuntimeError("inspect")
                except RuntimeError:
                    completed.check_returncode()
                return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_follow_builtin_exception_hierarchy(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    raise KeyError("inspect")
                except LookupError:
                    return response.text

            def run():
                try:
                    completed = subprocess.run(["worker"])
                    raise KeyError("inspect")
                except LookupError:
                    return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_do_not_apply_builtin_hierarchy_to_shadowed_names(
        self,
    ) -> None:
        findings = self.lint("""
            import requests

            class KeyError(Exception):
                pass

            class LookupError(KeyError):
                pass

            def fetch():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    raise LookupError("inspect")
                except KeyError:
                    return response.text
        """)

        self.assert_codes(findings, ["SLP011"])

    def test_operational_rules_distinguish_unrelated_builtin_handlers(
        self,
    ) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    raise TypeError("stop")
                except LookupError:
                    return response.text

            def run():
                try:
                    completed = subprocess.run(["worker"])
                    raise TypeError("stop")
                except LookupError:
                    return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_do_not_overcatch_baseexception(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    raise KeyboardInterrupt()
                except Exception:
                    response.raise_for_status()
                finally:
                    return response.text

            def run():
                try:
                    completed = subprocess.run(["worker"])
                    raise KeyboardInterrupt()
                except Exception:
                    completed.check_returncode()
                finally:
                    return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertEqual(codes.count("SLP009"), 1)
        self.assertEqual(codes.count("SLP011"), 1)

    def test_operational_rules_follow_constant_wrapped_raises(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    if 1:
                        raise TypeError("inspect")
                except TypeError:
                    return response.text

            def run():
                try:
                    completed = subprocess.run(["worker"], capture_output=True)
                    if 1:
                        raise TypeError("inspect")
                except TypeError:
                    return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_ignore_unreachable_result_handlers(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    raise TypeError("inspect")
                except ValueError:
                    return response.text
                except TypeError:
                    response.raise_for_status()
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    raise TypeError("inspect")
                except ValueError:
                    return completed.stdout
                except TypeError:
                    completed.check_returncode()
                return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_check_all_potential_handlers(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            class RequestError(Exception):
                pass

            class MaybeRequestBase(Exception):
                pass

            def fetch():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    raise RequestError()
                except MaybeRequestBase:
                    response.raise_for_status()
                except RequestError:
                    return response.text

            def run():
                try:
                    completed = subprocess.run(["worker"], capture_output=True)
                    raise RequestError()
                except MaybeRequestBase:
                    completed.check_returncode()
                except RequestError:
                    return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_follow_implicit_exception_handlers(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            class Recoverable(Exception):
                pass

            def unchecked_http():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    might_raise()
                except Recoverable:
                    return response.text
                response.raise_for_status()
                return response.text

            def unchecked_process():
                try:
                    completed = subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                    might_raise()
                except Recoverable:
                    return completed.stdout
                completed.check_returncode()
                return completed.stdout

            def checked_http():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    might_raise()
                except Recoverable:
                    response.raise_for_status()
                response.raise_for_status()
                return response.text

            def reraised_process():
                try:
                    completed = subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                    might_raise()
                except Recoverable:
                    raise
                completed.check_returncode()
                return completed.stdout
        """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_allow_exceptional_result_abandonment(self) -> None:
        findings = self.lint("""
            import logging
            import requests
            import subprocess

            logger = logging.getLogger(__name__)

            def fetch(url):
                try:
                    response = requests.get(url, timeout=5)
                    logger.info("fetched %s", url)
                    response.raise_for_status()
                except requests.RequestException as error:
                    logger.error("request failed: %s", error)
                    return None
                return response.text

            def run(command):
                try:
                    completed = subprocess.run(command, capture_output=True)
                    logger.info("ran %s", command)
                    completed.check_returncode()
                except subprocess.CalledProcessError as error:
                    logger.error("command failed: %s", error)
                    return None
                return completed.stdout

            def unchecked_fetch(url):
                response = requests.get(url, timeout=5)
                return None

            def unchecked_run(command):
                completed = subprocess.run(command)
                return None
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])
        self.assertIn("requests.get", findings[0].message)
        self.assertIn("subprocess.run", findings[1].message)

    def test_operational_rules_ignore_unreachable_implicit_exceptions(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            class Recoverable(Exception):
                pass

            def unreachable_http():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    if False:
                        might_raise()
                except Recoverable:
                    return response.text
                response.raise_for_status()
                return response.text

            def unreachable_process():
                try:
                    completed = subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                    while ():
                        might_raise()
                except Recoverable:
                    return completed.stdout
                completed.check_returncode()
                return completed.stdout

            def reachable_http():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    if True:
                        might_raise()
                except Recoverable:
                    return response.text
                response.raise_for_status()
                return response.text

            def reachable_process():
                try:
                    completed = subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                    while (1,):
                        might_raise()
                        break
                except Recoverable:
                    return completed.stdout
                completed.check_returncode()
                return completed.stdout
        """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_route_nested_raises_to_outer_handlers(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            class Recoverable(Exception):
                pass

            def unchecked_http():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    try:
                        raise Recoverable("fallback")
                    finally:
                        audit()
                except Recoverable:
                    return response.text
                response.raise_for_status()
                return response.text

            def unchecked_process():
                try:
                    completed = subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                    try:
                        raise Recoverable("fallback")
                    finally:
                        audit()
                except Recoverable:
                    return completed.stdout
                completed.check_returncode()
                return completed.stdout

            def checked_http():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    try:
                        raise Recoverable("fallback")
                    finally:
                        audit()
                except Recoverable:
                    response.raise_for_status()
                    return response.text

            def uncaught_process():
                completed = subprocess.run(
                    ["worker"],
                    capture_output=True,
                )
                try:
                    raise Recoverable("stop")
                finally:
                    audit()
                completed.check_returncode()
        """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_follow_break_to_post_loop_checks(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def checked_http():
                while True:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    break
                else:
                    return response.text
                response.raise_for_status()
                return response.text

            def checked_process():
                while True:
                    completed = subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                    if True:
                        break
                completed.check_returncode()
                return completed.stdout

            def used_before_break():
                while True:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    print(response.text)
                    break
                response.raise_for_status()
        """)

        self.assert_codes(findings, ["SLP011"])

    def test_operational_failure_branches_reject_loop_exits(self) -> None:
        unsafe = self.lint("""
            import requests
            import subprocess

            def fetch(urls):
                for url in urls:
                    response = requests.get(url, timeout=5)
                    if not response.ok:
                        break
                return response.text

            def run(commands):
                for command in commands:
                    completed = subprocess.run(command, capture_output=True)
                    if completed.returncode:
                        continue
                return completed.stdout
            """)
        safe = self.lint("""
            import requests
            import subprocess

            def fetch(url):
                response = requests.get(url, timeout=5)
                if not response.ok:
                    return None
                return response.text

            def run(command):
                completed = subprocess.run(command, capture_output=True)
                if completed.returncode:
                    raise RuntimeError("worker failed")
                return completed.stdout
            """)

        self.assert_codes(unsafe, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in unsafe], [7, 14])
        safe_codes = [finding.code for finding in safe]
        self.assertNotIn("SLP009", safe_codes)
        self.assertNotIn("SLP011", safe_codes)

    def test_operational_rules_ignore_false_loop_result_uses(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                while 0:
                    print(response.text)
                while not True:
                    print(response.text)
                while ():
                    print(response.text)
                response.raise_for_status()
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                while 0:
                    print(completed.stdout)
                while not True:
                    print(completed.stdout)
                while ():
                    print(completed.stdout)
                completed.check_returncode()
                return completed.stdout
        """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_reject_unchecked_finally_overrides(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    raise TypeError("stop")
                except ValueError:
                    response.raise_for_status()
                finally:
                    return response.text

            def run():
                try:
                    completed = subprocess.run(["worker"])
                    raise TypeError("stop")
                except ValueError:
                    completed.check_returncode()
                finally:
                    return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_reject_finally_suppressed_checks(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                finally:
                    return None

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    completed.check_returncode()
                finally:
                    return None
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_accept_fallthrough_finally_blocks(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                finally:
                    audit()
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    completed.check_returncode()
                finally:
                    audit()
                return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_continue_after_mixed_finally_inputs(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch(flag):
                try:
                    if flag:
                        raise ValueError("stop")
                finally:
                    response = requests.get("https://service.test", timeout=5)
                response.raise_for_status()
                return response.text

            def run(flag):
                try:
                    if flag:
                        raise ValueError("stop")
                finally:
                    completed = subprocess.run(["worker"], capture_output=True)
                completed.check_returncode()
                return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_accept_validation_before_later_handlers(
        self,
    ) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                    might_raise()
                except ValueError:
                    return response.text
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    completed.check_returncode()
                    might_raise()
                except ValueError:
                    return completed.stdout
                return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_accept_unconditional_finally_checks(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def checked_http():
                response = requests.get(
                    "https://service.test",
                    timeout=5,
                )
                try:
                    audit()
                finally:
                    response.raise_for_status()
                return response.text

            def checked_process():
                completed = subprocess.run(
                    ["worker"],
                    capture_output=True,
                )
                try:
                    audit()
                finally:
                    completed.check_returncode()
                return completed.stdout

            def checked_before_early_return(skip):
                completed = subprocess.run(
                    ["worker"],
                    capture_output=True,
                )
                try:
                    if skip:
                        return None
                    audit()
                finally:
                    completed.check_returncode()
                return completed.stdout

            def used_http_first():
                response = requests.get(
                    "https://service.test",
                    timeout=5,
                )
                try:
                    print(response.text)
                finally:
                    response.raise_for_status()

            def used_process_first():
                completed = subprocess.run(
                    ["worker"],
                    capture_output=True,
                )
                try:
                    print(completed.stdout)
                finally:
                    completed.check_returncode()

            def returned_output_first():
                completed = subprocess.run(
                    ["worker"],
                    capture_output=True,
                )
                try:
                    return completed.stdout
                finally:
                    completed.check_returncode()
        """)

        self.assert_codes(findings, ["SLP011", "SLP009", "SLP009"])

    def test_operational_rules_accept_later_common_checks(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch(strict):
                response = requests.get("https://service.test", timeout=5)
                if strict:
                    response.raise_for_status()
                response.raise_for_status()
                return response.text

            def run(strict):
                completed = subprocess.run(["worker"], capture_output=True)
                if strict:
                    completed.check_returncode()
                completed.check_returncode()
                return completed.stdout
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_accept_guaranteed_loop_checks(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch(url):
                response = requests.get(url, timeout=5)
                while True:
                    response.raise_for_status()
                    break
                return response.text

            def run(command):
                completed = subprocess.run(command, capture_output=True)
                while True:
                    completed.check_returncode()
                    break
                return completed.stdout

            def split_fetch(url, use_primary):
                response = requests.get(url, timeout=5)
                while True:
                    if use_primary:
                        response.raise_for_status()
                        break
                    response.raise_for_status()
                    break
                return response.text

            def split_run(command, use_primary):
                completed = subprocess.run(command, capture_output=True)
                while True:
                    if use_primary:
                        completed.check_returncode()
                        break
                    completed.check_returncode()
                    break
                return completed.stdout

            def maybe_fetch(url, values):
                response = requests.get(url, timeout=5)
                for value in values:
                    response.raise_for_status()
                    break
                return response.text

            def maybe_run(command, values):
                completed = subprocess.run(command, capture_output=True)
                for value in values:
                    completed.check_returncode()
                    break
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_rules_reject_use_before_later_common_checks(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch(strict):
                response = requests.get("https://service.test", timeout=5)
                if strict:
                    print(response.text)
                response.raise_for_status()

            def run(strict):
                completed = subprocess.run(["worker"], capture_output=True)
                if strict:
                    print(completed.stdout)
                completed.check_returncode()
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_literal_conditions_only_analyze_reachable_branches(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def always_reraise():
                try:
                    risky()
                except Exception:
                    if True:
                        raise

            def never_reraise():
                try:
                    risky()
                except Exception:
                    if False:
                        raise

            def always_abort():
                response = requests.get("https://service.test", timeout=5)
                if True:
                    raise RuntimeError("stop")

            def unreachable_http_check():
                response = requests.get("https://service.test", timeout=5)
                if False:
                    response.raise_for_status()
                return response.text

            def unreachable_process_check():
                completed = subprocess.run(["worker"])
                if False:
                    completed.check_returncode()
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP003", "SLP011", "SLP009"])

    def test_http_status_rule_accepts_observed_aliases_and_delegation(
        self,
    ) -> None:
        findings = self.lint("""
            import requests as req

            def checked_through_predicate():
                response = req.get("https://service.test", timeout=5)
                success = response.ok
                if not success:
                    raise RuntimeError("request failed")
                return response.text

            def checked_through_status_alias():
                response = req.get("https://service.test", timeout=5)
                status = response.status_code
                if status >= 400:
                    raise RuntimeError("request failed")
                return response.text

            def checked_through_derived_success():
                response = req.get("https://service.test", timeout=5)
                success = response.status_code == 200
                if not success:
                    raise RuntimeError("request failed")
                return response.text

            def checked_through_derived_failure():
                response = req.get("https://service.test", timeout=5)
                failed = response.status_code >= 400
                if failed:
                    raise RuntimeError("request failed")
                return response.text

            def checked_inline_predicate():
                success = req.get("https://service.test", timeout=5).ok
                if not success:
                    raise RuntimeError("request failed")
                return success

            def checked_inline_status():
                success = (
                    req.get("https://service.test", timeout=5).status_code == 200
                )
                if not success:
                    raise RuntimeError("request failed")
                return success

            def inline_status():
                return req.get(
                    "https://service.test",
                    timeout=5,
                ).status_code

            def assigned_status():
                response = req.get("https://service.test", timeout=5)
                return response.status_code

            def yielded_status():
                yield req.get(
                    "https://service.test",
                    timeout=5,
                ).status_code
            """)

        self.assertNotIn("SLP011", [finding.code for finding in findings])

    def test_http_status_rule_resolves_derived_status_semantics(self) -> None:
        resolved = self.lint("""
            from http import HTTPStatus as Status
            from requests import codes
            import requests

            def named_success():
                response = requests.get("https://service.test", timeout=5)
                success = response.status_code == Status.OK
                if not success:
                    raise RuntimeError("request failed")
                return response.text

            def requests_success():
                response = requests.get("https://service.test", timeout=5)
                success = response.status_code == codes.ok
                if not success:
                    raise RuntimeError("request failed")
                return response.text

            def configured_success(expected):
                response = requests.get("https://service.test", timeout=5)
                success = response.status_code == expected
                if not success:
                    raise RuntimeError("request failed")
                return response.text
            """)
        unresolved = self.lint("""
            import requests

            def failure_constant():
                response = requests.get("https://service.test", timeout=5)
                success = response.status_code == 500
                if not success:
                    raise RuntimeError("wrong branch")
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in resolved])
        self.assert_codes(unresolved, ["SLP011"])
        self.assertEqual(unresolved[0].line, 5)

    def test_http_status_rule_requires_success_only_continuation(self) -> None:
        handled = self.lint("""
            import requests

            def branch():
                response = requests.get("https://service.test", timeout=5)
                if not response.ok:
                    raise RuntimeError("request failed")
                return response.text

            def assertion():
                response = requests.get("https://service.test", timeout=5)
                assert response.status_code < 400
                return response.text

            def inline_branch():
                if not requests.get("https://service.test", timeout=5).ok:
                    raise RuntimeError("request failed")
            """)
        unsafe = self.lint("""
            import requests

            def no_op_branch():
                response = requests.get("https://service.test", timeout=5)
                if response.ok:
                    log("ok")
                return response.text

            def inverted_assertion():
                response = requests.get("https://service.test", timeout=5)
                assert response.status_code >= 400
                return response.text

            def aliased_no_op_branch():
                response = requests.get("https://service.test", timeout=5)
                status = response.status_code
                if status == 200:
                    log("ok")
                return response.text

            def inline_no_op_branch():
                if requests.get("https://service.test", timeout=5).ok:
                    log("ok")
            """)

        self.assertNotIn("SLP011", [finding.code for finding in handled])
        self.assert_codes(unsafe, ["SLP011", "SLP011", "SLP011", "SLP011"])
        self.assertEqual([finding.line for finding in unsafe], [5, 11, 16, 23])

    def test_http_boolean_derivation_rejects_ambiguous_short_circuit(self) -> None:
        handled = self.lint("""
            import requests

            def success_and_flag(flag):
                response = requests.get("https://service.test", timeout=5)
                success = response.ok and flag
                if not success:
                    raise RuntimeError("request failed")
                return response.text

            def failure_or_flag(flag):
                response = requests.get("https://service.test", timeout=5)
                failed = (not response.ok) or flag
                if failed:
                    raise RuntimeError("request failed")
                return response.text
            """)
        ambiguous = self.lint("""
            import requests

            def failure_and_flag(flag):
                response = requests.get("https://service.test", timeout=5)
                failed = (not response.ok) and flag
                if failed:
                    raise RuntimeError("request failed")
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in handled])
        self.assert_codes(ambiguous, ["SLP011"])
        self.assertEqual(ambiguous[0].line, 5)

    def test_http_status_constants_require_import_resolution(self) -> None:
        resolved = self.lint("""
            from http import HTTPStatus as Status
            from requests import codes
            import requests

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                status_ok = response.status_code == Status.OK
                code_ok = response.status_code == codes.ok
                if not (status_ok and code_ok):
                    raise RuntimeError("request failed")
                return response.text
            """)
        unresolved = self.lint("""
            import requests as client

            class requests:
                class codes:
                    ok = 200

            def shadowed():
                response = client.get("https://service.test", timeout=5)
                success = response.status_code == requests.codes.ok
                if not success:
                    raise RuntimeError("request failed")
                return response.text

            def unimported():
                response = client.get("https://service.test", timeout=5)
                success = response.status_code == http.HTTPStatus.OK
                if not success:
                    raise RuntimeError("request failed")
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in resolved])
        self.assert_codes(unresolved, ["SLP011", "SLP011"])
        self.assertEqual([finding.line for finding in unresolved], [9, 16])

    def test_http_status_rule_accepts_semantic_status_comparisons(self) -> None:
        findings = self.lint("""
            from http import HTTPStatus
            from http import HTTPStatus as Status
            from requests import codes
            import requests

            class Client:
                expected = 200

                def fetch(self):
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    if response.status_code != self.expected:
                        raise RuntimeError("request failed")
                    return response.text

            def boolean_comparison():
                response = requests.get("https://service.test", timeout=5)
                if response.ok is False:
                    raise RuntimeError("request failed")
                return response.text

            def status_membership():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code not in {200, 204}:
                    raise RuntimeError("request failed")
                return response.text

            def status_constant():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code != HTTPStatus.OK:
                    raise RuntimeError("request failed")
                return response.text

            def aliased_status_constant():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code != Status.OK:
                    raise RuntimeError("request failed")
                return response.text

            def imported_status_codes():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code != codes.ok:
                    raise RuntimeError("request failed")
                return response.text

            def boolean_alias():
                response = requests.get("https://service.test", timeout=5)
                success = response.ok
                if success is False:
                    raise RuntimeError("request failed")
                return response.text

            def dynamic_expected_status(expected_status):
                response = requests.get("https://service.test", timeout=5)
                if response.status_code != expected_status:
                    raise RuntimeError("request failed")
                return response.text

            def success_range():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code not in range(200, 300):
                    raise RuntimeError("request failed")
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in findings])

    def test_http_status_rule_accepts_exhaustive_success_matches(self) -> None:
        findings = self.lint("""
            from http import HTTPStatus as Status
            import requests

            def status_match():
                response = requests.get("https://service.test", timeout=5)
                match response.status_code:
                    case 200 | 204:
                        pass
                    case _:
                        raise RuntimeError("request failed")
                return response.text

            def boolean_alias_match():
                response = requests.get("https://service.test", timeout=5)
                success = response.ok
                match success:
                    case True:
                        pass
                    case False:
                        raise RuntimeError("request failed")
                return response.text

            def named_status_match():
                response = requests.get("https://service.test", timeout=5)
                match response.status_code:
                    case Status.OK:
                        pass
                    case _:
                        raise RuntimeError("request failed")
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in findings])

    def test_operational_matches_reject_terminal_failure_arms(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def unchecked_http():
                response = requests.get(
                    "https://service.test",
                    timeout=5,
                )
                match response.status_code:
                    case 200:
                        pass
                    case _:
                        return response.text
                return response.text

            def unchecked_process():
                completed = subprocess.run(
                    ["worker"],
                    capture_output=True,
                )
                match completed.returncode:
                    case 0:
                        pass
                    case _:
                        return completed.stdout
                return completed.stdout

            def checked_http():
                response = requests.get(
                    "https://service.test",
                    timeout=5,
                )
                match response.status_code:
                    case 200:
                        pass
                    case _:
                        response.raise_for_status()
                        return response.text
                return response.text

            def raising_process():
                completed = subprocess.run(
                    ["worker"],
                    capture_output=True,
                )
                match completed.returncode:
                    case 0:
                        pass
                    case _:
                        raise RuntimeError("worker failed")
                return completed.stdout
        """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_http_status_rule_rejects_wildcard_only_matches(self) -> None:
        findings = self.lint("""
            import requests

            def status_alias():
                response = requests.get("https://service.test", timeout=5)
                status = response.status_code
                match status:
                    case _:
                        pass
                return response.text

            def direct_status():
                response = requests.get("https://service.test", timeout=5)
                match response.status_code:
                    case _:
                        pass
                return response.text
            """)

        self.assert_codes(findings, ["SLP011", "SLP011"])

    def test_http_status_rule_preserves_observation_polarity(self) -> None:
        findings = self.lint("""
            import requests

            def inverted_not():
                response = requests.get("https://service.test", timeout=5)
                failed = not response.ok
                match failed:
                    case True:
                        pass
                    case False:
                        raise RuntimeError("request failed")
                return response.text

            def inverted_comparison():
                response = requests.get("https://service.test", timeout=5)
                failed = response.ok is False
                match failed:
                    case True:
                        pass
                    case False:
                        raise RuntimeError("request failed")
                return response.text

            def handled_failure():
                response = requests.get("https://service.test", timeout=5)
                failed = not response.ok
                match failed:
                    case True:
                        raise RuntimeError("request failed")
                    case False:
                        pass
                return response.text
            """)

        self.assert_codes(findings, ["SLP011", "SLP011"])

    def test_http_status_rule_preserves_if_observation_polarity(self) -> None:
        findings = self.lint("""
            import requests

            def inverted_unhandled():
                response = requests.get("https://service.test", timeout=5)
                failed = not response.ok
                if failed:
                    pass
                return response.text

            def success_unhandled():
                response = requests.get("https://service.test", timeout=5)
                success = response.ok
                if success:
                    pass
                return response.text

            def inverted_handled():
                response = requests.get("https://service.test", timeout=5)
                failed = not response.ok
                if failed:
                    raise RuntimeError("request failed")
                return response.text

            def success_handled():
                response = requests.get("https://service.test", timeout=5)
                success = response.ok
                if not success:
                    return None
                return response.text
            """)

        self.assert_codes(findings, ["SLP011", "SLP011"])

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

    def test_operational_rules_resolve_imports_before_later_rebinding(self) -> None:
        findings = self.lint("""
            def before_rebinding():
                import requests as client

                response = client.get("https://service.test")
                client = LocalClient()
                return response.text

            def after_rebinding():
                import requests as client

                client = LocalClient()
                return client.get("https://service.test").text
            """)

        self.assert_codes(findings, ["SLP010", "SLP011"])
        self.assertEqual([finding.line for finding in findings], [5, 5])

    def test_http_status_rule_does_not_treat_printing_status_as_validation(
        self,
    ) -> None:
        findings = self.lint("""
            import requests

            response = requests.post("https://service.test", timeout=5)
            print(response.status_code)
            """)

        self.assert_codes(findings, ["SLP011"])

    def test_http_status_rule_requires_observed_predicates_to_be_used(
        self,
    ) -> None:
        findings = self.lint("""
            import requests

            def ignored_boolean():
                response = requests.get("https://service.test", timeout=5)
                observed = response.ok
                return response.text

            def ignored_status():
                response = requests.get("https://service.test", timeout=5)
                status = response.status_code
                return response.text

            def short_circuited_observation():
                response = requests.get("https://service.test", timeout=5)
                observed = response.text or response.ok
                if observed:
                    return response.text
                return ""

            def ignored_inline_observation():
                success = requests.get(
                    "https://service.test",
                    timeout=5,
                ).ok
                return success is not None
            """)

        self.assert_codes(findings, ["SLP011", "SLP011", "SLP011", "SLP011"])

    def test_http_status_rule_rejects_existence_comparisons(self) -> None:
        findings = self.lint("""
            import requests

            def direct_status():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code is not None:
                    return response.text

            def direct_boolean():
                response = requests.get("https://service.test", timeout=5)
                if response.ok is not None:
                    return response.text

            def status_alias():
                response = requests.get("https://service.test", timeout=5)
                status = response.status_code
                if status is not None:
                    return response.text

            def boolean_alias():
                response = requests.get("https://service.test", timeout=5)
                success = response.ok
                if success is not None:
                    return response.text
            """)

        self.assert_codes(findings, ["SLP011", "SLP011", "SLP011", "SLP011"])

    def test_http_status_rule_accepts_checks_inside_binding_statements(
        self,
    ) -> None:
        findings = self.lint("""
            import requests

            def managed():
                with requests.get(
                    "https://service.test",
                    timeout=5,
                ) as response:
                    response.raise_for_status()
                    return response.text

            def walrus(flag):
                if (
                    response := requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                ) and flag:
                    response.raise_for_status()
                else:
                    response.raise_for_status()
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in findings])

    def test_operational_rules_reject_walrus_body_reads(self) -> None:
        unsafe = self.lint("""
            import requests
            import subprocess

            def fetch():
                payload = (
                    response := requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                ).text
                response.raise_for_status()
                return payload

            def run():
                output = (
                    completed := subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                ).stdout
                completed.check_returncode()
                return output
            """)
        safe = self.lint("""
            import requests
            import subprocess

            def fetch():
                (
                    response := requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                ).raise_for_status()

            def run():
                (
                    completed := subprocess.run(["worker"])
                ).check_returncode()
            """)

        self.assert_codes(unsafe, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in unsafe], [7, 17])
        safe_codes = [finding.code for finding in safe]
        self.assertNotIn("SLP009", safe_codes)
        self.assertNotIn("SLP011", safe_codes)

    def test_operational_success_branches_follow_post_if_failure(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                if response.ok:
                    return response.text
                raise RuntimeError("request failed")

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                if completed.returncode == 0:
                    return completed.stdout
                raise RuntimeError("worker failed")
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_http_status_rule_models_nested_suppressed_raises(self) -> None:
        findings = self.lint("""
            import contextlib
            import requests

            def unchecked(strict):
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(Exception):
                    if strict:
                        response.raise_for_status()
                    else:
                        raise RuntimeError("ignored")
                return response.text

            def checked(strict):
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(Exception):
                    if strict:
                        response.raise_for_status()
                    else:
                        response.raise_for_status()
                return response.text
            """)

        self.assert_codes(findings, ["SLP011", "SLP011"])
        self.assertEqual([finding.line for finding in findings], [6, 15])

    def test_http_status_rule_rejects_late_and_truthy_status_checks(self) -> None:
        findings = self.lint("""
            import requests

            def consumed_first():
                response = requests.get("https://service.test", timeout=5)
                payload = response.json()
                response.raise_for_status()
                return payload

            def truthy_status():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code:
                    return response.text
                return ""

            def checked_after_loop(urls):
                for url in urls:
                    response = requests.get(url, timeout=5)
                response.raise_for_status()
                return response.text

            def checked_after_returning_finally():
                try:
                    response = requests.get("https://service.test", timeout=5)
                finally:
                    return ""
                response.raise_for_status()
                return response.text

            def request_inside_returning_finally():
                try:
                    return ""
                finally:
                    response = requests.get("https://service.test", timeout=5)
                response.raise_for_status()
                return response.text
            """)

        self.assert_codes(
            findings,
            ["SLP011", "SLP011", "SLP011", "SLP011", "SLP011"],
        )

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
            from unittest import TestCase as Case

            def test_value():
                assert calculate() == 42

            def test_failure():
                with pytest.raises(ValueError):
                    calculate("bad")

            def test_mock(mock):
                run_workflow(mock)
                mock.assert_called_once_with("done")

            class WorkflowTests(Case):
                def test_value(self):
                    self.assertEqual(calculate(), 42)
            """,
            path="tests/test_workflow.py",
        )

        self.assertNotIn("SLP014", [finding.code for finding in findings])

    def test_assertion_free_test_rule_tracks_local_testcase_inheritance(self) -> None:
        findings = self.lint(
            """
            import unittest

            class BaseCase(unittest.TestCase):
                pass

            Alias = BaseCase

            class WorkflowTests(Alias):
                def test_value(case):
                    case.assertEqual(calculate(), 42)

            Alias = object

            class PlainTests(Alias):
                def test_value(case):
                    case.assertEqual(calculate(), 42)
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014"])
        self.assertEqual(findings[0].line, 16)

    def test_assertion_free_test_rule_ignores_unreachable_oracles(self) -> None:
        findings = self.lint(
            """
            import pytest

            def test_if_branch():
                if False:
                    pytest.fail("unreachable")
                run_workflow()

            def test_while_body():
                while False:
                    assert calculate() == 42
                run_workflow()
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014"])
        self.assertEqual([finding.line for finding in findings], [4, 9])

    def test_assertion_free_test_rule_ignores_empty_literal_loops(self) -> None:
        findings = self.lint(
            """
            def test_empty_list():
                for _ in []:
                    assert True

            def test_empty_tuple():
                for _ in ():
                    assert True

            def test_nonempty_list():
                for _ in [1]:
                    assert True
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014"])
        self.assertEqual([finding.line for finding in findings], [2, 6])

    def test_assertion_free_test_rule_ignores_oracles_after_return(self) -> None:
        findings = self.lint(
            """
            def test_direct_return():
                return
                assert True

            def test_conditional_return():
                if True:
                    return
                    assert True
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014"])
        self.assertEqual([finding.line for finding in findings], [2, 6])

    def test_assertion_free_test_rule_accepts_callable_pytest_oracles(
        self,
    ) -> None:
        findings = self.lint(
            """
            import pytest

            def test_failure():
                pytest.raises(ValueError, calculate, "bad")

            def test_warning():
                pytest.warns(UserWarning, warn_user)

            def test_deprecation():
                pytest.deprecated_call(old_api)
            """,
            path="tests/test_workflow.py",
        )

        self.assertNotIn("SLP014", [finding.code for finding in findings])

    def test_assertion_free_test_rule_rejects_unused_pytest_contexts(
        self,
    ) -> None:
        findings = self.lint(
            """
            import pytest

            def test_failure():
                pytest.raises(ValueError)
                calculate("bad")

            def test_warning():
                pytest.warns(UserWarning)
                warn_user()

            def test_deprecation():
                pytest.deprecated_call()
                old_api()
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014", "SLP014"])

    def test_assertion_free_test_rule_resolves_aliased_pytest_oracles(self) -> None:
        findings = self.lint(
            """
            import pytest as testing
            from pytest import raises as expect_failure

            def test_warning():
                with testing.warns(UserWarning):
                    warn_user()

            def test_failure():
                with expect_failure(ValueError):
                    calculate("bad")
            """,
            path="tests/test_workflow.py",
        )

        self.assertNotIn("SLP014", [finding.code for finding in findings])

    def test_assertion_free_test_rule_accepts_imported_assertions(self) -> None:
        findings = self.lint(
            """
            from numpy.testing import assert_equal
            from pandas.testing import assert_frame_equal as assert_frames

            def test_array():
                assert_equal(actual_array(), expected_array())

            def test_frame():
                assert_frames(actual_frame(), expected_frame())
            """,
            path="tests/test_workflow.py",
        )

        self.assertNotIn("SLP014", [finding.code for finding in findings])

    def test_assertion_free_test_rule_rejects_custom_imported_assertions(
        self,
    ) -> None:
        findings = self.lint(
            """
            from helpers import assert_equal

            def test_value():
                assert_equal(actual(), expected())
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014"])

    def test_assertion_free_test_rule_rejects_oracle_like_helper_names(
        self,
    ) -> None:
        findings = self.lint(
            """
            def raises(*exceptions):
                return custom_context()

            def assertion_factory():
                return build_helper()

            def test_local_raises():
                with raises(ValueError):
                    calculate("bad")

            def test_named_factory():
                assertion_factory()

            def test_attribute_helper():
                helper.assert_result()

            class CustomTests:
                def test_self_helper(self):
                    self.assert_result()
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014", "SLP014", "SLP014"])

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

    def test_assertion_free_test_rule_resolves_outcome_decorators(self) -> None:
        findings = self.lint(
            """
            from unittest import skip as ignore

            def skip(reason):
                return lambda function: function

            @ignore("real skip")
            def test_aliased():
                value = compute()

            @skip("not a skip")
            def test_shadowed():
                value = compute()
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014"])
        self.assertIn("test_shadowed", findings[0].message)

    def test_assertion_free_test_rule_evaluates_conditional_skips(self) -> None:
        findings = self.lint(
            """
            import pytest
            import unittest

            @pytest.mark.skipif(False, reason="runs")
            def test_pytest_runs():
                exercise()

            @unittest.skipIf(False, "runs")
            def test_unittest_runs():
                exercise()

            @unittest.skipUnless(True, "runs")
            def test_unless_runs():
                exercise()

            @pytest.mark.skipif(True, reason="skipped")
            def test_pytest_skipped():
                exercise()

            @unittest.skipIf(True, "skipped")
            def test_unittest_skipped():
                exercise()

            @unittest.skipUnless(False, "skipped")
            def test_unless_skipped():
                exercise()
            """,
            path="tests/test_workflow.py",
        )

        assertion_findings = [
            finding for finding in findings if finding.code == "SLP014"
        ]
        self.assertEqual(len(assertion_findings), 3)
        self.assertEqual(
            {
                name
                for name in (
                    "test_pytest_runs",
                    "test_pytest_skipped",
                    "test_unittest_runs",
                    "test_unittest_skipped",
                    "test_unless_runs",
                    "test_unless_skipped",
                )
                if any(name in finding.message for finding in assertion_findings)
            },
            {
                "test_pytest_runs",
                "test_unittest_runs",
                "test_unless_runs",
            },
        )

    def test_assertion_free_test_rule_evaluates_conditional_xfail(self) -> None:
        findings = self.lint(
            """
            import pytest

            @pytest.mark.xfail(False, reason="runs")
            def test_xfail_runs():
                exercise()

            @pytest.mark.xfail(condition=False, reason="runs")
            def test_keyword_xfail_runs():
                exercise()

            @pytest.mark.xfail(runtime_condition, reason="may run")
            def test_conditional_xfail_may_run():
                exercise()

            @pytest.mark.xfail(True, reason="known bug")
            def test_xfail_expected():
                exercise()

            @pytest.mark.xfail(reason="known bug")
            def test_unconditional_xfail():
                exercise()
            """,
            path="tests/test_workflow.py",
        )

        assertion_findings = [
            finding for finding in findings if finding.code == "SLP014"
        ]
        self.assertEqual(len(assertion_findings), 3)
        self.assertEqual(
            {
                name
                for name in (
                    "test_xfail_runs",
                    "test_keyword_xfail_runs",
                    "test_conditional_xfail_may_run",
                    "test_xfail_expected",
                    "test_unconditional_xfail",
                )
                if any(name in finding.message for finding in assertion_findings)
            },
            {
                "test_xfail_runs",
                "test_keyword_xfail_runs",
                "test_conditional_xfail_may_run",
            },
        )

    def test_assertion_free_test_rule_stops_at_irrefutable_match_case(
        self,
    ) -> None:
        findings = self.lint(
            """
            def test_unreachable_assertion(value):
                match value:
                    case _ if True:
                        exercise()
                    case _:
                        assert False

            def test_reachable_assertion(value):
                match value:
                    case 1:
                        exercise()
                    case _:
                        assert value != 1
            """,
            path="tests/test_workflow.py",
        )

        self.assert_codes(findings, ["SLP014"])
        self.assertIn("test_unreachable_assertion", findings[0].message)

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
                    instance.ready = True

                def configure(instance):
                    return None

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

    def test_overridable_init_call_accepts_completed_state(self) -> None:
        findings = self.lint("""
            class InitializedBeforeHook:
                def __init__(self):
                    self.ready = False
                    self.prepare()

                def prepare(self):
                    return self.ready

            class CompleteBranches:
                def __init__(self, active):
                    if active:
                        self.state = "active"
                    else:
                        self.state = "idle"
                    self.prepare()

                def prepare(self):
                    return self.state

            class HookOnly:
                def __init__(self):
                    self.prepare()

                def prepare(self):
                    return None
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

    def test_conditional_instance_state_tracks_loop_break_paths(self) -> None:
        findings = self.lint("""
            class InfiniteUntilReady:
                def __init__(self):
                    while True:
                        self.ready = True
                        break

                def read(self):
                    return self.ready

            class TruthyInfiniteUntilReady:
                def __init__(self):
                    while 1:
                        self.ready = True
                        break

                def read(self):
                    return self.ready

            class MaybeEmpty:
                def __init__(self, values):
                    for value in values:
                        self.ready = value
                        break

                def read(self):
                    return self.ready
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("MaybeEmpty.ready", state_findings[0].message)

    def test_conditional_instance_state_tracks_loop_assignment_targets(self) -> None:
        findings = self.lint("""
            class SyncLoopTarget:
                def __init__(self, values):
                    for self.value in values:
                        break

                def read(self):
                    return self.value

            class AsyncLoopTarget:
                async def __init__(self, values):
                    async for self.value in values:
                        break

                def read(self):
                    return self.value

            class SafeSyncLoopTarget:
                def __init__(self, values):
                    self.value = None
                    for self.value in values:
                        break

                def read(self):
                    return self.value

            class SafeAsyncLoopTarget:
                async def __init__(self, values):
                    self.value = None
                    async for self.value in values:
                        break

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 2)
        self.assertEqual(
            {
                finding.message.partition("`")[2].partition("`")[0]
                for finding in state_findings
            },
            {"AsyncLoopTarget.value", "SyncLoopTarget.value"},
        )

    def test_conditional_instance_state_handles_definite_loop_and_match_paths(
        self,
    ) -> None:
        findings = self.lint("""
            class GuardedMatch:
                def __init__(self, value):
                    match value:
                        case _ if True:
                            self.state = value

                def read(self):
                    return self.state

            class GuaranteedBody:
                def __init__(self):
                    for marker in [1]:
                        self.value = marker

                def read(self):
                    return self.value

            class GuaranteedTarget:
                def __init__(self):
                    for self.value in [1]:
                        pass

                def read(self):
                    return self.value

            class MaybeBody:
                def __init__(self, values):
                    for marker in values:
                        self.value = marker

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("MaybeBody.value", state_findings[0].message)

    def test_conditional_instance_state_collects_context_and_comprehension_targets(
        self,
    ) -> None:
        findings = self.lint("""
            class ComprehensionTarget:
                def __init__(self, values):
                    [None for self.value in values]

                def read(self):
                    return self.value

            class ConditionalContextTarget:
                def __init__(self, enabled, manager):
                    if enabled:
                        with manager as self.value:
                            pass

                def read(self):
                    return self.value

            class SafeComprehensionTarget:
                def __init__(self, values):
                    self.value = None
                    [None for self.value in values]

                def read(self):
                    return self.value

            class SafeContextTarget:
                def __init__(self, manager):
                    with manager as self.value:
                        pass

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 2)
        self.assertEqual(
            {
                name
                for name in (
                    "ComprehensionTarget.value",
                    "ConditionalContextTarget.value",
                    "SafeComprehensionTarget.value",
                    "SafeContextTarget.value",
                )
                if any(name in finding.message for finding in state_findings)
            },
            {"ComprehensionTarget.value", "ConditionalContextTarget.value"},
        )

    def test_conditional_instance_state_folds_constant_truthiness(self) -> None:
        findings = self.lint("""
            class Ready:
                def __init__(self):
                    if 1:
                        self.value = 1

                def read(self):
                    return self.value

            class Missing:
                def __init__(self):
                    if 0:
                        self.value = 1

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("Missing.value", state_findings[0].message)

    def test_conditional_instance_state_keeps_starred_truthiness_unknown(
        self,
    ) -> None:
        findings = self.lint("""
            class ListBacked:
                def __init__(self, items):
                    if [*items]:
                        self.value = 1

                def read(self):
                    return self.value

            class DictBacked:
                def __init__(self, values):
                    if {**values}:
                        self.value = 1

                def read(self):
                    return self.value
            """)

        self.assert_codes(findings, ["SLP016", "SLP016"])

    def test_conditional_instance_state_tracks_loop_carried_mutations(self) -> None:
        findings = self.lint("""
            class DeletedBeforeLaterBreak:
                def __init__(self):
                    self.value = 1
                    while True:
                        if ready():
                            break
                        del self.value

                def read(self):
                    return self.value

            class ReassignedBeforeEveryBreak:
                def __init__(self):
                    while True:
                        self.value = 1
                        if ready():
                            break
                        del self.value

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("DeletedBeforeLaterBreak.value", state_findings[0].message)

    def test_conditional_instance_state_accepts_guarded_reads(self) -> None:
        findings = self.lint("""
            class GuardedState:
                def __init__(self, supplied):
                    if supplied:
                        self.optional = supplied

                def direct_guard(self):
                    if hasattr(self, "optional"):
                        return self.optional
                    return None

                def inverse_guard(self):
                    if not hasattr(self, "optional"):
                        return None
                    return self.optional

                def expression_guard(self):
                    return self.optional if hasattr(self, "optional") else None

            class LazyState:
                def __init__(self, supplied):
                    if supplied:
                        self.optional = supplied

                def read(self):
                    try:
                        return self.optional
                    except AttributeError:
                        return None

            class TestAndSetDefault:
                def __init__(self, label):
                    if not hasattr(self, "label"):
                        self.label = label

                def read(self):
                    return self.label
            """)

        self.assertNotIn("SLP016", [finding.code for finding in findings])

    def test_conditional_instance_state_resolves_attribute_error_identity(
        self,
    ) -> None:
        findings = self.lint("""
            from builtins import AttributeError as MissingAttribute
            from custom_errors import AttributeError as CustomAttributeError

            class BuiltinAlias:
                def __init__(self, supplied):
                    if supplied:
                        self.optional = supplied

                def read(self):
                    try:
                        return self.optional
                    except MissingAttribute:
                        return None

            class CustomAlias:
                def __init__(self, supplied):
                    if supplied:
                        self.optional = supplied

                def read(self):
                    try:
                        return self.optional
                    except CustomAttributeError:
                        return None
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("CustomAlias.optional", state_findings[0].message)

    def test_conditional_instance_state_keeps_unguarded_reads(self) -> None:
        findings = self.lint("""
            class PartiallyGuardedState:
                def __init__(self, supplied):
                    if supplied:
                        self.optional = supplied

                def read(self):
                    if hasattr(self, "optional"):
                        audit(self.optional)
                    return self.optional
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertEqual(state_findings[0].line, 10)

    def test_conditional_instance_state_does_not_trust_shadowed_guards(self) -> None:
        findings = self.lint("""
            class ShadowedGuards:
                def __init__(self, supplied):
                    if supplied:
                        self.optional = supplied
                        self.lazy = supplied

                def custom_hasattr(self, hasattr):
                    if hasattr(self, "optional"):
                        return self.optional
                    return None

                def custom_exception(self, AttributeError):
                    try:
                        return self.lazy
                    except AttributeError:
                        return None
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 2)
        self.assertEqual([finding.line for finding in state_findings], [10, 15])

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

    def test_conditional_instance_state_preserves_explicit_raise_state_in_handlers(
        self,
    ) -> None:
        findings = self.lint("""
            class Complete:
                def __init__(self):
                    try:
                        self.value = 1
                        raise ValueError("fallback")
                    except ValueError:
                        return

                def read(self):
                    return self.value

            class Conditional:
                def __init__(self, ready):
                    try:
                        if ready:
                            self.value = 1
                        raise ValueError("fallback")
                    except ValueError:
                        return

                def read(self):
                    return self.value
        """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("Conditional.value", state_findings[0].message)

    def test_conditional_instance_state_tracks_suppressed_raise_paths(self) -> None:
        escaped = self.lint("""
            import contextlib

            class CompleteOrUnconstructed:
                def __init__(self, ready):
                    with contextlib.suppress(ValueError):
                        if ready:
                            self.value = 1
                        raise RuntimeError("stop")

                def read(self):
                    return self.value
            """)
        suppressed = self.lint("""
            import contextlib

            class Conditional:
                def __init__(self, ready):
                    with contextlib.suppress(RuntimeError):
                        if ready:
                            self.value = 1
                        raise RuntimeError("ignored")

                def read(self):
                    return self.value
            """)

        self.assertNotIn("SLP016", [finding.code for finding in escaped])
        state_findings = [finding for finding in suppressed if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertEqual(state_findings[0].line, 12)
        self.assertIn("Conditional.value", state_findings[0].message)

    def test_conditional_instance_state_tracks_suppressed_implicit_raises(
        self,
    ) -> None:
        findings = self.lint("""
            import contextlib

            class Parsed:
                def __init__(self, text):
                    with contextlib.suppress(ValueError):
                        self.value = int(text)

                def read(self):
                    return self.value

            class Interrupting:
                def __init__(self, enabled):
                    with contextlib.suppress(Exception):
                        if enabled:
                            self.value = 1
                        else:
                            raise KeyboardInterrupt()

                def read(self):
                    return self.value
            """)

        self.assert_codes(findings, ["SLP016"])
        self.assertIn("Parsed", findings[0].message)

    def test_conditional_instance_state_tracks_raises_overridden_by_finally(
        self,
    ) -> None:
        findings = self.lint("""
            class Missing:
                def __init__(self, ready):
                    try:
                        if ready:
                            self.value = 1
                        raise RuntimeError("stop")
                    finally:
                        return

                def read(self):
                    return self.value

            class Complete:
                def __init__(self, ready):
                    try:
                        if ready:
                            self.value = 1
                        raise RuntimeError("stop")
                    finally:
                        self.value = 0
                        return

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("Missing.value", state_findings[0].message)

    def test_conditional_instance_state_tracks_uncaught_selective_handlers(
        self,
    ) -> None:
        findings = self.lint("""
            class Selective:
                def __init__(self, ready):
                    try:
                        if ready:
                            self.value = 1
                        raise TypeError("stop")
                    except ValueError:
                        self.value = 2
                    finally:
                        return

                def read(self):
                    return self.value

            class Broad:
                def __init__(self, ready):
                    try:
                        if ready:
                            self.value = 1
                        raise TypeError("stop")
                    except Exception:
                        self.value = 2
                    finally:
                        return

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("Selective.value", state_findings[0].message)

    def test_conditional_instance_state_does_not_overcatch_baseexception(
        self,
    ) -> None:
        findings = self.lint("""
            class Missing:
                def __init__(self):
                    try:
                        raise KeyboardInterrupt()
                    except Exception:
                        self.value = 1
                    finally:
                        return

                def read(self):
                    return self.value

            class Complete:
                def __init__(self):
                    try:
                        raise ValueError("fallback")
                    except Exception:
                        self.value = 1
                    finally:
                        return

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 1)
        self.assertIn("Missing.value", state_findings[0].message)

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

    def test_shared_mutable_class_state_ignores_test_recorders(self) -> None:
        findings = self.lint(
            """
            class RecordingBackend:
                calls = []

                def send(self, message):
                    self.calls.append(message)
            """,
            path="tests/test_backend.py",
        )

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

    def test_inline_suppressions_allow_reasons_and_other_directives(self) -> None:
        findings = self.lint("""
            def reason():  # noqa: SLP001 intentional compatibility stub
                pass

            def typed():  # type: ignore[misc]  # noqa: SLP001
                pass

            def slop_reason():  # slop: ignore [SLP001] - generated interface
                pass
            """)

        self.assert_codes(findings, [])

    def test_multiline_call_suppression_uses_the_closing_line(self) -> None:
        findings = self.lint("""
            import requests

            requests.get(
                "https://service.test",
                timeout=5,
            )  # noqa: SLP011

            payload = (
                requests.get(
                    "https://service.test",
                    timeout=5,
                )
                .json()
            )  # noqa: SLP011
            """)

        self.assert_codes(findings, [])

    def test_multiline_compound_header_suppression_uses_the_colon_line(self) -> None:
        suppressed = self.lint("""
            import requests

            if (
                requests.get("https://service.test", timeout=5).ok
            ):  # noqa: SLP011
                pass

            while (
                requests.get("https://service.test", timeout=5).ok
            ):  # noqa: SLP011
                break

            with requests.get(
                "https://service.test",
                timeout=5,
            ) as response:  # noqa: SLP011
                consume(response)
            """)
        unsuppressed = self.lint("""
            import requests

            if (
                requests.get("https://service.test", timeout=5).ok
            ):
                pass
            """)

        self.assert_codes(suppressed, [])
        self.assert_codes(unsuppressed, ["SLP011"])
        self.assertEqual(unsuppressed[0].line, 5)

    def test_multiline_exception_header_suppression_uses_the_colon_line(
        self,
    ) -> None:
        suppressed = self.lint("""
            def normal():
                try:
                    risky()
                except (
                    Exception
                ):  # noqa: SLP003
                    recover()

            def grouped():
                try:
                    risky()
                except* (
                    Exception
                ):  # noqa: SLP003
                    recover()
            """)
        unsuppressed = self.lint("""
            def normal():
                try:
                    risky()
                except (
                    Exception
                ):
                    recover()

            def grouped():
                try:
                    risky()
                except* (
                    Exception
                ):
                    recover()
            """)

        self.assert_codes(suppressed, [])
        self.assert_codes(unsuppressed, ["SLP003", "SLP003"])

    def test_multiline_match_guard_suppression_uses_the_colon_line(self) -> None:
        suppressed = self.lint("""
            import requests

            match subject:
                case _ if (
                    requests.get("https://service.test", timeout=5).ok
                ):  # noqa: SLP011
                    pass
            """)
        unsuppressed = self.lint("""
            import requests

            match subject:
                case _ if (
                    requests.get("https://service.test", timeout=5).ok
                ):
                    pass
            """)

        self.assert_codes(suppressed, [])
        self.assert_codes(unsuppressed, ["SLP011"])
        self.assertEqual(unsuppressed[0].line, 6)

    def test_multiline_match_subject_suppression_uses_the_colon_line(self) -> None:
        findings = self.lint("""
            import requests

            def fetch():
                match requests.get(
                    "https://service.test",
                    timeout=5,
                ).status_code:  # noqa: SLP011
                    case _:
                        requests.get(
                            "https://other.test",
                            timeout=5,
                        ).text
            """)

        self.assert_codes(findings, ["SLP011"])
        self.assertEqual(findings[0].line, 10)

    def test_compound_header_suppression_does_not_leak_into_body(self) -> None:
        findings = self.lint("""
            import requests

            if enabled:  # noqa: SLP011
                requests.get("https://service.test", timeout=5).text
            """)

        self.assert_codes(findings, ["SLP011"])
        self.assertEqual(findings[0].line, 5)

    def test_body_suppressions_do_not_suppress_compound_findings(self) -> None:
        findings = self.lint("""
            def pending():
                pass  # noqa: SLP001

            def recover_value():
                try:
                    risky()
                except Exception:
                    recover()  # noqa: SLP003
            """)

        self.assert_codes(findings, ["SLP001", "SLP003"])

    def test_suppression_text_embedded_in_comment_prose_is_not_a_directive(
        self,
    ) -> None:
        findings = self.lint("""
            def pending():  # Example: # noqa: SLP001
                pass
            """)

        self.assert_codes(findings, ["SLP001"])

    def test_suppression_payload_must_be_an_explicit_code_list(self) -> None:
        findings = self.lint("""
            def noqa_prose():  # noqa: This SLP001 example is documentation
                pass

            def slop_prose():  # slop: ignore [This SLP001 example]
                pass

            def malformed_code():  # noqa: SLP001suffix
                pass

            def valid_list():  # noqa: F401, SLP001
                pass
            """)

        self.assert_codes(findings, ["SLP001", "SLP001", "SLP001"])

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

    def test_http_status_rule_rejects_resolved_failure_statuses(self) -> None:
        findings = self.lint("""
            import requests

            def direct_branch():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code != 500:
                    raise RuntimeError("unexpected status")
                return response.text

            def direct_assertion():
                response = requests.get("https://service.test", timeout=5)
                assert response.status_code == 500
                return response.text

            def failure_membership():
                response = requests.get("https://service.test", timeout=5)
                if response.status_code not in {500, 503}:
                    raise RuntimeError("unexpected status")
                return response.text
            """)

        self.assert_codes(findings, ["SLP011", "SLP011", "SLP011"])

    def test_operational_matches_require_pure_subjects_and_accept_inline_results(
        self,
    ) -> None:
        unsafe = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                match response.text or response.ok:
                    case True:
                        return response.text
                    case False:
                        raise RuntimeError("request failed")

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                match completed.stdout or completed.returncode:
                    case 0:
                        return completed.stdout
                    case _:
                        raise RuntimeError("worker failed")
            """)
        corrected = self.lint("""
            import requests
            import subprocess

            def fetch():
                match requests.get(
                    "https://service.test",
                    timeout=5,
                ).status_code:
                    case 200 | 204:
                        return True
                    case _:
                        raise RuntimeError("request failed")

            def run():
                match subprocess.run(["worker"]).returncode:
                    case 0:
                        return True
                    case _:
                        raise RuntimeError("worker failed")
            """)

        self.assert_codes(unsafe, ["SLP011", "SLP009"])
        self.assert_codes(corrected, [])

    def test_operational_matches_respect_constant_irrefutable_guards(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def checked_http(marker):
                response = requests.get("https://service.test", timeout=5)
                match marker:
                    case _ if True:
                        response.raise_for_status()
                return response.text

            def checked_process(marker):
                completed = subprocess.run(["worker"], capture_output=True)
                match marker:
                    case _ if True:
                        completed.check_returncode()
                return completed.stdout

            def unchecked_http(marker):
                response = requests.get("https://service.test", timeout=5)
                match marker:
                    case _ if False:
                        response.raise_for_status()
                    case _:
                        pass
                return response.text

            def unchecked_process(marker):
                completed = subprocess.run(["worker"], capture_output=True)
                match marker:
                    case _ if False:
                        completed.check_returncode()
                    case _:
                        pass
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in findings], [20, 29])

    def test_operational_boolean_checks_validate_before_consumption(self) -> None:
        unsafe = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                if not (response.text and response.ok):
                    raise RuntimeError("request failed")
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                if not (completed.stdout and completed.returncode == 0):
                    raise RuntimeError("worker failed")
                return completed.stdout

            def chained():
                response = requests.get("https://service.test", timeout=5)
                if False == response.ok == True:
                    raise RuntimeError("request failed")
                return response.text
            """)
        corrected = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                if not (response.ok and response.text):
                    raise RuntimeError("request failed")
                return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                if not (completed.returncode == 0 and completed.stdout):
                    raise RuntimeError("worker failed")
                return completed.stdout
            """)

        self.assert_codes(unsafe, ["SLP011", "SLP009", "SLP011"])
        self.assert_codes(corrected, [])

    def test_operational_failure_paths_follow_enclosing_controls(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def nested_if(enabled):
                response = requests.get("https://service.test", timeout=5)
                if enabled:
                    if response.ok:
                        return response.text
                raise RuntimeError("request failed")

            def nested_with():
                completed = subprocess.run(["worker"], capture_output=True)
                with managed():
                    if completed.returncode == 0:
                        return completed.stdout
                raise RuntimeError("worker failed")

            def nested_try():
                response = requests.get("https://service.test", timeout=5)
                try:
                    if response.ok:
                        return response.text
                finally:
                    audit()
                raise RuntimeError("request failed")

            def nested_match(flag):
                completed = subprocess.run(["worker"], capture_output=True)
                match flag:
                    case True:
                        if completed.returncode == 0:
                            return completed.stdout
                    case _:
                        pass
                raise RuntimeError("worker failed")
            """)

        self.assert_codes(findings, [])

    def test_operational_loop_exits_can_abandon_failed_results(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch(urls):
                for url in urls:
                    response = requests.get(url, timeout=5)
                    if not response.ok:
                        continue
                    consume(response.text)

            def run(commands):
                for command in commands:
                    completed = subprocess.run(command, capture_output=True)
                    if completed.returncode:
                        break
                    consume(completed.stdout)
            """)

        self.assert_codes(findings, [])

    def test_operational_validation_precedes_later_exception_handlers(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch(flag):
                response = requests.get("https://service.test", timeout=5)
                try:
                    if flag:
                        if True:
                            response.raise_for_status()
                    else:
                        response.raise_for_status()
                    risky()
                except ValueError:
                    consume(response.text)

            def run(flag):
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    if flag:
                        completed.check_returncode()
                    else:
                        completed.check_returncode()
                    if other():
                        risky()
                except ValueError:
                    consume(completed.stdout)

            def ordered_handlers():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except Exception:
                    raise
                except requests.RequestException:
                    recover()
                return response.text

            def specific_then_broad():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except requests.RequestException:
                    raise
                except Exception:  # noqa: SLP003
                    recover()
                return response.text

            def common_validation(flag):
                response = requests.get("https://service.test", timeout=5)
                try:
                    if flag:
                        response.raise_for_status()
                    response.raise_for_status()
                    risky()
                except ValueError:
                    consume(response.text)
            """)

        self.assert_codes(findings, [])

    def test_operational_validation_handlers_respect_http_client(self) -> None:
        findings = self.lint("""
            import httpx
            import requests

            def httpx_with_requests_handler():
                response = httpx.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except requests.RequestException:
                    raise
                except Exception:  # noqa: SLP003
                    recover()
                return response.text

            def requests_with_httpx_handler():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except httpx.HTTPError:
                    raise
                except Exception:  # noqa: SLP003
                    recover()
                return response.text

            def inline_httpx_with_requests_handler():
                try:
                    httpx.get(
                        "https://service.test",
                        timeout=5,
                    ).raise_for_status()
                except requests.RequestException:
                    raise
                except Exception:  # noqa: SLP003
                    recover()

            def inline_requests_with_httpx_handler():
                try:
                    requests.get(
                        "https://service.test",
                        timeout=5,
                    ).raise_for_status()
                except httpx.HTTPError:
                    raise
                except Exception:  # noqa: SLP003
                    recover()
            """)

        self.assert_codes(findings, ["SLP011", "SLP011", "SLP011", "SLP011"])

    def test_operational_suppressors_respect_http_client(self) -> None:
        findings = self.lint("""
            import contextlib
            import httpx
            import requests

            def httpx_with_requests_suppressor():
                response = httpx.get("https://service.test", timeout=5)
                with contextlib.suppress(requests.RequestException):
                    response.raise_for_status()
                return response.text

            def requests_with_httpx_suppressor():
                response = requests.get("https://service.test", timeout=5)
                with contextlib.suppress(httpx.HTTPError):
                    response.raise_for_status()
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in findings])

    def test_operational_flow_tracks_non_call_raises_and_trystar(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def mapping_lookup(mapping, key):
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    mapping[key]
                    completed.check_returncode()
                except KeyError:
                    consume(completed.stdout)

            def division(n):
                response = requests.get("https://service.test", timeout=5)
                try:
                    1 / n
                    response.raise_for_status()
                except ZeroDivisionError:
                    consume(response.text)

            def attribute_access(obj):
                response = requests.get("https://service.test", timeout=5)
                try:
                    obj.value
                    response.raise_for_status()
                except AttributeError:
                    consume(response.text)

            def process_group():
                try:
                    completed = subprocess.run(["worker"], capture_output=True)
                    risky()
                    completed.check_returncode()
                except* ValueError:
                    consume(completed.stdout)

            def request_group():
                try:
                    response = requests.get("https://service.test", timeout=5)
                    risky()
                    response.raise_for_status()
                except* ValueError:
                    consume(response.text)
            """)

        self.assert_codes(
            findings,
            ["SLP009", "SLP011", "SLP011", "SLP009", "SLP011"],
        )

    def test_validation_handlers_stop_after_builtin_supertype(self) -> None:
        findings = self.lint("""
            import requests

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except OSError:
                    raise
                except requests.HTTPError:
                    return response.text
                return response.text
            """)

        self.assertNotIn("SLP011", [finding.code for finding in findings])

    def test_inline_validation_respects_finally_overrides(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    audit()
                except ValueError:
                    recover()
                else:
                    requests.get(
                        "https://service.test",
                        timeout=5,
                    ).raise_for_status()
                finally:
                    return None

            def run():
                try:
                    raise ValueError
                except ValueError:
                    subprocess.run(["worker"]).check_returncode()
                finally:
                    return None
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_inline_walrus_validation_tracks_handler_consumption(self) -> None:
        findings = self.lint("""
            import requests

            def fetch():
                try:
                    (response := requests.get(
                        "https://service.test",
                        timeout=5,
                    )).raise_for_status()
                except requests.HTTPError:
                    return response.text
            """)

        self.assert_codes(findings, ["SLP011"])

    def test_operational_flow_tracks_import_errors(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    import optional_dependency
                    response.raise_for_status()
                except ImportError:
                    return response.text

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    from optional_dependency import feature
                    completed.check_returncode()
                except ImportError:
                    return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_flow_routes_inner_suite_raises_outward(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def from_else():
                try:
                    try:
                        audit()
                    except ValueError:
                        recover()
                    else:
                        response = requests.get(
                            "https://service.test",
                            timeout=5,
                        )
                        helper()
                        response.raise_for_status()
                except TypeError:
                    return response.text

            def from_handler():
                try:
                    try:
                        raise ValueError
                    except ValueError:
                        completed = subprocess.run(
                            ["worker"],
                            capture_output=True,
                        )
                        helper()
                        completed.check_returncode()
                except TypeError:
                    return completed.stdout

            def from_finally():
                try:
                    try:
                        audit()
                    finally:
                        response = requests.get(
                            "https://service.test",
                            timeout=5,
                        )
                        helper()
                        response.raise_for_status()
                except TypeError:
                    return response.text
            """)

        self.assert_codes(findings, ["SLP011", "SLP009", "SLP011"])

    def test_operational_flow_routes_mixed_explicit_raise_paths(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def unsafe_http(flag):
                try:
                    response = requests.get("https://service.test", timeout=5)
                    if flag:
                        raise ValueError("fallback")
                    response.raise_for_status()
                except ValueError:
                    return response.text
                return response.text

            def unsafe_process(flag):
                try:
                    completed = subprocess.run(["worker"], capture_output=True)
                    if flag:
                        raise ValueError("fallback")
                    completed.check_returncode()
                except ValueError:
                    return completed.stdout
                return completed.stdout

            def safe_http(flag):
                try:
                    response = requests.get("https://service.test", timeout=5)
                    if flag:
                        raise ValueError("fallback")
                    response.raise_for_status()
                except ValueError:
                    return None
                return response.text

            def safe_process(flag):
                try:
                    completed = subprocess.run(["worker"], capture_output=True)
                    if flag:
                        raise ValueError("fallback")
                    completed.check_returncode()
                except ValueError:
                    return None
                return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])
        self.assertEqual([finding.line for finding in findings], [7, 17])

    def test_operational_rules_accept_non_expression_validation_calls(
        self,
    ) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def assigned_http():
                response = requests.get("https://service.test", timeout=5)
                checked = response.raise_for_status()
                return response.text

            def annotated_process():
                completed = subprocess.run(["worker"], capture_output=True)
                checked: None = completed.check_returncode()
                return completed.stdout

            def returned_http():
                response = requests.get("https://service.test", timeout=5)
                return response.raise_for_status()

            def returned_process():
                completed = subprocess.run(["worker"], capture_output=True)
                return completed.check_returncode()
            """)

        codes = [finding.code for finding in findings]
        self.assertNotIn("SLP009", codes)
        self.assertNotIn("SLP011", codes)

    def test_operational_rules_accept_ordered_expression_validation(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def tuple_validation():
                response = requests.get("https://service.test", timeout=5)
                checked = (response.raise_for_status(),)
                return response.text

            def list_validation():
                completed = subprocess.run(["worker"], capture_output=True)
                checked = [completed.check_returncode()]
                return completed.stdout

            def late_validation():
                response = requests.get("https://service.test", timeout=5)
                checked = (response.text, response.raise_for_status())
                return response.text
            """)

        self.assert_codes(findings, ["SLP011"])
        self.assertEqual(findings[0].line, 16)

    def test_operational_handlers_keep_preceding_implicit_raises(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    helper()
                    raise ValueError
                except TypeError:
                    consume(response.text)

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    helper()
                    raise ValueError
                except TypeError:
                    consume(completed.stdout)

            def raise_expression():
                response = requests.get("https://service.test", timeout=5)
                try:
                    raise ValueError(helper())
                except TypeError:
                    consume(response.text)
            """)

        self.assert_codes(findings, ["SLP011", "SLP009", "SLP011"])

    def test_operational_walrus_failure_paths_track_bound_results(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                if not (
                    response := requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                ).ok:
                    return response.text

            def run():
                if (
                    completed := subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                ).returncode:
                    return completed.stdout
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_walrus_headers_reject_early_body_uses(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                if (
                    response := requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                ) is not None:
                    consume(response.text)
                response.raise_for_status()

            def run():
                if (
                    completed := subprocess.run(
                        ["worker"],
                        capture_output=True,
                    )
                ) is not None:
                    consume(completed.stdout)
                completed.check_returncode()
            """)

        self.assert_codes(findings, ["SLP011", "SLP009"])

    def test_operational_abrupt_exits_run_finally_blocks(self) -> None:
        unsafe = self.lint("""
            import requests

            def fetch(items):
                for item in items:
                    try:
                        response = requests.get(
                            "https://service.test",
                            timeout=5,
                        )
                        break
                    finally:
                        consume(response.text)
                response.raise_for_status()
            """)
        checked = self.lint("""
            import requests

            def return_after_check():
                try:
                    response = requests.get(
                        "https://service.test",
                        timeout=5,
                    )
                    return
                finally:
                    response.raise_for_status()

            def continue_after_check(items):
                for item in items:
                    try:
                        response = requests.get(
                            "https://service.test",
                            timeout=5,
                        )
                        continue
                    finally:
                        response.raise_for_status()
            """)

        self.assert_codes(unsafe, ["SLP011"])
        self.assertNotIn("SLP011", [finding.code for finding in checked])

    def test_operational_implicit_raises_respect_boolean_short_circuiting(
        self,
    ) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def fetch():
                response = requests.get("https://service.test", timeout=5)
                try:
                    False and risky()
                    response.raise_for_status()
                except TypeError:
                    consume(response.text)

            def run():
                completed = subprocess.run(["worker"], capture_output=True)
                try:
                    True or risky()
                    completed.check_returncode()
                except TypeError:
                    consume(completed.stdout)

            def reachable():
                response = requests.get("https://service.test", timeout=5)
                try:
                    True and risky()
                    response.raise_for_status()
                except TypeError:
                    consume(response.text)
            """)

        self.assert_codes(findings, ["SLP011"])

    def test_operational_bindings_do_not_validate_replaced_results(self) -> None:
        findings = self.lint("""
            import requests
            import subprocess

            def match_http(value):
                response = requests.get("https://service.test", timeout=5)
                match value:
                    case response:
                        response.raise_for_status()

            def match_subprocess(value):
                completed = subprocess.run(["worker"], capture_output=True)
                match value:
                    case completed:
                        completed.check_returncode()

            def with_http():
                response = requests.get("https://service.test", timeout=5)
                with managed() as response:
                    response.raise_for_status()

            def with_subprocess():
                completed = subprocess.run(["worker"], capture_output=True)
                with managed() as completed:
                    completed.check_returncode()

            def preserved_http(value):
                response = requests.get("https://service.test", timeout=5)
                match value:
                    case captured:
                        response.raise_for_status()

            def preserved_subprocess():
                completed = subprocess.run(["worker"], capture_output=True)
                with managed() as other:
                    completed.check_returncode()
            """)

        self.assert_codes(findings, ["SLP011", "SLP009", "SLP011", "SLP009"])

    def test_inline_failure_raises_must_escape_enclosing_handlers(self) -> None:
        swallowed = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    if not requests.get(
                        "https://service.test",
                        timeout=5,
                    ).ok:
                        raise ValueError("request failed")
                except ValueError:
                    recover()

            def run():
                try:
                    if subprocess.run(["worker"]).returncode != 0:
                        raise ValueError("worker failed")
                except ValueError:
                    recover()
            """)
        escaping = self.lint("""
            import requests
            import subprocess

            def fetch():
                try:
                    if not requests.get(
                        "https://service.test",
                        timeout=5,
                    ).ok:
                        raise ValueError("request failed")
                except ValueError:
                    raise

            def run():
                try:
                    if subprocess.run(["worker"]).returncode != 0:
                        raise ValueError("worker failed")
                except ValueError:
                    raise

            def continued():
                try:
                    if not requests.get(
                        "https://service.test",
                        timeout=5,
                    ).ok:
                        raise ValueError("request failed")
                except ValueError:
                    recover()
                raise RuntimeError("request failed")
            """)

        self.assert_codes(swallowed, ["SLP011", "SLP009"])
        self.assert_codes(escaping, [])

    def test_assertion_free_tests_ignore_unreachable_nested_oracles(self) -> None:
        findings = self.lint(
            """
            def test_return_inside_try():
                try:
                    return
                    assert False
                finally:
                    cleanup()

            def test_return_inside_with():
                with managed():
                    return
                    assert False

            def test_unreachable_handler():
                try:
                    pass
                except ValueError:
                    assert False

            def test_false_match_guard(value):
                match value:
                    case _ if False:
                        assert False
                    case _:
                        pass
            """,
            path="tests/test_nested_oracles.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014", "SLP014", "SLP014"])

    def test_assertion_free_tests_follow_reachable_exception_handlers(
        self,
    ) -> None:
        findings = self.lint(
            """
            def test_return_with_unreachable_following_oracle():
                try:
                    return
                except ValueError:
                    recover()
                assert False

            def test_mismatched_handler():
                try:
                    raise ValueError
                except TypeError:
                    assert False
            """,
            path="tests/test_exception_oracles.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014"])

    def test_assertion_free_testcase_aliases_merge_branch_state(self) -> None:
        findings = self.lint(
            """
            import unittest

            class BaseCase(unittest.TestCase):
                pass

            if enabled:
                FirstAlias = object
            else:
                FirstAlias = BaseCase

            class FirstTests(FirstAlias):
                def test_example(case):
                    case.assertEqual(value, 1)

            if enabled:
                SecondAlias = BaseCase
            else:
                SecondAlias = object

            class SecondTests(SecondAlias):
                def test_example(case):
                    case.assertEqual(value, 1)
            """,
            path="tests/test_aliases.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014"])

    def test_assertion_free_testcase_aliases_merge_compound_state(self) -> None:
        findings = self.lint(
            """
            import unittest

            class BaseCase(unittest.TestCase):
                pass

            LoopAlias = object
            for _ in values:
                LoopAlias = BaseCase

            class LoopTests(LoopAlias):
                def test_example(case):
                    case.assertEqual(value, 1)

            TryAlias = object
            try:
                TryAlias = object
            except LookupError:
                TryAlias = BaseCase

            class TryTests(TryAlias):
                def test_example(case):
                    case.assertEqual(value, 1)

            MatchAlias = object
            match value:
                case 1:
                    MatchAlias = object
                case _:
                    MatchAlias = BaseCase

            class MatchTests(MatchAlias):
                def test_example(case):
                    case.assertEqual(value, 1)
            """,
            path="tests/test_aliases.py",
        )

        self.assert_codes(findings, ["SLP014", "SLP014", "SLP014"])

    def test_conditional_instance_state_tracks_expression_header_raises(
        self,
    ) -> None:
        findings = self.lint("""
            from contextlib import suppress

            class CallHeader:
                def __init__(self, text):
                    with suppress(ValueError):
                        if int(text):
                            self.value = 1
                        else:
                            self.value = 2

                def read(self):
                    return self.value

            class SubscriptHeader:
                def __init__(self, values):
                    with suppress(IndexError):
                        if values[0]:
                            self.value = 1
                        else:
                            self.value = 2

                def read(self):
                    return self.value

            class AttributeHeader:
                def __init__(self, obj):
                    with suppress(AttributeError):
                        self.value = obj.value

                def read(self):
                    return self.value

            class SafeHeader:
                def __init__(self, flag):
                    with suppress(ValueError):
                        if flag:
                            self.value = 1
                        else:
                            self.value = 2

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 3)
        expected_classes = {"AttributeHeader", "CallHeader", "SubscriptHeader"}
        reported_classes = {
            class_name
            for class_name in (*expected_classes, "SafeHeader")
            if any(f"`{class_name}." in finding.message for finding in state_findings)
        }
        self.assertEqual(reported_classes, expected_classes)

    def test_conditional_instance_state_tracks_iteration_header_raises(
        self,
    ) -> None:
        findings = self.lint("""
            from contextlib import suppress

            class LoopHeader:
                def __init__(self):
                    with suppress(ValueError):
                        for item in load_items():
                            consume(item)
                        self.value = 1

                def read(self):
                    return self.value

            class MatchHeader:
                def __init__(self, text):
                    with suppress(ValueError):
                        match parse(text):
                            case _:
                                self.value = 1

                def read(self):
                    return self.value
            """)

        state_findings = [finding for finding in findings if finding.code == "SLP016"]
        self.assertEqual(len(state_findings), 2)
        self.assertTrue(
            all(
                any(f"`{class_name}." in finding.message for finding in state_findings)
                for class_name in ("LoopHeader", "MatchHeader")
            )
        )

    def test_conditional_instance_state_distinguishes_safe_literal_binops(
        self,
    ) -> None:
        findings = self.lint("""
            from contextlib import suppress

            class SafeLiteral:
                def __init__(self):
                    with suppress(Exception):
                        self.value = 1 + 2

                def read(self):
                    return self.value

            class RaisingLiteral:
                def __init__(self):
                    with suppress(ZeroDivisionError):
                        self.value = 1 / 0

                def read(self):
                    return self.value
            """)

        self.assert_codes(findings, ["SLP016"])
        self.assertIn("RaisingLiteral.value", findings[0].message)

    def test_conditional_instance_state_uses_implicit_exception_edge_state(
        self,
    ) -> None:
        findings = self.lint("""
            class AssignedFirst:
                def __init__(self, text):
                    try:
                        self.value = 1
                        int(text)
                    except ValueError:
                        return

                def read(self):
                    return self.value

            class RaisedFirst:
                def __init__(self, text):
                    try:
                        int(text)
                        self.value = 1
                    except ValueError:
                        return

                def read(self):
                    return self.value
            """)

        self.assert_codes(findings, ["SLP016"])
        self.assertIn("RaisedFirst.value", findings[0].message)

    def test_placeholder_aliases_follow_finally_and_reachable_handlers(
        self,
    ) -> None:
        findings = self.lint("""
            from typing import Protocol

            Changed = Protocol
            while True:
                try:
                    break
                finally:
                    Changed = object

            class Concrete(Changed):
                def run(self):
                    pass

            Safe = object
            while True:
                try:
                    break
                finally:
                    Safe = Protocol

            class Contract(Safe):
                def run(self):
                    pass

            Unreachable = object
            try:
                raise TypeError
            except ValueError:
                Unreachable = Protocol

            class StillConcrete(Unreachable):
                def run(self):
                    pass
            """)

        placeholders = [finding for finding in findings if finding.code == "SLP001"]
        self.assertEqual(len(placeholders), 2)
        self.assertTrue(any("Concrete.run" in item.message for item in placeholders))
        self.assertTrue(
            any("StillConcrete.run" in item.message for item in placeholders)
        )

    def test_broad_exception_aliases_follow_runtime_statement_order(self) -> None:
        findings = self.lint("""
            def fallback():
                from builtins import Exception as Broad
                try:
                    raise ValueError
                except Broad:
                    recover()

            def preserve():
                from builtins import Exception as Broad
                try:
                    raise ValueError
                except Broad:
                    raise

            def imported_too_late():
                try:
                    raise ValueError
                except Broad:
                    recover()
                from builtins import Exception as Broad

            Alias = Exception
            try:
                raise ValueError
            except Alias:
                recover()
            Alias = ValueError
            """)

        broad = [finding for finding in findings if finding.code == "SLP003"]
        self.assertEqual(len(broad), 2)
        self.assertEqual([finding.line for finding in broad], [6, 26])

    def test_operational_aliases_follow_scope_and_runtime_order(self) -> None:
        findings = self.lint("""
            def local_before_rebind():
                import requests as client
                response = client.get("https://service.test", timeout=5)
                client = LocalClient()
                return response.text

            def late_global():
                response = http.get("https://service.test", timeout=5)
                return response.text
            import requests as http

            def declared_global():
                global http
                response = http.get("https://service.test", timeout=5)
                return response.text

            def comprehension_scope():
                import requests as client
                [client for client in values]
                return client.get("https://service.test", timeout=5).text
            """)
        clean = self.lint("""
            response = client.get("https://service.test", timeout=5)
            import requests as client

            def match_capture():
                import requests as client
                match value:
                    case client:
                        return client.get(
                            "https://service.test",
                            timeout=5,
                        ).text
            """)

        operational = [item for item in findings if item.code == "SLP011"]
        self.assertEqual(len(operational), 4)
        self.assertNotIn("SLP011", [item.code for item in clean])

    def test_operational_validation_respects_expression_order(self) -> None:
        findings = self.lint("""
            import requests

            def list_checked():
                response = requests.get("https://service.test", timeout=5)
                values = [prepare(), response.raise_for_status()]
                return response.text

            def dict_checked():
                response = requests.get("https://service.test", timeout=5)
                values = {"status": response.raise_for_status()}
                return response.text

            def set_checked():
                response = requests.get("https://service.test", timeout=5)
                values = {response.raise_for_status()}
                return response.text

            def call_checked():
                response = requests.get("https://service.test", timeout=5)
                consume(prepare(), response.raise_for_status())
                return response.text

            def used_first():
                response = requests.get("https://service.test", timeout=5)
                values = [response.text, response.raise_for_status()]
                return response.text

            def handler_before_check():
                response = requests.get("https://service.test", timeout=5)
                try:
                    values = [prepare(), response.raise_for_status()]
                except ValueError:
                    return response.text
                return response.text
            """)

        operational = [item for item in findings if item.code == "SLP011"]
        self.assertEqual(len(operational), 2)
        self.assertEqual([item.line for item in operational], [25, 30])

    def test_operational_validation_accepts_guaranteed_loop_and_match(
        self,
    ) -> None:
        findings = self.lint("""
            import requests

            def nonempty_loop():
                response = requests.get("https://service.test", timeout=5)
                for _ in [1]:
                    response.raise_for_status()
                return response.text

            def maybe_loop(values):
                response = requests.get("https://service.test", timeout=5)
                for _ in values:
                    response.raise_for_status()
                return response.text

            def guarded_match(value):
                response = requests.get("https://service.test", timeout=5)
                match value:
                    case _ if response.raise_for_status() is None:
                        pass
                return response.text

            def refutable_match(value):
                response = requests.get("https://service.test", timeout=5)
                match value:
                    case 1 if response.raise_for_status() is None:
                        pass
                return response.text
            """)

        operational = [item for item in findings if item.code == "SLP011"]
        self.assertEqual(len(operational), 2)
        self.assertEqual([item.line for item in operational], [11, 24])

    def test_operational_handlers_use_aliases_at_handler_location(self) -> None:
        findings = self.lint("""
            import requests

            def broad_at_handler():
                Catch = Exception
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except Catch:
                    return response.text
                Catch = ValueError
                return response.text

            def narrow_at_handler():
                Catch = ValueError
                response = requests.get("https://service.test", timeout=5)
                try:
                    response.raise_for_status()
                except Catch:
                    return response.text
                Catch = Exception
                return response.text
            """)

        operational = [item for item in findings if item.code == "SLP011"]
        self.assertEqual(len(operational), 1)
        self.assertEqual(operational[0].line, 6)

    def test_assertion_free_rule_evaluates_string_and_comparison_skips(
        self,
    ) -> None:
        findings = self.lint(
            """
            import pytest

            @pytest.mark.skipif("False", reason="runs")
            def test_string_false():
                exercise()

            @pytest.mark.skipif("True", reason="skipped")
            def test_string_true():
                exercise()

            @pytest.mark.skipif(1 == 2, reason="runs")
            def test_compare_false():
                exercise()

            @pytest.mark.skipif(2 > 1, reason="skipped")
            def test_compare_true():
                exercise()

            @pytest.fixture
            def test_real_fixture():
                return object()

            pytest = helper

            @pytest.fixture
            def test_fake_fixture():
                exercise()
            """,
            path="tests/test_generated.py",
        )

        assertions = [item for item in findings if item.code == "SLP014"]
        self.assertEqual(len(assertions), 3)
        reported = {item.message.split("`")[1] for item in assertions}
        self.assertEqual(
            reported,
            {"test_compare_false", "test_fake_fixture", "test_string_false"},
        )

    def test_assertion_free_rule_requires_reachable_effective_oracles(
        self,
    ) -> None:
        findings = self.lint(
            """
            def test_swallowed_assertion():
                try:
                    assert result()
                except AssertionError:
                    pass

            def test_ordered_handlers():
                try:
                    raise ValueError
                except Exception:
                    recover()
                except ValueError:
                    assert False

            def test_empty_range():
                for _ in range(0):
                    assert True

            def test_nonempty_range():
                for _ in range(1):
                    assert True

            def test_local_oracle_before_rebind():
                import pytest as testing
                testing.fail("stop")
                testing = helper
            """,
            path="tests/test_generated.py",
        )

        assertions = [item for item in findings if item.code == "SLP014"]
        self.assertEqual(len(assertions), 3)
        reported = {item.message.split("`")[1] for item in assertions}
        self.assertEqual(
            reported,
            {
                "test_empty_range",
                "test_ordered_handlers",
                "test_swallowed_assertion",
            },
        )

    def test_conditional_state_accepts_eager_nonempty_comprehensions(
        self,
    ) -> None:
        findings = self.lint("""
            class Eager:
                def __init__(self):
                    [None for self.first in [1]]
                    {self.second for self.second in {1}}
                    {self.third: None for self.third in range(1)}

                def read(self):
                    return self.first, self.second, self.third

            class Empty:
                def __init__(self):
                    [None for self.value in []]

                def read(self):
                    return self.value

            class Lazy:
                def __init__(self):
                    (None for self.value in [1])

                def read(self):
                    return self.value
            """)

        state = [item for item in findings if item.code == "SLP016"]
        self.assertEqual(len(state), 2)
        reported = {item.message.split("`")[1] for item in state}
        self.assertEqual(reported, {"Empty.value", "Lazy.value"})

    def test_conditional_state_tracks_context_entry_and_guard_aliases(
        self,
    ) -> None:
        findings = self.lint("""
            from builtins import AttributeError as Missing
            from builtins import hasattr as has_attribute
            from contextlib import suppress

            class ContextEntry:
                def __init__(self, first, second):
                    with suppress(Exception), first, second as self.value:
                        pass

                def read(self):
                    return self.value

            class Guarded:
                def __init__(self, value):
                    if value:
                        self.optional = value

                def read(self):
                    if has_attribute(self, "optional"):
                        return self.optional
                    try:
                        return self.optional
                    except Missing:
                        return None

            has_attribute = custom_hasattr

            class ShadowedGuard:
                def __init__(self, value):
                    if value:
                        self.optional = value

                def read(self):
                    if has_attribute(self, "optional"):
                        return self.optional
                    return None
            """)

        state = [item for item in findings if item.code == "SLP016"]
        self.assertEqual(len(state), 2)
        reported = {item.message.split("`")[1] for item in state}
        self.assertEqual(reported, {"ContextEntry.value", "ShadowedGuard.optional"})

    def test_conditional_state_excludes_failed_construction_paths(self) -> None:
        findings = self.lint("""
            class NonNoneReturn:
                def __init__(self, ready):
                    if ready:
                        self.value = 1
                    return 1

                def read(self):
                    return self.value

            class TypedSafe:
                def __init__(self, flag):
                    try:
                        if flag:
                            self.value = 1
                            raise ValueError
                        self.value = 2
                        raise TypeError
                    except ValueError:
                        self.value = 3
                    except TypeError:
                        pass

                def read(self):
                    return self.value

            class TypedMissing:
                def __init__(self, flag):
                    try:
                        if flag:
                            self.value = 1
                            raise ValueError
                        raise TypeError
                    except ValueError:
                        pass
                    except TypeError:
                        pass

                def read(self):
                    return self.value
            """)

        state = [item for item in findings if item.code == "SLP016"]
        self.assertEqual(len(state), 1)
        self.assertIn("TypedMissing.value", state[0].message)

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
            mixed_result = self.run_main([str(dirty), str(root / "missing.py")])

        self.assertEqual(clean_result[0], pyclichecker.EXIT_CLEAN)
        self.assertIn("No pyclichecker findings", clean_result[1])
        self.assertNotIn("AI-slop", clean_result[1])
        self.assertEqual(dirty_result[0], pyclichecker.EXIT_FINDINGS)
        self.assertIn("SLP001", dirty_result[1])
        self.assertEqual(missing_result[0], pyclichecker.EXIT_OPERATIONAL_ERROR)
        self.assertIn("path does not exist", missing_result[2])
        self.assertEqual(mixed_result[0], pyclichecker.EXIT_OPERATIONAL_ERROR)
        self.assertIn("SLP001", mixed_result[1])
        self.assertIn("path does not exist", mixed_result[2])

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

    def test_standard_input_read_errors_are_operational_errors(self) -> None:
        for read_error in (OSError("read failed"), UnicodeError("decode failed")):
            with self.subTest(error=type(read_error).__name__):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                    patch("sys.stdin") as input_stream,
                ):
                    input_stream.read.side_effect = read_error
                    exit_code = pyclichecker.main(["-", "--format", "json"])
                payload = json.loads(stdout.getvalue())

                self.assertEqual(exit_code, pyclichecker.EXIT_OPERATIONAL_ERROR)
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(payload["files_checked"], 0)
                self.assertEqual(payload["findings"], [])
                self.assertIn(str(read_error), payload["errors"][0])

    def test_package_version_matches_distribution_metadata(self) -> None:
        self.assertEqual(pyclichecker.VERSION, version("pyclichecker"))

    def test_documented_skill_version_matches_project_version(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with (root / "pyproject.toml").open("rb") as project_file:
            project_version = tomllib.load(project_file)["project"]["version"]
        readme = (root / "README.md").read_text(encoding="utf-8")
        skill = (root / "skills/pyclichecker/SKILL.md").read_text(encoding="utf-8")

        for document in (readme, skill):
            versions = set(re.findall(r"pyclichecker@(\d+\.\d+\.\d+)", document))
            self.assertEqual(versions, {project_version})

    def test_workflow_security_controls(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ci_workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        workflow = (root / ".github/workflows/publish.yml").read_text(encoding="utf-8")

        self.assertEqual(workflow.count("enable-cache: false"), 2)
        self.assertNotIn("enable-cache: true", workflow)
        self.assertEqual(ci_workflow.count("persist-credentials: false"), 1)
        self.assertEqual(workflow.count("persist-credentials: false"), 1)
        for content in (ci_workflow, workflow):
            self.assertIn("uv export --quiet --locked --all-groups", content)
            self.assertIn(
                "pip-audit --strict --requirement .audit-requirements.txt",
                content,
            )
        self.assertIn(
            "WHEEL_PATH: ${{ steps.wheel.outputs.path }}",
            ci_workflow,
        )
        self.assertIn(
            "- name: Smoke-test built wheel\n        shell: python",
            ci_workflow,
        )
        self.assertIn('wheel = os.environ["WHEEL_PATH"]', ci_workflow)
        self.assertNotIn('uvx --from "$WHEEL_PATH"', ci_workflow)
        self.assertNotIn('uvx --from "${{ steps.wheel.outputs.path }}"', ci_workflow)

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
