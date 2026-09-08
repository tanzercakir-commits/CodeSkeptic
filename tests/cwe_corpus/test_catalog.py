#!/usr/bin/env python3
"""Catalog and measurement regressions; synthetic reports are never product evidence."""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("cwe_quality", ROOT / "scripts/cwe_quality.py")
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.catalog = quality.read_json(ROOT, quality.CATALOG)
        self.inventory = quality.read_json(ROOT, quality.INVENTORY)

    def validate(self, root=ROOT):
        return quality.validate(root, self.catalog, self.inventory)

    def reject(self):
        with self.assertRaises((ValueError, TypeError)):
            self.validate()

    @contextmanager
    def copied_root(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-catalog-test-") as temporary:
            root = Path(temporary)
            paths = {row["path"] for row in self.inventory["inputs"]}
            paths.update(row["path"] for row in self.catalog["cases"])
            paths.update((quality.CATALOG, quality.INVENTORY))
            paths.add("tests/cwe_corpus/test_catalog.py")
            paths.update(path.relative_to(ROOT).as_posix()
                         for path in (ROOT / "tests/cwe_corpus/snapshots").glob("*.json"))
            for name in paths:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            yield root

    def test_complete_frozen_input_catalog_is_not_a_quality_result(self):
        result = self.validate()
        expected = quality.frozen_contract_counts(ROOT, self.catalog)
        self.assertEqual(result["rules"], expected["rules"])
        self.assertEqual(result["cases"], expected["cases"])
        self.assertEqual(result["protected_inputs"], expected["protected_inputs"])
        self.assertEqual(result["roles"], expected["roles"])
        self.assertIs(result["quality_measured"], False)

    def test_all_existing_source_tests_are_required(self):
        tests = [row for row in self.inventory["inputs"] if row["path"].startswith("tests/")]
        self.assertEqual(len(tests), quality.frozen_contract_counts(ROOT, self.catalog)["source_test_inputs"])
        self.assertTrue({"tests/AllocSizeOverflowRuleTest.cpp", "tests/FdResourceRuleTest.cpp",
                         "tests/TestHelper.cpp", "tests/TestHelper.h", "tests/CMakeLists.txt",
                         "tests/RegressionCheckpointTest.py", "tests/WorkflowPolicyTest.py"}
                        <= {row["path"] for row in tests})

    def test_missing_rule_rejected(self):
        self.catalog["rules"].pop("uninit-scalar")
        self.reject()

    def test_tier_promotion_rejected(self):
        self.catalog["rules"]["bounds"]["tier_at_selection"] = "supported"
        self.reject()

    def test_noninteger_cwe_identity_rejected(self):
        self.catalog["rules"]["uninit-ptr"]["cwes"] = [824.0]
        self.reject()

    def test_omitted_fixture_rejected(self):
        self.catalog["cases"].pop()
        self.reject()

    def test_duplicate_id_rejected(self):
        self.catalog["cases"].append(copy.deepcopy(self.catalog["cases"][0]))
        self.reject()

    def test_missing_safe_pair_rejected(self):
        row = next(c for c in self.catalog["cases"] if c["rule"] == "uninit-ptr" and c["role"] == "safe")
        row.update(role="unsupported", expected_diagnostics=None)
        self.reject()

    def test_unknown_and_unsupported_cannot_be_counted_as_clean(self):
        for role in ("unknown", "unsupported"):
            with self.subTest(role=role):
                original = copy.deepcopy(self.catalog)
                next(c for c in self.catalog["cases"] if c["role"] == role)["expected_diagnostics"] = []
                self.reject()
                self.catalog = original

    def test_buggy_cannot_be_clean(self):
        self.catalog["cases"][0]["expected_diagnostics"] = []
        self.reject()

    def test_safe_cannot_contain_expected_findings(self):
        self.catalog["cases"][1]["expected_diagnostics"] = [["uninit-ptr", "f"]]
        self.reject()

    def test_wrong_rule_or_function_rejected(self):
        for value in (["bounds", "f"], ["uninit-ptr", "other"], ["uninit-ptr"], True):
            with self.subTest(value=value):
                self.catalog["cases"][0]["expected_diagnostics"] = [value]
                self.reject()

    def test_unfrozen_flags_and_source_config_rejected(self):
        self.catalog["cases"][0]["compile_flags"].append("-DRESULT_DEPENDENT=1")
        self.reject()
        self.catalog["cases"][0]["compile_flags"] = ["-std=c++17"]
        self.catalog["cases"][0]["untrusted_sources"] = ["--accept-partial-coverage"]
        self.reject()

    def test_extra_fields_bad_schema_and_bad_base_rejected(self):
        for key, value in (("schema", "other"), ("selection_base", "short"), ("extra", 1)):
            with self.subTest(key=key):
                original = copy.deepcopy(self.catalog)
                self.catalog[key] = value
                self.reject()
                self.catalog = original

    def test_inventory_removal_duplicate_and_digest_drift_rejected(self):
        original = copy.deepcopy(self.inventory)
        self.inventory["inputs"].pop()
        self.reject()
        self.inventory = copy.deepcopy(original)
        self.inventory["inputs"].append(copy.deepcopy(self.inventory["inputs"][0]))
        self.reject()
        self.inventory = original
        self.inventory["inputs"][0]["sha256"] = "0" * 64
        self.reject()

    def test_floor_bytes_cannot_be_rewritten_silently(self):
        with self.copied_root() as root:
            (root / "scripts/juliet_expected.txt").write_text("CWE476 0 0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "protected input changed"):
                self.validate(root)

    def test_test_deletion_or_edit_rejected(self):
        with self.copied_root() as root:
            (root / "tests/FdResourceRuleTest.cpp").write_text("// removed hard negatives\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "protected input changed"):
                self.validate(root)

    def test_new_source_test_requires_inventory_revision(self):
        with self.copied_root() as root:
            (root / "tests/NewCoreTest.cpp").write_text("// new regression\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "protected inputs"):
                self.validate(root)

    def test_new_corpus_source_cannot_be_silently_omitted(self):
        for extension in (".cpp", ".cc", ".cxx", ".c", ".C", ".h", ".txt"):
            with self.subTest(extension=extension), self.copied_root() as root:
                (root / ("tests/cwe_corpus/omitted" + extension)).write_text("int f(){return 0;}\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "unlisted/missing corpus"):
                    self.validate(root)

    def test_fixture_byte_drift_rejected(self):
        with self.copied_root() as root:
            (root / self.catalog["cases"][0]["path"]).write_text("int f(){return 0;}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fixture changed"):
                self.validate(root)

    def test_symlink_fixture_and_traversal_rejected(self):
        with self.copied_root() as root:
            fixture = root / self.catalog["cases"][0]["path"]
            fixture.unlink()
            fixture.symlink_to(ROOT / self.catalog["cases"][0]["path"])
            with self.assertRaisesRegex(ValueError, "symlink"):
                self.validate(root)
            for name in ("../outside", "/tmp/input", "tests/../input", "tests//input", "tests\\input"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    quality.safe_file(root, name)

    def test_duplicate_json_keys_and_nonfinite_numbers_rejected(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-catalog-json-") as directory:
            root = Path(directory)
            for raw in ('{"same":1,"same":2}', '{"number":NaN}', '{"number":Infinity}', '{"number":1e999}'):
                (root / "input.json").write_text(raw, encoding="utf-8")
                with self.assertRaises(ValueError):
                    quality.read_json(root, "input.json")

    def test_inventory_bytes_bound_to_catalog(self):
        with self.copied_root() as root:
            with (root / quality.INVENTORY).open("ab") as stream:
                stream.write(b"\n")
            with self.assertRaisesRegex(ValueError, "inventory digest"):
                self.validate(root)


class MeasurementTest(unittest.TestCase):
    def setUp(self):
        self.source = Path("/frozen/case.cpp")
        self.version = "0.4.9-dev+g" + "a" * 12
        self.case = {"id": "case", "rule": "resource-leak", "role": "buggy",
                     "expected_diagnostics": [["resource-leak", "f"]] * 2}
        self.capability = {"tier": "supported", "cwes": [401, 772, 775]}
        self.report = {
            "schema": "codeskeptic-report/v1", "tool": "CodeSkeptic",
            "tool_version": self.version, "exit_code": 1, "complete": True,
            "status": "findings", "baseline": None, "suppressions": [],
            "coverage": {
                "schema": "codeskeptic-source-coverage/v1", "complete": True,
                "accept_partial_coverage": False, "analyze_broken_tus": False,
                "attempted_tus": 1, "analyzed_tus": 1, "skipped_tus": 0,
                "broken_tus": 0, "failed_tus": 0, "recovery_tus": 0,
                "attempted_commands": 1, "analyzed_commands": 1,
                "skipped_commands": 0, "failed_commands": 0, "incomplete_functions": 0,
                "sources": [{"file": str(self.source), "status": "analyzed", "reason": "analyzed",
                             "commands": 1, "analyzed_commands": 1, "skipped_commands": 0,
                             "failed_commands": 0, "recovery_commands": 0,
                             "prepass": {"status": "not_requested", "reason": "", "recovery_commands": 0}}]},
            "evidence": {flag: False for flag in quality.stress.EVIDENCE_FLAGS},
            "diagnostics": [], "total": 0, "finding_counts": {},
        }
        self.diagnostics(2)

    def diagnostics(self, count):
        self.report["diagnostics"] = [{"file": str(self.source), "line": 2 + i, "column": 1,
            "function": "f", "rule_id": "resource-leak", "blocks_verdict": True,
            "capability_tier": "supported", "fingerprint": "csf1-" + format(i, "016x"),
            "severity": "error", "message": "Resource leak", "notes": [],
            "rule_metadata": {"cwe_mapping": "mapped", "cwes": [{"id": 772}]}}
            for i in range(count)]
        self.report.update(total=count, exit_code=int(count > 0), status="findings" if count else "clean",
                           finding_counts={"total": count, "blocking": count, "report_only": 0})

    def measure(self):
        return quality.measure_report(self.report, self.case, self.source,
                                      self.report["exit_code"], self.version, self.capability)

    def test_exact_multiplicity_and_order(self):
        expected = {"tp": 2, "fp": 0, "fn": 0, "expected": 2, "observed": 2}
        self.assertEqual(self.measure(), expected)
        self.report["diagnostics"].reverse()
        self.assertEqual(self.measure(), expected)

    def test_missing_finding_is_fn_extra_finding_is_fp(self):
        for count, tp, fp, fn in ((0, 0, 0, 2), (1, 1, 0, 1), (3, 2, 1, 0)):
            with self.subTest(count=count):
                self.diagnostics(count)
                self.assertEqual(self.measure(), {"tp": tp, "fp": fp, "fn": fn,
                                                  "expected": 2, "observed": count})

    def test_safe_fp_is_not_filtered(self):
        self.case.update(role="safe", expected_diagnostics=[])
        self.assertEqual(self.measure()["fp"], 2)

    def test_experimental_findings_are_measured_despite_exit_zero(self):
        self.capability["tier"] = "experimental"
        self.report.update(exit_code=0, status="report-only",
                           finding_counts={"total": 2, "blocking": 0, "report_only": 2})
        for diagnostic in self.report["diagnostics"]:
            diagnostic.update(capability_tier="experimental", blocks_verdict=False)
        self.assertEqual(self.measure()["tp"], 2)

    def test_experimental_blocking_verdict_is_rejected(self):
        self.capability["tier"] = "experimental"
        for diagnostic in self.report["diagnostics"]:
            diagnostic["capability_tier"] = "experimental"
        with self.assertRaisesRegex(ValueError, "tier mismatch"):
            self.measure()

    def test_unknown_and_unsupported_unscored_with_raw_observations(self):
        for role in ("unknown", "unsupported"):
            self.case.update(role=role, expected_diagnostics=None)
            self.assertIsNone(self.measure())
            self.assertEqual(self.report["total"], 2)

    def test_wrong_function_is_both_fp_and_fn(self):
        self.report["diagnostics"][0]["function"] = "other"
        self.assertEqual(self.measure(), {"tp": 1, "fp": 1, "fn": 1, "expected": 2, "observed": 2})

    def test_envelope_inconsistencies_are_not_scored(self):
        for key, value in (("schema", "other"), ("tool_version", "wrong"), ("total", True),
                           ("complete", False), ("baseline", {}), ("suppressions", [{}]),
                           ("exit_code", 2), ("status", "clean")):
            with self.subTest(key=key):
                before = copy.deepcopy(self.report)
                self.report[key] = value
                with self.assertRaises(ValueError):
                    self.measure()
                self.report = before

    def test_missing_envelope_fields_not_defaulted_to_clean(self):
        for key in ("baseline", "suppressions", "schema", "tool_version", "coverage", "evidence"):
            with self.subTest(key=key):
                before = copy.deepcopy(self.report)
                del self.report[key]
                with self.assertRaises(ValueError):
                    self.measure()
                self.report = before

    def test_coverage_and_failure_evidence_rejected(self):
        for key, value in (("analyzed_tus", True), ("analyzed_tus", 0),
                           ("accept_partial_coverage", True), ("incomplete_functions", 1)):
            with self.subTest(key=key):
                before = copy.deepcopy(self.report)
                self.report["coverage"][key] = value
                with self.assertRaises(ValueError):
                    self.measure()
                self.report = before
        self.report["evidence"]["no_rules"] = True
        with self.assertRaises(ValueError):
            self.measure()

    def test_wrong_source_rule_tier_cwe_and_identical_duplicate_rejected(self):
        for key, value in (("file", "/other.cpp"), ("rule_id", "memory-leak"),
                           ("capability_tier", "experimental"), ("line", True),
                           ("fingerprint", "bad"), ("rule_metadata", {"cwe_mapping": "mapped", "cwes": [{"id": 999}]})):
            with self.subTest(key=key):
                before = copy.deepcopy(self.report)
                self.report["diagnostics"][0][key] = value
                with self.assertRaises(ValueError):
                    self.measure()
                self.report = before
        self.report["diagnostics"][1] = copy.deepcopy(self.report["diagnostics"][0])
        with self.assertRaises(ValueError):
            self.measure()

    def test_distinct_pipe_findings_can_share_the_line_fingerprint(self):
        self.report["diagnostics"][1].update(
            fingerprint=self.report["diagnostics"][0]["fingerprint"], line=2,
            message="Resource leak: second pipe endpoint")
        self.assertEqual(self.measure()["tp"], 2)

    def test_aggregate_requires_every_selected_row_once(self):
        row = {"id": "case", "coverage_complete": True, "metrics": self.measure()}
        for rows in ([], [row, row], [dict(row, id="other")]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                quality.summarize([self.case], rows)
        with self.assertRaises(ValueError):
            quality.summarize([], [])

    def test_infrastructure_failure_nulls_rule_metrics(self):
        row = {"id": "case", "coverage_complete": False, "metrics": None}
        result = quality.summarize([self.case], [row])["resource-leak"]
        self.assertFalse(result["measurement_complete"])
        self.assertIsNone(result["metrics"])
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["addressable_recall"])

    def test_aggregate_denominators_are_per_rule(self):
        rows = [{"id": "case", "coverage_complete": True, "metrics": self.measure()}]
        result = quality.summarize([self.case], rows)["resource-leak"]
        self.assertEqual(result["metrics"]["tp"], 2)
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["addressable_recall"], 1.0)

    def test_scan_retains_real_exit_and_uses_explicit_isolation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "input.cpp"
            source.write_text("int f(){return 0;}\n", encoding="utf-8")
            self.case.update(compile_flags=["-std=c++17"], untrusted_sources=["read_size"],
                             sha256=quality.file_sha(source))
            self.report["coverage"]["sources"][0]["file"] = str(source)
            for diag in self.report["diagnostics"]:
                diag["file"] = str(source)
            def process(command, cwd, timeout):
                quality.save_json(cwd / "report.json", self.report)
                self.assertEqual(command[command.index("--disable-rule") + 1], "null-deref")
                self.assertIn("--no-analysis-cache", command)
                self.assertIn("--untrusted-int-sources", command)
                return {"returncode": 1, "reason": "", "stdout": "", "stderr": ""}
            with patch.object(quality.stress, "run_process", side_effect=process):
                result = quality.scan_case(Path("/binary"), self.case, source, directory / "run",
                    {"resource-leak": self.capability, "null-deref": {}}, self.version, 20)
            self.assertTrue(result["coverage_complete"])
            self.assertEqual(result["metrics"]["tp"], 2)
            self.assertEqual(result["process"]["returncode"], 1)

    def test_scan_timeout_missing_report_and_truncation_never_clean(self):
        for process in ({"returncode": -9, "reason": "timeout"},
                        {"returncode": 0, "reason": "", "stdout_truncated": True},
                        {"returncode": 0, "reason": ""}):
            with self.subTest(process=process), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source = directory / "input.cpp"
                source.write_text("int f(){return 0;}\n", encoding="utf-8")
                self.case.update(compile_flags=["-std=c++17"], untrusted_sources=[], sha256=quality.file_sha(source))
                with patch.object(quality.stress, "run_process", return_value=process):
                    result = quality.scan_case(Path("/binary"), self.case, source, directory / "run",
                        {"resource-leak": self.capability}, self.version, 20)
                self.assertFalse(result["coverage_complete"])
                self.assertIsNone(result["metrics"])
                self.assertTrue((directory / "run/execution.json").is_file())

    def test_runner_identity_failure_preserves_evidence_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "binary"
            binary.write_bytes(b"synthetic, never executed")
            output = directory / "run"
            process = {"returncode": 0, "reason": "", "stdout": "CodeSkeptic wrong\n", "stderr": ""}
            with patch.object(quality.stress, "run_process", return_value=process), \
                    patch.object(quality, "source_checkout", return_value="b" * 40):
                result = quality.run_catalog(ROOT, binary, output, "a" * 40)
            self.assertFalse(result["measurement_complete"])
            self.assertIn("version mismatch", result["error"])
            original = (output / "results.json").read_bytes()
            with patch.object(quality, "source_checkout", return_value="b" * 40):
                with self.assertRaises(FileExistsError):
                    quality.run_catalog(ROOT, binary, output, "a" * 40)
            self.assertEqual(original, (output / "results.json").read_bytes())

    def test_runner_frozen_selection_and_capability_schema(self):
        self.runner_selection("supported", *self.frozen_selection_counts("supported"))

    def test_runner_selects_all_five_experimental_cwe_families(self):
        self.runner_selection("experimental", *self.frozen_selection_counts("experimental"))

    def frozen_selection_counts(self, tier):
        catalog = quality.read_json(ROOT, quality.CATALOG)
        capabilities = quality.registry(ROOT)
        selected = [case for case in catalog["cases"] if capabilities[case["rule"]]["tier"] == tier]
        return len({case["rule"] for case in selected}), len(selected)

    def runner_selection(self, tier, rule_count, case_count):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "binary"
            binary.write_bytes(b"synthetic, never executed")
            capabilities = quality.registry(ROOT)
            discovery = {"schema_version": 2, "product": "CodeSkeptic", "version": self.version,
                "rule_capabilities": [{"id": name, "tier": row["tier"],
                    "default_enabled": row["default_enabled"], "quality_gated": row["quality_gated"],
                    "blocks_verdict": row["blocks_verdict"],
                    "potential_cwes": [{"id": cwe, "name": "CWE-" + str(cwe)} for cwe in row["cwes"]]}
                    for name, row in capabilities.items()]}
            processes = [{"returncode": 0, "reason": "", "stdout": "CodeSkeptic " + self.version, "stderr": ""},
                         {"returncode": 0, "reason": "", "stdout": json.dumps(discovery), "stderr": ""}]
            def scan(binary, case, source, output, capabilities, version, timeout):
                expected = case["expected_diagnostics"]
                return {"id": case["id"], "coverage_complete": True, "metrics": None if expected is None else
                        {"tp": len(expected), "fp": 0, "fn": 0, "expected": len(expected), "observed": len(expected)}}
            with patch.object(quality.stress, "run_process", side_effect=processes), \
                    patch.object(quality, "source_checkout", return_value="b" * 40), \
                    patch.object(quality, "scan_case", side_effect=scan) as scanner:
                result = quality.run_catalog(ROOT, binary, directory / "run", "a" * 40, tier=tier)
            self.assertNotIn("error", result)
            self.assertTrue(result["regression_passed"])
            self.assertFalse(result["full_product_qualification"])
            self.assertEqual(result["tier"], tier)
            self.assertEqual(len(result["rules"]), rule_count)
            self.assertEqual(len(result["cases"]), case_count)
            self.assertEqual(len(result["cases"]), scanner.call_count - 1)

    def test_arbitrary_rule_or_tier_subset_not_selectable(self):
        with patch.object(quality.stress, "run_process") as process:
            for tier in ("", "bounds", "all", ["supported"], None):
                with self.subTest(tier=tier), self.assertRaises(ValueError):
                    quality.run_catalog(ROOT, Path("/absent"), Path("/absent"), "a" * 40, tier=tier)
            process.assert_not_called()

    def test_invalid_timeout_and_revision_fail_before_execution(self):
        with patch.object(quality.stress, "run_process") as process:
            for timeout in (0, -1, 61, float("inf"), float("nan")):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    quality.run_catalog(ROOT, Path("/absent"), Path("/absent"), "a" * 40, timeout)
            with self.assertRaises(ValueError):
                quality.run_catalog(ROOT, Path("/absent"), Path("/absent"), "short")
            process.assert_not_called()

    def test_nonfrozen_fixture_is_rejected_before_analyzer_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "input.cpp"
            source.write_text("int f(){return 0;}\n", encoding="utf-8")
            self.case.update(compile_flags=["-std=c++17"], untrusted_sources=[], sha256="0" * 64)
            with patch.object(quality.stress, "run_process") as process:
                with self.assertRaisesRegex(ValueError, "frozen fixture"):
                    quality.scan_case(Path("/binary"), self.case, source, directory / "run",
                                      {"resource-leak": self.capability}, self.version, 20)
                process.assert_not_called()

    def test_full_checkout_revision_not_only_twelve_character_prefix(self):
        actual = "a" * 40
        wrong = "a" * 12 + "b" * 28
        identity = subprocess.CompletedProcess([], 0, str(ROOT) + "\n" + actual + "\n" + "c" * 40 + "\n", "")
        with patch.object(quality.subprocess, "run", return_value=identity):
            with self.assertRaisesRegex(ValueError, "checkout identity"):
                quality.source_checkout(ROOT, wrong)

    def test_dirty_checkout_not_a_qualified_source_tree(self):
        identity = subprocess.CompletedProcess([], 0, str(ROOT) + "\n" + "a" * 40 + "\n" + "c" * 40 + "\n", "")
        dirty = subprocess.CompletedProcess([], 0, " M src/changed.cpp\n", "")
        with patch.object(quality.subprocess, "run", side_effect=[identity, dirty]):
            with self.assertRaisesRegex(ValueError, "dirty checkout"):
                quality.source_checkout(ROOT, "a" * 40)


class VersionedCatalogTest(unittest.TestCase):
    def test_historical_snapshot_identity_is_not_live_qualification(self):
        result = quality.historical_identity(ROOT)
        self.assertEqual(result["source_revision"], "4fd4a21f9b5dc381ea1ec3014daa3082a9d14e24")
        self.assertEqual(result["public_capabilities"], 15)
        self.assertEqual(result["rules"], 12)
        self.assertEqual(result["cases"], 52)
        self.assertEqual(result["protected_inputs"], 124)
        self.assertEqual(result["source_test_inputs"], 96)
        self.assertEqual(result["roles"], {"buggy": 24, "safe": 22, "unknown": 3, "unsupported": 3})
        self.assertFalse(result["current_inputs_verified"])
        self.assertFalse(result["quality_measured"])
        old = quality.historical_snapshot(ROOT)
        caps = old["contract"]["capabilities"]
        cases = old["catalog"]["cases"]
        for tier, families, fixtures in (("supported", 7, 25), ("experimental", 5, 27)):
            selected = [case for case in cases if caps[case["rule"]]["tier"] == tier]
            self.assertEqual(len({case["rule"] for case in selected}), families)
            self.assertEqual(len(selected), fixtures)

    @contextmanager
    def version_root(self):
        parent = CatalogTest()
        parent.setUp()
        with parent.copied_root() as root:
            for name in quality.VERSION_INPUTS:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            catalog = quality.read_json(root, quality.CATALOG)
            catalog.pop("evidence_version", None)
            catalog["schema"] = "codeskeptic-cwe-catalog/v2"
            inventory = quality.read_json(root, quality.INVENTORY)
            inventory["schema"] = "codeskeptic-cwe-regression-inputs/v2"
            self.freeze(root, catalog, inventory)
            yield root, catalog, inventory

    def freeze(self, root, catalog, inventory, previous=None):
        """Synthetic fixture review; not a producer/qualification receipt."""
        inventory["inputs"] = [{"path": path, "sha256": quality.digest_file(root, path)}
                               for path in sorted(quality.required_inputs(root, version=2))]
        (root / quality.INVENTORY).write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
        catalog["inventory_sha256"] = quality.digest_file(root, quality.INVENTORY)
        catalog["evidence_version"] = {
            "schema": "codeskeptic-cwe-evidence-version/v1", "sequence": 1,
            "previous_catalog_sha256": "ed163a76437f70d4179b05973c3d2566cc8d1f13cbdf01c5eaedf576f53451c8",
            "previous_inventory_sha256": "f018bfc0844bec6d12af82f7691fedd1857557852a16a4b970c2dc6e5c1a9e28",
            "previous_version_id": None, "registry_sha256": quality.digest_file(root, quality.REGISTRY),
            "capabilities": quality.registry_descriptor(root),
            "input_paths": [entry["path"] for entry in inventory["inputs"]],
            "case_ids": [case["id"] for case in catalog["cases"]],
            "id": "", "review": {}}
        if previous is not None:
            catalog["evidence_version"].update(sequence=previous["sequence"] + 1,
                previous_catalog_sha256=previous["catalog_sha256"],
                previous_inventory_sha256=previous["inventory_sha256"], previous_version_id=previous["id"])
        catalog["evidence_version"]["review"] = {
            "schema": "codeskeptic-cwe-successor-review/v1", "source_base": "b" * 40,
            "source_head": "a" * 40, "implementer": "synthetic-primary",
            "verifier": "synthetic-independent", "verdict": "PASS", "findings": [],
            "reason": "Synthetic exact-source successor fixture only", "payload_sha256": ""}
        identity = quality.evidence_payload_digest(catalog)
        catalog["evidence_version"]["id"] = identity
        catalog["evidence_version"]["review"]["payload_sha256"] = identity
        (root / quality.CATALOG).write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")

    def test_versioned_exact_current_set_passes(self):
        with self.version_root() as (root, catalog, inventory):
            result = quality.validate(root, catalog, inventory)
            expected = quality.frozen_contract_counts(root, catalog)
            self.assertEqual(result["rules"], expected["rules"])
            self.assertEqual(result["protected_inputs"], len(inventory["inputs"]))
            self.assertFalse(result["quality_measured"])
            self.assertEqual(result["evidence_version_id"], catalog["evidence_version"]["id"])

    def test_wrong_version_or_review_is_rejected(self):
        with self.version_root() as (root, catalog, inventory):
            original = copy.deepcopy(catalog)
            mutations = (("schema", "unknown"), ("id", "0" * 64), ("sequence", True),
                         ("previous_catalog_sha256", "0" * 64), ("previous_inventory_sha256", "0" * 64),
                         ("previous_version_id", "0" * 64), ("registry_sha256", "0" * 64))
            for key, value in mutations:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    catalog = copy.deepcopy(original)
                    catalog["evidence_version"][key] = value
                    quality.validate(root, catalog, inventory)
            for key, value in (("verdict", "PENDING"), ("findings", ["material"]),
                               ("verifier", "synthetic-primary"), ("payload_sha256", "0" * 64),
                               ("source_head", "short"), ("source_head", "c" * 40),
                               ("source_base", "d" * 40), ("reason", "")):
                with self.subTest(review_key=key), self.assertRaises(ValueError):
                    catalog = copy.deepcopy(original)
                    catalog["evidence_version"]["review"][key] = value
                    quality.validate(root, catalog, inventory)

    def test_same_count_missing_duplicate_ghost_and_flags_rejected(self):
        with self.version_root() as (root, catalog, inventory):
            original = copy.deepcopy(catalog)
            for mode in ("replacement", "missing", "ghost", "tier", "cwe", "default", "quality", "blocking"):
                catalog = copy.deepcopy(original)
                caps = catalog["evidence_version"]["capabilities"]
                if mode == "replacement":
                    caps["fake-rule"] = caps.pop("memory-leak")
                elif mode == "missing":
                    caps.pop("bounds")
                elif mode == "ghost":
                    caps["fake-rule"] = copy.deepcopy(caps["bounds"])
                else:
                    field = {"tier": "tier", "cwe": "cwes", "default": "default_enabled",
                             "quality": "quality_gated", "blocking": "blocks_verdict"}[mode]
                    caps["bounds"][field] = ({"tier": "supported", "cwe": [134]}[mode]
                                              if mode in ("tier", "cwe") else not caps["bounds"][field])
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    quality.validate(root, catalog, inventory)

    def test_registry_duplicate_and_invalid_flags_are_not_count_checks(self):
        with self.version_root() as (root, catalog, inventory):
            path = root / quality.REGISTRY
            raw = path.read_text(encoding="utf-8")
            line = next(line for line in raw.splitlines() if line.startswith('CODESKEPTIC_RULE_CAPABILITY("bounds"'))
            for changed in (raw + line + "\n", raw.replace('Supported, true, true, true', 'Supported, false, true, true', 1),
                            raw.replace('Experimental, true, false, false', 'Experimental, true, false, true', 1)):
                path.write_text(changed, encoding="utf-8")
                with self.assertRaises(ValueError):
                    quality.registry_descriptor(root)

    def test_coordinated_old_fixture_relabel_rehash_still_rejected(self):
        for mode in ("label", "source", "expectation", "order", "remove"):
            with self.subTest(mode=mode), self.version_root() as (root, catalog, inventory):
                if mode == "label":
                    catalog["cases"][0].update(role="unsupported", expected_diagnostics=None)
                elif mode == "source":
                    case = catalog["cases"][0]
                    (root / case["path"]).write_text("int f(){return 0;}\n", encoding="utf-8")
                    case["sha256"] = quality.digest_file(root, case["path"])
                elif mode == "expectation":
                    catalog["cases"][0]["expected_diagnostics"] *= 2
                elif mode == "order":
                    catalog["cases"][0], catalog["cases"][1] = catalog["cases"][1], catalog["cases"][0]
                else:
                    catalog["cases"].pop()
                self.freeze(root, catalog, inventory)
                with self.assertRaisesRegex(ValueError, "historical fixture"):
                    quality.validate(root, catalog, inventory)

    def test_coordinated_floor_rehash_cannot_weaken_original_floor(self):
        with self.version_root() as (root, catalog, inventory):
            (root / "scripts/juliet_expected.txt").write_text("CWE476 0 0\n", encoding="utf-8")
            self.freeze(root, catalog, inventory)
            with self.assertRaisesRegex(ValueError, "historical quality floor"):
                quality.validate(root, catalog, inventory)

    def test_original_test_path_cannot_be_removed_with_new_inventory(self):
        with self.version_root() as (root, catalog, inventory):
            (root / "tests/FdResourceRuleTest.cpp").unlink()
            self.freeze(root, catalog, inventory)
            with self.assertRaisesRegex(ValueError, "historical protected input"):
                quality.validate(root, catalog, inventory)

    def test_new_test_requires_exact_successor_then_is_admitted(self):
        with self.version_root() as (root, catalog, inventory):
            previous = self.previous(root, catalog)
            (root / "tests/AdditionalRegression.cpp").write_text("// synthetic addition\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                quality.validate(root, catalog, inventory)
            self.freeze(root, catalog, inventory, previous)
            result = quality.validate(root, catalog, inventory)
            self.assertEqual(result["protected_inputs"], len(inventory["inputs"]))
            self.assertIn("tests/AdditionalRegression.cpp", catalog["evidence_version"]["input_paths"])

    def previous(self, root, catalog):
        return {"sequence": catalog["evidence_version"]["sequence"], "id": catalog["evidence_version"]["id"],
                "catalog_sha256": quality.digest_file(root, quality.CATALOG),
                "inventory_sha256": quality.digest_file(root, quality.INVENTORY)}

    def test_additive_family_and_pair_require_new_exact_version(self):
        with self.version_root() as (root, catalog, inventory):
            previous = self.previous(root, catalog)
            path = root / quality.REGISTRY
            with path.open("a", encoding="utf-8") as stream:
                stream.write('CODESKEPTIC_RULE_CAPABILITY("format-string", Experimental, true, false, false, '
                             '"synthetic fixture only", "Format argument origin", (134))\n')
                stream.write('CODESKEPTIC_CWE(134, "Uncontrolled format string")\n')
            origin = "tests/SyntheticFutureFormatTest.cpp"
            (root / origin).write_text("// synthetic parser test; no detector implementation\n", encoding="utf-8")
            catalog["rules"]["format-string"] = {"tier_at_selection": "experimental", "cwes": [134],
                "subset": "Synthetic metadata migration fixture", "limitations": ["No product execution"]}
            for role in ("buggy", "safe"):
                name = "synthetic-format-" + role
                path = "tests/cwe_corpus/" + name + ".cpp"
                (root / path).write_text("int f(){return 0;}\n", encoding="utf-8")
                catalog["cases"].append({"id": name, "rule": "format-string", "role": role, "path": path,
                    "sha256": quality.digest_file(root, path), "expected_diagnostics": [["format-string", "f"]] if role == "buggy" else [],
                    "rationale": "Synthetic metadata positive; never analyzed/scored", "origin": origin,
                    "compile_flags": ["-std=c++17"], "untrusted_sources": []})
            with self.assertRaises(ValueError):
                quality.validate(root, catalog, inventory)
            self.freeze(root, catalog, inventory, previous)
            result = quality.validate(root, catalog, inventory)
            self.assertEqual(result["rules"], 13)
            self.assertEqual(result["cases"], 54)
            self.assertEqual(len(quality.registry(root)), 16)
            self.assertFalse(result["quality_measured"])
            self.assertNotEqual(result["evidence_version_id"], previous["id"])

    def test_source_derived_promotion_preserves_old_case_contracts(self):
        with self.version_root() as (root, catalog, inventory):
            previous = self.previous(root, catalog)
            path = root / quality.REGISTRY
            raw = path.read_text(encoding="utf-8")
            raw = raw.replace('("bounds", Experimental, true, false, false', '("bounds", Supported, true, true, true')
            path.write_text(raw, encoding="utf-8")
            catalog["rules"]["bounds"]["tier_at_selection"] = "supported"
            with self.assertRaises(ValueError):
                quality.validate(root, catalog, inventory)
            self.freeze(root, catalog, inventory, previous)
            result = quality.validate(root, catalog, inventory)
            self.assertEqual(result["cases"], 52)
            self.assertEqual(quality.registry(root)["bounds"]["tier"], "supported")
            self.assertEqual(quality.historical_snapshot(root)["contract"]["capabilities"]["bounds"]["tier"], "experimental")

    def test_coordinated_fake_rule_identity_is_still_rejected(self):
        with self.version_root() as (root, catalog, inventory):
            path = root / quality.REGISTRY
            path.write_text(path.read_text(encoding="utf-8").replace('"memory-leak"', '"fake-memory"'), encoding="utf-8")
            self.freeze(root, catalog, inventory)
            with self.assertRaisesRegex(ValueError, "unapproved capability identity"):
                quality.validate(root, catalog, inventory)

    def test_numeric_lookalikes_do_not_equal_bool_or_integer_descriptor(self):
        with self.version_root() as (root, catalog, inventory):
            original = copy.deepcopy(catalog)
            for key, value in (("default_enabled", 1), ("quality_gated", 0), ("cwes", [824.0])):
                catalog = copy.deepcopy(original)
                catalog["evidence_version"]["capabilities"]["uninit-ptr"][key] = value
                identity = quality.evidence_payload_digest(catalog)
                catalog["evidence_version"]["id"] = identity
                catalog["evidence_version"]["review"]["payload_sha256"] = identity
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "registry mismatch"):
                    quality.validate(root, catalog, inventory)

    def test_native_discovery_matches_explicit_flags_and_identities(self):
        caps = quality.registry(ROOT)
        version = "0.4.9-dev+g" + "a" * 12
        actual = {"schema_version": 2, "product": "CodeSkeptic", "version": version,
            "rule_capabilities": [{"id": name, "tier": row["tier"],
                "default_enabled": row["default_enabled"], "quality_gated": row["quality_gated"],
                "blocks_verdict": row["blocks_verdict"], "potential_cwes": [{"id": cwe} for cwe in row["cwes"]]}
                for name, row in caps.items()]}
        quality.capability_parity(actual, version, caps)
        for mode in ("schema", "version", "duplicate", "missing", "ghost", "default", "quality", "blocking", "cwe-float"):
            changed = copy.deepcopy(actual)
            rows = changed["rule_capabilities"]
            if mode == "schema":
                changed["schema_version"] = 2.0
            elif mode == "version":
                changed["version"] += "stale"
            elif mode == "duplicate":
                rows[-1] = copy.deepcopy(rows[0])
            elif mode == "missing":
                rows.pop()
            elif mode == "ghost":
                rows[0]["id"] = "ghost"
            elif mode == "cwe-float":
                next(row for row in rows if row["potential_cwes"])["potential_cwes"][0]["id"] = 824.0
            else:
                key = {"default": "default_enabled", "quality": "quality_gated", "blocking": "blocks_verdict"}[mode]
                rows[0][key] = not rows[0][key]
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                quality.capability_parity(changed, version, caps)

    def test_only_three_exact_snapshot_files_are_admitted(self):
        with self.version_root() as (root, catalog, inventory):
            (root / "tests/cwe_corpus/snapshots/hidden.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unlisted/missing corpus"):
                quality.validate(root, catalog, inventory)

    def test_snapshot_tampering_and_symlink_are_rejected(self):
        for name in quality.HISTORICAL_FILES:
            with self.subTest(name=name), self.version_root() as (root, catalog, inventory):
                path = root / name
                raw = path.read_bytes()
                path.write_bytes(raw + b"\n")
                with self.assertRaisesRegex(ValueError, "historical snapshot"):
                    quality.validate(root, catalog, inventory)
                path.unlink()
                path.symlink_to(ROOT / name)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    quality.validate(root, catalog, inventory)

    def test_mixed_inventory_schema_is_rejected(self):
        with self.version_root() as (root, catalog, inventory):
            inventory["schema"] = "codeskeptic-cwe-regression-inputs/v1"
            with self.assertRaises(ValueError):
                quality.validate(root, catalog, inventory)


if __name__ == "__main__":
    unittest.main()
