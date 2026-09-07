#!/usr/bin/env python3
"""Catalog and measurement regressions; synthetic reports are never product evidence."""
import copy
from contextlib import contextmanager
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
            for name in paths:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            yield root

    def test_complete_frozen_input_catalog_is_not_a_quality_result(self):
        result = self.validate()
        self.assertEqual(result["rules"], 12)
        self.assertEqual(result["cases"], 52)
        self.assertEqual(result["protected_inputs"], 124)
        self.assertEqual(result["roles"], {"buggy": 24, "safe": 22, "unknown": 3, "unsupported": 3})
        self.assertIs(result["quality_measured"], False)

    def test_all_existing_source_tests_are_required(self):
        tests = [row for row in self.inventory["inputs"] if row["path"].startswith("tests/")]
        self.assertEqual(len(tests), 96)
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
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "binary"
            binary.write_bytes(b"synthetic, never executed")
            capabilities = quality.registry(ROOT)
            discovery = {"schema_version": 2, "product": "CodeSkeptic", "version": self.version,
                "rule_capabilities": [{"id": name, "tier": row["tier"],
                    "default_enabled": name != "assumption", "quality_gated": row["tier"] == "supported",
                    "blocks_verdict": row["tier"] == "supported",
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
                result = quality.run_catalog(ROOT, binary, directory / "run", "a" * 40)
            self.assertNotIn("error", result)
            self.assertTrue(result["regression_passed"])
            self.assertFalse(result["full_product_qualification"])
            self.assertEqual(len(result["rules"]), 7)
            self.assertEqual(len(result["cases"]), scanner.call_count - 1)

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


if __name__ == "__main__":
    unittest.main()
