import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_upstream_validation.py"
LEDGER = ROOT / "scripts" / "upstream_validation_ledger.json"

SPEC = importlib.util.spec_from_file_location("check_upstream_validation", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UpstreamValidationTest(unittest.TestCase):
    def setUp(self):
        self.ledger = json.loads(LEDGER.read_text(encoding="utf-8"))

    def test_repository_ledger_has_verified_red_baseline(self):
        summary = MODULE.validate_ledger(self.ledger)
        self.assertEqual(summary["records"], 3)
        self.assertEqual(summary["accepted_fixes"], 3)
        self.assertEqual(summary["projects"], 2)
        self.assertFalse(summary["complete"])

    def test_cli_passes_schema_but_completion_gate_stays_red(self):
        valid = subprocess.run(
            [sys.executable, str(SCRIPT)], text=True, capture_output=True
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn("accepted=3/10", valid.stdout)
        complete = subprocess.run(
            [sys.executable, str(SCRIPT), "--require-complete"],
            text=True,
            capture_output=True,
        )
        self.assertEqual(complete.returncode, 2)
        self.assertIn("3/10", complete.stderr)

    def test_all_four_gate_a_proofs_are_required(self):
        changed = copy.deepcopy(self.ledger)
        changed["records"][0]["gate_a"].pop()
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_ledger(changed)

    def test_accepted_record_requires_proven_current_ancestry(self):
        changed = copy.deepcopy(self.ledger)
        changed["records"][0]["fix"]["ancestry"] = "unknown"
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_ledger(changed)

    def test_dates_and_general_report_references_are_required(self):
        changed = copy.deepcopy(self.ledger)
        changed["records"][0]["observed"]["checked_at"] = "not-a-date"
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_ledger(changed)
        changed = copy.deepcopy(self.ledger)
        changed["records"][0]["gate_c"].pop("report_ref")
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_ledger(changed)

    def test_duplicate_ids_fail_closed(self):
        changed = copy.deepcopy(self.ledger)
        changed["records"].append(copy.deepcopy(changed["records"][0]))
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_ledger(changed)

    def test_nonaccepted_record_requires_durable_classification(self):
        changed = copy.deepcopy(self.ledger)
        record = copy.deepcopy(changed["records"][0])
        record["id"] = "example-rejected"
        record["outcome"] = "rejected"
        record.pop("fix")
        record.pop("gate_a")
        record.pop("gate_b")
        record.pop("gate_c")
        changed["records"].append(record)
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_ledger(changed)
        record["classification"] = "not suitable after current-head review"
        summary = MODULE.validate_ledger(changed)
        self.assertEqual(summary["records"], 4)
        self.assertEqual(summary["accepted_fixes"], 3)

    def test_append_only_allows_only_a_strict_suffix(self):
        current = copy.deepcopy(self.ledger)
        extra = copy.deepcopy(current["records"][0])
        extra["id"] = "example-hold"
        extra["outcome"] = "hold"
        extra["classification"] = "awaiting maintainer decision"
        extra.pop("fix")
        extra.pop("gate_a")
        extra.pop("gate_b")
        extra.pop("gate_c")
        current["records"].append(extra)
        MODULE.validate_append_only(self.ledger, current)

        mutated = copy.deepcopy(current)
        mutated["records"][0]["project"] = "changed"
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_append_only(self.ledger, mutated)

        shortened = copy.deepcopy(self.ledger)
        shortened["records"].pop()
        with self.assertRaises(MODULE.LedgerError):
            MODULE.validate_append_only(self.ledger, shortened)

    def test_cli_previous_gate_detects_mutation(self):
        current = copy.deepcopy(self.ledger)
        current["records"][0]["project"] = "changed"
        with tempfile.TemporaryDirectory() as directory:
            current_path = Path(directory) / "current.json"
            previous_path = Path(directory) / "previous.json"
            current_path.write_text(json.dumps(current), encoding="utf-8")
            previous_path.write_text(json.dumps(self.ledger), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--ledger",
                    str(current_path),
                    "--previous",
                    str(previous_path),
                ],
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("changed or reordered", result.stderr)

    def test_cli_optional_previous_allows_initial_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "not-created.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--previous-if-exists",
                    str(missing),
                ],
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("UPSTREAM_LEDGER_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
