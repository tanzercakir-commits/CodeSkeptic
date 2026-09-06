#!/usr/bin/env python3
"""Runner evidence contract. Actual frontend qualification is StressMatrixCorpus."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stress_matrix.py"
spec = importlib.util.spec_from_file_location("stress_matrix", SCRIPT)
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def report_for(source):
    return {"tool": "CodeSkeptic", "status": "clean", "complete": True, "exit_code": 0,
            "coverage": {"schema": "codeskeptic-source-coverage/v1", "complete": True,
                         "attempted_tus": 1, "analyzed_tus": 1, "skipped_tus": 0, "broken_tus": 0,
                         "failed_tus": 0, "recovery_tus": 0, "attempted_commands": 1,
                         "analyzed_commands": 1, "skipped_commands": 0, "failed_commands": 0,
                         "incomplete_functions": 0, "accept_partial_coverage": False,
                         "analyze_broken_tus": False,
                         "sources": [{"file": str(source), "status": "analyzed", "reason": "analyzed",
                                      "commands": 1, "analyzed_commands": 1, "skipped_commands": 0,
                                      "failed_commands": 0, "recovery_commands": 0,
                                      "prepass": {"status": "not_requested", "reason": "", "recovery_commands": 0}}]},
            "evidence": dict.fromkeys(matrix.EVIDENCE_FLAGS, False),
            "total": 0, "finding_counts": {"total": 0, "blocking": 0, "report_only": 0}, "diagnostics": []}


class StressMatrixTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-stress-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "input.cpp"
        self.source.write_text("int safe() { return 7; }\n")
        self.case = {"id": "safe", "source": str(self.source), "flags": ["-std=c++17"],
                     "expected_exit": 0, "expected_diagnostics": []}
        self.report = report_for(self.source)

    def validate(self, report, code=0):
        return matrix.validate_report(report, self.source, code)

    def test_complete_zero_and_one_exit_profiles(self):
        self.assertTrue(self.validate(self.report)["complete"])
        report = copy.deepcopy(self.report)
        report.update(status="findings", exit_code=1, total=1,
                      diagnostics=[{"rule_id": "null-deref", "function": "seeded",
                                    "file": str(self.source), "blocks_verdict": True}],
                      finding_counts={"total": 1, "blocking": 1, "report_only": 0})
        self.assertTrue(self.validate(report, 1)["complete"])

    def test_counters_are_typed_and_reconciled(self):
        for location in ("coverage", "source"):
            original = self.report["coverage"] if location == "coverage" else self.report["coverage"]["sources"][0]
            for key, value in original.items():
                if type(value) is not int:
                    continue
                for wrong in (True, -1, value + 2):
                    with self.subTest(location=location, key=key, wrong=wrong):
                        report = copy.deepcopy(self.report)
                        row = report["coverage"] if location == "coverage" else report["coverage"]["sources"][0]
                        row[key] = wrong
                        with self.assertRaises(ValueError):
                            self.validate(report)

    def test_wrong_missing_duplicate_source_identity(self):
        for sources in ([], [self.report["coverage"]["sources"][0]] * 2,
                        [dict(self.report["coverage"]["sources"][0], file="other.cpp")]):
            with self.subTest(sources=sources):
                report = copy.deepcopy(self.report)
                report["coverage"]["sources"] = sources
                with self.assertRaises(ValueError):
                    self.validate(report)

    def test_partial_recovery_prepass_and_unknown_schema_rejected(self):
        for field, value in (("complete", False), ("accept_partial_coverage", True),
                             ("analyze_broken_tus", True), ("schema", "old")):
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report["coverage"][field] = value
                with self.assertRaises(ValueError):
                    self.validate(report)
        for value in (None, {"status": "analyzed", "reason": "", "recovery_commands": 0},
                      {"status": "not_requested", "reason": "", "recovery_commands": False}):
            report = copy.deepcopy(self.report)
            report["coverage"]["sources"][0]["prepass"] = value
            with self.assertRaises(ValueError):
                self.validate(report)

    def test_missing_fields_and_evidence_failures_rejected(self):
        for field in self.report:
            report = copy.deepcopy(self.report)
            del report[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(report)
        for field in matrix.EVIDENCE_FLAGS:
            report = copy.deepcopy(self.report)
            report["evidence"][field] = True
            with self.subTest(flag=field), self.assertRaises(ValueError):
                self.validate(report)

    def test_exit_and_diagnostic_count_mismatches_rejected(self):
        for field, value in (("complete", 1), ("exit_code", False), ("exit_code", 1),
                             ("total", True), ("total", 2), ("status", "findings"),
                             ("finding_counts", {"total": 0, "blocking": 1, "report_only": 0})):
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(report)

    def fake_writer(self, raw):
        def run(command, cwd, timeout):
            if raw is not None:
                Path(command[command.index("--json") + 1]).write_bytes(raw)
            return {"returncode": 0, "reason": "", "stdout": "", "stderr": ""}
        return run

    def test_missing_truncated_non_utf8_and_duplicate_json_fail_closed(self):
        valid = json.dumps(self.report).encode()
        for raw in (None, b"{", b"\xff", b"[]", b'{"tool":"X","tool":"CodeSkeptic"}',
                    valid.replace(b'"total": 0', b'"total": NaN', 1),
                    valid.replace(b'"total": 0', b'"total": 1e400', 1), b" " * (matrix.REPORT_LIMIT + 1)):
            with self.subTest(raw=None if raw is None else raw[:40]), patch.object(
                    matrix, "run_process", side_effect=self.fake_writer(raw)):
                row = matrix.run_case(sys.executable, self.case)
                self.assertFalse(row["qualification_passed"])
                self.assertFalse(row["coverage_complete"])
                self.assertEqual(row["reason"], "invalid_or_unexpected_evidence")
                json.dumps(row, allow_nan=False)  # Even invalid evidence must remain writable.

    def test_fresh_report_is_required_for_every_invocation(self):
        with patch.object(matrix, "run_process", side_effect=self.fake_writer(json.dumps(self.report).encode())):
            first = matrix.run_case(sys.executable, self.case)
        with patch.object(matrix, "run_process", side_effect=self.fake_writer(None)):
            second = matrix.run_case(sys.executable, self.case)
        self.assertTrue(first["qualification_passed"])
        self.assertFalse(second["qualification_passed"])
        self.assertNotEqual(first["command"], second["command"])

    def test_expected_failure_preserves_incomplete_reason(self):
        report = copy.deepcopy(self.report)
        report.update(status="failed", complete=False, exit_code=2)
        report["coverage"].update(complete=False, analyzed_tus=0, skipped_tus=1, broken_tus=1,
                                  analyzed_commands=0, skipped_commands=1)
        report["coverage"]["sources"][0].update(status="skipped", reason="broken_translation_unit",
                                                analyzed_commands=0, skipped_commands=1)
        case = dict(self.case, expected_exit=2, expected_reason="broken_translation_unit",
                    expected_source_status="skipped", stderr_contains="depth limit")
        def run(command, cwd, timeout):
            result = self.fake_writer(json.dumps(report).encode())(command, cwd, timeout)
            return dict(result, returncode=2, stderr="depth limit")
        with patch.object(matrix, "run_process", side_effect=run):
            row = matrix.run_case(sys.executable, case)
        self.assertTrue(row["qualification_passed"])
        self.assertFalse(row["coverage_complete"])
        self.assertEqual(row["reason"], "broken_translation_unit")
        with patch.object(matrix, "run_process", side_effect=run):
            self.assertFalse(matrix.run_case(sys.executable, self.case)["qualification_passed"])
        report["coverage"].update(skipped_tus=0, broken_tus=0, failed_tus=1,
                                  skipped_commands=0, failed_commands=1)
        report["coverage"]["sources"][0].update(status="failed", skipped_commands=0, failed_commands=1)
        with patch.object(matrix, "run_process", side_effect=run):
            self.assertFalse(matrix.run_case(sys.executable, case)["qualification_passed"],
                             "broken/skipped compiler failure cannot turn into another failure class")

    def test_real_process_timeout_then_following_process_finishes(self):
        result = matrix.run_process([sys.executable, "-c", "import time; time.sleep(30)"], self.root, .15)
        self.assertEqual(result["reason"], "timeout")
        self.assertNotEqual(result["returncode"], 0)
        following = matrix.run_process([sys.executable, "-c", "print('next')"], self.root, 5)
        self.assertEqual(following["returncode"], 0)
        self.assertEqual(following["stdout"].strip(), "next")

    @unittest.skipUnless(os.name == "posix", "executable Python fixture uses a POSIX shebang")
    def test_real_matrix_timeout_is_incomplete_and_next_case_runs(self):
        binary = self.root / "fixture-analyzer"
        binary.write_text("#!" + sys.executable + "\n" +
                          "import json,pathlib,sys,time\n" +
                          "args=sys.argv[1:]\n" +
                          "database=pathlib.Path(args[args.index('--build-path')+1])/'compile_commands.json'\n" +
                          "flags=json.loads(database.read_text())[0]['arguments']\n" +
                          "if '-DWAIT=1' in flags: time.sleep(30)\n" +
                          "output=pathlib.Path(args[args.index('--json')+1])\n" +
                          "output.write_text(" + repr(json.dumps(self.report)) + ")\n")
        binary.chmod(0o700)
        slow = dict(self.case, id="timeout", flags=["-DWAIT=1"])
        result = matrix.run_matrix(binary, [slow, self.case], timeout=2)
        self.assertFalse(result["qualification_passed"])
        self.assertFalse(result["coverage_complete"])
        first, second = result["cases"]
        self.assertEqual(first["reason"], "timeout")
        self.assertFalse(first["coverage_complete"])
        self.assertNotIn("analyzer_report", first)
        self.assertTrue(second["qualification_passed"])

    def test_real_process_launch_failure_nonzero_and_log_bound(self):
        missing = matrix.run_process([str(self.root / "missing-binary")], self.root, 1)
        self.assertEqual(missing["reason"], "launch_error")
        failed = matrix.run_process([sys.executable, "-c", "raise SystemExit(42)"], self.root, 5)
        self.assertEqual(failed["returncode"], 42)
        noisy = matrix.run_process([sys.executable, "-c", "print('x' * 100000)"], self.root, 5)
        self.assertTrue(noisy["stdout_truncated"])
        self.assertEqual(len(noisy["stdout"]), matrix.LOG_LIMIT)

    @unittest.skipUnless(os.name == "posix", "POSIX signal and owned-process-group behavior")
    def test_real_signal_and_timeout_child_group_cleanup(self):
        crash = matrix.run_process([sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"], self.root, 5)
        self.assertEqual(crash["reason"], "signal")
        self.assertEqual(crash["returncode"], -signal.SIGTERM)
        # Child holds a lock while its parent sleeps. Timeout must free the lock,
        # proving the child was stopped as well, without host-wide process kills.
        lock = self.root / "child.lock"
        child = "import fcntl,sys,time; f=open(sys.argv[1],'w'); fcntl.flock(f,fcntl.LOCK_EX); print('locked',flush=True); time.sleep(30)"
        parent = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdout=subprocess.PIPE); print(p.stdout.readline().decode(),flush=True); time.sleep(30)"
        result = matrix.run_process([sys.executable, "-c", parent, child, str(lock)], self.root, 3)
        self.assertEqual(result["reason"], "timeout")
        self.assertIn("locked", result["stdout"])
        import fcntl
        with lock.open() as stream:
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        self.fail("owned child still holds lock after group termination")
                    time.sleep(.01)

    def test_invalid_timeout_and_empty_matrix_cannot_pass(self):
        for timeout in (0, -1, float("nan"), float("inf"), 61):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                matrix.run_process([sys.executable], self.root, timeout)
        self.assertFalse(matrix.run_matrix(sys.executable, [])["qualification_passed"])


if __name__ == "__main__":
    unittest.main()
