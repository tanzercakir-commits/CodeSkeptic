#!/usr/bin/env python3
"""Focused tests of checked-in composite steps; synthetic analyzer, no network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def step_script(name):
    text = (ROOT / "action.yml").read_text()
    marker = "    - name: " + name + "\n"
    assert text.count(marker) == 1
    block = text.split(marker, 1)[1].split("    - name:", 1)[0]
    script = block.split("      run: |\n", 1)[1]
    lines = script.splitlines()
    assert all(not line.strip() or line.startswith("        ") for line in lines)
    return "\n".join(line[8:] for line in lines) + "\n"


def clean_sarif(source):
    coverage = {"schema": "codeskeptic-source-coverage/v1", "complete": True,
                "accept_partial_coverage": False, "analyze_broken_tus": False,
                "attempted_tus": 1, "analyzed_tus": 1, "broken_tus": 0,
                "skipped_tus": 0, "failed_tus": 0, "recovery_tus": 0,
                "incomplete_functions": 0, "skipped_commands": 0, "failed_commands": 0,
                "sources": [{"file": str(source), "status": "analyzed", "commands": 1,
                             "analyzed_commands": 1, "skipped_commands": 0,
                             "failed_commands": 0, "recovery_commands": 0,
                             "prepass": {"recovery_commands": 0}}]}
    report = {"schema": "codeskeptic-report/v1", "tool": "CodeSkeptic", "tool_version": "0.4.9-test",
              "complete": True, "exit_code": 0, "status": "clean", "total": 0,
              "finding_counts": {"total": 0, "blocking": 0, "report_only": 0}}
    report["evidence"] = dict.fromkeys(("no_inputs", "no_rules", "tool_failed", "summary_load_failed",
                                       "summary_stale", "summary_save_failed", "baseline_load_failed",
                                       "baseline_write_failed", "baseline_recorded", "report_write_failed"), False)
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeSkeptic", "version": "0.4.9-test"}},
            "properties": {"codeskeptic/report": report}, "results": [],
            "invocations": [{"executionSuccessful": True, "properties": {
                "codeskeptic/status": "clean", "codeskeptic/exitCode": 0,
                "codeskeptic/blockingFindings": 0, "codeskeptic/reportOnlyFindings": 0,
                "codeskeptic/coverage": coverage}}]}]}


class ActionExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="action fixtures ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.source = self.root / "input.cpp"
        self.source.write_text("int answer() { return 42; }\n")
        self.sarif = self.root / "result.sarif"
        self.output = self.root / "github-output"
        self.fixture = self.root / "fixture.json"
        self.fixture.write_text(json.dumps(clean_sarif(self.source)))
        executable = self.bin / "codeskeptic"
        executable.write_text("#!" + sys.executable + "\n" + '''
import json, os, time
from pathlib import Path
import sys
settings = json.loads(Path(__file__).with_name('stub-settings.json').read_text())
mode = settings.get('FIXTURE_MODE', 'ok')
if '--version' in sys.argv:
    print('CodeSkeptic 0.4.9-test')
    raise SystemExit(0)
if mode == 'sleep':
    time.sleep(5)
if mode != 'missing':
    destination = Path(sys.argv[sys.argv.index('--sarif') + 1])
    if mode == 'malformed':
        destination.write_text('not json')
    else:
        destination.write_bytes(Path(settings['FIXTURE_JSON']).read_bytes())
if settings.get('CHECK_ENV'):
    Path(settings['CHECK_ENV']).write_text(str('GH_TOKEN' in os.environ or 'UNRELATED_SECRET' in os.environ))
raise SystemExit(int(settings.get('FIXTURE_EXIT', '0')))
''')
        executable.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        GITHUB_ACTION_PATH=str(ROOT), RUNNER_TEMP=str(self.root),
                        GITHUB_WORKSPACE=str(self.root), GITHUB_OUTPUT=str(self.output),
                        INPUT_PATH=str(self.source), INPUT_BUILD_PATH="", INPUT_SARIF_PATH=str(self.sarif),
                        INPUT_GATE="report-only", INPUT_EXTRA_ARGS="", FIXTURE_JSON=str(self.fixture),
                        PYTHONDONTWRITEBYTECODE="1")

    def run_action(self, **env):
        (self.bin / "stub-settings.json").write_text(json.dumps(dict(self.env, **env)))
        return subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step_script("Analyze")],
                              env=dict(self.env, **env), cwd=self.root, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)

    def mutate_report(self, function):
        data = json.loads(self.fixture.read_text())
        function(data)
        self.fixture.write_text(json.dumps(data))

    def assert_failed(self, result):
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_valid_clean_report_passes(self):
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("exit-code=0", self.output.read_text())
        self.assertEqual(json.loads(self.sarif.read_text()), json.loads(self.fixture.read_text()))

    def test_missing_report_cannot_pass(self):
        self.assert_failed(self.run_action(FIXTURE_MODE="missing"))

    def test_malformed_report_cannot_pass(self):
        self.assert_failed(self.run_action(FIXTURE_MODE="malformed"))

    def test_existing_report_is_preserved_and_rejected(self):
        self.sarif.write_text("old report must stay\n")
        self.assert_failed(self.run_action(FIXTURE_MODE="missing"))
        self.assertEqual(self.sarif.read_text(), "old report must stay\n")

    def test_wrong_schema_cannot_pass(self):
        self.mutate_report(lambda data: data["runs"][0]["properties"]["codeskeptic/report"].update(schema="wrong"))
        self.assert_failed(self.run_action())

    def test_process_and_report_must_agree(self):
        self.assert_failed(self.run_action(FIXTURE_EXIT="1", INPUT_GATE="report-only"))

    def test_incomplete_report_cannot_pass_as_clean(self):
        self.mutate_report(lambda data: data["runs"][0]["properties"]["codeskeptic/report"].update(complete=False))
        self.assert_failed(self.run_action())

    def test_invocation_must_agree(self):
        self.mutate_report(lambda data: data["runs"][0]["invocations"][0].update(executionSuccessful=False))
        self.assert_failed(self.run_action())

    def test_report_counts_must_match_results(self):
        self.mutate_report(lambda data: data["runs"][0]["properties"]["codeskeptic/report"]["finding_counts"].update(total=1))
        self.assert_failed(self.run_action())

    def test_upload_is_explicit_opt_in(self):
        text = (ROOT / "action.yml").read_text()
        block = text.split("  upload-sarif:\n", 1)[1].split("\n  gate:", 1)[0]
        self.assertRegex(block, r'default: "false"')

    def scenario(self, status, blocking=0, report_only=0):
        data = clean_sarif(self.source)
        run = data["runs"][0]
        report = run["properties"]["codeskeptic/report"]
        invocation = run["invocations"][0]
        properties = invocation["properties"]
        coverage = properties["codeskeptic/coverage"]
        code = 2 if status == "incomplete" else int(blocking > 0)
        report.update(status=status, exit_code=code, complete=code != 2,
                      total=blocking + report_only,
                      finding_counts={"total": blocking + report_only, "blocking": blocking, "report_only": report_only})
        invocation["executionSuccessful"] = code != 2
        properties.update({"codeskeptic/status": status, "codeskeptic/exitCode": code,
                           "codeskeptic/blockingFindings": blocking, "codeskeptic/reportOnlyFindings": report_only})
        for index in range(blocking + report_only):
            run["results"].append({"ruleId": "test-rule", "message": {"text": "synthetic finding"},
                                   "properties": {"codeskeptic/blocksVerdict": index < blocking}})
        if status in ("incomplete", "partial-accepted"):
            coverage.update(complete=False, attempted_tus=2, skipped_tus=1, broken_tus=1,
                            accept_partial_coverage=status == "partial-accepted")
            coverage["sources"].append({"file": str(self.root / "skipped.cpp"), "status": "skipped"})
        if status == "recovery-accepted":
            coverage.update(complete=False, recovery_tus=1, analyze_broken_tus=True)
        self.fixture.write_text(json.dumps(data))
        return code

    def test_valid_findings_keep_raw_exit_and_sarif_with_both_gates(self):
        for gate, expected in (("report-only", 0), ("error", 1)):
            with self.subTest(gate=gate):
                self.scenario("findings", blocking=1)
                result = self.run_action(INPUT_GATE=gate, FIXTURE_EXIT="1")
                self.assertEqual(result.returncode, expected, result.stdout)
                self.assertIn("exit-code=1\nsarif-valid=true", self.output.read_text())
                self.assertEqual(json.loads(self.sarif.read_text()), json.loads(self.fixture.read_text()))
                self.sarif.unlink()
                self.output.unlink()

    def test_experimental_only_remains_exit_zero(self):
        self.scenario("report-only", report_only=1)
        result = self.run_action(INPUT_GATE="error")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.sarif.is_file())

    def test_valid_incomplete_report_is_preserved_but_fails(self):
        self.scenario("incomplete")
        result = self.run_action(FIXTURE_EXIT="2")
        self.assert_failed(result)
        self.assertTrue(self.sarif.is_file())
        self.assertIn("exit-code=2\nsarif-valid=true", self.output.read_text())

    def test_explicit_partial_and_recovery_preserve_cli_contract(self):
        for status in ("partial-accepted", "recovery-accepted"):
            for blocking in (0, 1):
                with self.subTest(status=status, blocking=blocking):
                    code = self.scenario(status, blocking=blocking)
                    result = self.run_action(INPUT_GATE="error", FIXTURE_EXIT=str(code))
                    self.assertEqual(result.returncode, code, result.stdout)
                    self.assertEqual(json.loads(self.sarif.read_text()), json.loads(self.fixture.read_text()))
                    self.sarif.unlink()
                    self.output.unlink()

    def test_unrequested_partial_cannot_pass(self):
        self.scenario("partial-accepted")
        self.mutate_report(lambda data: data["runs"][0]["invocations"][0]["properties"]["codeskeptic/coverage"].update(accept_partial_coverage=False))
        self.assert_failed(self.run_action())

    def test_native_verdict_must_match_count(self):
        self.scenario("findings", blocking=1)
        self.mutate_report(lambda data: data["runs"][0]["results"][0]["properties"].update({"codeskeptic/blocksVerdict": False}))
        self.assert_failed(self.run_action(FIXTURE_EXIT="1"))

    def test_boolean_exit_code_is_not_an_integer_verdict(self):
        self.mutate_report(lambda data: data["runs"][0]["properties"]["codeskeptic/report"].update(exit_code=False))
        self.assert_failed(self.run_action())

    def test_version_must_match_executed_binary(self):
        self.mutate_report(lambda data: data["runs"][0]["properties"]["codeskeptic/report"].update(tool_version="0.0.0"))
        self.assert_failed(self.run_action())

    def test_duplicate_json_keys_rejected(self):
        self.fixture.write_text(self.fixture.read_text().replace('"version": "2.1.0"', '"version": "wrong", "version": "2.1.0"', 1))
        self.assert_failed(self.run_action())

    def test_native_analyzer_does_not_receive_runner_secrets(self):
        observed = self.root / "environment-observation"
        result = self.run_action(GH_TOKEN="synthetic-token", UNRELATED_SECRET="synthetic-secret", CHECK_ENV=str(observed))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(observed.read_text(), "False")

    def test_report_path_symlink_does_not_overwrite_target(self):
        preserved = self.root / "preserved"
        preserved.write_text("keep\n")
        self.sarif.symlink_to(preserved)
        self.assert_failed(self.run_action())
        self.assertEqual(preserved.read_text(), "keep\n")

    def test_extra_args_cannot_redirect_report(self):
        self.assert_failed(self.run_action(INPUT_EXTRA_ARGS="--sarif elsewhere.sarif"))
        self.assertFalse((self.root / "elsewhere.sarif").exists())

    def test_nonstandard_process_failure_never_becomes_report_only_success(self):
        result = self.run_action(FIXTURE_EXIT="137")
        self.assert_failed(result)
        self.assertFalse(self.sarif.exists())
        self.assertIn("exit-code=137\nsarif-valid=false", self.output.read_text())

    def test_timeout_remains_failure(self):
        self.assert_failed(self.run_action(FIXTURE_MODE="sleep", INPUT_TIMEOUT="1"))
        self.assertFalse(self.sarif.exists())

    def test_failure_evidence_cannot_claim_clean(self):
        self.mutate_report(lambda data: data["runs"][0]["properties"]["codeskeptic/report"]["evidence"].update(tool_failed=True))
        self.assert_failed(self.run_action())

    def test_recovery_count_cannot_claim_full_coverage(self):
        self.mutate_report(lambda data: data["runs"][0]["invocations"][0]["properties"]["codeskeptic/coverage"].update(recovery_tus=1))
        self.assert_failed(self.run_action())


if __name__ == "__main__":
    unittest.main()
