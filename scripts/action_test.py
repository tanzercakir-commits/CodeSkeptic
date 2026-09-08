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


def source_row(path, status="analyzed"):
    return {"file": str(path), "status": status, "reason": "" if status == "analyzed" else "synthetic",
            "commands": 1, "analyzed_commands": int(status == "analyzed"),
            "skipped_commands": int(status == "skipped"), "failed_commands": int(status == "failed"),
            "recovery_commands": 0, "prepass": {"status": "not_requested", "reason": "", "recovery_commands": 0}}


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
                "incomplete_functions": 0, "attempted_commands": 1, "analyzed_commands": 1,
                "skipped_commands": 0, "failed_commands": 0, "sources": [source_row(source)]}
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
                "codeskeptic/attemptedTUs": 1, "codeskeptic/analyzedTUs": 1,
                "codeskeptic/brokenTUs": 0, "codeskeptic/incompleteFunctions": 0,
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
            run["results"].append({"ruleId": "test-rule", "level": "warning", "message": {"text": "synthetic finding"},
                                   "properties": {"codeskeptic/blocksVerdict": index < blocking}})
        if status in ("incomplete", "partial-accepted"):
            coverage.update(complete=False, attempted_tus=2, skipped_tus=1, broken_tus=1,
                            attempted_commands=2, skipped_commands=1,
                            accept_partial_coverage=status == "partial-accepted")
            coverage["sources"].append(source_row(self.root / "skipped.cpp", "skipped"))
            properties.update({"codeskeptic/attemptedTUs": 2, "codeskeptic/brokenTUs": 1})
        if status == "recovery-accepted":
            coverage.update(complete=False, recovery_tus=1, analyze_broken_tus=True)
            coverage["sources"][0]["recovery_commands"] = 1
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

    def change_coverage(self, function):
        self.mutate_report(lambda data: function(data["runs"][0]["invocations"][0]["properties"]["codeskeptic/coverage"]))

    def test_command_aggregate_must_match_sources(self):
        self.change_coverage(lambda coverage: coverage.update(failed_commands=99))
        self.assert_failed(self.run_action())

    def test_command_aggregate_is_required(self):
        self.change_coverage(lambda coverage: coverage.pop("attempted_commands"))
        self.assert_failed(self.run_action())

    def test_row_recovery_must_match_aggregate(self):
        self.change_coverage(lambda coverage: coverage["sources"][0].update(recovery_commands=1))
        self.assert_failed(self.run_action())

    def test_prepass_recovery_must_match_aggregate(self):
        self.change_coverage(lambda coverage: coverage["sources"][0]["prepass"].update(recovery_commands=1))
        self.assert_failed(self.run_action())

    def test_duplicated_invocation_counters_must_agree(self):
        for key in ("attemptedTUs", "analyzedTUs", "brokenTUs", "incompleteFunctions"):
            with self.subTest(key=key):
                self.fixture.write_text(json.dumps(clean_sarif(self.source)))
                self.mutate_report(lambda data: data["runs"][0]["invocations"][0]["properties"].update({"codeskeptic/" + key: 99}))
                result = self.run_action()
                # Clear only a wrongly published test report, so every subcase runs.
                if self.sarif.exists():
                    self.sarif.unlink()
                self.assert_failed(result)

    def test_results_must_be_array(self):
        self.mutate_report(lambda data: data["runs"][0].update(results={}))
        self.assert_failed(self.run_action())

    def test_non_finite_json_cannot_be_published(self):
        for value in ("NaN", "Infinity", "-Infinity", "1e999"):
            with self.subTest(value=value):
                text = json.dumps(clean_sarif(self.source))
                self.fixture.write_text(text[:-1] + ', "extra": ' + value + '}')
                result = self.run_action()
                if self.sarif.exists():
                    self.sarif.unlink()
                self.assert_failed(result)

    def test_native_finding_requires_message_text(self):
        self.scenario("findings", blocking=1)
        self.mutate_report(lambda data: data["runs"][0]["results"][0].update(message=[]))
        self.assert_failed(self.run_action(FIXTURE_EXIT="1"))

    def test_native_row_counters_are_typed(self):
        self.change_coverage(lambda coverage: coverage["sources"][0].update(failed_commands=False))
        self.assert_failed(self.run_action())

    def test_prepass_recovery_positive_is_preserved(self):
        self.scenario("recovery-accepted")
        def prepass_only(coverage):
            coverage["sources"][0]["recovery_commands"] = 0
            coverage["sources"][0]["prepass"].update(status="analyzed", recovery_commands=1)
        self.change_coverage(prepass_only)
        result = self.run_action(INPUT_GATE="error")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("sarif-valid=true", self.output.read_text())

    def test_command_failure_cannot_hide_under_analyzed_status(self):
        def contradict(coverage):
            coverage.update(analyzed_commands=0, failed_commands=1)
            coverage["sources"][0].update(analyzed_commands=0, failed_commands=1)
        self.change_coverage(contradict)
        self.assert_failed(self.run_action())

    def test_unrequested_prepass_cannot_carry_recovery(self):
        self.scenario("recovery-accepted")
        self.change_coverage(lambda coverage: coverage["sources"][0]["prepass"].update(recovery_commands=1))
        self.assert_failed(self.run_action())

    def test_prepass_recovery_cannot_exceed_commands(self):
        self.scenario("recovery-accepted")
        self.change_coverage(lambda coverage: coverage["sources"][0]["prepass"].update(status="analyzed", recovery_commands=2))
        self.assert_failed(self.run_action())

    def test_recovery_requires_explicit_opt_in(self):
        self.scenario("recovery-accepted")
        self.change_coverage(lambda coverage: coverage.update(analyze_broken_tus=False))
        self.assert_failed(self.run_action())

    def test_prepass_promoted_skipped_with_analyzed_commands_is_valid(self):
        self.scenario("partial-accepted")
        def promoted(coverage):
            coverage.update(analyzed_commands=2, skipped_commands=0)
            row = coverage["sources"][1]
            row.update(reason="summary_prepass_skipped", analyzed_commands=1, skipped_commands=0)
            row["prepass"].update(status="skipped", reason="parse_errors")
        self.change_coverage(promoted)
        result = self.run_action(INPUT_GATE="error")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("sarif-valid=true", self.output.read_text())

    def test_native_failed_and_zero_command_reports_are_retained(self):
        for zero_commands in (False, True):
            with self.subTest(zero_commands=zero_commands):
                data = clean_sarif(self.source)
                run = data["runs"][0]
                run["properties"]["codeskeptic/report"].update(status="failed", complete=False, exit_code=2)
                invocation = run["invocations"][0]
                invocation["executionSuccessful"] = False
                properties = invocation["properties"]
                properties.update({"codeskeptic/status": "failed", "codeskeptic/exitCode": 2, "codeskeptic/analyzedTUs": 0})
                coverage = properties["codeskeptic/coverage"]
                coverage.update(complete=False, analyzed_tus=0, failed_tus=1)
                row = coverage["sources"][0]
                row.update(status="failed", reason="summary_prepass_failed")
                row["prepass"].update(status="failed", reason="synthetic failure")
                if zero_commands:
                    coverage.update(attempted_commands=0, analyzed_commands=0)
                    row.update(commands=0, analyzed_commands=0, reason="missing_input")
                    row["prepass"].update(status="not_requested", reason="")
                self.fixture.write_text(json.dumps(data))
                result = self.run_action(FIXTURE_EXIT="2")
                self.assert_failed(result)
                self.assertIn("sarif-valid=true", self.output.read_text())
                self.sarif.unlink()
                self.output.unlink()


if __name__ == "__main__":
    unittest.main()
