#!/usr/bin/env python3
"""Execute repository-owned onboarding recipes with a locally installed CLI."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


if len(sys.argv) < 2:
    raise SystemExit("usage: FirstScanTest.py <codeskeptic-binary> [unittest options]")
BINARY = Path(sys.argv.pop(1)).resolve(strict=True)
REPO = Path(__file__).resolve().parents[1]


def snippet(name, document="docs/first-scan.md"):
    text = (REPO / document).read_text(encoding="utf-8")
    matches = re.findall(r"<!-- first-scan:" + re.escape(name) + r" -->\n```[^\n]*\n(.*?)\n```",
                         text, re.DOTALL)
    if len(matches) != 1:
        raise AssertionError("expected one executable documentation block: " + name)
    return matches[0] + "\n"


class FirstScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installation = tempfile.TemporaryDirectory(prefix="first-scan-install-")
        cls.addClassCleanup(cls.installation.cleanup)
        cls.prefix = Path(cls.installation.name) / "local prefix"
        env = {**os.environ, "CODESKEPTIC_BUILT_BINARY": str(BINARY),
               "CODESKEPTIC_LOCAL_PREFIX": str(cls.prefix)}
        installed = subprocess.run(["bash", "-eu", "-c", snippet("install")], env=env,
                                   capture_output=True, text=True, timeout=30)
        if installed.returncode:
            raise AssertionError(installed.stdout + installed.stderr)
        cls.cli = cls.prefix / "bin/codeskeptic"
        cls.install_env = {**env, "PATH": str(cls.cli.parent) + os.pathsep + os.environ["PATH"]}
        digest = hashlib.sha256(cls.cli.read_bytes()).hexdigest()
        if digest != hashlib.sha256(BINARY.read_bytes()).hexdigest():
            raise AssertionError("installed binary bytes differ")
        print("FIRST_SCAN_INSTALLED path=" + str(cls.cli) + " sha256=" + digest
              + " version=" + installed.stdout.strip(), flush=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="first-scan-project-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.env = dict(self.install_env)
        self.env["FIRST_SCAN_REAL_CLI"] = str(self.cli)
        for directory in ("src", "include", "ci"):
            (self.root / directory).mkdir()
        for name, path in (("cmake-file", "CMakeLists.txt"), ("header-file", "include/fixture.h"),
                           ("c-file", "src/answer.c"), ("cpp-file", "src/answer.cpp")):
            (self.root / path).write_text(snippet(name), encoding="utf-8")
        self.recipe = self.root / "ci/report_only.py"
        self.recipe.write_text(snippet("report-only-file", "docs/integrations.md"), encoding="utf-8")

    def command(self, arguments, expected=0, env=None):
        result = subprocess.run(arguments, cwd=self.root, env=env or self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def shell(self, name, expected=0, document="docs/first-scan.md"):
        return self.command(["bash", "-eu", "-c", snippet(name, document)], expected)

    def configure(self):
        self.shell("configure")

    def report_only(self, expected=0, build="build", output="scan-artifacts", env=None):
        result = self.command([sys.executable, str(self.recipe), "src", build, output], expected, env)
        self.assertIn("REPORT_ONLY_OK" if expected == 0 else "REPORT_ONLY_FAILED", result.stdout + result.stderr)
        if expected:
            self.assertNotIn("REPORT_ONLY_OK", result.stdout)
        return result

    def sarif(self, output="scan-artifacts"):
        return json.loads((self.root / output / "codeskeptic.sarif").read_text(encoding="utf-8"))

    def stub(self, body):
        directory = self.root / "stub-bin"
        directory.mkdir(exist_ok=True)
        executable = directory / "codeskeptic"
        executable.write_text("#!/bin/bash\nset -eu\n" + body + "\n", encoding="utf-8")
        executable.chmod(0o755)
        return {**self.env, "PATH": str(directory) + os.pathsep + self.env["PATH"]}

    def test_documented_c_and_cpp_workflow_and_missing_input_repair(self):
        unavailable = self.shell("doctor", expected=2)
        for field in ("status: unavailable", "reason:", "next:"):
            self.assertIn(field, unavailable.stderr)
        self.configure()
        ready = self.shell("doctor")
        self.assertIn("status: ready", ready.stdout)
        self.assertIn("source-files: 2", ready.stdout)
        self.shell("scan")
        report = json.loads((self.root / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(report["schema"], "codeskeptic-report/v1")
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["exit_code"], 0)
        self.assertIs(report["complete"], True)
        self.assertIs(report["coverage"]["complete"], True)
        self.assertEqual(report["coverage"]["analyzed_tus"], 2)
        self.assertEqual({Path(row["file"]).suffix for row in report["coverage"]["sources"]}, {".c", ".cpp"})
        self.shell("baseline")
        self.assertTrue((self.root / ".codeskeptic-baseline").read_text().startswith("# codeskeptic-baseline v3\n"))

    def test_documented_report_only_command_is_clean_and_keeps_artifact(self):
        self.configure()
        result = self.shell("report-only-run", document="docs/integrations.md")
        self.assertIn("REPORT_ONLY_OK analyzer_exit=0 sources=2", result.stdout)
        report = self.sarif()["runs"][0]["properties"]["codeskeptic/report"]
        self.assertEqual(report["status"], "clean")

    def test_install_refuses_existing_prefix(self):
        before = self.cli.read_bytes()
        result = subprocess.run(["bash", "-eu", "-c", snippet("install")], env=self.env,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cli.read_bytes(), before)

    def test_c_and_cpp_findings_are_visible_but_wrapper_nonblocking(self):
        self.configure()
        for suffix in ("c", "cpp"):
            with (self.root / ("src/answer." + suffix)).open("a", encoding="utf-8") as stream:
                stream.write("\nint broken_" + suffix + "(void) { int *p = 0; return *p; }\n")
        result = self.report_only()
        self.assertIn("analyzer_exit=1 sources=2", result.stdout)
        run = self.sarif()["runs"][0]
        report = run["properties"]["codeskeptic/report"]
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["status"], "findings")
        self.assertGreaterEqual(report["finding_counts"]["blocking"], 2)
        locations = {finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                     for finding in run["results"]}
        self.assertTrue(any(path.endswith("answer.c") for path in locations))
        self.assertTrue(any(path.endswith("answer.cpp") for path in locations))
        self.shell("baseline")
        self.command([str(self.cli), "src", "--build-path", "build", "--baseline",
                      ".codeskeptic-baseline", "--json", "accepted.json"])
        accepted = json.loads((self.root / "accepted.json").read_text())
        self.assertEqual(accepted["status"], "clean")
        self.assertGreaterEqual(accepted["baseline"]["matched_callbacks"], 2)
        self.assertIs(accepted["coverage"]["complete"], True)

    def test_report_only_missing_and_wrong_database_remain_failures(self):
        self.report_only(expected=2, output="missing-db")
        self.configure()
        self.report_only(expected=2, build="wrong-build", output="wrong-db")

    def test_report_only_missing_header_and_unmapped_source_remain_failures(self):
        self.configure()
        header = self.root / "include/fixture.h"
        original = header.read_bytes()
        header.unlink()  # Only this test's generated fixture file.
        self.report_only(expected=2, output="missing-header")
        header.write_bytes(original)
        (self.root / "src/unmapped.c").write_text("int unmapped(void) { return 1; }\n")
        self.report_only(expected=2, output="unmapped")

    def test_old_output_is_refused_without_overwriting_it(self):
        self.configure()
        self.report_only()
        before = (self.root / "scan-artifacts/codeskeptic.sarif").read_bytes()
        self.report_only(expected=2)
        self.assertEqual((self.root / "scan-artifacts/codeskeptic.sarif").read_bytes(), before)

    def test_missing_malformed_and_real_no_source_reports_do_not_turn_green(self):
        self.configure()
        for index, body in enumerate(("exit 0", "exit 1", 'exec "$FIRST_SCAN_REAL_CLI"',
                                      'printf "not json" > "${@: -1}"; exit 0')):
            with self.subTest(body=body):
                self.report_only(expected=2, output="bad-report-" + str(index), env=self.stub(body))

    def test_incomplete_forged_or_mismatching_reports_are_rejected(self):
        self.configure()
        self.report_only()
        valid = self.sarif()
        mutations = (
            lambda r, c: r.update(complete=False),
            lambda r, c: r.update(schema="unknown"),
            lambda r, c: r.update(exit_code=1),
            lambda r, c: r.update(status="findings"),
            lambda r, c: c.update(complete=False),
            lambda r, c: c.update(analyzed_tus=1),
            lambda r, c: c.update(recovery_tus=1),
            lambda r, c: c.update(accept_partial_coverage=True),
            lambda r, c: c.update(analyze_broken_tus=True),
            lambda r, c: c["sources"][0].update(file="/unrelated/input.c"),
            lambda r, c: c["sources"][0].update(analyzed_commands=0),
            lambda r, c: c["sources"][0]["prepass"].update(recovery_commands=1),
            lambda r, c: r["finding_counts"].update(total=99),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                payload = copy.deepcopy(valid)
                run = payload["runs"][0]
                mutate(run["properties"]["codeskeptic/report"],
                       run["invocations"][0]["properties"]["codeskeptic/coverage"])
                (self.root / "stub.sarif").write_text(json.dumps(payload), encoding="utf-8")
                self.report_only(expected=2, output="mutation-" + str(index),
                                 env=self.stub('cp stub.sarif "${@: -1}"; exit 0'))

    def test_launch_and_timeout_failures_are_not_accepted(self):
        namespace = {"__name__": "first_scan_recipe_test"}
        exec(compile(self.recipe.read_text(), str(self.recipe), "exec"), namespace)
        for index, error in enumerate((FileNotFoundError("binary unavailable"),
                                       subprocess.TimeoutExpired("codeskeptic", 300))):
            output = self.root / ("exception-" + str(index))
            args = [str(self.recipe), str(self.root / "src"), str(self.root / "build"), str(output)]
            with self.subTest(error=type(error).__name__), mock.patch.object(sys, "argv", args), \
                    mock.patch.object(subprocess, "run", side_effect=error), \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(namespace["main"](), 2)
                self.assertIn("REPORT_ONLY_FAILED", errors.getvalue())


class FirstScanDocRegressionTest(unittest.TestCase):
    def test_baseline_recipe_creates_before_loading(self):
        text = (REPO / "docs/first-scan.md").read_text(encoding="utf-8")
        commands = re.findall(r"^codeskeptic src/ --build-path build --(?:write-)?baseline .+$",
                              text, re.MULTILINE)
        self.assertTrue(commands, "first-scan must contain a baseline recipe")
        with tempfile.TemporaryDirectory(prefix="first-scan-baseline-") as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "build").mkdir()
            source = root / "src/input.c"
            source.write_text("int safe(void) { return 42; }\n", encoding="utf-8")
            (root / "build/compile_commands.json").write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang", "-c", str(source)],
            }]), encoding="utf-8")
            # Only execute trusted, repository-owned documentation commands.
            command = commands[0].replace("codeskeptic ", '"$FIRST_SCAN_BINARY" ', 1)
            result = subprocess.run(["bash", "-eu", "-c", command], cwd=root,
                                    env={**os.environ, "FIRST_SCAN_BINARY": str(BINARY)},
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("--write-baseline", commands[0])

    def test_no_blanket_success_in_documented_ci(self):
        text = (REPO / "docs/integrations.md").read_text(encoding="utf-8")
        unsafe = [line for line in text.splitlines()
                  if "run:" in line and "codeskeptic" in line and "|| true" in line]
        if unsafe:
            with tempfile.TemporaryDirectory(prefix="first-scan-old-ci-") as temporary:
                root = Path(temporary)
                (root / "input.c").write_text("int safe(void) { return 42; }\n")
                command = '"$FIRST_SCAN_BINARY" . --build-path missing --sarif out.sarif'
                env = {**os.environ, "FIRST_SCAN_BINARY": str(BINARY)}
                failure = subprocess.run(["bash", "-c", command], cwd=root, env=env,
                                         capture_output=True, text=True, timeout=30)
                masked = subprocess.run(["bash", "-c", command + " || true"], cwd=root,
                                        env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(failure.returncode, 2, failure.stderr)
                self.assertNotEqual(masked.returncode, 0,
                                    "documented || true masks actual missing-input exit 2")
        self.assertFalse(unsafe)


if __name__ == "__main__":
    unittest.main()
