#!/usr/bin/env python3
"""Behavioral contract for the fail-closed thesis quality gate."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_thesis.sh"


class ThesisWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("cc") is None and shutil.which("clang") is None:
            self.skipTest("thesis runner requires a C compiler for its compile DB")

        self._temporary = tempfile.TemporaryDirectory()
        self.fixture = Path(self._temporary.name)
        scripts = self.fixture / "scripts"
        corpus = self.fixture / "tests" / "thesis_corpus"
        binary = self.fixture / "bin"
        scripts.mkdir()
        corpus.mkdir(parents=True)
        binary.mkdir()

        shutil.copy2(RUNNER, scripts / "run_thesis.sh")
        (corpus / "sample.c").write_text(
            "int sample(void) { return 0; }\n",
            encoding="utf-8",
        )
        self.analyzer = binary / "fake-codeskeptic"
        self.analyzer.write_text(
            """#!/usr/bin/env bash
case "${FAKE_ANALYZER_MODE:?}" in
  clean)
    exit 0
    ;;
  finding)
    printf '%s:1:1 [warning] synthetic finding\n' "$1" >&2
    exit 1
    ;;
  unavailable)
    exit 2
    ;;
esac
""",
            encoding="utf-8",
        )
        self.analyzer.chmod(0o755)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def run_gate(self, manifest: str, mode: str) -> subprocess.CompletedProcess[str]:
        (self.fixture / "tests" / "thesis_corpus" / "thesis_expected.txt").write_text(
            manifest,
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["FAKE_ANALYZER_MODE"] = mode
        return subprocess.run(
            [
                "bash",
                str(self.fixture / "scripts" / "run_thesis.sh"),
                str(self.analyzer),
            ],
            cwd=self.fixture,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

    def test_exit_2_without_findings_is_fail_closed(self) -> None:
        result = self.run_gate("sample.c CLEAN 0\n", "unavailable")

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("THESIS_FAIL analyzer unavailable", result.stdout)
        self.assertIn("sample.c exit 2", result.stdout)

    def test_exit_0_clean_result_remains_accepted(self) -> None:
        result = self.run_gate("sample.c CLEAN 0\n", "clean")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("clean_fp=0", result.stdout)
        self.assertIn("[thesis] gate OK", result.stdout)

    def test_exit_1_finding_result_remains_analyzable(self) -> None:
        result = self.run_gate("sample.c BUG 1\n", "finding")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("bug_caught=1/1", result.stdout)
        self.assertIn("total_findings=1", result.stdout)


if __name__ == "__main__":
    unittest.main()
