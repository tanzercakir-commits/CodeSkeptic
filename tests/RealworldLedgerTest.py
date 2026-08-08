#!/usr/bin/env python3
"""Regression tests for the fail-closed real-world replay ledger."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "check_realworld_ledger.py"
CANONICAL = ROOT / "scripts" / "realworld_expected.txt"

LIBGIT2 = "libgit2 338e6fb681369ff0537719095e22ce9dc602dbf0 v1.9.0 167 34 1 - -"
RTP = "rtp2httpd a7a1e568d46ee3176f8a3e94e0f88f131ebd444e a7a1e568 38 4 1 4 0"


def run_ledger(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "ledger.txt"
        path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(path)],
            check=False,
            capture_output=True,
            text=True,
        )


class RealworldLedgerTest(unittest.TestCase):
    def test_canonical_ledger_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(CANONICAL)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REALWORLD_LEDGER_OK", result.stdout)

    def test_duplicate_project_fails(self) -> None:
        result = run_ledger(f"{LIBGIT2}\n{LIBGIT2}\n{RTP}\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate_project=libgit2", result.stderr)

    def test_movable_revision_fails(self) -> None:
        result = run_ledger(f"{LIBGIT2.replace('338e6fb681369ff0537719095e22ce9dc602dbf0', 'v1.9.0')}\n{RTP}\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid_revision", result.stderr)

    def test_unavailable_verdict_fails(self) -> None:
        result = run_ledger(f"{LIBGIT2.replace('34 1', '34 2')}\n{RTP}\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unavailable_verdict_exit=2", result.stderr)

    def test_finding_exit_contradiction_fails(self) -> None:
        result = run_ledger(f"{LIBGIT2.replace('34 1', '34 0')}\n{RTP}\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("contradict_exit=0", result.stderr)

    def test_incomplete_or_dishonest_triage_fails(self) -> None:
        partial = run_ledger(f"{LIBGIT2}\n{RTP.rsplit(' ', 1)[0]} -\n")
        self.assertEqual(partial.returncode, 1)
        self.assertIn("partial_triage_partition", partial.stderr)

        wrong_sum = run_ledger(f"{LIBGIT2}\n{RTP.rsplit(' ', 2)[0]} 3 2\n")
        self.assertEqual(wrong_sum.returncode, 1)
        self.assertIn("triage_total=5 findings=4", wrong_sum.stderr)


if __name__ == "__main__":
    unittest.main()
