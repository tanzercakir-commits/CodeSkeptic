#!/usr/bin/env python3
"""Static hosted contract for Phase 10 determinism qualification."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "determinism.yml"


class DeterminismWorkflowTest(unittest.TestCase):
    def test_exact_head_runs_all_three_workloads_ten_times(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn("git worktree add --detach", text)
        self.assertIn("--verify-baseline-authority", text)
        self.assertIn("--verify-bootstrap-promotion", text)
        self.assertIn("--verify-baseline-promotion", text)
        self.assertIn("head-bootstrap", text)
        self.assertIn("head-promotion", text)
        self.assertIn("protected-base", text)
        self.assertIn("Candidate deletes the protected baseline authority", text)
        self.assertGreaterEqual(text.count("--verify-baseline-authority"), 2)
        self.assertIn("--baseline-authority-root", text)
        self.assertIn("--repetitions 10", text)
        self.assertIn("--performance-policy record-only", text)
        self.assertIn("scripts/determinism_workloads.json", text)
        self.assertIn("--prepare-release-candidate", text)
        self.assertIn("--verify-receipt", text)
        self.assertIn("--establish-baseline", text)
        self.assertIn("--calibration-output", text)
        self.assertIn("--calibration-evidence-path", text)
        self.assertIn("--promotion-reason", text)
        self.assertIn("Calibration evidence produced", text)
        self.assertIn("exit 2", text)
        self.assertIn("llama-cpp", text)
        self.assertIn("CC=/usr/bin/clang-20", text)
        self.assertIn("CXX=/usr/bin/clang++-20", text)
        self.assertIn("/usr/bin/cmake -S . -B build-determinism", text)
        self.assertIn("-DCMAKE_MAKE_PROGRAM=/usr/bin/ninja", text)
        self.assertIn("/usr/bin/cmake --build build-determinism", text)
        self.assertIn("--c-compiler /usr/bin/clang-20", text)
        self.assertIn("--cxx-compiler /usr/bin/clang++-20", text)

    def test_hosted_evidence_is_bounded_visible_and_fail_closed(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("timeout-minutes:", text)
        self.assertIn("GITHUB_STEP_SUMMARY", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("if: always()", text)
        self.assertIn("if-no-files-found: error", text)
        self.assertIn("retention-days:", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("pull_request_target", text)


if __name__ == "__main__":
    unittest.main()
