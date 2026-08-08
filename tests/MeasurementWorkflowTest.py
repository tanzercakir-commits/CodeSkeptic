#!/usr/bin/env python3
"""Static contract for the fail-closed base/head measurement workflow."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "measurement.yml"


class MeasurementWorkflowTest(unittest.TestCase):
    def test_exact_base_and_head_are_built_and_measured(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", text)
        self.assertIn("git worktree add --detach", text)
        self.assertEqual(text.count("scripts/run_measurement_lab.py"), 2)
        self.assertIn("scripts/compare_measurements.py", text)

    def test_receipts_are_visible_and_bounded(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("GITHUB_STEP_SUMMARY", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("timeout-minutes: 30", text)
        self.assertIn("if-no-files-found: error", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("pull_request_target", text)


if __name__ == "__main__":
    unittest.main()
