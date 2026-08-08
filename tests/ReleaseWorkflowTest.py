#!/usr/bin/env python3
"""Contract tests for release-workflow fail-closed smoke assertions."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
MACOS_SMOKE = "      - name: Smoke from an unpacked tree outside the repo"
NEXT_STEP = "      - name: Upload to draft release"


def macos_smoke_step() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    start = workflow.index(MACOS_SMOKE)
    end = workflow.index(NEXT_STEP, start)
    return workflow[start:end]


class ReleaseWorkflowTest(unittest.TestCase):
    def test_unavailable_analysis_uses_canonical_verdict(self) -> None:
        smoke = macos_smoke_step()
        self.assertIn('test "$code2" -eq 2', smoke)
        self.assertIn('grep -q "VERDICT UNAVAILABLE"', smoke)
        self.assertNotIn("ANALYSIS FAILED", smoke)


if __name__ == "__main__":
    unittest.main()
