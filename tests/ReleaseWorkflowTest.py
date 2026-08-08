#!/usr/bin/env python3
"""Contract tests for release-workflow fail-closed smoke assertions."""

from __future__ import annotations

import re
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


def job(name: str) -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    start_marker = f"  {name}:\n"
    start = workflow.index(start_marker)
    next_job = re.search(
        r"(?m)^  [A-Za-z0-9_-]+:\s*$",
        workflow[start + len(start_marker):],
    )
    if next_job is None:
        return workflow[start:]
    end = start + len(start_marker) + next_job.start()
    return workflow[start:end]


class ReleaseWorkflowTest(unittest.TestCase):
    def test_unavailable_analysis_uses_canonical_verdict(self) -> None:
        smoke = macos_smoke_step()
        self.assertIn('test "$code2" -eq 2', smoke)
        self.assertIn('grep -q "VERDICT UNAVAILABLE"', smoke)
        self.assertNotIn("ANALYSIS FAILED", smoke)

    def test_draft_release_is_created_once_before_parallel_jobs(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("gh release create"), 1)
        prepare = job("prepare")
        self.assertIn("gh release create", prepare)
        self.assertIn("--json isDraft", prepare)
        self.assertIn('test "$draft" = "true"', prepare)
        for platform in ("linux", "macos", "windows"):
            self.assertIn("    needs: prepare", job(platform))


if __name__ == "__main__":
    unittest.main()
