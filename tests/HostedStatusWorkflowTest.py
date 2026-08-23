#!/usr/bin/env python3
"""Ensure hosted status refs always target the exact workflow source revision."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class HostedStatusWorkflowTest(unittest.TestCase):
    def test_every_status_ref_pushes_github_sha_not_mutated_head(self) -> None:
        observed = 0
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if "refs/status/" not in text:
                continue
            with self.subTest(workflow=path.name):
                self.assertNotIn("HEAD:refs/status/", text)
                pushes = re.findall(
                    r'"([^"\n]+):refs/status/\$\{\{ github\.sha \}\}/[^"\n]+"',
                    text,
                )
                self.assertTrue(pushes, "workflow mentions status refs but pushes none")
                self.assertTrue(
                    all(source == "${{ github.sha }}" for source in pushes),
                    "status ref source is not the immutable workflow revision",
                )
                observed += len(pushes)
        self.assertGreaterEqual(observed, 15)

    def test_juliet_log_commit_cannot_become_the_success_ref_target(self) -> None:
        text = (WORKFLOWS / "juliet.yml").read_text(encoding="utf-8")
        self.assertIn('"HEAD:refs/ci-logs/${{ github.sha }}/juliet"', text)
        self.assertIn(
            '"${{ github.sha }}:refs/status/${{ github.sha }}/juliet/${{ job.status }}"',
            text,
        )


if __name__ == "__main__":
    unittest.main()
