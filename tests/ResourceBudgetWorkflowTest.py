#!/usr/bin/env python3
"""Contract for the native-macOS per-TU resource-budget CI gate."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


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


class ResourceBudgetWorkflowTest(unittest.TestCase):
    def test_native_macos_gate_builds_and_runs_the_complete_suite(self) -> None:
        gate = job("resource-budget-macos")
        self.assertIn("runs-on: macos-14", gate)
        self.assertIn("fetch-depth: 0", gate)
        self.assertIn("brew install llvm@20 cmake ninja", gate)
        self.assertIn('CMAKE_PREFIX_PATH="$(brew --prefix llvm@20)"', gate)
        self.assertIn("cmake --build build", gate)
        self.assertIn("ctest --test-dir build --output-on-failure", gate)
        self.assertIn("./build/tests/codeskeptic_tests", gate)

    def test_native_macos_gate_is_bounded_and_fail_closed(self) -> None:
        gate = job("resource-budget-macos")
        self.assertIn("timeout-minutes: 45", gate)
        self.assertIn("if: failure()", gate)
        self.assertIn(
            'refs/status/${{ github.sha }}/resource-budget-macos/${{ job.status }}',
            gate,
        )
        self.assertNotIn("continue-on-error", gate)


if __name__ == "__main__":
    unittest.main()
