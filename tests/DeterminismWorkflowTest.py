#!/usr/bin/env python3
"""Static hosted contract for Phase 10 determinism qualification."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "determinism.yml"
CMAKE = ROOT / "CMakeLists.txt"


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
        self.assertNotIn("--establish-baseline", text)
        self.assertNotIn("--calibration-output", text)
        self.assertNotIn("--calibration-evidence-path", text)
        self.assertNotIn("--promotion-reason", text)
        self.assertIn(
            "Shared GitHub runners cannot establish or promote performance authority",
            text,
        )
        self.assertNotIn("determinism-calibration", text)
        self.assertNotIn("determinism-hosted-baseline.json", text)
        self.assertIn("exit 2", text)
        self.assertIn("llama-cpp", text)
        self.assertIn("CC=/usr/bin/clang-20", text)
        self.assertIn("CXX=/usr/bin/clang++-20", text)
        self.assertIn("/usr/bin/cmake -S . -B build-determinism", text)
        self.assertIn("-DCMAKE_MAKE_PROGRAM=/usr/bin/ninja", text)
        self.assertIn("/usr/bin/cmake --build build-determinism", text)
        self.assertIn("--c-compiler /usr/bin/clang-20", text)
        self.assertIn("--cxx-compiler /usr/bin/clang++-20", text)

        build = text.split(
            "      - name: Build exact-head release analyzer\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertIn(
            "env:\n          CODESKEPTIC_VERSION_OVERRIDE: 0.4.9-dev",
            build,
        )
        self.assertNotIn("-DCODESKEPTIC_VERSION_OVERRIDE", build)

    def test_evidence_identity_override_does_not_mutate_cmake_cache(self) -> None:
        text = CMAKE.read_text(encoding="utf-8")
        cache_override = 'if(CODESKEPTIC_VERSION_OVERRIDE)'
        environment_override = (
            'elseif(DEFINED ENV{CODESKEPTIC_VERSION_OVERRIDE} AND\n'
            '       NOT "$ENV{CODESKEPTIC_VERSION_OVERRIDE}" STREQUAL "")'
        )
        git_identity = "COMMAND git describe --tags --exact-match HEAD"
        self.assertIn(cache_override, text)
        self.assertIn(environment_override, text)
        self.assertIn(
            'set(CODESKEPTIC_VERSION_STRING '
            '"$ENV{CODESKEPTIC_VERSION_OVERRIDE}")',
            text,
        )
        self.assertLess(text.index(cache_override), text.index(environment_override))
        self.assertLess(text.index(environment_override), text.index(git_identity))

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
        self.assertIn("receipt['decision']['classification']", text)
        self.assertIn('receipt["decision"]["failures"]', text)
        self.assertIn('receipt["observations"]', text)
        self.assertNotIn("receipt['failure']", text)

    def test_runner_context_is_only_used_after_a_step_starts(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        job_definition = text.split("    steps:\n", 1)[0]
        self.assertNotIn("${{ runner.", job_definition)
        materialize = text.split(
            "      - name: Materialize protected-base performance authority\n", 1
        )[1].split("      - name:", 1)[0]
        qualify = text.split(
            "      - name: Qualify unit, real-repository, and "
            "llama-cpp release-candidate workloads\n",
            1,
        )[1].split("      - name:", 1)[0]
        self.assertIn(
            "PINNED_BASELINE: ${{ runner.temp }}/"
            "pinned-base-determinism-baseline.json",
            materialize,
        )
        self.assertIn(
            "BASELINE_ROOT: ${{ runner.temp }}/pinned-base-worktree",
            materialize,
        )
        self.assertIn(
            "PINNED_BASELINE: ${{ runner.temp }}/"
            "pinned-base-determinism-baseline.json",
            qualify,
        )


if __name__ == "__main__":
    unittest.main()
