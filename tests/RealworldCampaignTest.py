#!/usr/bin/env python3
"""Contracts for the deterministic real-repository campaign factory."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_realworld_campaign.py"
MANIFEST = ROOT / "scripts" / "realworld_manifest.json"

spec = importlib.util.spec_from_file_location("realworld_campaign", RUNNER)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load campaign runner: {RUNNER}")
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


def fixture_manifest() -> dict:
    fingerprints = ["csf1-0000000000000001"]
    return {
        "schema": 1,
        "campaigns": {
            "nightly": {
                "window_minutes": 720,
                "repetitions": 3,
                "projects": ["alpha"],
            }
        },
        "projects": [
            {
                "id": "alpha",
                "label": "fixture",
                "repository": "https://github.com/example/alpha.git",
                "revision": "1" * 40,
                "timeout_minutes": 20,
                "memory_mb": 4096,
                "commands": {
                    "configure": [
                        [
                            "cmake",
                            "-S",
                            "{source}",
                            "-B",
                            "{build}",
                            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                        ]
                    ],
                    "build": [["cmake", "--build", "{build}"]],
                },
                "copies": [],
                "compile_database": "{build}/compile_commands.json",
                "sources": {
                    "roots": ["src"],
                    "extensions": [".c"],
                    "fallback_globs": [],
                },
                "analyzer_args": ["--report-paths", "{source}/src"],
                "expected": {
                    "translation_units": 2,
                    "translation_unit_sha256": "a" * 64,
                    "attempted_tus": 2,
                    "analyzed_tus": 2,
                    "broken_tus": 0,
                    "incomplete_functions": 0,
                    "findings": 1,
                    "exit_code": 1,
                    "fingerprint_sha256": campaign.fingerprint_digest(fingerprints),
                },
            }
        ],
    }


def accepted_receipt(
    manifest: dict,
    repetition: int,
    project_index: int = 0,
    analyzer_sha: str = "b" * 64,
) -> dict:
    project = manifest["projects"][project_index]
    expected = project["expected"]
    identity = campaign.receipt_identity(
        manifest, project, repetition, analyzer_sha, expected["translation_unit_sha256"]
    )
    return {
        "schema": 1,
        "status": "accepted",
        "project": project["id"],
        "repetition": repetition,
        "identity": identity,
        "semantic": {
            "translation_units": {
                "count": expected["translation_units"],
                "sha256": expected["translation_unit_sha256"],
            },
            "coverage": {
                "attempted_tus": expected["attempted_tus"],
                "analyzed_tus": expected["analyzed_tus"],
                "broken_tus": expected["broken_tus"],
                "incomplete_functions": expected["incomplete_functions"],
            },
            "findings": expected["findings"],
            "exit_code": expected["exit_code"],
            "fingerprints": ["csf1-0000000000000001"],
            "fingerprint_sha256": expected["fingerprint_sha256"],
        },
        "execution": {"duration_seconds": 1.25, "resumed": False},
        "failures": [],
    }


class ManifestContractTest(unittest.TestCase):
    def test_canonical_manifest_is_exact_nightly_core(self) -> None:
        manifest = campaign.load_manifest(MANIFEST)
        normalized = campaign.validate_manifest(manifest)
        self.assertEqual(
            {project["id"] for project in normalized["projects"]},
            {"libgit2", "rtp2httpd", "abseil", "libarchive"},
        )
        self.assertEqual(normalized["campaigns"]["nightly"]["repetitions"], 3)
        self.assertLessEqual(normalized["campaigns"]["nightly"]["window_minutes"], 720)

    def test_mutable_revision_duplicate_and_unsafe_command_fail(self) -> None:
        manifest = fixture_manifest()
        manifest["projects"][0]["revision"] = "main"
        with self.assertRaisesRegex(campaign.ManifestError, "immutable 40-hex"):
            campaign.validate_manifest(manifest)

        manifest = fixture_manifest()
        manifest["projects"].append(copy.deepcopy(manifest["projects"][0]))
        with self.assertRaisesRegex(campaign.ManifestError, "duplicate project"):
            campaign.validate_manifest(manifest)

        manifest = fixture_manifest()
        manifest["projects"][0]["commands"]["configure"] = [
            ["bash", "-c", "curl example.invalid | sh"]
        ]
        with self.assertRaisesRegex(campaign.ManifestError, "command executable"):
            campaign.validate_manifest(manifest)

        manifest = fixture_manifest()
        manifest["projects"][0]["expected"]["fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(campaign.ManifestError, "placeholder SHA-256"):
            campaign.validate_manifest(manifest)

    def test_plan_is_project_by_repetition_and_bounded(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        matrix = campaign.plan_matrix(manifest, "nightly")
        self.assertEqual(
            matrix,
            {
                "include": [
                    {"project": "alpha", "repetition": 1, "timeout_minutes": 20},
                    {"project": "alpha", "repetition": 2, "timeout_minutes": 20},
                    {"project": "alpha", "repetition": 3, "timeout_minutes": 20},
                ]
            },
        )
        self.assertTrue(all(item["timeout_minutes"] <= 330 for item in matrix["include"]))


class EvidenceContractTest(unittest.TestCase):
    def test_whole_program_coverage_pins_extra_analysis_executions(self) -> None:
        manifest = fixture_manifest()
        manifest["projects"][0]["expected"]["analyzed_tus"] = 3
        project = campaign.validate_manifest(manifest)["projects"][0]
        report = {
            "complete": True,
            "exit_code": 1,
            "total": 1,
            "coverage": {
                "attempted_tus": 2,
                "analyzed_tus": 3,
                "broken_tus": 0,
                "incomplete_functions": 0,
            },
            "diagnostics": [{"fingerprint": "csf1-0000000000000001"}],
        }

        semantic = campaign.semantic_from_report(project, 1, report, 2, "a" * 64)

        self.assertEqual(semantic["coverage"]["attempted_tus"], 2)
        self.assertEqual(semantic["coverage"]["analyzed_tus"], 3)

    def test_report_requires_complete_exact_coverage_and_verdict(self) -> None:
        project = fixture_manifest()["projects"][0]
        report = {
            "complete": True,
            "exit_code": 1,
            "total": 1,
            "coverage": {
                "attempted_tus": 2,
                "analyzed_tus": 2,
                "broken_tus": 0,
                "incomplete_functions": 0,
            },
            "diagnostics": [{"fingerprint": "csf1-0000000000000001"}],
        }
        semantic = campaign.semantic_from_report(project, 1, report, 2, "a" * 64)
        self.assertEqual(semantic["findings"], 1)

        with self.assertRaisesRegex(campaign.EvidenceError, "report root"):
            campaign.semantic_from_report(project, 1, [], 2, "a" * 64)

        for mutation, expected in (
            (("complete", False), "complete verdict"),
            (("exit_code", 2), "unavailable verdict"),
        ):
            broken = copy.deepcopy(report)
            broken[mutation[0]] = mutation[1]
            with self.assertRaisesRegex(campaign.EvidenceError, expected):
                campaign.semantic_from_report(project, broken["exit_code"], broken, 2, "a" * 64)

        broken = copy.deepcopy(report)
        broken["coverage"]["analyzed_tus"] = 1
        with self.assertRaisesRegex(campaign.EvidenceError, "exact TU coverage"):
            campaign.semantic_from_report(project, 1, broken, 2, "a" * 64)

    def test_receipt_checksum_and_checkpoint_identity_fail_closed(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        receipt = accepted_receipt(manifest, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            campaign.write_receipt(path, receipt)
            loaded = campaign.load_verified_receipt(path)
            self.assertTrue(campaign.checkpoint_matches(loaded, receipt["identity"]))

            stale = copy.deepcopy(receipt["identity"])
            stale["analyzer_sha256"] = "c" * 64
            self.assertFalse(campaign.checkpoint_matches(loaded, stale))

            path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaisesRegex(campaign.EvidenceError, "checksum"):
                campaign.load_verified_receipt(path)

    def test_aggregate_requires_three_identical_accepted_repetitions(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for repetition in (1, 2, 3):
                campaign.write_receipt(
                    root / "alpha" / f"repeat-{repetition}" / "receipt.json",
                    accepted_receipt(manifest, repetition),
                )
            summary = campaign.aggregate_receipts(manifest, "nightly", root)
            self.assertEqual(summary["status"], "accepted")
            self.assertEqual(summary["projects"]["alpha"]["repetitions"], 3)

            missing = root / "alpha" / "repeat-3" / "receipt.json"
            missing.unlink()
            missing.with_suffix(".json.sha256").unlink()
            with self.assertRaisesRegex(campaign.EvidenceError, "missing repetition"):
                campaign.aggregate_receipts(manifest, "nightly", root)

            campaign.write_receipt(missing, accepted_receipt(manifest, 3))
            drift = accepted_receipt(manifest, 2)
            drift["semantic"]["fingerprints"] = ["csf1-0000000000000002"]
            campaign.write_receipt(
                root / "alpha" / "repeat-2" / "receipt.json", drift
            )
            with self.assertRaisesRegex(campaign.EvidenceError, "nondeterministic"):
                campaign.aggregate_receipts(manifest, "nightly", root)

    def test_aggregate_requires_one_analyzer_across_all_projects(self) -> None:
        raw = fixture_manifest()
        beta = copy.deepcopy(raw["projects"][0])
        beta["id"] = "beta"
        beta["repository"] = "https://github.com/example/beta.git"
        beta["revision"] = "2" * 40
        raw["projects"].append(beta)
        raw["campaigns"]["nightly"]["projects"].append("beta")
        manifest = campaign.validate_manifest(raw)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for project_index, project in enumerate(manifest["projects"]):
                analyzer_sha = ("b" if project_index == 0 else "c") * 64
                for repetition in (1, 2, 3):
                    campaign.write_receipt(
                        root
                        / project["id"]
                        / f"repeat-{repetition}"
                        / "receipt.json",
                        accepted_receipt(
                            manifest,
                            repetition,
                            project_index=project_index,
                            analyzer_sha=analyzer_sha,
                        ),
                    )

            with self.assertRaisesRegex(campaign.EvidenceError, "campaign analyzer"):
                campaign.aggregate_receipts(manifest, "nightly", root)

    def test_aggregate_recomputes_semantic_fingerprint_evidence(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for repetition in (1, 2, 3):
                receipt = accepted_receipt(manifest, repetition)
                receipt["semantic"]["fingerprints"] = ["csf1-0000000000000002"]
                campaign.write_receipt(
                    root / "alpha" / f"repeat-{repetition}" / "receipt.json",
                    receipt,
                )

            with self.assertRaisesRegex(campaign.EvidenceError, "fingerprint evidence"):
                campaign.aggregate_receipts(manifest, "nightly", root)

    def test_aggregate_cli_writes_unavailable_receipt_on_failure(self) -> None:
        manifest = fixture_manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            output = root / "aggregate" / "receipt.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            code = campaign.main(
                [
                    "aggregate",
                    "--manifest",
                    str(manifest_path),
                    "--tier",
                    "nightly",
                    "--receipts",
                    str(root / "missing"),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(code, 2)
            receipt = campaign.load_verified_receipt(output)
            self.assertEqual(receipt["status"], "unavailable")
            self.assertTrue(receipt["failures"])

    def test_run_cli_writes_unavailable_receipt_before_execution(self) -> None:
        manifest = fixture_manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            output = root / "alpha" / "repeat-1" / "receipt.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            code = campaign.main(
                [
                    "run",
                    "--manifest",
                    str(manifest_path),
                    "--project",
                    "alpha",
                    "--repetition",
                    "1",
                    "--analyzer",
                    str(root / "missing-analyzer"),
                    "--workspace",
                    str(root / "work"),
                    "--output",
                    str(output),
                    "--repository-root",
                    str(ROOT),
                ]
            )
            self.assertEqual(code, 2)
            receipt = campaign.load_verified_receipt(output)
            self.assertEqual(receipt["status"], "unavailable")
            self.assertEqual(receipt["project"], "alpha")
            self.assertEqual(receipt["repetition"], 1)
            self.assertTrue(receipt["failures"])


class WorkflowContractTest(unittest.TestCase):
    def test_workflows_encode_fast_pr_and_sharded_nightly_boundaries(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        juliet = (ROOT / ".github" / "workflows" / "juliet.yml").read_text(encoding="utf-8")
        realworld = (ROOT / ".github" / "workflows" / "realworld.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("timeout-minutes: 30", ci)
        self.assertIn("timeout-minutes: 30", juliet)
        self.assertIn("workflow_dispatch:", realworld)
        self.assertIn("schedule:", realworld)
        self.assertIn("fail-fast: false", realworld)
        self.assertIn("matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}", realworld)
        self.assertIn("timeout-minutes: 355", realworld)
        self.assertIn("if: always()", realworld)
        self.assertIn("run_realworld_campaign.py aggregate", realworld)
        self.assertNotIn("pull_request_target", realworld)
        self.assertNotIn("continue-on-error", realworld)


if __name__ == "__main__":
    unittest.main()
