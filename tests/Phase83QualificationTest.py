#!/usr/bin/env python3
"""Contract tests for the observational Phase 8.3 qualification lane."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import phase83_qualification as qualification  # noqa: E402
import run_realworld_campaign as campaign  # noqa: E402


DOCUMENT = SCRIPTS / "phase83_candidates.json"


class CandidateContractTest(unittest.TestCase):
    def test_canonical_document_is_exact_observational_surface(self) -> None:
        document = qualification.validate_candidates(
            qualification._load_document(DOCUMENT)
        )
        self.assertEqual(
            [project["id"] for project in document["projects"]],
            ["llama-cpp", "shadps4", "tensorflow-lite"],
        )
        projects = {project["id"]: project for project in document["projects"]}
        self.assertEqual(
            projects["llama-cpp"]["revision"],
            "4dee52f82dc455a035e900fed6a40cb45cd7a454",
        )
        self.assertEqual(
            projects["shadps4"]["revision"],
            "5a4373c80e32c7a9d5d6e5a0b7d31d371d194caa",
        )
        self.assertEqual(
            projects["tensorflow-lite"]["revision"],
            "a481b10260dfdf833a1b16007eead49c1d7febf3",
        )
        self.assertEqual(projects["shadps4"]["checkout"]["submodules"], "recursive")
        self.assertEqual(projects["tensorflow-lite"]["sources"]["roots"], ["tensorflow/lite"])
        self.assertIn(
            "-DTENSORFLOW_SOURCE_DIR={source}",
            projects["tensorflow-lite"]["commands"]["configure"][0],
        )
        self.assertIn("-DTFLITE_ENABLE_XNNPACK=OFF", projects["tensorflow-lite"]["commands"]["configure"][0])
        self.assertTrue(
            all(project["sources"]["fallback_globs"] == [] for project in projects.values())
        )
        self.assertNotIn("expected", DOCUMENT.read_text(encoding="utf-8"))
        self.assertNotIn("accepted", DOCUMENT.read_text(encoding="utf-8"))

    def test_mutable_inputs_unsafe_commands_and_scope_drift_fail(self) -> None:
        raw = qualification._load_document(DOCUMENT)
        raw["projects"][0]["revision"] = "main"
        with self.assertRaisesRegex(campaign.ManifestError, "immutable 40-hex"):
            qualification.validate_candidates(raw)

        raw = qualification._load_document(DOCUMENT)
        raw["projects"][0]["commands"]["configure"] = [["bash", "-c", "true"]]
        with self.assertRaisesRegex(campaign.ManifestError, "not admitted"):
            qualification.validate_candidates(raw)

        raw = qualification._load_document(DOCUMENT)
        raw["projects"][0]["commands"]["configure"] = [["cmake", "-P", "evil.cmake"]]
        with self.assertRaisesRegex(campaign.ManifestError, "configure shape"):
            qualification.validate_candidates(raw)

        raw = qualification._load_document(DOCUMENT)
        raw["projects"][0]["sources"]["fallback_globs"] = ["src/*.cpp"]
        with self.assertRaisesRegex(campaign.ManifestError, "forbids fallback"):
            qualification.validate_candidates(raw)

        raw = qualification._load_document(DOCUMENT)
        raw["projects"][0]["checkout"]["submodules"] = "recursive"
        with self.assertRaisesRegex(campaign.ManifestError, "only for shadps4"):
            qualification.validate_candidates(raw)

        raw = qualification._load_document(DOCUMENT)
        raw["projects"][2]["commands"]["configure"][0].remove(
            "-DTENSORFLOW_SOURCE_DIR={source}"
        )
        with self.assertRaisesRegex(campaign.ManifestError, "must bind the pinned"):
            qualification.validate_candidates(raw)

        raw = qualification._load_document(DOCUMENT)
        raw["projects"][0]["commands"]["configure"][0].append(
            "-DTENSORFLOW_SOURCE_DIR={source}"
        )
        with self.assertRaisesRegex(campaign.ManifestError, "configure shape"):
            qualification.validate_candidates(raw)

    def test_plan_is_one_bounded_observation_per_candidate(self) -> None:
        document = qualification.validate_candidates(
            qualification._load_document(DOCUMENT)
        )
        matrix = qualification.plan_matrix(document)
        self.assertEqual(
            [row["project"] for row in matrix["include"]],
            ["llama-cpp", "shadps4", "tensorflow-lite"],
        )
        self.assertTrue(
            all(1 <= row["timeout_minutes"] <= 330 for row in matrix["include"])
        )

    def test_submodule_identity_requires_exact_clean_status(self) -> None:
        output = (
            " 1111111111111111111111111111111111111111 externals/a (heads/main)\n"
            " 2222222222222222222222222222222222222222 externals/a/nested\n"
        )
        entries = qualification.parse_submodule_status(output)
        self.assertEqual(entries[0]["path"], "externals/a")
        self.assertEqual(entries[1]["revision"], "2" * 40)
        self.assertEqual(
            campaign.digest_json(entries), campaign.digest_json(copy.deepcopy(entries))
        )
        for prefix in ("-", "+", "U"):
            with self.assertRaisesRegex(campaign.EvidenceError, "uninitialized"):
                qualification.parse_submodule_status(prefix + output[1:])
        with self.assertRaisesRegex(campaign.EvidenceError, "empty"):
            qualification.parse_submodule_status("")

    def test_run_failure_writes_unavailable_receipt_and_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence" / "receipt.json"
            code = qualification.main(
                [
                    "run",
                    "--project",
                    "llama-cpp",
                    "--analyzer",
                    str(root / "missing-analyzer"),
                    "--workspace",
                    str(root / "workspace"),
                    "--output",
                    str(output),
                    "--repository-root",
                    str(ROOT),
                ]
            )
            self.assertEqual(code, 2)
            receipt = campaign.load_verified_receipt(output)
            self.assertEqual(receipt["kind"], "phase83-qualification")
            self.assertEqual(receipt["status"], "unavailable")
            self.assertIsNone(receipt["semantic"])
            self.assertTrue(receipt["failures"])


class WorkflowContractTest(unittest.TestCase):
    def test_workflow_is_branch_bounded_read_only_and_fail_closed(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "phase83-qualification.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("phase-realworld-release-candidate-factory", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("timeout-minutes: 355", workflow)
        self.assertIn("max-parallel: 3", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("phase83_qualification.py run", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("continue-on-error", workflow)


if __name__ == "__main__":
    unittest.main()
