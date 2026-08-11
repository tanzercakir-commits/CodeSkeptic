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
        shadps4_configure = projects["shadps4"]["commands"]["configure"][0]
        self.assertIn("-DCMAKE_C_COMPILER=clang-19", shadps4_configure)
        self.assertIn("-DCMAKE_CXX_COMPILER=clang++-19", shadps4_configure)
        self.assertIn(
            "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON", shadps4_configure
        )
        self.assertIn("-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=mold", shadps4_configure)
        self.assertIn("-DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=mold", shadps4_configure)
        self.assertFalse(any("-stdlib=libc++" in arg for arg in shadps4_configure))
        self.assertNotIn("-DENABLE_DISCORD_RPC=OFF", shadps4_configure)
        self.assertNotIn("-DENABLE_UPDATER=OFF", shadps4_configure)
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

    def test_target_commands_exclude_configured_non_target_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            build = root / "build"
            production = source / "src" / "production.cc"
            configured_only = source / "src" / "configured_only.cc"
            dependency = source / "third_party" / "dependency.cc"
            external = root / "external.cc"
            files = [configured_only, production]
            relative_files = [
                "src/configured_only.cc",
                "src/production.cc",
            ]
            commands = (
                f"clang++ -c {production.as_posix()} -o production.cc.o\n"
                f"clang++ -c {dependency.as_posix()} -o dependency.cc.o\n"
                "ar qc libproduction.a production.cc.o dependency.cc.o\n"
            )
            selected, relative = qualification.filter_target_translation_units(
                commands, source, build, files, relative_files
            )
            self.assertEqual(selected, [production])
            self.assertEqual(relative, ["src/production.cc"])

            scan_deps_commands = (
                '"/usr/bin/clang-scan-deps-19" -format=p1689 -- '
                f"clang++ {production.as_posix()} -c -o production.cc.o\n"
            )
            selected, relative = qualification.filter_target_translation_units(
                scan_deps_commands, source, build, files, relative_files
            )
            self.assertEqual(selected, [production])
            self.assertEqual(relative, ["src/production.cc"])

            with self.assertRaisesRegex(campaign.EvidenceError, "target closure"):
                qualification.filter_target_translation_units(
                    "clang++ -c malformed.cc -o malformed.cc.o\n",
                    source,
                    build,
                    files,
                    relative_files,
                )

            with self.assertRaisesRegex(campaign.EvidenceError, "source tree"):
                qualification.filter_target_translation_units(
                    f"clang++ -c {external.as_posix()} -o external.cc.o\n",
                    source,
                    build,
                    [external],
                    ["../external.cc"],
                )

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
        self.assertIn(
            "clang-19 clang-tools-19 clang-20 cmake ninja-build mold build-essential",
            workflow,
        )
        self.assertIn("libpulse-dev libopenal-dev", workflow)
        self.assertNotIn("libc++", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("continue-on-error", workflow)


if __name__ == "__main__":
    unittest.main()
