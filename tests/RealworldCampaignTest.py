#!/usr/bin/env python3
"""Contracts for the deterministic real-repository campaign factory."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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
        "execution": {
            "duration_seconds": 1.25,
            "resumed": False,
            "translation_unit_plan": {
                "count": expected["translation_units"],
                "sha256": "d" * 64,
                "executed": expected["translation_units"],
                "checkpoint": 0,
            },
        },
        "failures": [],
    }


def translation_unit_receipts(count: int) -> list[dict]:
    return [
        {
            "path": f"/tmp/unit-{index}.c",
            "compile_command_sha256": f"{index + 1:064x}",
            "command_ordinal": 0,
            "phase": "analysis",
            "status": "completed",
            "duration_ms": 10,
            "peak_memory_kib": 1024,
            "timeout_seconds": 30,
            "memory_mib": 4096,
            "origin": "executed",
            "checkpoint_key_sha256": "",
            "payload_sha256": "",
        }
        for index in range(count)
    ]


class ManifestContractTest(unittest.TestCase):
    def test_canonical_manifest_is_exact_three_tier_factory(self) -> None:
        manifest = campaign.load_manifest(MANIFEST)
        normalized = campaign.validate_manifest(manifest)
        self.assertEqual(
            {project["id"] for project in normalized["projects"]},
            {
                "libgit2",
                "rtp2httpd",
                "abseil",
                "libarchive",
                "systemd",
                "curl",
                "redis",
                "lvgl",
                "llama-cpp",
                "tensorflow-lite",
                "shadps4",
            },
        )
        self.assertEqual(
            normalized["campaigns"]["nightly"]["projects"],
            ["libgit2", "rtp2httpd", "abseil", "libarchive"],
        )
        self.assertEqual(
            normalized["campaigns"]["weekend"]["projects"],
            ["systemd", "curl", "redis", "lvgl"],
        )
        self.assertEqual(
            normalized["campaigns"]["release-candidate"]["projects"],
            ["llama-cpp", "tensorflow-lite", "shadps4"],
        )
        self.assertEqual(
            normalized["campaigns"]["release-candidate"]["repetitions"], 3
        )
        self.assertEqual(
            normalized["campaigns"]["release-candidate"]["window_minutes"], 4320
        )
        self.assertEqual(normalized["campaigns"]["nightly"]["repetitions"], 3)
        self.assertLessEqual(normalized["campaigns"]["nightly"]["window_minutes"], 720)
        self.assertEqual(normalized["campaigns"]["weekend"]["repetitions"], 3)
        self.assertEqual(normalized["campaigns"]["weekend"]["window_minutes"], 2880)
        self.assertEqual(
            {
                project["id"]: (
                    project["revision"],
                    project["expected"]["translation_units"],
                    project["expected"]["translation_unit_sha256"],
                )
                for project in normalized["projects"]
                if project["id"] in {"systemd", "curl", "redis", "lvgl"}
            },
            {
                "systemd": (
                    "009adf6c0e435376c80fbc11675d581e0a94d350",
                    390,
                    "5a65361ff67a6bc1dca48d0da5aee60ead0f1a061084492684e2c1cb7313823c",
                ),
                "curl": (
                    "b1ef0e1a01c0bb6ee5367bd9c186a603bde3615a",
                    169,
                    "213f0c1cb75de379b16ade4d0ab7cc8e701ced13a51fc822060db1f95ec92a01",
                ),
                "redis": (
                    "a0a6f23d997b024689ba157916837f493a593a34",
                    103,
                    "289cde3a18f71ccdcf3fd3b317a232e57514c14690b8d67f8551af261bcff844",
                ),
                "lvgl": (
                    "7f07a129e8d77f4984fff8e623fd5be18ff42e74",
                    311,
                    "30a090f5cdffb81f3b2184b5cd537d4ac85fff23acf3cdccecdb9ec13af00e50",
                ),
            },
        )
        self.assertEqual(
            {
                project["id"]: (
                    project["expected"]["attempted_tus"],
                    project["expected"]["analyzed_tus"],
                    project["expected"]["broken_tus"],
                    project["expected"]["incomplete_functions"],
                    project["expected"]["findings"],
                    project["expected"]["exit_code"],
                    project["expected"]["fingerprint_sha256"],
                )
                for project in normalized["projects"]
                if project["id"] in {"systemd", "curl", "redis", "lvgl"}
            },
            {
                "systemd": (
                    390,
                    815,
                    0,
                    0,
                    0,
                    0,
                    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                ),
                "curl": (
                    169,
                    169,
                    0,
                    0,
                    59,
                    1,
                    "195b80888b1e4e788c67f4e6024f31e667767e50d66d3fc3d483e619b424f094",
                ),
                "redis": (
                    103,
                    206,
                    0,
                    0,
                    0,
                    0,
                    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                ),
                "lvgl": (
                    311,
                    311,
                    0,
                    0,
                    16,
                    1,
                    "687bfeaa19046230afd60e116bb0d2fe73361d8b931161e33029bd79988ae808",
                ),
            },
        )

    def test_release_candidate_profiles_and_submodule_identity_are_pinned(self) -> None:
        normalized = campaign.load_manifest(MANIFEST)
        candidate_document = json.loads(
            (ROOT / "scripts" / "phase83_candidates.json").read_text(encoding="utf-8")
        )
        candidates = {
            project["id"]: project for project in candidate_document["projects"]
        }
        promoted = {
            project["id"]: project
            for project in normalized["projects"]
            if project["id"] in {"llama-cpp", "tensorflow-lite", "shadps4"}
        }
        self.assertEqual(set(promoted), set(candidates))
        for project_id, project in promoted.items():
            for field in (
                "id",
                "label",
                "repository",
                "revision",
                "compile_database",
                "sources",
                "commands",
                "analyzer_args",
                "timeout_minutes",
                "memory_mb",
            ):
                self.assertEqual(project[field], candidates[project_id][field])

        expected_profiles = {
          "llama-cpp": {
            "revision": "4dee52f82dc455a035e900fed6a40cb45cd7a454",
            "checkout": {
              "submodules": "none",
              "expected_count": 0,
              "expected_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
            },
            "translation_units": 200,
            "attempted_tus": 200,
            "analyzed_tus": 200,
            "findings": 40,
            "translation_unit_sha256": "e9ea7d634287ae942ce5c9b0b0cf5e1595114f60b13e8e7e431fff410ccf8783",
            "fingerprint_sha256": "842c6903f3d506cff9b5a5723de8dc10701b294c12ce59be032f368d3eacc4b4"
          },
          "tensorflow-lite": {
            "revision": "a481b10260dfdf833a1b16007eead49c1d7febf3",
            "checkout": {
              "submodules": "none",
              "expected_count": 0,
              "expected_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
            },
            "translation_units": 241,
            "attempted_tus": 241,
            "analyzed_tus": 245,
            "findings": 73,
            "translation_unit_sha256": "2dd69e73c882f6a3ea17a63349500db7d350eb1d3aaa5a8a47f06a716f5fed5f",
            "fingerprint_sha256": "6cf30f16db0a5eb2537e6178a30087a0385b7dfdb1ff5f61d9bb2815a765a81a"
          },
          "shadps4": {
            "revision": "5a4373c80e32c7a9d5d6e5a0b7d31d371d194caa",
            "checkout": {
              "submodules": "recursive",
              "expected_count": 53,
              "expected_sha256": "9f779c183535a2af8148a3b7bfc69b4733cf947d036d98b49e740dbe7ea7c54c"
            },
            "translation_units": 382,
            "attempted_tus": 382,
            "analyzed_tus": 382,
            "findings": 66,
            "translation_unit_sha256": "890628723d3db1645429d4fc2f134ecbdac32cd8e322e8dddf09f0d8835c24e9",
            "fingerprint_sha256": "0b14abf3eb69012ee95678b7a3c4198bd440a761757df8cbad482374d767fd74"
          }
        }
        actual_profiles = {
            project_id: {
                "revision": project["revision"],
                "checkout": project["checkout"],
                "translation_units": project["expected"]["translation_units"],
                "attempted_tus": project["expected"]["attempted_tus"],
                "analyzed_tus": project["expected"]["analyzed_tus"],
                "findings": project["expected"]["findings"],
                "translation_unit_sha256": project["expected"][
                    "translation_unit_sha256"
                ],
                "fingerprint_sha256": project["expected"]["fingerprint_sha256"],
            }
            for project_id, project in promoted.items()
        }
        self.assertEqual(actual_profiles, expected_profiles)

        shad = promoted["shadps4"]
        identity = campaign.receipt_identity(
            normalized,
            shad,
            1,
            "a" * 64,
            shad["expected"]["translation_unit_sha256"],
        )
        self.assertEqual(identity["submodules"], {
            "mode": "recursive",
            "count": 53,
            "sha256": "9f779c183535a2af8148a3b7bfc69b4733cf947d036d98b49e740dbe7ea7c54c",
        })

        revision = "1" * 40
        self.assertEqual(
            campaign._parse_submodule_status(
                f" {revision} dependencies/example (heads/main)"
            ),
            [{"path": "dependencies/example", "revision": revision}],
        )
        for bad in (
            "",
            f"-{revision} dependencies/example",
            f"+{revision} dependencies/example",
            f"U{revision} dependencies/example",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(campaign.EvidenceError):
                    campaign._parse_submodule_status(bad)

        raw = fixture_manifest()
        raw["projects"][0]["checkout"] = {
            "submodules": "recursive",
            "expected_count": 0,
            "expected_sha256": "1" * 64,
        }
        with self.assertRaises(campaign.ManifestError):
            campaign.validate_manifest(raw)

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

    def test_weekend_window_is_between_36_and_48_hours(self) -> None:
        manifest = fixture_manifest()
        manifest["campaigns"]["weekend"] = {
            "window_minutes": 2159,
            "repetitions": 3,
            "projects": ["alpha"],
        }
        with self.assertRaisesRegex(campaign.ManifestError, "weekend campaign window"):
            campaign.validate_manifest(manifest)

        manifest["campaigns"]["weekend"]["window_minutes"] = 2881
        with self.assertRaisesRegex(campaign.ManifestError, "weekend campaign window"):
            campaign.validate_manifest(manifest)

        manifest["campaigns"]["weekend"]["window_minutes"] = 2880
        campaign.validate_manifest(manifest)

    def test_meson_and_bear_adapters_are_strictly_shaped(self) -> None:
        manifest = fixture_manifest()
        project = manifest["projects"][0]
        project["commands"] = {
            "configure": [
                [
                    "meson",
                    "setup",
                    "{build}",
                    "{source}",
                    "--buildtype=release",
                ]
            ],
            "build": [["meson", "compile", "-C", "{build}", "app:executable"]],
        }
        campaign.validate_manifest(manifest)

        project["commands"]["configure"] = [["meson", "introspect", "{build}"]]
        with self.assertRaisesRegex(campaign.ManifestError, "meson configure shape"):
            campaign.validate_manifest(manifest)

        project["commands"] = {
            "configure": [["meson", "setup", "{build}", "{source}"]],
            "build": [["meson", "compile", "-C", "{build}", "--clean"]],
        }
        with self.assertRaisesRegex(campaign.ManifestError, "meson build shape"):
            campaign.validate_manifest(manifest)

        manifest = fixture_manifest()
        project = manifest["projects"][0]
        project["commands"]["build"] = [
            [
                "bear",
                "--output",
                "{build}/compile_commands.json",
                "--",
                "make",
                "-C",
                "{source}",
                "-j{jobs}",
                "CC=clang-20",
                "MALLOC=libc",
                "CFLAGS=-resource-dir=/opt/llvm/lib/clang/19",
            ]
        ]
        campaign.validate_manifest(manifest)

        project["commands"]["build"] = [
            [
                "bear",
                "--output",
                "{build}/compile_commands.json",
                "--",
                "make",
                "-f",
                "Injected.mk",
            ]
        ]
        with self.assertRaisesRegex(campaign.ManifestError, "bear build shape"):
            campaign.validate_manifest(manifest)

    def test_build_environment_is_validated_and_recipe_bound(self) -> None:
        baseline = campaign.validate_manifest(fixture_manifest())
        baseline_digest = campaign.digest_json(baseline)
        baseline_recipe = campaign.digest_json(
            campaign.project_recipe(baseline["projects"][0])
        )
        self.assertNotIn("environment", baseline["projects"][0])
        self.assertEqual(
            baseline_digest,
            "e2d962d0cad32776eef3a4da72da4a4f3ca3e00dcabd2d3b6ceb7977fe6e878c",
        )
        self.assertEqual(
            baseline_recipe,
            "00518a68774f47b7787e494ec78af1e6b75c85cd9e69958648f72b66d2c93e55",
        )

        manifest = fixture_manifest()
        project = manifest["projects"][0]
        project["environment"] = {
            "CXX": "/usr/bin/clang++-19",
            "CC": "/usr/bin/clang-19",
        }
        normalized = campaign.validate_manifest(manifest)
        normalized_project = normalized["projects"][0]
        self.assertEqual(
            normalized_project["environment"],
            {"CC": "/usr/bin/clang-19", "CXX": "/usr/bin/clang++-19"},
        )
        self.assertEqual(
            campaign.project_recipe(normalized_project)["environment"],
            normalized_project["environment"],
        )
        self.assertNotEqual(campaign.digest_json(normalized), baseline_digest)
        self.assertNotEqual(
            campaign.digest_json(campaign.project_recipe(normalized_project)),
            baseline_recipe,
        )

        without_environment = campaign.validate_manifest(fixture_manifest())
        self.assertEqual(campaign.digest_json(without_environment), baseline_digest)
        self.assertEqual(
            campaign.digest_json(
                campaign.project_recipe(without_environment["projects"][0])
            ),
            baseline_recipe,
        )

        for invalid in (
            {"LD_PRELOAD": "/usr/lib/example.so"},
            {"CC": "clang-19"},
            {"CC": "/usr/bin/clang-19\nextra"},
        ):
            changed = fixture_manifest()
            changed["projects"][0]["environment"] = invalid
            with self.assertRaisesRegex(campaign.ManifestError, "environment"):
                campaign.validate_manifest(changed)


class EvidenceContractTest(unittest.TestCase):
    def test_multi_command_coverage_pins_extra_analysis_executions(self) -> None:
        manifest = fixture_manifest()
        manifest["projects"][0]["expected"]["analyzed_tus"] = 3
        project = campaign.validate_manifest(manifest)["projects"][0]
        receipts = translation_unit_receipts(3)
        receipts[2]["path"] = receipts[0]["path"]
        receipts[2]["command_ordinal"] = 1
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
            "translation_units": receipts,
        }

        semantic = campaign.semantic_from_report(project, 1, report, 2, "a" * 64)

        self.assertEqual(semantic["coverage"]["attempted_tus"], 2)
        self.assertEqual(semantic["coverage"]["analyzed_tus"], 3)

    def test_whole_program_requires_both_exact_phase_sets(self) -> None:
        manifest = fixture_manifest()
        manifest["projects"][0]["analyzer_args"].append("--whole-program")
        project = campaign.validate_manifest(manifest)["projects"][0]
        analysis = translation_unit_receipts(2)
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
            "translation_units": analysis,
        }

        with self.assertRaisesRegex(campaign.EvidenceError, "phases"):
            campaign.semantic_from_report(project, 1, report, 2, "a" * 64)

        harvest = copy.deepcopy(analysis)
        for receipt in harvest:
            receipt["phase"] = "summary-harvest"
        report["translation_units"] = harvest + analysis
        semantic = campaign.semantic_from_report(
            project, 1, report, 2, "a" * 64
        )
        self.assertEqual(semantic["coverage"]["analyzed_tus"], 2)

    def test_plan_requires_every_requested_path_with_multi_command_units(self) -> None:
        receipts = translation_unit_receipts(2)
        receipts[1]["path"] = receipts[0]["path"]
        receipts[1]["command_ordinal"] = 1
        report = {"translation_units": receipts}

        with self.assertRaisesRegex(campaign.EvidenceError, "path omission"):
            campaign.translation_unit_plan(
                report,
                2,
                2,
                [Path("/tmp/unit-0.c"), Path("/tmp/unit-1.c")],
            )

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
            "translation_units": translation_unit_receipts(2),
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

        duplicate = copy.deepcopy(report)
        duplicate["translation_units"][1] = copy.deepcopy(
            duplicate["translation_units"][0]
        )
        with self.assertRaisesRegex(campaign.EvidenceError, "duplicate"):
            campaign.semantic_from_report(
                project, 1, duplicate, 2, "a" * 64
            )

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

    def test_receipt_staging_and_read_symlinks_fail_without_escape(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        receipt = accepted_receipt(manifest, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "receipt.json"
            outside = root / "outside.txt"
            outside.write_text("sentinel\n", encoding="utf-8")
            (root / ".receipt.json.tmp").symlink_to(outside)

            with self.assertRaisesRegex(campaign.EvidenceError, "staging"):
                campaign.write_receipt(path, receipt)
            self.assertEqual(outside.read_text(encoding="utf-8"), "sentinel\n")

            (root / ".receipt.json.tmp").unlink()
            campaign.write_receipt(path, receipt)
            real_receipt = root / "real-receipt.json"
            path.replace(real_receipt)
            path.symlink_to(real_receipt)
            with self.assertRaisesRegex(campaign.EvidenceError, "regular"):
                campaign.load_verified_receipt(path)

    def test_explicit_checkpoint_mismatch_and_partial_pair_fail_closed(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        receipt = accepted_receipt(manifest, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "checkpoint" / "receipt.json"
            self.assertIsNone(
                campaign.load_matching_checkpoint(
                    path, receipt["identity"], manifest["projects"][0]
                )
            )

            campaign.write_receipt(path, receipt)
            stale = copy.deepcopy(receipt["identity"])
            stale["analyzer_sha256"] = "c" * 64
            with self.assertRaisesRegex(campaign.EvidenceError, "incompatible"):
                campaign.load_matching_checkpoint(
                    path, stale, manifest["projects"][0]
                )

            path.with_suffix(".json.sha256").unlink()
            self.assertIsNone(campaign.load_matching_checkpoint(
                path, receipt["identity"], manifest["projects"][0]
            ))
            self.assertFalse(path.exists())

            campaign.write_receipt(path, receipt)
            path.unlink()
            sidecar = path.with_suffix(".json.sha256")
            self.assertTrue(sidecar.is_file())
            self.assertIsNone(campaign.load_matching_checkpoint(
                path, receipt["identity"], manifest["projects"][0]
            ))
            self.assertFalse(sidecar.exists())

            for mutation, expected in (
                (("project", "forged"), "shard identity"),
                (("repetition", 2), "shard identity"),
            ):
                malformed = copy.deepcopy(receipt)
                malformed[mutation[0]] = mutation[1]
                campaign.write_receipt(path, malformed)
                with self.assertRaisesRegex(campaign.EvidenceError, expected):
                    campaign.load_matching_checkpoint(
                        path, receipt["identity"], manifest["projects"][0]
                    )

            malformed = copy.deepcopy(receipt)
            malformed["execution"]["duration_seconds"] = "fast"
            campaign.write_receipt(path, malformed)
            with self.assertRaisesRegex(campaign.EvidenceError, "execution"):
                campaign.load_matching_checkpoint(
                    path, receipt["identity"], manifest["projects"][0]
                )

            malformed = copy.deepcopy(receipt)
            malformed["execution"]["translation_unit_plan"]["count"] += 1
            malformed["execution"]["translation_unit_plan"]["executed"] += 1
            campaign.write_receipt(path, malformed)
            with self.assertRaisesRegex(campaign.EvidenceError, "inconsistent"):
                campaign.load_matching_checkpoint(
                    path, receipt["identity"], manifest["projects"][0]
                )

    def test_analyzer_checkpoint_directory_is_stable_and_parent_scoped(self) -> None:
        checkpoint = Path("root/project/repeat-1/receipt.json")
        self.assertEqual(
            campaign.analyzer_checkpoint_arguments(checkpoint),
            ["--checkpoint-dir",
             str(checkpoint.parent / "unit-evidence")],
        )
        self.assertEqual(campaign.analyzer_checkpoint_arguments(None), [])

    def test_accepted_shard_receipt_revalidates_current_execution_plan(self) -> None:
        raw_manifest = fixture_manifest()
        relative_files = ["src/a.c", "src/b.c"]
        raw_manifest["projects"][0]["expected"]["translation_unit_sha256"] = (
            campaign.translation_unit_digest(relative_files)
        )
        manifest = campaign.validate_manifest(raw_manifest)
        project = manifest["projects"][0]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyzer = root / "codeskeptic"
            analyzer.write_bytes(b"fixture analyzer")
            analyzer = analyzer.resolve()
            analyzer_sha = campaign.file_digest(analyzer)
            checkpoint = root / "checkpoint" / "receipt.json"
            prior = accepted_receipt(manifest, 1, analyzer_sha=analyzer_sha)
            campaign.write_receipt(checkpoint, prior)
            output = root / "output" / "receipt.json"
            files = [root / "work" / "alpha" / path for path in relative_files]
            analyzer_invocations: list[list[str]] = []

            def fake_command(command, cwd, deadline, memory_mb, log_path, env=None):
                del cwd, deadline, memory_mb, log_path, env
                if command and command[0] == str(analyzer):
                    analyzer_invocations.append(command)
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
                        "diagnostics": [
                            {"fingerprint": "csf1-0000000000000001"}
                        ],
                        "translation_units": translation_unit_receipts(2),
                    }
                    for index, receipt in enumerate(report["translation_units"]):
                        receipt["path"] = str(files[index])
                        receipt["origin"] = "checkpoint" if index == 0 else "executed"
                        receipt["checkpoint_key_sha256"] = f"{index + 3:064x}"
                        receipt["payload_sha256"] = f"{index + 5:064x}"
                    report_path = Path(command[command.index("--json") + 1])
                    report_path.write_text(json.dumps(report), encoding="utf-8")
                    return subprocess.CompletedProcess(command, 1)
                return subprocess.CompletedProcess(command, 0)

            revision_result = subprocess.CompletedProcess(
                ["git", "rev-parse", "HEAD"], 0, stdout=project["revision"] + "\n"
            )
            with (
                mock.patch.object(campaign, "_run_command", side_effect=fake_command),
                mock.patch.object(
                    campaign.subprocess, "run", return_value=revision_result
                ),
                mock.patch.object(
                    campaign,
                    "_derive_translation_units",
                    return_value=(files, relative_files),
                ),
                mock.patch.object(
                    campaign,
                    "_submodule_identity",
                    return_value=campaign._expected_submodules(project),
                ),
            ):
                code = campaign.run_shard(
                    manifest,
                    "alpha",
                    1,
                    analyzer,
                    root / "work",
                    output,
                    checkpoint,
                    ROOT,
                )

            self.assertEqual(code, 0)
            self.assertEqual(len(analyzer_invocations), 1)
            receipt = campaign.load_verified_receipt(output)
            self.assertNotEqual(
                receipt["execution"]["translation_unit_plan"]["sha256"],
                prior["execution"]["translation_unit_plan"]["sha256"],
            )
            self.assertEqual(
                receipt["execution"]["translation_unit_plan"]["checkpoint"], 1
            )
            self.assertTrue(receipt["execution"]["resumed"])

    def test_legacy_execution_plan_exception_is_explicit_and_uniform(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        receipts = [accepted_receipt(manifest, repetition) for repetition in (1, 2, 3)]
        for receipt in receipts:
            del receipt["execution"]["translation_unit_plan"]

        with self.assertRaisesRegex(campaign.EvidenceError, "execution evidence"):
            campaign.validate_receipt_group(
                manifest, "nightly", "alpha", receipts
            )
        summary = campaign.validate_receipt_group(
            manifest,
            "nightly",
            "alpha",
            receipts,
            require_execution_plan=False,
        )
        self.assertEqual(summary["repetitions"], 3)

        receipts[1] = accepted_receipt(manifest, 2)
        with self.assertRaisesRegex(campaign.EvidenceError, "execution schemas"):
            campaign.validate_receipt_group(
                manifest,
                "nightly",
                "alpha",
                receipts,
                require_execution_plan=False,
            )

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

            malformed_plan = accepted_receipt(manifest, 2)
            malformed_plan["execution"]["translation_unit_plan"]["count"] += 1
            malformed_plan["execution"]["translation_unit_plan"]["executed"] += 1
            campaign.write_receipt(
                root / "alpha" / "repeat-2" / "receipt.json", malformed_plan
            )
            with self.assertRaisesRegex(campaign.EvidenceError, "inconsistent"):
                campaign.aggregate_receipts(manifest, "nightly", root)

            plan_drift = accepted_receipt(manifest, 2)
            plan_drift["execution"]["translation_unit_plan"]["sha256"] = "e" * 64
            campaign.write_receipt(
                root / "alpha" / "repeat-2" / "receipt.json", plan_drift
            )
            with self.assertRaisesRegex(campaign.EvidenceError, "plans are nondeterministic"):
                campaign.aggregate_receipts(manifest, "nightly", root)

            campaign.write_receipt(
                root / "alpha" / "repeat-2" / "receipt.json",
                accepted_receipt(manifest, 2),
            )

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
        self.assertIn('cron: "17 1 * * *"', realworld)
        self.assertIn("- weekend", realworld)
        self.assertIn('cron: "43 0 * * 0"', realworld)
        self.assertIn("github.event.schedule", realworld)
        for dependency in ("meson", "bear", "gperf", "libcap-dev", "libmount-dev"):
            self.assertIn(dependency, realworld)
        self.assertIn("fail-fast: false", realworld)
        self.assertIn("matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}", realworld)
        self.assertIn("timeout-minutes: 355", realworld)
        self.assertIn("if: always()", realworld)
        self.assertIn("run_realworld_campaign.py aggregate", realworld)
        self.assertNotIn("uses: actions/cache@v4", realworld)
        self.assertIn("uses: actions/cache/restore@v4", realworld)
        self.assertIn("uses: actions/cache/save@v4", realworld)
        self.assertIn("github.run_id", realworld)
        self.assertIn("github.run_attempt", realworld)
        self.assertIn("restore-keys: |", realworld)
        self.assertIn(
            "if: ${{ always() && steps.run-shard.outcome != 'skipped' }}",
            realworld,
        )
        self.assertIn(
            'mkdir -p "realworld-checkpoints/${{ matrix.project }}/repeat-${{ matrix.repetition }}"',
            realworld,
        )
        self.assertNotIn(
            'repeat-${{ matrix.repetition }}/unit-evidence"', realworld
        )
        self.assertLess(
            realworld.index("uses: actions/cache/restore@v4"),
            realworld.index("id: run-shard"),
        )
        self.assertLess(
            realworld.index("id: run-shard"),
            realworld.index("uses: actions/cache/save@v4"),
        )
        self.assertNotIn("pull_request_target", realworld)
        self.assertNotIn("continue-on-error", realworld)


    def test_release_candidate_workflow_selects_llvm19_only_for_that_tier(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "realworld.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("build-analyzer:\n    needs: plan", workflow)
        self.assertIn('needs.plan.outputs.tier }}" = release-candidate', workflow)
        self.assertIn("version=19", workflow)
        self.assertIn("version=20", workflow)
        self.assertIn("compiler_packages=(clang-20)", workflow)
        self.assertIn("compiler_packages+=(clang-19 mold", workflow)
        self.assertIn('"${compiler_packages[@]}" cmake ninja-build', workflow)
        self.assertIn("llvm-${{ steps.llvm.outputs.version }}-dev", workflow)
        self.assertIn("clang-${{ steps.llvm.outputs.version }}", workflow)
        self.assertIn("-DLLVM_DIR=${{ steps.llvm.outputs.root }}/lib/cmake/llvm", workflow)
        self.assertIn("-DClang_DIR=${{ steps.llvm.outputs.root }}/lib/cmake/clang", workflow)


    def test_release_candidate_installs_qualified_linker(self):
        workflow = (ROOT / ".github/workflows/realworld.yml").read_text(
            encoding="utf-8"
        )
        package_lines = [
            line for line in workflow.splitlines() if "clang-19" in line
        ]
        self.assertEqual(len(package_lines), 1)
        packages = package_lines[0].split("(", 1)[1].split(")", 1)[0].split()
        required = {
            "clang-19",
            "clang-tools-19",
            "mold",
            "libasound2-dev",
            "libdecor-0-dev",
            "libgles2-mesa-dev",
            "libglfw3-dev",
            "libopenal-dev",
            "libpulse-dev",
            "libudev-dev",
            "libwayland-dev",
            "libx11-dev",
            "libxcursor-dev",
            "libxext-dev",
            "libxfixes-dev",
            "libxi-dev",
            "libxkbcommon-dev",
            "libxrandr-dev",
            "libxss-dev",
            "libxtst-dev",
        }
        self.assertTrue(required.issubset(packages))


if __name__ == "__main__":
    unittest.main()
