#!/usr/bin/env python3
"""Contracts for the deterministic real-repository campaign factory."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
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
LINUX_SUBREAPER_AVAILABLE = (
    sys.platform.startswith("linux")
    and Path("/proc").is_dir()
    and campaign._enable_subreaper()
)


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
            "timeout_seconds": campaign.DEFAULT_TU_TIMEOUT_SECONDS,
            "memory_mib": 4096,
            "origin": "executed",
            "checkpoint_key_sha256": "",
            "payload_sha256": "",
        }
        for index in range(count)
    ]


def mirror_authority(
    manifest: dict,
    *,
    tree: str = "2" * 40,
    submodules: list[dict] | None = None,
) -> dict:
    project = manifest["projects"][0]
    return {
        "schema": "codeskeptic-realworld-mirror-authority-v1",
        "manifest_sha256": campaign.digest_json(manifest),
        "projects": [
            {
                "id": project["id"],
                "repository": project["repository"],
                "revision": project["revision"],
                "tree": tree,
                "bundle": "bundles/alpha.bundle",
                "bundle_sha256": "0" * 64,
                "submodules": submodules or [],
            }
        ],
    }


def seal_mirror(root: Path, authority: dict, bundles: dict[str, bytes]) -> Path:
    bundle_root = root / "bundles"
    bundle_root.mkdir(parents=True, exist_ok=True)
    for relative, payload in bundles.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        os.chmod(path, 0o444)
    for project in authority["projects"]:
        records = [project, *project["submodules"]]
        for record in records:
            if record["bundle"] in bundles:
                record["bundle_sha256"] = campaign.digest_bytes(
                    bundles[record["bundle"]]
                )
    authority_path = root / "authority.json"
    encoded = campaign.canonical_bytes(authority) + b"\n"
    authority_path.write_bytes(encoded)
    authority_path.with_suffix(".json.sha256").write_text(
        f"{campaign.digest_bytes(encoded)}  authority.json\n",
        encoding="ascii",
    )
    for directory in sorted(
        (path for path in root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        os.chmod(directory, 0o555)
    os.chmod(authority_path, 0o444)
    os.chmod(authority_path.with_suffix(".json.sha256"), 0o444)
    os.chmod(root, 0o555)
    return authority_path


def unseal_mirror(root: Path) -> None:
    if not root.exists():
        return
    os.chmod(root, 0o755)
    for path in root.rglob("*"):
        if path.is_dir():
            os.chmod(path, 0o755)
        elif not path.is_symlink():
            os.chmod(path, 0o644)


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


@unittest.skipUnless(os.name == "posix", "sealed offline mirror requires POSIX")
class MirrorAuthorityContractTest(unittest.TestCase):
    def test_release_candidate_authority_scope_is_exact_and_all_bundles_are_checked(self) -> None:
        raw = fixture_manifest()
        beta = copy.deepcopy(raw["projects"][0])
        beta["id"] = "beta"
        beta["repository"] = "https://github.com/example/beta.git"
        beta["revision"] = "9" * 40
        gamma = copy.deepcopy(beta)
        gamma["id"] = "gamma"
        gamma["repository"] = "https://github.com/example/gamma.git"
        gamma["revision"] = "8" * 40
        raw["projects"].extend([beta, gamma])
        raw["campaigns"]["nightly"]["projects"].append("gamma")
        raw["campaigns"]["release-candidate"] = {
            "window_minutes": 4320,
            "repetitions": 3,
            "projects": ["alpha", "beta"],
        }
        manifest = campaign.validate_manifest(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sealed-mirror"
            authority = mirror_authority(manifest)
            beta_record = copy.deepcopy(authority["projects"][0])
            beta_record.update({
                "id": "beta",
                "repository": beta["repository"],
                "revision": beta["revision"],
                "bundle": "bundles/beta.bundle",
            })
            authority["projects"].append(beta_record)
            authority_path = seal_mirror(
                root,
                authority,
                {
                    "bundles/alpha.bundle": b"alpha bundle\n",
                    "bundles/beta.bundle": b"beta bundle\n",
                },
            )
            try:
                beta_bundle = root / "bundles" / "beta.bundle"
                os.chmod(root / "bundles", 0o755)
                beta_bundle.unlink()
                os.chmod(root / "bundles", 0o555)
                with self.assertRaisesRegex(campaign.EvidenceError, "unavailable"):
                    campaign.load_mirror_authority(
                        authority_path, manifest, "alpha"
                    )
            finally:
                unseal_mirror(root)

        extra = copy.deepcopy(authority)
        gamma_record = copy.deepcopy(extra["projects"][0])
        gamma_record.update({
            "id": "gamma",
            "repository": gamma["repository"],
            "revision": gamma["revision"],
            "bundle": "bundles/gamma.bundle",
        })
        extra["projects"].append(gamma_record)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "extra"
            authority_path = seal_mirror(
                root,
                extra,
                {
                    "bundles/alpha.bundle": b"alpha bundle\n",
                    "bundles/beta.bundle": b"beta bundle\n",
                    "bundles/gamma.bundle": b"gamma bundle\n",
                },
            )
            try:
                with self.assertRaisesRegex(campaign.EvidenceError, "project set"):
                    campaign.load_mirror_authority(
                        authority_path, manifest, "alpha"
                    )
            finally:
                unseal_mirror(root)

        missing = copy.deepcopy(authority)
        missing["projects"] = missing["projects"][:1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "missing"
            authority_path = seal_mirror(
                root, missing, {"bundles/alpha.bundle": b"alpha bundle\n"}
            )
            try:
                with self.assertRaisesRegex(campaign.EvidenceError, "project set"):
                    campaign.load_mirror_authority(
                        authority_path, manifest, "alpha"
                    )
            finally:
                unseal_mirror(root)

    def test_hardlinked_mirror_file_is_rejected(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sealed-mirror"
            authority_path = seal_mirror(
                root,
                mirror_authority(manifest),
                {"bundles/alpha.bundle": b"fixture bundle\n"},
            )
            try:
                os.chmod(root, 0o755)
                os.chmod(root / "bundles", 0o755)
                os.link(root / "bundles" / "alpha.bundle", root / "bundle-alias")
                os.chmod(root / "bundles", 0o555)
                os.chmod(root, 0o555)
                with self.assertRaisesRegex(campaign.EvidenceError, "hard link"):
                    campaign.load_mirror_authority(
                        authority_path, manifest, "alpha"
                    )
            finally:
                unseal_mirror(root)

    def test_selected_offline_mirror_is_canonical_immutable_and_checksummed(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sealed-mirror"
            authority = mirror_authority(manifest)
            authority_path = seal_mirror(
                root, authority, {"bundles/alpha.bundle": b"fixture bundle\n"}
            )
            try:
                selected, selected_root = campaign.load_mirror_authority(
                    authority_path, manifest, "alpha"
                )
                self.assertEqual(selected_root, root)
                self.assertEqual(selected["revision"], "1" * 40)
                self.assertEqual(selected["tree"], "2" * 40)
                self.assertEqual(selected["submodules"], [])
                identity = campaign.receipt_identity(
                    manifest,
                    manifest["projects"][0],
                    1,
                    "b" * 64,
                    manifest["projects"][0]["expected"][
                        "translation_unit_sha256"
                    ],
                )
                self.assertNotIn("mirror", identity)
                self.assertNotIn("transport", identity)
            finally:
                unseal_mirror(root)

    def test_authority_may_seal_a_canonical_manifest_subset_only(self) -> None:
        raw = fixture_manifest()
        beta = copy.deepcopy(raw["projects"][0])
        beta["id"] = "beta"
        beta["repository"] = "https://github.com/example/beta.git"
        beta["revision"] = "9" * 40
        raw["projects"].append(beta)
        raw["campaigns"]["nightly"]["projects"].append("beta")
        manifest = campaign.validate_manifest(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sealed-mirror"
            authority_path = seal_mirror(
                root,
                mirror_authority(manifest),
                {"bundles/alpha.bundle": b"fixture bundle\n"},
            )
            try:
                selected, _ = campaign.load_mirror_authority(
                    authority_path, manifest, "alpha"
                )
                self.assertEqual(selected["id"], "alpha")
                with self.assertRaisesRegex(campaign.EvidenceError, "no project beta"):
                    campaign.load_mirror_authority(
                        authority_path, manifest, "beta"
                    )
            finally:
                unseal_mirror(root)

    def test_offline_mirror_rejects_missing_mismatch_mutability_and_unsafe_paths(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        cases = (
            ("missing", None, "unavailable"),
            ("checksum", b"different bundle\n", "checksum"),
            ("mutable", b"fixture bundle\n", "immutable"),
            ("absolute", b"fixture bundle\n", "inside"),
            ("traversal", b"fixture bundle\n", "inside"),
            ("revision", b"fixture bundle\n", "revision"),
        )
        for name, replacement, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "sealed-mirror"
                authority = mirror_authority(manifest)
                authority_path = seal_mirror(
                    root,
                    authority,
                    {"bundles/alpha.bundle": b"fixture bundle\n"},
                )
                try:
                    bundle = root / "bundles" / "alpha.bundle"
                    if name == "missing":
                        os.chmod(bundle.parent, 0o755)
                        bundle.unlink()
                        os.chmod(bundle.parent, 0o555)
                    elif name == "checksum":
                        os.chmod(bundle.parent, 0o755)
                        os.chmod(bundle, 0o644)
                        bundle.write_bytes(replacement or b"")
                        os.chmod(bundle, 0o444)
                        os.chmod(bundle.parent, 0o555)
                    elif name == "mutable":
                        os.chmod(bundle, 0o644)
                    else:
                        unseal_mirror(root)
                        if name == "absolute":
                            authority["projects"][0]["bundle"] = str(bundle)
                        elif name == "traversal":
                            authority["projects"][0]["bundle"] = "../alpha.bundle"
                        else:
                            authority["projects"][0]["revision"] = "3" * 40
                        authority_path = seal_mirror(
                            root,
                            authority,
                            {"bundles/alpha.bundle": b"fixture bundle\n"},
                        )
                    with self.assertRaisesRegex(campaign.EvidenceError, expected):
                        campaign.load_mirror_authority(
                            authority_path, manifest, "alpha"
                        )
                finally:
                    unseal_mirror(root)

    def test_offline_mirror_rejects_symlinked_authority_and_bundle(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        for target in ("authority", "bundle"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / "sealed-mirror"
                authority = mirror_authority(manifest)
                authority_path = seal_mirror(
                    root,
                    authority,
                    {"bundles/alpha.bundle": b"fixture bundle\n"},
                )
                try:
                    if target == "authority":
                        real = parent / "real-authority.json"
                        real.write_bytes(authority_path.read_bytes())
                        os.chmod(root, 0o755)
                        os.chmod(authority_path, 0o644)
                        authority_path.unlink()
                        authority_path.symlink_to(real)
                        os.chmod(root, 0o555)
                    else:
                        bundle = root / "bundles" / "alpha.bundle"
                        real = parent / "real-alpha.bundle"
                        real.write_bytes(bundle.read_bytes())
                        os.chmod(bundle.parent, 0o755)
                        os.chmod(bundle, 0o644)
                        bundle.unlink()
                        bundle.symlink_to(real)
                        os.chmod(bundle.parent, 0o555)
                    with self.assertRaisesRegex(campaign.EvidenceError, "symlink|regular"):
                        campaign.load_mirror_authority(
                            authority_path, manifest, "alpha"
                        )
                finally:
                    unseal_mirror(root)

    def test_offline_authority_itself_must_be_canonical_checksummed_and_read_only(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        for mutation, expected in (
            ("checksum", "checksum"),
            ("noncanonical", "canonical"),
            ("mutable", "immutable"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "sealed-mirror"
                authority = mirror_authority(manifest)
                authority_path = seal_mirror(
                    root,
                    authority,
                    {"bundles/alpha.bundle": b"fixture bundle\n"},
                )
                try:
                    os.chmod(root, 0o755)
                    if mutation == "checksum":
                        os.chmod(authority_path, 0o644)
                        authority_path.write_bytes(authority_path.read_bytes() + b" ")
                        os.chmod(authority_path, 0o444)
                    elif mutation == "noncanonical":
                        os.chmod(authority_path, 0o644)
                        encoded = (
                            json.dumps(authority, indent=2, sort_keys=True) + "\n"
                        ).encode("utf-8")
                        authority_path.write_bytes(encoded)
                        sidecar = authority_path.with_suffix(".json.sha256")
                        os.chmod(sidecar, 0o644)
                        sidecar.write_text(
                            f"{campaign.digest_bytes(encoded)}  authority.json\n",
                            encoding="ascii",
                        )
                        os.chmod(authority_path, 0o444)
                        os.chmod(sidecar, 0o444)
                    else:
                        os.chmod(authority_path, 0o644)
                    os.chmod(root, 0o555)
                    with self.assertRaisesRegex(campaign.EvidenceError, expected):
                        campaign.load_mirror_authority(
                            authority_path, manifest, "alpha"
                        )
                finally:
                    unseal_mirror(root)

    def test_offline_environment_closes_host_compiler_cache_and_build_injection(self) -> None:
        hostile = {
            "PATH": "/hostile/bin:/usr/lib64/ccache:/usr/bin",
            "HOME": "/runtime/home",
            "TMPDIR": "/runtime/tmp",
            "CC": "/hostile/cc",
            "CXX": "/hostile/cxx",
            "CFLAGS": "-include /hostile/header.h",
            "CMAKE_GENERATOR": "Hostile",
            "CCACHE_DIR": "/hostile/cache",
            "CCACHE_PREFIX": "/hostile/prefix",
            "HTTP_PROXY": "http://hostile.invalid",
            "LD_PRELOAD": "/hostile/preload.so",
            "BASH_ENV": "/hostile/bash-env",
            "XDG_CACHE_HOME": "/hostile/xdg-cache",
        }
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            temporary = workspace / ".codeskeptic-tmp"
            temporary.mkdir()
            identity = campaign._workspace_directory_identity(workspace)
            token = campaign._COMMAND_WORKSPACE_STATE.set(
                (
                    workspace,
                    identity,
                    0,
                    0,
                    temporary,
                    {"reserve": None, "probe": None},
                )
            )
            try:
                with mock.patch.dict(os.environ, hostile, clear=True):
                    environment = campaign._offline_base_environment()
            finally:
                campaign._COMMAND_WORKSPACE_STATE.reset(token)
        self.assertEqual(
            environment["PATH"],
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        self.assertEqual(environment["HOME"], os.fspath(temporary))
        self.assertEqual(environment["TMPDIR"], os.fspath(temporary))
        self.assertEqual(environment["XDG_CACHE_HOME"], os.fspath(temporary))
        self.assertEqual(environment["XDG_CONFIG_HOME"], os.fspath(temporary))
        self.assertEqual(environment["XDG_DATA_HOME"], os.fspath(temporary))
        self.assertEqual(environment["CCACHE_DISABLE"], "1")
        for rejected in (
            "CC",
            "CXX",
            "CFLAGS",
            "CMAKE_GENERATOR",
            "CCACHE_DIR",
            "CCACHE_PREFIX",
            "HTTP_PROXY",
            "LD_PRELOAD",
            "BASH_ENV",
        ):
            self.assertNotIn(rejected, environment)

    def test_recursive_offline_mapping_is_exact_and_network_is_disabled(self) -> None:
        raw = fixture_manifest()
        entries = [{"path": "deps/example", "revision": "4" * 40}]
        raw["projects"][0]["checkout"] = {
            "submodules": "recursive",
            "expected_count": 1,
            "expected_sha256": campaign.digest_json(entries),
        }
        manifest = campaign.validate_manifest(raw)
        submodule = {
            "path": "deps/example",
            "repository": "https://android.googlesource.com/platform/external/aac",
            "revision": "4" * 40,
            "tree": "5" * 40,
            "bundle": "bundles/dependency.bundle",
            "bundle_sha256": "0" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sealed-mirror"
            authority = mirror_authority(manifest, submodules=[submodule])
            authority_path = seal_mirror(
                root,
                authority,
                {
                    "bundles/alpha.bundle": b"root bundle\n",
                    "bundles/dependency.bundle": b"dependency bundle\n",
                },
            )
            try:
                selected, selected_root = campaign.load_mirror_authority(
                    authority_path, manifest, "alpha"
                )
                repositories = {
                    selected["repository"]: root / "transport-alpha.git",
                    submodule["repository"]: root / "transport-dependency.git",
                }
                with mock.patch.dict(
                    os.environ,
                    {"GIT_DIR": "/tmp/forged", "GIT_CONFIG_COUNT": "99"},
                    clear=False,
                ):
                    environment = campaign.offline_git_environment(
                        selected, repositories
                    )
                self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "file")
                self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertNotIn("GIT_DIR", environment)
                values = {
                    environment[f"GIT_CONFIG_VALUE_{index}"]
                    for index in range(int(environment["GIT_CONFIG_COUNT"]))
                }
                self.assertIn(manifest["projects"][0]["repository"], values)
                self.assertIn(submodule["repository"], values)

                forged = copy.deepcopy(authority)
                forged["projects"][0]["submodules"][0]["revision"] = "6" * 40
                unseal_mirror(root)
                authority_path = seal_mirror(
                    root,
                    forged,
                    {
                        "bundles/alpha.bundle": b"root bundle\n",
                        "bundles/dependency.bundle": b"dependency bundle\n",
                    },
                )
                with self.assertRaisesRegex(campaign.EvidenceError, "submodule identity"):
                    campaign.load_mirror_authority(
                        authority_path, manifest, "alpha"
                    )
            finally:
                unseal_mirror(root)

    def test_offline_checkout_never_fetches_an_upstream_url(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        project = manifest["projects"][0]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            root = temporary / "sealed-mirror"
            authority = mirror_authority(manifest)
            authority_path = seal_mirror(
                root, authority, {"bundles/alpha.bundle": b"fixture bundle\n"}
            )
            try:
                selected, selected_root = campaign.load_mirror_authority(
                    authority_path, manifest, "alpha"
                )
                commands: list[tuple[list[str], dict[str, str] | None]] = []

                def fake_run(command, cwd, deadline, memory_mb, log_path, env=None):
                    del cwd, deadline, memory_mb, log_path
                    commands.append((command, env))
                    return subprocess.CompletedProcess(command, 0)

                with (
                    mock.patch.object(campaign, "_run_command", side_effect=fake_run),
                    mock.patch.object(
                        campaign,
                        "_materialize_offline_repositories",
                        return_value={
                            project["repository"]: temporary / "transport-alpha.git"
                        },
                    ),
                    mock.patch.object(
                        campaign,
                        "_capture_git",
                        side_effect=[project["revision"] + "\n", selected["tree"] + "\n"],
                    ),
                    mock.patch.object(
                        campaign,
                        "_submodule_identity",
                        return_value=campaign._expected_submodules(project),
                    ),
                ):
                    actual = campaign._checkout_project(
                        project,
                        temporary / "work" / "alpha",
                        10_000.0,
                        temporary / "commands.log",
                        selected,
                        selected_root,
                    )
                self.assertEqual(actual, campaign._expected_submodules(project))
                fetches = [command for command, _ in commands if "fetch" in command]
                self.assertEqual(len(fetches), 1)
                self.assertNotIn(project["repository"], fetches[0])
                self.assertIn(str(temporary / "transport-alpha.git"), fetches[0])
                for command, environment in commands:
                    if command[0] == "git":
                        self.assertIsNotNone(environment)
                        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "file")
            finally:
                unseal_mirror(root)

    def test_offline_transport_staging_symlink_is_rejected_without_deletion(self) -> None:
        manifest = campaign.validate_manifest(fixture_manifest())
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            root = temporary / "sealed-mirror"
            authority = mirror_authority(manifest)
            authority_path = seal_mirror(
                root, authority, {"bundles/alpha.bundle": b"fixture bundle\n"}
            )
            try:
                selected, selected_root = campaign.load_mirror_authority(
                    authority_path, manifest, "alpha"
                )
                workspace = temporary / "work"
                workspace.mkdir()
                sentinel = temporary / "sentinel"
                sentinel.mkdir()
                (sentinel / "keep.txt").write_text("keep\n", encoding="utf-8")
                (workspace / ".alpha-mirror-transport").symlink_to(
                    sentinel, target_is_directory=True
                )
                with self.assertRaisesRegex(campaign.EvidenceError, "staging path"):
                    campaign._checkout_project(
                        manifest["projects"][0],
                        workspace / "alpha",
                        campaign.time.monotonic() + 30.0,
                        workspace / "commands.log",
                        selected,
                        selected_root,
                    )
                self.assertEqual(
                    (sentinel / "keep.txt").read_text(encoding="utf-8"),
                    "keep\n",
                )
            finally:
                unseal_mirror(root)

    @unittest.skipUnless(
        LINUX_SUBREAPER_AVAILABLE,
        "offline execution requires Linux /proc subreaper containment",
    )
    def test_offline_bundle_checkout_resolves_recursive_submodule_without_network(self) -> None:
        def git(repository: Path, *arguments: str) -> str:
            environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("GIT_")
            }
            environment.update(
                {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
            )
            return subprocess.run(
                ["git", *arguments],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            ).stdout.strip()

        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            dependency = temporary / "dependency-source"
            dependency.mkdir()
            git(dependency, "init", "--quiet")
            git(dependency, "config", "user.name", "Fixture")
            git(dependency, "config", "user.email", "fixture@example.invalid")
            (dependency / "dependency.txt").write_text("dependency\n", encoding="utf-8")
            git(dependency, "add", "dependency.txt")
            git(dependency, "commit", "--quiet", "-m", "dependency")
            dependency_revision = git(dependency, "rev-parse", "HEAD")
            dependency_tree = git(dependency, "rev-parse", "HEAD^{tree}")

            source = temporary / "alpha-source"
            source.mkdir()
            git(source, "init", "--quiet")
            git(source, "config", "user.name", "Fixture")
            git(source, "config", "user.email", "fixture@example.invalid")
            (source / "alpha.txt").write_text("alpha\n", encoding="utf-8")
            git(source, "add", "alpha.txt")
            git(source, "commit", "--quiet", "-m", "alpha")
            git(
                source,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "--quiet",
                str(dependency),
                "deps/example",
            )
            git(
                source,
                "config",
                "--file",
                ".gitmodules",
                "submodule.deps/example.url",
                "../dependency.git",
            )
            git(source, "add", ".gitmodules", "deps/example")
            git(source, "commit", "--quiet", "-m", "submodule")
            source_revision = git(source, "rev-parse", "HEAD")
            source_tree = git(source, "rev-parse", "HEAD^{tree}")

            raw = fixture_manifest()
            raw["projects"][0]["revision"] = source_revision
            submodule_identity = [
                {"path": "deps/example", "revision": dependency_revision}
            ]
            raw["projects"][0]["checkout"] = {
                "submodules": "recursive",
                "expected_count": 1,
                "expected_sha256": campaign.digest_json(submodule_identity),
            }
            manifest = campaign.validate_manifest(raw)

            source_bundle = temporary / "alpha.bundle"
            dependency_bundle = temporary / "dependency.bundle"
            git(source, "bundle", "create", str(source_bundle), "--all")
            git(dependency, "bundle", "create", str(dependency_bundle), "--all")
            submodule = {
                "path": "deps/example",
                "repository": "https://github.com/example/dependency.git",
                "revision": dependency_revision,
                "tree": dependency_tree,
                "bundle": "bundles/dependency.bundle",
                "bundle_sha256": "0" * 64,
            }
            root = temporary / "sealed-mirror"
            authority = mirror_authority(
                manifest, tree=source_tree, submodules=[submodule]
            )
            authority_path = seal_mirror(
                root,
                authority,
                {
                    "bundles/alpha.bundle": source_bundle.read_bytes(),
                    "bundles/dependency.bundle": dependency_bundle.read_bytes(),
                },
            )
            try:
                selected, selected_root = campaign.load_mirror_authority(
                    authority_path, manifest, "alpha"
                )
                workspace = temporary / "offline-work" / "alpha"
                workspace.parent.mkdir()
                try:
                    actual = campaign._checkout_project(
                        manifest["projects"][0],
                        workspace,
                        campaign.time.monotonic() + 30.0,
                        temporary / "offline-work" / "commands.log",
                        selected,
                        selected_root,
                    )
                except campaign.EvidenceError as error:
                    self.fail(
                        f"{error}\n"
                        + (temporary / "offline-work" / "commands.log").read_text(
                            encoding="utf-8"
                        )
                    )
                self.assertEqual(
                    actual,
                    {
                        "mode": "recursive",
                        "count": 1,
                        "sha256": campaign.digest_json(submodule_identity),
                    },
                )
                self.assertEqual(
                    (workspace / "deps/example/dependency.txt").read_text(
                        encoding="utf-8"
                    ),
                    "dependency\n",
                )
                self.assertFalse(
                    (workspace.parent / ".alpha-mirror-transport").exists()
                )
                log = (temporary / "offline-work" / "commands.log").read_text(
                    encoding="utf-8"
                )
                self.assertNotIn("fetch\", \"https://", log)
            finally:
                unseal_mirror(root)

    def test_online_run_cli_remains_the_default_and_offline_is_explicit(self) -> None:
        parser = campaign.build_parser()
        required = [
            "run",
            "--project",
            "alpha",
            "--repetition",
            "1",
            "--analyzer",
            "analyzer",
            "--workspace",
            "work",
            "--output",
            "receipt.json",
        ]
        online = parser.parse_args(required)
        self.assertIsNone(online.mirror_authority)
        offline = parser.parse_args(
            [*required, "--mirror-authority", "sealed/authority.json"]
        )
        self.assertEqual(
            offline.mirror_authority, Path("sealed/authority.json")
        )


@unittest.skipUnless(
    LINUX_SUBREAPER_AVAILABLE,
    "process supervision requires Linux /proc subreaper containment",
)
class CommandSupervisorTest(unittest.TestCase):
    def _detached_script(
        self, root: Path, *, inherit_pipe: bool, leader_delay: float = 0.1
    ) -> tuple[Path, Path]:
        pid_path = root / "child.pid"
        script = root / "launcher.py"
        redirection = "" if inherit_pipe else "os.close(1); os.close(2);"
        script.write_text(
            "#!/usr/bin/python3\nimport os,time\n"
            "pid=os.fork()\n"
            "if pid == 0:\n"
            " os.setsid(); " + redirection + f" open('{pid_path}','w').write(str(os.getpid())); time.sleep(30)\n"
            f"time.sleep({leader_delay!r})\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script, pid_path

    def _assert_pid_gone(self, pid_path: Path) -> None:
        pid = int(pid_path.read_text(encoding="ascii"))
        for _ in range(100):
            if not Path(f"/proc/{pid}").exists():
                break
            campaign.time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_closed_pipe_detached_descendant_is_killed_after_leader_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script, pid_path = self._detached_script(root, inherit_pipe=False)
            with self.assertRaisesRegex(campaign.EvidenceError, "orphan"):
                campaign._run_command(
                    [str(script)], root, campaign.time.monotonic() + 2,
                    512, root / "commands.log",
                )
            self._assert_pid_gone(pid_path)

    def test_inherited_pipe_detached_descendant_is_killed_at_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script, pid_path = self._detached_script(root, inherit_pipe=True)
            with self.assertRaisesRegex(campaign.EvidenceError, "timed out"):
                campaign._capture_git(
                    [str(script)], root, campaign.time.monotonic() + 0.25,
                    512, root / "commands.log", os.environ.copy(),
                )
            self._assert_pid_gone(pid_path)

    def test_immediate_exit_closed_pipe_escape_is_rejected_repeatedly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for attempt in range(10):
                attempt_root = root / str(attempt)
                attempt_root.mkdir()
                script, pid_path = self._detached_script(
                    attempt_root, inherit_pipe=False, leader_delay=0
                )
                with self.assertRaisesRegex(campaign.EvidenceError, "orphan"):
                    campaign._run_command(
                        [str(script)], attempt_root,
                        campaign.time.monotonic() + 2, 512,
                        attempt_root / "commands.log",
                    )
                self._assert_pid_gone(pid_path)
                self.assertTrue(campaign._child_table_empty())

    def test_preexisting_direct_child_rejects_execution_without_killing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unrelated = subprocess.Popen(["/usr/bin/sleep", "30"])
            try:
                with self.assertRaisesRegex(campaign.EvidenceError, "pre-existing child"):
                    campaign._run_command(
                        ["/usr/bin/true"], root,
                        campaign.time.monotonic() + 2, 512,
                        root / "commands.log",
                    )
                self.assertIsNone(unrelated.poll())
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=2)

    def test_second_controller_thread_rejects_execution_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stop = threading.Event()
            other = threading.Thread(target=stop.wait)
            other.start()
            try:
                with self.assertRaisesRegex(campaign.EvidenceError, "single-threaded"):
                    campaign._run_command(
                        ["/usr/bin/true"], root,
                        campaign.time.monotonic() + 2, 512,
                        root / "commands.log",
                    )
            finally:
                stop.set()
                other.join(timeout=2)

    def test_child_table_treats_echild_as_the_only_empty_postcondition(self) -> None:
        with mock.patch.object(
            campaign.os, "waitpid", side_effect=ChildProcessError()
        ):
            self.assertTrue(campaign._child_table_empty())
        with mock.patch.object(campaign.os, "waitpid", return_value=(0, 0)):
            self.assertFalse(campaign._child_table_empty())

    @unittest.skipUnless(
        hasattr(os, "fork") and Path("/proc").is_dir(),
        "Linux fork/subreaper semantics unavailable",
    )
    def test_subreaper_cache_is_revalidated_after_fork(self) -> None:
        self.assertTrue(campaign._enable_subreaper())
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:  # pragma: no cover - assertion is returned to the parent.
            os.close(read_fd)
            result = b"0"
            try:
                enabled = campaign._enable_subreaper()
                state = campaign.ctypes.c_int(0)
                library = campaign.ctypes.CDLL(None, use_errno=True)
                if (
                    enabled
                    and library.prctl(
                        37, campaign.ctypes.byref(state), 0, 0, 0
                    ) == 0
                ):
                    result = b"1" if state.value == 1 else b"0"
            finally:
                os.write(write_fd, result)
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        try:
            observed = os.read(read_fd, 1)
        finally:
            os.close(read_fd)
        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertEqual(observed, b"1")

    def test_selector_registration_failure_closes_and_reaps(self) -> None:
        class BrokenSelector:
            closed = False

            def register(self, *_arguments) -> None:
                raise RuntimeError("selector registration failed")

            def close(self) -> None:
                self.closed = True
                raise OSError("selector close failed")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selector = BrokenSelector()
            captured: list[subprocess.Popen] = []
            real_popen = campaign.subprocess.Popen

            def recording_popen(*arguments, **keywords):
                process = real_popen(*arguments, **keywords)
                captured.append(process)
                return process

            with (
                mock.patch.object(
                    campaign.subprocess, "Popen", side_effect=recording_popen
                ),
                mock.patch.object(
                    campaign.selectors, "DefaultSelector", return_value=selector
                ),
            ):
                with self.assertRaisesRegex(
                    campaign.EvidenceError,
                    "registration failed; selector cleanup failed",
                ):
                    campaign._run_command(
                        ["/usr/bin/sleep", "30"],
                        root,
                        campaign.time.monotonic() + 2,
                        512,
                        root / "commands.log",
                    )
            self.assertTrue(selector.closed)
            self.assertEqual(len(captured), 1)
            self.assertIsNotNone(captured[0].poll())
            self.assertTrue(campaign._child_table_empty())

    def test_shard_reserve_release_retries_delayed_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = mock.Mock(f_bavail=1 << 20, f_frsize=1)
            below_floor = mock.Mock(f_bavail=0, f_frsize=1)
            delayed = root / "delayed"
            delayed.mkdir()
            with (
                mock.patch.object(
                    campaign, "MIN_SHARD_FILESYSTEM_FREE_BYTES", 1 << 20
                ),
                mock.patch.object(
                    campaign, "SHARD_EMERGENCY_RESERVE_BYTES", 1 << 20
                ),
                campaign._bounded_shard_workspace(delayed),
                mock.patch.object(
                    campaign.os,
                    "fstatvfs",
                    side_effect=[below_floor, recovered],
                ) as probe,
                mock.patch.object(campaign.time, "sleep") as pause,
            ):
                campaign._release_shard_emergency_reserve()
                self.assertEqual(probe.call_count, 2)
                pause.assert_called_once()

            never = root / "never"
            never.mkdir()
            with (
                mock.patch.object(
                    campaign, "MIN_SHARD_FILESYSTEM_FREE_BYTES", 1 << 20
                ),
                mock.patch.object(
                    campaign, "SHARD_EMERGENCY_RESERVE_BYTES", 1 << 20
                ),
                mock.patch.object(
                    campaign, "SHARD_RESERVE_RECOVERY_TIMEOUT_SECONDS", 0
                ),
                campaign._bounded_shard_workspace(never),
                mock.patch.object(
                    campaign.os, "fstatvfs", return_value=below_floor
                ),
            ):
                with self.assertRaisesRegex(campaign.EvidenceError, "recover"):
                    campaign._release_shard_emergency_reserve()

    def test_live_log_and_capture_floods_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flood = ["/usr/bin/python3", "-c", "import sys;sys.stdout.write('x'*100000)"]
            with mock.patch.object(campaign, "MAX_COMMAND_LOG_BYTES", 1024):
                with self.assertRaisesRegex(campaign.EvidenceError, "commands log"):
                    campaign._run_command(
                        flood, root, campaign.time.monotonic() + 2,
                        512, root / "commands.log",
                    )
            self.assertLessEqual((root / "commands.log").stat().st_size, 1024)
            (root / "commands.log").unlink()
            with mock.patch.object(campaign, "MAX_COMMAND_CAPTURE_BYTES", 128):
                with self.assertRaisesRegex(campaign.EvidenceError, "capture"):
                    campaign._capture_git(
                        flood, root, campaign.time.monotonic() + 2,
                        512, root / "commands.log", os.environ.copy(),
                    )

    def test_child_written_report_growth_is_stopped_live(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            writer = [
                "/usr/bin/python3", "-c",
                "import pathlib,time; p=pathlib.Path(r'%s'); f=p.open('wb'); "
                "[(f.write(b'x'*128),f.flush(),time.sleep(.01)) for _ in range(100)]"
                % report,
            ]
            with self.assertRaisesRegex(campaign.EvidenceError, "bounded output"):
                campaign._run_command(
                    writer, root, campaign.time.monotonic() + 2,
                    512, root / "commands.log",
                    watched_files={report: 512},
                )
            self.assertLess(report.stat().st_size, 4096)

    def test_closed_output_child_cannot_flood_watched_report_while_waiting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            writer = [
                "/usr/bin/python3", "-c",
                "import os,pathlib,time; os.close(1); os.close(2); "
                "f=pathlib.Path(r'%s').open('wb'); "
                "[(f.write(b'x'*128),f.flush(),time.sleep(.01)) for _ in range(100)]"
                % report,
            ]
            with self.assertRaisesRegex(campaign.EvidenceError, "bounded output"):
                campaign._run_command(
                    writer, root, campaign.time.monotonic() + 2,
                    512, root / "commands.log",
                    watched_files={report: 512},
                )
            self.assertLess(report.stat().st_size, 4096)

    def test_exiting_closed_pipe_descendant_cannot_escape_final_file_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            launcher = root / "late-writer.py"
            launcher.write_text(
                "#!/usr/bin/python3\nimport os,time\n"
                "pid=os.fork()\n"
                "if pid == 0:\n"
                " os.setsid(); os.close(1); os.close(2); time.sleep(.03); "
                f"open('{report}','wb').write(b'x'*4096); os._exit(0)\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            with self.assertRaisesRegex(campaign.EvidenceError, "bounded output"):
                campaign._run_command(
                    [str(launcher)], root, campaign.time.monotonic() + 2,
                    512, root / "commands.log",
                    watched_files={report: 128},
                )
            self.assertGreater(report.stat().st_size, 128)
            self.assertTrue(campaign._child_table_empty())

    def test_shard_workspace_multi_file_growth_and_tmp_are_bounded_live(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "shard"
            workspace.mkdir()
            payloads = workspace / "payloads"
            pid_path = workspace / "writer.pid"
            tmp_record = workspace / "tmp.txt"
            writer = root / "workspace-writer.py"
            writer.write_text(
                "#!/usr/bin/python3\nimport os,pathlib,time\n"
                f"root=pathlib.Path('{payloads}'); root.mkdir(); "
                f"pathlib.Path('{pid_path}').write_text(str(os.getpid())); "
                f"pathlib.Path('{tmp_record}').write_text(os.environ['TMPDIR']); "
                "os.close(1); os.close(2)\n"
                "for index in range(10000):\n"
                " fd=os.open(root / str(index),os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600); "
                "os.posix_fallocate(fd,0,4096); os.close(fd); time.sleep(.002)\n",
                encoding="utf-8",
            )
            writer.chmod(0o755)
            before = campaign._shard_workspace_allocated_bytes(workspace)
            with (
                mock.patch.object(
                    campaign, "MAX_SHARD_WORKSPACE_ALLOCATED_BYTES", 128 << 10
                ),
                mock.patch.object(
                    campaign, "MIN_SHARD_FILESYSTEM_FREE_BYTES", 1 << 20
                ),
                mock.patch.object(campaign, "SHARD_EMERGENCY_RESERVE_BYTES", 1 << 20),
                campaign._bounded_shard_workspace(workspace),
            ):
                with self.assertRaisesRegex(campaign.EvidenceError, "workspace allocation"):
                    campaign._run_command(
                        [str(writer)], workspace,
                        campaign.time.monotonic() + 3, 512,
                        root / "commands.log",
                        file_size_limit_bytes=1 << 20,
                    )
                reserve = campaign._COMMAND_WORKSPACE_STATE.get()
                self.assertIsNotNone(reserve)
                pid = int(pid_path.read_text(encoding="ascii"))
                self.assertFalse(Path(f"/proc/{pid}").exists())
                self.assertIsNone(reserve[5]["reserve"])
                capacity = os.fstatvfs(reserve[5]["probe"])
                self.assertGreaterEqual(
                    capacity.f_bavail * capacity.f_frsize,
                    campaign.MIN_SHARD_FILESYSTEM_FREE_BYTES,
                )
                stable_allocation = campaign._shard_workspace_allocated_bytes(workspace)
                campaign.time.sleep(0.05)
                self.assertEqual(
                    campaign._shard_workspace_allocated_bytes(workspace),
                    stable_allocation,
                )
            pid = int(pid_path.read_text(encoding="ascii"))
            self.assertFalse(Path(f"/proc/{pid}").exists())
            self.assertEqual(tmp_record.read_text(encoding="utf-8"), str(workspace / ".codeskeptic-tmp"))
            growth = campaign._shard_workspace_allocated_bytes(workspace) - before
            self.assertLess(growth, 4 << 20)

    def test_default_single_file_rlimit_is_hard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload.bin"
            writer = [
                "/usr/bin/python3", "-c",
                f"open(r'{payload}','wb').write(b'x'*4096)",
            ]
            with mock.patch.object(campaign, "MAX_PROCESS_FILE_BYTES", 512):
                result = campaign._run_command(
                    writer, root, campaign.time.monotonic() + 2,
                    512, root / "commands.log",
                )
            self.assertIn(result.returncode, (0, -signal.SIGXFSZ, 1))
            self.assertLessEqual(payload.stat().st_size, 512)

    def test_compile_database_and_report_reads_reject_oversize_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "compile_commands.json"
            database.write_text("[]" + " " * 100, encoding="utf-8")
            project = campaign.validate_manifest(fixture_manifest())["projects"][0]
            with mock.patch.object(campaign, "MAX_COMPILE_DATABASE_BYTES", 8):
                with self.assertRaisesRegex(campaign.EvidenceError, "size limit"):
                    campaign._derive_translation_units(project, root, root, database)
            report = root / "report.json"
            report.write_text("{}", encoding="utf-8")
            os.link(report, root / "report-alias.json")
            with self.assertRaisesRegex(campaign.EvidenceError, "regular file"):
                campaign._read_regular_bytes(report, campaign.MAX_ANALYZER_REPORT_BYTES)


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

    def test_plan_enforces_and_projects_exact_tu_resource_budgets(self) -> None:
        report = {"translation_units": translation_unit_receipts(2)}
        plan = campaign.translation_unit_plan(report, 2, 2)
        resources = campaign.translation_unit_resource_summary(
            report,
            expected_timeout_seconds=300,
            expected_memory_mib=4096,
        )
        self.assertEqual(resources["translation_units"], plan["count"])
        self.assertEqual(resources["maximum_duration_ms"], 10)
        self.assertEqual(resources["maximum_peak_memory_kib"], 1024)
        self.assertEqual(resources["timeout_seconds"], 300)
        self.assertEqual(resources["memory_mib"], 4096)
        self.assertEqual(resources["duration_budget_violations"], 0)
        self.assertEqual(resources["memory_budget_violations"], 0)

        inflated = copy.deepcopy(report)
        for receipt in inflated["translation_units"]:
            receipt["timeout_seconds"] = 86_400
            receipt["memory_mib"] = 131_072
        with self.assertRaisesRegex(campaign.EvidenceError, "timeout budget"):
            campaign.translation_unit_resource_summary(
                inflated,
                expected_timeout_seconds=300,
                expected_memory_mib=4096,
            )

        mixed = copy.deepcopy(report)
        mixed["translation_units"][1]["memory_mib"] = 8192
        with self.assertRaisesRegex(campaign.EvidenceError, "not uniform"):
            campaign.translation_unit_resource_summary(mixed)

        duration = copy.deepcopy(report)
        duration["translation_units"][0]["duration_ms"] = 300_001
        with self.assertRaisesRegex(campaign.EvidenceError, "duration budget"):
            campaign.translation_unit_plan(duration, 2, 2)

        memory = copy.deepcopy(report)
        memory["translation_units"][0]["peak_memory_kib"] = 4_194_305
        with self.assertRaisesRegex(campaign.EvidenceError, "memory budget"):
            campaign.translation_unit_plan(memory, 2, 2)

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

    @unittest.skipUnless(
        LINUX_SUBREAPER_AVAILABLE,
        "real shard execution requires Linux /proc subreaper containment",
    )
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

            def fake_command(
                command, cwd, deadline, memory_mb, log_path, env=None, **keywords
            ):
                del cwd, deadline, memory_mb, log_path, env, keywords
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

            with (
                mock.patch.object(campaign, "_run_command", side_effect=fake_command),
                mock.patch.object(
                    campaign, "_capture_git", return_value=project["revision"] + "\n"
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
                mock.patch.object(
                    campaign, "SHARD_EMERGENCY_RESERVE_BYTES", 1 << 20
                ),
                mock.patch.object(
                    campaign, "MIN_SHARD_FILESYSTEM_FREE_BYTES", 1 << 20
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
            analyzer_argv = analyzer_invocations[0]
            self.assertEqual(
                analyzer_argv[analyzer_argv.index("--tu-timeout-seconds") + 1],
                "300",
            )
            self.assertEqual(
                analyzer_argv[analyzer_argv.index("--tu-memory-mib") + 1],
                "4096",
            )
            receipt = campaign.load_verified_receipt(output)
            self.assertNotEqual(
                receipt["execution"]["translation_unit_plan"]["sha256"],
                prior["execution"]["translation_unit_plan"]["sha256"],
            )
            self.assertEqual(
                receipt["execution"]["translation_unit_plan"]["checkpoint"], 1
            )
            self.assertTrue(receipt["execution"]["resumed"])
            self.assertFalse((root / "work").exists())

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
