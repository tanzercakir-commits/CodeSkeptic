#!/usr/bin/env python3
"""Contracts for the raw-derived Phase 10 quality-floor producer."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_floor_receipt as quality  # noqa: E402
import run_quality_floor_campaign as campaign  # noqa: E402


def temporary_root(value: str) -> Path:
    """Return the real directory behind a platform temporary-path alias."""

    return Path(value).resolve(strict=True)


def _coverage(attempted: int = 1, analyzed: int = 1,
              broken: int = 0) -> dict[str, int]:
    return {
        "attempted_tus": attempted,
        "analyzed_tus": analyzed,
        "broken_tus": broken,
        "incomplete_functions": 0,
    }


def _accepted_observations() -> tuple[
    list[dict], list[dict], list[dict], dict[str, list[str]]
]:
    rules = []
    for rule_id in quality.EXPECTED_RULES:
        resource = rule_id == "resource-leak"
        rules.append(
            {
                "id": rule_id,
                "corpus": "resource-leak-mutation" if resource else "juliet",
                "exact_head": True,
                "fresh": True,
                "raw_sha256": "",
                "diagnostics": {
                    "true_positives": 3 if resource else 9,
                    "false_positives": 0 if resource else 1,
                },
                "cases": {
                    "files": 3 if resource else 10,
                    "misses": {
                        "total": 0 if resource else 2,
                        "addressable": 0 if resource else 2,
                        "model_gap": 0,
                        "out_of_scope": 0,
                    },
                },
            }
        )
    clean = [
        {
            "id": f"clean-{index}",
            "process_exit": 0,
            "report_exit": 0,
            "complete": True,
            "coverage": _coverage(),
            "findings": 0,
            "raw_sha256": "",
        }
        for index in range(9)
    ]
    negatives = [
        {
            "id": "broken-requested-tu",
            "kind": "broken",
            "process_exit": 2,
            "report_exit": 2,
            "complete": False,
            "verdict": None,
            "coverage": _coverage(2, 1, 1),
            "raw_sha256": "",
        },
        {
            "id": "missing-requested-tu",
            "kind": "missing",
            "process_exit": 2,
            "report_exit": 2,
            "complete": False,
            "verdict": None,
            "coverage": _coverage(2, 1, 0),
            "raw_sha256": "",
        },
    ]
    juliet = ["juliet/operator.json", "juliet/operator.log",
              "juliet/input-manifest.json"]
    for cwe in campaign.JULIET_RULES:
        juliet.extend(
            [
                f"juliet/files_{cwe}.txt",
                f"juliet/analysis_{cwe}.txt",
                f"juliet/findings_{cwe}.json",
                f"juliet/log_{cwe}.txt",
                f"juliet/build_{cwe}/compile_commands.json",
            ]
        )
    used = {
        "authority": [
            campaign.AUTHORITY_NAME,
            campaign.CAMPAIGN_LAUNCH_NAME,
        ],
        "build_authority": [
            f"{campaign.BUILD_AUTHORITY_RAW_DIR}/{name}"
            for name in sorted(campaign.build_authority.AUTHORITY_FILES)
        ],
        "juliet": juliet,
        "resource": ["resource/raw.json"],
        "clean_corpus": [f"thesis/clean-{index}/raw.json" for index in range(9)],
        "requested_tu_negatives": [
            "stress/operator.json",
            "stress/receipt.json",
            "stress/logs/mixed-clean-broken-1.log",
            "stress/reports/mixed-clean-broken-1.json",
            "stress/logs/mixed-clean-broken-2.log",
            "stress/reports/mixed-clean-broken-2.json",
            "stress/logs/missing-requested-tu-1.log",
            "stress/reports/missing-requested-tu-1.json",
            "stress/logs/missing-requested-tu-2.log",
            "stress/reports/missing-requested-tu-2.json",
        ],
    }
    return rules, clean, negatives, used


def _write_fake_raw(package: Path) -> None:
    _rules, _clean, _negatives, used = _accepted_observations()
    for paths in used.values():
        for relative in paths:
            if relative == campaign.AUTHORITY_NAME:
                continue
            path = package / "raw" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"raw {relative}\n", encoding="utf-8")
    runs = lambda case_id: [  # noqa: E731
        {
            "log": f"logs/{case_id}-{index}.log",
            "report": f"reports/{case_id}-{index}.json",
        }
        for index in (1, 2)
    ]
    stress_receipt = {
        "cases": [
            {"id": "mixed-clean-broken", "runs": runs("mixed-clean-broken")},
            {"id": "missing-requested-tu", "runs": runs("missing-requested-tu")},
        ]
    }
    (package / "raw" / "stress" / "receipt.json").write_bytes(
        campaign.canonical_json(stress_receipt)
    )


def _seal_fake_authority(
    package: Path,
    source: dict[str, str],
    analyzer: dict[str, str],
    build_receipt: dict,
) -> dict:
    retained = package / "raw" / campaign.BUILD_AUTHORITY_RAW_DIR
    build_record = campaign._build_authority_record(retained, build_receipt)
    container_layout = campaign._campaign_container_layout(build_record)
    normalized = campaign._normalized_campaign_argv(
        "run", 1, container_layout=container_layout
    )
    runtime = {
        "schema": campaign.CAMPAIGN_RUNTIME_SCHEMA,
        "image": copy.deepcopy(build_receipt["runtime"]["image"]),
        "podman": copy.deepcopy(build_receipt["runtime"]["podman"]),
        "normalized_argv": normalized,
        "normalized_argv_sha256": campaign.compact_json_digest(normalized),
    }
    launch = campaign._launch_payload(
        "run",
        1,
        build_record,
        runtime,
        {
            "source": copy.deepcopy(build_record["source"]),
            "build_authority": copy.deepcopy(build_record),
            "mounts": campaign._campaign_mounts(
                "run", container_layout=container_layout
            ),
            "juliet": {"file_count": 1, "manifest_sha256": "6" * 64},
            "juliet_archive": campaign._official_corpus_identity(),
            "libarchive": {
                "checkout": campaign._resource_checkout_identity(),
                "tree": {"file_count": 1, "manifest_sha256": "7" * 64},
            },
        },
    )
    launch_path = package / "raw" / campaign.CAMPAIGN_LAUNCH_NAME
    campaign.write_json(launch_path, launch)
    execution = campaign._execution_authority(
        launch, campaign.sha256_file(launch_path)
    )
    authority = campaign._new_raw_authority(
        source, analyzer, build_record, execution
    )
    authority["run"]["state"] = "complete"
    authority["run"]["completed_at"] = authority["run"]["started_at"]
    authority["raw_artifacts"] = campaign._raw_artifact_summary(package / "raw")
    campaign.write_json(package / "raw" / campaign.AUTHORITY_NAME, authority)
    return authority


def _fake_build_receipt(
    source: dict[str, str],
    analyzer: dict[str, str],
    *,
    container_layout: str = "legacy",
) -> dict:
    build = campaign.build_authority
    configuration_material = {
        "cmake_cache_schema": build.determinism.CMAKE_CACHE_IDENTITY_SCHEMA,
        "cmake_cache_canonical_sha256": "3" * 64,
        "cmake_cache_sha256": "4" * 64,
        "cmake_cache_size": 1024,
        "compile_commands_sha256": "5" * 64,
        "compile_commands_size": 2048,
    }
    configuration = {
        "schema": build.CONFIGURATION_SCHEMA,
        **configuration_material,
        "identity_sha256": build.digest_json(configuration_material),
    }
    tool_records = {
        role: {
            "path": f"/usr/bin/fake-{role}",
            "sha256": f"{index:x}" * 64,
            "version": f"fake {role} 1.0",
        }
        for index, role in enumerate(build.TOOL_ROLES, start=6)
    }
    toolchain = {
        "schema": build.TOOLCHAIN_SCHEMA,
        "tools": tool_records,
        "identity_sha256": build.digest_json(tool_records),
    }
    normalized_argv = build._normalized_container_argv(
        "produce", container_layout
    )
    runtime = {
        "schema": build.RUNTIME_SCHEMA,
        "image": {
            "reference": build.PINNED_IMAGE,
            "digest": build.PINNED_IMAGE_DIGEST,
            "id": build.PINNED_IMAGE_ID,
        },
        "podman": {
            "path": str(build.DEFAULT_PODMAN.absolute()),
            "sha256": "a" * 64,
            "version": "podman version 5.0",
        },
        "normalized_argv": normalized_argv,
        "normalized_argv_sha256": build.digest_json(normalized_argv),
    }
    receipt = {
        "schema": campaign.build_authority.RECEIPT_SCHEMA,
        "status": "accepted",
        "image": campaign.build_authority.PINNED_IMAGE,
        "source": {
            **source,
            "file_count": 386,
        },
        "recipe": build._normalized_recipe(),
        "configuration": configuration,
        "toolchain": toolchain,
        "analyzer": {
            "path": campaign.build_authority.ANALYZER_RELATIVE,
            "sha256": analyzer["binary_sha256"],
            "version": analyzer["version"],
        },
        "logs": {
            name: {"path": name, "sha256": "b" * 64, "size": 1}
            for name in campaign.build_authority.LOG_NAMES
        },
        "runtime": runtime,
        "build_identity_sha256": "",
    }
    receipt["build_identity_sha256"] = build.digest_json(
        build._build_identity_material(receipt)
    )
    build._validate_receipt(receipt, None, final=True)
    return receipt


def _fake_build(root: Path) -> tuple[Path, Path, dict[str, str]]:
    build_dir = root / "build"
    binary = build_dir / campaign.build_authority.ANALYZER_RELATIVE
    binary.parent.mkdir(parents=True)
    binary.write_text(
        "#!/bin/sh\nprintf 'CodeSkeptic 0.4.9-dev\\n'\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary, build_dir, campaign._binary_identity(binary)


def _write_fake_build_authority(root: Path) -> Path:
    authority = root / "build-authority"
    authority.mkdir()
    for name in campaign.build_authority.AUTHORITY_FILES:
        (authority / name).write_text(f"{name}\n", encoding="utf-8")
    return authority


def _write_structural_build_authority(
    authority: Path, receipt: dict
) -> dict:
    """Write a build-dir-free authority bundle accepted by static verification."""
    authority.mkdir(parents=True, exist_ok=True)
    for path in authority.iterdir():
        if path.is_file() and not path.is_symlink():
            path.unlink()
    retained = copy.deepcopy(receipt)
    artifacts = {
        "build.log": b"fake build completed\n",
        "configure.log": b"fake configure completed\n",
    }
    retained["logs"] = {
        name: {
            "path": name,
            "sha256": campaign.sha256_bytes(raw),
            "size": len(raw),
        }
        for name, raw in artifacts.items()
    }
    container_layout = campaign.build_authority._container_layout_from_runtime(
        retained["runtime"]
    )
    operator = campaign.build_authority._expected_operator_log(
        campaign.build_authority._inner_build_identity_from_final(retained),
        container_layout,
    )
    artifacts["operator.log"] = operator
    retained["logs"]["operator.log"] = {
        "path": "operator.log",
        "sha256": campaign.sha256_bytes(operator),
        "size": len(operator),
    }
    retained["build_identity_sha256"] = campaign.build_authority.digest_json(
        campaign.build_authority._build_identity_material(retained)
    )
    campaign.build_authority._validate_receipt(
        retained,
        None,
        final=True,
        podman=campaign.build_authority.DEFAULT_PODMAN,
    )
    sealed = campaign.build_authority._seal_artifacts(retained, artifacts)
    self_set = set(sealed)
    if self_set != set(campaign.build_authority.AUTHORITY_FILES):
        raise AssertionError(f"unexpected fake authority files: {self_set}")
    for name, raw in sealed.items():
        (authority / name).write_bytes(raw)
    return retained


def _fake_launch_authority(
    root: Path,
    authority_dir: Path,
    receipt: dict,
    *,
    action: str = "run",
    jobs: int | None = 1,
    require_accepted: bool = True,
) -> tuple[Path, dict, dict]:
    build_record = campaign._build_authority_record(authority_dir, receipt)
    container_layout = campaign._campaign_container_layout(build_record)
    normalized = campaign._normalized_campaign_argv(
        action,
        jobs,
        require_accepted=require_accepted,
        container_layout=container_layout,
    )
    runtime = {
        "schema": campaign.CAMPAIGN_RUNTIME_SCHEMA,
        "image": copy.deepcopy(receipt["runtime"]["image"]),
        "podman": copy.deepcopy(receipt["runtime"]["podman"]),
        "normalized_argv": normalized,
        "normalized_argv_sha256": campaign.compact_json_digest(normalized),
    }
    inputs = {
        "source": copy.deepcopy(build_record["source"]),
        "build_authority": copy.deepcopy(build_record),
        "mounts": campaign._campaign_mounts(
            action, container_layout=container_layout
        ),
    }
    if action == "run":
        inputs.update(
            {
                "juliet": {"file_count": 1, "manifest_sha256": "6" * 64},
                "juliet_archive": campaign._official_corpus_identity(),
                "libarchive": {
                    "checkout": campaign._resource_checkout_identity(),
                    "tree": {
                        "file_count": 1,
                        "manifest_sha256": "7" * 64,
                    },
                },
            }
        )
    else:
        inputs["package_raw" if action == "assemble" else "package"] = {
            "file_count": 1,
            "manifest_sha256": "8" * 64,
        }
    launch = campaign._launch_payload(
        action,
        jobs,
        build_record,
        runtime,
        inputs,
        require_accepted=require_accepted,
    )
    path = root / f"{action}-{campaign.CAMPAIGN_LAUNCH_NAME}"
    campaign.write_json(path, launch)
    return path, launch, build_record


class QualityFloorCampaignTest(unittest.TestCase):
    def _collector(self, *_args, **_kwargs):
        return copy.deepcopy(_accepted_observations())

    def _raw_parser_patches(self, *, resource_from_raw: bool = False):
        rules, clean, negatives, used = _accepted_observations()
        juliet_rows = [row for row in rules if row["id"] != "resource-leak"]
        resource_row = next(row for row in rules if row["id"] == "resource-leak")

        def collect_resource(raw_root, _authority, **_kwargs):
            row = copy.deepcopy(resource_row)
            if resource_from_raw and (
                raw_root / "resource" / "raw.json"
            ).read_text(encoding="utf-8") != "raw resource/raw.json\n":
                row["diagnostics"]["false_positives"] = 1
            return row, copy.deepcopy(used["resource"])

        return (
            mock.patch.object(
                campaign,
                "collect_juliet",
                return_value=(copy.deepcopy(juliet_rows), copy.deepcopy(used["juliet"])),
            ),
            mock.patch.object(
                campaign, "collect_resource", side_effect=collect_resource
            ),
            mock.patch.object(
                campaign,
                "collect_clean_corpus",
                return_value=(copy.deepcopy(clean), copy.deepcopy(used["clean_corpus"])),
            ),
            mock.patch.object(
                campaign,
                "collect_requested_tu_negatives",
                return_value=(
                    copy.deepcopy(negatives),
                    copy.deepcopy(used["requested_tu_negatives"]),
                ),
            ),
        )

    def test_historical_source_authority_skips_only_current_tree_equality(self) -> None:
        determinism = campaign.build_authority.determinism
        recorded = {
            "revision": "a" * 40,
            "manifest_sha256": "b" * 64,
            "file_count": 7,
        }
        with mock.patch.object(
            determinism.subprocess,
            "run",
            return_value=mock.Mock(returncode=0),
        ), mock.patch.object(
            determinism,
            "source_manifest_at_revision",
            return_value=recorded,
        ), mock.patch.object(
            determinism,
            "source_manifest",
            side_effect=AssertionError("historical mode read current source"),
        ) as current:
            determinism._verify_source_authority(
                recorded,
                ROOT,
                "historical fixture",
                require_current_source=False,
            )
        current.assert_not_called()

    def test_current_source_authority_still_rejects_descendant_drift(self) -> None:
        determinism = campaign.build_authority.determinism
        recorded = {
            "revision": "a" * 40,
            "manifest_sha256": "b" * 64,
            "file_count": 7,
        }
        current = {**recorded, "manifest_sha256": "c" * 64}
        with mock.patch.object(
            determinism.subprocess,
            "run",
            return_value=mock.Mock(returncode=0),
        ), mock.patch.object(
            determinism,
            "source_manifest_at_revision",
            return_value=recorded,
        ), mock.patch.object(
            determinism, "source_manifest", return_value=current
        ), self.assertRaisesRegex(
            determinism.QualificationError, "current repository"
        ):
            determinism._verify_source_authority(
                recorded, ROOT, "current fixture"
            )

    def test_historical_source_authority_rejects_nonancestor_and_revision_drift(self) -> None:
        determinism = campaign.build_authority.determinism
        recorded = {
            "revision": "a" * 40,
            "manifest_sha256": "b" * 64,
            "file_count": 7,
        }
        with mock.patch.object(
            determinism.subprocess,
            "run",
            return_value=mock.Mock(returncode=1),
        ), self.assertRaisesRegex(
            determinism.QualificationError, "not an ancestor"
        ):
            determinism._verify_source_authority(
                recorded,
                ROOT,
                "historical fixture",
                require_current_source=False,
            )
        with mock.patch.object(
            determinism.subprocess,
            "run",
            return_value=mock.Mock(returncode=0),
        ), mock.patch.object(
            determinism,
            "source_manifest_at_revision",
            return_value={**recorded, "manifest_sha256": "d" * 64},
        ), self.assertRaisesRegex(
            determinism.QualificationError, "recorded revision"
        ):
            determinism._verify_source_authority(
                recorded,
                ROOT,
                "historical fixture",
                require_current_source=False,
            )

    def test_historical_source_material_comes_from_recorded_git_blobs(self) -> None:
        blobs = {
            relative: f"recorded {relative}\n".encode("utf-8")
            for relative in (
                *campaign.AUTHORITY_INPUT_PATHS,
                campaign.CAPABILITY_REGISTRY_RELATIVE,
            )
        }
        with mock.patch.object(
            campaign.build_authority.determinism,
            "_git_blob",
            side_effect=lambda _root, _revision, relative: blobs[relative],
        ) as git_blob:
            material = campaign._source_authority_material(
                ROOT, revision="a" * 40
            )
        self.assertEqual(
            material["scripts"],
            {
                relative: hashlib.sha256(blobs[relative]).hexdigest()
                for relative in campaign.AUTHORITY_INPUT_PATHS
            },
        )
        self.assertEqual(
            material["mutation_manifest"],
            blobs["scripts/quality_floor_resource_mutations.json"],
        )
        self.assertEqual(
            material["capability_registry"],
            blobs[campaign.CAPABILITY_REGISTRY_RELATIVE],
        )
        self.assertEqual(
            git_blob.call_count, len(campaign.AUTHORITY_INPUT_PATHS) + 1
        )

    def test_campaign_source_projection_matches_build_authority_manifest(self) -> None:
        build_source = campaign.build_authority.determinism.source_manifest(ROOT)
        self.assertEqual(
            campaign._source_identity(require_clean=False),
            {
                "revision": build_source["revision"],
                "manifest_sha256": build_source["manifest_sha256"],
            },
        )
        self.assertIn(
            "scripts/run_determinism_qualification.py",
            campaign.AUTHORITY_INPUT_PATHS,
        )
        self.assertIn(
            "scripts/podman-config/containers/mounts.conf",
            campaign.AUTHORITY_INPUT_PATHS,
        )

    def test_quality_evidence_is_byte_preserved_by_git_attributes(self) -> None:
        relative = "docs/evidence/phase10/quality/example.bin"
        attributes = campaign._git(
            ROOT, "check-attr", "text", "diff", "--", relative
        ).splitlines()
        self.assertEqual(
            attributes,
            [
                f"{relative}: text: unset",
                f"{relative}: diff: unset",
            ],
        )

    def test_accepted_assemble_and_verify_use_real_bundle_file_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = temporary_root(directory) / "package"
            package.mkdir()
            _write_fake_raw(package)
            binary, build_dir, analyzer = _fake_build(temporary_root(directory))
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            build_receipt = _fake_build_receipt(source, analyzer)
            _seal_fake_authority(package, source, analyzer, build_receipt)
            verifier = mock.Mock(return_value=build_receipt)
            patches = (
                mock.patch.object(
                    campaign, "_collect_observations", side_effect=self._collector
                ),
                mock.patch.object(campaign, "_source_identity", return_value=source),
            )
            with patches[0], patches[1]:
                receipt = campaign.assemble_package(
                    package,
                    build_dir,
                    build_verifier=verifier,
                    require_clean_source=False,
                )
                self.assertEqual(receipt["status"], "accepted")
                verified = campaign.verify_package(
                    package,
                    build_dir,
                    build_verifier=verifier,
                    require_accepted=True,
                    require_clean_source=False,
                )
            self.assertEqual(verified, receipt)
            bundles = sorted((package / "bundles").rglob("*.json"))
            self.assertEqual(len(bundles), 18)
            required_authority_paths = {
                f"raw/{campaign.AUTHORITY_NAME}",
                f"raw/{campaign.CAMPAIGN_LAUNCH_NAME}",
                *{
                    f"raw/{campaign.BUILD_AUTHORITY_RAW_DIR}/{name}"
                    for name in campaign.build_authority.AUTHORITY_FILES
                },
            }
            for bundle in bundles:
                payload = json.loads(bundle.read_text(encoding="utf-8"))
                artifact_paths = {item["path"] for item in payload["artifacts"]}
                self.assertTrue(required_authority_paths.issubset(artifact_paths))
                self.assertEqual(
                    payload["authority"]["execution_authority"],
                    json.loads(
                        (package / "raw" / campaign.AUTHORITY_NAME).read_text(
                            encoding="utf-8"
                        )
                    )["execution_authority"],
                )
            manifest = (package / quality.RAW_MANIFEST_NAME).read_text(
                encoding="utf-8"
            )
            retained_input = json.loads(
                (package / "quality-floor-input.json").read_text(encoding="utf-8")
            )
            evidence_hashes = [row["raw_sha256"] for row in retained_input["rules"]]
            evidence_hashes.extend(
                row["raw_sha256"]
                for row in retained_input["clean_corpus"]["cases"]
            )
            evidence_hashes.extend(
                row["raw_sha256"]
                for row in retained_input["requested_tu_negatives"]["cases"]
            )
            self.assertEqual(len(evidence_hashes), len(set(evidence_hashes)))
            for digest in evidence_hashes:
                self.assertEqual(manifest.count(digest), 1)
                self.assertTrue(any(campaign.sha256_file(path) == digest for path in bundles))

    def test_offline_retained_verifier_passes_without_build_or_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            package.mkdir()
            _write_fake_raw(package)
            _binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _fake_build_receipt(source, analyzer)
            receipt = _write_structural_build_authority(
                package / "raw" / campaign.BUILD_AUTHORITY_RAW_DIR,
                receipt,
            )
            _seal_fake_authority(package, source, analyzer, receipt)
            parsers = self._raw_parser_patches()
            with parsers[0], parsers[1], parsers[2], parsers[3], \
                    mock.patch.object(
                        campaign, "_source_identity", return_value=source
                    ):
                expected = campaign.assemble_package(
                    package,
                    build_dir,
                    build_verifier=mock.Mock(return_value=receipt),
                    require_clean_source=False,
                )
            shutil.rmtree(build_dir)
            parsers = self._raw_parser_patches()
            with parsers[0], parsers[1], parsers[2], parsers[3], \
                    mock.patch.object(
                        campaign,
                        "_verify_retained_source_authority",
                        return_value=source,
                    ), mock.patch.object(
                        campaign,
                        "_binary_identity",
                        side_effect=AssertionError("offline verifier executed analyzer"),
                    ), mock.patch.object(
                        campaign.build_authority,
                        "verify_authority",
                        side_effect=AssertionError("offline verifier launched Podman"),
                    ), mock.patch.object(
                        campaign.build_authority,
                        "_runtime_authority",
                        side_effect=AssertionError("offline verifier inspected Podman"),
                    ):
                retained = campaign.verify_retained_package(
                    package,
                    require_accepted=True,
                )
            self.assertEqual(retained, expected)
            self.assertNotIn(
                "build_dir",
                __import__("inspect").signature(
                    campaign.verify_retained_package
                ).parameters,
            )

            for name in ("receipt.json", "receipt.json.sha256"):
                with self.subTest(top_level_symlink=name):
                    retained_bytes = (package / name).read_bytes()
                    external = root / f"external-{name}"
                    external.write_bytes(retained_bytes)
                    (package / name).unlink()
                    (package / name).symlink_to(external)
                    with self.assertRaisesRegex(
                        campaign.CampaignError, "missing or unsafe"
                    ):
                        campaign.verify_retained_package(package)
                    (package / name).unlink()
                    (package / name).write_bytes(retained_bytes)

            for index, relative in enumerate(
                (
                    "receipt.json",
                    "raw/resource/raw.json",
                    "bundles/rules/resource-leak.json",
                )
            ):
                with self.subTest(external_hardlink=relative):
                    target = package / relative
                    external = root / f"external-hardlink-{index}"
                    target.rename(external)
                    os.link(external, target)
                    with self.assertRaisesRegex(
                        campaign.CampaignError,
                        "externally aliased hard link",
                    ):
                        campaign.verify_retained_package(package)
                    target.unlink()
                    external.rename(target)

            operator = (
                package
                / "raw"
                / campaign.BUILD_AUTHORITY_RAW_DIR
                / "operator.log"
            )
            operator.write_bytes(operator.read_bytes() + b"tampered\n")
            with self.assertRaisesRegex(
                campaign.CampaignError, "build authority rejected"
            ):
                campaign.verify_retained_package(package)

    def test_p10_09_retained_build_authority_static_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            _binary, _build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _fake_build_receipt(
                source, analyzer, container_layout="p10-09"
            )
            retained = _write_structural_build_authority(
                root / "build-authority", receipt
            )
            record, verified = (
                campaign._verify_retained_build_authority_static(
                    root / "build-authority"
                )
            )
            self.assertEqual(verified, retained)
            self.assertEqual(
                campaign._campaign_container_layout(record), "p10-09"
            )

    def test_offline_verifier_rejects_favorable_resigned_raw_semantic_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            package.mkdir()
            _write_fake_raw(package)
            _binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _write_structural_build_authority(
                package / "raw" / campaign.BUILD_AUTHORITY_RAW_DIR,
                _fake_build_receipt(source, analyzer),
            )
            _seal_fake_authority(package, source, analyzer, receipt)
            verifier = mock.Mock(return_value=receipt)
            parsers = self._raw_parser_patches()
            with parsers[0], parsers[1], parsers[2], parsers[3], \
                    mock.patch.object(
                        campaign, "_source_identity", return_value=source
                    ):
                campaign.assemble_package(
                    package,
                    build_dir,
                    build_verifier=verifier,
                    require_clean_source=False,
                )

            target = package / "raw" / "resource" / "raw.json"
            target.write_text("semantic false positive\n", encoding="utf-8")
            authority_path = package / "raw" / campaign.AUTHORITY_NAME
            authority = campaign.strict_json(authority_path)
            authority["raw_artifacts"] = campaign._raw_artifact_summary(
                package / "raw"
            )
            campaign.write_json(authority_path, authority)
            shutil.rmtree(package / "bundles")
            for name in (
                quality.RAW_MANIFEST_NAME,
                "quality-floor-input.json",
                "receipt.json",
                "receipt.json.sha256",
            ):
                (package / name).unlink()

            # Model an attacker re-signing every derived layer with the old,
            # favorable projection despite changed raw semantics.
            parsers = self._raw_parser_patches(resource_from_raw=False)
            with parsers[0], parsers[1], parsers[2], parsers[3], \
                    mock.patch.object(
                        campaign, "_source_identity", return_value=source
                    ):
                forged = campaign.assemble_package(
                    package,
                    build_dir,
                    build_verifier=verifier,
                    require_clean_source=False,
                )
            self.assertEqual(forged["status"], "accepted")

            external = root / "externally-aliased-favorable-raw.json"
            target.rename(external)
            os.link(external, target)
            with self.assertRaisesRegex(
                campaign.CampaignError,
                "externally aliased hard link",
            ):
                campaign.verify_retained_package(package)
            target.unlink()
            external.rename(target)

            semantic_parsers = self._raw_parser_patches(resource_from_raw=True)
            with semantic_parsers[0], semantic_parsers[1], semantic_parsers[2], \
                    semantic_parsers[3], mock.patch.object(
                        campaign,
                        "_verify_retained_source_authority",
                        return_value=source,
                    ), self.assertRaisesRegex(
                        campaign.CampaignError, "bundle evidence|raw-derived"
                    ):
                campaign.verify_retained_package(package)

    def test_verify_rederives_bundle_and_rejects_raw_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = temporary_root(directory) / "package"
            package.mkdir()
            _write_fake_raw(package)
            binary, build_dir, analyzer = _fake_build(temporary_root(directory))
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            build_receipt = _fake_build_receipt(source, analyzer)
            _seal_fake_authority(package, source, analyzer, build_receipt)
            verifier = mock.Mock(return_value=build_receipt)
            with mock.patch.object(
                campaign, "_collect_observations", side_effect=self._collector
            ), mock.patch.object(
                campaign, "_source_identity", return_value=source
            ):
                campaign.assemble_package(
                    package,
                    build_dir,
                    build_verifier=verifier,
                    require_clean_source=False,
                )
                target = package / "raw" / "resource" / "raw.json"
                target.write_text("tampered\n", encoding="utf-8")
                (package / quality.RAW_MANIFEST_NAME).write_bytes(
                    campaign._raw_manifest_bytes(package)
                )
                with self.assertRaisesRegex(
                    campaign.CampaignError, "authority|bundle evidence"
                ):
                    campaign.verify_package(
                        package,
                        build_dir,
                        build_verifier=verifier,
                        require_clean_source=False,
                    )

    def test_assemble_requires_completed_preexisting_raw_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = temporary_root(directory) / "package"
            package.mkdir()
            _write_fake_raw(package)
            binary, build_dir, _analyzer = _fake_build(temporary_root(directory))
            verifier = mock.Mock(side_effect=AssertionError("must not verify"))
            with self.assertRaisesRegex(campaign.CampaignError, "authority"):
                campaign.assemble_package(
                    package,
                    build_dir,
                    build_verifier=verifier,
                    require_clean_source=False,
                )
            self.assertFalse((package / "bundles").exists())
            self.assertFalse((package / campaign.quality.RAW_MANIFEST_NAME).exists())

    def test_raw_authority_rejects_binary_mix_stale_bytes_and_bad_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = temporary_root(directory) / "package"
            package.mkdir()
            _write_fake_raw(package)
            binary, build_dir, analyzer = _fake_build(temporary_root(directory))
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            build_receipt = _fake_build_receipt(source, analyzer)
            authority = _seal_fake_authority(
                package, source, analyzer, build_receipt
            )
            with mock.patch.object(
                campaign, "_source_identity", return_value=source
            ), mock.patch.object(
                campaign,
                "_binary_identity",
                return_value={**analyzer, "binary_sha256": "d" * 64},
            ), self.assertRaisesRegex(campaign.CampaignError, "binary mismatch"):
                campaign._validate_raw_authority(
                    package,
                    build_dir,
                    build_verifier=mock.Mock(return_value=build_receipt),
                    require_clean_source=False,
                    exact_source_revision=True,
                )

            with mock.patch.object(
                campaign, "_source_identity", return_value=source
            ), mock.patch.object(
                campaign, "_binary_identity", return_value=analyzer
            ):
                (package / "raw" / "resource" / "raw.json").write_text(
                    "mixed run\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(campaign.CampaignError, "artifact authority"):
                    campaign._validate_raw_authority(
                        package,
                        build_dir,
                        build_verifier=mock.Mock(return_value=build_receipt),
                        require_clean_source=False,
                        exact_source_revision=True,
                    )

                (package / "raw" / "resource" / "raw.json").write_text(
                    "raw resource/raw.json\n", encoding="utf-8"
                )
                authority["run"]["completed_at"] = "2026-01-01T00:00:00Z"
                authority["run"]["started_at"] = "2026-01-02T00:00:00Z"
                campaign.write_json(
                    package / "raw" / campaign.AUTHORITY_NAME, authority
                )
                with self.assertRaisesRegex(campaign.CampaignError, "precedes"):
                    campaign._validate_raw_authority(
                        package,
                        build_dir,
                        build_verifier=mock.Mock(return_value=build_receipt),
                        require_clean_source=False,
                        exact_source_revision=True,
                    )

    def test_retained_build_authority_is_publicly_reverified_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            package.mkdir()
            _write_fake_raw(package)
            binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _fake_build_receipt(source, analyzer)
            authority = _seal_fake_authority(package, source, analyzer, receipt)
            retained = package / "raw" / campaign.BUILD_AUTHORITY_RAW_DIR
            public_verify = mock.Mock(return_value=receipt)
            with mock.patch.object(
                campaign, "_source_identity", return_value=source
            ):
                verified = campaign._validate_raw_authority(
                    package,
                    build_dir,
                    build_verifier=public_verify,
                    require_clean_source=False,
                    exact_source_revision=True,
                )
            self.assertEqual(
                verified["analyzer_build_authority"],
                authority["analyzer_build_authority"],
            )
            public_verify.assert_called_once_with(retained, ROOT, build_dir)

    def test_build_authority_rejects_wrong_source_analyzer_and_stale_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            package.mkdir()
            _write_fake_raw(package)
            binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _fake_build_receipt(source, analyzer)
            _seal_fake_authority(package, source, analyzer, receipt)
            cases = (
                (
                    "wrong source",
                    {
                        **receipt,
                        "source": {**receipt["source"], "revision": "c" * 40},
                    },
                    "source differs",
                ),
                (
                    "wrong analyzer",
                    {
                        **receipt,
                        "analyzer": {**receipt["analyzer"], "sha256": "d" * 64},
                    },
                    "analyzer differs",
                ),
                (
                    "wrong analyzer version",
                    {
                        **receipt,
                        "analyzer": {
                            **receipt["analyzer"],
                            "version": "CodeSkeptic stale",
                        },
                    },
                    "analyzer differs",
                ),
                (
                    "stale identity",
                    {**receipt, "build_identity_sha256": "3" * 64},
                    "identity mismatch",
                ),
            )
            for label, returned, error in cases:
                with self.subTest(label=label), mock.patch.object(
                    campaign, "_source_identity", return_value=source
                ), self.assertRaisesRegex(campaign.CampaignError, error):
                    campaign._validate_raw_authority(
                        package,
                        build_dir,
                        build_verifier=mock.Mock(return_value=returned),
                        require_clean_source=False,
                        exact_source_revision=True,
                    )

    def test_missing_or_tampered_retained_build_authority_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            package.mkdir()
            _write_fake_raw(package)
            binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _fake_build_receipt(source, analyzer)
            _seal_fake_authority(package, source, analyzer, receipt)
            retained = package / "raw" / campaign.BUILD_AUTHORITY_RAW_DIR
            target = retained / "operator.log"
            original = target.read_bytes()
            target.unlink()
            with mock.patch.object(
                campaign, "_source_identity", return_value=source
            ), self.assertRaisesRegex(campaign.CampaignError, "file set"):
                campaign._validate_raw_authority(
                    package,
                    build_dir,
                    build_verifier=mock.Mock(return_value=receipt),
                    require_clean_source=False,
                    exact_source_revision=True,
                )

            target.write_bytes(original + b"tampered\n")
            with mock.patch.object(
                campaign, "_source_identity", return_value=source
            ), self.assertRaisesRegex(campaign.CampaignError, "identity mismatch"):
                campaign._validate_raw_authority(
                    package,
                    build_dir,
                    build_verifier=mock.Mock(return_value=receipt),
                    require_clean_source=False,
                    exact_source_revision=True,
                )

    def test_alternate_or_symlinked_binary_is_not_the_authoritative_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _fake_build_receipt(source, analyzer)
            authority_dir = root / "authority"
            authority_dir.mkdir()
            for name in campaign.build_authority.AUTHORITY_FILES:
                (authority_dir / name).write_text(f"{name}\n", encoding="utf-8")
            alternate = root / "alternate-codeskeptic"
            shutil.copyfile(binary, alternate)
            alternate.chmod(0o755)
            linked = root / "linked-codeskeptic"
            linked.symlink_to(binary)
            for candidate in (alternate, linked):
                with self.subTest(candidate=candidate.name), self.assertRaisesRegex(
                    campaign.CampaignError, "exactly build-dir|unsafe"
                ):
                    campaign._require_build_binary(candidate, build_dir)
            with self.assertRaisesRegex(campaign.CampaignError, "missing or unsafe"):
                campaign._require_build_binary(binary, root / "missing-build")

    def test_raw_validation_path_gates_binary_before_executing_it(self) -> None:
        import inspect

        self.assertNotIn(
            "binary",
            inspect.signature(campaign._validate_raw_authority).parameters,
        )
        self.assertNotIn(
            "binary", inspect.signature(campaign.verify_package).parameters
        )
        for function in (
            campaign._run_campaign_core,
            campaign._validate_raw_authority,
            campaign.assemble_package,
            campaign.verify_package,
        ):
            parameter = inspect.signature(function).parameters["build_verifier"]
            self.assertIs(parameter.default, inspect.Parameter.empty)
            self.assertFalse(
                any("skip" in name for name in inspect.signature(function).parameters)
            )
        for function in (
            campaign.run_campaign,
            campaign.assemble_campaign,
            campaign.verify_campaign,
        ):
            parameters = inspect.signature(function).parameters
            self.assertNotIn("binary", parameters)
            self.assertNotIn("compiler", parameters)

    def test_run_verifies_external_build_authority_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            binary, build_dir, _analyzer = _fake_build(root)
            source_dir = root / "source"
            source_dir.mkdir()
            authority_dir = root / "authority"
            authority_dir.mkdir()
            for name in campaign.build_authority.AUTHORITY_FILES:
                (authority_dir / name).write_text(f"{name}\n", encoding="utf-8")
            output = root / "campaign"
            with mock.patch.object(
                campaign, "_verify_outer_script_authority", return_value={}
            ), mock.patch.object(
                campaign.build_authority,
                "verify_authority",
                side_effect=campaign.build_authority.BuildAuthorityError("tampered"),
            ), self.assertRaisesRegex(campaign.CampaignError, "rejected"):
                campaign.run_campaign(
                    source_dir,
                    authority_dir,
                    build_dir,
                    root / "juliet",
                    root / "juliet.zip",
                    root / "libarchive",
                    output,
                    jobs=1,
                )
            self.assertFalse(output.exists())

    def test_build_authority_copy_is_exact_and_rejects_extra_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            published = root / "published"
            published.mkdir()
            for name in campaign.build_authority.AUTHORITY_FILES:
                (published / name).write_text(f"{name}\n", encoding="utf-8")
            raw = root / "raw"
            raw.mkdir()
            retained = campaign._copy_build_authority(published, raw)
            self.assertEqual(
                campaign._build_authority_entries(retained),
                campaign._build_authority_entries(published),
            )
            (published / "unexpected.txt").write_text("extra\n", encoding="utf-8")
            second_raw = root / "second-raw"
            second_raw.mkdir()
            with self.assertRaisesRegex(campaign.CampaignError, "file set"):
                campaign._copy_build_authority(published, second_raw)
            self.assertFalse(
                (second_raw / campaign.BUILD_AUTHORITY_RAW_DIR).exists()
            )

    def test_operator_binding_rejects_a_different_run(self) -> None:
        source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
        analyzer = {"version": "CodeSkeptic test", "binary_sha256": "c" * 64}
        authority = campaign._new_raw_authority(
            source,
            analyzer,
            {"build_identity_sha256": "d" * 64},
            {"schema": campaign.EXECUTION_AUTHORITY_SCHEMA},
        )
        operator = {"authority": campaign._authority_binding(authority)}
        campaign._require_operator_authority(operator, authority, "operator")
        operator["authority"]["run_id"] = str(campaign.uuid.uuid4())
        with self.assertRaisesRegex(campaign.CampaignError, "mixed campaign"):
            campaign._require_operator_authority(operator, authority, "operator")

    def test_output_overlap_and_symlink_are_rejected_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            protected = root / "input"
            protected.mkdir()
            descendant = protected / "output"
            with self.assertRaisesRegex(campaign.CampaignError, "overlaps"):
                campaign._prepare_output(
                    descendant, protected_inputs=((protected.resolve(), "input"),)
                )
            self.assertFalse(descendant.exists())

            empty = root / "empty"
            empty.mkdir()
            linked = root / "linked-output"
            linked.symlink_to(empty, target_is_directory=True)
            with self.assertRaisesRegex(campaign.CampaignError, "absent or an empty"):
                campaign._prepare_output(linked, protected_inputs=())

            public_empty = root / "public-empty"
            public_empty.mkdir()
            with self.assertRaisesRegex(campaign.CampaignError, "absent"):
                campaign._validate_output_target(public_empty, ())
            self.assertTrue(public_empty.is_dir())

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "atomic package exchange requires Linux renameat2",
    )
    def test_existing_package_replacement_uses_atomic_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            staged = root / "staged"
            (package / "raw").mkdir(parents=True)
            (package / "raw" / "old.txt").write_text("old\n", encoding="utf-8")
            (staged / "raw").mkdir(parents=True)
            (staged / "bundles").mkdir()
            (staged / "raw" / "new.txt").write_text("new raw\n", encoding="utf-8")
            (staged / "bundles" / "new.txt").write_text(
                "new bundle\n", encoding="utf-8"
            )
            (staged / quality.RAW_MANIFEST_NAME).write_text(
                "new manifest\n", encoding="utf-8"
            )
            (staged / "quality-floor-input.json").write_text(
                "{}\n", encoding="utf-8"
            )
            (staged / "receipt.json").write_text("new\n", encoding="utf-8")
            (staged / "receipt.json.sha256").write_text(
                campaign.sha256_file(staged / "receipt.json") + "\n",
                encoding="ascii",
            )
            expected = campaign._tree_identity(package / "raw", "raw campaign")
            expected_staged = campaign._tree_identity(
                staged, "independently verified staged campaign"
            )
            campaign._replace_package(
                staged, package, expected, expected_staged
            )
            self.assertEqual(
                (package / "receipt.json").read_text(encoding="utf-8"), "new\n"
            )
            self.assertEqual(
                (staged / "raw" / "old.txt").read_text(encoding="utf-8"),
                "old\n",
            )

    def test_verified_tree_rejects_hardlink_injection_at_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            staged = root / "staged"
            (staged / "raw").mkdir(parents=True)
            (staged / "bundles").mkdir()
            (staged / "raw" / "evidence.bin").write_bytes(b"raw\n")
            (staged / "bundles" / "evidence.bin").write_bytes(b"bundle\n")
            (staged / quality.RAW_MANIFEST_NAME).write_bytes(b"manifest\n")
            (staged / "quality-floor-input.json").write_bytes(b"{}\n")
            (staged / "receipt.json").write_bytes(b"{}\n")
            (staged / "receipt.json.sha256").write_bytes(b"sidecar\n")
            verified = campaign._tree_identity(
                staged, "independently verified campaign package"
            )

            external = root / "outside-evidence-alias.bin"
            os.link(staged / "raw" / "evidence.bin", external)
            self.assertNotEqual(
                campaign._tree_identity(
                    staged, "campaign package at promotion boundary"
                ),
                verified,
            )
            output = root / "published"
            with self.assertRaisesRegex(
                campaign.CampaignError, "externally aliased hard link"
            ):
                campaign._promote_new_package(staged, output, verified)
            self.assertFalse(output.exists())
            self.assertTrue(staged.is_dir())

            external.unlink()
            verified = campaign._tree_identity(
                staged, "independently verified campaign package"
            )
            (staged / "raw" / "evidence.bin").write_bytes(b"evil\n")
            with self.assertRaisesRegex(
                campaign.CampaignError,
                "changed after independent verification",
            ):
                campaign._promote_new_package(staged, output, verified)
            self.assertFalse(output.exists())

    def test_atomic_replacement_rejects_post_verify_content_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            staged = root / "staged"
            (package / "raw").mkdir(parents=True)
            (package / "raw" / "old.bin").write_bytes(b"old\n")
            expected_raw = campaign._tree_identity(
                package / "raw", "raw campaign"
            )
            (staged / "raw").mkdir(parents=True)
            (staged / "bundles").mkdir()
            (staged / "raw" / "new.bin").write_bytes(b"new\n")
            (staged / "bundles" / "new.bin").write_bytes(b"bundle\n")
            (staged / quality.RAW_MANIFEST_NAME).write_bytes(b"manifest\n")
            (staged / "quality-floor-input.json").write_bytes(b"{}\n")
            (staged / "receipt.json").write_bytes(b"{}\n")
            (staged / "receipt.json.sha256").write_bytes(b"sidecar\n")
            verified = campaign._tree_identity(
                staged, "independently verified campaign package"
            )
            (staged / "bundles" / "new.bin").write_bytes(b"evil!!\n")

            with self.assertRaisesRegex(
                campaign.CampaignError,
                "changed after independent verification",
            ):
                campaign._replace_package(
                    staged, package, expected_raw, verified
                )
            self.assertEqual(
                (package / "raw" / "old.bin").read_bytes(), b"old\n"
            )
            self.assertTrue(staged.is_dir())

    def test_mini_juliet_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = temporary_root(directory)
            juliet = raw / "juliet"
            juliet.mkdir()
            relative = "C/testcases/CWE401_Memory_Leak/example.c"
            payload = {
                "schema": campaign.JULIET_INPUT_SCHEMA,
                "official_archive": {
                    "sha256": campaign.JULIET_ARCHIVE_SHA256,
                    "size": 152957342,
                },
                "case_counts": dict(campaign.JULIET_CASE_COUNTS),
                "entry_count": 1,
                "entries": [{"path": relative, "sha256": "a" * 64}],
                "digest": campaign.compact_json_digest(
                    [{"path": relative, "sha256": "a" * 64}]
                ),
            }
            campaign.write_json(juliet / "input-manifest.json", payload)
            with self.assertRaisesRegex(campaign.CampaignError, "schema|surface"):
                campaign._validate_juliet_input_manifest(raw, {relative})

    def test_mutation_manifest_is_hash_bound_and_reconstructs_exact_deletions(self) -> None:
        config = campaign._load_mutations()
        self.assertEqual(config["project"]["translation_units"], 123)
        self.assertEqual(
            config["project"]["translation_unit_sha256"],
            "1d8306b703571b7c88ed8e3c549950d508e1eb3259f43d7eca34fa7f0a934b10",
        )
        expected_before = {
            "3b1e2be6d903246ca3023af1ff215f10bb01293a037423a6da89ea6a2c540e46",
            "86bea9ba904f3668571754f00a1bae688bf8e154afe4c5d2df85cfebb8d3ba83",
            "34821e8482d43b87a3f5ae4822015c65029c6f9bb61ed259ffbc18d8a7d4830c",
        }
        self.assertEqual(
            {item["before_sha256"] for item in config["mutations"]},
            expected_before,
        )
        for item in config["mutations"]:
            self.assertEqual(item["source_revision"], campaign.RESOURCE_REVISION)
            self.assertEqual(item["expected_matches"], 1)
            self.assertEqual(
                hashlib.sha256(item["before"].encode()).hexdigest(),
                item["before_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(item["replacement"].encode()).hexdigest(),
                item["replacement_sha256"],
            )
            self.assertIn("close(", item["before"])
            self.assertNotIn("close(", item["replacement"])
            self.assertNotIn("(void)", item["replacement"])

    def test_juliet_metrics_are_recomputed_from_raw_findings_and_case_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = temporary_root(directory)
            juliet = raw / "juliet"
            juliet.mkdir()
            cwe = "CWE401_Memory_Leak"
            cases = [
                f"/suite/C/testcases/{cwe}/CWE401_case_{index:02d}_01.c"
                for index in range(10)
            ]
            analysis = [*cases, "/suite/C/testcasesupport/io.c"]
            (juliet / f"files_{cwe}.txt").write_text(
                "\n".join(cases) + "\n", encoding="utf-8"
            )
            (juliet / f"analysis_{cwe}.txt").write_text(
                "\n".join(analysis) + "\n", encoding="utf-8"
            )
            diagnostics = [
                {
                    "rule_id": "memory-leak",
                    "file": cases[index],
                    "function": f"case_{index}_bad",
                    "capability_tier": "supported",
                    "blocks_verdict": True,
                }
                for index in range(8)
            ]
            diagnostics.extend(
                [
                    {
                        "rule_id": "memory-leak",
                        "file": cases[0],
                        "function": "duplicate_bad",
                        "capability_tier": "supported",
                        "blocks_verdict": True,
                    },
                    {
                        "rule_id": "memory-leak",
                        "file": cases[8],
                        "function": "clean_good",
                        "capability_tier": "supported",
                        "blocks_verdict": True,
                    },
                ]
            )
            report = {"exit_code": 1, "diagnostics": diagnostics}
            (juliet / f"findings_{cwe}.json").write_bytes(
                campaign.canonical_json(report)
            )
            (juliet / f"log_{cwe}.txt").write_text("raw log\n", encoding="utf-8")
            with mock.patch.object(
                campaign,
                "_report_semantic",
                return_value=(report, {"coverage": {}}),
            ), mock.patch.object(
                campaign, "_validate_juliet_compile_db"
            ):
                row, _bundle, _requested = campaign._juliet_rule_row(
                    raw, cwe, "memory-leak"
                )
            self.assertEqual(row["diagnostics"], {
                "true_positives": 9, "false_positives": 1
            })
            self.assertEqual(row["cases"]["files"], 10)
            self.assertEqual(
                row["cases"]["misses"],
                {"total": 2, "addressable": 2, "model_gap": 0, "out_of_scope": 0},
            )

    def test_official_corpus_and_resource_pins_are_exact(self) -> None:
        self.assertIn(
            "scripts/analyzer_build_authority.py",
            campaign.AUTHORITY_INPUT_PATHS,
        )
        self.assertEqual(
            campaign.JULIET_ARCHIVE_SHA256,
            "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb",
        )
        self.assertEqual(campaign.JULIET_ENTRY_COUNT, 2392)
        self.assertEqual(
            campaign.JULIET_INPUT_MANIFEST_SHA256,
            "4b94a809a8d0f85c421d9622c6c8b15e1663ab489027c5d332d5fdbe4d6baace",
        )
        self.assertEqual(
            campaign.JULIET_CASE_COUNTS,
            {
                "CWE401_Memory_Leak": 397,
                "CWE415_Double_Free": 399,
                "CWE416_Use_After_Free": 397,
                "CWE369_Divide_by_Zero": 397,
                "CWE476_NULL_Pointer_Dereference": 400,
                "CWE190_Integer_Overflow": 401,
            },
        )
        self.assertEqual(
            campaign.RESOURCE_TREE_OID,
            "7e56e62d504013b00eae01739d2fe01e45dbbe84",
        )
        self.assertEqual(
            campaign.RESOURCE_CLEAN_ENTRIES_SHA256,
            "eb4f35dbaa89f184b37a9d65c178c72dd2ac7842e94015e475db4f81c421e6ea",
        )
        self.assertEqual(
            campaign.RESOURCE_MUTATED_ENTRIES_SHA256,
            "a574a08ac5d167f76cdca18e9f51ca2ac7403b71ecd2ba135771c8930954b714",
        )

    def test_unsafe_symlink_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            target = root / "target"
            target.write_text("target\n", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(campaign.CampaignError, "unsafe"):
                campaign._regular(link, "linked input")

            real_dir = root / "real-dir"
            real_dir.mkdir()
            linked_dir = root / "linked-dir"
            linked_dir.symlink_to(real_dir, target_is_directory=True)
            with self.assertRaisesRegex(campaign.CampaignError, "unsafe"):
                campaign._directory(linked_dir, "linked directory")

    def test_credited_juliet_diagnostic_must_be_supported_and_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = temporary_root(directory)
            juliet = raw / "juliet"
            juliet.mkdir()
            cwe = "CWE401_Memory_Leak"
            case = f"/suite/C/testcases/{cwe}/CWE401_case_01.c"
            support = "/suite/C/testcasesupport/io.c"
            (juliet / f"files_{cwe}.txt").write_text(case + "\n", encoding="utf-8")
            (juliet / f"analysis_{cwe}.txt").write_text(
                case + "\n" + support + "\n", encoding="utf-8"
            )
            diagnostic = {
                "rule_id": "memory-leak",
                "file": case,
                "function": "case_bad",
                "capability_tier": "experimental",
                "blocks_verdict": True,
            }
            report = {"exit_code": 1, "diagnostics": [diagnostic]}
            (juliet / f"findings_{cwe}.json").write_bytes(
                campaign.canonical_json(report)
            )
            (juliet / f"log_{cwe}.txt").write_text("raw\n", encoding="utf-8")
            with mock.patch.object(
                campaign, "_report_semantic", return_value=(report, {"coverage": {}})
            ), mock.patch.object(
                campaign, "_validate_juliet_compile_db"
            ), self.assertRaisesRegex(campaign.CampaignError, "supported.*blocking"):
                campaign._juliet_rule_row(raw, cwe, "memory-leak")

    def test_resource_compile_database_requires_exact_clang_surface(self) -> None:
        relatives = ["libarchive/a.c", "libarchive/b.c"]
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "compile_commands.json"
            valid = []
            for relative in relatives:
                for suffix in ("one", "two"):
                    source = f"/source/{relative}"
                    valid.append(
                        {
                            "directory": f"/build/{suffix}",
                            "file": source,
                            "command": f"/usr/bin/clang-20 -c {source}",
                        }
                    )
            path.write_bytes(campaign.canonical_json(valid))
            campaign._validate_retained_resource_compile_db(path, relatives)

            valid[0]["command"] = ""
            path.write_bytes(campaign.canonical_json(valid))
            with self.assertRaisesRegex(campaign.CampaignError, "clang"):
                campaign._validate_retained_resource_compile_db(path, relatives)

            path.write_bytes(
                campaign.canonical_json(
                    [
                        {
                            "directory": "/foreign",
                            "file": "/foreign/a.c",
                            "command": "clang -c /foreign/a.c",
                        }
                    ]
                )
            )
            with self.assertRaisesRegex(campaign.CampaignError, "surface"):
                campaign._validate_retained_resource_compile_db(path, relatives)

    def test_retained_container_paths_are_host_platform_neutral(self) -> None:
        expected = [
            "C/testcases/CWE401_Memory_Leak/case_01.c",
            "C/testcasesupport/io.c",
        ]
        report = {
            "translation_units": [
                {"phase": phase, "path": f"/juliet/{relative}"}
                for phase in ("summary-harvest", "analysis")
                for relative in expected
            ]
        }
        campaign._validate_retained_translation_unit_paths(
            report, expected, whole_program=True
        )
        self.assertEqual(
            campaign._canonical_posix_absolute_path(
                "/scratch/work/source.c", "fixture"
            ).as_posix(),
            "/scratch/work/source.c",
        )
        for invalid in (
            r"C:\scratch\work\source.c",
            "scratch/work/source.c",
            "/scratch/../source.c",
            "//scratch/source.c",
        ):
            with self.subTest(path=invalid), self.assertRaisesRegex(
                campaign.CampaignError, "canonical container path"
            ):
                campaign._canonical_posix_absolute_path(invalid, "fixture")
        for action in ("run", "assemble", "verify"):
            self.assertEqual(
                campaign._validate_campaign_mounts(
                    campaign._campaign_mounts(action), action
                ),
                campaign._campaign_mounts(action),
            )

    def test_retained_resource_paths_require_exact_compile_multiplicity(self) -> None:
        expected = ["libarchive/a.c", "libarchive/b.c"]
        receipts = [
            {"phase": phase, "path": f"/scratch/resource/{relative}"}
            for phase in ("summary-harvest", "analysis")
            for relative in expected
            for _command in range(2)
        ]
        report = {"translation_units": receipts}
        campaign._validate_retained_translation_unit_paths(
            report,
            expected,
            whole_program=True,
            expected_path_multiplicity=2,
        )

        for corrupted in (receipts[:-1], [*receipts, receipts[-1]]):
            with self.subTest(count=len(corrupted)), self.assertRaisesRegex(
                campaign.CampaignError, "paths differ"
            ):
                campaign._validate_retained_translation_unit_paths(
                    {"translation_units": corrupted},
                    expected,
                    whole_program=True,
                    expected_path_multiplicity=2,
                )

        skewed = [
            {"phase": phase, "path": f"/scratch/resource/{relative}"}
            for phase in ("summary-harvest", "analysis")
            for relative, count in ((expected[0], 3), (expected[1], 1))
            for _command in range(count)
        ]
        with self.assertRaisesRegex(campaign.CampaignError, "paths differ"):
            campaign._validate_retained_translation_unit_paths(
                {"translation_units": skewed},
                expected,
                whole_program=True,
                expected_path_multiplicity=2,
            )

    def test_retained_juliet_compile_database_is_exact_and_posix(self) -> None:
        requested = [
            campaign.PurePosixPath(
                "/juliet/C/testcases/CWE401_Memory_Leak/case_01.c"
            ),
            campaign.PurePosixPath("/juliet/C/testcasesupport/io.c"),
        ]
        relatives = [
            "C/testcases/CWE401_Memory_Leak/case_01.c",
            "C/testcasesupport/io.c",
        ]
        support_root = requested[1].parent.as_posix()
        database = [
            {
                "directory": "/",
                "file": source.as_posix(),
                "command": (
                    f"cc -x c -c {source.as_posix()} -I {support_root}"
                ),
            }
            for source in requested
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "compile_commands.json"
            path.write_bytes(campaign.canonical_json(database))
            campaign._validate_juliet_compile_db(path, requested, relatives)

            database[0]["command"] = "cc -c /alternate/source.c"
            path.write_bytes(campaign.canonical_json(database))
            with self.assertRaisesRegex(
                campaign.CampaignError, "not source-bound"
            ):
                campaign._validate_juliet_compile_db(path, requested, relatives)

    def test_stress_receipt_uses_authority_identity_and_source_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = temporary_root(directory)
            stress_root = raw / "stress"
            (stress_root / "logs").mkdir(parents=True)
            (stress_root / "reports").mkdir()
            receipt_path = stress_root / "receipt.json"
            receipt_path.write_bytes(campaign.canonical_json({"fixture": True}))
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            analyzer = {
                "version": campaign.build_authority.ANALYZER_VERSION,
                "binary_sha256": "c" * 64,
            }
            authority = {
                "schema": campaign.AUTHORITY_SCHEMA,
                "run": {"id": "00000000-0000-0000-0000-000000000001"},
                "source": source,
                "analyzer": analyzer,
                "analyzer_build_authority": {"identity": "build"},
                "execution_authority": {"identity": "execution"},
            }
            campaign.write_json(
                stress_root / "operator.json",
                {
                    "schema": campaign.OPERATOR_SCHEMA,
                    "authority": campaign._authority_binding(authority),
                    "receipt_sha256": campaign.sha256_file(receipt_path),
                },
            )

            def case(case_id, coverage):
                runs = []
                for index in (1, 2):
                    log = f"logs/{case_id}-{index}.log"
                    report = f"reports/{case_id}-{index}.json"
                    (stress_root / log).write_text("log\n", encoding="utf-8")
                    (stress_root / report).write_text("{}\n", encoding="utf-8")
                    runs.append(
                        {
                            "repetition": index,
                            "log": log,
                            "report": report,
                            "projection": {
                                "process_exit": 2,
                                "report_exit": 2,
                                "complete": False,
                                "status": "failed",
                                "coverage": coverage,
                            },
                        }
                    )
                return {"id": case_id, "runs": runs}

            retained = {
                "source": {
                    "base_commit": source["revision"],
                    "manifest": {"fixture": True},
                },
                "cases": [
                    case(campaign.RESOURCE_BROKEN_CASE, _coverage(2, 1, 1)),
                    case(campaign.RESOURCE_MISSING_CASE, _coverage(2, 1, 0)),
                ]
            }
            verifier = mock.Mock(return_value=retained)
            with mock.patch.object(
                campaign.stress,
                "verify_receipt_with_identity",
                verifier,
            ):
                rows, used = campaign.collect_requested_tu_negatives(
                    raw, None, authority
                )
            self.assertEqual([row["kind"] for row in rows], ["broken", "missing"])
            self.assertEqual(
                set(used),
                {
                    "stress/operator.json",
                    "stress/receipt.json",
                    *{
                        f"stress/{kind}/{case_id}-{index}.{extension}"
                        for case_id in (
                            campaign.RESOURCE_BROKEN_CASE,
                            campaign.RESOURCE_MISSING_CASE,
                        )
                        for index in (1, 2)
                        for kind, extension in (
                            ("logs", "log"),
                            ("reports", "json"),
                        )
                    },
                },
            )
            verifier.assert_called_once_with(
                receipt_path.resolve(),
                {
                    "sha256": analyzer["binary_sha256"],
                    "version": analyzer["version"],
                },
                expected_source_revision=source["revision"],
            )

            (stress_root / "unrecognized-extra.bin").write_bytes(b"extra\n")
            with mock.patch.object(
                campaign.stress,
                "verify_receipt_with_identity",
                return_value=retained,
            ), self.assertRaisesRegex(
                campaign.CampaignError, "incomplete or extra"
            ):
                campaign.collect_requested_tu_negatives(raw, None, authority)

            wrong_source = copy.deepcopy(retained)
            wrong_source["source"]["base_commit"] = "d" * 40
            with mock.patch.object(
                campaign.stress,
                "verify_receipt_with_identity",
                return_value=wrong_source,
            ), self.assertRaisesRegex(
                campaign.CampaignError,
                "source revision differs",
            ):
                campaign.collect_requested_tu_negatives(raw, None, authority)

    def test_resource_input_rejects_non_target_hash_and_rebased_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = temporary_root(directory)
            resource = raw / "resource"
            resource.mkdir()
            shutil.copyfile(campaign.MUTATION_PATH, resource / "mutations.json")
            paths = ["libarchive/non-target.c", "libarchive/target.c"]
            clean_target = b"clean target\n"
            mutant_target = b"mutant target\n"
            clean_target_sha = hashlib.sha256(clean_target).hexdigest()
            mutant_target_sha = hashlib.sha256(mutant_target).hexdigest()
            clean_entries = [
                {"path": paths[0], "sha256": "1" * 64},
                {"path": paths[1], "sha256": clean_target_sha},
            ]
            mutant_entries = [
                {"path": paths[0], "sha256": "1" * 64},
                {"path": paths[1], "sha256": mutant_target_sha},
            ]
            clean_digest = campaign.compact_json_digest(clean_entries)
            mutant_digest = campaign.compact_json_digest(mutant_entries)
            config = {
                "project": {
                    "revision": campaign.RESOURCE_REVISION,
                    "translation_units": 2,
                    "translation_unit_sha256": campaign.realworld.translation_unit_digest(
                        paths
                    ),
                    "source_files": {
                        paths[1]: {
                            "clean_sha256": clean_target_sha,
                            "mutated_sha256": mutant_target_sha,
                        }
                    },
                }
            }
            payload = {
                "schema": campaign.RESOURCE_INPUT_SCHEMA,
                "revision": campaign.RESOURCE_REVISION,
                "checkout": campaign._resource_checkout_identity(),
                "mutation_manifest_sha256": campaign.sha256_file(
                    resource / "mutations.json"
                ),
                "translation_units": {
                    "count": 2,
                    "sha256": config["project"]["translation_unit_sha256"],
                },
                "clean_entries": clean_entries,
                "clean_digest": clean_digest,
                "mutated_entries": mutant_entries,
                "mutated_digest": mutant_digest,
            }
            for label, content in (
                ("clean", clean_target),
                ("mutant", mutant_target),
            ):
                target = resource / "targets" / label / paths[1]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            campaign.write_json(resource / "input-manifest.json", payload)
            pins = (
                mock.patch.object(campaign, "_load_mutations", return_value=config),
                mock.patch.object(
                    campaign, "RESOURCE_CLEAN_ENTRIES_SHA256", clean_digest
                ),
                mock.patch.object(
                    campaign, "RESOURCE_MUTATED_ENTRIES_SHA256", mutant_digest
                ),
            )
            with pins[0], pins[1], pins[2]:
                campaign._resource_input(raw)
                payload["clean_entries"][0]["sha256"] = "2" * 64
                campaign.write_json(resource / "input-manifest.json", payload)
                with self.assertRaisesRegex(campaign.CampaignError, "digest mismatch"):
                    campaign._resource_input(raw)

                payload["clean_digest"] = campaign.compact_json_digest(
                    payload["clean_entries"]
                )
                campaign.write_json(resource / "input-manifest.json", payload)
                with self.assertRaisesRegex(campaign.CampaignError, "canonical checkout"):
                    campaign._resource_input(raw)

    def test_wrong_juliet_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = temporary_root(directory) / "juliet.zip"
            archive.write_bytes(b"not the official archive")
            with self.assertRaisesRegex(campaign.CampaignError, "official pinned"):
                campaign._validate_juliet_archive(archive)

    def test_main_converts_quality_and_os_errors_to_unavailable(self) -> None:
        argv = [
            "run_quality_floor_campaign.py",
            "assemble",
            "--source", "/does/not/matter",
            "--build-authority", "/does/not/matter",
            "--build-dir", "/does/not/matter",
            "--package", "/does/not/matter",
        ]
        for error in (
            campaign.CampaignError("bad build authority"),
            quality.QualityFloorError("bad receipt"),
            OSError("disk error"),
        ):
            stderr = io.StringIO()
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                campaign, "assemble_campaign", side_effect=error
            ), redirect_stderr(stderr):
                self.assertEqual(campaign.main(), 2)
            self.assertIn("QUALITY_FLOOR_CAMPAIGN_UNAVAILABLE", stderr.getvalue())

    def test_cli_requires_build_authority_and_build_directory_arguments(self) -> None:
        commands = (
            [
                "run_quality_floor_campaign.py",
                "run",
                "--source", "/tmp/source",
                "--build-dir", "/tmp/build",
                "--juliet-dir", "/tmp/juliet",
                "--juliet-archive", "/tmp/juliet.zip",
                "--libarchive-checkout", "/tmp/libarchive",
                "--output", "/tmp/output",
            ],
            [
                "run_quality_floor_campaign.py",
                "assemble",
                "--source", "/tmp/source",
                "--build-authority", "/tmp/authority",
                "--package", "/tmp/package",
            ],
            [
                "run_quality_floor_campaign.py",
                "verify",
                "--source", "/tmp/source",
                "--build-authority", "/tmp/authority",
                "--package", "/tmp/package",
            ],
        )
        for argv in commands:
            with self.subTest(action=argv[1]), mock.patch.object(
                sys, "argv", argv
            ), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                campaign.main()
            self.assertEqual(raised.exception.code, 2)

    def test_container_contract_is_offline_read_only_and_git_closed(self) -> None:
        normalized = campaign._normalized_campaign_argv("run", 4)
        environment = [
            normalized[index + 1]
            for index, token in enumerate(normalized[:-1])
            if token == "-e"
        ]
        mounts = [
            normalized[index + 1]
            for index, token in enumerate(normalized[:-1])
            if token == "-v"
        ]
        self.assertIn("--pull=never", normalized)
        self.assertEqual(
            normalized[1:7],
            [
                "--cgroup-manager=cgroupfs",
                "--conmon=/usr/bin/conmon",
                "--events-backend=none",
                "--hooks-dir=/usr/share/empty",
                "--runtime=/usr/bin/crun",
                "run",
            ],
        )
        self.assertIn("--network=none", normalized)
        self.assertIn("--read-only", normalized)
        self.assertIn("--cap-drop=all", normalized)
        self.assertIn("no-new-privileges", normalized)
        self.assertIn("--http-proxy=false", normalized)
        self.assertIn("--env-host=false", normalized)
        self.assertIn("--image-volume=ignore", normalized)
        tmpfs_index = normalized.index("--tmpfs")
        self.assertEqual(
            normalized[tmpfs_index + 1],
            "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        )
        self.assertIn(
            f"{campaign.CAMPAIGN_INNER_ENV_TOKEN_ENV}=$ENV_SHA256",
            environment,
        )
        for key, value in campaign._inner_environment().items():
            self.assertIn(f"{key}={value}", environment)
        self.assertEqual(
            {item for item in mounts if item.endswith(":rw")},
            {"$STAGE:/stage:rw", "$SCRATCH:/scratch:rw"},
        )
        self.assertTrue(all("podman.sock" not in item for item in normalized))
        image_index = normalized.index(campaign.build_authority.PINNED_IMAGE)
        self.assertEqual(
            normalized[image_index:image_index + 3],
            [
                campaign.build_authority.PINNED_IMAGE,
                "/usr/bin/python3",
                "/source/scripts/run_quality_floor_campaign.py",
            ],
        )
        assemble = campaign._normalized_campaign_argv("assemble", None)
        verify = campaign._normalized_campaign_argv("verify", None)
        self.assertNotIn("$PACKAGE:/package:ro", assemble)
        self.assertIn("$STAGE:/stage:rw", assemble)
        self.assertIn("$PACKAGE:/package:ro", verify)
        self.assertIn("$LAUNCH_DIR:/launch:ro", verify)
        self.assertNotIn("$STAGE:/stage:rw", verify)
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            command = campaign._campaign_container_command(
                "run",
                4,
                "0" * 64,
                source=root / "source",
                build_dir=root / "build",
                build_authority_dir=root / "build-authority",
                scratch=root / "scratch",
                stage=root / "stage",
                juliet_dir=root / "juliet",
                juliet_archive=root / "juliet-archive.zip",
                libarchive_checkout=root / "libarchive",
            )
        self.assertIn(f"{root / 'build'}:/build:ro", command)
        self.assertIn(
            f"{root / 'build-authority'}:/build-authority:ro", command
        )
        self.assertIn(f"{root / 'juliet'}:/juliet:ro", command)
        self.assertIn(f"{root / 'juliet-archive.zip'}:/juliet.zip:ro", command)
        self.assertFalse(any("$" in token for token in command))

    def test_p10_09_container_layout_is_inferred_from_build_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            _binary, _build_dir, analyzer = _fake_build(root)
            source_identity = {
                "revision": "a" * 40,
                "manifest_sha256": "b" * 64,
            }
            authority_dir = _write_fake_build_authority(root)
            receipt = _fake_build_receipt(
                source_identity, analyzer, container_layout="p10-09"
            )
            build_record = campaign._build_authority_record(
                authority_dir, receipt
            )
            self.assertEqual(
                campaign._campaign_container_layout(build_record), "p10-09"
            )

            with mock.patch.object(
                campaign.build_authority,
                "_runtime_authority",
                return_value=copy.deepcopy(receipt["runtime"]),
            ) as runtime_authority:
                runtime = campaign._campaign_runtime("verify", None, build_record)
            runtime_authority.assert_called_once_with(
                container_layout="p10-09"
            )
            normalized = runtime["normalized_argv"]
            self.assertEqual(
                normalized,
                campaign._normalized_campaign_argv(
                    "verify", None, container_layout="p10-09"
                ),
            )
            self.assertEqual(
                normalized[normalized.index("--workdir") + 1],
                "/authority/source",
            )
            self.assertIn(
                "GIT_CONFIG_VALUE_0=/authority/source", normalized
            )
            self.assertIn(
                "$SOURCE:/authority/source:ro", normalized
            )
            self.assertIn("$BUILD:/authority/build:ro", normalized)
            self.assertIn(
                "$BUILD_AUTHORITY:/authority/build-authority:ro", normalized
            )
            self.assertIn(
                "/authority/source/scripts/run_quality_floor_campaign.py",
                normalized,
            )
            for action, jobs in (
                ("run", 2),
                ("assemble", None),
                ("verify", None),
            ):
                with self.subTest(action=action):
                    template = campaign._normalized_campaign_argv(
                        action, jobs, container_layout="p10-09"
                    )
                    self.assertEqual(
                        template[template.index("--workdir") + 1],
                        "/authority/source",
                    )
                    self.assertIn(
                        "$SOURCE:/authority/source:ro", template
                    )
                    self.assertIn("$BUILD:/authority/build:ro", template)
                    self.assertIn(
                        "$BUILD_AUTHORITY:/authority/build-authority:ro",
                        template,
                    )
                    mounts = campaign._campaign_mounts(
                        action, container_layout="p10-09"
                    )
                    self.assertEqual(mounts["source"], "/authority/source")
                    self.assertEqual(mounts["build"], "/authority/build")
                    self.assertEqual(
                        mounts["build_authority"],
                        "/authority/build-authority",
                    )

            source_dir = root / "source"
            source_dir.mkdir()
            package = root / "package"
            package.mkdir()
            (package / "evidence").write_text("sealed\n", encoding="utf-8")
            with mock.patch.object(
                campaign, "_source_identity", return_value=source_identity
            ):
                inputs = campaign._campaign_input_identity(
                    "verify",
                    source=source_dir,
                    build_record=build_record,
                    package=package,
                )
            self.assertEqual(
                inputs["mounts"]["source"], "/authority/source"
            )
            self.assertEqual(inputs["mounts"]["build"], "/authority/build")
            self.assertEqual(
                inputs["mounts"]["build_authority"],
                "/authority/build-authority",
            )

            command = campaign._campaign_container_command(
                "verify",
                None,
                "0" * 64,
                source=root / "source",
                build_dir=root / "build",
                build_authority_dir=root / "build-authority",
                scratch=root / "scratch",
                package=root / "package",
                launch_dir=root / "launch",
                build_record=build_record,
            )
            self.assertIn(
                f"{root / 'source'}:/authority/source:ro", command
            )
            self.assertIn(f"{root / 'build'}:/authority/build:ro", command)
            self.assertIn(
                f"{root / 'build-authority'}:/authority/build-authority:ro",
                command,
            )
            self.assertIn(
                "GIT_CONFIG_VALUE_0=/authority/source", command
            )

        environment = {
            **campaign._inner_environment("p10-09"),
            campaign.CAMPAIGN_INNER_ENV_TOKEN_ENV: campaign.compact_json_digest(
                campaign._inner_environment("p10-09")
            ),
            campaign.CAMPAIGN_INNER_TOKEN_ENV: "1" * 64,
            "HOSTNAME": "0123456789ab",
            "container": "podman",
        }
        with mock.patch.object(
            campaign, "ROOT", Path("/authority/source")
        ), mock.patch.object(
            campaign,
            "__file__",
            "/authority/source/scripts/run_quality_floor_campaign.py",
        ), mock.patch.dict(campaign.os.environ, environment, clear=True):
            self.assertEqual(
                campaign._validate_inner_paths(
                    "run",
                    source=Path("/authority/source"),
                    build_dir=Path("/authority/build"),
                    build_authority_dir=Path("/authority/build-authority"),
                    package=Path("/stage/package"),
                    launch_authority=Path(
                        f"/stage/{campaign.CAMPAIGN_LAUNCH_NAME}"
                    ),
                    juliet_dir=Path("/juliet"),
                    juliet_archive=Path("/juliet.zip"),
                    libarchive_checkout=Path("/libarchive"),
                ),
                "p10-09",
            )

    def test_p10_09_outer_recheck_preserves_inferred_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            _binary, _build_dir, analyzer = _fake_build(root)
            source_identity = {
                "revision": "a" * 40,
                "manifest_sha256": "b" * 64,
            }
            authority_dir = _write_fake_build_authority(root)
            receipt = _fake_build_receipt(
                source_identity, analyzer, container_layout="p10-09"
            )
            build_record = campaign._build_authority_record(
                authority_dir, receipt
            )
            with mock.patch.object(
                campaign.build_authority,
                "_runtime_authority",
                return_value=copy.deepcopy(receipt["runtime"]),
            ):
                runtime = campaign._campaign_runtime(
                    "verify", None, build_record
                )
            inputs = {"exact": "p10-09"}
            snapshot = {
                "scripts": {"script": "identity"},
                "build_record": build_record,
                "container_layout": "p10-09",
                "source": root,
                "runtime": runtime,
                "inputs": inputs,
                "launch": {"jobs": None},
            }
            with mock.patch.object(
                campaign,
                "_verify_outer_script_authority",
                return_value=snapshot["scripts"],
            ), mock.patch.object(
                campaign.build_authority,
                "_runtime_authority",
                return_value=copy.deepcopy(receipt["runtime"]),
            ) as runtime_authority, mock.patch.object(
                campaign,
                "_campaign_input_identity",
                return_value=inputs,
            ):
                campaign._lightweight_outer_recheck(
                    snapshot,
                    action="verify",
                    require_accepted=True,
                    package=root,
                )
            runtime_authority.assert_called_once_with(
                container_layout="p10-09"
            )

            changed = copy.deepcopy(snapshot)
            changed["container_layout"] = "legacy"
            with self.assertRaisesRegex(
                campaign.CampaignError, "layout changed"
            ):
                campaign._lightweight_outer_recheck(
                    changed,
                    action="verify",
                    require_accepted=True,
                    package=root,
                )

    def test_container_layout_hybrids_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            _binary, _build_dir, analyzer = _fake_build(root)
            source_identity = {
                "revision": "a" * 40,
                "manifest_sha256": "b" * 64,
            }
            authority_dir = _write_fake_build_authority(root)
            receipt = _fake_build_receipt(
                source_identity, analyzer, container_layout="p10-09"
            )
            build_record = campaign._build_authority_record(
                authority_dir, receipt
            )

            hybrid_build = copy.deepcopy(build_record)
            hybrid_argv = hybrid_build["runtime"]["normalized_argv"]
            hybrid_argv[hybrid_argv.index("/authority/source")] = "/source"
            with self.assertRaisesRegex(campaign.CampaignError, "layout"):
                campaign._campaign_container_layout(hybrid_build)

            hybrid_receipt = copy.deepcopy(receipt)
            hybrid_receipt["runtime"]["normalized_argv"] = hybrid_argv
            with self.assertRaisesRegex(campaign.CampaignError, "layout"):
                campaign._build_authority_record(
                    authority_dir, hybrid_receipt
                )

            normalized = campaign._normalized_campaign_argv(
                "verify", None, container_layout="p10-09"
            )
            hybrid_runtime = {
                "schema": campaign.CAMPAIGN_RUNTIME_SCHEMA,
                "image": copy.deepcopy(receipt["runtime"]["image"]),
                "podman": copy.deepcopy(receipt["runtime"]["podman"]),
                "normalized_argv": normalized,
                "normalized_argv_sha256": campaign.compact_json_digest(
                    normalized
                ),
            }
            hybrid_runtime["normalized_argv"][
                hybrid_runtime["normalized_argv"].index(
                    "$BUILD:/authority/build:ro"
                )
            ] = "$BUILD:/build:ro"
            hybrid_runtime["normalized_argv_sha256"] = (
                campaign.compact_json_digest(
                    hybrid_runtime["normalized_argv"]
                )
            )
            with self.assertRaisesRegex(campaign.CampaignError, "argv drift"):
                campaign._validate_campaign_runtime(
                    hybrid_runtime,
                    "verify",
                    None,
                    require_accepted=True,
                    build_record=build_record,
                )

            mounts = campaign._campaign_mounts(
                "verify", container_layout="p10-09"
            )
            mounts["build"] = "/build"
            with self.assertRaisesRegex(
                campaign.CampaignError, "mount authority drift"
            ):
                campaign._validate_campaign_mounts(
                    mounts, "verify", container_layout="p10-09"
                )
            with self.assertRaisesRegex(
                campaign.CampaignError, "unsupported"
            ):
                campaign._normalized_campaign_argv(
                    "verify", None, container_layout="hybrid"
                )

        environment = {
            **campaign._inner_environment("p10-09"),
            campaign.CAMPAIGN_INNER_ENV_TOKEN_ENV: campaign.compact_json_digest(
                campaign._inner_environment("p10-09")
            ),
            campaign.CAMPAIGN_INNER_TOKEN_ENV: "1" * 64,
            "HOSTNAME": "0123456789ab",
            "container": "podman",
        }
        with mock.patch.object(
            campaign, "ROOT", Path("/authority/source")
        ), mock.patch.object(
            campaign,
            "__file__",
            "/authority/source/scripts/run_quality_floor_campaign.py",
        ), mock.patch.dict(campaign.os.environ, environment, clear=True), \
                self.assertRaisesRegex(campaign.CampaignError, "layout"):
            campaign._validate_inner_paths(
                "run",
                source=Path("/authority/source"),
                build_dir=Path("/build"),
                build_authority_dir=Path("/authority/build-authority"),
                package=Path("/stage/package"),
                launch_authority=Path(
                    f"/stage/{campaign.CAMPAIGN_LAUNCH_NAME}"
                ),
                juliet_dir=Path("/juliet"),
                juliet_archive=Path("/juliet.zip"),
                libarchive_checkout=Path("/libarchive"),
            )

    def test_inner_environment_requires_digest_and_rejects_git_injection(self) -> None:
        expected = campaign._inner_environment()
        environment = {
            **expected,
            campaign.CAMPAIGN_INNER_ENV_TOKEN_ENV:
                campaign.compact_json_digest(expected),
            campaign.CAMPAIGN_INNER_TOKEN_ENV: "1" * 64,
            "HOSTNAME": "0123456789ab",
            "container": "podman",
        }
        with mock.patch.dict(campaign.os.environ, environment, clear=True):
            campaign._validate_inner_environment()
        for label, mutation in (
            ("wrong digest", {campaign.CAMPAIGN_INNER_ENV_TOKEN_ENV: "0" * 64}),
            ("hook drift", {"GIT_CONFIG_VALUE_2": "/tmp/hooks"}),
            ("Git injection", {"GIT_DIR": "/tmp/alternate"}),
            ("compiler injection", {"CC": "/tmp/compiler"}),
            ("flags injection", {"CFLAGS": "-fplugin=/tmp/plugin.so"}),
            ("proxy injection", {"HTTP_PROXY": "http://127.0.0.1:9"}),
        ):
            with self.subTest(label=label):
                changed = {**environment, **mutation}
                with mock.patch.dict(campaign.os.environ, changed, clear=True), \
                        self.assertRaisesRegex(campaign.CampaignError, "environment"):
                    campaign._validate_inner_environment()

    def test_campaign_git_commands_use_closed_authority_environment(self) -> None:
        completed = mock.Mock(returncode=0, stdout="clean\n", stderr="")
        with mock.patch.dict(
            campaign.os.environ,
            {
                "PATH": "/usr/bin:/bin",
                "GIT_DIR": "/tmp/alternate",
                "GIT_CONFIG_PARAMETERS": "'core.fsmonitor'='/tmp/hook'",
            },
            clear=True,
        ), mock.patch.object(
            campaign.subprocess, "run", return_value=completed
        ) as invoked:
            self.assertEqual(campaign._git(Path("/source"), "status"), "clean")
        environment = invoked.call_args.kwargs["env"]
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_CONFIG_PARAMETERS", environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], campaign.os.devnull)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_CONFIG_VALUE_1"], "/dev/null")
        self.assertEqual(environment["GIT_CONFIG_VALUE_2"], "false")
        self.assertEqual(environment["GIT_CONFIG_VALUE_3"], "false")

    def test_inner_launch_uses_only_in_runtime_build_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            authority_dir = _write_fake_build_authority(root)
            receipt = _fake_build_receipt(source, analyzer)
            launch_path, launch, build_record = _fake_launch_authority(
                root, authority_dir, receipt
            )
            token = campaign.sha256_file(launch_path)
            in_runtime = mock.Mock(return_value=receipt)
            with mock.patch.dict(
                campaign.os.environ,
                {campaign.CAMPAIGN_INNER_TOKEN_ENV: token},
                clear=True,
            ), mock.patch.object(
                campaign, "_source_identity", return_value=source
            ), mock.patch.object(
                campaign.build_authority,
                "verify_authority_in_current_runtime",
                in_runtime,
            ), mock.patch.object(
                campaign.build_authority,
                "verify_authority",
                side_effect=AssertionError("nested Podman verifier invoked"),
            ):
                payload, execution, retained, derived_binary = (
                    campaign._inner_launch_context(
                        "run", launch_path, root, authority_dir, build_dir
                    )
                )
            self.assertEqual(payload, launch)
            self.assertEqual(retained, build_record)
            self.assertEqual(derived_binary, binary)
            self.assertEqual(execution["launch_sha256"], token)
            in_runtime.assert_called_once_with(authority_dir, root, build_dir)

    def test_inner_launch_rejects_stale_token_before_any_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            _binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            authority_dir = _write_fake_build_authority(root)
            receipt = _fake_build_receipt(source, analyzer)
            launch_path, _launch, _record = _fake_launch_authority(
                root, authority_dir, receipt
            )
            verifier = mock.Mock(side_effect=AssertionError("verifier invoked"))
            with mock.patch.dict(
                campaign.os.environ,
                {campaign.CAMPAIGN_INNER_TOKEN_ENV: "0" * 64},
                clear=True,
            ), mock.patch.object(
                campaign.build_authority,
                "verify_authority_in_current_runtime",
                verifier,
            ), self.assertRaisesRegex(campaign.CampaignError, "missing or stale"):
                campaign._inner_launch_context(
                    "run", launch_path, root, authority_dir, build_dir
                )
            verifier.assert_not_called()

    def test_launch_rejects_runtime_argv_and_mount_path_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            _binary, _build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            authority_dir = _write_fake_build_authority(root)
            receipt = _fake_build_receipt(source, analyzer)
            _path, launch, build_record = _fake_launch_authority(
                root, authority_dir, receipt
            )
            changes = (
                (
                    "runtime image",
                    lambda value: value["runtime"]["image"].__setitem__(
                        "id", "sha256:" + "0" * 64
                    ),
                    "build-runtime bound",
                ),
                (
                    "normalized argv",
                    lambda value: value["runtime"]["normalized_argv"].append(
                        "--privileged"
                    ),
                    "argv drift",
                ),
                (
                    "launch mount",
                    lambda value: value["inputs"]["mounts"].__setitem__(
                        "build", "/alternate-build"
                    ),
                    "mount authority drift",
                ),
            )
            for label, mutate, error in changes:
                changed = copy.deepcopy(launch)
                mutate(changed)
                raw = campaign.canonical_json(changed)
                with self.subTest(label=label), self.assertRaisesRegex(
                    campaign.CampaignError, error
                ):
                    campaign._validate_launch_payload(
                        changed,
                        raw,
                        expected_action="run",
                        build_record=build_record,
                        require_token=False,
                    )
        with self.assertRaisesRegex(campaign.CampaignError, "mount path drift: build"):
            campaign._validate_inner_paths(
                "run",
                source=Path("/source"),
                build_dir=Path("/alternate-build"),
                build_authority_dir=Path("/build-authority"),
                package=Path("/stage/package"),
                launch_authority=Path(
                    f"/stage/{campaign.CAMPAIGN_LAUNCH_NAME}"
                ),
                juliet_dir=Path("/juliet"),
                juliet_archive=Path("/juliet.zip"),
                libarchive_checkout=Path("/libarchive"),
            )

    def test_public_preflight_does_not_execute_host_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            _binary, build_dir, analyzer = _fake_build(root)
            source_identity = {
                "revision": "a" * 40,
                "manifest_sha256": "b" * 64,
            }
            authority_dir = _write_fake_build_authority(root)
            receipt = _fake_build_receipt(source_identity, analyzer)
            source = root / "source"
            source.mkdir()
            package = root / "package"
            package.mkdir()
            (package / "evidence").write_text("sealed\n", encoding="utf-8")
            normalized = campaign._normalized_campaign_argv("verify", None)
            runtime = {
                "schema": campaign.CAMPAIGN_RUNTIME_SCHEMA,
                "image": copy.deepcopy(receipt["runtime"]["image"]),
                "podman": copy.deepcopy(receipt["runtime"]["podman"]),
                "normalized_argv": normalized,
                "normalized_argv_sha256": campaign.compact_json_digest(normalized),
            }
            host_analyzer = mock.Mock(
                side_effect=AssertionError("host analyzer executed")
            )
            with mock.patch.object(
                campaign, "_verify_outer_script_authority", return_value={}
            ), mock.patch.object(
                campaign, "_source_identity", return_value=source_identity
            ), mock.patch.object(
                campaign.build_authority, "verify_authority", return_value=receipt
            ), mock.patch.object(
                campaign, "_campaign_runtime", return_value=runtime
            ), mock.patch.object(
                campaign, "_binary_identity", host_analyzer
            ):
                snapshot = campaign._outer_snapshot(
                    "verify",
                    source=source,
                    build_authority_dir=authority_dir,
                    build_dir=build_dir,
                    jobs=None,
                    package=package,
                )
            self.assertEqual(snapshot["build_record"]["analyzer"]["sha256"],
                             analyzer["binary_sha256"])
            host_analyzer.assert_not_called()

    def test_container_failure_or_partial_marker_never_counts_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            for label, returncode, output, error in (
                ("nonzero", 2, b"partial\n", "exit 2.*partial"),
                ("bad marker", 0, b"partial\n", "marker"),
                ("non-UTF-8", 0, b"\xff", "unreadable"),
            ):
                log = root / f"{label}.log"

                def fake_run(_command, **kwargs):
                    kwargs["stdout"].write(output)
                    return mock.Mock(returncode=returncode)

                with self.subTest(label=label), mock.patch.object(
                    campaign.subprocess, "run", side_effect=fake_run
                ), self.assertRaisesRegex(campaign.CampaignError, error):
                    campaign._execute_campaign_container(
                        ["/usr/bin/podman"], log, "run"
                    )

    def test_container_failure_detail_is_bounded_escaped_and_last_line_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = temporary_root(directory) / "container.log"
            log.write_text("earlier detail\nlast \x1b[31m detail\n", encoding="utf-8")
            detail = campaign._campaign_failure_detail(log)
            self.assertNotIn("earlier detail", detail)
            self.assertNotIn("\x1b", detail)
            self.assertIn(r"\u001b", detail)

            log.write_text(
                "x" * (campaign.MAX_CAMPAIGN_FAILURE_DETAIL_CHARS + 100) + "\n",
                encoding="utf-8",
            )
            detail = campaign._campaign_failure_detail(log)
            self.assertIn("[truncated]", detail)
            self.assertLessEqual(
                len(detail),
                campaign.MAX_CAMPAIGN_FAILURE_DETAIL_CHARS + 32,
            )

    def test_campaign_podman_process_uses_only_shared_closed_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = temporary_root(directory) / "container.log"
            digest = "1" * 64
            environment = {"CLOSED_PODMAN_ENV": "1"}

            def fake_run(_command, **kwargs):
                kwargs["stdout"].write(
                    f"CODESKEPTIC_QUALITY_FLOOR_INNER_VERIFY {digest}\n".encode()
                )
                return mock.Mock(returncode=0)

            with mock.patch.dict(
                campaign.os.environ,
                {
                    "CONTAINERS_CONF": "/tmp/host-injection",
                    "CONTAINER_HOST": "ssh://attacker.invalid",
                    "HTTP_PROXY": "http://attacker.invalid",
                },
                clear=True,
            ), mock.patch.object(
                campaign.build_authority,
                "_podman_environment",
                return_value=environment,
            ), mock.patch.object(
                campaign.subprocess, "run", side_effect=fake_run
            ) as invoked:
                self.assertEqual(
                    campaign._execute_campaign_container(
                        ["/usr/bin/podman"], log, "verify"
                    ),
                    digest,
                )
            self.assertIs(invoked.call_args.kwargs["env"], environment)

    def test_failed_public_run_leaves_no_output_or_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "source"
            build_dir = root / "build"
            authority = root / "authority"
            juliet = root / "juliet"
            libarchive = root / "libarchive"
            for path in (source, build_dir, authority, juliet, libarchive):
                path.mkdir()
            archive = root / "juliet.zip"
            archive.write_bytes(b"archive")
            output = root / "campaign"
            build_record = {
                "runtime": {
                    "normalized_argv": (
                        campaign.build_authority._normalized_container_argv(
                            "produce"
                        )
                    )
                }
            }
            snapshot = {
                "source": source,
                "build_dir": build_dir,
                "build_authority_dir": authority,
                "build_record": build_record,
                "launch": {"schema": "test-launch"},
            }
            execute = mock.Mock(
                side_effect=campaign.CampaignError("container failed")
            )
            with mock.patch.object(
                campaign, "_outer_snapshot", return_value=snapshot
            ), mock.patch.object(
                campaign,
                "_execute_campaign_container",
                execute,
            ), self.assertRaisesRegex(campaign.CampaignError, "container failed"):
                campaign.run_campaign(
                    source,
                    authority,
                    build_dir,
                    juliet,
                    archive,
                    libarchive,
                    output,
                    jobs=1,
                )
            self.assertFalse(output.exists())
            self.assertFalse(any(root.glob(".campaign.campaign-*")))
            command = execute.call_args.args[0]
            writable_mounts = [
                command[index + 1]
                for index, token in enumerate(command[:-1])
                if token == "-v" and command[index + 1].endswith(":rw")
            ]
            self.assertEqual(len(writable_mounts), 2)
            for mount in writable_mounts:
                host = Path(mount.split(":", 1)[0])
                self.assertIn(root, host.parents)

    def test_public_run_verifies_in_separate_phase_before_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "source"
            build_dir = root / "build"
            authority = root / "authority"
            juliet = root / "juliet"
            libarchive = root / "libarchive"
            for path in (source, build_dir, authority, juliet, libarchive):
                path.mkdir()
            archive = root / "juliet.zip"
            archive.write_bytes(b"archive")
            output = root / "campaign"
            build_record = {
                "runtime": {
                    "normalized_argv": (
                        campaign.build_authority._normalized_container_argv(
                            "produce"
                        )
                    )
                }
            }
            snapshot = {
                "source": source,
                "build_dir": build_dir,
                "build_authority_dir": authority,
                "build_record": build_record,
                "launch": {"schema": "test-launch"},
            }
            receipt = {"status": "accepted"}
            order: list[str] = []

            def execute(command, _log, action):
                self.assertEqual(action, "run")
                stage_mount = next(
                    command[index + 1]
                    for index, token in enumerate(command[:-1])
                    if token == "-v" and command[index + 1].endswith(":/stage:rw")
                )
                stage = Path(stage_mount.removesuffix(":/stage:rw"))
                staged_package = stage / "package"
                staged_package.mkdir()
                (staged_package / "raw").mkdir()
                (staged_package / "bundles").mkdir()
                (staged_package / "raw" / "fixture.bin").write_bytes(b"raw\n")
                (staged_package / "bundles" / "fixture.bin").write_bytes(
                    b"bundle\n"
                )
                (staged_package / quality.RAW_MANIFEST_NAME).write_text(
                    "fixture manifest\n", encoding="utf-8"
                )
                campaign.write_json(
                    staged_package / "quality-floor-input.json",
                    {"fixture": True},
                )
                campaign.write_json(staged_package / "receipt.json", receipt)
                (staged_package / "receipt.json.sha256").write_text(
                    campaign.sha256_file(staged_package / "receipt.json") + "\n",
                    encoding="ascii",
                )
                order.append("container-B")
                return campaign.sha256_file(staged_package / "receipt.json")

            def independent(_workspace, package, _snapshot, *, require_accepted):
                self.assertTrue(require_accepted)
                self.assertTrue((package / "receipt.json").is_file())
                order.append("container-C")
                return receipt, campaign._tree_identity(
                    package, "independently verified package"
                )

            original_promote = campaign._promote_new_package

            def promote(staged, target, expected_staged):
                order.append("promote")
                original_promote(staged, target, expected_staged)

            with mock.patch.object(
                campaign, "_outer_snapshot", return_value=snapshot
            ), mock.patch.object(
                campaign, "_execute_campaign_container", side_effect=execute
            ), mock.patch.object(
                campaign, "_lightweight_outer_recheck"
            ), mock.patch.object(
                campaign, "_launch_independent_verify", side_effect=independent
            ), mock.patch.object(
                campaign, "_final_outer_recheck"
            ), mock.patch.object(
                campaign, "_promote_new_package", side_effect=promote
            ):
                retained = campaign.run_campaign(
                    source,
                    authority,
                    build_dir,
                    juliet,
                    archive,
                    libarchive,
                    output,
                    jobs=1,
                )
            self.assertEqual(retained, receipt)
            self.assertEqual(order, ["container-B", "container-C", "promote"])
            self.assertEqual(
                json.loads((output / "receipt.json").read_text(encoding="utf-8")),
                receipt,
            )

    def test_retained_execution_authority_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            package = root / "package"
            package.mkdir()
            _write_fake_raw(package)
            _binary, build_dir, analyzer = _fake_build(root)
            source = {"revision": "a" * 40, "manifest_sha256": "b" * 64}
            receipt = _fake_build_receipt(source, analyzer)
            authority = _seal_fake_authority(package, source, analyzer, receipt)
            authority["execution_authority"]["launch_sha256"] = "0" * 64
            campaign.write_json(
                package / "raw" / campaign.AUTHORITY_NAME, authority
            )
            with mock.patch.object(
                campaign, "_source_identity", return_value=source
            ), self.assertRaisesRegex(campaign.CampaignError, "execution authority"):
                campaign._validate_raw_authority(
                    package,
                    build_dir,
                    build_verifier=mock.Mock(return_value=receipt),
                    require_clean_source=False,
                    exact_source_revision=True,
                )

    def test_public_cli_rejects_binary_compiler_and_unbounded_jobs(self) -> None:
        base = [
            "run",
            "--source", "/tmp/source",
            "--build-authority", "/tmp/authority",
            "--build-dir", "/tmp/build",
            "--juliet-dir", "/tmp/juliet",
            "--juliet-archive", "/tmp/juliet.zip",
            "--libarchive-checkout", "/tmp/libarchive",
            "--output", "/tmp/output",
        ]
        for option in ("--binary", "--compiler"):
            with self.subTest(option=option), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                campaign.main([*base, option, "/tmp/alternate"])
            self.assertEqual(raised.exception.code, 2)
        for jobs in (0, 65, True):
            with self.subTest(jobs=jobs), self.assertRaisesRegex(
                campaign.CampaignError, "between 1 and 64"
            ):
                campaign._campaign_jobs("run", jobs)
        help_text = campaign._parser().format_help()
        self.assertNotIn("_inner-run", help_text)
        self.assertNotIn("_inner-assemble", help_text)
        self.assertNotIn("_inner-verify", help_text)

    def test_package_overlap_protection_covers_build_and_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "source"
            build_dir = root / "build"
            authority = root / "authority"
            for path in (source, build_dir, authority):
                path.mkdir()
            snapshot = {
                "source": source,
                "build_dir": build_dir,
                "build_authority_dir": authority,
            }
            for package, label in (
                (build_dir, "analyzer build"),
                (authority, "build authority"),
            ):
                with self.subTest(label=label), self.assertRaisesRegex(
                    campaign.CampaignError, "overlaps"
                ):
                    campaign._reject_package_overlap(
                        package, snapshot, label="sealed campaign package"
                    )


if __name__ == "__main__":
    unittest.main()
