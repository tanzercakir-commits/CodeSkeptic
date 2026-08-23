#!/usr/bin/env python3
"""Fail-closed contracts for the cumulative Phase 10 quality floor."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_floor_receipt as quality  # noqa: E402


def temporary_root(value: str) -> Path:
    """Return the real directory behind a platform temporary-path alias."""

    return Path(value).resolve(strict=True)


def sha(character: str) -> str:
    return character * 64


def raw_payload(label: str) -> bytes:
    return quality.canonical_json({"artifact": label})


def raw_sha(label: str) -> str:
    return hashlib.sha256(raw_payload(label)).hexdigest()


def artifact_payloads() -> dict[str, bytes]:
    payloads = {
        f"raw/rules/{rule_id}.json": raw_payload(f"rule-{rule_id}")
        for rule_id in quality.EXPECTED_RULES
    }
    payloads.update({
        f"raw/clean/clean-{index}.json": raw_payload(f"clean-{index}")
        for index in range(1, 10)
    })
    payloads.update({
        "raw/requested/missing.json": raw_payload("requested-missing"),
        "raw/requested/broken.json": raw_payload("requested-broken"),
        "logs/campaign.log": b"quality-floor campaign\n",
    })
    return payloads


def raw_manifest_bytes(payloads: dict[str, bytes] | None = None) -> bytes:
    retained = payloads if payloads is not None else artifact_payloads()
    return "".join(
        f"{hashlib.sha256(retained[path]).hexdigest()}  {path}\n"
        for path in sorted(retained)
    ).encode()


def materialize_artifacts(
    root: Path, payloads: dict[str, bytes] | None = None
) -> None:
    retained = payloads if payloads is not None else artifact_payloads()
    for relative, data in retained.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / quality.RAW_MANIFEST_NAME).write_bytes(raw_manifest_bytes(retained))


def rule_row(rule_id: str) -> dict:
    return {
        "id": rule_id,
        "corpus": (
            "resource-leak-mutation"
            if rule_id == "resource-leak"
            else "juliet"
        ),
        "exact_head": True,
        "fresh": True,
        "raw_sha256": raw_sha(f"rule-{rule_id}"),
        "diagnostics": {
            "true_positives": 9,
            "false_positives": 1,
        },
        "cases": {
            "files": 10,
            "misses": {
                "total": 2,
                "addressable": 2,
                "model_gap": 0,
                "out_of_scope": 0,
            },
        },
    }


def coverage(attempted: int = 1, analyzed: int = 1,
             broken: int = 0, incomplete: int = 0) -> dict:
    return {
        "attempted_tus": attempted,
        "analyzed_tus": analyzed,
        "broken_tus": broken,
        "incomplete_functions": incomplete,
    }


def accepted_manifest() -> dict:
    rules = list(quality.EXPECTED_RULES)
    retained = artifact_payloads()
    retained_manifest = raw_manifest_bytes(retained)
    return {
        "schema": quality.INPUT_SCHEMA,
        "identity": {
            "source": {
                "revision": "a" * 40,
                "manifest_sha256": sha("b"),
            },
            "analyzer": {
                "version": "CodeSkeptic 0.4.9-dev",
                "binary_sha256": sha("c"),
            },
            "capabilities": {
                "registry_sha256": quality.capability_registry_identity()[
                    "sha256"
                ],
                "supported_quality_gated_default_rules": list(reversed(rules)),
            },
            "retained_artifacts": {
                "manifest_path": quality.RAW_MANIFEST_NAME,
                "manifest_sha256": hashlib.sha256(
                    retained_manifest
                ).hexdigest(),
                "file_count": len(retained),
            },
        },
        "rules": [rule_row(rule_id) for rule_id in rules],
        "clean_corpus": {
            "cases": [
                {
                    "id": f"clean-{index + 1}",
                    "process_exit": 0,
                    "report_exit": 0,
                    "complete": True,
                    "coverage": coverage(),
                    "findings": 0,
                    "raw_sha256": raw_sha(f"clean-{index + 1}"),
                }
                for index in range(9)
            ],
        },
        "requested_tu_negatives": {
            "cases": [
                {
                    "id": "missing-requested-tu",
                    "kind": "missing",
                    "process_exit": 2,
                    "report_exit": 2,
                    "complete": False,
                    "verdict": None,
                    "coverage": coverage(attempted=2, analyzed=1),
                    "raw_sha256": raw_sha("requested-missing"),
                },
                {
                    "id": "broken-requested-tu",
                    "kind": "broken",
                    "process_exit": 2,
                    "report_exit": 2,
                    "complete": False,
                    "verdict": None,
                    "coverage": coverage(broken=1),
                    "raw_sha256": raw_sha("requested-broken"),
                },
            ],
        },
    }


class QualityFloorReceiptTest(unittest.TestCase):
    def build(self, manifest: dict) -> dict:
        raw = quality.canonical_json(manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            materialize_artifacts(root)
            return quality.build_receipt(
                manifest,
                input_sha256=hashlib.sha256(raw).hexdigest(),
                input_bytes=len(raw),
                artifacts_root=root,
            )

    def test_accepts_exact_seven_rule_floor_and_uses_integer_fractions(self) -> None:
        receipt = self.build(accepted_manifest())
        self.assertEqual(receipt["status"], "accepted")
        self.assertEqual(receipt["availability"], "available")
        self.assertEqual(receipt["failures"], [])
        self.assertEqual(
            receipt["retained_artifact_verification"]["evidence_file_count"],
            18,
        )
        self.assertEqual(
            receipt["identity"]["capabilities"]
            ["supported_quality_gated_default_rules"],
            list(quality.EXPECTED_RULES),
        )
        self.assertEqual(
            receipt["metrics"]["micro_precision"],
            {
                "numerator": 63,
                "denominator": 70,
                "threshold_percent": 90,
                "passed": True,
            },
        )
        self.assertEqual(
            receipt["metrics"]["addressable_recall"],
            {
                "numerator": 56,
                "denominator": 70,
                "addressable_false_negatives": 14,
                "threshold_percent": 70,
                "passed": True,
            },
        )

    def test_recall_never_mixes_diagnostic_tp_with_case_false_negatives(self) -> None:
        manifest = accepted_manifest()
        for row in manifest["rules"]:
            row["diagnostics"] = {
                "true_positives": 1_000_000,
                "false_positives": 0,
            }
            row["cases"]["misses"] = {
                "total": 9,
                "addressable": 9,
                "model_gap": 0,
                "out_of_scope": 0,
            }
        receipt = self.build(manifest)
        self.assertEqual(receipt["status"], "rejected")
        self.assertEqual(
            receipt["metrics"]["addressable_recall"]["numerator"], 7
        )
        self.assertEqual(
            receipt["metrics"]["addressable_recall"]["denominator"], 70
        )
        self.assertTrue(
            any("addressable recall" in failure for failure in receipt["failures"])
        )

    def test_exact_70_percent_case_level_recall_is_accepted(self) -> None:
        manifest = accepted_manifest()
        for row in manifest["rules"]:
            row["cases"]["misses"] = {
                "total": 3,
                "addressable": 3,
                "model_gap": 0,
                "out_of_scope": 0,
            }
        receipt = self.build(manifest)
        self.assertEqual(receipt["status"], "accepted")
        self.assertEqual(
            receipt["metrics"]["addressable_recall"]["numerator"], 49
        )
        self.assertEqual(
            receipt["metrics"]["addressable_recall"]["denominator"], 70
        )

    def test_rejects_per_rule_and_micro_precision_below_their_floors(self) -> None:
        per_rule = accepted_manifest()
        per_rule["rules"][0]["diagnostics"] = {
            "true_positives": 84,
            "false_positives": 16,
        }
        receipt = self.build(per_rule)
        self.assertEqual(receipt["status"], "rejected")
        self.assertTrue(
            any("per-rule precision" in failure for failure in receipt["failures"])
        )

        micro = accepted_manifest()
        for row in micro["rules"]:
            row["diagnostics"] = {
                "true_positives": 85,
                "false_positives": 15,
            }
        receipt = self.build(micro)
        self.assertEqual(receipt["status"], "rejected")
        self.assertTrue(
            all(rule["diagnostic_precision"]["passed"]
                for rule in receipt["metrics"]["rules"])
        )
        self.assertFalse(receipt["metrics"]["micro_precision"]["passed"])

    def test_missing_duplicate_or_stale_rule_evidence_is_unavailable(self) -> None:
        mutations = []

        missing = accepted_manifest()
        missing["rules"].pop()
        mutations.append(missing)

        duplicate = accepted_manifest()
        duplicate["rules"][-1]["id"] = duplicate["rules"][0]["id"]
        mutations.append(duplicate)

        duplicate_raw = accepted_manifest()
        duplicate_raw["rules"][-1]["raw_sha256"] = duplicate_raw["rules"][0][
            "raw_sha256"
        ]
        mutations.append(duplicate_raw)

        cross_section_duplicate = accepted_manifest()
        cross_section_duplicate["clean_corpus"]["cases"][0][
            "raw_sha256"
        ] = cross_section_duplicate["rules"][0]["raw_sha256"]
        mutations.append(cross_section_duplicate)

        stale = accepted_manifest()
        resource = next(row for row in stale["rules"]
                        if row["id"] == "resource-leak")
        resource["fresh"] = False
        mutations.append(stale)

        wrong_capabilities = accepted_manifest()
        wrong_capabilities["identity"]["capabilities"][
            "supported_quality_gated_default_rules"
        ].pop()
        mutations.append(wrong_capabilities)

        for manifest in mutations:
            with self.subTest(manifest=manifest):
                receipt = self.build(manifest)
                self.assertEqual(receipt["status"], "rejected")
                self.assertEqual(receipt["availability"], "unavailable")
                self.assertIsNone(receipt["metrics"])

    def test_zero_denominator_and_malformed_miss_partition_fail_closed(self) -> None:
        zero = accepted_manifest()
        zero["rules"][0]["diagnostics"] = {
            "true_positives": 0,
            "false_positives": 0,
        }
        receipt = self.build(zero)
        self.assertEqual(receipt["availability"], "unavailable")
        self.assertTrue(any("zero denominator" in item
                            for item in receipt["failures"]))

        malformed = accepted_manifest()
        malformed["rules"][0]["cases"]["misses"]["total"] = 3
        receipt = self.build(malformed)
        self.assertEqual(receipt["availability"], "unavailable")
        self.assertTrue(any("miss partition" in item
                            for item in receipt["failures"]))

    def test_clean_corpus_requires_nine_exact_complete_zero_finding_runs(self) -> None:
        mutations = []
        missing = accepted_manifest()
        missing["clean_corpus"]["cases"].pop()
        mutations.append(missing)
        finding = accepted_manifest()
        finding["clean_corpus"]["cases"][0]["findings"] = 1
        mutations.append(finding)
        incomplete = accepted_manifest()
        incomplete["clean_corpus"]["cases"][0]["coverage"]["analyzed_tus"] = 0
        mutations.append(incomplete)
        unavailable = accepted_manifest()
        unavailable["clean_corpus"]["cases"][0]["process_exit"] = 2
        mutations.append(unavailable)
        boolean_exit = accepted_manifest()
        boolean_exit["clean_corpus"]["cases"][0]["process_exit"] = False
        mutations.append(boolean_exit)

        for manifest in mutations:
            with self.subTest(manifest=manifest):
                receipt = self.build(manifest)
                self.assertEqual(receipt["status"], "rejected")
                self.assertEqual(receipt["availability"], "unavailable")

    def test_requested_tu_negatives_require_process_and_report_exit_two(self) -> None:
        mutations = []
        missing_kind = accepted_manifest()
        missing_kind["requested_tu_negatives"]["cases"].pop()
        mutations.append(missing_kind)
        report_green = accepted_manifest()
        report_green["requested_tu_negatives"]["cases"][0]["report_exit"] = 0
        mutations.append(report_green)
        complete = accepted_manifest()
        complete["requested_tu_negatives"]["cases"][0]["complete"] = True
        mutations.append(complete)
        verdict = accepted_manifest()
        verdict["requested_tu_negatives"]["cases"][0]["verdict"] = "clean"
        mutations.append(verdict)
        float_exit = accepted_manifest()
        float_exit["requested_tu_negatives"]["cases"][0]["report_exit"] = 2.0
        mutations.append(float_exit)
        impossible_coverage = accepted_manifest()
        impossible_coverage["requested_tu_negatives"]["cases"][1]["coverage"][
            "broken_tus"
        ] = 2
        mutations.append(impossible_coverage)

        for manifest in mutations:
            with self.subTest(manifest=manifest):
                receipt = self.build(manifest)
                self.assertEqual(receipt["status"], "rejected")
                self.assertEqual(receipt["availability"], "unavailable")

    def test_identity_hashes_and_retained_artifact_manifest_are_mandatory(self) -> None:
        mutations = []
        bad_source = accepted_manifest()
        bad_source["identity"]["source"]["manifest_sha256"] = "not-a-hash"
        mutations.append(bad_source)
        bad_analyzer = accepted_manifest()
        bad_analyzer["identity"]["analyzer"]["binary_sha256"] = sha("A")
        mutations.append(bad_analyzer)
        capability_drift = accepted_manifest()
        capability_drift["identity"]["capabilities"]["registry_sha256"] = sha("0")
        mutations.append(capability_drift)
        no_artifacts = accepted_manifest()
        no_artifacts["identity"]["retained_artifacts"]["file_count"] = 0
        mutations.append(no_artifacts)
        sha256_revision = accepted_manifest()
        sha256_revision["identity"]["source"]["revision"] = "a" * 64
        mutations.append(sha256_revision)

        for manifest in mutations:
            with self.subTest(manifest=manifest):
                receipt = self.build(manifest)
                self.assertEqual(receipt["availability"], "unavailable")

    def test_experimental_registry_rows_cannot_be_quality_gated_or_blocking(self) -> None:
        original = quality.CAPABILITY_REGISTRY.read_text(encoding="utf-8")
        experimental = (
            'CODESKEPTIC_RULE_CAPABILITY("uninit-ptr", Experimental, '
            'true, false, false, "per-rule precision sample pending")'
        )
        self.assertIn(experimental, original)
        mutations = (
            experimental.replace("true, false, false", "true, true, false"),
            experimental.replace("true, false, false", "true, false, true"),
        )
        for replacement in mutations:
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    registry = temporary_root(directory) / "RuleCapabilities.def"
                    registry.write_text(
                        original.replace(experimental, replacement),
                        encoding="utf-8",
                    )
                    with mock.patch.object(
                        quality, "CAPABILITY_REGISTRY", registry
                    ):
                        with self.assertRaisesRegex(
                            quality.ManifestUnavailable, "experimental"
                        ):
                            quality.capability_registry_identity()

    def test_indented_supported_registry_row_is_not_ignored(self) -> None:
        original = quality.CAPABILITY_REGISTRY.read_text(encoding="utf-8")
        extra = (
            '    CODESKEPTIC_RULE_CAPABILITY("unexpected-supported", '
            'Supported, true, true, true, "must not be ignored")\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            registry = temporary_root(directory) / "RuleCapabilities.def"
            registry.write_text(original + extra, encoding="utf-8")
            with mock.patch.object(quality, "CAPABILITY_REGISTRY", registry):
                with self.assertRaisesRegex(
                    quality.ManifestUnavailable, "exact seven"
                ):
                    quality.capability_registry_identity()

    def test_recorded_registry_bytes_rederive_historical_receipt(self) -> None:
        recorded_registry = quality.CAPABILITY_REGISTRY.read_bytes()
        manifest = accepted_manifest()
        raw = quality.canonical_json(manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            materialize_artifacts(root)
            input_path = root / "quality-floor-input.json"
            receipt_path = root / "receipt.json"
            input_path.write_bytes(raw)
            quality.generate_receipt(input_path, receipt_path)
            drifted_registry = root / "RuleCapabilities.def"
            drifted_registry.write_bytes(
                recorded_registry + b"// later source-only comment\n"
            )
            with mock.patch.object(
                quality, "CAPABILITY_REGISTRY", drifted_registry
            ):
                with self.assertRaisesRegex(
                    quality.QualityFloorError, "registry hash"
                ):
                    quality.verify_receipt(receipt_path, input_path)
                historical = quality.verify_receipt(
                    receipt_path,
                    input_path,
                    capability_registry=recorded_registry,
                )
        self.assertEqual(historical["status"], "accepted")
        with self.assertRaisesRegex(
            quality.ManifestUnavailable, "cannot read capability registry"
        ):
            quality.capability_registry_identity(b"\xff")
        with self.assertRaisesRegex(
            quality.ManifestUnavailable, "bytes are malformed"
        ):
            quality.capability_registry_identity("not bytes")  # type: ignore[arg-type]

    def test_inner_validation_cannot_accept_unverified_artifact_declarations(self) -> None:
        manifest = accepted_manifest()
        raw = quality.canonical_json(manifest)
        receipt = quality.build_receipt(
            manifest,
            input_sha256=hashlib.sha256(raw).hexdigest(),
            input_bytes=len(raw),
        )
        self.assertEqual(receipt["status"], "rejected")
        self.assertEqual(receipt["availability"], "unavailable")
        self.assertTrue(any("externally verified" in item
                            for item in receipt["failures"]))
        self.assertIn("exact_head", quality.__doc__)
        self.assertIn("does not prove", quality.__doc__)

    def test_raw_manifest_binds_entry_count_evidence_hashes_and_real_files(self) -> None:
        mutations = ("file", "manifest", "count", "missing-evidence")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    root = temporary_root(directory)
                    manifest = accepted_manifest()
                    if mutation == "missing-evidence":
                        retained = artifact_payloads()
                        retained.pop("raw/rules/memory-leak.json")
                        materialize_artifacts(root, retained)
                        raw_manifest = raw_manifest_bytes(retained)
                        identity = manifest["identity"]["retained_artifacts"]
                        identity["manifest_sha256"] = hashlib.sha256(
                            raw_manifest
                        ).hexdigest()
                        identity["file_count"] = len(retained)
                    else:
                        materialize_artifacts(root)
                    if mutation == "file":
                        (root / "raw/rules/memory-leak.json").write_bytes(
                            b"tampered\n"
                        )
                    elif mutation == "manifest":
                        retained_path = root / quality.RAW_MANIFEST_NAME
                        retained_path.write_bytes(
                            retained_path.read_bytes()
                            + f"{sha('f')}  raw/extra.json\n".encode()
                        )
                    else:
                        manifest["identity"]["retained_artifacts"][
                            "file_count"
                        ] += 1
                    input_path = root / "input.json"
                    receipt_path = root / "receipt.json"
                    input_path.write_bytes(quality.canonical_json(manifest))
                    receipt = quality.generate_receipt(input_path, receipt_path)
                    self.assertEqual(receipt["status"], "rejected")
                    self.assertEqual(receipt["availability"], "unavailable")
                    self.assertTrue(any("retained artifact" in item
                                        for item in receipt["failures"]))

    def test_build_receipt_rejects_symlinked_artifact_root(self) -> None:
        manifest = accepted_manifest()
        raw = quality.canonical_json(manifest)
        with tempfile.TemporaryDirectory() as directory:
            parent = temporary_root(directory)
            target = parent / "artifact-target"
            target.mkdir()
            materialize_artifacts(target)
            alias = parent / "artifact-alias"
            alias.symlink_to(target, target_is_directory=True)
            receipt = quality.build_receipt(
                manifest,
                input_sha256=hashlib.sha256(raw).hexdigest(),
                input_bytes=len(raw),
                artifacts_root=alias,
            )
            self.assertEqual(receipt["status"], "rejected")
            self.assertEqual(receipt["availability"], "unavailable")
            self.assertIn("symbolic link", receipt["failures"][0])

    def test_generate_and_verify_bind_raw_input_sidecar_and_canonical_bytes(self) -> None:
        manifest = accepted_manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            input_path = root / "input.json"
            receipt_path = root / "receipt.json"
            materialize_artifacts(root)
            raw = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"
            input_path.write_bytes(raw)

            generated = quality.generate_receipt(input_path, receipt_path)
            self.assertEqual(generated["status"], "accepted")
            self.assertEqual(
                generated["input"]["sha256"], hashlib.sha256(raw).hexdigest()
            )
            self.assertEqual(receipt_path.read_bytes(), quality.canonical_json(generated))
            self.assertEqual(
                quality.verify_receipt(receipt_path, input_path), generated
            )

            retained_file = root / "raw/rules/memory-leak.json"
            retained_file.write_bytes(b"post-generation drift\n")
            with self.assertRaisesRegex(
                quality.QualityFloorError, "retained artifact"
            ):
                quality.verify_receipt(receipt_path, input_path)
            retained_file.write_bytes(raw_payload("rule-memory-leak"))

            tampered = copy.deepcopy(generated)
            tampered["metrics"]["micro_precision"]["numerator"] += 1
            receipt_path.write_bytes(quality.canonical_json(tampered))
            digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            quality.receipt_checksum_path(receipt_path).write_text(
                f"{digest}  {receipt_path.name}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(quality.QualityFloorError, "differs"):
                quality.verify_receipt(receipt_path, input_path)

    def test_public_api_rejects_symlinked_input_receipt_and_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            materialize_artifacts(root)
            input_path = root / "input.json"
            input_target = root / "outside-input.json"
            input_target.write_bytes(quality.canonical_json(accepted_manifest()))
            input_path.symlink_to(input_target)
            receipt_path = root / "receipt.json"
            with self.assertRaisesRegex(
                quality.QualityFloorError, "symbolic link"
            ):
                quality.generate_receipt(input_path, receipt_path)
            self.assertFalse(receipt_path.exists())

            input_path.unlink()
            input_target.replace(input_path)
            quality.generate_receipt(input_path, receipt_path)
            checksum_path = quality.receipt_checksum_path(receipt_path)

            receipt_target = root / "outside-receipt.json"
            receipt_path.replace(receipt_target)
            receipt_path.symlink_to(receipt_target)
            with self.assertRaisesRegex(
                quality.QualityFloorError, "symbolic link"
            ):
                quality.verify_receipt(receipt_path, input_path)
            receipt_path.unlink()
            receipt_target.replace(receipt_path)

            checksum_target = root / "outside-receipt.sha256"
            checksum_path.replace(checksum_target)
            checksum_path.symlink_to(checksum_target)
            with self.assertRaisesRegex(
                quality.QualityFloorError, "symbolic link"
            ):
                quality.verify_receipt(receipt_path, input_path)

    def test_public_api_rejects_external_hardlink_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            materialize_artifacts(root)
            input_path = root / "input.json"
            input_path.write_bytes(quality.canonical_json(accepted_manifest()))
            receipt_path = root / "receipt.json"
            input_alias = root / "outside-input.json"
            try:
                os.link(input_path, input_alias)
            except OSError as error:
                self.skipTest(f"hard links are unavailable: {error}")
            with self.assertRaisesRegex(
                quality.QualityFloorError, "external hard links"
            ):
                quality.generate_receipt(input_path, receipt_path)
            input_alias.unlink()

            quality.generate_receipt(input_path, receipt_path)
            receipt_alias = root / "outside-receipt.json"
            os.link(receipt_path, receipt_alias)
            with self.assertRaisesRegex(
                quality.QualityFloorError, "external hard links"
            ):
                quality.verify_receipt(receipt_path, input_path)
            receipt_alias.unlink()

            checksum_path = quality.receipt_checksum_path(receipt_path)
            checksum_alias = root / "outside-receipt.sha256"
            os.link(checksum_path, checksum_alias)
            with self.assertRaisesRegex(
                quality.QualityFloorError, "external hard links"
            ):
                quality.verify_receipt(receipt_path, input_path)

    def test_generate_refuses_output_aliases_before_clobbering_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            materialize_artifacts(root)
            input_path = root / "input.json"
            input_raw = quality.canonical_json(accepted_manifest())
            input_path.write_bytes(input_raw)
            protected = {
                "input": input_path,
                "raw-manifest": root / quality.RAW_MANIFEST_NAME,
                "retained-artifact": root / "raw/rules/memory-leak.json",
            }
            snapshots = {
                label: path.read_bytes() for label, path in protected.items()
            }

            for label, output_path in protected.items():
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        quality.QualityFloorError, "aliases protected"
                    ):
                        quality.generate_receipt(input_path, output_path)
                    self.assertEqual(output_path.read_bytes(), snapshots[label])

    def test_generate_refuses_checksum_alias_and_sidecar_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            retained = artifact_payloads()
            retained["receipt.json.sha256"] = b"retained sidecar name\n"
            materialize_artifacts(root, retained)
            manifest = accepted_manifest()
            raw_manifest = raw_manifest_bytes(retained)
            manifest["identity"]["retained_artifacts"].update({
                "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
                "file_count": len(retained),
            })
            input_path = root / "input.json"
            input_path.write_bytes(quality.canonical_json(manifest))
            receipt_path = root / "receipt.json"
            retained_sidecar = quality.receipt_checksum_path(receipt_path)
            before = retained_sidecar.read_bytes()
            with self.assertRaisesRegex(
                quality.QualityFloorError, "aliases protected"
            ):
                quality.generate_receipt(input_path, receipt_path)
            self.assertEqual(retained_sidecar.read_bytes(), before)
            self.assertFalse(receipt_path.exists())

            retained.pop("receipt.json.sha256")
            materialize_artifacts(root, retained)
            manifest["identity"]["retained_artifacts"].update({
                "manifest_sha256": hashlib.sha256(
                    raw_manifest_bytes(retained)
                ).hexdigest(),
                "file_count": len(retained),
            })
            input_path.write_bytes(quality.canonical_json(manifest))
            sentinel = root / "sidecar-target"
            sentinel.write_bytes(b"must survive\n")
            retained_sidecar.unlink()
            retained_sidecar.symlink_to(sentinel)
            with self.assertRaisesRegex(
                quality.QualityFloorError, "symbolic link"
            ):
                quality.generate_receipt(input_path, receipt_path)
            self.assertEqual(sentinel.read_bytes(), b"must survive\n")
            self.assertFalse(receipt_path.exists())

    def test_verify_canonical_non_object_receipt_raises_contract_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            materialize_artifacts(root)
            input_path = root / "input.json"
            input_path.write_bytes(quality.canonical_json(accepted_manifest()))
            receipt_path = root / "receipt.json"
            data = quality.canonical_json([])
            receipt_path.write_bytes(data)
            quality.receipt_checksum_path(receipt_path).write_text(
                f"{hashlib.sha256(data).hexdigest()}  {receipt_path.name}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                quality.QualityFloorError, "JSON object"
            ):
                quality.verify_receipt(receipt_path, input_path)

    def test_regular_file_reader_rejects_mid_read_metadata_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "artifact.json"
            path.write_bytes(b"stable\n")
            observed = os.stat(path)
            before = mock.Mock(
                st_mode=stat.S_IFREG | 0o600,
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
                st_nlink=1,
                st_size=observed.st_size,
                st_mtime_ns=observed.st_mtime_ns,
                st_ctime_ns=observed.st_ctime_ns,
            )
            after = copy.copy(before)
            after.st_size += 1
            with mock.patch.object(
                quality.os, "fstat", side_effect=(before, after)
            ):
                with self.assertRaisesRegex(
                    quality.ManifestUnavailable, "changed while being read"
                ):
                    quality._inspect_regular_file(
                        path, "retained artifact", collect=False
                    )

    def test_malformed_json_still_produces_a_verifiable_rejected_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            input_path = root / "input.json"
            receipt_path = root / "receipt.json"
            malformed_inputs = (
                (b'{"schema":', "malformed input JSON"),
                (
                    b'{"schema":"first","schema":"second"}\n',
                    "duplicate JSON key",
                ),
                (b'{"schema":NaN}\n', "non-finite JSON number"),
            )
            for raw, failure in malformed_inputs:
                with self.subTest(raw=raw):
                    input_path.write_bytes(raw)
                    receipt = quality.generate_receipt(input_path, receipt_path)
                    self.assertEqual(receipt["status"], "rejected")
                    self.assertEqual(receipt["availability"], "unavailable")
                    self.assertIsNone(receipt["identity"])
                    self.assertIsNone(receipt["metrics"])
                    self.assertTrue(any(failure in item
                                        for item in receipt["failures"]))
                    self.assertEqual(
                        quality.verify_receipt(
                            receipt_path, input_path, require_accepted=False
                        ),
                        receipt,
                    )


if __name__ == "__main__":
    unittest.main()
