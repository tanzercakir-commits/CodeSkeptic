#!/usr/bin/env python3
"""Retained-evidence contract for the accepted Phase 10.8 quality floor."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import analyzer_build_authority as build_authority  # noqa: E402
import quality_floor_receipt as quality  # noqa: E402
import run_determinism_qualification as determinism  # noqa: E402
import run_quality_floor_campaign as campaign  # noqa: E402


EVIDENCE_ROOT = ROOT / "docs/evidence/phase10/quality"
PACKAGE_NAME = "2026-08-22-linux-x86_64"
PACKAGE = EVIDENCE_ROOT / PACKAGE_NAME
EXTERNAL_MANIFEST = EVIDENCE_ROOT / "SHA256SUMS"
THIS_TEST = "tests/QualityFloorEvidenceTest.py"
SHA256_LINE = re.compile(r"^([0-9a-f]{64})  ([^\x00\r\n]+)$")
EXPECTED_TOP = {
    "raw",
    "bundles",
    quality.RAW_MANIFEST_NAME,
    "quality-floor-input.json",
    "receipt.json",
    "receipt.json.sha256",
}
EXPECTED_BUNDLES = {
    *(f"rules/{rule_id}.json" for rule_id in quality.EXPECTED_RULES),
    *(
        f"clean/{case_id}.json"
        for case_id in (
            "array-from-int",
            "cmd-args",
            "concat-heap",
            "config-parse",
            "port-parse",
            "running-product",
            "simple-hash",
            "tiny-stack",
            "tokenize",
        )
    ),
    "requested-tu/broken.json",
    "requested-tu/missing.json",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(*arguments: str) -> tuple[int, str]:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=determinism._git_authority_environment(ROOT),
    )
    return completed.returncode, completed.stdout.strip()


def _is_exact_pending_checkpoint() -> bool:
    head_code, head = _git("rev-parse", "HEAD^{commit}")
    intro_code, introduced = _git(
        "log", "--diff-filter=A", "--format=%H", "--", THIS_TEST
    )
    status_code, status = _git(
        "status", "--porcelain=v1", "--untracked-files=all", "--", THIS_TEST
    )
    if head_code or intro_code or status_code:
        return False
    introductions = introduced.splitlines()
    if not introductions:
        return status == f"?? {THIS_TEST}"
    return len(introductions) == 1 and head == introductions[0] and status == ""


def _manifest_entries(root: Path, manifest: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    try:
        _manifest_digest, raw = quality._inspect_regular_file(
            manifest,
            "external quality evidence manifest",
            max_bytes=4 * 1024 * 1024,
            collect=True,
        )
        assert raw is not None
        lines = raw.decode("utf-8").splitlines()
    except (quality.ManifestUnavailable, UnicodeDecodeError) as error:
        raise AssertionError(f"cannot read external SHA256SUMS: {error}") from error
    for line in lines:
        match = SHA256_LINE.fullmatch(line)
        if match is None:
            raise AssertionError(f"malformed SHA256SUMS line: {line!r}")
        expected, name = match.groups()
        relative = PurePosixPath(name)
        if (
            "\\" in name
            or relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != name
            or name in entries
        ):
            raise AssertionError(f"unsafe or duplicate manifest path: {name!r}")
        candidate = root.joinpath(*relative.parts)
        if not candidate.is_file() or candidate.is_symlink():
            raise AssertionError(f"manifest path is not a regular file: {name!r}")
        try:
            observed, _unused = quality._inspect_regular_file(
                candidate,
                f"external quality evidence file {name}",
                collect=False,
            )
        except quality.ManifestUnavailable as error:
            raise AssertionError(str(error)) from error
        if observed != expected:
            raise AssertionError(f"manifest hash mismatch: {name!r}")
        entries[name] = expected
    return entries


def _verify_external_manifest_tree(
    evidence_root: Path,
    package_name: str,
    *,
    expected_file_count: int,
) -> dict[str, str]:
    manifest = evidence_root / "SHA256SUMS"
    package = evidence_root / package_name
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        raise AssertionError("quality evidence root is not a regular directory")
    if {path.name for path in evidence_root.iterdir()} != {
        manifest.name,
        package_name,
    }:
        raise AssertionError("quality evidence root children are not exact")
    if not manifest.is_file() or manifest.is_symlink():
        raise AssertionError("external SHA256SUMS is not a regular file")
    if not package.is_dir() or package.is_symlink():
        raise AssertionError("quality evidence package is not a regular directory")
    invalid_nodes = [
        path.relative_to(evidence_root).as_posix()
        for path in evidence_root.rglob("*")
        if path.is_symlink() or (not path.is_dir() and not path.is_file())
    ]
    if invalid_nodes:
        raise AssertionError(f"invalid quality evidence nodes: {invalid_nodes!r}")
    entries = _manifest_entries(evidence_root, manifest)
    actual = {
        path.relative_to(evidence_root).as_posix()
        for path in package.rglob("*")
        if path.is_file()
    }
    if set(entries) != actual:
        raise AssertionError("external manifest does not bind the exact package tree")
    if len(entries) != expected_file_count:
        raise AssertionError(
            "external manifest file count mismatch: "
            f"expected {expected_file_count}, got {len(entries)}"
        )
    return entries


class QualityFloorEvidenceCheckpointTest(unittest.TestCase):
    def test_pending_exception_is_only_the_untracked_or_introduction_state(self) -> None:
        source_checkpoint = "a" * 40
        later_revision = "b" * 40
        untracked = [
            (0, source_checkpoint),
            (0, ""),
            (0, f"?? {THIS_TEST}"),
        ]
        exact_introduction = [
            (0, source_checkpoint),
            (0, source_checkpoint),
            (0, ""),
        ]
        later_touch = [
            (0, later_revision),
            (0, source_checkpoint),
            (0, ""),
        ]
        readdition = [
            (0, later_revision),
            (0, f"{later_revision}\n{source_checkpoint}"),
            (0, ""),
        ]

        for responses, expected in (
            (untracked, True),
            (exact_introduction, True),
            (later_touch, False),
            (readdition, False),
        ):
            with self.subTest(expected=expected), mock.patch(
                __name__ + "._git", side_effect=responses
            ):
                self.assertEqual(_is_exact_pending_checkpoint(), expected)

    def test_external_manifest_tree_rejects_extra_root_children(self) -> None:
        for extra_name, directory in (
            ("unexpected.txt", False),
            ("stale-package", True),
        ):
            with self.subTest(extra_name=extra_name), tempfile.TemporaryDirectory() as tmp:
                evidence_root = Path(tmp)
                package = evidence_root / "package"
                package.mkdir()
                payload = package / "payload.json"
                payload.write_text("{}\n", encoding="utf-8")
                (evidence_root / "SHA256SUMS").write_text(
                    f"{sha256_file(payload)}  package/payload.json\n",
                    encoding="utf-8",
                )
                _verify_external_manifest_tree(
                    evidence_root,
                    "package",
                    expected_file_count=1,
                )
                extra = evidence_root / extra_name
                if directory:
                    extra.mkdir()
                else:
                    extra.write_text("unexpected\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    AssertionError, "root children are not exact"
                ):
                    _verify_external_manifest_tree(
                        evidence_root,
                        "package",
                        expected_file_count=1,
                    )

    def test_external_manifest_rejects_noncanonical_portable_paths(self) -> None:
        for unsafe in ("package\\payload.json", "package//payload.json"):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as tmp:
                evidence_root = Path(tmp)
                package = evidence_root / "package"
                package.mkdir()
                payload = package / "payload.json"
                payload.write_text("{}\n", encoding="utf-8")
                manifest = evidence_root / "SHA256SUMS"
                manifest.write_text(
                    f"{sha256_file(payload)}  {unsafe}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    AssertionError, "unsafe or duplicate manifest path"
                ):
                    _manifest_entries(evidence_root, manifest)

    def test_external_manifest_rejects_external_hardlink_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            evidence_root = parent / "evidence"
            package = evidence_root / "package"
            package.mkdir(parents=True)
            payload = package / "payload.json"
            payload.write_text("{}\n", encoding="utf-8")
            (evidence_root / "SHA256SUMS").write_text(
                f"{sha256_file(payload)}  package/payload.json\n",
                encoding="utf-8",
            )
            os.link(payload, parent / "outside-payload.json")
            with self.assertRaisesRegex(
                AssertionError, "external hard links"
            ):
                _verify_external_manifest_tree(
                    evidence_root,
                    "package",
                    expected_file_count=1,
                )


class QualityFloorEvidenceTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        receipt = PACKAGE / "receipt.json"
        if receipt.is_file():
            return
        if not EVIDENCE_ROOT.exists() and _is_exact_pending_checkpoint():
            raise unittest.SkipTest(
                "P10-08 exact-source checkpoint intentionally precedes evidence"
            )
        raise AssertionError("accepted P10-08 retained evidence is missing")

    def test_external_manifest_binds_exact_regular_evidence_tree(self) -> None:
        entries = _verify_external_manifest_tree(
            EVIDENCE_ROOT,
            PACKAGE_NAME,
            expected_file_count=167,
        )
        self.assertEqual(len(entries), 145 + 18 + 4)

    def test_package_shape_manifests_bundles_and_receipt_are_exact(self) -> None:
        self.assertEqual({path.name for path in PACKAGE.iterdir()}, EXPECTED_TOP)
        raw_files = {
            path.relative_to(PACKAGE / "raw").as_posix()
            for path in (PACKAGE / "raw").rglob("*")
            if path.is_file()
        }
        bundle_files = {
            path.relative_to(PACKAGE / "bundles").as_posix()
            for path in (PACKAGE / "bundles").rglob("*")
            if path.is_file()
        }
        self.assertEqual(len(raw_files), 145)
        self.assertEqual(bundle_files, EXPECTED_BUNDLES)
        self.assertEqual(len(bundle_files), 18)
        campaign.verify_raw_manifest(PACKAGE)
        self.assertEqual(
            len((PACKAGE / quality.RAW_MANIFEST_NAME).read_text(
                encoding="utf-8"
            ).splitlines()),
            163,
        )
        receipt = campaign.verify_retained_package(
            PACKAGE,
            require_accepted=True,
            source_root=ROOT,
            require_current_source=False,
        )
        self.assertEqual(receipt["status"], "accepted")
        self.assertEqual(receipt["availability"], "available")
        self.assertEqual(receipt["failures"], [])
        self.assertEqual(
            [row["id"] for row in receipt["metrics"]["rules"]],
            list(quality.EXPECTED_RULES),
        )
        self.assertTrue(all(
            row["diagnostic_precision"]["passed"]
            for row in receipt["metrics"]["rules"]
        ))
        self.assertTrue(receipt["metrics"]["micro_precision"]["passed"])
        self.assertTrue(receipt["metrics"]["addressable_recall"]["passed"])
        self.assertEqual(
            receipt["metrics"]["clean_corpus"],
            {"accepted_cases": 9, "required_cases": 9, "passed": True},
        )
        self.assertEqual(
            receipt["metrics"]["requested_tu_negatives"],
            {
                "accepted_cases": 2,
                "required_kinds": ["broken", "missing"],
                "passed": True,
            },
        )

    def test_historical_capability_blob_tampering_is_rejected(self) -> None:
        raw_root = PACKAGE / "raw"
        build_record, build_receipt = (
            campaign._verify_retained_build_authority_static(
                raw_root / campaign.BUILD_AUTHORITY_RAW_DIR
            )
        )
        source = campaign._verify_retained_source_authority(
            ROOT,
            build_receipt,
            require_current_source=False,
        )
        material = campaign._source_authority_material(
            ROOT, revision=build_receipt["source"]["revision"]
        )
        authority = campaign._validate_raw_authority_envelope(
            PACKAGE,
            source_root=ROOT,
            verified_source=source,
            verified_analyzer=campaign._campaign_analyzer_from_build(
                build_record
            ),
            verified_build=build_record,
            expected_scripts=material["scripts"],
        )
        tampered = {
            **material,
            "capability_registry": (
                material["capability_registry"]
                + b"// forged historical registry bytes\n"
            ),
        }
        with self.assertRaisesRegex(
            campaign.CampaignError, "input differs from raw-derived metrics"
        ):
            campaign._verify_retained_semantic_chain(
                PACKAGE,
                None,
                authority,
                source,
                require_accepted=True,
                source_material=tampered,
            )

    def test_build_source_and_execution_authorities_rederive(self) -> None:
        retained = PACKAGE / "raw" / campaign.BUILD_AUTHORITY_RAW_DIR
        payload = build_authority._verify_bundle_structure(
            retained,
            None,
            final=True,
            podman=build_authority.DEFAULT_PODMAN,
        )
        self.assertEqual(
            (retained / "operator.log").read_bytes(),
            build_authority._expected_operator_log(
                build_authority._inner_build_identity_from_final(payload)
            ),
        )
        record = campaign._build_authority_record(retained, payload)
        source = payload["source"]
        self.assertEqual(
            determinism.source_manifest_at_revision(ROOT, source["revision"]),
            source,
        )
        determinism._verify_source_authority(
            source,
            ROOT,
            "retained P10-08 evidence",
            require_current_source=False,
        )

        launch_path = PACKAGE / "raw" / campaign.CAMPAIGN_LAUNCH_NAME
        execution = campaign._validate_retained_execution_authority(
            launch_path, record
        )
        authority = campaign.strict_json(
            PACKAGE / "raw" / campaign.AUTHORITY_NAME
        )
        quality_input = campaign.strict_json(
            PACKAGE / "quality-floor-input.json"
        )
        self.assertEqual(authority["analyzer_build_authority"], record)
        self.assertEqual(authority["execution_authority"], execution)
        self.assertEqual(authority["source"], quality_input["identity"]["source"])
        self.assertEqual(
            authority["analyzer"], quality_input["identity"]["analyzer"]
        )
        self.assertEqual(
            execution["build_identity_sha256"],
            record["build_identity_sha256"],
        )
        self.assertEqual(execution["action"], "run")
        self.assertEqual(execution["image"], record["runtime"]["image"])

    def test_retained_runtime_v1_requires_exact_p10_08_provenance(self) -> None:
        retained = PACKAGE / "raw" / campaign.BUILD_AUTHORITY_RAW_DIR
        payload = build_authority._verify_bundle_structure(
            retained,
            None,
            final=True,
            podman=build_authority.DEFAULT_PODMAN,
        )
        record = campaign._build_authority_record(retained, payload)
        launch_path = PACKAGE / "raw" / campaign.CAMPAIGN_LAUNCH_NAME
        launch = campaign.strict_json(launch_path)
        self.assertEqual(
            campaign.sha256_file(launch_path),
            campaign.RETAINED_RUNTIME_V1_LAUNCH_SHA256,
        )
        self.assertEqual(
            record["source"]["revision"],
            campaign.RETAINED_RUNTIME_V1_SOURCE_REVISION,
        )
        self.assertEqual(
            record["build_identity_sha256"],
            campaign.RETAINED_RUNTIME_V1_BUILD_IDENTITY_SHA256,
        )
        campaign._validate_retained_execution_authority(launch_path, record)

        forged_record = campaign.copy_json(record)
        forged_record["source"]["revision"] = "0" * 40
        with self.assertRaisesRegex(
            campaign.CampaignError, "runtime v1 provenance drift"
        ):
            campaign._validate_retained_execution_authority(
                launch_path, forged_record
            )

        with tempfile.TemporaryDirectory() as directory:
            changed_path = Path(directory) / campaign.CAMPAIGN_LAUNCH_NAME
            changed = campaign.copy_json(launch)
            changed["runtime"]["normalized_argv"].append("--privileged")
            changed["runtime"]["normalized_argv_sha256"] = (
                campaign.compact_json_digest(
                    changed["runtime"]["normalized_argv"]
                )
            )
            campaign.write_json(changed_path, changed)
            with self.assertRaisesRegex(
                campaign.CampaignError, "runtime v1 provenance drift"
            ):
                campaign._validate_retained_execution_authority(
                    changed_path, record
                )

    def test_repository_preserves_quality_evidence_bytes(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("docs/evidence/phase10/quality/** -text\n", attributes)
        self.assertIn("docs/evidence/phase10/quality/** -diff\n", attributes)


if __name__ == "__main__":
    unittest.main()
