#!/usr/bin/env python3
"""Fail-closed contracts for the portable P10-09 evidence export."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "scripts" / "export_stability_evidence.py"
STAGING_TEST = ROOT / "tests" / "StabilityStagingProducerTest.py"
REVISION = "a" * 40
BUNDLE_SHA256 = "b" * 64


def load_exporter():
    specification = importlib.util.spec_from_file_location(
        "stability_evidence_exporter", EXPORTER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import stability exporter: {EXPORTER}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


exporter = load_exporter() if EXPORTER.is_file() else None


def load_staging_fixture():
    specification = importlib.util.spec_from_file_location(
        "stability_export_staging_fixture", STAGING_TEST
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import staging fixture: {STAGING_TEST}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def canonical_document(value: object) -> bytes:
    return (
        json.dumps(
            value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
        )
        + "\n"
    ).encode("utf-8")


def sha(character: str) -> str:
    return character * 64


def write(path: Path, data: bytes, mode: int = 0o444) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def fixture_roots(root: Path):
    roots = exporter.SnapshotRoots(
        authority=root / "authority",
        bundle=root / "bundle",
        operator=root / "operator",
        config=root / "config",
        launch=root / "launch-accepted",
        session=(
            root
            / "20260825T120000Z-11111111-1111-1111-1111-111111111111-"
            "22222222-2222-2222-2222-222222222222"
        ),
    )
    for path in roots:
        path.mkdir(parents=True)
    for name in exporter.BUNDLE_METADATA_FILES:
        write(roots.bundle / name, f"fixture {name}\n".encode("ascii"))
    write(roots.authority / "source" / "runner.py", b"runner\n", 0o555)
    write(roots.authority / "build" / "codeskeptic", b"binary\n", 0o555)
    write(roots.operator / "run-authoritative-stability.sh", b"operator\n", 0o555)
    config = canonical_document({"fixture": "config"})
    write(roots.config / "runtime.json", config)
    write(
        roots.config / "runtime.json.sha256",
        f"{hashlib.sha256(config).hexdigest()}  runtime.json\n".encode("ascii"),
    )
    launch = canonical_document({"fixture": "launch"})
    write(roots.launch / "receipt.json", launch)
    write(
        roots.launch / "receipt.json.sha256",
        f"{hashlib.sha256(launch).hexdigest()}  receipt.json\n".encode("ascii"),
    )
    write(roots.session / "campaign" / "receipt.json", b"campaign\n")
    write(roots.session / "host" / "cleanup.json", b"cleanup\n")
    write(roots.session / "receipt.json", b"outer\n")
    return roots


def bootstrap_identity(roots, revision=REVISION, digest=BUNDLE_SHA256):
    return {
        "bundle_receipt_sha256": digest,
        "runtime_config_sha256": sha("c"),
        "session_name": roots.session.name,
        "source_manifest_sha256": sha("d"),
        "source_revision": revision,
        "source_tree_sha1": "e" * 40,
    }


def semantic_identity(_roots):
    return {
        "inner_receipt_sha256": sha("f"),
        "outer_receipt_sha256": sha("1"),
        "session_id": sha("2"),
    }


class ExporterPresenceTest(unittest.TestCase):
    def test_exporter_exists(self):
        self.assertTrue(EXPORTER.is_file(), "missing portable stability exporter")


@unittest.skipIf(exporter is None, "exporter has not been implemented")
class StabilityEvidenceExportTest(unittest.TestCase):
    def test_real_sealed_bootstrap_rejects_extra_authority_file(self):
        fixture = load_staging_fixture()
        with fixture.sealed_bundle_fixture() as (
            workspace, _prepared, revision, sealed, bundle_receipt
        ):
            launch = workspace / "launch-accepted"
            launch.mkdir()
            launch_data = canonical_document({"fixture": "launch"})
            write(launch / "receipt.json", launch_data)
            write(
                launch / "receipt.json.sha256",
                (
                    f"{hashlib.sha256(launch_data).hexdigest()}  receipt.json\n"
                ).encode("ascii"),
            )
            session = (
                workspace
                / "20260825T120000Z-11111111-1111-1111-1111-111111111111-"
                "22222222-2222-2222-2222-222222222222"
            )
            (session / "host").mkdir(parents=True)
            bundle_receipt_path = sealed / "bundle" / "receipt.json"
            bundle_sha = hashlib.sha256(
                bundle_receipt_path.read_bytes()
            ).hexdigest()
            stage = fixture.stage
            self.assertIsNotNone(stage)
            installation_authority = {
                "bundle_receipt_sha256": bundle_sha,
                "bundle_revision": revision,
                "schema": stage.INSTALLATION_AUTHORITY_SCHEMA,
            }
            installation_receipt = {
                "authority_root": "/opt/codeskeptic-p10-09/authority",
                "bundle_inventory_sha256": bundle_receipt["inventory_sha256"],
                "bundle_receipt_sha256": bundle_sha,
                "bundle_revision": revision,
                "config_path": "/etc/codeskeptic-p10-09/runtime.json",
                "image": {
                    "archive_sha256": bundle_receipt["image_archive_sha256"],
                    "digest": stage.PINNED_EVIDENCE_IMAGE_DIGEST,
                    "id": stage.PINNED_EVIDENCE_IMAGE_ID,
                    "reference": stage.PINNED_EVIDENCE_IMAGE,
                },
                "installed_inventory_sha256": bundle_receipt["inventory_sha256"],
                "operator_root": "/opt/codeskeptic-p10-09/operator",
                "schema": stage.INSTALLATION_RECEIPT_SCHEMA,
                "unit_path": "/etc/systemd/system/codeskeptic-stability.service",
            }
            installation = {
                "bundle_inventory_sha256": bundle_receipt["inventory_sha256"],
                "bundle_receipt_sha256": bundle_sha,
                "bundle_revision": revision,
                "image_archive_sha256": bundle_receipt["image_archive_sha256"],
                "image_digest": stage.PINNED_EVIDENCE_IMAGE_DIGEST,
                "image_id": stage.PINNED_EVIDENCE_IMAGE_ID,
                "image_reference": stage.PINNED_EVIDENCE_IMAGE,
                "installation_authority_sha256": hashlib.sha256(
                    stage.canonical_document(installation_authority)
                ).hexdigest(),
                "installation_receipt_sha256": hashlib.sha256(
                    stage.canonical_document(installation_receipt)
                ).hexdigest(),
                "installed_inventory_sha256": bundle_receipt["inventory_sha256"],
                "runtime_config_sha256": bundle_receipt["runtime_config_sha256"],
                "source_manifest_sha256": bundle_receipt[
                    "source_manifest_sha256"
                ],
                "source_tree_sha1": bundle_receipt["source_tree_sha1"],
            }
            intent = {
                "boot_id": "1" * 36,
                "containers": {},
                "installation": installation,
                "mode": "campaign",
                "schema": "fixture",
                "session": session.name,
                "session_nonce": "2" * 36,
                "status": "armed",
            }
            write(
                session / "host" / "host-recovery-intent.json",
                exporter.canonical_json(intent) + b"\n",
            )

            def record(fixed: str, copied: Path) -> dict[str, object]:
                return {
                    "path": fixed,
                    "sha256": hashlib.sha256(copied.read_bytes()).hexdigest(),
                    "size": copied.stat().st_size,
                }

            config = sealed / "config"
            authority = sealed / "authority"
            operator = sealed / "operator"
            fixed_launch = (
                f"/var/lib/codeskeptic-p10-09/launches/{launch.name}/receipt.json"
            )
            outer = {
                "session": {"name": session.name},
                "authorities": {
                    "config": record(
                        "/etc/codeskeptic-p10-09/runtime.json",
                        config / "runtime.json",
                    ),
                    "config_checksum": record(
                        "/etc/codeskeptic-p10-09/runtime.json.sha256",
                        config / "runtime.json.sha256",
                    ),
                    "launch_receipt": record(
                        fixed_launch, launch / "receipt.json"
                    ),
                    "launch_checksum": record(
                        fixed_launch + ".sha256",
                        launch / "receipt.json.sha256",
                    ),
                    "operator": record(
                        "/opt/codeskeptic-p10-09/operator/"
                        "run-authoritative-stability.sh",
                        operator / "run-authoritative-stability.sh",
                    ),
                    "runner": record(
                        "/opt/codeskeptic-p10-09/authority/source/scripts/"
                        "run_stability_campaign.py",
                        authority / "source/scripts/run_stability_campaign.py",
                    ),
                },
            }
            write(session / "receipt.json", canonical_document(outer))
            roots = exporter.SnapshotRoots(
                authority=authority.resolve(strict=True),
                bundle=(sealed / "bundle").resolve(strict=True),
                operator=operator.resolve(strict=True),
                config=config.resolve(strict=True),
                launch=launch.resolve(strict=True),
                session=session.resolve(strict=True),
            )
            result = exporter.bootstrap_authorities(
                roots, revision, bundle_sha, workspace
            )
            self.assertEqual(result["source_revision"], revision)
            self.assertEqual(result["bundle_receipt_sha256"], bundle_sha)
            self.assertEqual(
                result["runtime_config_sha256"],
                bundle_receipt["runtime_config_sha256"],
            )
            portable = workspace / "portable-evidence"
            exported = exporter.export_evidence(
                roots,
                portable,
                expected_source_revision=revision,
                expected_bundle_receipt_sha256=bundle_sha,
                semantic_verifier=semantic_identity,
            )
            self.assertEqual(
                exporter.verify_export(
                    portable,
                    expected_source_revision=revision,
                    expected_bundle_receipt_sha256=bundle_sha,
                    semantic_verifier=semantic_identity,
                ),
                exported,
            )
            authority.chmod(0o755)
            try:
                write(
                    authority / "UNEXPECTED-EXTRA.txt",
                    b"not present in the sealed bundle inventory\n",
                )
            finally:
                authority.chmod(0o555)
            with self.assertRaisesRegex(
                exporter.ExportError,
                "installed authority differs from sealed bundle inventory",
            ):
                exporter.bootstrap_authorities(
                    roots, revision, bundle_sha, workspace
                )
            with self.assertRaisesRegex(
                exporter.ExportError,
                "installed authority differs from sealed bundle inventory",
            ):
                exporter.export_evidence(
                    roots,
                    workspace / "rejected-portable-evidence",
                    expected_source_revision=revision,
                    expected_bundle_receipt_sha256=bundle_sha,
                    semantic_verifier=semantic_identity,
                )

    def test_export_is_create_new_canonical_compact_and_offline_replayable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            inputs = fixture_roots(root / "inputs")
            output = root / "portable-evidence"
            seen: list[exporter.SnapshotRoots] = []

            def bootstrap(roots, revision, digest, scratch_root):
                del scratch_root
                self.assertEqual(revision, REVISION)
                self.assertEqual(digest, BUNDLE_SHA256)
                seen.append(roots)
                return bootstrap_identity(roots, revision, digest)

            receipt = exporter.export_evidence(
                inputs,
                output,
                expected_source_revision=REVISION,
                expected_bundle_receipt_sha256=BUNDLE_SHA256,
                bootstrap_verifier=bootstrap,
                semantic_verifier=semantic_identity,
            )
            self.assertEqual(receipt["schema"], exporter.RECEIPT_SCHEMA)
            self.assertEqual(receipt["status"], "accepted")
            self.assertEqual(receipt["failures"], [])
            self.assertEqual(
                set(receipt),
                {
                    "schema",
                    "status",
                    "identity",
                    "inventory",
                    "payload",
                    "semantic_verification",
                    "gates",
                    "failures",
                },
            )
            self.assertLess((output / "receipt.json").stat().st_size, 64 * 1024)
            self.assertEqual(
                (output / "receipt.json").read_bytes(), canonical_document(receipt)
            )
            self.assertEqual(
                sorted(path.name for path in (output / "payload").iterdir()),
                list(exporter.COMPONENTS),
            )
            self.assertTrue(seen)
            for copied in seen:
                self.assertEqual(copied.launch.name, inputs.launch.name)
                self.assertEqual(copied.session.name, inputs.session.name)
                for path in copied:
                    self.assertFalse(
                        any(path.is_relative_to(source) for source in inputs)
                    )

            verified = exporter.verify_export(
                output,
                expected_source_revision=REVISION,
                expected_bundle_receipt_sha256=BUNDLE_SHA256,
                bootstrap_verifier=bootstrap,
                semantic_verifier=semantic_identity,
            )
            self.assertEqual(verified, receipt)
            with self.assertRaisesRegex(exporter.ExportError, "already exists"):
                exporter.export_evidence(
                    inputs,
                    output,
                    expected_source_revision=REVISION,
                    expected_bundle_receipt_sha256=BUNDLE_SHA256,
                    bootstrap_verifier=bootstrap,
                    semantic_verifier=semantic_identity,
                )

    def test_verify_rejects_payload_checksum_mode_and_inventory_drift(self):
        mutations = ("content", "mode", "unexpected")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(strict=True)
                inputs = fixture_roots(root / "inputs")
                output = root / "portable-evidence"
                exporter.export_evidence(
                    inputs,
                    output,
                    expected_source_revision=REVISION,
                    expected_bundle_receipt_sha256=BUNDLE_SHA256,
                    bootstrap_verifier=lambda roots, revision, digest, scratch: (
                        bootstrap_identity(roots, revision, digest)
                    ),
                    semantic_verifier=semantic_identity,
                )
                target = output / "payload" / "authority" / "source" / "runner.py"
                if mutation == "content":
                    target.chmod(0o644)
                    target.write_bytes(b"changed\n")
                    target.chmod(0o555)
                elif mutation == "mode":
                    target.chmod(0o444)
                else:
                    unexpected = output / "payload" / "authority" / "extra"
                    write(unexpected, b"unexpected\n")
                with self.assertRaisesRegex(exporter.ExportError, "inventory"):
                    exporter.verify_export(
                        output,
                        expected_source_revision=REVISION,
                        expected_bundle_receipt_sha256=BUNDLE_SHA256,
                        bootstrap_verifier=lambda roots, revision, digest, scratch: (
                            bootstrap_identity(roots, revision, digest)
                        ),
                        semantic_verifier=semantic_identity,
                    )

    def test_named_component_wrappers_reject_extra_unsafe_and_renamed_roots(self):
        for mutation in ("extra", "unsafe", "renamed"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(strict=True)
                inputs = fixture_roots(root / "inputs")
                output = root / "portable-evidence"
                exporter.export_evidence(
                    inputs,
                    output,
                    expected_source_revision=REVISION,
                    expected_bundle_receipt_sha256=BUNDLE_SHA256,
                    bootstrap_verifier=lambda roots, revision, digest, scratch: (
                        bootstrap_identity(roots, revision, digest)
                    ),
                    semantic_verifier=semantic_identity,
                )
                component = "session" if mutation != "renamed" else "launch"
                wrapper = output / "payload" / component
                child = next(wrapper.iterdir())
                wrapper.chmod(0o755)
                try:
                    if mutation == "extra":
                        (wrapper / "unexpected-second-root").mkdir()
                    elif mutation == "unsafe":
                        child.rename(wrapper / "unsafe\nname")
                    else:
                        child.rename(wrapper / "renamed-launch")
                finally:
                    wrapper.chmod(0o555)
                with self.assertRaisesRegex(
                    exporter.ExportError,
                    "inventory|inadmissible|wrapper",
                ):
                    exporter.verify_export(
                        output,
                        expected_source_revision=REVISION,
                        expected_bundle_receipt_sha256=BUNDLE_SHA256,
                        bootstrap_verifier=lambda roots, revision, digest, scratch: (
                            bootstrap_identity(roots, revision, digest)
                        ),
                        semantic_verifier=semantic_identity,
                    )

    def test_verify_rejects_noncanonical_metadata_and_self_nominated_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            inputs = fixture_roots(root / "inputs")
            output = root / "portable-evidence"
            exporter.export_evidence(
                inputs,
                output,
                expected_source_revision=REVISION,
                expected_bundle_receipt_sha256=BUNDLE_SHA256,
                bootstrap_verifier=lambda roots, revision, digest, scratch: (
                    bootstrap_identity(roots, revision, digest)
                ),
                semantic_verifier=semantic_identity,
            )
            with self.assertRaisesRegex(exporter.ExportError, "out-of-band"):
                exporter.verify_export(
                    output,
                    expected_source_revision="9" * 40,
                    expected_bundle_receipt_sha256=BUNDLE_SHA256,
                    bootstrap_verifier=lambda roots, revision, digest, scratch: (
                        bootstrap_identity(roots, revision, digest)
                    ),
                    semantic_verifier=semantic_identity,
                )
            receipt_path = output / "receipt.json"
            receipt_path.chmod(0o644)
            parsed = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt_path.write_text(json.dumps(parsed) + "\n", encoding="utf-8")
            receipt_path.chmod(0o444)
            with self.assertRaisesRegex(exporter.ExportError, "canonical"):
                exporter.verify_export(
                    output,
                    expected_source_revision=REVISION,
                    expected_bundle_receipt_sha256=BUNDLE_SHA256,
                    bootstrap_verifier=lambda roots, revision, digest, scratch: (
                        bootstrap_identity(roots, revision, digest)
                    ),
                    semantic_verifier=semantic_identity,
                )

    def test_export_rejects_symlinks_fifos_and_hardlinks(self):
        for mutation in ("symlink", "fifo", "hardlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(strict=True)
                inputs = fixture_roots(root / "inputs")
                authority = inputs.authority
                if mutation == "symlink":
                    (authority / "alias").symlink_to("source/runner.py")
                elif mutation == "fifo":
                    os.mkfifo(authority / "pipe", 0o600)
                else:
                    os.link(
                        authority / "source" / "runner.py",
                        authority / "runner-hardlink.py",
                    )
                with self.assertRaisesRegex(
                    exporter.ExportError, "regular|link|inventory"
                ):
                    exporter.export_evidence(
                        inputs,
                        root / "portable-evidence",
                        expected_source_revision=REVISION,
                        expected_bundle_receipt_sha256=BUNDLE_SHA256,
                        bootstrap_verifier=lambda roots, revision, digest, scratch: (
                            bootstrap_identity(roots, revision, digest)
                        ),
                        semantic_verifier=semantic_identity,
                    )

    def test_source_root_and_fixed_small_root_inventories_are_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            inputs = fixture_roots(root / "inputs")
            write(inputs.config / "extra", b"drift\n")
            with self.assertRaisesRegex(exporter.ExportError, "config.*inventory"):
                exporter.export_evidence(
                    inputs,
                    root / "portable-evidence",
                    expected_source_revision=REVISION,
                    expected_bundle_receipt_sha256=BUNDLE_SHA256,
                    bootstrap_verifier=lambda roots, revision, digest, scratch: (
                        bootstrap_identity(roots, revision, digest)
                    ),
                    semantic_verifier=semantic_identity,
                )

    def test_bwrap_replay_has_only_toolchain_plus_exported_authorities(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            inputs = fixture_roots(root / "inputs")
            # This contract checks the namespace topology, not whether the
            # development host happens to have bubblewrap installed.  The
            # production path still performs the fail-closed executable
            # checks before every real replay.
            with mock.patch.object(exporter, "_require_regular_executable"):
                commands = exporter.semantic_commands(inputs)
            self.assertEqual(len(commands), 2)
            for command in commands:
                self.assertEqual(command[0], "/usr/bin/bwrap")
                self.assertIn("--unshare-net", command)
                self.assertNotIn("/", command[command.index("--ro-bind") + 1 :][:1])
                self.assertNotIn("--bind", command)
                self.assertIn("/usr", command)
                self.assertIn("/opt/codeskeptic-p10-09/authority", command)
                self.assertIn("/opt/codeskeptic-p10-09/operator", command)
                self.assertIn("/var/lib/codeskeptic-p10-09/sessions", command)
                self.assertIn("/var/lib/codeskeptic-p10-09/launches", command)
                self.assertIn("/config", command)
                self.assertIn("/authority", command)
                self.assertIn("/evidence", command)
            self.assertIn("verify", commands[0])
            self.assertIn("verify-operator", commands[1])
            self.assertEqual(
                commands[0][commands[0].index("--nofile=4096:4096") + 1], "--"
            )

    def test_semantic_runner_requires_two_exact_success_markers(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots = fixture_roots(Path(temporary).resolve(strict=True) / "inputs")
            outputs = iter(
                (
                    subprocess.CompletedProcess(
                        [], 0,
                        stdout=(
                            f"CODESKEPTIC_STABILITY_VERIFIED {sha('f')} {sha('2')}\n"
                        ).encode("ascii"),
                        stderr=b"",
                    ),
                    subprocess.CompletedProcess(
                        [], 0,
                        stdout=(
                            "CODESKEPTIC_OPERATOR_EVIDENCE_VERIFIED "
                            f"{sha('1')} {sha('2')}\n"
                        ).encode("ascii"),
                        stderr=b"",
                    ),
                )
            )
            # The injected runner makes this a parser/marker contract.  Keep
            # host executable discovery outside that unit boundary so it is
            # portable to the pinned offline build image.
            with mock.patch.object(exporter, "_require_regular_executable"):
                result = exporter.run_semantic_verifiers(
                    roots, command_runner=lambda argv, timeout: next(outputs)
                )
            self.assertEqual(result, semantic_identity(roots))

            failures = (
                subprocess.CompletedProcess([], 2, stdout=b"", stderr=b"fail\n"),
                subprocess.CompletedProcess(
                    [], 0,
                    stdout=(
                        f"CODESKEPTIC_STABILITY_VERIFIED {sha('f')} {sha('2')}\nextra\n"
                    ).encode("ascii"),
                    stderr=b"",
                ),
            )
            for failed in failures:
                with self.subTest(failed=failed), self.assertRaisesRegex(
                    exporter.ExportError, "semantic"
                ):
                    with mock.patch.object(
                        exporter, "_require_regular_executable"
                    ):
                        exporter.run_semantic_verifiers(
                            roots,
                            command_runner=lambda argv, timeout, value=failed: value,
                        )

    def test_cli_requires_out_of_band_identity_for_export_and_verify(self):
        parser = exporter.build_parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["verify", "--bundle", "/tmp/bundle"])
        parsed = parser.parse_args(
            [
                "verify",
                "--bundle",
                "/tmp/bundle",
                "--expected-source-revision",
                REVISION,
                "--expected-bundle-receipt-sha256",
                BUNDLE_SHA256,
            ]
        )
        self.assertEqual(parsed.command, "verify")
        export_arguments = [
            "export",
            "--authority-root", "/tmp/authority",
            "--operator-root", "/tmp/operator",
            "--config-root", "/tmp/config",
            "--launch-root", "/tmp/launch",
            "--session-root", "/tmp/session",
            "--output", "/tmp/output",
            "--expected-source-revision", REVISION,
            "--expected-bundle-receipt-sha256", BUNDLE_SHA256,
        ]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(export_arguments)
        parsed = parser.parse_args(
            [*export_arguments, "--bundle-root", "/tmp/installation/bundle"]
        )
        self.assertEqual(parsed.bundle_root, Path("/tmp/installation/bundle"))


if __name__ == "__main__":
    unittest.main()
