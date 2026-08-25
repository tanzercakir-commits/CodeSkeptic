#!/usr/bin/env python3
"""Focused tests for the durable P10-09 whole-host recovery authority."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "stability-systemd" / "host-recovery.py"
OPERATOR_PATH = (
    ROOT / "scripts" / "stability-systemd" / "run-authoritative-stability.sh"
)
SPEC = importlib.util.spec_from_file_location("codeskeptic_host_recovery", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
host_recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host_recovery)


BOOT_ID = "11111111-1111-4111-8111-111111111111"
NONCE = "22222222-2222-4222-8222-222222222222"
SESSION = f"20260824T120000Z-{BOOT_ID}-{NONCE}"
REVISION = "a" * 40
CONTAINER_ID = "b" * 64


def preflight_python() -> str:
    source = OPERATOR_PATH.read_text(encoding="utf-8")
    matched = re.search(
        r"readonly PREFLIGHT_PYTHON='(.*?)'\n\n"
        r"readonly -a RUNTIME_CONTROLLER_COMMAND",
        source,
        re.DOTALL,
    )
    assert matched is not None
    return matched.group(1)


def pretty_canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def compact_canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


class FakePodman:
    def __init__(self) -> None:
        self.containers: dict[str, dict[str, object]] = {}
        self.removed: list[str] = []
        self.required_marker: Path | None = None
        self.required_absent_on_remove: Path | None = None
        self.image_id = host_recovery.PINNED_EVIDENCE_IMAGE_ID
        self.image_digest = host_recovery.PINNED_EVIDENCE_IMAGE_DIGEST
        self.image_inventory = [host_recovery.PINNED_EVIDENCE_IMAGE_ID]
        self.version = host_recovery.PINNED_PODMAN_VERSION

    def add_owned(
        self,
        marker: dict[str, object],
        kind: str,
        identifier: str = CONTAINER_ID,
    ) -> dict[str, object]:
        name = host_recovery.container_name(marker, kind)
        if kind == "campaign":
            command = list(host_recovery.RUNTIME_CONTROLLER_COMMAND)
        elif kind == "verifier":
            command = list(host_recovery.RUNTIME_VERIFIER_COMMAND)
        else:
            command = [
                "/usr/bin/taskset",
                "--cpu-list",
                "4-11",
                "/usr/bin/python3",
                "-B",
                "-c",
                preflight_python(),
                host_recovery.CONTROLLER_CGROUP_RELATIVE,
                os.fspath(host_recovery.MEASUREMENT_CGROUP),
                f"{host_recovery.PAYLOAD_CGROUP_RELATIVE}/measurement",
                host_recovery.MEASUREMENT_CPU_LIST,
            ]
        mounts = [
            {
                "Destination": destination,
                "Options": ["nosuid", "nodev", "rbind"],
                "Propagation": "rprivate",
                "RW": writable,
                "Source": source,
                "Type": "bind",
            }
            for destination, (source, writable) in sorted(
                host_recovery.expected_container_mounts(marker, kind).items()
            )
        ]
        inspection: dict[str, object] = {
            "Args": command[1:],
            "Config": {
                "Cmd": command,
                "Entrypoint": "",
                "Env": [
                    f"{key}={value}"
                    for key, value in sorted(
                        host_recovery.CONTAINER_ENVIRONMENT.items()
                    )
                ],
                "Image": host_recovery.PINNED_EVIDENCE_IMAGE,
                "Labels": {
                    **host_recovery.IMAGE_CONFIG_LABELS,
                    **host_recovery.expected_container_labels(marker, kind),
                },
                "User": "0:0",
                "WorkingDir": host_recovery.CONTAINER_WORKDIR,
            },
            "HostConfig": {
                "AutoRemove": False,
                "Binds": host_recovery.expected_container_binds(marker, kind),
                "CapAdd": [],
                "CapDrop": [],
                "Cgroup": "",
                "CgroupManager": "cgroupfs",
                "CgroupMode": "host",
                "CgroupParent": "",
                "Cgroups": "disabled",
                "CpusetCpus": "",
                "ContainerIDFile": os.fspath(
                    host_recovery.expected_container_cidfile(marker, kind)
                ),
                "IpcMode": "private",
                "NetworkMode": "none",
                "PidMode": "private",
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
                "SecurityOpt": ["label=disable", "no-new-privileges"],
                "Ulimits": [
                    {"Hard": 4096, "Name": "RLIMIT_NOFILE", "Soft": 4096}
                ],
                "UTSMode": "private",
                "UsernsMode": "",
                "Devices": [],
            },
            "Driver": "overlay",
            "Id": identifier,
            "Image": host_recovery.PINNED_EVIDENCE_IMAGE_ID.removeprefix("sha256:"),
            "ImageDigest": host_recovery.PINNED_EVIDENCE_IMAGE_DIGEST,
            "ImageName": host_recovery.PINNED_EVIDENCE_IMAGE,
            "IsInfra": False,
            "IsService": False,
            "Mounts": mounts,
            "Name": name,
            "NetworkSettings": {"Ports": {}},
            "OCIRuntime": os.fspath(host_recovery.CRUN),
            "Path": command[0],
            "Pod": "",
            "ProcessLabel": "",
            "State": {
                "ConmonPid": 4241,
                "Dead": False,
                "Paused": False,
                "Pid": 4242,
                "Restarting": False,
                "Running": True,
                "Status": "running",
                "StoppedByUser": False,
            },
        }
        self.containers[identifier] = inspection
        return inspection

    def __call__(
        self,
        argv: list[str],
        *,
        capture_output: bool,
        text: bool,
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        self.assert_invocation_contract(capture_output, text, check)
        if self.required_marker is not None and not self.required_marker.exists():
            raise AssertionError("Podman was accessed before durable marker publication")
        if "version" in argv:
            return subprocess.CompletedProcess(
                argv,
                0,
                f"{self.version}\n".encode("ascii"),
                b"",
            )
        if "image" in argv and "inspect" in argv:
            output = (
                f"{self.image_id}|{self.image_digest}\n"
            ).encode("ascii")
            return subprocess.CompletedProcess(argv, 0, output, b"")
        if "image" in argv and "list" in argv:
            output = "".join(
                f"{identifier}\n" for identifier in self.image_inventory
            ).encode("ascii")
            return subprocess.CompletedProcess(argv, 0, output, b"")
        if "list" in argv:
            output = "".join(f"{identifier}\n" for identifier in self.containers)
            return subprocess.CompletedProcess(argv, 0, output.encode("ascii"), b"")
        if "inspect" in argv:
            identifier = argv[-1]
            value = self.containers.get(identifier)
            if value is None:
                return subprocess.CompletedProcess(argv, 125, b"", b"not found")
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([value]).encode("utf-8"), b""
            )
        if "rm" in argv:
            if self.required_absent_on_remove is not None:
                assert not self.required_absent_on_remove.exists()
                assert not self.required_absent_on_remove.is_symlink()
            identifier = argv[-1]
            self.removed.append(identifier)
            self.containers.pop(identifier, None)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(f"unexpected Podman command: {argv!r}")

    @staticmethod
    def assert_invocation_contract(
        capture_output: bool, text: bool, check: bool
    ) -> None:
        assert capture_output is True
        assert text is False
        assert check is False


class HostRecoveryTest(unittest.TestCase):
    def test_podman_commands_use_only_the_pinned_host_environment(self) -> None:
        argv = host_recovery._podman_argv(("version",))
        self.assertEqual(
            argv[:3],
            [os.fspath(host_recovery.ENV), "--ignore-environment", "--"],
        )
        podman_index = argv.index(os.fspath(host_recovery.PODMAN))
        environment = argv[3:podman_index]
        self.assertIn(
            f"CONTAINERS_CONF={host_recovery.CONTAINERS_CONF}", environment
        )
        self.assertIn("LANG=C", environment)
        self.assertIn("LC_ALL=C", environment)
        self.assertIn(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            environment,
        )
        self.assertFalse(
            any(item.startswith("CONTAINERS_CONF_OVERRIDE=") for item in environment)
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "var" / "lib" / "codeskeptic-p10-09"
        self.runtime = self.root / "run" / "codeskeptic-p10-09"
        self.installation_authority = (
            self.state / "installation-authority.json"
        )
        self.installation = self.root / "opt" / "installation" / "receipt.json"
        self.installation_sha = self.installation.with_name("receipt.json.sha256")
        self.bundle_receipt = (
            self.installation.parent / "bundle" / "receipt.json"
        )
        self.bundle_receipt_sha = self.bundle_receipt.with_name(
            "receipt.json.sha256"
        )
        self.cgroup = self.root / "opt" / "operator" / "cgroup-authority.py"
        self.boot_id = self.root / "proc" / "boot_id"
        self.state.mkdir(parents=True, mode=0o700)
        self.runtime.mkdir(parents=True, mode=0o700)
        self.installation.parent.mkdir(parents=True)
        self.bundle_receipt.parent.mkdir()
        self.cgroup.parent.mkdir(parents=True)
        self.cgroup.write_text("#!/bin/true\n", encoding="ascii")
        self.cgroup.chmod(0o500)
        self.boot_id.parent.mkdir(parents=True)
        self.boot_id.write_text(f"{BOOT_ID}\n", encoding="ascii")
        bundle_receipt = {
            "image_archive_sha256": "5" * 64,
            "image_digest": host_recovery.PINNED_EVIDENCE_IMAGE_DIGEST,
            "image_id": host_recovery.PINNED_EVIDENCE_IMAGE_ID,
            "image_reference": host_recovery.PINNED_EVIDENCE_IMAGE,
            "inventory_sha256": "1" * 64,
            "revision": REVISION,
            "runtime_config_sha256": "6" * 64,
            "schema": host_recovery.BUNDLE_RECEIPT_SCHEMA,
            "source_manifest_sha256": "7" * 64,
            "source_tree_sha1": "8" * 40,
        }
        bundle_raw = pretty_canonical(bundle_receipt)
        self.bundle_digest = hashlib.sha256(bundle_raw).hexdigest()
        self.bundle_receipt.write_bytes(bundle_raw)
        self.bundle_receipt.chmod(0o400)
        self.bundle_receipt_sha.write_text(
            f"{self.bundle_digest}  receipt.json\n", encoding="ascii"
        )
        self.bundle_receipt_sha.chmod(0o400)
        self.installation_authority.write_bytes(
            pretty_canonical(
                {
                    "bundle_receipt_sha256": self.bundle_digest,
                    "bundle_revision": REVISION,
                    "schema": host_recovery.INSTALLATION_AUTHORITY_SCHEMA,
                }
            )
        )
        self.installation_authority.chmod(0o400)
        receipt = {
            "authority_root": "/opt/codeskeptic-p10-09/authority",
            "bundle_inventory_sha256": "1" * 64,
            "bundle_receipt_sha256": self.bundle_digest,
            "bundle_revision": REVISION,
            "config_path": "/etc/codeskeptic-p10-09/runtime.json",
            "image": {
                "archive_sha256": "5" * 64,
                "digest": host_recovery.PINNED_EVIDENCE_IMAGE_DIGEST,
                "id": host_recovery.PINNED_EVIDENCE_IMAGE_ID,
                "reference": host_recovery.PINNED_EVIDENCE_IMAGE,
            },
            "installed_inventory_sha256": "1" * 64,
            "operator_root": "/opt/codeskeptic-p10-09/operator",
            "schema": "codeskeptic-stability-installation-v1",
            "unit_path": "/etc/systemd/system/codeskeptic-stability.service",
        }
        receipt_raw = pretty_canonical(receipt)
        self.installation.write_bytes(receipt_raw)
        self.installation.chmod(0o400)
        self.installation_sha.write_text(
            f"{hashlib.sha256(receipt_raw).hexdigest()}  receipt.json\n",
            encoding="ascii",
        )
        self.installation_sha.chmod(0o400)
        self.fake_podman = FakePodman()
        self.cgroup_calls: list[str] = []
        self.cgroup_clean_calls: list[str] = []
        self.patches = mock.patch.multiple(
            host_recovery,
            ROOT_UID=os.getuid(),
            ROOT_GID=os.getgid(),
            STATE_ROOT=self.state,
            GUIDED_LIFECYCLE_LOCK=self.state / "guided.lock",
            MARKER=self.state / "host-recovery-intent.json",
            MARKER_TEMP=self.state / ".host-recovery-intent.tmp",
            PODMAN_INSPECTION_MARKER=self.state / "podman-inspection-intent.json",
            PODMAN_INSPECTION_MARKER_TEMP=(
                self.state / ".podman-inspection-intent.tmp"
            ),
            SESSION_ROOT=self.state / "sessions",
            RUNTIME_ROOT=self.runtime,
            CONTAINER_RUNTIME_ROOT=self.state / "runtime",
            RUNTIME_IDENTITY_ROOT=self.state / "runtime-identities",
            CGROUP_MARKER=self.state / "cgroup-authority-intent.json",
            CGROUP_MARKER_TEMP=self.state / ".cgroup-authority-intent.tmp",
            GRAPHICAL_RESTORATION=self.state / "graphical-restoration-state.json",
            GRAPHICAL_RESTORATION_TEMP=(
                self.state / ".graphical-restoration-state.json.tmp"
            ),
            PODMAN_ROOT=self.state / "podman-root",
            PODMAN_RUNROOT=self.runtime / "podman-runroot",
            PODMAN_ENVIRONMENT_ROOT=self.state / "podman-environment",
            INSTALLATION_RECEIPT=self.installation,
            INSTALLATION_RECEIPT_SHA=self.installation_sha,
            INSTALLATION_AUTHORITY=self.installation_authority,
            BUNDLE_RECEIPT=self.bundle_receipt,
            BUNDLE_RECEIPT_SHA=self.bundle_receipt_sha,
            CGROUP_AUTHORITY=self.cgroup,
            BOOT_ID_PATH=self.boot_id,
        )
        self.patches.start()
        self.run_patch = mock.patch.object(
            host_recovery, "COMMAND_RUNNER", self.fake_podman
        )
        self.run_patch.start()
        self.installation_verifications: list[tuple[str, str]] = []
        self.installation_patch = mock.patch.object(
            host_recovery,
            "verify_installed_filesystem_authority",
            side_effect=lambda revision, receipt_sha: (
                self.installation_verifications.append((revision, receipt_sha))
            ),
        )
        self.installation_patch.start()

        def record_cgroup_recovery(*_arguments: object) -> None:
            self.cgroup_calls.append("recover")
            if (
                host_recovery.CGROUP_MARKER_TEMP.exists()
                and not host_recovery.CGROUP_MARKER.exists()
            ):
                host_recovery.CGROUP_MARKER_TEMP.unlink()

        self.cgroup_patch = mock.patch.object(
            host_recovery,
            "recover_cgroup_authority",
            side_effect=record_cgroup_recovery,
        )
        self.cgroup_patch.start()
        self.cgroup_clean_patch = mock.patch.object(
            host_recovery,
            "check_clean_cgroup_authority",
            side_effect=lambda: self.cgroup_clean_calls.append("check-clean"),
        )
        self.cgroup_clean_patch.start()

    def tearDown(self) -> None:
        self.cgroup_clean_patch.stop()
        self.cgroup_patch.stop()
        self.installation_patch.stop()
        self.run_patch.stop()
        self.patches.stop()
        self.temporary.cleanup()

    def initialise_podman_store(self) -> None:
        host_recovery.PODMAN_ROOT.mkdir(mode=0o700)
        host_recovery.PODMAN_RUNROOT.mkdir(mode=0o700)
        host_recovery.PODMAN_ENVIRONMENT_ROOT.mkdir(mode=0o700)
        for name in ("home", "data", "cache", "config", "runtime", "tmp"):
            (host_recovery.PODMAN_ENVIRONMENT_ROOT / name).mkdir(mode=0o700)

    def arm(self) -> dict[str, object]:
        self.assertEqual(host_recovery.arm("campaign", SESSION), "armed")
        return host_recovery.read_marker(SESSION)

    def arm_cgroup(self, marker: dict[str, object]) -> None:
        host_recovery.CGROUP_MARKER.write_bytes(
            compact_canonical(host_recovery.expected_cgroup_marker(marker))
        )
        host_recovery.CGROUP_MARKER.chmod(0o400)

    def test_pre_handoff_recovery_accepts_both_publication_cutpoints(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        self.assertEqual(marker["session"], SESSION)
        self.assertEqual(marker["installation"]["bundle_revision"], REVISION)
        self.assertFalse(host_recovery.MARKER_TEMP.exists())
        self.assertEqual(host_recovery.recover(), "recovered")
        self.assertFalse(host_recovery.MARKER.exists())

        self.arm()
        os.link(host_recovery.MARKER, host_recovery.MARKER_TEMP)
        self.assertEqual(host_recovery.recover(), "recovered")
        self.assertFalse(host_recovery.MARKER.exists())
        self.assertFalse(host_recovery.MARKER_TEMP.exists())

        self.arm()
        os.link(host_recovery.MARKER, host_recovery.MARKER_TEMP)
        host_recovery.MARKER.unlink()
        self.assertEqual(host_recovery.recover(), "recovered")
        self.assertFalse(host_recovery.MARKER_TEMP.exists())
        self.assertEqual(self.cgroup_clean_calls, ["check-clean"] * 6)

    def test_unpublished_partial_temporary_is_safely_discarded(self) -> None:
        host_recovery.MARKER_TEMP.write_bytes(b'{"boot_id"')
        host_recovery.MARKER_TEMP.chmod(0o400)
        self.assertEqual(host_recovery.recover(), "already-clean")
        self.assertFalse(host_recovery.MARKER_TEMP.exists())
        self.assertEqual(self.cgroup_clean_calls, ["check-clean"])

    def test_unpublished_host_marker_prefix_is_strict_and_correlated(self) -> None:
        expected = compact_canonical(
            host_recovery.expected_marker(
                "campaign",
                SESSION,
                boot_id=BOOT_ID,
                verify_filesystem=False,
            )
        )
        self.assertFalse(
            host_recovery.is_strict_unpublished_host_marker_prefix(expected)
        )
        nonce = NONCE.encode("ascii")
        first = expected.index(nonce)
        second = expected.index(nonce, first + len(nonce))
        forged = bytearray(expected[: second + 5])
        forged[second] = ord("3")
        self.assertFalse(
            host_recovery.is_strict_unpublished_host_marker_prefix(bytes(forged))
        )

    def test_noncanonical_unpublished_host_marker_fails_without_mutation(
        self,
    ) -> None:
        host_recovery.MARKER_TEMP.write_bytes(b'{"boot_X"')
        host_recovery.MARKER_TEMP.chmod(0o400)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "malformed"):
            host_recovery.recover()
        self.assertTrue(host_recovery.MARKER_TEMP.exists())
        self.assertEqual(self.cgroup_clean_calls, [])
        self.assertEqual(self.cgroup_calls, [])

    def test_container_free_marker_repair_rechecks_exact_cgroup_state(
        self,
    ) -> None:
        marker = self.arm()
        self.arm_cgroup(marker)
        recovery = mock.Mock()
        with mock.patch.object(
            host_recovery,
            "verify_recovery_cgroup_authority",
            recovery,
        ):
            self.assertEqual(host_recovery.recover(), "recovered")
        self.assertEqual(
            recovery.call_args_list,
            [mock.call(marker, []), mock.call(marker, [])],
        )
        self.assertEqual(self.cgroup_clean_calls, [])

    def test_published_host_recovers_unpublished_cgroup_marker_first(
        self,
    ) -> None:
        marker = self.arm()
        raw = compact_canonical(host_recovery.expected_cgroup_marker(marker))
        host_recovery.CGROUP_MARKER_TEMP.write_bytes(raw[:17])
        host_recovery.CGROUP_MARKER_TEMP.chmod(0o400)
        self.assertEqual(host_recovery.recover(), "recovered")
        self.assertFalse(host_recovery.MARKER.exists())
        self.assertFalse(host_recovery.CGROUP_MARKER_TEMP.exists())
        self.assertEqual(self.cgroup_calls, ["recover", "recover"])
        self.assertEqual(self.cgroup_clean_calls, ["check-clean", "check-clean"])

    def test_unpublished_host_and_cgroup_markers_cannot_authorize_repair(
        self,
    ) -> None:
        marker = self.arm()
        os.link(host_recovery.MARKER, host_recovery.MARKER_TEMP)
        host_recovery.MARKER.unlink()
        raw = compact_canonical(host_recovery.expected_cgroup_marker(marker))
        host_recovery.CGROUP_MARKER_TEMP.write_bytes(raw[:17])
        host_recovery.CGROUP_MARKER_TEMP.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "unpublished cgroup authority"
        ):
            host_recovery.recover()
        self.assertFalse(host_recovery.MARKER.exists())
        self.assertTrue(host_recovery.MARKER_TEMP.exists())
        self.assertTrue(host_recovery.CGROUP_MARKER_TEMP.exists())
        self.assertEqual(self.cgroup_clean_calls, [])
        self.assertEqual(self.cgroup_calls, [])

    def test_forged_unpublished_cgroup_marker_is_never_discarded(self) -> None:
        marker = self.arm()
        raw = bytearray(
            compact_canonical(host_recovery.expected_cgroup_marker(marker))[:17]
        )
        raw[-1] = ord("X")
        host_recovery.CGROUP_MARKER_TEMP.write_bytes(raw)
        host_recovery.CGROUP_MARKER_TEMP.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "cgroup authority marker temporary claims"
        ):
            host_recovery.recover()
        self.assertTrue(host_recovery.MARKER.exists())
        self.assertTrue(host_recovery.CGROUP_MARKER_TEMP.exists())
        self.assertEqual(self.cgroup_clean_calls, [])
        self.assertEqual(self.cgroup_calls, [])

    def test_no_marker_refuses_an_untrusted_guided_request(self) -> None:
        target = self.root / "foreign-request"
        target.write_text("foreign", encoding="ascii")
        (self.runtime / "campaign.request").symlink_to(target)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "launch request"):
            host_recovery.recover()
        self.assertEqual(self.cgroup_calls, [])

    def test_arm_publishes_before_first_podman_access(self) -> None:
        self.initialise_podman_store()
        self.fake_podman.required_marker = host_recovery.MARKER
        self.arm()
        self.assertTrue(host_recovery.MARKER.exists())

    def test_arm_accepts_only_the_bound_consumed_launch_request(self) -> None:
        consumed = self.runtime / ".campaign.consumed.123"
        consumed.write_bytes(
            compact_canonical(
                {
                    "mode": "campaign",
                    "nonce": NONCE,
                    "schema": host_recovery.CAMPAIGN_REQUEST_SCHEMA,
                    "target_uid": os.getuid() or 1,
                    "target_user": "fixture",
                }
            )
        )
        consumed.chmod(0o600)
        self.arm()
        self.assertTrue(host_recovery.MARKER.exists())

    def test_probe_arm_binds_its_exact_consumed_request(self) -> None:
        consumed = self.runtime / ".probe-only.consumed.456"
        consumed.write_bytes(
            compact_canonical(
                {
                    "mode": "probe-only",
                    "nonce": NONCE,
                    "schema": host_recovery.PROBE_REQUEST_SCHEMA,
                }
            )
        )
        consumed.chmod(0o600)
        self.assertEqual(
            host_recovery.arm("probe-only", f"probe-{NONCE}"), "armed"
        )
        self.assertEqual(host_recovery.recover(), "recovered")

    def test_arm_rejects_overlapping_public_and_consumed_launch_requests(
        self,
    ) -> None:
        request = {
            "mode": "campaign",
            "nonce": NONCE,
            "schema": host_recovery.CAMPAIGN_REQUEST_SCHEMA,
            "target_uid": os.getuid() or 1,
            "target_user": "fixture",
        }
        for path in (
            self.runtime / "campaign.request",
            self.runtime / ".campaign.consumed.123",
        ):
            path.write_bytes(compact_canonical(request))
            path.chmod(0o600)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "public and consumed"
        ):
            self.arm()
        self.assertFalse(host_recovery.MARKER.exists())

    def test_recovers_live_owned_podman_cgroup_and_exact_runtime(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        evidence_host = self.state / "sessions" / SESSION / "host"
        evidence_host.mkdir(parents=True, mode=0o700)
        snapshot = host_recovery.snapshot(SESSION)
        self.assertEqual(snapshot, evidence_host / "host-recovery-intent.json")
        self.assertEqual(snapshot.read_bytes(), host_recovery.MARKER.read_bytes())
        host_recovery.CONTAINER_RUNTIME_ROOT.mkdir(mode=0o700)
        runtime_tree = host_recovery.CONTAINER_RUNTIME_ROOT / SESSION
        runtime_tree.mkdir(mode=0o700)
        (runtime_tree / "tmp").mkdir(mode=0o700)
        (runtime_tree / "tmp" / "partial").write_text("partial", encoding="ascii")
        host_recovery.RUNTIME_IDENTITY_ROOT.mkdir(mode=0o700)
        identity = host_recovery.RUNTIME_IDENTITY_ROOT / f"{SESSION}.json"
        identity.write_bytes(
            compact_canonical(host_recovery.expected_runtime_identity(marker))
        )
        identity.chmod(0o400)
        session_path = self.runtime / "session-name"
        session_path.write_text(f"{SESSION}\n", encoding="ascii")
        session_path.chmod(0o400)
        handoff = self.runtime / "guided-handoff.json"
        handoff.write_bytes(compact_canonical(host_recovery.expected_handoff(marker)))
        handoff.chmod(0o400)
        cidfile = self.runtime / f"{SESSION}.cid"
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        stderr = self.runtime / f"{SESSION}.verifier.stderr"
        stderr.touch(mode=0o400)
        self.fake_podman.add_owned(marker, "campaign")
        self.arm_cgroup(marker)

        self.assertEqual(host_recovery.recover(), "recovered")
        self.assertEqual(self.fake_podman.removed, [CONTAINER_ID])
        self.assertEqual(self.cgroup_calls, ["recover"])
        self.assertFalse(runtime_tree.exists())
        self.assertFalse(identity.exists())
        self.assertFalse(session_path.exists())
        self.assertFalse(handoff.exists())
        self.assertFalse(cidfile.exists())
        self.assertFalse(stderr.exists())
        self.assertFalse(host_recovery.MARKER.exists())
        self.assertTrue(snapshot.exists())

    def test_reboot_stopped_container_uses_read_only_recovery_gate(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        inspection = self.fake_podman.add_owned(marker, "campaign")
        state = inspection["State"]
        assert isinstance(state, dict)
        state.update({"Pid": 0, "Running": False, "Status": "stopped"})
        self.arm_cgroup(marker)
        active = mock.Mock()
        recovery = mock.Mock()
        with (
            mock.patch.object(
                host_recovery,
                "verify_active_cgroup_authority",
                active,
            ),
            mock.patch.object(
                host_recovery,
                "verify_recovery_cgroup_authority",
                recovery,
            ),
        ):
            self.assertEqual(host_recovery.recover(), "recovered")
        active.assert_not_called()
        self.assertEqual(
            recovery.call_args_list,
            [
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
            ],
        )
        self.assertEqual(self.fake_podman.removed, [CONTAINER_ID])
        self.assertEqual(self.cgroup_calls, ["recover"])

    def test_exact_durable_stopped_container_states_are_accepted(self) -> None:
        for status in ("created", "stopped", "exited"):
            with self.subTest(status=status):
                state: dict[str, object] = {
                    "Dead": False,
                    "Paused": False,
                    "Pid": 0,
                    "Restarting": False,
                    "Running": False,
                    "Status": status,
                }
                self.assertEqual(host_recovery._container_lifecycle({"State": state}), "stopped")

    def test_removing_container_requires_the_cid_first_cutpoint(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        inspection = self.fake_podman.add_owned(marker, "campaign")
        state = inspection["State"]
        assert isinstance(state, dict)
        state.update({"Pid": 0, "Running": False, "Status": "removing"})
        self.arm_cgroup(marker)
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "CID-first cutpoint"
        ):
            host_recovery.recover()
        self.assertEqual(self.fake_podman.removed, [])
        cidfile.unlink()
        active = mock.Mock()
        recovery = mock.Mock()
        with (
            mock.patch.object(
                host_recovery, "verify_active_cgroup_authority", active
            ),
            mock.patch.object(
                host_recovery, "verify_recovery_cgroup_authority", recovery
            ),
        ):
            self.assertEqual(host_recovery.recover(), "recovered")
        active.assert_not_called()
        self.assertEqual(
            recovery.call_args_list,
            [
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
            ],
        )
        self.assertEqual(self.fake_podman.removed, [CONTAINER_ID])

    def test_initialized_container_requires_launch_cid_and_active_gate(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        inspection = self.fake_podman.add_owned(marker, "campaign")
        state = inspection["State"]
        assert isinstance(state, dict)
        state.update(
            {
                "ConmonPid": 4241,
                "Pid": 4242,
                "Running": False,
                "Status": "initialized",
            }
        )
        self.arm_cgroup(marker)
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        active = mock.Mock()
        recovery = mock.Mock()
        with (
            mock.patch.object(
                host_recovery, "verify_active_cgroup_authority", active
            ),
            mock.patch.object(
                host_recovery, "verify_recovery_cgroup_authority", recovery
            ),
        ):
            self.assertEqual(host_recovery.recover(), "recovered")
        self.assertEqual(
            active.call_args_list,
            [
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
            ],
        )
        recovery.assert_not_called()
        self.assertEqual(self.fake_podman.removed, [CONTAINER_ID])

    def test_initialized_container_resumes_after_cid_first_interruption(
        self,
    ) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        inspection = self.fake_podman.add_owned(marker, "campaign")
        state = inspection["State"]
        assert isinstance(state, dict)
        state.update(
            {
                "ConmonPid": 4241,
                "Pid": 4242,
                "Running": False,
                "Status": "initialized",
            }
        )
        self.arm_cgroup(marker)
        active = mock.Mock()
        recovery = mock.Mock()
        with (
            mock.patch.object(
                host_recovery, "verify_active_cgroup_authority", active
            ),
            mock.patch.object(
                host_recovery, "verify_recovery_cgroup_authority", recovery
            ),
        ):
            self.assertEqual(host_recovery.recover(), "recovered")
        self.assertEqual(
            active.call_args_list,
            [
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
            ],
        )
        recovery.assert_not_called()
        self.assertEqual(self.fake_podman.removed, [CONTAINER_ID])

    def test_stopping_container_requires_cid_first_and_active_gate(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        inspection = self.fake_podman.add_owned(marker, "campaign")
        state = inspection["State"]
        assert isinstance(state, dict)
        state.update(
            {
                "ConmonPid": 4241,
                "Pid": 4242,
                "Running": False,
                "Status": "stopping",
                "StoppedByUser": True,
            }
        )
        self.arm_cgroup(marker)
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "CID-first cutpoint"
        ):
            host_recovery.recover()
        cidfile.unlink()
        active = mock.Mock()
        recovery = mock.Mock()
        with (
            mock.patch.object(
                host_recovery, "verify_active_cgroup_authority", active
            ),
            mock.patch.object(
                host_recovery, "verify_recovery_cgroup_authority", recovery
            ),
        ):
            self.assertEqual(host_recovery.recover(), "recovered")
        self.assertEqual(
            active.call_args_list,
            [
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
                mock.call(marker, [(CONTAINER_ID, "campaign")]),
            ],
        )
        recovery.assert_not_called()
        self.assertEqual(self.fake_podman.removed, [CONTAINER_ID])

    def test_transitional_or_unknown_container_states_fail_before_mutation(
        self,
    ) -> None:
        for status in ("configured", "initialized", "stopping"):
            with self.subTest(status=status):
                state: dict[str, object] = {
                    "ConmonPid": 0,
                    "Dead": False,
                    "Paused": False,
                    "Pid": 0,
                    "Restarting": False,
                    "Running": False,
                    "Status": status,
                }
                with self.assertRaisesRegex(
                    host_recovery.RecoveryError, "lifecycle state"
                ):
                    host_recovery._container_lifecycle({"State": state})

    def test_ambiguous_container_lifecycle_fails_before_mutation(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        inspection = self.fake_podman.add_owned(marker, "campaign")
        state = inspection["State"]
        assert isinstance(state, dict)
        state["Paused"] = True
        self.arm_cgroup(marker)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "lifecycle state"
        ):
            host_recovery.recover()
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertEqual(self.fake_podman.removed, [])
        self.assertEqual(self.cgroup_calls, [])

    def test_all_owned_container_kinds_require_the_exact_execution_contract(
        self,
    ) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        for kind in ("preflight", "campaign", "verifier"):
            with self.subTest(kind=kind):
                self.fake_podman.containers.clear()
                self.fake_podman.add_owned(marker, kind)
                self.assertEqual(
                    host_recovery._owned_container_inventory(marker),
                    [(CONTAINER_ID, kind)],
                )

    def test_preflight_source_digest_matches_the_recovery_contract(self) -> None:
        self.assertEqual(
            hashlib.sha256(preflight_python().encode("utf-8")).hexdigest(),
            host_recovery.PREFLIGHT_PYTHON_SHA256,
        )

    def test_forged_container_execution_contract_fails_before_cleanup(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()

        def command(value: dict[str, object]) -> None:
            config = value["Config"]
            assert isinstance(config, dict)
            config["Cmd"] = ["/usr/bin/false"]

        def mount(value: dict[str, object]) -> None:
            mounts = value["Mounts"]
            assert isinstance(mounts, list) and isinstance(mounts[0], dict)
            mounts[0]["Source"] = "/foreign"

        def mount_mode(value: dict[str, object]) -> None:
            mounts = value["Mounts"]
            assert isinstance(mounts, list) and isinstance(mounts[0], dict)
            mounts[0]["RW"] = True

        def mount_propagation(value: dict[str, object]) -> None:
            mounts = value["Mounts"]
            assert isinstance(mounts, list) and isinstance(mounts[0], dict)
            mounts[0]["Propagation"] = "rshared"

        def bind_order(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            binds = host["Binds"]
            assert isinstance(binds, list)
            host["Binds"] = list(reversed(binds))

        def environment(value: dict[str, object]) -> None:
            config = value["Config"]
            assert isinstance(config, dict)
            environment = config["Env"]
            assert isinstance(environment, list)
            environment.append("HOME=/foreign")

        def extra_environment(value: dict[str, object]) -> None:
            config = value["Config"]
            assert isinstance(config, dict)
            environment = config["Env"]
            assert isinstance(environment, list)
            environment.append("LD_PRELOAD=/foreign.so")

        def network(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            host["NetworkMode"] = "host"

        def process(value: dict[str, object]) -> None:
            value["Args"] = ["--forged"]

        def entrypoint(value: dict[str, object]) -> None:
            config = value["Config"]
            assert isinstance(config, dict)
            config["Entrypoint"] = "/usr/bin/false"

        def entrypoint_type(value: dict[str, object]) -> None:
            config = value["Config"]
            assert isinstance(config, dict)
            config["Entrypoint"] = ["/usr/bin/false"]

        def image(value: dict[str, object]) -> None:
            value["ImageDigest"] = "sha256:" + "9" * 64

        def label(value: dict[str, object]) -> None:
            config = value["Config"]
            assert isinstance(config, dict)
            labels = config["Labels"]
            assert isinstance(labels, dict)
            labels["io.codeskeptic.p10-09.forged"] = "true"

        def foreign_label(value: dict[str, object]) -> None:
            config = value["Config"]
            assert isinstance(config, dict)
            labels = config["Labels"]
            assert isinstance(labels, dict)
            labels["foreign"] = "true"

        def ipc(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            host["IpcMode"] = "host"

        def uts(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            host["UTSMode"] = "host"

        def cidfile(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            host["ContainerIDFile"] = "/run/foreign.cid"

        def cpuset(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            host["CpusetCpus"] = "0-11"

        def security(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            host["SecurityOpt"] = ["label=disable"]

        def privilege(value: dict[str, object]) -> None:
            host = value["HostConfig"]
            assert isinstance(host, dict)
            host["Privileged"] = True

        for label, mutate in (
            ("command", command),
            ("process", process),
            ("entrypoint", entrypoint),
            ("entrypoint-type", entrypoint_type),
            ("mount", mount),
            ("mount-mode", mount_mode),
            ("mount-propagation", mount_propagation),
            ("bind-order", bind_order),
            ("environment", environment),
            ("extra-environment", extra_environment),
            ("image", image),
            ("label", label),
            ("foreign-label", foreign_label),
            ("network", network),
            ("ipc", ipc),
            ("uts", uts),
            ("cidfile", cidfile),
            ("cpuset", cpuset),
            ("security", security),
            ("privilege", privilege),
        ):
            with self.subTest(label=label):
                self.fake_podman.containers.clear()
                inspection = self.fake_podman.add_owned(marker, "campaign")
                mutate(inspection)
                with self.assertRaisesRegex(
                    host_recovery.RecoveryError, "owned|foreign container"
                ):
                    host_recovery.recover()
                self.assertIn(CONTAINER_ID, self.fake_podman.containers)
                self.assertEqual(self.fake_podman.removed, [])
                self.assertEqual(self.cgroup_calls, [])

    def test_one_forged_container_prevents_cleanup_of_all_owned_containers(
        self,
    ) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        second_id = "c" * 64
        self.fake_podman.add_owned(marker, "campaign")
        forged = self.fake_podman.add_owned(marker, "verifier", second_id)
        mounts = forged["Mounts"]
        assert isinstance(mounts, list) and isinstance(mounts[0], dict)
        mounts[0]["Source"] = "/foreign"
        with self.assertRaisesRegex(host_recovery.RecoveryError, "mount"):
            host_recovery.recover()
        self.assertEqual(
            set(self.fake_podman.containers), {CONTAINER_ID, second_id}
        )
        self.assertEqual(self.fake_podman.removed, [])
        self.assertEqual(self.cgroup_calls, [])
        self.assertTrue(host_recovery.MARKER.exists())

    def test_marker_is_retained_until_the_pinned_image_store_is_reverified(
        self,
    ) -> None:
        self.initialise_podman_store()
        self.arm()
        self.fake_podman.image_digest = "sha256:" + "9" * 64
        with self.assertRaisesRegex(host_recovery.RecoveryError, "image identity"):
            host_recovery.recover()
        self.assertTrue(host_recovery.MARKER.exists())
        self.assertEqual(self.cgroup_calls, [])

    def test_guided_decision_publication_cutpoints_are_recoverable(self) -> None:
        for name in ("guided-decision.json", ".guided-decision.consumed.789"):
            for action in ("accept", "cancel"):
                with self.subTest(name=name, action=action):
                    marker = self.arm()
                    decision = self.runtime / name
                    decision.write_bytes(
                        compact_canonical(
                            host_recovery.expected_guided_decision(marker, action)
                        )
                    )
                    decision.chmod(0o400)
                    self.assertEqual(host_recovery.recover(), "recovered")
                    self.assertFalse(decision.exists())
                    self.assertFalse(host_recovery.MARKER.exists())

    def test_partial_session_bound_runtime_files_are_recoverable(self) -> None:
        marker = self.arm()
        expected_files = {
            self.runtime / ".session-name.tmp": f"{SESSION}\n".encode("ascii"),
            self.runtime / ".guided-handoff.json.tmp": compact_canonical(
                host_recovery.expected_handoff(marker)
            ),
            self.runtime / ".guided-decision.json.tmp": compact_canonical(
                host_recovery.expected_guided_decision(marker, "accept")
            ),
            self.state / ".graphical-restoration-state.json.tmp": compact_canonical(
                host_recovery.expected_graphical_restoration(marker)
            ),
        }
        for path, expected in expected_files.items():
            with self.subTest(path=path.name):
                path.write_bytes(expected[: max(1, len(expected) // 3)])
                path.chmod(0o400)
                self.assertEqual(host_recovery.recover(), "recovered")
                self.assertFalse(path.exists())
                self.assertFalse(host_recovery.MARKER.exists())
                marker = self.arm()

    def test_atomic_runtime_hardlink_cutpoints_are_recoverable(self) -> None:
        cases = (
            ("session-name", ".session-name.tmp", lambda marker: f"{SESSION}\n".encode("ascii")),
            (
                "guided-handoff.json",
                ".guided-handoff.json.tmp",
                lambda marker: compact_canonical(host_recovery.expected_handoff(marker)),
            ),
            (
                ".guided-decision.consumed.789",
                ".guided-decision.json.tmp",
                lambda marker: compact_canonical(
                    host_recovery.expected_guided_decision(marker, "accept")
                ),
            ),
        )
        for final_name, temporary_name, payload in cases:
            with self.subTest(final=final_name):
                marker = self.arm()
                temporary = self.runtime / temporary_name
                final = self.runtime / final_name
                temporary.write_bytes(payload(marker))
                temporary.chmod(0o400)
                os.link(temporary, final)
                self.assertEqual(host_recovery.recover(), "recovered")
                self.assertFalse(temporary.exists())
                self.assertFalse(final.exists())

        marker = self.arm()
        temporary = self.state / ".graphical-restoration-state.json.tmp"
        final = self.state / "graphical-restoration-state.json"
        temporary.write_bytes(
            compact_canonical(host_recovery.expected_graphical_restoration(marker))
        )
        temporary.chmod(0o400)
        os.link(temporary, final)
        self.assertEqual(host_recovery.recover(), "recovered")
        self.assertFalse(temporary.exists())
        self.assertTrue(final.exists())

    def test_partial_cidfiles_are_recoverable_but_complete_ids_are_bound(self) -> None:
        for suffix in (".cid", ".preflight.cid", ".verifier.cid"):
            for raw in (b"", CONTAINER_ID[:19].encode("ascii")):
                with self.subTest(suffix=suffix, length=len(raw)):
                    self.arm()
                    cidfile = self.runtime / f"{SESSION}{suffix}"
                    cidfile.write_bytes(raw)
                    cidfile.chmod(0o400)
                    self.assertEqual(host_recovery.recover(), "recovered")
                    self.assertFalse(cidfile.exists())
                    self.assertFalse(host_recovery.MARKER.exists())

        self.initialise_podman_store()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        cidfile = self.runtime / f"{SESSION}.cid"
        cidfile.write_text(f"{'c' * 64}\n", encoding="ascii")
        cidfile.chmod(0o400)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "container ID"):
            host_recovery.recover()
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertTrue(host_recovery.MARKER.exists())

        cidfile.chmod(0o600)
        cidfile.write_text("deadbeef", encoding="ascii")
        cidfile.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "partial container ID"
        ):
            host_recovery.recover()
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertTrue(host_recovery.MARKER.exists())

    def test_central_container_removal_validates_full_chain_and_unlinks_cid_first(
        self,
    ) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        self.arm_cgroup(marker)
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        verifications_before = len(self.installation_verifications)
        self.fake_podman.required_absent_on_remove = cidfile
        self.assertEqual(
            host_recovery.remove_owned_container(SESSION, "campaign"),
            CONTAINER_ID,
        )
        self.assertGreater(
            len(self.installation_verifications), verifications_before
        )
        self.assertFalse(cidfile.exists())
        self.assertNotIn(CONTAINER_ID, self.fake_podman.containers)

    def test_central_container_removal_refuses_wrong_complete_cid(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{'c' * 64}\n", encoding="ascii")
        cidfile.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "container ID"
        ):
            host_recovery.remove_owned_container(SESSION, "campaign")
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertEqual(self.fake_podman.removed, [])

    def test_central_container_removal_requires_live_cgroup_authority(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "without cgroup authority"
        ):
            host_recovery.remove_owned_container(SESSION, "campaign")
        self.assertTrue(cidfile.exists())
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertEqual(self.fake_podman.removed, [])

    def test_podman_version_drift_precedes_central_cleanup_mutation(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        self.arm_cgroup(marker)
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        self.fake_podman.version = "5.8.3"

        with self.assertRaisesRegex(host_recovery.RecoveryError, "version drift"):
            host_recovery.remove_owned_container(SESSION, "campaign")

        self.assertTrue(cidfile.exists())
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertEqual(self.fake_podman.removed, [])
        self.assertEqual(self.cgroup_calls, [])

    def test_podman_version_drift_precedes_recovery_mutation(self) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        self.arm_cgroup(marker)
        cidfile = host_recovery.expected_container_cidfile(marker, "campaign")
        cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        cidfile.chmod(0o400)
        self.fake_podman.version = "5.8.3"

        with self.assertRaisesRegex(host_recovery.RecoveryError, "version drift"):
            host_recovery.recover()

        self.assertTrue(host_recovery.MARKER.exists())
        self.assertTrue(cidfile.exists())
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertEqual(self.fake_podman.removed, [])
        self.assertEqual(self.cgroup_calls, [])

    def test_recovery_unlinks_and_fsyncs_cid_before_container_rm(
        self,
    ) -> None:
        self.initialise_podman_store()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        self.arm_cgroup(marker)
        path = host_recovery.expected_container_cidfile(marker, "campaign")
        path.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
        path.chmod(0o400)

        events: list[str] = []
        real_unlink = host_recovery._unlink_exact
        real_fsync = host_recovery.fsync_directory
        real_run = host_recovery.run_podman

        def unlink(path: Path) -> None:
            if path.name.endswith(".cid"):
                events.append(f"unlink:{path.name}")
            real_unlink(path)

        def fsync(path: Path) -> None:
            if path == self.runtime:
                events.append("fsync:runtime")
            real_fsync(path)

        def run(arguments: tuple[str, ...]) -> bytes:
            if arguments and arguments[0] == "rm":
                events.append(f"rm:{arguments[-1]}")
            return real_run(arguments)

        with (
            mock.patch.object(host_recovery, "_unlink_exact", side_effect=unlink),
            mock.patch.object(host_recovery, "fsync_directory", side_effect=fsync),
            mock.patch.object(host_recovery, "run_podman", side_effect=run),
        ):
            self.assertEqual(host_recovery.recover(), "recovered")

        first_rm = next(index for index, item in enumerate(events) if item.startswith("rm:"))
        cid_unlinks = [
            index for index, item in enumerate(events) if item.startswith("unlink:")
        ]
        self.assertEqual(len(cid_unlinks), 1)
        self.assertTrue(all(index < first_rm for index in cid_unlinks))
        self.assertGreaterEqual(
            sum(1 for item in events[:first_rm] if item == "fsync:runtime"),
            1,
        )

    def test_recovery_retries_container_removal_crash_cutpoints(self) -> None:
        class SimulatedKill(BaseException):
            pass

        self.initialise_podman_store()
        for phase in ("before-rm", "after-rm"):
            with self.subTest(phase=phase):
                marker = self.arm()
                self.fake_podman.add_owned(marker, "campaign")
                self.arm_cgroup(marker)
                cidfile = host_recovery.expected_container_cidfile(
                    marker, "campaign"
                )
                cidfile.write_text(f"{CONTAINER_ID}\n", encoding="ascii")
                cidfile.chmod(0o400)

                real_run = host_recovery.run_podman
                removals = 0

                def interrupted(arguments: tuple[str, ...]) -> bytes:
                    nonlocal removals
                    if not arguments or arguments[0] != "rm":
                        return real_run(arguments)
                    if phase == "before-rm" and removals == 0:
                        raise SimulatedKill()
                    result = real_run(arguments)
                    removals += 1
                    if phase == "after-rm" and removals == 1:
                        raise SimulatedKill()
                    return result

                with mock.patch.object(
                    host_recovery, "run_podman", side_effect=interrupted
                ):
                    with self.assertRaises(SimulatedKill):
                        host_recovery.recover()
                self.assertTrue(host_recovery.MARKER.exists())
                self.assertFalse(
                    host_recovery.expected_container_cidfile(
                        marker, "campaign"
                    ).exists()
                )
                self.assertEqual(host_recovery.recover(), "recovered")
                self.assertEqual(self.fake_podman.containers, {})
                if host_recovery.CGROUP_MARKER.exists():
                    host_recovery.CGROUP_MARKER.chmod(0o600)
                    host_recovery.CGROUP_MARKER.unlink()

    def test_installation_identity_rejects_staging_contract_drift(self) -> None:
        original = json.loads(self.installation.read_text(encoding="utf-8"))
        mutations = (
            ("inventory", lambda value: value.__setitem__(
                "installed_inventory_sha256", "9" * 64
            )),
            ("authority", lambda value: value.__setitem__(
                "authority_root", "/foreign/authority"
            )),
            ("image-reference", lambda value: value["image"].__setitem__(
                "reference", "fixture"
            )),
            ("image-digest", lambda value: value["image"].__setitem__(
                "digest", "sha256:" + "8" * 64
            )),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = json.loads(json.dumps(original))
                mutate(value)
                self.installation.chmod(0o600)
                raw = pretty_canonical(value)
                self.installation.write_bytes(raw)
                self.installation.chmod(0o400)
                self.installation_sha.chmod(0o600)
                self.installation_sha.write_text(
                    f"{hashlib.sha256(raw).hexdigest()}  receipt.json\n",
                    encoding="ascii",
                )
                self.installation_sha.chmod(0o400)
                with self.assertRaises(host_recovery.RecoveryError):
                    host_recovery.installation_identity()
        self.installation.chmod(0o600)
        original_raw = pretty_canonical(original)
        self.installation.write_bytes(original_raw)
        self.installation.chmod(0o400)
        self.installation_sha.chmod(0o600)
        self.installation_sha.write_text(
            f"{hashlib.sha256(original_raw).hexdigest()}  receipt.json\n",
            encoding="ascii",
        )
        self.installation_sha.chmod(0o400)

    def test_installation_identity_invokes_the_pure_full_chain_validator(
        self,
    ) -> None:
        identity = host_recovery.installation_identity()
        self.assertEqual(identity["bundle_revision"], REVISION)
        self.assertEqual(
            self.installation_verifications[-1], (REVISION, self.bundle_digest)
        )

    def test_installation_identity_rejects_a_resealed_authority_mismatch(
        self,
    ) -> None:
        original = self.installation_authority.read_bytes()
        forged = json.loads(original.decode("ascii"))
        forged["bundle_revision"] = "f" * 40
        self.installation_authority.chmod(0o600)
        self.installation_authority.write_bytes(pretty_canonical(forged))
        self.installation_authority.chmod(0o400)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "out-of-band authority"
        ):
            host_recovery.installation_identity()

    def test_installation_authority_requires_one_root_owned_regular_inode(
        self,
    ) -> None:
        original = self.installation_authority.read_bytes()

        self.installation_authority.chmod(0o600)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "authority.*metadata"
        ):
            host_recovery.installation_identity()
        self.installation_authority.chmod(0o400)

        hardlink = self.root / "installation-authority-hardlink.json"
        os.link(self.installation_authority, hardlink)
        with self.assertRaisesRegex(
            host_recovery.RecoveryError, "authority.*metadata"
        ):
            host_recovery.installation_identity()
        hardlink.unlink()

        backup = self.root / "installation-authority-original.json"
        self.installation_authority.rename(backup)
        self.installation_authority.symlink_to(backup)
        try:
            with self.assertRaisesRegex(
                host_recovery.RecoveryError, "authority.*unavailable"
            ):
                host_recovery.installation_identity()
        finally:
            self.installation_authority.unlink()
            backup.rename(self.installation_authority)
        self.assertEqual(self.installation_authority.read_bytes(), original)

    def test_malformed_marker_and_foreign_container_fail_without_deletion(self) -> None:
        self.initialise_podman_store()
        self.arm()
        value = json.loads(host_recovery.MARKER.read_text(encoding="ascii"))
        value["foreign"] = True
        host_recovery.MARKER.chmod(0o600)
        host_recovery.MARKER.write_bytes(compact_canonical(value))
        host_recovery.MARKER.chmod(0o400)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "claims drift"):
            host_recovery.recover()
        self.assertTrue(host_recovery.MARKER.exists())
        self.assertEqual(self.fake_podman.removed, [])

        host_recovery.MARKER.unlink()
        marker = self.arm()
        self.fake_podman.add_owned(marker, "campaign")
        labels = self.fake_podman.containers[CONTAINER_ID]["Config"]["Labels"]
        assert isinstance(labels, dict)
        labels[host_recovery.SESSION_LABEL] = "probe-" + NONCE
        with self.assertRaisesRegex(host_recovery.RecoveryError, "foreign container"):
            host_recovery.recover()
        self.assertIn(CONTAINER_ID, self.fake_podman.containers)
        self.assertEqual(self.fake_podman.removed, [])
        self.assertTrue(host_recovery.MARKER.exists())

    def test_foreign_runtime_identity_is_refused(self) -> None:
        marker = self.arm()
        host_recovery.CONTAINER_RUNTIME_ROOT.mkdir(mode=0o700)
        (host_recovery.CONTAINER_RUNTIME_ROOT / SESSION).mkdir(mode=0o700)
        host_recovery.RUNTIME_IDENTITY_ROOT.mkdir(mode=0o700)
        identity = host_recovery.RUNTIME_IDENTITY_ROOT / f"{SESSION}.json"
        forged = host_recovery.expected_runtime_identity(marker)
        forged["session_nonce"] = "33333333-3333-4333-8333-333333333333"
        identity.write_bytes(compact_canonical(forged))
        identity.chmod(0o400)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "runtime identity"):
            host_recovery.recover()
        self.assertTrue(identity.exists())
        self.assertTrue(host_recovery.MARKER.exists())

    def test_partial_owned_runtime_identity_is_a_recoverable_cutpoint(self) -> None:
        marker = self.arm()
        host_recovery.CONTAINER_RUNTIME_ROOT.mkdir(mode=0o700)
        (host_recovery.CONTAINER_RUNTIME_ROOT / SESSION).mkdir(mode=0o700)
        host_recovery.RUNTIME_IDENTITY_ROOT.mkdir(mode=0o700)
        identity = host_recovery.RUNTIME_IDENTITY_ROOT / f"{SESSION}.json"
        expected = compact_canonical(host_recovery.expected_runtime_identity(marker))
        identity.write_bytes(expected[:17])
        identity.chmod(0o400)
        self.assertEqual(host_recovery.recover(), "recovered")
        self.assertFalse(identity.exists())

    def test_marker_is_retained_when_unrelated_runtime_state_appears(self) -> None:
        self.arm()
        host_recovery.CONTAINER_RUNTIME_ROOT.mkdir(mode=0o700)
        (host_recovery.CONTAINER_RUNTIME_ROOT / "foreign").mkdir(mode=0o700)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "without authority"):
            host_recovery.recover()
        self.assertTrue(host_recovery.MARKER.exists())
        self.assertEqual(self.cgroup_calls, [])

    def test_foreign_cgroup_session_is_refused_before_any_cleanup(self) -> None:
        marker = self.arm()
        foreign_session = (
            f"20260824T120001Z-{BOOT_ID}-"
            "33333333-3333-4333-8333-333333333333"
        )
        cgroup_claims = host_recovery.expected_cgroup_marker(marker)
        cgroup_claims["session"] = foreign_session
        host_recovery.CGROUP_MARKER.write_bytes(compact_canonical(cgroup_claims))
        host_recovery.CGROUP_MARKER.chmod(0o400)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "cgroup.*session"):
            host_recovery.recover()
        self.assertEqual(self.cgroup_calls, [])
        self.assertTrue(host_recovery.MARKER.exists())

    def test_terminal_cleanup_is_idempotent_and_no_marker_refuses_foreign_state(self) -> None:
        self.initialise_podman_store()
        self.arm()
        self.assertEqual(host_recovery.cleanup(SESSION), "recovered")
        self.assertEqual(host_recovery.recover(), "already-clean")
        self.assertEqual(self.cgroup_calls, ["recover", "recover"])

        host_recovery.CONTAINER_RUNTIME_ROOT.mkdir(mode=0o700)
        foreign = host_recovery.CONTAINER_RUNTIME_ROOT / "foreign"
        foreign.mkdir(mode=0o700)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "without authority"):
            host_recovery.recover()
        self.assertTrue(foreign.exists())

    def test_marker_last_fsyncs_durable_runtime_parents_when_children_are_absent(
        self,
    ) -> None:
        host_recovery.CONTAINER_RUNTIME_ROOT.mkdir(mode=0o700)
        host_recovery.RUNTIME_IDENTITY_ROOT.mkdir(mode=0o700)
        self.arm()
        calls: list[Path] = []
        real_fsync = host_recovery.fsync_directory

        def record_fsync(path: Path) -> None:
            calls.append(path)
            real_fsync(path)

        with mock.patch.object(
            host_recovery, "fsync_directory", side_effect=record_fsync
        ):
            self.assertEqual(host_recovery.recover(), "recovered")
        runtime_sync = max(
            index
            for index, path in enumerate(calls)
            if path == host_recovery.CONTAINER_RUNTIME_ROOT
        )
        identity_sync = max(
            index
            for index, path in enumerate(calls)
            if path == host_recovery.RUNTIME_IDENTITY_ROOT
        )
        marker_sync = max(
            index
            for index, path in enumerate(calls)
            if path == host_recovery.STATE_ROOT
        )
        self.assertLess(runtime_sync, marker_sync)
        self.assertLess(identity_sync, marker_sync)

    def test_markerless_podman_inventory_cutpoint_is_durably_recoverable(self) -> None:
        class SimulatedKill(BaseException):
            pass

        self.initialise_podman_store()
        calls = 0

        def interrupted_inventory() -> list[str]:
            nonlocal calls
            calls += 1
            self.assertTrue(host_recovery.PODMAN_INSPECTION_MARKER.exists())
            if calls == 1:
                (host_recovery.PODMAN_RUNROOT / "podman-created.lock").touch()
                raise SimulatedKill()
            return []

        with mock.patch.object(
            host_recovery, "_podman_ids", side_effect=interrupted_inventory
        ):
            with self.assertRaises(SimulatedKill):
                host_recovery.recover()
            self.assertTrue(host_recovery.PODMAN_INSPECTION_MARKER.exists())
            self.assertEqual(host_recovery.recover(), "already-clean")

        self.assertFalse(host_recovery.PODMAN_INSPECTION_MARKER.exists())
        self.assertFalse(host_recovery.PODMAN_INSPECTION_MARKER_TEMP.exists())
        self.assertEqual(list(host_recovery.PODMAN_RUNROOT.iterdir()), [])

    def test_unbound_request_publication_cutpoints_and_orphan_discard(self) -> None:
        temporary = self.runtime / ".probe-only.request.tmp"
        temporary.write_bytes(b'{"mode":"probe')
        temporary.chmod(0o600)
        self.assertEqual(host_recovery.recover(), "already-clean")
        self.assertFalse(temporary.exists())

        request = self.runtime / "probe-only.request"
        raw = compact_canonical(
            {
                "mode": "probe-only",
                "nonce": NONCE,
                "schema": host_recovery.PROBE_REQUEST_SCHEMA,
            }
        )
        temporary.write_bytes(raw)
        temporary.chmod(0o600)
        os.link(temporary, request)
        self.assertEqual(host_recovery.recover(), "already-clean")
        self.assertFalse(temporary.exists())
        self.assertTrue(request.exists())
        self.assertEqual(
            host_recovery.discard_unbound_launch_requests(), "discarded-1"
        )
        self.assertFalse(request.exists())

    def test_guided_lifecycle_lock_is_safe_and_serializes_request_ownership(
        self,
    ) -> None:
        lock = host_recovery.GUIDED_LIFECYCLE_LOCK
        target = self.root / "foreign-lock-target"
        target.write_bytes(b"must-not-change")
        lock.symlink_to(target)
        with self.assertRaises(OSError):
            host_recovery.acquire_guided_lifecycle_lock()
        self.assertEqual(target.read_bytes(), b"must-not-change")
        lock.unlink()

        descriptor = host_recovery.acquire_guided_lifecycle_lock()
        try:
            self.assertEqual(
                host_recovery.validate_guided_lifecycle_lock(descriptor),
                "locked",
            )
            with self.assertRaisesRegex(
                host_recovery.RecoveryError, "already active"
            ):
                host_recovery.acquire_guided_lifecycle_lock()
        finally:
            os.close(descriptor)

        lock.write_bytes(b"foreign")
        lock.chmod(0o600)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "authority drift"):
            host_recovery.acquire_guided_lifecycle_lock()
        self.assertEqual(lock.read_bytes(), b"foreign")

        lock.unlink()
        lock.touch(mode=0o600)
        alias = self.state / "guided.lock.alias"
        os.link(lock, alias)
        with self.assertRaisesRegex(host_recovery.RecoveryError, "authority drift"):
            host_recovery.acquire_guided_lifecycle_lock()
        self.assertEqual(lock.stat().st_nlink, 2)


if __name__ == "__main__":
    unittest.main()
