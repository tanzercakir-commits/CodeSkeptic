#!/usr/bin/env python3
"""Contracts for the P10-09 sealed host-contamination envelope."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_stability_campaign as stability  # noqa: E402


BOOT_ID = "12345678-1234-1234-1234-123456789abc"
NONCE = "abcdefab-cdef-abcd-efab-cdefabcdefab"
USER = "tester"
UID = 1000
SOURCE_REVISION = "2" * 40
SOURCE_TREE_SHA1 = "8" * 40
SOURCE_MANIFEST_SHA256 = "7" * 64
RUNTIME_CONFIG_SHA256 = "6" * 64
BUNDLE_INVENTORY_SHA256 = "1" * 64
IMAGE_ARCHIVE_SHA256 = "4" * 64
SYSTEM_CURSOR = b"-- cursor: system-cursor\n"
USER_CURSOR = b"-- cursor: user-cursor\n"
SYSTEM_LIFECYCLE_MESSAGE_IDS = (
    "7d4958e842da4a758f6c1cdc7b36dcc5",
    "39f53479d3a045ac8e11786248231fbf",
    "be02cf6855d2428ba40df7e9d022f03d",
)
COREDUMP_MESSAGE_ID = "fc2e22bc6ee647b6b90729ab34a250b1"


def journal_event(
    unit: str,
    message_id: str = SYSTEM_LIFECYCLE_MESSAGE_IDS[0],
    *,
    user: bool = False,
    boot_id: str = BOOT_ID.replace("-", ""),
) -> bytes:
    value = {
        "MESSAGE_ID": message_id,
        "_BOOT_ID": boot_id,
        "USER_UNIT" if user else "UNIT": unit,
    }
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def command_binds_after_cursor(argv: list[str], cursor: bytes) -> bool:
    value = cursor.removeprefix(b"-- cursor: ").removesuffix(b"\n").decode(
        "ascii"
    )
    return (
        f"--after-cursor={value}" in argv
        or any(
            argument == "--after-cursor"
            and index + 1 < len(argv)
            and argv[index + 1] == value
            for index, argument in enumerate(argv)
        )
    )


def cursor_anchor_bytes(cursor: bytes) -> bytes:
    value = cursor.removeprefix(b"-- cursor: ").removesuffix(b"\n").decode(
        "ascii"
    )
    return (
        json.dumps({"__CURSOR": value}, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def command_binds_cursor_anchor(argv: list[str], cursor: bytes) -> bool:
    value = cursor.removeprefix(b"-- cursor: ").removesuffix(b"\n").decode(
        "ascii"
    )
    return (
        f"--cursor={value}" in argv
        or any(
            argument == "--cursor"
            and index + 1 < len(argv)
            and argv[index + 1] == value
            for index, argument in enumerate(argv)
        )
    ) and not any(
        argument == "--after-cursor"
        or argument.startswith("--after-cursor=")
        for argument in argv
    )


def socket_bytes(accepted: int = 0) -> bytes:
    values = {
        "Id": "drkonqi-coredump-launcher.socket",
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "UnitFileState": "masked",
        "Result": "success",
        "Job": "",
        "NAccepted": str(accepted),
        "Listen": "/run/user/1000/drkonqi-coredump-launcher",
    }
    return b"".join(
        f"{name}={values[name]}\n".encode("utf-8")
        for name in stability.HOST_SOCKET_PROPERTIES
    )


class FakeHostRunner:
    def __init__(self, *, coredump: bytes = b"", socket: bytes | None = None,
                 overrides: dict[str, bytes] | None = None) -> None:
        self.outputs = {
            "coredumpctl": coredump,
            "system_helpers": b"",
            "user_launchers": b"",
            "failed_system": b"",
            "failed_user": b"",
            "user_socket": socket_bytes() if socket is None else socket,
            "system_journal_cursor": SYSTEM_CURSOR,
            "user_journal_cursor": USER_CURSOR,
            "system_journal_anchor": cursor_anchor_bytes(SYSTEM_CURSOR),
            "user_journal_anchor": cursor_anchor_bytes(USER_CURSOR),
            "system_journal_delta": b"",
            "user_journal_delta": b"",
        }
        if overrides:
            self.outputs.update(overrides)
        self.phase: str | None = None
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], maximum: int) -> bytes:
        del maximum
        self.calls.append(copy.deepcopy(argv))
        if argv and argv[0] == "/usr/bin/podman":
            return b""
        if argv and argv[0] == "/usr/bin/coredumpctl":
            return self.outputs["coredumpctl"]
        if any(Path(argument).name == "journalctl" for argument in argv):
            if "--sync" in argv:
                return b""
            scope = "user" if "--user" in argv else "system"
            after_cursor = any(
                argument == "--after-cursor"
                or argument.startswith("--after-cursor=")
                for argument in argv
            )
            cursor_anchor = any(
                argument == "--cursor" or argument.startswith("--cursor=")
                for argument in argv
            )
            if after_cursor:
                kind = "delta"
            elif cursor_anchor:
                kind = "anchor"
            else:
                kind = "cursor"
            return self.outputs[f"{scope}_journal_{kind}"]
        if argv and argv[0] == "/usr/bin/systemctl":
            is_user = "--user" in argv
            if "show" in argv and "drkonqi-coredump-launcher.socket" in argv:
                return self.outputs["user_socket"]
            if "--state=failed" in argv:
                return self.outputs["failed_user" if is_user else "failed_system"]
            if any("drkonqi-coredump-launcher@" in argument for argument in argv):
                return self.outputs["user_launchers"]
            if any(
                "systemd-coredump@" in argument
                or "drkonqi-coredump-processor@" in argument
                for argument in argv
            ):
                return self.outputs["system_helpers"]
        raise AssertionError(f"unexpected host observation command: {argv!r}")


def capture(root: Path, phase: str, runner: FakeHostRunner) -> dict:
    runner.phase = phase
    return stability.capture_host_snapshot(
        root / "host" / phase,
        BOOT_ID,
        USER,
        UID,
        command_runner=runner,
        live_boot_id=BOOT_ID,
        identity_verifier=lambda user, uid: (user, uid) == (USER, UID),
        require_root=False,
    )


@unittest.skipUnless(
    os.name == "posix" and Path("/proc/self/stat").is_file(),
    "Linux process containment unavailable",
)
class BoundedHostCommandContractTest(unittest.TestCase):
    def assert_identity_absent(self, identity_path: Path) -> None:
        pid_text, start_text = identity_path.read_text(
            encoding="ascii"
        ).split(":")
        pid = int(pid_text)
        start_time = int(start_text)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            identity = stability._proc_process_identity(pid)
            if identity is None or identity[1] != start_time:
                break
            time.sleep(0.02)
        identity = stability._proc_process_identity(pid)
        self.assertTrue(
            identity is None or identity[1] != start_time,
            f"owned descendant {pid}:{start_time} survived",
        )

    def test_cleanup_treats_zombie_leader_live_worker_as_owned(
        self,
    ) -> None:
        root_pid = 11_001
        root_start = 81
        child_pid = 11_002
        child_start = 82
        process = mock.Mock(pid=root_pid)
        process.wait.return_value = 0
        child_snapshots = iter([
            {child_pid: "Z", child_pid + 100: "R"},
            {child_pid: "Z", child_pid + 100: "T"},
        ])

        def identity(pid: int) -> tuple[int, int] | None:
            return (1, root_start) if pid == root_pid else None

        def record(pid: int) -> tuple[int, int, str] | None:
            if pid == root_pid:
                return (1, root_start, "T")
            if pid == child_pid:
                return (root_pid, child_start, "Z")
            return None

        def task_states(pid: int, start_time: int) -> dict[int, str] | None:
            del start_time
            if pid == root_pid:
                return {root_pid: "T"}
            return next(child_snapshots)

        with (
            mock.patch.object(
                stability, "_proc_process_identity", side_effect=identity
            ),
            mock.patch.object(
                stability, "_proc_process_record", side_effect=record
            ),
            mock.patch.object(
                stability,
                "_owned_host_descendants",
                side_effect=[
                    {child_pid: child_start},
                    {child_pid: child_start},
                    {},
                ],
            ),
            mock.patch.object(
                stability, "_action_task_states", side_effect=task_states
            ),
            mock.patch.object(stability, "_signal_owned_pid") as signal_owned,
        ):
            stability._kill_owned_host_command(process)

        self.assertIn(
            mock.call(child_pid, child_start, stability.signal.SIGSTOP),
            signal_owned.call_args_list,
        )
        self.assertIn(
            mock.call(child_pid, child_start, stability.signal.SIGKILL),
            signal_owned.call_args_list,
        )

    @staticmethod
    def detached_identity_command(identity_path: Path) -> list[str]:
        child = "import time;time.sleep(60)"
        code = (
            "import os,pathlib,subprocess,sys;"
            "sink=open(os.devnull,'wb');"
            f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
            "start_new_session=True,stdin=subprocess.DEVNULL,"
            "stdout=sink,stderr=sink,close_fds=True);"
            "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
            "encoding='ascii').rsplit(')',1)[1].strip().split();"
            "open(sys.argv[1],'w',encoding='ascii').write("
            "str(child.pid)+':'+fields[19])"
        )
        return [sys.executable, "-c", code, str(identity_path)]

    def test_selector_constructor_failure_cleans_detached_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity_path = Path(temporary) / "selector-ctor.identity"
            captured: list[object] = []
            real_popen = stability.subprocess.Popen

            def capture_popen(*args: object, **kwargs: object) -> object:
                process = real_popen(*args, **kwargs)
                captured.append(process)
                return process

            def fail_after_child_started() -> object:
                deadline = time.monotonic() + 2.0
                while not identity_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise OSError("fixture selector constructor failure")

            try:
                with (
                    mock.patch.object(
                        stability.subprocess, "Popen", side_effect=capture_popen
                    ),
                    mock.patch.object(
                        stability.selectors,
                        "DefaultSelector",
                        side_effect=fail_after_child_started,
                    ),
                    self.assertRaisesRegex(
                        stability.StabilityError,
                        "selector constructor failure",
                    ),
                ):
                    stability._bounded_host_command(
                        self.detached_identity_command(identity_path),
                        1024,
                        timeout_seconds=5,
                    )
                self.assertTrue(identity_path.is_file())
                self.assert_identity_absent(identity_path)
                self.assertTrue(captured)
                self.assertIsNotNone(captured[0].poll())
            finally:
                for process in captured:
                    if process.poll() is None:
                        stability._kill_owned_host_command(process)

    def test_selector_register_and_close_failures_are_composed_after_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity_path = Path(temporary) / "selector-register.identity"
            captured: list[object] = []
            real_popen = stability.subprocess.Popen
            real_selector = stability.selectors.DefaultSelector

            def capture_popen(*args: object, **kwargs: object) -> object:
                process = real_popen(*args, **kwargs)
                captured.append(process)
                return process

            class FailingSelector:
                def __init__(self) -> None:
                    self.inner = real_selector()

                def register(self, *args: object, **kwargs: object) -> None:
                    del args, kwargs
                    deadline = time.monotonic() + 2.0
                    while (
                        not identity_path.exists()
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.01)
                    raise OSError("fixture selector register failure")

                def close(self) -> None:
                    self.inner.close()
                    raise OSError("fixture selector close failure")

            try:
                with (
                    mock.patch.object(
                        stability.subprocess, "Popen", side_effect=capture_popen
                    ),
                    mock.patch.object(
                        stability.selectors,
                        "DefaultSelector",
                        new=FailingSelector,
                    ),
                    self.assertRaisesRegex(
                        stability.StabilityError,
                        "register failure.*cleanup failed.*close failure",
                    ),
                ):
                    stability._bounded_host_command(
                        self.detached_identity_command(identity_path),
                        1024,
                        timeout_seconds=5,
                    )
                self.assertTrue(identity_path.is_file())
                self.assert_identity_absent(identity_path)
                self.assertTrue(captured)
                self.assertIsNotNone(captured[0].poll())
            finally:
                for process in captured:
                    if process.poll() is None:
                        stability._kill_owned_host_command(process)

    def test_inherited_pipe_descendant_cannot_outlive_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "descendant.pid"
            child = "import time;time.sleep(60)"
            code = (
                "import pathlib,subprocess,sys;"
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}]);"
                "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
                "encoding='ascii').rsplit(')',1)[1].strip().split();"
                "open(sys.argv[1],'w',encoding='ascii').write("
                "str(child.pid)+':'+fields[19])"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(stability.StabilityError, "timed out"):
                stability._bounded_host_command(
                    [sys.executable, "-c", code, str(pid_path)],
                    1024,
                    timeout_seconds=1,
                )
            self.assertGreaterEqual(time.monotonic() - started, 0.8)
            self.assert_identity_absent(pid_path)

    def test_closed_pipe_new_session_descendant_is_owned_and_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "detached.pid"
            child = "import time;time.sleep(60)"
            code = (
                "import os,pathlib,subprocess,sys;"
                "sink=open(os.devnull,'wb');"
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
                "start_new_session=True,stdout=sink,stderr=sink);"
                "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
                "encoding='ascii').rsplit(')',1)[1].strip().split();"
                "open(sys.argv[1],'w',encoding='ascii').write("
                "str(child.pid)+':'+fields[19])"
            )
            with self.assertRaisesRegex(stability.StabilityError, "timed out"):
                stability._bounded_host_command(
                    [sys.executable, "-c", code, str(pid_path)],
                    1024,
                    timeout_seconds=1,
                )
            self.assert_identity_absent(pid_path)

    def test_output_overflow_kills_the_owned_detached_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "overflow-descendant.pid"
            child = "import time;time.sleep(60)"
            code = (
                "import os,pathlib,subprocess,sys;"
                "sink=open(os.devnull,'wb');"
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
                "start_new_session=True,stdout=sink,stderr=sink);"
                "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
                "encoding='ascii').rsplit(')',1)[1].strip().split();"
                "open(sys.argv[1],'w',encoding='ascii').write("
                "str(child.pid)+':'+fields[19]);"
                "block=b'x'*65536;"
                "[(os.write(1,block)) for _ in range(1024)]"
            )
            with self.assertRaisesRegex(stability.StabilityError, "size limit"):
                stability._bounded_host_command(
                    [sys.executable, "-c", code, str(pid_path)],
                    4096,
                    timeout_seconds=5,
                )
            self.assert_identity_absent(pid_path)

    def test_cleanup_converges_while_descendant_forks_new_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            children_path = root / "fork-race-children.identities"
            forker_path = root / "fork-race-parent.identity"
            forker = f"""import os,signal,time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    pid = os.fork()
    if pid == 0:
        os.setsid()
        fields = open('/proc/self/stat', encoding='ascii').read().rsplit(')', 1)[1].strip().split()
        descriptor = os.open({str(children_path)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.write(descriptor, (str(os.getpid()) + ':' + fields[19] + '\\n').encode('ascii'))
        os.fsync(descriptor)
        os.close(descriptor)
        time.sleep(60)
        os._exit(0)
    time.sleep(0.01)
"""
            code = (
                "import os,pathlib,subprocess,sys,time;"
                "forker=subprocess.Popen([sys.executable,'-c',sys.argv[2]],"
                "start_new_session=True,stdin=subprocess.DEVNULL,"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True);"
                "fields=(pathlib.Path('/proc')/str(forker.pid)/'stat').read_text("
                "encoding='ascii').rsplit(')',1)[1].strip().split();"
                "open(sys.argv[1],'w',encoding='ascii').write("
                "str(forker.pid)+':'+fields[19]);time.sleep(60)"
            )
            observed: list[tuple[int, int]] = []
            real_signal = stability._signal_owned_pid
            stop_calls: dict[int, int] = {}

            def delayed_second_stop(
                pid: int, start_time: int, signal_number: int,
            ) -> None:
                if signal_number == stability.signal.SIGSTOP and forker_path.exists():
                    forker_pid = int(
                        forker_path.read_text(encoding="ascii").split(":", 1)[0]
                    )
                    if pid == forker_pid:
                        stop_calls[pid] = stop_calls.get(pid, 0) + 1
                        if stop_calls[pid] == 1:
                            return
                        if stop_calls[pid] == 2:
                            time.sleep(0.10)
                real_signal(pid, start_time, signal_number)

            try:
                with (
                    mock.patch.object(
                        stability,
                        "_signal_owned_pid",
                        side_effect=delayed_second_stop,
                    ),
                    self.assertRaisesRegex(stability.StabilityError, "timed out"),
                ):
                    stability._bounded_host_command(
                        [
                            sys.executable,
                            "-c",
                            code,
                            str(forker_path),
                            forker,
                        ],
                        1024,
                        timeout_seconds=1,
                    )
                observed = [
                    tuple(map(int, line.split(":")))
                    for line in children_path.read_text(
                        encoding="ascii"
                    ).splitlines()
                ]
                self.assertGreaterEqual(len(observed), 10)
                for pid, start_time in observed:
                    identity = stability._proc_process_identity(pid)
                    self.assertTrue(
                        identity is None or identity[1] != start_time
                    )
                self.assert_identity_absent(forker_path)
            finally:
                for pid, start_time in observed:
                    real_signal(pid, start_time, stability.signal.SIGKILL)
                if forker_path.exists():
                    pid_text, start_text = forker_path.read_text(
                        encoding="ascii"
                    ).split(":")
                    real_signal(
                        int(pid_text), int(start_text), stability.signal.SIGKILL
                    )


def session_record(
    runtime_config_sha256: str = "6" * 64,
    runtime_launch_receipt_sha256: str = "7" * 64,
) -> dict:
    identity = {
        "schema": stability.SESSION_SCHEMA,
        "policy_sha256": "1" * 64,
        "source_revision": "2" * 40,
        "source_tree_sha1": "3" * 40,
        "source_manifest_sha256": "4" * 64,
        "analyzer_sha256": "5" * 64,
        "runtime_config_sha256": runtime_config_sha256,
        "runtime_launch_receipt_sha256": runtime_launch_receipt_sha256,
        "build_authority_receipt_sha256": "8" * 64,
        "realworld_manifest_sha256": "9" * 64,
        "realworld_mirror_authority_sha256": "a" * 64,
        "determinism_manifest_sha256": "b" * 64,
        "baseline_sha256": "c" * 64,
        "baseline_authority_projection_sha256": "f" * 64,
        "sanitizer_receipts": {"address": "d" * 64, "undefined": "e" * 64},
        "prerequisite_receipts": {
            "hosted_exact_head": "0" * 64,
            "quality_floor": "1" * 64,
        },
        "fault_injection_test_binary": {
            "path": "/authority/undefined/tests/codeskeptic_tests",
            "sha256": "2" * 64,
            "sanitizer_profile": "undefined",
            "sanitizer_receipt_sha256": "e" * 64,
        },
        "hardware_class": "test-host",
        "boot_id": BOOT_ID,
    }
    return {
        "id": stability.build_session_identity(identity),
        "controller_id": "3" * 64,
        "identity": identity,
    }


def write_inner_campaign(
    root: Path,
    runtime_config_sha256: str = "6" * 64,
    runtime_launch_receipt_sha256: str = "7" * 64,
) -> dict:
    campaign = root / "campaign"
    campaign.mkdir(parents=True)
    (campaign / "retained.txt").write_text("retained\n", encoding="ascii")
    base = {
        "schema": stability.RECEIPT_SCHEMA,
        "status": "accepted",
        "policy": {},
        "session": session_record(
            runtime_config_sha256, runtime_launch_receipt_sha256
        ),
        "schedule": {},
        "timeline": {},
        "cycles": [],
        "cycle_summary": {},
        "establishment": {},
        "authorities": {},
        "diagnostics": {},
        "gates": {},
        "failures": [],
    }
    return stability.finalize_evidence(campaign, base)


def cgroup_intent(session: str) -> dict:
    return {
        "schema": stability.CGROUP_AUTHORITY_INTENT_SCHEMA,
        "status": "armed",
        "source_revision": SOURCE_REVISION,
        "session": session,
        "exclusive_cpus": "0-3",
        "system_slice_cgroup": stability.RUNTIME_SYSTEM_SLICE_CGROUP,
        "service_cgroup": stability.RUNTIME_SERVICE_CGROUP,
        "payload_cgroup": f"/sys/fs/cgroup{stability.RUNTIME_CGROUP_PARENT}",
        "measurement_cgroup": stability.RUNTIME_MEASUREMENT_CGROUP,
        "original_root_isolated_cpus": "",
        "original_system_slice_exclusive_cpus": "",
        "original_service_exclusive_cpus": "",
    }


def host_recovery_intent(
    session: str,
    *,
    runtime_config_sha256: str = RUNTIME_CONFIG_SHA256,
    source_tree_sha1: str = SOURCE_TREE_SHA1,
    source_manifest_sha256: str = SOURCE_MANIFEST_SHA256,
) -> dict:
    bundle_receipt = {
        "image_archive_sha256": IMAGE_ARCHIVE_SHA256,
        "image_digest": stability.PINNED_EVIDENCE_IMAGE_DIGEST,
        "image_id": stability.PINNED_EVIDENCE_IMAGE_ID,
        "image_reference": stability.PINNED_EVIDENCE_IMAGE,
        "inventory_sha256": BUNDLE_INVENTORY_SHA256,
        "revision": SOURCE_REVISION,
        "runtime_config_sha256": runtime_config_sha256,
        "schema": stability.BUNDLE_RECEIPT_SCHEMA,
        "source_manifest_sha256": source_manifest_sha256,
        "source_tree_sha1": source_tree_sha1,
    }
    bundle_receipt_sha256 = hashlib.sha256(
        stability.canonical_document(bundle_receipt)
    ).hexdigest()
    installation_authority = {
        "bundle_receipt_sha256": bundle_receipt_sha256,
        "bundle_revision": SOURCE_REVISION,
        "schema": stability.INSTALLATION_AUTHORITY_SCHEMA,
    }
    installation_receipt = {
        "authority_root": "/opt/codeskeptic-p10-09/authority",
        "bundle_inventory_sha256": BUNDLE_INVENTORY_SHA256,
        "bundle_receipt_sha256": bundle_receipt_sha256,
        "bundle_revision": SOURCE_REVISION,
        "config_path": "/etc/codeskeptic-p10-09/runtime.json",
        "image": {
            "archive_sha256": IMAGE_ARCHIVE_SHA256,
            "digest": stability.PINNED_EVIDENCE_IMAGE_DIGEST,
            "id": stability.PINNED_EVIDENCE_IMAGE_ID,
            "reference": stability.PINNED_EVIDENCE_IMAGE,
        },
        "installed_inventory_sha256": BUNDLE_INVENTORY_SHA256,
        "operator_root": "/opt/codeskeptic-p10-09/operator",
        "schema": stability.INSTALLATION_RECEIPT_SCHEMA,
        "unit_path": "/etc/systemd/system/codeskeptic-stability.service",
    }
    return {
        "boot_id": BOOT_ID,
        "containers": {
            "campaign": f"codeskeptic-p10-09-{NONCE}",
            "preflight": f"codeskeptic-p10-09-preflight-{NONCE}",
            "verifier": f"codeskeptic-p10-09-verifier-{NONCE}",
        },
        "installation": {
            "bundle_inventory_sha256": BUNDLE_INVENTORY_SHA256,
            "bundle_receipt_sha256": bundle_receipt_sha256,
            "bundle_revision": SOURCE_REVISION,
            "image_archive_sha256": IMAGE_ARCHIVE_SHA256,
            "image_digest": stability.PINNED_EVIDENCE_IMAGE_DIGEST,
            "image_id": stability.PINNED_EVIDENCE_IMAGE_ID,
            "image_reference": stability.PINNED_EVIDENCE_IMAGE,
            "installation_authority_sha256": hashlib.sha256(
                stability.canonical_document(installation_authority)
            ).hexdigest(),
            "installation_receipt_sha256": hashlib.sha256(
                stability.canonical_document(installation_receipt)
            ).hexdigest(),
            "installed_inventory_sha256": BUNDLE_INVENTORY_SHA256,
            "runtime_config_sha256": runtime_config_sha256,
            "source_manifest_sha256": source_manifest_sha256,
            "source_tree_sha1": source_tree_sha1,
        },
        "mode": "campaign",
        "schema": stability.HOST_RECOVERY_INTENT_SCHEMA,
        "session": session,
        "session_nonce": NONCE,
        "status": "armed",
    }


def write_restored_cgroup_tree(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "cpuset.cpus.isolated").write_text("\n", encoding="ascii")
    for relative in (
        Path("system.slice"),
        Path("system.slice/codeskeptic-stability.service"),
    ):
        cgroup = root / relative
        cgroup.mkdir(parents=True)
        for name, value in {
            "cpuset.cpus.partition": "member\n",
            "cpuset.cpus.exclusive": "\n",
            "cpuset.cpus.exclusive.effective": "\n",
            "cpuset.cpus.effective": "0-11\n",
        }.items():
            (cgroup / name).write_text(value, encoding="ascii")


def write_cleanup(
    root: Path,
    operator: Path,
    container_id: str = "4" * 64,
    *,
    runtime_config_sha256: str = RUNTIME_CONFIG_SHA256,
    source_tree_sha1: str = SOURCE_TREE_SHA1,
    source_manifest_sha256: str = SOURCE_MANIFEST_SHA256,
) -> None:
    session = root.name
    intent_path = root / stability.CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH
    intent_data = stability.canonical_json(cgroup_intent(session)) + b"\n"
    intent_path.write_bytes(intent_data)
    intent_sha256 = hashlib.sha256(intent_data).hexdigest()
    host_recovery_path = root / stability.HOST_RECOVERY_INTENT_EVIDENCE_PATH
    host_recovery_data = (
        stability.canonical_json(
            host_recovery_intent(
                session,
                runtime_config_sha256=runtime_config_sha256,
                source_tree_sha1=source_tree_sha1,
                source_manifest_sha256=source_manifest_sha256,
            )
        )
        + b"\n"
    )
    host_recovery_path.write_bytes(host_recovery_data)
    host_recovery_sha256 = hashlib.sha256(host_recovery_data).hexdigest()
    value = {
        "schema": stability.HOST_CLEANUP_SCHEMA,
        "boot_id": BOOT_ID,
        "session": session,
        "session_nonce": NONCE,
        "target_user": USER,
        "target_uid": UID,
        "podman": {
            "executable": "/usr/bin/podman",
            "root": "/var/lib/codeskeptic-p10-09/podman-root",
            "runroot": "/run/codeskeptic-p10-09/podman-runroot",
            "storage_driver": "overlay",
            "cgroup_manager": "cgroupfs",
            "events_backend": "none",
            "hooks_dir": operator.parent.as_posix(),
            "runtime": "/usr/bin/crun",
            "conmon": "/usr/bin/conmon",
        },
        "container": {
            "id": container_id,
            "name": f"codeskeptic-p10-09-{NONCE}",
            "cidfile": f"/run/codeskeptic-p10-09/{session}.cid",
            "image_id": stability.PINNED_EVIDENCE_IMAGE_ID,
            "command": stability.RUNTIME_CONTROLLER_COMMAND,
        },
        "verifier_container": {
            "id": "5" * 64,
            "name": f"codeskeptic-p10-09-verifier-{NONCE}",
            "cidfile": (
                f"/run/codeskeptic-p10-09/{session}.verifier.cid"
            ),
            "image_id": stability.PINNED_EVIDENCE_IMAGE_ID,
            "command": stability.RUNTIME_VERIFIER_COMMAND,
        },
        "completion": {
            "campaign": "inner-verified",
            "cleanup": "authoritative-runner",
            "exec_stop_post_recovery": False,
        },
        "cgroup_authority": {
            "intent": {
                "path": stability.CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH,
                "sha256": intent_sha256,
            },
            "marker": stability.CGROUP_AUTHORITY_MARKER,
            "temporary_marker": stability.CGROUP_AUTHORITY_MARKER_TEMP,
        },
        "host_recovery": {
            "intent": {
                "path": stability.HOST_RECOVERY_INTENT_EVIDENCE_PATH,
                "sha256": host_recovery_sha256,
            },
            "marker": stability.HOST_RECOVERY_MARKER,
            "temporary_marker": stability.HOST_RECOVERY_MARKER_TEMP,
        },
        "cgroups": {
            "root": "/sys/fs/cgroup",
            "system_slice": stability.RUNTIME_SYSTEM_SLICE_CGROUP,
            "service": stability.RUNTIME_SERVICE_CGROUP,
            "measurement": stability.RUNTIME_MEASUREMENT_CGROUP,
            "payload": f"/sys/fs/cgroup{stability.RUNTIME_CGROUP_PARENT}",
        },
        "cgroup_restoration": {
            "root": {"cpuset_cpus_isolated": ""},
            "system_slice": {
                "cpuset_cpus_partition": "member",
                "cpuset_cpus_exclusive": "",
                "cpuset_cpus_exclusive_effective": "",
                "cpuset_cpus_effective": "0-11",
            },
            "service": {
                "cpuset_cpus_partition": "member",
                "cpuset_cpus_exclusive": "",
                "cpuset_cpus_exclusive_effective": "",
                "cpuset_cpus_effective": "0-11",
            },
        },
        "runtime": {
            "identity_marker": (
                "/var/lib/codeskeptic-p10-09/runtime-identities/"
                f"{session}.json"
            ),
            "tree": f"/var/lib/codeskeptic-p10-09/runtime/{session}",
        },
        "gates": {
            "campaign_cidfile_absent": "pass",
            "campaign_container_identity_absent": "pass",
            "container_inventory_empty": "pass",
            "cgroup_authority_intent_bound": "pass",
            "cgroup_authority_marker_absent": "pass",
            "cgroup_authority_temporary_absent": "pass",
            "host_recovery_intent_bound": "pass",
            "host_recovery_marker_absent": "pass",
            "host_recovery_temporary_absent": "pass",
            "measurement_cgroup_empty": "pass",
            "payload_cgroup_empty": "pass",
            "root_isolated_cpus_empty": "pass",
            "runtime_absent": "pass",
            "runtime_identity_absent": "pass",
            "service_effective_cpus_restored": "pass",
            "service_exclusive_cpus_effective_empty": "pass",
            "service_exclusive_cpus_empty": "pass",
            "service_partition_member": "pass",
            "system_slice_effective_cpus_restored": "pass",
            "system_slice_exclusive_cpus_effective_empty": "pass",
            "system_slice_exclusive_cpus_empty": "pass",
            "system_slice_partition_member": "pass",
            "verifier_cidfile_absent": "pass",
            "verifier_container_identity_absent": "pass",
        },
    }
    (root / "host" / "cleanup.json").write_bytes(stability.canonical_document(value))


def cleanup_validation_authority(
    *, runtime_config_sha256: str = RUNTIME_CONFIG_SHA256,
) -> dict[str, str]:
    return {
        "expected_runtime_config_sha256": runtime_config_sha256,
        "expected_source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "expected_source_revision": SOURCE_REVISION,
        "expected_source_tree_sha1": SOURCE_TREE_SHA1,
    }


class StabilityHostContaminationTest(unittest.TestCase):
    def test_clean_snapshot_pair_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "session"
            (root / "host").mkdir(parents=True)
            pre = capture(root, "pre", FakeHostRunner())
            post = capture(root, "post", FakeHostRunner())
            gates = stability._host_pair_projection(root, pre, post)
            self.assertTrue(all(value == "pass" for value in gates.values()))

    def test_coredump_delta_and_naccepted_drift_fail(self) -> None:
        cases = (
            (
                FakeHostRunner(),
                FakeHostRunner(coredump=b'{"COREDUMP_PID":1}\n'),
                "coredump inventory changed",
            ),
            (
                FakeHostRunner(socket=socket_bytes(7)),
                FakeHostRunner(socket=socket_bytes(8)),
                "socket identity changed",
            ),
        )
        for pre_runner, post_runner, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "session"
                (root / "host").mkdir(parents=True)
                pre = capture(root, "pre", pre_runner)
                post = capture(root, "post", post_runner)
                with self.assertRaisesRegex(stability.StabilityError, message):
                    stability._host_pair_projection(root, pre, post)

    def test_helper_and_failed_inventories_fail(self) -> None:
        for field in ("system_helpers", "user_launchers", "failed_system", "failed_user"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "session"
                (root / "host").mkdir(parents=True)
                dirty = FakeHostRunner(overrides={field: b"dirty.service loaded failed\n"})
                with self.assertRaisesRegex(
                    stability.StabilityError, "baseline is not empty"
                ):
                    capture(root, "pre", dirty)

    def test_transient_system_helper_lifecycle_is_rejected(self) -> None:
        cases = (
            (
                "systemd-coredump@9-123-456.service",
                SYSTEM_LIFECYCLE_MESSAGE_IDS[0],
            ),
            (
                "drkonqi-coredump-processor@9-123-456.service",
                SYSTEM_LIFECYCLE_MESSAGE_IDS[2],
            ),
        )
        for unit, message_id in cases:
            with self.subTest(unit=unit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "session"
                (root / "host").mkdir(parents=True)
                pre = capture(root, "pre", FakeHostRunner())
                post_runner = FakeHostRunner(
                    overrides={
                        "system_journal_delta": journal_event(unit, message_id),
                    }
                )
                with self.assertRaisesRegex(
                    stability.StabilityError, "journal|coredump|DrKonqi|helper"
                ):
                    post = capture(root, "post", post_runner)
                    stability._host_pair_projection(root, pre, post)

    def test_transient_user_launcher_or_socket_lifecycle_is_rejected(self) -> None:
        cases = (
            (
                "drkonqi-coredump-launcher@9-123-456.service",
                SYSTEM_LIFECYCLE_MESSAGE_IDS[1],
            ),
            (
                "drkonqi-coredump-launcher.socket",
                SYSTEM_LIFECYCLE_MESSAGE_IDS[2],
            ),
        )
        for unit, message_id in cases:
            with self.subTest(unit=unit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "session"
                (root / "host").mkdir(parents=True)
                pre = capture(root, "pre", FakeHostRunner())
                post_runner = FakeHostRunner(
                    overrides={
                        "user_journal_delta": journal_event(
                            unit, message_id, user=True
                        ),
                    }
                )
                with self.assertRaisesRegex(
                    stability.StabilityError, "journal|DrKonqi|launcher|socket"
                ):
                    post = capture(root, "post", post_runner)
                    stability._host_pair_projection(root, pre, post)

    def test_direct_system_coredump_message_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "session"
            (root / "host").mkdir(parents=True)
            pre = capture(root, "pre", FakeHostRunner())
            event = {
                "MESSAGE_ID": COREDUMP_MESSAGE_ID,
                "_BOOT_ID": BOOT_ID.replace("-", ""),
            }
            delta = (
                json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
            with self.assertRaisesRegex(
                stability.StabilityError, "journal|coredump"
            ):
                post = capture(
                    root,
                    "post",
                    FakeHostRunner(
                        overrides={"system_journal_delta": delta}
                    ),
                )
                stability._host_pair_projection(root, pre, post)

    def test_unrelated_lifecycle_events_are_retained_but_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "session"
            (root / "host").mkdir(parents=True)
            pre_runner = FakeHostRunner()
            pre = capture(root, "pre", pre_runner)
            post_runner = FakeHostRunner(
                overrides={
                    "system_journal_delta": journal_event(
                        "unrelated.service", SYSTEM_LIFECYCLE_MESSAGE_IDS[1]
                    ),
                    "user_journal_delta": journal_event(
                        "another-unrelated.service",
                        SYSTEM_LIFECYCLE_MESSAGE_IDS[2],
                        user=True,
                    ),
                }
            )
            post = capture(
                root,
                "post",
                post_runner,
            )
            self.assertIn("system_journal", pre["commands"])
            self.assertIn("user_journal", pre["commands"])
            self.assertTrue(
                any(
                    "--show-cursor" in argv and "--user" not in argv
                    for argv in pre_runner.calls
                )
            )
            self.assertTrue(
                any(
                    "--show-cursor" in argv and "--user" in argv
                    for argv in pre_runner.calls
                )
            )
            self.assertTrue(
                any(
                    command_binds_after_cursor(argv, SYSTEM_CURSOR)
                    for argv in post_runner.calls
                )
            )
            self.assertTrue(
                any(
                    "--user" in argv
                    and command_binds_after_cursor(argv, USER_CURSOR)
                    for argv in post_runner.calls
                )
            )
            gates = stability._host_pair_projection(root, pre, post)
            self.assertEqual(gates["journal_delta_clean"], "pass")

    def test_post_rejects_missing_or_different_pre_cursor_anchor(self) -> None:
        stale_delta = journal_event(
            "unrelated.service", SYSTEM_LIFECYCLE_MESSAGE_IDS[1]
        )
        cases = (
            ("system", b""),
            ("system", b'{"__CURSOR":"different-system-cursor"}\n'),
            ("user", b""),
            ("user", b'{"__CURSOR":"different-user-cursor"}\n'),
        )
        for scope, anchor in cases:
            with (
                self.subTest(scope=scope, anchor=anchor),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary) / "session"
                (root / "host").mkdir(parents=True)
                capture(root, "pre", FakeHostRunner())
                post_runner = FakeHostRunner(
                    overrides={
                        f"{scope}_journal_anchor": anchor,
                        "system_journal_delta": stale_delta,
                    }
                )
                with self.assertRaisesRegex(
                    stability.StabilityError, "anchor|cursor"
                ):
                    capture(root, "post", post_runner)
                expected_cursor = (
                    SYSTEM_CURSOR if scope == "system" else USER_CURSOR
                )
                self.assertTrue(
                    any(
                        ("--user" in argv) == (scope == "user")
                        and command_binds_cursor_anchor(argv, expected_cursor)
                        for argv in post_runner.calls
                    ),
                    f"{scope} journal anchor was not queried exactly",
                )

    def test_malformed_or_oversize_journal_cursor_is_rejected(self) -> None:
        cursors = (
            b"not-a-journal-cursor\n",
            b"-- cursor: first\n-- cursor: second\n",
            b"-- cursor: " + (b"x" * 5000) + b"\n",
        )
        for scope in ("system", "user"):
            for cursor in cursors:
                with (
                    self.subTest(scope=scope, cursor_size=len(cursor)),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary) / "session"
                    (root / "host").mkdir(parents=True)
                    with self.assertRaisesRegex(
                        stability.StabilityError, "cursor|size limit"
                    ):
                        capture(
                            root,
                            "pre",
                            FakeHostRunner(
                                overrides={f"{scope}_journal_cursor": cursor}
                            ),
                        )

    def test_malformed_or_wrong_boot_journal_delta_is_rejected(self) -> None:
        cases = (
            (b'{"MESSAGE_ID":\n', "journal|JSON|malformed"),
            (
                journal_event(
                    "unrelated.service",
                    SYSTEM_LIFECYCLE_MESSAGE_IDS[0],
                    boot_id="0" * 32,
                ),
                "boot",
            ),
        )
        for delta, message in cases:
            with (
                self.subTest(message=message),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary) / "session"
                (root / "host").mkdir(parents=True)
                pre = capture(root, "pre", FakeHostRunner())
                with self.assertRaisesRegex(stability.StabilityError, message):
                    post = capture(
                        root,
                        "post",
                        FakeHostRunner(
                            overrides={"system_journal_delta": delta}
                        ),
                    )
                    stability._host_pair_projection(root, pre, post)

    def test_journal_artifact_tamper_is_rejected(self) -> None:
        for scope in ("system", "user"):
            with (
                self.subTest(scope=scope),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary) / "session"
                (root / "host").mkdir(parents=True)
                capture(root, "pre", FakeHostRunner())
                post = capture(root, "post", FakeHostRunner())
                key = f"{scope}_journal"
                self.assertIn(key, post["commands"])
                journal = post["commands"][key]
                (root / "host" / "post" / journal["path"]).write_bytes(
                    journal_event("unrelated.service", user=scope == "user")
                )
                with self.assertRaises(stability.StabilityError):
                    stability.verify_host_snapshot(root / "host" / "post")

    def test_inflated_command_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "session"
            (root / "host").mkdir(parents=True)
            runner = FakeHostRunner(
                overrides={"failed_system": b"x" * (stability.MAX_HOST_COMMAND_BYTES + 1)}
            )
            with self.assertRaisesRegex(stability.StabilityError, "size limit"):
                capture(root, "pre", runner)

    def test_snapshot_manifest_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "session"
            (root / "host").mkdir(parents=True)
            capture(root, "pre", FakeHostRunner())
            (root / "host" / "pre" / "failed-system.txt").write_text(
                "tampered\n", encoding="ascii"
            )
            with self.assertRaises(stability.StabilityError):
                stability.verify_host_snapshot(root / "host" / "pre")

    def test_outer_seal_binds_inner_host_and_authorities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / f"20260823T000000Z-{BOOT_ID}-{NONCE}"
            (root / "host").mkdir(parents=True)
            pre = capture(root, "pre", FakeHostRunner())
            post = capture(root, "post", FakeHostRunner())
            self.assertEqual(pre["identity"], post["identity"])
            config = base / "runtime.json"
            config.write_text("{}\n", encoding="ascii")
            config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
            Path(f"{config}.sha256").write_text(
                f"{config_sha}  runtime.json\n", encoding="ascii"
            )
            launch = base / "launch" / "receipt.json"
            launch.parent.mkdir()
            launch.write_text("{}\n", encoding="ascii")
            Path(f"{launch}.sha256").write_text(
                f"{hashlib.sha256(launch.read_bytes()).hexdigest()}  receipt.json\n",
                encoding="ascii",
            )
            launch_sha = stability.sha256_file(launch)
            operator = base / "operator" / "run.sh"
            operator.parent.mkdir()
            operator.write_text("#!/bin/sh\n", encoding="ascii")
            write_cleanup(
                root, operator, runtime_config_sha256=config_sha
            )
            live_cgroup_root = base / "cgroup"
            live_state_root = base / "state"
            write_restored_cgroup_tree(live_cgroup_root)
            live_state_root.mkdir()
            inner = write_inner_campaign(root, "f" * 64, launch_sha)
            inner_sha = stability.sha256_file(root / "campaign" / "receipt.json")
            (root / "host" / "inner-verification.log").write_text(
                "CODESKEPTIC_STABILITY_VERIFIED "
                f"{inner_sha} {inner['session']['id']}\n",
                encoding="ascii",
            )
            runner = FakeHostRunner()
            with (
                mock.patch.object(
                    stability,
                    "load_runtime_config_file",
                    return_value={
                        "source": {
                            "manifest_sha256": SOURCE_MANIFEST_SHA256,
                            "revision": SOURCE_REVISION,
                            "tree_sha1": SOURCE_TREE_SHA1,
                        }
                    },
                ),
                mock.patch.object(stability, "load_runtime_launch_receipt", return_value={}),
            ):
                with self.assertRaisesRegex(
                    stability.StabilityError, "inner campaign authority"
                ):
                    stability.seal_operator_evidence(
                        root, config, launch, operator, BOOT_ID, NONCE,
                        root / "host" / "inner-verification.log",
                        cleanup_command_runner=runner,
                        cleanup_live_cgroup_root=live_cgroup_root,
                        cleanup_live_state_root=live_state_root,
                    )
                shutil.rmtree(root / "campaign")
                (root / "host" / "inner-verification.log").unlink()
                inner = write_inner_campaign(root, config_sha, launch_sha)
                inner_sha = stability.sha256_file(
                    root / "campaign" / "receipt.json"
                )
                (root / "host" / "inner-verification.log").write_text(
                    "CODESKEPTIC_STABILITY_VERIFIED "
                    f"{inner_sha} {inner['session']['id']}\n",
                    encoding="ascii",
                )
                receipt = stability.seal_operator_evidence(
                    root, config, launch, operator, BOOT_ID, NONCE,
                    root / "host" / "inner-verification.log",
                    cleanup_command_runner=runner,
                    cleanup_live_cgroup_root=live_cgroup_root,
                    cleanup_live_state_root=live_state_root,
                )
                self.assertEqual(receipt["status"], "accepted")
                host_recovery_path = (
                    root / stability.HOST_RECOVERY_INTENT_EVIDENCE_PATH
                )
                self.assertEqual(
                    receipt["authorities"]["host_recovery_intent"]["sha256"],
                    hashlib.sha256(host_recovery_path.read_bytes()).hexdigest(),
                )
                config.write_text("{ }\n", encoding="ascii")
                with self.assertRaisesRegex(
                    stability.StabilityError,
                    "inner campaign authority|differs from rederived evidence",
                ):
                    stability.verify_operator_evidence(root, config, launch, operator)

    def test_cleanup_rejects_reused_main_and_verifier_container_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / f"20260823T000000Z-{BOOT_ID}-{NONCE}"
            (root / "host").mkdir(parents=True)
            operator = base / "operator" / "run.sh"
            write_cleanup(root, operator)
            cleanup_path = root / "host" / "cleanup.json"
            cleanup = json.loads(cleanup_path.read_text(encoding="utf-8"))
            cleanup["verifier_container"]["id"] = cleanup["container"]["id"]
            cleanup_path.write_bytes(stability.canonical_document(cleanup))

            with self.assertRaisesRegex(
                stability.StabilityError, "distinct|reuse|same|identity"
            ):
                stability._validate_cleanup_record(
                    cleanup_path,
                    session_root=root,
                    boot_id=BOOT_ID,
                    session_nonce=NONCE,
                    target_user=USER,
                    target_uid=UID,
                    operator_path=operator,
                    verify_live=False,
                    **cleanup_validation_authority(),
                )

    def test_cleanup_authority_is_exact_and_resealed_mutations_fail(self) -> None:
        mutations = (
            ("extra cleanup field", lambda cleanup, intent: cleanup.update(extra=True)),
            (
                "type-confused intent digest",
                lambda cleanup, intent: cleanup["cgroup_authority"]["intent"].update(
                    sha256=0
                ),
            ),
            (
                "ExecStopPost recovery",
                lambda cleanup, intent: cleanup["completion"].update(
                    exec_stop_post_recovery=True
                ),
            ),
            (
                "foreign restored exclusive CPUs",
                lambda cleanup, intent: cleanup["cgroup_restoration"][
                    "service"
                ].update(cpuset_cpus_exclusive="0-3"),
            ),
            (
                "type-confused gate",
                lambda cleanup, intent: cleanup["gates"].update(
                    root_isolated_cpus_empty=True
                ),
            ),
            (
                "resealed intent claims",
                lambda cleanup, intent: intent.update(extra="forged"),
            ),
            (
                "resealed intent revision",
                lambda cleanup, intent: intent.update(source_revision="3" * 40),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / f"20260823T000000Z-{BOOT_ID}-{NONCE}"
                (root / "host").mkdir(parents=True)
                operator = base / "operator" / "run.sh"
                write_cleanup(root, operator)
                cleanup_path = root / "host" / "cleanup.json"
                intent_path = root / stability.CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH
                cleanup = json.loads(cleanup_path.read_text(encoding="utf-8"))
                intent = json.loads(intent_path.read_text(encoding="utf-8"))
                mutate(cleanup, intent)
                intent_data = stability.canonical_json(intent) + b"\n"
                intent_path.write_bytes(intent_data)
                if label.startswith("resealed intent"):
                    cleanup["cgroup_authority"]["intent"]["sha256"] = (
                        hashlib.sha256(intent_data).hexdigest()
                    )
                cleanup_path.write_bytes(stability.canonical_document(cleanup))
                with self.assertRaises(stability.StabilityError):
                    stability._validate_cleanup_record(
                        cleanup_path,
                        session_root=root,
                        boot_id=BOOT_ID,
                        session_nonce=NONCE,
                        target_user=USER,
                        target_uid=UID,
                        operator_path=operator,
                        verify_live=False,
                        **cleanup_validation_authority(),
                    )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / f"20260823T000000Z-{BOOT_ID}-{NONCE}"
            (root / "host").mkdir(parents=True)
            operator = base / "operator" / "run.sh"
            write_cleanup(root, operator)
            (root / stability.CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH).write_bytes(
                b'{"schema":\n'
            )
            with self.assertRaisesRegex(stability.StabilityError, "JSON.*malformed"):
                stability._validate_cleanup_record(
                    root / "host" / "cleanup.json",
                    session_root=root,
                    boot_id=BOOT_ID,
                    session_nonce=NONCE,
                    target_user=USER,
                    target_uid=UID,
                    operator_path=operator,
                    verify_live=False,
                    **cleanup_validation_authority(),
                )

    def test_cleanup_binds_exact_host_recovery_authority(self) -> None:
        mutations = (
            (
                "type-confused digest",
                lambda cleanup, intent: cleanup["host_recovery"]["intent"].update(
                    sha256=0
                ),
            ),
            (
                "wrong mode",
                lambda cleanup, intent: intent.update(mode="probe-only"),
            ),
            (
                "wrong revision",
                lambda cleanup, intent: intent["installation"].update(
                    bundle_revision="9" * 40
                ),
            ),
            (
                "installed inventory mismatch",
                lambda cleanup, intent: intent["installation"].update(
                    installed_inventory_sha256="9" * 64
                ),
            ),
            (
                "resealed alternate inventory",
                lambda cleanup, intent: intent["installation"].update(
                    bundle_inventory_sha256="9" * 64,
                    installed_inventory_sha256="9" * 64,
                ),
            ),
            (
                "wrong bundle receipt",
                lambda cleanup, intent: intent["installation"].update(
                    bundle_receipt_sha256="9" * 64
                ),
            ),
            (
                "wrong installation authority",
                lambda cleanup, intent: intent["installation"].update(
                    installation_authority_sha256="9" * 64
                ),
            ),
            (
                "wrong installation receipt",
                lambda cleanup, intent: intent["installation"].update(
                    installation_receipt_sha256="9" * 64
                ),
            ),
            (
                "wrong runtime config",
                lambda cleanup, intent: intent["installation"].update(
                    runtime_config_sha256="9" * 64
                ),
            ),
            (
                "wrong source manifest",
                lambda cleanup, intent: intent["installation"].update(
                    source_manifest_sha256="9" * 64
                ),
            ),
            (
                "wrong source tree",
                lambda cleanup, intent: intent["installation"].update(
                    source_tree_sha1="9" * 40
                ),
            ),
            (
                "wrong image archive",
                lambda cleanup, intent: intent["installation"].update(
                    image_archive_sha256="9" * 64
                ),
            ),
            (
                "wrong pinned image digest",
                lambda cleanup, intent: intent["installation"].update(
                    image_digest="sha256:" + "9" * 64
                ),
            ),
            (
                "malformed source tree",
                lambda cleanup, intent: intent["installation"].update(
                    source_tree_sha1="9" * 64
                ),
            ),
            (
                "extra marker claim",
                lambda cleanup, intent: intent.update(foreign=True),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / f"20260823T000000Z-{BOOT_ID}-{NONCE}"
                (root / "host").mkdir(parents=True)
                operator = base / "operator" / "run.sh"
                write_cleanup(root, operator)
                cleanup_path = root / "host" / "cleanup.json"
                intent_path = root / stability.HOST_RECOVERY_INTENT_EVIDENCE_PATH
                cleanup = json.loads(cleanup_path.read_text(encoding="utf-8"))
                intent = json.loads(intent_path.read_text(encoding="utf-8"))
                mutate(cleanup, intent)
                intent_data = stability.canonical_json(intent) + b"\n"
                intent_path.write_bytes(intent_data)
                if label != "type-confused digest":
                    cleanup["host_recovery"]["intent"]["sha256"] = (
                        hashlib.sha256(intent_data).hexdigest()
                    )
                cleanup_path.write_bytes(stability.canonical_document(cleanup))
                with self.assertRaises(stability.StabilityError):
                    stability._validate_cleanup_record(
                        cleanup_path,
                        session_root=root,
                        boot_id=BOOT_ID,
                        session_nonce=NONCE,
                        target_user=USER,
                        target_uid=UID,
                        operator_path=operator,
                        verify_live=False,
                        **cleanup_validation_authority(),
                    )

    def test_cleanup_live_restoration_rejects_survivors_and_cpuset_drift(self) -> None:
        mutations = (
            (
                "durable marker",
                lambda state, cgroup: (
                    state / Path(stability.CGROUP_AUTHORITY_MARKER).name
                ).write_text("survived\n", encoding="ascii"),
            ),
            (
                "temporary marker",
                lambda state, cgroup: (
                    state / Path(stability.CGROUP_AUTHORITY_MARKER_TEMP).name
                ).write_text("survived\n", encoding="ascii"),
            ),
            (
                "host recovery marker",
                lambda state, cgroup: (
                    state / Path(stability.HOST_RECOVERY_MARKER).name
                ).write_text("survived\n", encoding="ascii"),
            ),
            (
                "host recovery temporary marker",
                lambda state, cgroup: (
                    state / Path(stability.HOST_RECOVERY_MARKER_TEMP).name
                ).write_text("survived\n", encoding="ascii"),
            ),
            (
                "root isolated CPUs",
                lambda state, cgroup: (cgroup / "cpuset.cpus.isolated").write_text(
                    "0-3\n", encoding="ascii"
                ),
            ),
            (
                "service exclusive CPUs",
                lambda state, cgroup: (
                    cgroup
                    / "system.slice/codeskeptic-stability.service"
                    / "cpuset.cpus.exclusive"
                ).write_text("0-3\n", encoding="ascii"),
            ),
            (
                "system slice effective CPUs",
                lambda state, cgroup: (
                    cgroup / "system.slice" / "cpuset.cpus.effective"
                ).write_text("4-11\n", encoding="ascii"),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / f"20260823T000000Z-{BOOT_ID}-{NONCE}"
                (root / "host").mkdir(parents=True)
                operator = base / "operator" / "run.sh"
                write_cleanup(root, operator)
                cgroup_root = base / "cgroup"
                state_root = base / "state"
                write_restored_cgroup_tree(cgroup_root)
                state_root.mkdir()
                mutate(state_root, cgroup_root)
                with self.assertRaises(stability.StabilityError):
                    stability._validate_cleanup_record(
                        root / "host" / "cleanup.json",
                        session_root=root,
                        boot_id=BOOT_ID,
                        session_nonce=NONCE,
                        target_user=USER,
                        target_uid=UID,
                        operator_path=operator,
                        verify_live=True,
                        **cleanup_validation_authority(),
                        command_runner=FakeHostRunner(),
                        live_cgroup_root=cgroup_root,
                        live_state_root=state_root,
                    )


if __name__ == "__main__":
    unittest.main()
