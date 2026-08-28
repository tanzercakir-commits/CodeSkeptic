#!/usr/bin/env python3
"""Fail-closed controller and verifier for the Phase 10.9 stability gate."""

from __future__ import annotations

import argparse
import copy
import ctypes
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol

try:
    import resource
except ImportError:  # pragma: no cover - exercised by native Windows CI.
    resource = None  # type: ignore[assignment]

import run_realworld_campaign as realworld
import run_stability_fault_injection as fault_injection


POLICY_SCHEMA = "codeskeptic-stability-campaign-v2"
RUNTIME_CONFIG_SCHEMA = "codeskeptic-stability-runtime-v3"
RUNTIME_LAUNCH_SCHEMA = "codeskeptic-stability-runtime-launch-v2"
EVENT_SCHEMA = "codeskeptic-stability-event-v1"
SESSION_SCHEMA = "codeskeptic-stability-session-v3"
CYCLE_SCHEMA = "codeskeptic-stability-cycle-v1"
RECEIPT_SCHEMA = "codeskeptic-stability-receipt-v3"
ESTABLISHMENT_SCHEMA = "codeskeptic-stability-establishment-v3"
CYCLE_IDENTITY_SCHEMA = "codeskeptic-stability-cycle-identity-v1"
ACTION_IDENTITY_SCHEMA = "codeskeptic-stability-action-identity-v1"
CYCLE_PLAN_SCHEMA = "codeskeptic-stability-cycle-plan-v1"
ACTION_PLAN_SCHEMA = "codeskeptic-stability-action-plan-v1"
ACTION_RECEIPT_SCHEMA = "codeskeptic-stability-action-receipt-v1"
DETERMINISM_PROJECTION_SCHEMA = (
    "codeskeptic-stability-determinism-projection-v1"
)
DETERMINISM_BASELINE_AUTHORITY_SCHEMA = (
    "codeskeptic-determinism-baseline-authority-v1"
)
REALWORLD_PROJECTION_SCHEMA = "codeskeptic-stability-realworld-projection-v2"
REALWORLD_SHARD_PROJECTION_SCHEMA = (
    "codeskeptic-stability-realworld-shard-projection-v2"
)
BUILD_AUTHORITY_PROJECTION_SCHEMA = (
    "codeskeptic-stability-build-authority-projection-v1"
)
QUALITY_FLOOR_PROJECTION_SCHEMA = (
    "codeskeptic-stability-quality-floor-projection-v1"
)
SANITIZER_PROJECTION_SCHEMA = "codeskeptic-stability-sanitizer-projection-v1"
HOSTED_EXACT_HEAD_SCHEMA = "codeskeptic-hosted-exact-head-receipt-v1"
HOSTED_EXACT_HEAD_PROJECTION_SCHEMA = (
    "codeskeptic-stability-hosted-exact-head-projection-v1"
)
FAULT_INJECTION_PROJECTION_SCHEMA = (
    "codeskeptic-stability-fault-injection-projection-v1"
)
HOST_SNAPSHOT_SCHEMA = "codeskeptic-stability-host-snapshot-v2"
HOST_CLEANUP_SCHEMA = "codeskeptic-stability-host-cleanup-v5"
OPERATOR_RECEIPT_SCHEMA = "codeskeptic-stability-operator-receipt-v3"
CGROUP_AUTHORITY_INTENT_SCHEMA = "codeskeptic-p10-09-cgroup-authority-intent-v1"
HOST_RECOVERY_INTENT_SCHEMA = "codeskeptic-p10-09-host-recovery-intent-v1"
INSTALLATION_AUTHORITY_SCHEMA = (
    "codeskeptic-stability-installation-authority-v1"
)
INSTALLATION_RECEIPT_SCHEMA = "codeskeptic-stability-installation-v1"
BUNDLE_RECEIPT_SCHEMA = "codeskeptic-stability-staging-bundle-v1"
REQUIRED_HOSTED_GATES = [
    "build-and-test",
    "resource-budget-macos",
    "fuzz-smoke",
    "sanitizer-address",
    "sanitizer-undefined",
    "windows-native",
    "docs-structure",
    "docs-quickstart",
    "docker",
    "juliet",
]
REQUIRED_DEFAULT_RULES = [
    "memory-leak",
    "double-free",
    "use-after-free",
    "resource-leak",
    "div-by-zero",
    "null-deref",
    "int-overflow",
]
PINNED_EVIDENCE_IMAGE = (
    "localhost/codeskeptic-p10-07-evidence@sha256:"
    "3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
)
PINNED_EVIDENCE_IMAGE_DIGEST = (
    "sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
)
PINNED_EVIDENCE_IMAGE_ID = (
    "sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5"
)
PINNED_PODMAN_VERSION = "5.8.4"
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
ZERO_SHA256 = "0" * 64
REQUIRED_COMPLETE_ROUNDS = 2
REQUIRED_REALWORLD_SHARDS = 18
# Scheduling metadata remains bounded for parser/resource safety, but elapsed
# wall-clock time is not a completion authority.  P10 acceptance is derived
# from the exact projects, repetitions, cold/warm rounds, and retained results.
MAX_MATRIX_SCHEDULING_WINDOW_MINUTES = 4320
ACTION_SUPERVISION_GRACE_SECONDS = 120
REQUIRED_MATRIX_PROJECTS = ["llama-cpp", "tensorflow-lite", "shadps4"]
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_JOURNAL_EVENTS = 1_000_000
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
# The fixed topology has 823 translation units, three repetitions, and two
# cold/warm rounds: 4,938 observations.  The retained predecessor corpus used
# about 3.9 GiB/28,475 files and its largest file was about 65 MiB.  These
# limits therefore admit over 26 files per observation, eight times the
# observed maximum file size, and four times the observed aggregate while
# keeping traversal, hashing, and live disk exposure finite.
MAX_ARTIFACTS = 131_072
MAX_ARTIFACT_DIRECTORIES = 32_768
MAX_ARTIFACT_FILE_BYTES = 512 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024
# Runtime contains three mutable source/build workspaces.  It is not retained
# evidence, so its cheap live authority is actual filesystem allocation from
# one campaign baseline rather than recursively reading a hot checkout.  The
# 96-GiB observed budget is six times the complete evidence allowance and,
# when both roots share a device, detects their combined allocation plus
# unrelated host writes (which intentionally fail closed rather than being
# attributed away).  statvfs polling is detection, not a kernel quota: an
# authoritative campaign therefore runs on the dedicated host/private PID
# namespace required by its production launcher, with no sibling workloads.
# The separately preallocated emergency extent below is the hard recovery-
# space invariant if several admitted writes cross an observed threshold at
# once.
MAX_FILESYSTEM_CONSUMPTION_BYTES = 96 * 1024 * 1024 * 1024
MAX_FILESYSTEM_CONSUMPTION_INODES = 524_288
MAX_ACTION_FILE_BYTES = 8 * 1024 * 1024 * 1024
# An unlinked, controller-owned extent is held for the campaign.  It is larger
# than one RLIMIT_FSIZE-admitted write. On the first live allocation violation,
# every exact owned writer is first observably stopped and rediscovered; only
# then is this extent released and its recovery floor verified before KILL/reap
# and failure sealing. If quiescence cannot be proved, the reserve stays held.
FILESYSTEM_EMERGENCY_RESERVE_BYTES = 16 * 1024 * 1024 * 1024
MINIMUM_FILESYSTEM_FREE_BYTES = 4 * 1024 * 1024 * 1024
MINIMUM_FILESYSTEM_RECOVERY_BYTES = 8 * 1024 * 1024 * 1024
MINIMUM_FILESYSTEM_FREE_INODES = 32_768
ACTION_RESOURCE_POLL_SECONDS = 0.20
ACTION_TREE_SCAN_SECONDS = 2.0
ACTION_EXIT_CONVERGENCE_SECONDS = 0.50
FILESYSTEM_RECOVERY_TIMEOUT_SECONDS = 2.0
MAX_ACTION_LOG_BYTES = 64 * 1024 * 1024
MAXIMUM_OPEN_FDS = 4096
MAX_HOST_COREDUMP_BYTES = 16 * 1024 * 1024
MAX_HOST_COMMAND_BYTES = 1024 * 1024
MAX_HOST_COMMAND_STDERR_BYTES = 256 * 1024
MAX_HOST_CURSOR_BYTES = 4096
HOST_COMMAND_TIMEOUT_SECONDS = 30
TU_TIMEOUT_SECONDS = 300
TU_MEMORY_MIB = 4096
PERFORMANCE_SCOPE = "p10-07-representative-pre-post"
RUNTIME_CGROUP_PARENT = (
    "/system.slice/codeskeptic-stability.service/codeskeptic-p10-09"
)
RUNTIME_SYSTEM_SLICE_CGROUP = "/sys/fs/cgroup/system.slice"
RUNTIME_SERVICE_CGROUP = (
    "/sys/fs/cgroup/system.slice/codeskeptic-stability.service"
)
RUNTIME_MEASUREMENT_CGROUP = (
    "/sys/fs/cgroup/system.slice/codeskeptic-stability.service/"
    "codeskeptic-p10-09/measurement"
)
CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH = "host/cgroup-authority-intent.json"
CGROUP_AUTHORITY_MARKER = (
    "/var/lib/codeskeptic-p10-09/cgroup-authority-intent.json"
)
CGROUP_AUTHORITY_MARKER_TEMP = (
    "/var/lib/codeskeptic-p10-09/.cgroup-authority-intent.tmp"
)
HOST_RECOVERY_INTENT_EVIDENCE_PATH = "host/host-recovery-intent.json"
HOST_RECOVERY_MARKER = (
    "/var/lib/codeskeptic-p10-09/host-recovery-intent.json"
)
HOST_RECOVERY_MARKER_TEMP = (
    "/var/lib/codeskeptic-p10-09/.host-recovery-intent.tmp"
)
RUNTIME_LAUNCH_MOUNTS = [
    {"destination": "/authority", "mode": "ro"},
    {"destination": "/operator", "mode": "ro"},
    {"destination": "/config/runtime.json", "mode": "ro"},
    {"destination": "/config/runtime.json.sha256", "mode": "ro"},
    {"destination": "/launch", "mode": "ro"},
    {"destination": "/evidence", "mode": "rw"},
    {"destination": "/runtime", "mode": "rw"},
    {"destination": "/sys/fs/cgroup", "mode": "ro"},
    {
        "destination": (
            "/sys/fs/cgroup/system.slice/codeskeptic-stability.service/"
            "codeskeptic-p10-09/measurement/cgroup.procs"
        ),
        "mode": "rw",
    },
]
RUNTIME_CONTROLLER_COMMAND = [
    "/usr/bin/taskset",
    "--cpu-list",
    "4-11",
    "/usr/bin/python3",
    "-B",
    "/operator/container-entry.py",
    "run",
]
RUNTIME_VERIFIER_COMMAND = [
    "/usr/bin/taskset",
    "--cpu-list",
    "4-11",
    "/usr/bin/python3",
    "-B",
    "/operator/container-entry.py",
    "verify",
]
HOST_SNAPSHOT_COMMON_RAW_FILES = {
    "coredumpctl": "coredumpctl.jsonl",
    "system_helpers": "system-helpers.txt",
    "user_launchers": "user-launchers.txt",
    "failed_system": "failed-system.txt",
    "failed_user": "failed-user.txt",
    "user_socket": "user-socket.properties",
}
HOST_SNAPSHOT_PRE_RAW_FILES = {
    **HOST_SNAPSHOT_COMMON_RAW_FILES,
    "system_journal": "system-journal.cursor",
    "user_journal": "user-journal.cursor",
}
HOST_SNAPSHOT_POST_RAW_FILES = {
    **HOST_SNAPSHOT_COMMON_RAW_FILES,
    "system_journal_sync": "system-journal-sync.txt",
    "user_journal_sync": "user-journal-sync.txt",
    "system_journal_anchor": "system-journal-anchor.jsonl",
    "user_journal_anchor": "user-journal-anchor.jsonl",
    "system_journal": "system-journal.jsonl",
    "user_journal": "user-journal.jsonl",
}
SYSTEMD_LIFECYCLE_MESSAGE_IDS = (
    "7d4958e842da4a758f6c1cdc7b36dcc5",
    "39f53479d3a045ac8e11786248231fbf",
    "be02cf6855d2428ba40df7e9d022f03d",
)
SYSTEMD_COREDUMP_MESSAGE_ID = "fc2e22bc6ee647b6b90729ab34a250b1"
JOURNAL_OUTPUT_FIELDS = "MESSAGE_ID,UNIT,USER_UNIT,_BOOT_ID,COREDUMP_PID"
HOST_SOCKET_PROPERTIES = [
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "Result",
    "Job",
    "NAccepted",
    "Listen",
]


class StabilityError(RuntimeError):
    """The stability evidence is unavailable or violates its fixed policy."""


def _load_private_determinism_authority() -> types.ModuleType:
    """Load exact sibling verifier bytes without consulting sys.modules."""

    filename = "run_determinism_qualification.py"
    path = Path(__file__).resolve().with_name(filename)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StabilityError(
            "cannot open private determinism authority"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= 16 << 20
        ):
            raise StabilityError(
                "private determinism authority is not a bounded regular file"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise StabilityError(
                    "private determinism authority was truncated"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise StabilityError(
                "private determinism authority grew during loading"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        pathname = path.stat(follow_symlinks=False)
    except OSError as error:
        raise StabilityError(
            "cannot recheck private determinism authority"
        ) from error

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if (
        identity(before) != identity(after)
        or identity(after) != identity(pathname)
    ):
        raise StabilityError(
            "private determinism authority changed during loading"
        )
    try:
        code = compile(
            b"".join(chunks), os.fspath(path), "exec", dont_inherit=True
        )
    except (SyntaxError, ValueError) as error:
        raise StabilityError(
            "private determinism authority cannot be compiled"
        ) from error
    module = types.ModuleType("_codeskeptic_private_determinism_qualification")
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    try:
        exec(code, module.__dict__)
    except Exception as error:
        raise StabilityError(
            "private determinism authority cannot be loaded"
        ) from error
    return module


class _ActionTaskSnapshotChanged(StabilityError):
    """A TGID's task set changed while a fail-closed snapshot was read."""


class _ActionTaskInventoryUnavailable(_ActionTaskSnapshotChanged):
    """The kernel exposes a TGID identity but not its thread inventory."""


class StabilityClock(Protocol):
    def monotonic_ns(self) -> int: ...
    def boottime_ns(self) -> int: ...
    def utc_now(self) -> dt.datetime: ...
    def boot_id(self) -> str: ...
    def sleep(self, seconds: float) -> None: ...


class CommandHandle(Protocol):
    pid: int

    def wait(self, timeout_seconds: float) -> int | None: ...
    def terminate_group(self) -> None: ...
    def kill_group(self) -> None: ...
    def group_alive(self) -> bool: ...
    def wait_group(self, timeout_seconds: float) -> bool: ...
    def unexpected_pids(self) -> list[int]: ...
    def terminate_unexpected(self) -> None: ...
    def kill_unexpected(self) -> None: ...
    def wait_unexpected(self, timeout_seconds: float) -> bool: ...


class CommandRunner(Protocol):
    def start(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        stdout_path: Path,
        stderr_path: Path,
    ) -> CommandHandle: ...


class LinuxClock:
    """Linux clock authority; wall time is metadata, never duration authority."""

    BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def boottime_ns(self) -> int:
        if not hasattr(time, "CLOCK_BOOTTIME"):
            raise StabilityError("CLOCK_BOOTTIME is unavailable")
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

    def utc_now(self) -> dt.datetime:
        return dt.datetime.now(dt.timezone.utc)

    def boot_id(self) -> str:
        try:
            value = _read_regular_bytes(self.BOOT_ID_PATH, 128).decode(
                "ascii", errors="strict"
            ).strip()
        except UnicodeDecodeError as error:
            raise StabilityError("Linux boot identity is not ASCII") from error
        if BOOT_ID.fullmatch(value) is None:
            raise StabilityError("Linux boot identity is malformed")
        return value

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _action_process_record(
    pid: int,
) -> tuple[int, int, int, str] | None:
    try:
        fields = (
            (Path("/proc") / str(pid) / "stat")
            .read_text(encoding="ascii")
            .rsplit(")", 1)[1]
            .strip()
            .split()
        )
        state = fields[0]
        if len(state) != 1:
            return None
        return (
            int(fields[1]),  # parent PID
            int(fields[2]),  # process group ID
            int(fields[19]),  # kernel start time
            state,
        )
    except (
        FileNotFoundError, OSError, UnicodeDecodeError,
        ValueError, IndexError,
    ):
        return None


_DEAD_ACTION_TASK_STATES = frozenset({"Z", "X", "x"})
_QUIESCED_ACTION_TASK_STATES = frozenset({"T", "t", "Z", "X", "x"})


def _action_task_states(pid: int, start_time: int) -> dict[int, str] | None:
    """Return one stable, exact-thread snapshot for a TGID identity."""

    before = _action_process_record(pid)
    if before is None or before[2] != start_time:
        return None
    task_root = Path("/proc") / str(pid) / "task"
    try:
        before_names = {
            name for name in os.listdir(task_root)
            if name.isascii() and name.isdigit()
        }
    except FileNotFoundError:
        after = _action_process_record(pid)
        if after is None or after[2] != start_time:
            return None
        raise _ActionTaskInventoryUnavailable(
            f"owned action TGID {pid} task directory changed"
        )
    except OSError as error:
        raise StabilityError(
            f"cannot enumerate owned action TGID {pid} tasks: {error}"
        ) from error
    if not before_names or str(pid) not in before_names:
        raise _ActionTaskInventoryUnavailable(
            f"owned action TGID {pid} task inventory is incomplete"
        )

    states: dict[int, str] = {}
    for name in before_names:
        path = task_root / name / "stat"
        try:
            fields = (
                path.read_text(encoding="ascii")
                .rsplit(")", 1)[1]
                .strip()
                .split()
            )
            state = fields[0]
            if len(state) != 1:
                raise ValueError("malformed task state")
        except FileNotFoundError as error:
            raise _ActionTaskSnapshotChanged(
                f"owned action TGID {pid} task inventory changed"
            ) from error
        except (OSError, UnicodeDecodeError, ValueError, IndexError) as error:
            raise StabilityError(
                f"cannot inspect owned action task {pid}/{name}: {error}"
            ) from error
        states[int(name)] = state

    try:
        after_names = {
            name for name in os.listdir(task_root)
            if name.isascii() and name.isdigit()
        }
    except FileNotFoundError as error:
        after = _action_process_record(pid)
        if after is None or after[2] != start_time:
            return None
        raise _ActionTaskInventoryUnavailable(
            f"owned action TGID {pid} task directory changed"
        ) from error
    except OSError as error:
        raise StabilityError(
            f"cannot re-enumerate owned action TGID {pid} tasks: {error}"
        ) from error
    after = _action_process_record(pid)
    if after is None or after[2] != start_time:
        return None
    if before_names != after_names:
        raise _ActionTaskSnapshotChanged(
            f"owned action TGID {pid} task inventory changed"
        )
    return states


def _action_tgid_has_live_tasks(pid: int, start_time: int) -> bool:
    try:
        states = _action_task_states(pid, start_time)
    except _ActionTaskSnapshotChanged:
        return True
    return states is not None and any(
        state not in _DEAD_ACTION_TASK_STATES for state in states.values()
    )


def _action_process_table() -> dict[int, tuple[int, int, int, str]]:
    try:
        names = os.listdir("/proc")
    except OSError as error:
        raise StabilityError(f"cannot enumerate PID namespace: {error}") from error
    result: dict[int, tuple[int, int, int, str]] = {}
    for name in names:
        if not name.isascii() or not name.isdigit():
            continue
        pid = int(name)
        record = _action_process_record(pid)
        if record is not None:
            result[pid] = record
    return result


def _enable_action_subreaper() -> None:
    if not sys.platform.startswith("linux") or not Path("/proc/self/stat").is_file():
        raise StabilityError("action descendant containment requires Linux /proc")
    libc = ctypes.CDLL(None, use_errno=True)
    enabled = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0:  # GET_CHILD_SUBREAPER
        raise StabilityError("cannot inspect action subreaper state")
    if enabled.value == 0 and libc.prctl(36, 1, 0, 0, 0) != 0:  # SET_CHILD_SUBREAPER
        raise StabilityError("cannot enable action subreaper containment")
    enabled = ctypes.c_int()
    if (
        libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0
        or enabled.value != 1
    ):
        raise StabilityError("action subreaper containment is not active")


def _direct_action_children(
    controller_pid: int, table: dict[int, tuple[int, int, int, str]] | None = None,
) -> dict[int, int]:
    records = _action_process_table() if table is None else table
    return {
        pid: record[2]
        for pid, record in records.items()
        if record[0] == controller_pid
    }


def _controller_action_records(
    controller_pid: int,
) -> dict[int, tuple[int, int, int, str]]:
    table = _action_process_table()
    children: dict[int, list[int]] = {}
    for pid, record in table.items():
        children.setdefault(record[0], []).append(pid)
    result: dict[int, tuple[int, int, int, str]] = {}
    pending = list(children.get(controller_pid, []))
    while pending:
        pid = pending.pop()
        if pid in result:
            continue
        record = table.get(pid)
        if record is None:
            continue
        result[pid] = record
        pending.extend(children.get(pid, []))
    return result


def _signal_action_pid(
    pid: int, start_time: int, signal_number: int,
) -> None:
    record = _action_process_record(pid)
    if record is None or record[2] != start_time:
        return
    try:
        os.kill(pid, signal_number)
    except ProcessLookupError:
        return
    except PermissionError as error:
        raise StabilityError(
            f"cannot signal owned action PID {pid}: {error}"
        ) from error


def _cleanup_adopted_action_children(controller_pid: int) -> None:
    """Converge a prelaunch-empty controller's adopted children to ECHILD."""

    deadline = time.monotonic() + 5.0
    while True:
        records = _controller_action_records(controller_pid)
        live = False
        for pid, record in records.items():
            try:
                task_states = _action_task_states(pid, record[2])
            except _ActionTaskInventoryUnavailable:
                # Exact TGID ownership is still available. Kill the whole
                # thread group and rediscover any racing children after they
                # are adopted by this controller subreaper.
                live = True
                _signal_action_pid(pid, record[2], signal.SIGKILL)
                continue
            except _ActionTaskSnapshotChanged:
                live = True
                _signal_action_pid(pid, record[2], signal.SIGSTOP)
                continue
            if task_states is None:
                continue
            active_states = [
                state for state in task_states.values()
                if state not in _DEAD_ACTION_TASK_STATES
            ]
            if not active_states:
                if record[0] == controller_pid:
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                    except OSError as error:
                        raise StabilityError(
                            f"cannot reap adopted action PID {pid}: {error}"
                        ) from error
                continue
            live = True
            if all(state in {"T", "t"} for state in active_states):
                _signal_action_pid(pid, record[2], signal.SIGSTOP)
                _signal_action_pid(pid, record[2], signal.SIGKILL)
            else:
                _signal_action_pid(pid, record[2], signal.SIGSTOP)
        if not records:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            except OSError as error:
                raise StabilityError(
                    f"cannot prove adopted-action ECHILD: {error}"
                ) from error
            if pid > 0:
                continue
        if time.monotonic() >= deadline:
            raise StabilityError(
                "adopted action descendants did not converge to ECHILD"
            )
        if not live:
            time.sleep(0.01)
        else:
            time.sleep(0.01)


def _directory_device(path: Path, label: str) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StabilityError(f"cannot inspect {label} root {path}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise StabilityError(f"{label} root is not a real directory")
    return metadata.st_dev, metadata.st_ino


def _statvfs_available(
    probe: Callable[[Path], Any], path: Path,
) -> tuple[int, int | None]:
    try:
        snapshot = probe(path)
        blocks = snapshot.f_bavail
        fragment_size = snapshot.f_frsize
        files = getattr(snapshot, "f_files", 0)
        available_files = snapshot.f_favail
    except Exception as error:
        raise StabilityError(
            f"cannot inspect action filesystem capacity at {path}: {error}"
        ) from error
    if (
        type(blocks) is not int
        or blocks < 0
        or type(fragment_size) is not int
        or fragment_size < 1
        or type(available_files) is not int
        or available_files < 0
    ):
        raise StabilityError("action filesystem capacity is malformed")
    # Btrfs reports f_files=f_favail=0 because it has no fixed inode pool.
    inode_availability = (
        available_files if type(files) is int and files > 0 else None
    )
    return blocks * fragment_size, inode_availability


class _FilesystemEmergencyReserve:
    """Hold invisible allocated extents so fail-closed sealing can recover."""

    def __init__(self, roots: list[Path]) -> None:
        if not hasattr(os, "posix_fallocate"):
            raise StabilityError("filesystem emergency reservation is unavailable")
        self._descriptors: list[int] = []
        self._reserved_bytes: dict[int, int] = {}
        self._released = False
        devices: set[int] = set()
        try:
            for root in roots:
                device, _inode = _directory_device(root, "action storage")
                if device in devices:
                    continue
                devices.add(device)
                descriptor = self._open_unlinked(root)
                try:
                    os.posix_fallocate(
                        descriptor, 0, FILESYSTEM_EMERGENCY_RESERVE_BYTES
                    )
                    os.fsync(descriptor)
                    allocated = os.fstat(descriptor).st_blocks * 512
                    if allocated < FILESYSTEM_EMERGENCY_RESERVE_BYTES:
                        raise StabilityError(
                            "filesystem did not allocate the emergency reserve"
                        )
                except Exception as allocation_error:
                    try:
                        os.close(descriptor)
                    except OSError as close_error:
                        raise StabilityError(
                            "filesystem emergency reserve allocation failed; "
                            f"descriptor cleanup failed: {close_error}"
                        ) from allocation_error
                    raise
                self._descriptors.append(descriptor)
                self._reserved_bytes[device] = FILESYSTEM_EMERGENCY_RESERVE_BYTES
        except Exception as error:
            try:
                self.release()
            except StabilityError as cleanup_error:
                raise StabilityError(
                    f"cannot allocate filesystem emergency reserve: {error}; "
                    f"cleanup failed: {cleanup_error}"
                ) from cleanup_error
            if isinstance(error, StabilityError):
                raise
            raise StabilityError(
                f"cannot allocate filesystem emergency reserve: {error}"
            ) from error

    @staticmethod
    def _open_unlinked(root: Path) -> int:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        path = root / (
            f".codeskeptic-emergency-reserve-{os.getpid()}-"
            f"{secrets.token_hex(16)}"
        )
        try:
            descriptor = os.open(path, flags, 0o000)
        except OSError as error:
            raise StabilityError(
                f"cannot create filesystem emergency reserve in {root}: {error}"
            ) from error
        try:
            path.unlink()
        except OSError as error:
            close_error: OSError | None = None
            try:
                os.close(descriptor)
            except OSError as descriptor_error:
                close_error = descriptor_error
            try:
                path.unlink()
            except OSError:
                pass
            if close_error is not None:
                raise StabilityError(
                    f"cannot hide filesystem emergency reserve in {root}: "
                    f"{error}; descriptor cleanup failed: {close_error}"
                ) from close_error
            raise StabilityError(
                f"cannot hide filesystem emergency reserve in {root}: {error}"
            ) from error
        return descriptor

    @property
    def released(self) -> bool:
        return self._released

    @property
    def reserved_bytes(self) -> dict[int, int]:
        return dict(self._reserved_bytes)

    def release(self, *, best_effort: bool = False) -> None:
        if self._released:
            return
        descriptors, self._descriptors = self._descriptors, []
        errors: list[str] = []
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(f"fd {descriptor}: {error}")
        if errors:
            if not best_effort:
                raise StabilityError(
                    "cannot release filesystem emergency reserve: "
                    + "; ".join(errors)
                )
            return
        self._released = True


def _scan_live_evidence(
    root: Path, expected_root_identity: tuple[int, int] | None = None,
) -> None:
    """Bound a changing evidence tree without following renamed symlinks."""

    file_count = 0
    directory_count = 1
    byte_count = 0
    pending = [root]
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    while pending:
        current = pending.pop()
        try:
            descriptor = os.open(current, directory_flags)
        except FileNotFoundError:
            if current == root:
                raise StabilityError("evidence root disappeared during action")
            continue
        except OSError as error:
            raise StabilityError(
                f"cannot open live evidence directory {current}: {error}"
            ) from error
        try:
            if current == root and expected_root_identity is not None:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != expected_root_identity:
                    raise StabilityError(
                        "evidence root identity changed during live traversal"
                    )
            iterator = os.scandir(descriptor)
            try:
                for entry in iterator:
                    path = current / entry.name
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    except OSError as error:
                        raise StabilityError(
                            f"cannot inspect live evidence path {path}: {error}"
                        ) from error
                    if stat.S_ISDIR(metadata.st_mode):
                        directory_count += 1
                        if directory_count > MAX_ARTIFACT_DIRECTORIES:
                            raise StabilityError(
                                "live evidence directory count exceeds the fixed limit"
                            )
                        pending.append(path)
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        raise StabilityError(
                            f"live evidence path is not a regular file: {path}"
                        )
                    file_count += 1
                    if file_count > MAX_ARTIFACTS:
                        raise StabilityError(
                            "live evidence file count exceeds the fixed limit"
                        )
                    if metadata.st_size > MAX_ARTIFACT_FILE_BYTES:
                        raise StabilityError(
                            f"live evidence file exceeds the fixed size limit: {path}"
                        )
                    allocated = max(
                        metadata.st_size,
                        max(0, getattr(metadata, "st_blocks", 0)) * 512,
                    )
                    byte_count += allocated
                    if byte_count > MAX_ARTIFACT_BYTES:
                        raise StabilityError(
                            "live evidence byte count exceeds the fixed limit"
                        )
            finally:
                iterator.close()
        finally:
            os.close(descriptor)


class _ActionDiskMonitor:
    """Cheap allocation guard plus a slower exact evidence-tree guard."""

    def __init__(
        self,
        evidence_root: Path,
        runtime_root: Path,
        filesystem_probe: Callable[[Path], Any],
        reserve: _FilesystemEmergencyReserve,
    ) -> None:
        self._roots = [
            (evidence_root, "evidence", _directory_device(evidence_root, "evidence")),
            (runtime_root, "runtime", _directory_device(runtime_root, "runtime")),
        ]
        self._evidence_root = evidence_root
        self._evidence_identity = self._roots[0][2]
        self._probe = filesystem_probe
        self._reserve = reserve
        self._next_tree_scan = 0.0
        self._released = False
        representatives: dict[int, Path] = {}
        for path, _label, (device, _inode) in self._roots:
            representatives.setdefault(device, path)
        self._representatives = representatives
        self._baseline: dict[int, tuple[int, int | None]] = {}
        self.check(force_tree=True, establish_baseline=True)

    def _check_root_identities(self) -> None:
        for path, label, expected in self._roots:
            if _directory_device(path, label) != expected:
                raise StabilityError(f"{label} root identity changed during action")

    def _check_filesystems(self, *, establish_baseline: bool) -> None:
        for device, path in self._representatives.items():
            available, available_inodes = _statvfs_available(self._probe, path)
            if available < MINIMUM_FILESYSTEM_FREE_BYTES:
                raise StabilityError(
                    f"action filesystem free-space reserve violated at {path}"
                )
            if (
                available_inodes is not None
                and available_inodes < MINIMUM_FILESYSTEM_FREE_INODES
            ):
                raise StabilityError(
                    f"action filesystem free-inode reserve violated at {path}"
                )
            if establish_baseline:
                self._baseline[device] = (available, available_inodes)
                continue
            baseline_bytes, baseline_inodes = self._baseline[device]
            if baseline_bytes - available > MAX_FILESYSTEM_CONSUMPTION_BYTES:
                raise StabilityError(
                    f"action filesystem allocation budget exceeded at {path}"
                )
            if (
                baseline_inodes is not None
                and available_inodes is not None
                and baseline_inodes - available_inodes
                > MAX_FILESYSTEM_CONSUMPTION_INODES
            ):
                raise StabilityError(
                    f"action filesystem inode budget exceeded at {path}"
                )

    def check(
        self, *, force_tree: bool = False, establish_baseline: bool = False,
    ) -> None:
        if self._released:
            return
        self._check_root_identities()
        self._check_filesystems(establish_baseline=establish_baseline)
        now = time.monotonic()
        if force_tree or now >= self._next_tree_scan:
            _scan_live_evidence(
                self._evidence_root, self._evidence_identity
            )
            self._next_tree_scan = now + ACTION_TREE_SCAN_SECONDS

    def release_reserve(self) -> None:
        if self._released:
            return
        self._reserve.release()
        self._released = True
        deadline = time.monotonic() + FILESYSTEM_RECOVERY_TIMEOUT_SECONDS
        while True:
            after = {
                device: _statvfs_available(self._probe, path)[0]
                for device, path in self._representatives.items()
            }
            pending = [
                device
                for device in self._representatives
                if after[device] < MINIMUM_FILESYSTEM_RECOVERY_BYTES
            ]
            if not pending:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                paths = ", ".join(
                    self._representatives[device].as_posix()
                    for device in pending
                )
                raise StabilityError(
                    "filesystem emergency reserve release did not restore "
                    f"the minimum recovery floor at {paths}"
                )
            time.sleep(min(0.05, remaining))


def _apply_action_file_limit() -> None:
    if resource is None:
        os._exit(125)
    _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    effective = MAX_ACTION_FILE_BYTES
    if hard != resource.RLIM_INFINITY:
        effective = min(effective, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (effective, effective))


class SubprocessCommandHandle:
    """POSIX process-group handle with an explicitly reaped leader."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        controller_pid: int,
        leader_start_time: int,
        disk_monitor: _ActionDiskMonitor,
    ) -> None:
        self.process = process
        self.pid = process.pid
        self._controller_pid = controller_pid
        self._leader_start_time = leader_start_time
        self._output_error: str | None = None
        self._output_lock = threading.Lock()
        self._output_threads: list[threading.Thread] = []
        self._pending_outputs: list[tuple[Any, int, str]] = []
        self._disk_monitor = disk_monitor
        self._resource_error: str | None = None
        self._reserve_release_permitted = True

    def start_output_pumps(
        self, outputs: list[tuple[Any, int, str]],
    ) -> None:
        if self._pending_outputs or self._output_threads:
            raise StabilityError("action output pumps are already configured")
        self._pending_outputs = list(outputs)
        for pipe, descriptor, label in outputs:
            thread = threading.Thread(
                target=self._pump_output,
                args=(pipe, descriptor, label),
                name=f"codeskeptic-{label}-{self.pid}",
                daemon=True,
            )
            thread.start()
            self._pending_outputs.remove((pipe, descriptor, label))
            self._output_threads.append(thread)

    def close_pending_outputs(self) -> list[str]:
        pending, self._pending_outputs = self._pending_outputs, []
        errors: list[str] = []
        for pipe, descriptor, label in pending:
            try:
                pipe.close()
            except BaseException as error:
                errors.append(f"{label} pipe close: {error}")
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(f"{label} log close: {error}")
        return errors

    def retain_disk_reserve(self) -> None:
        self._reserve_release_permitted = False

    def _record_output_error(self, message: str) -> None:
        with self._output_lock:
            if self._output_error is None:
                self._output_error = message

    def quiesce_owned(self) -> None:
        """Stop every exact owned writer before exposing recovery extents."""

        deadline = time.monotonic() + 5.0
        while True:
            records = self._owned_records()
            leader = self._leader_record()
            if leader is not None:
                records[self.pid] = leader
            unstopped = False
            for pid, record in records.items():
                try:
                    task_states = _action_task_states(pid, record[2])
                except _ActionTaskInventoryUnavailable as error:
                    raise StabilityError(
                        "owned action task inventory is unavailable; "
                        "filesystem reserve remains held"
                    ) from error
                except _ActionTaskSnapshotChanged:
                    unstopped = True
                    self._signal_exact(pid, record[2], signal.SIGSTOP)
                    continue
                if task_states is None:
                    continue
                if any(
                    state not in _QUIESCED_ACTION_TASK_STATES
                    for state in task_states.values()
                ):
                    unstopped = True
                    self._signal_exact(pid, record[2], signal.SIGSTOP)
            if not unstopped:
                # A second fresh discovery closes the fork-before-SIGSTOP
                # window. Every process found by the first scan is already
                # stopped, so no later fork can occur between these scans.
                confirmation = self._owned_records()
                confirmed_leader = self._leader_record()
                if confirmed_leader is not None:
                    confirmation[self.pid] = confirmed_leader
                confirmed = True
                for pid, record in confirmation.items():
                    try:
                        task_states = _action_task_states(pid, record[2])
                    except _ActionTaskInventoryUnavailable as error:
                        raise StabilityError(
                            "owned action task inventory is unavailable; "
                            "filesystem reserve remains held"
                        ) from error
                    except _ActionTaskSnapshotChanged:
                        confirmed = False
                        break
                    if task_states is not None and any(
                        state not in _QUIESCED_ACTION_TASK_STATES
                        for state in task_states.values()
                    ):
                        confirmed = False
                        break
                if confirmed:
                    return
            if time.monotonic() >= deadline:
                raise StabilityError(
                    "owned action writers did not quiesce before reserve release"
                )
            time.sleep(0.01)

    def _record_resource_error(self, error: StabilityError) -> None:
        if self._resource_error is not None:
            return
        message = str(error)
        if not self._reserve_release_permitted:
            self._resource_error = message
            return
        try:
            self.quiesce_owned()
        except StabilityError as quiescence_error:
            # Keep the reserve allocated if writers are not proven stopped.
            # The ordinary exact cleanup path will release it only after reap.
            self._resource_error = (
                f"{message}; cannot quiesce writers before filesystem "
                f"recovery: {quiescence_error}"
            )
            return
        try:
            # The unlinked extent is recovery authority, not ordinary spare
            # capacity. Return it only after all action writers are stopped.
            self.release_disk_reserve()
        except StabilityError as release_error:
            message = (
                f"{message}; filesystem recovery reserve release failed: "
                f"{release_error}"
            )
        self._resource_error = message

    def _pump_output(self, pipe: Any, descriptor: int, label: str) -> None:
        total = 0
        try:
            while True:
                block = os.read(pipe.fileno(), 64 * 1024)
                if not block:
                    break
                available = MAX_ACTION_LOG_BYTES - total
                if available < len(block):
                    if available > 0:
                        _write_descriptor_all(descriptor, block[:available])
                        total += available
                    self._record_output_error(
                        f"action {label} output exceeds its size limit"
                    )
                    self.kill_group()
                    break
                _write_descriptor_all(descriptor, block)
                total += len(block)
            os.fsync(descriptor)
        except Exception as error:
            self._record_output_error(
                f"cannot stream bounded action {label} output: {error}"
            )
            self.kill_group()
        finally:
            try:
                pipe.close()
            finally:
                os.close(descriptor)

    def wait(self, timeout_seconds: float) -> int | None:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        result: int | None = None
        while result is None:
            try:
                self._disk_monitor.check()
            except StabilityError as error:
                self._record_resource_error(error)
                self.kill_group()
                self.kill_unexpected()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    result = self.process.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    return None
                break
            try:
                result = self.process.wait(
                    timeout=min(ACTION_RESOURCE_POLL_SECONDS, remaining)
                )
            except subprocess.TimeoutExpired:
                continue
        try:
            self._disk_monitor.check(force_tree=True)
        except StabilityError as error:
            self._record_resource_error(error)
            self.kill_group()
            self.kill_unexpected()
        if any(thread.is_alive() for thread in self._output_threads) and (
            self.group_alive() or self.unexpected_pids()
        ):
            # Surface the reaped leader to the supervisor immediately.  The
            # still-open pipe is itself evidence of a live descendant; cleanup
            # below owns and joins it.
            return result
        for thread in self._output_threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            thread.join(remaining)
        if any(thread.is_alive() for thread in self._output_threads):
            return None
        return result

    def output_error(self) -> str | None:
        with self._output_lock:
            return self._output_error

    def resource_error(self) -> str | None:
        return self._resource_error

    def release_disk_reserve(self) -> None:
        self._disk_monitor.release_reserve()

    @staticmethod
    def _signal_exact(
        pid: int, start_time: int, signal_number: int,
    ) -> None:
        # Revalidate only this PID. A full namespace scan for every signal
        # turns cleanup into O(descendants * namespace_size) and can exhaust
        # the deadline under a fork-heavy failure.
        _signal_action_pid(pid, start_time, signal_number)

    def _owned_records(
        self,
    ) -> dict[int, tuple[int, int, int, str]]:
        table = _action_process_table()
        children: dict[int, list[int]] = {}
        for pid, record in table.items():
            children.setdefault(record[0], []).append(pid)
        roots: list[int] = []
        leader = table.get(self.pid)
        if leader is not None and leader[2] == self._leader_start_time:
            roots.extend(children.get(self.pid, []))
        roots.extend(
            pid
            for pid, record in table.items()
            if record[0] == self._controller_pid and pid != self.pid
        )
        result: dict[int, tuple[int, int, int, str]] = {}
        pending = roots
        while pending:
            pid = pending.pop()
            if pid in result or pid == self.pid:
                continue
            record = table.get(pid)
            if record is None:
                continue
            result[pid] = record
            pending.extend(children.get(pid, []))
        return result

    def _leader_record(
        self,
    ) -> tuple[int, int, int, str] | None:
        record = _action_process_record(self.pid)
        if record is None or record[2] != self._leader_start_time:
            return None
        return record

    def _signal_group(self, signal_number: int) -> None:
        leader = self._leader_record()
        if leader is not None:
            self._signal_exact(self.pid, self._leader_start_time, signal_number)
        for pid, record in self._owned_records().items():
            if record[1] == self.pid:
                self._signal_exact(pid, record[2], signal_number)

    def terminate_group(self) -> None:
        self._signal_group(signal.SIGTERM)

    def kill_group(self) -> None:
        self._signal_group(signal.SIGKILL)

    def group_alive(self) -> bool:
        leader = self._leader_record()
        if (
            leader is not None
            and leader[1] == self.pid
            and _action_tgid_has_live_tasks(self.pid, self._leader_start_time)
        ):
            return True
        return any(
            record[1] == self.pid
            and _action_tgid_has_live_tasks(pid, record[2])
            for pid, record in self._owned_records().items()
        )

    def wait_group(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while self.group_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.05, remaining))
        for thread in self._output_threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            thread.join(remaining)
        return not any(thread.is_alive() for thread in self._output_threads)

    def unexpected_pids(self) -> list[int]:
        records = self._owned_records()
        for pid, record in records.items():
            if record[0] != self._controller_pid or record[3] != "Z":
                continue
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            except OSError as error:
                raise StabilityError(
                    f"cannot reap unexpected PID {pid}: {error}"
                ) from error
        return sorted(self._owned_records())

    def _reap_controller_children_to_echild(self) -> bool:
        if self.process.returncode is None:
            return False
        while True:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return True
            except OSError as error:
                raise StabilityError(
                    f"cannot converge action child reaping: {error}"
                ) from error
            if pid == 0:
                return False

    def _signal_unexpected(self, signal_number: int) -> None:
        for pid, record in self._owned_records().items():
            self._signal_exact(pid, record[2], signal_number)

    def terminate_unexpected(self) -> None:
        self._signal_unexpected(signal.SIGTERM)

    def kill_unexpected(self) -> None:
        deadline = time.monotonic() + 5.0
        while True:
            records = self._owned_records()
            live = False
            for pid, record in records.items():
                try:
                    task_states = _action_task_states(pid, record[2])
                except _ActionTaskInventoryUnavailable:
                    # Exact TGID ownership remains authoritative even when
                    # Linux hides /proc/<tgid>/task after main-thread exit.
                    # SIGKILL the group, then rediscover adopted racing forks.
                    live = True
                    self._signal_exact(pid, record[2], signal.SIGKILL)
                    continue
                except _ActionTaskSnapshotChanged:
                    live = True
                    self._signal_exact(pid, record[2], signal.SIGSTOP)
                    continue
                if task_states is None:
                    continue
                active_states = [
                    state for state in task_states.values()
                    if state not in _DEAD_ACTION_TASK_STATES
                ]
                if not active_states:
                    continue
                live = True
                if all(state in {"T", "t"} for state in active_states):
                    self._signal_exact(pid, record[2], signal.SIGSTOP)
                    self._signal_exact(pid, record[2], signal.SIGKILL)
                else:
                    self._signal_exact(pid, record[2], signal.SIGSTOP)
            if not live:
                return
            if time.monotonic() >= deadline:
                raise StabilityError(
                    "owned action descendants did not quiesce during SIGKILL"
                )
            time.sleep(0.01)

    def wait_unexpected(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while True:
            unexpected = self.unexpected_pids()
            if not unexpected and self._reap_controller_children_to_echild():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.05, remaining))


def _open_exclusive_log(path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        return os.open(path, flags, 0o600)
    except OSError as error:
        raise StabilityError(f"cannot create action log {path}: {error}") from error


def _write_descriptor_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise StabilityError("short write to bounded action log")
        view = view[written:]


class SubprocessCommandRunner:
    """Production runner: every authority executes in a fresh POSIX session."""

    def __init__(
        self,
        *,
        evidence_root: Path,
        runtime_root: Path,
        filesystem_probe: Callable[[Path], Any] | None = None,
    ) -> None:
        self.last_handle: SubprocessCommandHandle | None = None
        self._closed = False
        probe = os.statvfs if filesystem_probe is None else filesystem_probe
        if not callable(probe):
            raise StabilityError("action filesystem probe is unavailable")
        self._reserve = _FilesystemEmergencyReserve(
            [evidence_root, runtime_root]
        )
        try:
            self._disk_monitor = _ActionDiskMonitor(
                evidence_root, runtime_root, probe, self._reserve
            )
        except Exception:
            self._reserve.release()
            raise

    def close(self) -> None:
        if self._closed:
            return
        handle = self.last_handle
        if handle is not None and (
            not handle.wait_group(ACTION_EXIT_CONVERGENCE_SECONDS)
            or not _action_process_tree_clean(handle)
        ):
            raise StabilityError(
                "cannot release filesystem reserve with an active action owner"
            )
        controller_pid = os.getpid()
        if _direct_action_children(controller_pid):
            raise StabilityError(
                "cannot release filesystem reserve with adopted action children"
            )
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            pass
        except OSError as error:
            raise StabilityError(
                f"cannot prove ECHILD before runner close: {error}"
            ) from error
        else:
            raise StabilityError(
                "cannot release filesystem reserve before controller ECHILD: "
                f"unexpected PID {pid}"
            )
        self._disk_monitor.release_reserve()
        self._closed = True

    def start(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        stdout_path: Path,
        stderr_path: Path,
    ) -> SubprocessCommandHandle:
        if self._closed or self._reserve.released:
            raise StabilityError("action runner is already closed")
        self._disk_monitor.check(force_tree=True)
        _enable_action_subreaper()
        try:
            task_ids = {
                name for name in os.listdir("/proc/self/task")
                if name.isascii() and name.isdigit()
            }
        except OSError as error:
            raise StabilityError(
                f"cannot verify dedicated action controller threads: {error}"
            ) from error
        if task_ids != {str(os.getpid())}:
            raise StabilityError("action controller is not a dedicated single thread")
        controller_pid = os.getpid()
        if _direct_action_children(controller_pid):
            raise StabilityError(
                "action controller already owns a child process before launch"
            )
        stdout_descriptor = _open_exclusive_log(stdout_path)
        try:
            stderr_descriptor = _open_exclusive_log(stderr_path)
        except Exception:
            os.close(stdout_descriptor)
            raise
        try:
            process = subprocess.Popen(
                argv,
                cwd=os.fspath(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
                preexec_fn=_apply_action_file_limit,
            )
        except Exception as error:
            os.close(stdout_descriptor)
            os.close(stderr_descriptor)
            raise StabilityError(f"cannot start action subprocess: {error}") from error
        handle: SubprocessCommandHandle | None = None
        outputs_transferred = False
        primary_error: BaseException | None = None
        cleanup_errors: list[str] = []
        try:
            leader_record = _action_process_record(process.pid)
            if leader_record is None or leader_record[0] != controller_pid:
                raise StabilityError("action subprocess identity is unavailable")
            handle = SubprocessCommandHandle(
                process,
                controller_pid,
                leader_record[2],
                self._disk_monitor,
            )
            # Publish ownership before any fallible pump setup. Cleanup can
            # now use exact leader/adopted identities even if Thread.start()
            # fails after the action has already forked or changed session.
            self.last_handle = handle
            if process.stdout is None or process.stderr is None:
                raise StabilityError("action subprocess pipes are unavailable")
            outputs = [
                (process.stdout, stdout_descriptor, "stdout"),
                (process.stderr, stderr_descriptor, "stderr"),
            ]
            outputs_transferred = True
            handle.start_output_pumps(outputs)
            return handle
        except BaseException as error:
            primary_error = error
            if handle is not None:
                handle.retain_disk_reserve()
                try:
                    _stop_process_group(handle, release_reserve=False)
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"process cleanup: {cleanup_error}")
                cleanup_errors.extend(handle.close_pending_outputs())
            else:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"leader signal: {cleanup_error}")
                try:
                    process.wait(timeout=2.0)
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"leader cleanup: {cleanup_error}")
                try:
                    _cleanup_adopted_action_children(controller_pid)
                except BaseException as cleanup_error:
                    cleanup_errors.append(
                        f"adopted-child cleanup: {cleanup_error}"
                    )
            if not outputs_transferred:
                for label, stream in (
                    ("stdout", process.stdout), ("stderr", process.stderr)
                ):
                    if stream is not None:
                        try:
                            stream.close()
                        except BaseException as cleanup_error:
                            cleanup_errors.append(
                                f"{label} pipe close: {cleanup_error}"
                            )
                for label, descriptor in (
                    ("stdout", stdout_descriptor),
                    ("stderr", stderr_descriptor),
                ):
                    try:
                        os.close(descriptor)
                    except OSError as cleanup_error:
                        cleanup_errors.append(
                            f"{label} log close: {cleanup_error}"
                        )
        suffix = (
            "; cleanup failed: " + "; ".join(cleanup_errors)
            if cleanup_errors else ""
        )
        if isinstance(primary_error, StabilityError):
            raise StabilityError(f"{primary_error}{suffix}") from primary_error
        if isinstance(primary_error, Exception):
            raise StabilityError(
                f"cannot configure action supervision: {primary_error}{suffix}"
            ) from primary_error
        if cleanup_errors:
            raise StabilityError(
                "action setup interrupted; cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from primary_error
        if primary_error is not None:
            raise primary_error
        raise StabilityError("action supervision setup failed without an error")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_document(value: Any) -> bytes:
    return (
        json.dumps(
            value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
        )
        + "\n"
    ).encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_file(
    path: Path, maximum_size: int = MAX_ARTIFACT_FILE_BYTES,
) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StabilityError(f"cannot stat regular file {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise StabilityError(f"evidence path is not a regular file: {path}")
    if metadata.st_size > maximum_size:
        raise StabilityError(f"evidence file exceeds hash size limit: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size
            ):
                raise StabilityError(f"evidence file changed while opening: {path}")
            remaining = maximum_size + 1
            total = 0
            while remaining:
                block = os.read(descriptor, min(1024 * 1024, remaining))
                if not block:
                    break
                digest.update(block)
                total += len(block)
                remaining -= len(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except StabilityError:
        raise
    except OSError as error:
        raise StabilityError(f"cannot read regular file {path}: {error}") from error
    if total > maximum_size:
        raise StabilityError(f"evidence file exceeds hash size limit: {path}")
    if (
        after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
    ):
        raise StabilityError(f"evidence file changed while reading: {path}")
    return digest.hexdigest()


def _read_regular_bytes(path: Path, maximum_size: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise StabilityError(f"cannot stat regular file {path}: {error}") from error
    if not stat.S_ISREG(before.st_mode):
        raise StabilityError(f"evidence path is not a regular file: {path}")
    if before.st_size > maximum_size:
        raise StabilityError(f"evidence file exceeds size limit: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
            ):
                raise StabilityError(f"evidence file changed while opening: {path}")
            chunks: list[bytes] = []
            remaining = maximum_size + 1
            while remaining:
                block = os.read(descriptor, min(1024 * 1024, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except StabilityError:
        raise
    except OSError as error:
        raise StabilityError(f"cannot read regular file {path}: {error}") from error
    if len(data) > maximum_size:
        raise StabilityError(f"evidence file exceeds size limit: {path}")
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
    ):
        raise StabilityError(f"evidence file changed while reading: {path}")
    return data


def load_journal(path: Path) -> list[dict[str, Any]]:
    data = _read_regular_bytes(path, MAX_JOURNAL_BYTES)
    if not data or not data.endswith(b"\n"):
        raise StabilityError("journal is empty or lacks its terminal newline")
    lines = data[:-1].split(b"\n")
    if not lines or len(lines) > MAX_JOURNAL_EVENTS or any(not line for line in lines):
        raise StabilityError("journal line inventory is malformed")
    events: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StabilityError(f"journal line {index} is malformed: {error}") from error
        if not isinstance(value, dict) or canonical_json(value) != line:
            raise StabilityError(f"journal line {index} is not canonical JSON")
        events.append(value)
    return events


def _exact_dict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise StabilityError(f"{label} fields are malformed")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StabilityError(f"{label} is malformed")
    return value


def _fixed_integer(value: Any, expected: int, label: str) -> int:
    actual = _integer(value, label)
    if actual != expected:
        raise StabilityError(f"{label} must be {expected}")
    return actual


def _relative_regular(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise StabilityError(f"{label} path is malformed")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise StabilityError(f"{label} path must be repository-relative")
    path = root / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StabilityError(f"{label} path is unavailable: {value}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise StabilityError(f"{label} path is not a regular file: {value}")
    return path


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StabilityError(f"{label} JSON is malformed: {error}") from error
    if not isinstance(value, dict):
        raise StabilityError(f"{label} JSON root is malformed")
    return value


def _validate_matrix_authority(path: Path, tier: str) -> None:
    manifest = _load_json(path, "real-world manifest")
    campaigns = manifest.get("campaigns")
    projects = manifest.get("projects")
    if manifest.get("schema") != 1 or not isinstance(campaigns, dict):
        raise StabilityError("real-world manifest authority is malformed")
    campaign = campaigns.get(tier)
    if not isinstance(campaign, dict) or set(campaign) != {
        "window_minutes", "repetitions", "projects"
    }:
        raise StabilityError("release-candidate matrix authority is malformed")
    window_minutes = _integer(
        campaign["window_minutes"],
        "release-candidate scheduling window minutes",
        1,
    )
    if window_minutes > MAX_MATRIX_SCHEDULING_WINDOW_MINUTES:
        raise StabilityError(
            "release-candidate scheduling window exceeds its metadata limit"
        )
    if (
        campaign["repetitions"] != 3
        or campaign["projects"] != REQUIRED_MATRIX_PROJECTS
    ):
        raise StabilityError("release-candidate matrix authority drift")
    if not isinstance(projects, list):
        raise StabilityError("real-world project authority is malformed")
    project_ids = {
        project.get("id") for project in projects if isinstance(project, dict)
    }
    if not set(REQUIRED_MATRIX_PROJECTS).issubset(project_ids):
        raise StabilityError("release-candidate project authority is incomplete")


def _validate_qualification_authority(manifest_path: Path, baseline_path: Path) -> None:
    manifest = _load_json(manifest_path, "determinism manifest")
    baseline = _load_json(baseline_path, "determinism baseline")
    if (
        manifest.get("schema") != "codeskeptic-determinism-workloads-v3"
        or manifest.get("repetitions") != 10
        or manifest.get("performance_regression_limit_percent") != 10
    ):
        raise StabilityError("determinism qualification authority drift")
    workloads = manifest.get("workloads")
    if not isinstance(workloads, list) or {
        item.get("kind") for item in workloads if isinstance(item, dict)
    } != {"unit", "real-repository", "release-candidate"}:
        raise StabilityError("determinism workload authority is incomplete")
    if (
        baseline.get("performance_regression_limit_percent") != 10
        or not isinstance(baseline.get("profiles"), dict)
        or not baseline["profiles"]
    ):
        raise StabilityError("determinism baseline authority drift")


def validate_policy(raw: Any, repository_root: Path) -> dict[str, Any]:
    policy = _exact_dict(raw, {
        "schema", "completion", "continuity", "heartbeat",
        "matrix", "resources", "qualification", "diagnostics",
        "fault_injection",
    }, "stability policy")
    if policy["schema"] != POLICY_SCHEMA:
        raise StabilityError("stability policy schema is unsupported")
    completion = _exact_dict(
        policy["completion"],
        {
            "basis", "required_cold_rounds", "required_complete_rounds",
            "required_realworld_shards", "required_warm_rounds",
        },
        "stability completion policy",
    )
    if completion["basis"] != "exact-cold-warm-matrix":
        raise StabilityError("stability completion basis drift")
    _fixed_integer(
        completion["required_complete_rounds"], REQUIRED_COMPLETE_ROUNDS,
        "required complete rounds",
    )
    _fixed_integer(completion["required_cold_rounds"], 1, "required cold rounds")
    _fixed_integer(completion["required_warm_rounds"], 1, "required warm rounds")
    _fixed_integer(
        completion["required_realworld_shards"], REQUIRED_REALWORLD_SHARDS,
        "required real-world shards",
    )

    continuity = _exact_dict(
        policy["continuity"],
        {"boot_change", "controller_restart", "suspend"},
        "continuity policy",
    )
    if continuity != {
        "boot_change": "reject",
        "controller_restart": "reject",
        "suspend": "reject",
    }:
        raise StabilityError("continuity policy is not fail-closed")

    heartbeat = _exact_dict(
        policy["heartbeat"],
        {
            "interval_seconds", "maximum_action_transition_seconds",
            "maximum_gap_seconds", "maximum_suspend_delta_seconds",
        },
        "heartbeat policy",
    )
    for field, expected in {
        "interval_seconds": 30,
        "maximum_action_transition_seconds": 60,
        "maximum_gap_seconds": 90,
        "maximum_suspend_delta_seconds": 2,
    }.items():
        _fixed_integer(heartbeat[field], expected, f"heartbeat {field}")

    matrix = _exact_dict(
        policy["matrix"],
        {"manifest", "minimum_complete_rounds", "tier"},
        "matrix policy",
    )
    if matrix["tier"] != "release-candidate":
        raise StabilityError("matrix tier is not release-candidate")
    _fixed_integer(matrix["minimum_complete_rounds"], 2, "minimum rounds")
    matrix_path = _relative_regular(
        repository_root, matrix["manifest"], "real-world manifest"
    )
    _validate_matrix_authority(matrix_path, matrix["tier"])

    resources = _exact_dict(
        policy["resources"],
        {
            "maximum_open_fds", "rss_budget", "time_budget",
            "tu_timeout_seconds", "tu_memory_mib",
        },
        "resource policy",
    )
    if resources != {
        "maximum_open_fds": MAXIMUM_OPEN_FDS,
        "rss_budget": "per-translation-unit-required",
        "time_budget": "per-translation-unit-required",
        "tu_timeout_seconds": TU_TIMEOUT_SECONDS,
        "tu_memory_mib": TU_MEMORY_MIB,
    }:
        raise StabilityError("stability resource policy drift")

    qualification = _exact_dict(
        policy["qualification"],
        {
            "baseline", "manifest", "outer_timeout_seconds",
            "performance_policy",
        },
        "qualification policy",
    )
    if qualification["performance_policy"] != "required":
        raise StabilityError("qualification performance policy must be required")
    _fixed_integer(
        qualification["outer_timeout_seconds"], 21600,
        "qualification outer timeout",
    )
    determinism_path = _relative_regular(
        repository_root, qualification["manifest"], "determinism manifest"
    )
    baseline_path = _relative_regular(
        repository_root, qualification["baseline"], "determinism baseline"
    )
    _validate_qualification_authority(determinism_path, baseline_path)

    diagnostics = _exact_dict(
        policy["diagnostics"], {"required_sanitizer_profiles"},
        "diagnostics policy",
    )
    if diagnostics["required_sanitizer_profiles"] != ["address", "undefined"]:
        raise StabilityError("required sanitizer profiles drift")

    faults = _exact_dict(
        policy["fault_injection"],
        {"mode", "required_test_count", "required_tests", "timeout_seconds"},
        "fault-injection policy",
    )
    if faults != {
        "mode": "cold-only",
        "required_test_count": len(fault_injection.CANONICAL_TESTS),
        "required_tests": list(fault_injection.CANONICAL_TESTS),
        "timeout_seconds": fault_injection.TIMEOUT_SECONDS,
    }:
        raise StabilityError("fault-injection policy drift")
    return copy.deepcopy(policy)


def verify_runtime_resource_limits(policy: dict[str, Any]) -> dict[str, Any]:
    """Require the hard FD budget inherited by every campaign descendant."""

    resources = _exact_dict(
        policy.get("resources"),
        {
            "maximum_open_fds", "rss_budget", "time_budget",
            "tu_timeout_seconds", "tu_memory_mib",
        },
        "runtime resource policy",
    )
    expected = _fixed_integer(
        resources["maximum_open_fds"], MAXIMUM_OPEN_FDS,
        "runtime maximum open files",
    )
    if resource is None:
        raise StabilityError("runtime FD limit API is unavailable")
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as error:
        raise StabilityError(f"cannot inspect runtime FD limit: {error}") from error
    if soft != expected or hard != expected:
        raise StabilityError(
            "runtime FD limit differs from the fixed campaign budget"
        )
    return {
        "schema": "codeskeptic-stability-runtime-resources-v1",
        "maximum_open_fds": expected,
        "soft_open_fds": soft,
        "hard_open_fds": hard,
        "rss_budget": resources["rss_budget"],
        "time_budget": resources["time_budget"],
        "tu_timeout_seconds": _fixed_integer(
            resources["tu_timeout_seconds"], TU_TIMEOUT_SECONDS,
            "runtime TU timeout",
        ),
        "tu_memory_mib": _fixed_integer(
            resources["tu_memory_mib"], TU_MEMORY_MIB,
            "runtime TU memory",
        ),
    }


def _absolute_config_path(
    value: Any, root: Path, label: str, *, exact: Path | None = None,
) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StabilityError(f"{label} path is malformed")
    path = Path(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
    ):
        raise StabilityError(f"{label} path is not canonical absolute")
    root_value = Path(root).absolute()
    if path != root_value and root_value not in path.parents:
        raise StabilityError(f"{label} path escapes {root_value}")
    if exact is not None and path != exact:
        raise StabilityError(f"{label} path differs from its fixed location")
    return value


def validate_runtime_config(
    raw: Any,
    *,
    authority_root: Path = Path("/authority"),
    launch_root: Path = Path("/launch"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> dict[str, Any]:
    """Validate deployment paths and immutable identities without touching them."""

    value = _exact_dict(
        raw,
        {
            "schema", "policy", "source", "runtime", "analyzer",
            "build_authority", "realworld", "fault_injection", "qualification",
            "prerequisites", "sanitizers",
        },
        "stability runtime config",
    )
    if value["schema"] != RUNTIME_CONFIG_SCHEMA:
        raise StabilityError("stability runtime config schema is unsupported")
    authority_root = authority_root.absolute()
    launch_root = launch_root.absolute()
    cgroup_root = cgroup_root.absolute()
    source_root = authority_root / "source"

    policy = _exact_dict(
        value["policy"], {"path", "sha256"}, "runtime policy"
    )
    _absolute_config_path(
        policy["path"], authority_root, "runtime policy",
        exact=source_root / "scripts" / "stability_manifest.json",
    )
    _valid_sha(policy["sha256"], "runtime policy")

    source = _exact_dict(
        value["source"],
        {"root", "revision", "tree_sha1", "manifest_sha256"},
        "runtime source",
    )
    _absolute_config_path(
        source["root"], authority_root, "runtime source", exact=source_root
    )
    for field in ("revision", "tree_sha1"):
        if not isinstance(source[field], str) or GIT_SHA1.fullmatch(source[field]) is None:
            raise StabilityError(f"runtime source {field} is malformed")
    _valid_sha(source["manifest_sha256"], "runtime source manifest")

    runtime = _exact_dict(
        value["runtime"],
        {"image_reference", "image_digest", "image_id", "launch_receipt"},
        "runtime authority",
    )
    if runtime != {
        "image_reference": PINNED_EVIDENCE_IMAGE,
        "image_digest": PINNED_EVIDENCE_IMAGE_DIGEST,
        "image_id": PINNED_EVIDENCE_IMAGE_ID,
        "launch_receipt": (launch_root / "receipt.json").as_posix(),
    }:
        raise StabilityError("pinned runtime authority drift")

    analyzer = _exact_dict(
        value["analyzer"], {"path", "sha256"}, "runtime analyzer"
    )
    _absolute_config_path(
        analyzer["path"], authority_root, "runtime analyzer",
        exact=authority_root / "build" / "src" / "codeskeptic",
    )
    _valid_sha(analyzer["sha256"], "runtime analyzer")

    build = _exact_dict(
        value["build_authority"],
        {"root", "receipt_sha256", "build_path"},
        "runtime build authority",
    )
    _absolute_config_path(
        build["root"], authority_root, "runtime build authority root",
        exact=authority_root / "build-authority",
    )
    _absolute_config_path(
        build["build_path"], authority_root,
        "runtime build authority build_path",
        exact=authority_root / "build",
    )
    _valid_sha(build["receipt_sha256"], "runtime build authority receipt")

    realworld_config = _exact_dict(
        value["realworld"],
        {"mirror_authority", "mirror_authority_sha256"},
        "runtime real-world authority",
    )
    _absolute_config_path(
        realworld_config["mirror_authority"],
        authority_root,
        "runtime real-world mirror authority",
        exact=authority_root / "mirrors" / "authority.json",
    )
    _valid_sha(
        realworld_config["mirror_authority_sha256"],
        "runtime real-world mirror authority",
    )

    fault_config = _exact_dict(
        value["fault_injection"],
        {"test_binary", "test_binary_sha256"},
        "runtime fault-injection authority",
    )
    _absolute_config_path(
        fault_config["test_binary"],
        authority_root,
        "runtime fault-injection test binary",
    )
    _valid_sha(
        fault_config["test_binary_sha256"],
        "runtime fault-injection test binary",
    )

    qualification = _exact_dict(
        value["qualification"],
        {
            "hardware_class", "measurement_cgroup", "baseline_authority",
            "release_source", "release_build", "release_receipt_sha256",
            "jobs", "tools",
        },
        "runtime qualification",
    )
    if (
        qualification["hardware_class"]
        != "fedora44-i5-1235u-exclusive-pcores-0-3"
    ):
        raise StabilityError("runtime hardware class drift")
    _absolute_config_path(
        qualification["measurement_cgroup"],
        cgroup_root,
        "runtime measurement cgroup",
        exact=Path(RUNTIME_MEASUREMENT_CGROUP),
    )
    baseline_authority = _exact_dict(
        qualification["baseline_authority"],
        {
            "root", "manifest_sha256", "baseline_sha256",
            "projection_sha256",
        },
        "runtime determinism baseline authority",
    )
    _absolute_config_path(
        baseline_authority["root"],
        authority_root,
        "runtime determinism baseline authority root",
        exact=source_root,
    )
    for field in ("manifest_sha256", "baseline_sha256", "projection_sha256"):
        _valid_sha(
            baseline_authority[field],
            f"runtime determinism baseline authority {field}",
        )
    for field, exact in {
        "release_source": authority_root / "release" / "source",
        "release_build": authority_root / "release" / "build",
    }.items():
        _absolute_config_path(
            qualification[field], authority_root,
            f"runtime qualification {field}", exact=exact,
        )
    _valid_sha(
        qualification["release_receipt_sha256"],
        "runtime qualification release receipt",
    )
    _fixed_integer(qualification["jobs"], 2, "runtime qualification jobs")
    tools = _exact_dict(
        qualification["tools"],
        {"clang", "time", "cmake", "ninja", "c_compiler", "cxx_compiler"},
        "runtime qualification tools",
    )
    expected_tools = {
        "clang": "/usr/bin/clang-20",
        "time": "/usr/bin/time",
        "cmake": "/usr/bin/cmake",
        "ninja": "/usr/bin/ninja",
        "c_compiler": "/usr/bin/clang-20",
        "cxx_compiler": "/usr/bin/clang++-20",
    }
    if tools != expected_tools:
        raise StabilityError("runtime qualification tool paths drift")

    prerequisites = _exact_dict(
        value["prerequisites"],
        {"hosted_exact_head", "quality_floor"},
        "runtime prerequisites",
    )
    prerequisite_roots = {
        "quality_floor": authority_root / "prerequisites" / "quality",
    }
    for name in ("quality_floor",):
        record = _exact_dict(
            prerequisites[name], {"root", "receipt_sha256"},
            f"runtime prerequisite {name}",
        )
        _absolute_config_path(
            record["root"], authority_root, f"runtime prerequisite {name}",
            exact=prerequisite_roots[name],
        )
        _valid_sha(
            record["receipt_sha256"], f"runtime prerequisite {name} receipt"
        )
    hosted = _exact_dict(
        prerequisites["hosted_exact_head"],
        {"root", "receipt_sha256", "repository"},
        "runtime prerequisite hosted exact-head",
    )
    _absolute_config_path(
        hosted["root"], authority_root, "runtime hosted exact-head",
        exact=authority_root / "prerequisites" / "hosted",
    )
    _valid_sha(hosted["receipt_sha256"], "runtime hosted exact-head receipt")
    if (
        not isinstance(hosted["repository"], str)
        or not hosted["repository"]
        or "/" not in hosted["repository"]
        or "\x00" in hosted["repository"]
    ):
        raise StabilityError("runtime hosted repository identity is malformed")

    sanitizers = _exact_dict(
        value["sanitizers"], {"address", "undefined"}, "runtime sanitizers"
    )
    for profile in ("address", "undefined"):
        record = _exact_dict(
            sanitizers[profile],
            {"root", "receipt_sha256", "test_build", "fuzz_build"},
            f"runtime sanitizer {profile}",
        )
        exact_paths = {
            "root": authority_root / "sanitizers" / profile,
            "test_build": (
                source_root / "build" / "p10-09-sanitizers"
                / f"{profile}-tests"
            ),
            "fuzz_build": (
                source_root / "build" / "p10-09-sanitizers"
                / f"{profile}-fuzz"
            ),
        }
        for field in ("root", "test_build", "fuzz_build"):
            _absolute_config_path(
                record[field], authority_root,
                f"runtime sanitizer {profile} {field}",
                exact=exact_paths[field],
            )
        _valid_sha(
            record["receipt_sha256"], f"runtime sanitizer {profile} receipt"
        )
    expected_fault_binary = (
        Path(sanitizers["undefined"]["test_build"])
        / "tests" / "codeskeptic_tests"
    )
    if Path(fault_config["test_binary"]) != expected_fault_binary:
        raise StabilityError(
            "runtime fault-injection binary is not the undefined sanitizer test binary"
        )
    return copy.deepcopy(value)


def load_runtime_config_file(
    path: Path,
    *,
    authority_root: Path = Path("/authority"),
    launch_root: Path = Path("/launch"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> dict[str, Any]:
    """Load one canonical runtime config and its exact adjacent checksum."""

    data = _read_regular_bytes(path, MAX_DOCUMENT_BYTES)
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StabilityError(f"runtime config JSON is malformed: {error}") from error
    if not isinstance(raw, dict) or canonical_document(raw) != data:
        raise StabilityError("runtime config is not canonical JSON")
    digest = hashlib.sha256(data).hexdigest()
    expected_sidecar = f"{digest}  {path.name}\n".encode("ascii")
    if _read_regular_bytes(Path(f"{path}.sha256"), 1024) != expected_sidecar:
        raise StabilityError("runtime config checksum mismatch")
    return validate_runtime_config(
        raw,
        authority_root=authority_root,
        launch_root=launch_root,
        cgroup_root=cgroup_root,
    )


def build_runtime_launch_receipt(
    runtime_config_sha256: str, boot_id: str,
) -> dict[str, Any]:
    """Build the fixed container launch claim emitted by the root operator."""

    config_sha = _valid_sha(runtime_config_sha256, "runtime launch config")
    if not isinstance(boot_id, str) or BOOT_ID.fullmatch(boot_id) is None:
        raise StabilityError("runtime launch boot identity is malformed")
    return {
        "schema": RUNTIME_LAUNCH_SCHEMA,
        "status": "accepted",
        "failures": [],
        "boot_id": boot_id,
        "runtime_config_sha256": config_sha,
        "image": {
            "reference": PINNED_EVIDENCE_IMAGE,
            "digest": PINNED_EVIDENCE_IMAGE_DIGEST,
            "id": PINNED_EVIDENCE_IMAGE_ID,
        },
        "container": {
            "network": "none",
            "cgroups": "disabled",
            "cgroup_namespace": "host",
            "pid_namespace": "private",
            "maximum_open_fds": MAXIMUM_OPEN_FDS,
            "read_only": True,
            "user": "0:0",
        },
        "mounts": copy.deepcopy(RUNTIME_LAUNCH_MOUNTS),
        "command": list(RUNTIME_CONTROLLER_COMMAND),
    }


def validate_runtime_launch_receipt(
    raw: Any,
    config: dict[str, Any],
    *,
    runtime_config_sha256: str,
    boot_id: str,
) -> dict[str, Any]:
    """Reject a launch claim that differs from the pinned offline topology."""

    config_value = validate_runtime_config(config)
    expected = build_runtime_launch_receipt(runtime_config_sha256, boot_id)
    value = _exact_dict(
        raw,
        {
            "schema", "status", "failures", "boot_id",
            "runtime_config_sha256", "image", "container", "mounts",
            "command",
        },
        "runtime launch receipt",
    )
    _exact_dict(value["image"], {"reference", "digest", "id"}, "launch image")
    _exact_dict(
        value["container"],
        {
            "network", "cgroups", "cgroup_namespace",
            "pid_namespace", "maximum_open_fds", "read_only", "user",
        },
        "launch container",
    )
    if value != expected:
        raise StabilityError("runtime launch receipt differs from the fixed topology")
    runtime = config_value["runtime"]
    if value["image"] != {
        "reference": runtime["image_reference"],
        "digest": runtime["image_digest"],
        "id": runtime["image_id"],
    }:
        raise StabilityError("runtime launch image differs from its config")
    return copy.deepcopy(value)


def load_runtime_launch_receipt(
    path: Path,
    config: dict[str, Any],
    *,
    runtime_config_sha256: str,
    boot_id: str,
) -> dict[str, Any]:
    data = _read_regular_bytes(path, MAX_DOCUMENT_BYTES)
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StabilityError(f"runtime launch receipt JSON is malformed: {error}") from error
    if not isinstance(raw, dict) or canonical_document(raw) != data:
        raise StabilityError("runtime launch receipt is not canonical JSON")
    digest = hashlib.sha256(data).hexdigest()
    expected_sidecar = f"{digest}  {path.name}\n".encode("ascii")
    if _read_regular_bytes(Path(f"{path}.sha256"), 1024) != expected_sidecar:
        raise StabilityError("runtime launch receipt checksum mismatch")
    return validate_runtime_launch_receipt(
        raw,
        config,
        runtime_config_sha256=runtime_config_sha256,
        boot_id=boot_id,
    )


def seal_runtime_launch_receipt(
    config_path: Path, output_root: Path, boot_id: str,
) -> dict[str, Any]:
    """Publish one canonical, no-replace host launch claim."""

    config = load_runtime_config_file(config_path)
    config_sha = sha256_file(config_path)
    try:
        metadata = output_root.lstat()
        entries = list(output_root.iterdir())
    except OSError as error:
        raise StabilityError(f"cannot inspect runtime launch output: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise StabilityError("runtime launch output is not a real directory")
    if entries:
        raise StabilityError("runtime launch output is not empty")
    receipt = build_runtime_launch_receipt(config_sha, boot_id)
    validate_runtime_launch_receipt(
        receipt,
        config,
        runtime_config_sha256=config_sha,
        boot_id=boot_id,
    )
    data = canonical_document(receipt)
    receipt_path = output_root / "receipt.json"
    sidecar_path = output_root / "receipt.json.sha256"
    _atomic_create(receipt_path, data)
    try:
        _atomic_create(
            sidecar_path,
            f"{hashlib.sha256(data).hexdigest()}  receipt.json\n".encode("ascii"),
        )
    except BaseException:
        try:
            receipt_path.unlink()
        except OSError:
            pass
        raise
    return verify_runtime_launch_files(config_path, receipt_path, boot_id)


def verify_runtime_launch_files(
    config_path: Path, receipt_path: Path, boot_id: str,
) -> dict[str, Any]:
    """Verify the exact config/launch pair before rootful Podman starts."""

    config = load_runtime_config_file(config_path)
    config_sha = sha256_file(config_path)
    expected_paths = ["receipt.json", "receipt.json.sha256"]
    if _regular_files(receipt_path.parent) != expected_paths:
        raise StabilityError("runtime launch directory file set drift")
    return load_runtime_launch_receipt(
        receipt_path,
        config,
        runtime_config_sha256=config_sha,
        boot_id=boot_id,
    )


def _valid_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise StabilityError(f"{label} hash is malformed")
    return value


def build_session_identity(material: Any) -> str:
    value = _exact_dict(material, {
        "schema", "policy_sha256", "source_revision", "source_tree_sha1",
        "source_manifest_sha256", "analyzer_sha256",
        "runtime_config_sha256", "runtime_launch_receipt_sha256",
        "build_authority_receipt_sha256",
        "release_candidate_receipt_sha256",
        "realworld_manifest_sha256", "realworld_mirror_authority_sha256",
        "determinism_manifest_sha256",
        "baseline_sha256", "baseline_authority_projection_sha256",
        "sanitizer_receipts", "prerequisite_receipts",
        "fault_injection_test_binary", "hardware_class", "boot_id",
    }, "stability session identity")
    if value["schema"] != SESSION_SCHEMA:
        raise StabilityError("stability session schema is unsupported")
    if (
        not isinstance(value["source_revision"], str)
        or GIT_SHA1.fullmatch(value["source_revision"]) is None
    ):
        raise StabilityError("session source revision is malformed")
    if (
        not isinstance(value["source_tree_sha1"], str)
        or GIT_SHA1.fullmatch(value["source_tree_sha1"]) is None
    ):
        raise StabilityError("session source tree is malformed")
    for field in (
        "policy_sha256", "source_manifest_sha256", "analyzer_sha256",
        "runtime_config_sha256", "runtime_launch_receipt_sha256",
        "build_authority_receipt_sha256",
        "release_candidate_receipt_sha256",
        "realworld_manifest_sha256", "realworld_mirror_authority_sha256",
        "determinism_manifest_sha256",
        "baseline_sha256", "baseline_authority_projection_sha256",
    ):
        _valid_sha(value[field], f"session {field}")
    sanitizer = _exact_dict(
        value["sanitizer_receipts"], {"address", "undefined"},
        "session sanitizer receipts",
    )
    for profile in ("address", "undefined"):
        _valid_sha(sanitizer[profile], f"session sanitizer {profile}")
    prerequisites = _exact_dict(
        value["prerequisite_receipts"],
        {"hosted_exact_head", "quality_floor"},
        "session prerequisite receipts",
    )
    for prerequisite in ("hosted_exact_head", "quality_floor"):
        _valid_sha(
            prerequisites[prerequisite],
            f"session prerequisite {prerequisite}",
        )
    fault_binary = _exact_dict(
        value["fault_injection_test_binary"],
        {"path", "sha256", "sanitizer_profile", "sanitizer_receipt_sha256"},
        "session fault-injection test binary",
    )
    if not isinstance(fault_binary["path"], str) or not fault_binary["path"]:
        raise StabilityError("session fault-injection test binary path is malformed")
    _valid_sha(
        fault_binary["sha256"], "session fault-injection test binary"
    )
    if fault_binary["sanitizer_profile"] != "undefined":
        raise StabilityError("session fault-injection sanitizer profile drift")
    _valid_sha(
        fault_binary["sanitizer_receipt_sha256"],
        "session fault-injection sanitizer receipt",
    )
    if (
        fault_binary["sanitizer_receipt_sha256"]
        != sanitizer["undefined"]
    ):
        raise StabilityError(
            "session fault-injection binary is not linked to undefined sanitizer"
        )
    if not isinstance(value["hardware_class"], str) or not value["hardware_class"]:
        raise StabilityError("session hardware class is malformed")
    if not isinstance(value["boot_id"], str) or BOOT_ID.fullmatch(value["boot_id"]) is None:
        raise StabilityError("session boot identity is malformed")
    return digest_json(value)


def build_runtime_session_record(
    config: dict[str, Any],
    *,
    runtime_config_sha256: str,
    runtime_launch_receipt_sha256: str,
    boot_id: str,
    controller_id: str,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Bind all immutable runtime inputs into the live controller identity."""

    value = validate_runtime_config(config)
    config_sha = _valid_sha(runtime_config_sha256, "runtime session config")
    launch_sha = _valid_sha(
        runtime_launch_receipt_sha256, "runtime session launch receipt"
    )
    controller = _valid_sha(controller_id, "runtime session controller")
    if not isinstance(boot_id, str) or BOOT_ID.fullmatch(boot_id) is None:
        raise StabilityError("runtime session boot identity is malformed")
    source_root = (
        Path(value["source"]["root"])
        if repository_root is None else repository_root
    )
    scripts = source_root / "scripts"
    material = {
        "schema": SESSION_SCHEMA,
        "policy_sha256": value["policy"]["sha256"],
        "source_revision": value["source"]["revision"],
        "source_tree_sha1": value["source"]["tree_sha1"],
        "source_manifest_sha256": value["source"]["manifest_sha256"],
        "analyzer_sha256": value["analyzer"]["sha256"],
        "runtime_config_sha256": config_sha,
        "runtime_launch_receipt_sha256": launch_sha,
        "build_authority_receipt_sha256": value["build_authority"][
            "receipt_sha256"
        ],
        "release_candidate_receipt_sha256": value["qualification"][
            "release_receipt_sha256"
        ],
        "realworld_manifest_sha256": sha256_file(
            scripts / "realworld_manifest.json"
        ),
        "realworld_mirror_authority_sha256": value["realworld"][
            "mirror_authority_sha256"
        ],
        "determinism_manifest_sha256": sha256_file(
            scripts / "determinism_workloads.json"
        ),
        "baseline_sha256": sha256_file(
            scripts / "determinism_baseline.json"
        ),
        "baseline_authority_projection_sha256": value["qualification"][
            "baseline_authority"
        ]["projection_sha256"],
        "sanitizer_receipts": {
            profile: value["sanitizers"][profile]["receipt_sha256"]
            for profile in ("address", "undefined")
        },
        "prerequisite_receipts": {
            prerequisite: value["prerequisites"][prerequisite][
                "receipt_sha256"
            ]
            for prerequisite in ("hosted_exact_head", "quality_floor")
        },
        "fault_injection_test_binary": {
            "path": value["fault_injection"]["test_binary"],
            "sha256": value["fault_injection"]["test_binary_sha256"],
            "sanitizer_profile": "undefined",
            "sanitizer_receipt_sha256": value["sanitizers"]["undefined"][
                "receipt_sha256"
            ],
        },
        "hardware_class": value["qualification"]["hardware_class"],
        "boot_id": boot_id,
    }
    session_id = build_session_identity(material)
    return {
        "id": session_id,
        "controller_id": controller,
        "identity": material,
    }


def build_schedule(
    policy: dict[str, Any], repository_root: Path,
) -> dict[str, Any]:
    matrix = policy["matrix"]
    manifest_path = _relative_regular(
        repository_root, matrix["manifest"], "real-world manifest"
    )
    try:
        manifest = realworld.validate_manifest(realworld.load_manifest(manifest_path))
        planned = realworld.plan_matrix(manifest, matrix["tier"])
    except realworld.CampaignError as error:
        raise StabilityError(f"cannot derive release-candidate schedule: {error}") from error
    include = planned.get("include")
    if not isinstance(include, list):
        raise StabilityError("release-candidate schedule is malformed")
    slots: list[dict[str, Any]] = []
    for index, item in enumerate(include):
        value = _exact_dict(
            item, {"project", "repetition", "timeout_minutes"},
            "release-candidate schedule slot",
        )
        if value["project"] not in REQUIRED_MATRIX_PROJECTS:
            raise StabilityError("release-candidate schedule project drift")
        repetition = _integer(value["repetition"], "schedule repetition", 1)
        if repetition > 3:
            raise StabilityError("schedule repetition is outside the fixed matrix")
        timeout = _integer(value["timeout_minutes"], "schedule timeout", 1)
        slots.append({
            "index": index,
            "project": value["project"],
            "repetition": repetition,
            "timeout_minutes": timeout,
        })
    expected = [
        (project, repetition)
        for project in REQUIRED_MATRIX_PROJECTS
        for repetition in (1, 2, 3)
    ]
    if [(slot["project"], slot["repetition"]) for slot in slots] != expected:
        raise StabilityError("release-candidate schedule is not the exact 3x3 matrix")
    return {
        "schema": "codeskeptic-stability-schedule-v1",
        "tier": matrix["tier"],
        "manifest_file_sha256": sha256_file(manifest_path),
        "manifest_identity_sha256": realworld.digest_json(manifest),
        "slot_count": len(slots),
        "slots": slots,
        "schedule_sha256": digest_json(slots),
    }


def cycle_identity(session_id: str, ordinal: Any, schedule_sha256: str) -> str:
    _valid_sha(session_id, "cycle session identity")
    ordinal_value = _integer(ordinal, "cycle ordinal", 1)
    _valid_sha(schedule_sha256, "cycle schedule")
    return digest_json({
        "schema": CYCLE_IDENTITY_SCHEMA,
        "session_id": session_id,
        "ordinal": ordinal_value,
        "schedule_sha256": schedule_sha256,
    })


def action_identity(
    cycle_id: str,
    ordinal: Any,
    kind: Any,
    parameters: Any,
) -> str:
    _valid_sha(cycle_id, "action cycle identity")
    ordinal_value = _integer(ordinal, "action ordinal")
    if kind not in {
        "qualification", "fault-injection", "realworld", "aggregate"
    }:
        raise StabilityError("action kind is unsupported")
    if not isinstance(parameters, dict):
        raise StabilityError("action parameters are malformed")
    try:
        canonical_json(parameters)
    except (TypeError, ValueError) as error:
        raise StabilityError("action parameters are not canonical JSON") from error
    return digest_json({
        "schema": ACTION_IDENTITY_SCHEMA,
        "cycle_id": cycle_id,
        "ordinal": ordinal_value,
        "kind": kind,
        "parameters": parameters,
    })


def build_cycle_plan(
    policy: dict[str, Any],
    schedule: Any,
    session_id: str,
    ordinal: Any,
) -> dict[str, Any]:
    schedule_value = _exact_dict(
        schedule,
        {
            "schema", "tier", "manifest_file_sha256",
            "manifest_identity_sha256", "slot_count", "slots",
            "schedule_sha256",
        },
        "stability schedule",
    )
    if schedule_value["schema"] != "codeskeptic-stability-schedule-v1":
        raise StabilityError("stability schedule schema is unsupported")
    if schedule_value["tier"] != policy["matrix"]["tier"]:
        raise StabilityError("stability schedule tier drift")
    _fixed_integer(schedule_value["slot_count"], 9, "schedule slot count")
    if (
        not isinstance(schedule_value["slots"], list)
        or len(schedule_value["slots"]) != 9
        or digest_json(schedule_value["slots"])
        != schedule_value["schedule_sha256"]
    ):
        raise StabilityError("stability schedule identity drift")
    _valid_sha(session_id, "cycle plan session identity")
    cycle_ordinal = _integer(ordinal, "cycle plan ordinal", 1)
    cycle_id = cycle_identity(
        session_id, cycle_ordinal, schedule_value["schedule_sha256"]
    )
    mode = "cold" if cycle_ordinal == 1 else "warm"
    actions: list[dict[str, Any]] = []

    def append_action(
        kind: str, parameters: dict[str, Any], timeout_seconds: int,
    ) -> None:
        action_ordinal = len(actions)
        action_id = action_identity(
            cycle_id, action_ordinal, kind, parameters
        )
        actions.append({
            "schema": ACTION_PLAN_SCHEMA,
            "id": action_id,
            "ordinal": action_ordinal,
            "kind": kind,
            "parameters": copy.deepcopy(parameters),
            "timeout_seconds": _integer(
                timeout_seconds, "planned action timeout", 1
            ),
        })

    qualification_timeout = policy["qualification"]["outer_timeout_seconds"]
    if cycle_ordinal == 1:
        append_action(
            "qualification",
            {"phase": "pre"},
            qualification_timeout + ACTION_SUPERVISION_GRACE_SECONDS,
        )
        append_action(
            "fault-injection",
            {"test_count": len(fault_injection.CANONICAL_TESTS)},
            fault_injection.TIMEOUT_SECONDS + ACTION_SUPERVISION_GRACE_SECONDS,
        )
    for expected_index, slot in enumerate(schedule_value["slots"]):
        value = _exact_dict(
            slot,
            {"index", "project", "repetition", "timeout_minutes"},
            "planned real-world slot",
        )
        if value["index"] != expected_index:
            raise StabilityError("planned real-world slot index drift")
        timeout_minutes = _integer(
            value["timeout_minutes"], "real-world slot timeout", 1
        )
        append_action(
            "realworld",
            {
                "checkpoint_mode": mode,
                "project": value["project"],
                "repetition": value["repetition"],
                "slot_index": expected_index,
                "tier": schedule_value["tier"],
                "timeout_minutes": timeout_minutes,
            },
            timeout_minutes * 60 + ACTION_SUPERVISION_GRACE_SECONDS,
        )
    append_action(
        "aggregate",
        {
            "checkpoint_mode": mode,
            "slot_count": 9,
            "tier": schedule_value["tier"],
        },
        qualification_timeout + ACTION_SUPERVISION_GRACE_SECONDS,
    )
    if cycle_ordinal == 2:
        append_action(
            "qualification",
            {"phase": "post"},
            qualification_timeout + ACTION_SUPERVISION_GRACE_SECONDS,
        )
    return {
        "schema": CYCLE_PLAN_SCHEMA,
        "id": cycle_id,
        "ordinal": cycle_ordinal,
        "mode": mode,
        "schedule_sha256": schedule_value["schedule_sha256"],
        "action_count": len(actions),
        "actions": actions,
        "plan_sha256": digest_json(actions),
    }


def fixed_action_environment(runtime_root: Path = Path("/runtime")) -> dict[str, str]:
    root = runtime_root.as_posix()
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": f"{root}/home",
        "TMPDIR": f"{root}/tmp",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def build_action_spec(
    config: dict[str, Any],
    plan: dict[str, Any],
    action: dict[str, Any],
    *,
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
) -> dict[str, Any]:
    """Derive exact child argv and isolated outputs from one fixed action plan."""

    config_value = validate_runtime_config(config)
    plan_value = _exact_dict(
        plan,
        {
            "schema", "id", "ordinal", "mode", "schedule_sha256",
            "action_count", "actions", "plan_sha256",
        },
        "action spec cycle plan",
    )
    if plan_value["schema"] != CYCLE_PLAN_SCHEMA:
        raise StabilityError("action spec cycle plan schema is unsupported")
    cycle_ordinal = _integer(
        plan_value["ordinal"], "action spec cycle ordinal", 1
    )
    expected_mode = "cold" if cycle_ordinal == 1 else "warm"
    if plan_value["mode"] != expected_mode:
        raise StabilityError("action spec cycle mode drift")
    _valid_sha(plan_value["id"], "action spec cycle identity")
    _valid_sha(plan_value["schedule_sha256"], "action spec schedule identity")
    actions = plan_value["actions"]
    if not isinstance(actions, list):
        raise StabilityError("action spec cycle actions are malformed")
    _fixed_integer(
        plan_value["action_count"], len(actions), "action spec action count"
    )
    if digest_json(actions) != plan_value["plan_sha256"]:
        raise StabilityError("action spec cycle plan identity drift")
    _valid_sha(plan_value["plan_sha256"], "action spec plan identity")
    action_value = _exact_dict(
        action,
        {
            "schema", "id", "ordinal", "kind", "parameters",
            "timeout_seconds",
        },
        "action spec plan entry",
    )
    if action_value["schema"] != ACTION_PLAN_SCHEMA:
        raise StabilityError("action spec schema is unsupported")
    action_ordinal = _integer(action_value["ordinal"], "action spec ordinal")
    if (
        action_ordinal >= len(actions)
        or actions[action_ordinal] != action_value
    ):
        raise StabilityError("action spec is not in its fixed cycle plan")
    if action_value["id"] != action_identity(
        plan_value["id"], action_ordinal,
        action_value["kind"], action_value["parameters"]
    ):
        raise StabilityError("action spec identity drift")

    source = Path(config_value["source"]["root"])
    scripts = source / "scripts"
    cycle_root = evidence_root / "cycles" / f"{cycle_ordinal:06d}"
    log_root = (
        cycle_root / "actions"
        / f"{action_ordinal:02d}-{action_value['kind']}"
    )
    stdout_path = log_root / "stdout.log"
    stderr_path = log_root / "stderr.log"
    python = "/usr/bin/python3"
    parameters = action_value["parameters"]
    kind = action_value["kind"]
    receipt_root: Path
    argv: list[str]

    if kind == "qualification":
        phase = parameters.get("phase") if isinstance(parameters, dict) else None
        if phase not in {"pre", "post"}:
            raise StabilityError("qualification action phase is malformed")
        receipt_root = cycle_root / "qualification" / phase
        qualification = config_value["qualification"]
        tools = qualification["tools"]
        argv = [
            python, "-B", os.fspath(scripts / "run_determinism_qualification.py"),
            "--manifest", os.fspath(scripts / "determinism_workloads.json"),
            "--baseline", os.fspath(scripts / "determinism_baseline.json"),
            "--baseline-authority-root", qualification["baseline_authority"]["root"],
            "--binary", config_value["analyzer"]["path"],
            "--repo-root", config_value["source"]["root"],
            "--build-path", config_value["build_authority"]["build_path"],
            "--revision", config_value["source"]["revision"],
            "--output", os.fspath(receipt_root),
            "--hardware-class", qualification["hardware_class"],
            "--measurement-cgroup", qualification["measurement_cgroup"],
            "--repetitions", "10",
            "--clang", tools["clang"],
            "--time-binary", tools["time"],
            "--cmake", tools["cmake"],
            "--ninja", tools["ninja"],
            "--c-compiler", tools["c_compiler"],
            "--cxx-compiler", tools["cxx_compiler"],
            "--release-source", qualification["release_source"],
            "--release-build", qualification["release_build"],
            "--jobs", "2",
            "--performance-policy", "required",
        ]
    elif kind == "fault-injection":
        parameter_value = _exact_dict(
            parameters, {"test_count"}, "fault-injection action parameters"
        )
        _fixed_integer(
            parameter_value["test_count"],
            len(fault_injection.CANONICAL_TESTS),
            "fault-injection test count",
        )
        receipt_root = cycle_root / "fault-injection"
        fault_config = config_value["fault_injection"]
        argv = [
            python,
            "-B",
            os.fspath(scripts / "run_stability_fault_injection.py"),
            "run",
            "--source-revision",
            config_value["source"]["revision"],
            "--binary",
            fault_config["test_binary"],
            "--binary-sha256",
            fault_config["test_binary_sha256"],
            "--output",
            os.fspath(receipt_root),
        ]
    elif kind == "realworld":
        parameter_value = _exact_dict(
            parameters,
            {
                "checkpoint_mode", "project", "repetition", "slot_index",
                "tier", "timeout_minutes",
            },
            "real-world action parameters",
        )
        project = parameter_value["project"]
        repetition = _integer(
            parameter_value["repetition"], "real-world action repetition", 1
        )
        slot = _integer(parameter_value["slot_index"], "real-world action slot")
        receipt_root = cycle_root / "realworld" / project / f"repeat-{repetition}"
        # Actions are strictly sequential. Every repetition of one project,
        # cold and warm, recreates the same absolute path so compile-command
        # plan hashes remain comparable and checkpoint-compatible. Checkpoints
        # remain repetition-specific outside the disposable workspace.
        workspace = runtime_root / "realworld" / "workspaces" / project
        checkpoint = (
            runtime_root / "realworld" / "checkpoints"
            / project / f"repeat-{repetition}" / "receipt.json"
        )
        argv = [
            python, "-B", os.fspath(scripts / "run_realworld_campaign.py"),
            "run",
            "--manifest", os.fspath(scripts / "realworld_manifest.json"),
            "--project", project,
            "--repetition", str(repetition),
            "--analyzer", config_value["analyzer"]["path"],
            "--workspace", os.fspath(workspace),
            "--output", os.fspath(receipt_root / "receipt.json"),
            "--checkpoint", os.fspath(checkpoint),
            "--tu-timeout-seconds", str(TU_TIMEOUT_SECONDS),
            "--tu-memory-mib", str(TU_MEMORY_MIB),
            "--mirror-authority", config_value["realworld"]["mirror_authority"],
            "--repository-root", config_value["source"]["root"],
        ]
    elif kind == "aggregate":
        parameter_value = _exact_dict(
            parameters, {"checkpoint_mode", "slot_count", "tier"},
            "aggregate action parameters",
        )
        if parameter_value["tier"] != "release-candidate":
            raise StabilityError("aggregate action tier drift")
        _fixed_integer(parameter_value["slot_count"], 9, "aggregate slot count")
        receipt_root = cycle_root / "realworld" / "aggregate"
        argv = [
            python, "-B", os.fspath(scripts / "run_realworld_campaign.py"),
            "aggregate",
            "--manifest", os.fspath(scripts / "realworld_manifest.json"),
            "--tier", "release-candidate",
            "--receipts", os.fspath(cycle_root / "realworld"),
            "--output", os.fspath(receipt_root / "receipt.json"),
        ]
    else:
        raise StabilityError("action spec kind is unsupported")
    return {
        "argv": argv,
        "cwd": source,
        "env": fixed_action_environment(runtime_root),
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "receipt_path": receipt_root / "receipt.json",
        "action_receipt_path": log_root / "receipt.json",
        "receipt_root": receipt_root,
        "log_root": log_root,
    }


def build_action_wrapper_spec(
    config: dict[str, Any],
    plan: dict[str, Any],
    action: dict[str, Any],
    *,
    config_path: Path = Path("/config/runtime.json"),
    plan_path: Path | None = None,
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
) -> dict[str, Any]:
    """Derive the supervised wrapper command for one immutable inner action."""

    config_value = validate_runtime_config(config)
    inner = build_action_spec(
        config_value,
        plan,
        action,
        evidence_root=evidence_root,
        runtime_root=runtime_root,
    )
    if config_path != Path("/config/runtime.json"):
        raise StabilityError("action wrapper config path differs from the fixed mount")
    expected_plan_path = (
        evidence_root / "cycles" / f"{plan['ordinal']:06d}" / "plan.json"
    )
    if plan_path is None:
        plan_path = expected_plan_path
    if plan_path != expected_plan_path:
        raise StabilityError("action wrapper plan path differs from its cycle")
    controller = Path(config_value["source"]["root"]) / "scripts" / (
        "run_stability_campaign.py"
    )
    return {
        "argv": [
            "/usr/bin/python3",
            "-B",
            controller.as_posix(),
            "_action",
            "--config",
            config_path.as_posix(),
            "--plan",
            plan_path.as_posix(),
            "--action-ordinal",
            str(action["ordinal"]),
            "--evidence",
            evidence_root.as_posix(),
            "--runtime",
            runtime_root.as_posix(),
        ],
        "cwd": inner["cwd"],
        "env": inner["env"],
        "stdout_path": inner["stdout_path"],
        "stderr_path": inner["stderr_path"],
        "receipt_path": inner["action_receipt_path"],
        "log_root": inner["log_root"],
    }


def _relative_evidence_path(path: Path, root: Path, label: str) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise StabilityError(f"{label} is outside the evidence root") from error
    value = relative.as_posix()
    if not value or value == "." or ".." in relative.parts:
        raise StabilityError(f"{label} is not an admissible evidence path")
    return value


def _validate_resource_projection(value: Any, label: str) -> dict[str, Any]:
    projection = _exact_dict(
        value,
        {
            "schema", "translation_units", "total_duration_ms",
            "maximum_duration_ms", "maximum_peak_memory_kib",
            "timeout_seconds", "memory_mib",
            "duration_budget_violations", "memory_budget_violations",
            "observations_sha256",
        },
        label,
    )
    if projection["schema"] != "codeskeptic-realworld-tu-resources-v1":
        raise StabilityError(f"{label} schema drift")
    units = _integer(
        projection["translation_units"], f"{label} translation units", 1
    )
    total = _integer(
        projection["total_duration_ms"], f"{label} total duration"
    )
    maximum = _integer(
        projection["maximum_duration_ms"], f"{label} maximum duration"
    )
    _integer(
        projection["maximum_peak_memory_kib"], f"{label} peak memory"
    )
    _fixed_integer(
        projection["timeout_seconds"], TU_TIMEOUT_SECONDS,
        f"{label} TU timeout",
    )
    _fixed_integer(
        projection["memory_mib"], TU_MEMORY_MIB,
        f"{label} TU memory",
    )
    if maximum > total and units > 1:
        raise StabilityError(f"{label} duration summary is inconsistent")
    for field in ("duration_budget_violations", "memory_budget_violations"):
        _fixed_integer(projection[field], 0, f"{label} {field}")
    _valid_sha(projection["observations_sha256"], f"{label} observations")
    return copy.deepcopy(projection)


def _validate_action_projection(
    projection: Any,
    config: dict[str, Any],
    action: dict[str, Any],
) -> dict[str, Any]:
    """Validate the compact result consumed by the cycle sealer.

    Full inner evidence is re-derived by the action wrapper and again by the
    terminal authority verifier.  This validator makes the intervening action
    receipt exact, bounded, and useful without treating it as substitute
    evidence.
    """

    kind = action["kind"]
    if kind == "qualification":
        value = _exact_dict(
            projection,
            {
                "schema", "source_revision", "source_manifest_sha256",
                "analyzer_sha256", "hardware_class", "manifest_sha256",
                "baseline_sha256", "performance_gate", "semantic_gate",
                "workload_count", "workloads", "semantic_sha256",
            },
            "qualification action projection",
        )
        if value["schema"] != DETERMINISM_PROJECTION_SCHEMA:
            raise StabilityError("qualification action projection schema drift")
        if (
            value["source_revision"] != config["source"]["revision"]
            or value["source_manifest_sha256"]
            != config["source"]["manifest_sha256"]
            or value["analyzer_sha256"] != config["analyzer"]["sha256"]
            or value["hardware_class"]
            != config["qualification"]["hardware_class"]
            or value["performance_gate"] != "pass"
            or value["semantic_gate"] != "pass"
        ):
            raise StabilityError("qualification action projection authority drift")
        for field in ("manifest_sha256", "baseline_sha256", "semantic_sha256"):
            _valid_sha(value[field], f"qualification action {field}")
        _fixed_integer(value["workload_count"], 3, "qualification workload count")
        workloads = value["workloads"]
        kinds = ["unit", "real-repository", "release-candidate"]
        if not isinstance(workloads, list) or len(workloads) != len(kinds):
            raise StabilityError("qualification action workload matrix drift")
        for expected_kind, raw in zip(kinds, workloads, strict=True):
            workload = _exact_dict(
                raw,
                {
                    "kind", "semantic_sha256", "input_identity_sha256",
                    "translation_unit_sha256",
                    "translation_unit_plan_sha256",
                },
                "qualification action workload",
            )
            if workload["kind"] != expected_kind:
                raise StabilityError("qualification action workload order drift")
            for field in (
                "semantic_sha256", "input_identity_sha256",
                "translation_unit_sha256", "translation_unit_plan_sha256",
            ):
                _valid_sha(workload[field], f"qualification workload {field}")
        return copy.deepcopy(value)

    if kind == "realworld":
        value = _exact_dict(
            projection,
            {
                "schema", "mode", "project", "repetition",
                "analyzer_sha256", "semantic_sha256", "requested_tus",
                "executed_tus", "checkpoint_tus", "resumed",
                "translation_unit_plan_sha256", "receipt_sha256",
                "duration_ms", "resources",
            },
            "real-world shard action projection",
        )
        if value["schema"] != REALWORLD_SHARD_PROJECTION_SCHEMA:
            raise StabilityError("real-world shard action projection schema drift")
        parameters = action["parameters"]
        if (
            value["mode"] != parameters["checkpoint_mode"]
            or value["project"] != parameters["project"]
            or value["repetition"] != parameters["repetition"]
            or value["analyzer_sha256"] != config["analyzer"]["sha256"]
        ):
            raise StabilityError("real-world shard action projection identity drift")
        requested = _integer(value["requested_tus"], "shard requested TU", 1)
        executed = _integer(value["executed_tus"], "shard executed TU")
        checkpoint = _integer(value["checkpoint_tus"], "shard checkpoint TU")
        if executed + checkpoint != requested:
            raise StabilityError("real-world shard action coverage drift")
        if type(value["resumed"]) is not bool:
            raise StabilityError("real-world shard resumed claim is malformed")
        if value["mode"] == "cold" and (
            checkpoint != 0 or executed != requested or value["resumed"] is not False
        ):
            raise StabilityError("cold real-world shard action used restart evidence")
        if value["mode"] == "warm" and (
            checkpoint != requested
            or executed != 0
            or value["resumed"] is not True
        ):
            raise StabilityError(
                "warm real-world shard action lacks complete restart evidence"
            )
        for field in (
            "semantic_sha256", "translation_unit_plan_sha256", "receipt_sha256",
        ):
            _valid_sha(value[field], f"real-world shard action {field}")
        _integer(value["duration_ms"], "real-world shard action duration")
        resources = _validate_resource_projection(
            value["resources"], "real-world shard action resources"
        )
        if resources["translation_units"] != requested:
            raise StabilityError(
                "real-world shard resource inventory differs from requested TUs"
            )
        return copy.deepcopy(value)

    if kind == "fault-injection":
        value = _exact_dict(
            projection,
            {
                "schema", "status", "source_revision", "test_binary_path",
                "test_binary_sha256", "receipt_sha256", "test_count", "tests",
            },
            "fault-injection action projection",
        )
        fault_config = config["fault_injection"]
        if (
            value["schema"] != FAULT_INJECTION_PROJECTION_SCHEMA
            or value["status"] != "pass"
            or value["source_revision"] != config["source"]["revision"]
            or value["test_binary_path"] != fault_config["test_binary"]
            or value["test_binary_sha256"]
            != fault_config["test_binary_sha256"]
            or value["tests"] != fault_injection.CANONICAL_TESTS
        ):
            raise StabilityError("fault-injection action projection authority drift")
        _fixed_integer(
            value["test_count"],
            len(fault_injection.CANONICAL_TESTS),
            "fault-injection action test count",
        )
        _valid_sha(
            value["receipt_sha256"], "fault-injection action receipt"
        )
        return copy.deepcopy(value)

    if kind == "aggregate":
        value = _exact_dict(
            projection,
            {
                "schema", "mode", "slot_count", "manifest_file_sha256",
                "manifest_identity_sha256", "aggregate_sha256",
                "analyzer_sha256", "requested_tus", "completed_tus",
                "executed_tus", "checkpoint_tus", "broken_tus",
                "missing_tus", "semantic_sha256",
                "translation_unit_plan_sha256", "duration_ms",
                "maximum_peak_memory_kib", "resource_observations_sha256",
                "shards",
            },
            "real-world aggregate action projection",
        )
        if (
            value["schema"] != REALWORLD_PROJECTION_SCHEMA
            or value["mode"] != action["parameters"]["checkpoint_mode"]
            or value["analyzer_sha256"] != config["analyzer"]["sha256"]
        ):
            raise StabilityError("real-world aggregate action projection identity drift")
        _fixed_integer(value["slot_count"], 9, "aggregate action slot count")
        requested = _integer(value["requested_tus"], "aggregate requested TU", 1)
        completed = _integer(value["completed_tus"], "aggregate completed TU")
        executed = _integer(value["executed_tus"], "aggregate executed TU")
        checkpoint = _integer(value["checkpoint_tus"], "aggregate checkpoint TU")
        broken = _integer(value["broken_tus"], "aggregate broken TU")
        missing = _integer(value["missing_tus"], "aggregate missing TU")
        if (
            completed != requested
            or executed + checkpoint != requested
            or broken != 0
            or missing != 0
        ):
            raise StabilityError("real-world aggregate action coverage drift")
        if value["mode"] == "cold" and checkpoint != 0:
            raise StabilityError("cold aggregate action used restart evidence")
        if value["mode"] == "warm" and (
            checkpoint != requested or executed != 0
        ):
            raise StabilityError(
                "warm aggregate action lacks complete restart evidence"
            )
        for field in (
            "manifest_file_sha256", "manifest_identity_sha256",
            "aggregate_sha256", "semantic_sha256",
            "translation_unit_plan_sha256", "resource_observations_sha256",
        ):
            _valid_sha(value[field], f"real-world aggregate action {field}")
        _integer(value["duration_ms"], "real-world aggregate action duration")
        _integer(
            value["maximum_peak_memory_kib"],
            "real-world aggregate action peak memory",
        )
        shards = value["shards"]
        if not isinstance(shards, list) or len(shards) != 9:
            raise StabilityError("real-world aggregate shard inventory drift")
        return copy.deepcopy(value)

    raise StabilityError("action projection kind is unsupported")


def build_action_receipt(
    config: dict[str, Any],
    plan: dict[str, Any],
    action: dict[str, Any],
    projection: Any,
    *,
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
) -> dict[str, Any]:
    """Bind one verified inner receipt to its immutable planned action."""

    config_value = validate_runtime_config(config)
    spec = build_action_spec(
        config_value,
        plan,
        action,
        evidence_root=evidence_root,
        runtime_root=runtime_root,
    )
    normalized_projection = _validate_action_projection(
        projection, config_value, action
    )
    if (
        action["kind"] == "fault-injection"
        and normalized_projection["receipt_sha256"]
        != sha256_file(spec["receipt_path"])
    ):
        raise StabilityError("fault-injection projection receipt checksum drift")
    inner_path = _relative_evidence_path(
        spec["receipt_path"], evidence_root, "action inner receipt"
    )
    return {
        "schema": ACTION_RECEIPT_SCHEMA,
        "status": "accepted",
        "failures": [],
        "identity": {
            "action_id": action["id"],
            "cycle_id": plan["id"],
            "cycle_ordinal": plan["ordinal"],
            "action_ordinal": action["ordinal"],
            "kind": action["kind"],
            "plan_sha256": plan["plan_sha256"],
        },
        "command": {
            "argv_sha256": digest_json(spec["argv"]),
            "cwd": spec["cwd"].as_posix(),
            "env_sha256": digest_json(spec["env"]),
        },
        "inner": {
            "receipt_path": inner_path,
            "receipt_sha256": sha256_file(spec["receipt_path"]),
            "projection": normalized_projection,
            "projection_sha256": digest_json(normalized_projection),
        },
    }


def verify_action_receipt(
    path: Path,
    config: dict[str, Any],
    plan: dict[str, Any],
    action: dict[str, Any],
    *,
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
) -> str:
    """Verify the sealed action claim without repeating long inner checks."""

    before = sha256_file(path)
    value = _load_document(path, "stability action receipt")
    exact = _exact_dict(
        value,
        {"schema", "status", "failures", "identity", "command", "inner"},
        "stability action receipt",
    )
    if (
        exact["schema"] != ACTION_RECEIPT_SCHEMA
        or exact["status"] != "accepted"
        or exact["failures"] != []
    ):
        raise StabilityError("stability action receipt is not accepted")
    expected = build_action_receipt(
        config,
        plan,
        action,
        exact.get("inner", {}).get("projection"),
        evidence_root=evidence_root,
        runtime_root=runtime_root,
    )
    if exact != expected:
        raise StabilityError("stability action receipt differs from its plan or inner receipt")
    after = sha256_file(path)
    if after != before:
        raise StabilityError("stability action receipt changed during verification")
    return before


def project_determinism_receipt(
    receipt: Any, expected: Any,
) -> dict[str, Any]:
    expected_value = _exact_dict(
        expected,
        {
            "source_revision", "source_manifest_sha256", "analyzer_sha256",
            "hardware_class", "manifest_sha256", "baseline_sha256",
        },
        "determinism projection authority",
    )
    value = receipt if isinstance(receipt, dict) else {}
    if value.get("schema") != "codeskeptic-determinism-qualification-v7":
        raise StabilityError("determinism receipt schema is unsupported")
    if value.get("status") != "accepted" or value.get("failures") != []:
        raise StabilityError("determinism receipt is not accepted")

    configuration = value.get("configuration")
    baseline = value.get("baseline")
    source = value.get("source")
    toolchain = value.get("toolchain")
    host = value.get("host")
    if not all(
        isinstance(item, dict)
        for item in (configuration, baseline, source, toolchain, host)
    ):
        raise StabilityError("determinism receipt authority fields are malformed")
    if (
        configuration.get("performance_policy") != "required"
        or configuration.get("repetitions") != 10
        or configuration.get("manifest_sha256")
        != expected_value["manifest_sha256"]
    ):
        raise StabilityError("determinism performance configuration drift")
    if (
        baseline.get("semantic_gate") != "pass"
        or baseline.get("performance_gate") != "pass"
        or baseline.get("regressions") != []
        or baseline.get("sha256") != expected_value["baseline_sha256"]
    ):
        raise StabilityError("determinism performance or semantic gate failed")
    if (
        source.get("revision") != expected_value["source_revision"]
        or source.get("manifest_sha256")
        != expected_value["source_manifest_sha256"]
    ):
        raise StabilityError("determinism source identity drift")
    analyzer = toolchain.get("analyzer")
    if (
        not isinstance(analyzer, dict)
        or analyzer.get("sha256") != expected_value["analyzer_sha256"]
    ):
        raise StabilityError("determinism analyzer identity drift")
    if host.get("class_id") != expected_value["hardware_class"]:
        raise StabilityError("determinism hardware identity drift")

    workloads = value.get("workloads")
    inputs = value.get("inputs")
    kinds = ["unit", "real-repository", "release-candidate"]
    if (
        not isinstance(workloads, list)
        or len(workloads) != len(kinds)
        or not isinstance(inputs, dict)
        or set(inputs) != set(kinds)
    ):
        raise StabilityError("determinism workload authority is incomplete")
    projection_workloads: list[dict[str, str]] = []
    for kind, workload in zip(kinds, workloads, strict=True):
        if not isinstance(workload, dict) or workload.get("kind") != kind:
            raise StabilityError("determinism workload order drift")
        input_record = inputs[kind]
        if not isinstance(input_record, dict) or input_record.get("kind") != kind:
            raise StabilityError("determinism input identity drift")
        projection_workloads.append({
            "kind": kind,
            "semantic_sha256": _valid_sha(
                workload.get("semantic_sha256"),
                f"determinism {kind} semantic",
            ),
            "input_identity_sha256": _valid_sha(
                input_record.get("identity_sha256"),
                f"determinism {kind} input identity",
            ),
            "translation_unit_sha256": _valid_sha(
                input_record.get("translation_unit_sha256"),
                f"determinism {kind} translation units",
            ),
            "translation_unit_plan_sha256": _valid_sha(
                input_record.get("translation_unit_plan_sha256"),
                f"determinism {kind} translation-unit plan",
            ),
        })
    semantic_material = {
        "schema": DETERMINISM_PROJECTION_SCHEMA,
        "workloads": projection_workloads,
    }
    return {
        "schema": DETERMINISM_PROJECTION_SCHEMA,
        "source_revision": expected_value["source_revision"],
        "source_manifest_sha256": expected_value["source_manifest_sha256"],
        "analyzer_sha256": expected_value["analyzer_sha256"],
        "hardware_class": expected_value["hardware_class"],
        "manifest_sha256": expected_value["manifest_sha256"],
        "baseline_sha256": expected_value["baseline_sha256"],
        "performance_gate": "pass",
        "semantic_gate": "pass",
        "workload_count": len(projection_workloads),
        "workloads": projection_workloads,
        "semantic_sha256": digest_json(semantic_material),
    }


def _accepted_ratio_gate(
    value: Any, *, label: str, threshold: int,
) -> dict[str, Any]:
    gate = _exact_dict(
        value, {"denominator", "numerator", "passed", "threshold_percent"},
        label,
    )
    denominator = _integer(gate["denominator"], f"{label} denominator", 1)
    numerator = _integer(gate["numerator"], f"{label} numerator")
    if (
        numerator > denominator
        or gate["passed"] is not True
        or gate["threshold_percent"] != threshold
        or numerator * 100 < threshold * denominator
    ):
        raise StabilityError(f"{label} is not accepted")
    return copy.deepcopy(gate)


def project_build_authority_receipt(
    receipt: Any, expected: Any,
) -> dict[str, Any]:
    expected_value = _exact_dict(
        expected,
        {"source_revision", "source_manifest_sha256", "analyzer_sha256"},
        "build authority projection inputs",
    )
    value = receipt if isinstance(receipt, dict) else {}
    if (
        value.get("schema") != "codeskeptic-analyzer-build-authority-v1"
        or value.get("status") != "accepted"
    ):
        raise StabilityError("analyzer build authority is not accepted")
    source = value.get("source")
    analyzer = value.get("analyzer")
    if not isinstance(source, dict) or not isinstance(analyzer, dict):
        raise StabilityError("analyzer build authority identity is malformed")
    if (
        source.get("revision") != expected_value["source_revision"]
        or source.get("manifest_sha256")
        != expected_value["source_manifest_sha256"]
        or analyzer.get("sha256") != expected_value["analyzer_sha256"]
    ):
        raise StabilityError("analyzer build authority identity drift")
    if analyzer.get("path") != "src/codeskeptic":
        raise StabilityError("analyzer build authority path drift")
    if not isinstance(analyzer.get("version"), str) or not analyzer["version"]:
        raise StabilityError("analyzer build authority version is malformed")
    build_identity = _valid_sha(
        value.get("build_identity_sha256"), "analyzer build identity"
    )
    return {
        "schema": BUILD_AUTHORITY_PROJECTION_SCHEMA,
        "source_revision": expected_value["source_revision"],
        "source_manifest_sha256": expected_value["source_manifest_sha256"],
        "analyzer_sha256": expected_value["analyzer_sha256"],
        "analyzer_version": analyzer["version"],
        "build_identity_sha256": build_identity,
    }


def project_quality_floor_receipt(
    receipt: Any, expected: Any,
) -> dict[str, Any]:
    expected_value = _exact_dict(
        expected,
        {"source_revision", "source_manifest_sha256", "analyzer_sha256"},
        "quality-floor projection inputs",
    )
    value = receipt if isinstance(receipt, dict) else {}
    if (
        value.get("schema") != "codeskeptic-quality-floor-receipt-v1"
        or value.get("status") != "accepted"
        or value.get("availability") != "available"
        or value.get("failures") != []
    ):
        raise StabilityError("quality-floor receipt is not accepted")
    identity = value.get("identity")
    metrics = value.get("metrics")
    if not isinstance(identity, dict) or not isinstance(metrics, dict):
        raise StabilityError("quality-floor authority is malformed")
    source = identity.get("source")
    analyzer = identity.get("analyzer")
    if not isinstance(source, dict) or not isinstance(analyzer, dict):
        raise StabilityError("quality-floor identity is malformed")
    if (
        source.get("revision") != expected_value["source_revision"]
        or source.get("manifest_sha256")
        != expected_value["source_manifest_sha256"]
        or analyzer.get("binary_sha256") != expected_value["analyzer_sha256"]
    ):
        raise StabilityError("quality-floor identity drift")

    metric_value = _exact_dict(
        metrics,
        {
            "addressable_recall", "clean_corpus", "micro_precision",
            "requested_tu_negatives", "rules",
        },
        "quality-floor metrics",
    )
    precision = _accepted_ratio_gate(
        metric_value["micro_precision"],
        label="quality-floor micro precision",
        threshold=90,
    )
    recall_raw = _exact_dict(
        metric_value["addressable_recall"],
        {
            "addressable_false_negatives", "denominator", "numerator",
            "passed", "threshold_percent",
        },
        "quality-floor addressable recall",
    )
    recall = _accepted_ratio_gate(
        {
            key: recall_raw[key]
            for key in ("denominator", "numerator", "passed", "threshold_percent")
        },
        label="quality-floor addressable recall",
        threshold=70,
    )
    false_negatives = _integer(
        recall_raw["addressable_false_negatives"],
        "quality-floor addressable false negatives",
    )
    if recall["numerator"] + false_negatives != recall["denominator"]:
        raise StabilityError("quality-floor recall accounting drift")
    clean = _exact_dict(
        metric_value["clean_corpus"],
        {"accepted_cases", "passed", "required_cases"},
        "quality-floor clean corpus",
    )
    accepted_clean = _integer(
        clean["accepted_cases"], "quality-floor accepted clean cases", 1
    )
    required_clean = _integer(
        clean["required_cases"], "quality-floor required clean cases", 1
    )
    if clean["passed"] is not True or accepted_clean != required_clean:
        raise StabilityError("quality-floor clean corpus is not accepted")
    negatives = _exact_dict(
        metric_value["requested_tu_negatives"],
        {"accepted_cases", "passed", "required_kinds"},
        "quality-floor requested-TU negatives",
    )
    if (
        negatives["passed"] is not True
        or negatives["accepted_cases"] != 2
        or negatives["required_kinds"] != ["broken", "missing"]
    ):
        raise StabilityError("quality-floor requested-TU negatives failed")

    rules = metric_value["rules"]
    if not isinstance(rules, list) or len(rules) != len(REQUIRED_DEFAULT_RULES):
        raise StabilityError("quality-floor default-rule matrix is incomplete")
    rule_projections: list[dict[str, Any]] = []
    for expected_rule, raw_rule in zip(REQUIRED_DEFAULT_RULES, rules, strict=True):
        rule = _exact_dict(
            raw_rule,
            {"case_recall_components", "diagnostic_precision", "id"},
            "quality-floor default rule",
        )
        if rule["id"] != expected_rule:
            raise StabilityError("quality-floor default-rule order drift")
        diagnostic = _accepted_ratio_gate(
            rule["diagnostic_precision"],
            label=f"quality-floor {expected_rule} precision",
            threshold=85,
        )
        components = _exact_dict(
            rule["case_recall_components"],
            {"addressable_false_negatives", "case_true_positives"},
            f"quality-floor {expected_rule} recall components",
        )
        for field in ("addressable_false_negatives", "case_true_positives"):
            _integer(components[field], f"quality-floor {expected_rule} {field}")
        rule_projections.append({
            "id": expected_rule,
            "diagnostic_precision": diagnostic,
            "case_recall_components": copy.deepcopy(components),
        })

    retained = identity.get("retained_artifacts")
    verification = value.get("retained_artifact_verification")
    if not isinstance(retained, dict) or not isinstance(verification, dict):
        raise StabilityError("quality-floor retained artifact authority drift")
    retained_value = _exact_dict(
        retained, {"file_count", "manifest_path", "manifest_sha256"},
        "quality-floor retained artifacts",
    )
    verification_value = _exact_dict(
        verification,
        {"evidence_file_count", "file_count", "manifest_path", "manifest_sha256"},
        "quality-floor retained artifact verification",
    )
    if any(
        verification_value[field] != retained_value[field]
        for field in ("file_count", "manifest_path", "manifest_sha256")
    ):
        raise StabilityError("quality-floor retained artifact authority drift")
    _integer(
        verification_value["evidence_file_count"],
        "quality-floor retained evidence file count",
        1,
    )
    _integer(retained_value["file_count"], "quality-floor artifact count", 1)
    if retained_value["manifest_path"] != "RAW_SHA256SUMS":
        raise StabilityError("quality-floor artifact manifest path drift")
    _valid_sha(retained_value["manifest_sha256"], "quality-floor artifact manifest")
    projection_metrics = {
        "micro_precision": precision,
        "addressable_recall": {**recall, "addressable_false_negatives": false_negatives},
        "clean_corpus": copy.deepcopy(clean),
        "requested_tu_negatives": copy.deepcopy(negatives),
        "rules": rule_projections,
    }
    return {
        "schema": QUALITY_FLOOR_PROJECTION_SCHEMA,
        "source_revision": expected_value["source_revision"],
        "source_manifest_sha256": expected_value["source_manifest_sha256"],
        "analyzer_sha256": expected_value["analyzer_sha256"],
        "metrics_sha256": digest_json(projection_metrics),
        "retained_artifact_manifest_sha256": retained_value["manifest_sha256"],
    }


def project_sanitizer_receipt(
    receipt: Any, expected: Any,
) -> dict[str, Any]:
    expected_value = _exact_dict(
        expected, {"profile", "source_revision", "source_manifest_sha256"},
        "sanitizer projection inputs",
    )
    if expected_value["profile"] not in {"address", "undefined"}:
        raise StabilityError("sanitizer profile is unsupported")
    value = receipt if isinstance(receipt, dict) else {}
    if (
        value.get("schema") != "codeskeptic-sanitizer-receipt-v1"
        or value.get("status") != "accepted"
        or value.get("profile") != expected_value["profile"]
        or value.get("failures") != []
    ):
        raise StabilityError("sanitizer receipt is not accepted")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {"base_commit", "manifest"}:
        raise StabilityError("sanitizer source identity is malformed")
    manifest = _exact_dict(
        source["manifest"], {"algorithm", "digest", "file_count"},
        "sanitizer source manifest",
    )
    if (
        source["base_commit"] != expected_value["source_revision"]
        or manifest["algorithm"] != "sha256"
        or manifest["digest"] != expected_value["source_manifest_sha256"]
    ):
        raise StabilityError("sanitizer source identity drift")
    _integer(manifest["file_count"], "sanitizer source file count", 1)
    builds = value.get("builds")
    if not isinstance(builds, dict) or set(builds) != {"tests", "fuzz"}:
        raise StabilityError("sanitizer build authority is incomplete")
    tests_build = builds["tests"]
    if not isinstance(tests_build, dict):
        raise StabilityError("sanitizer test-build authority is malformed")
    test_binaries = tests_build.get("binaries")
    if not isinstance(test_binaries, dict):
        raise StabilityError("sanitizer test binary authority is malformed")
    test_binary_sha = _valid_sha(
        test_binaries.get("tests/codeskeptic_tests"),
        "sanitizer codeskeptic_tests binary",
    )
    try:
        builds_sha = digest_json(builds)
    except (TypeError, ValueError) as error:
        raise StabilityError("sanitizer build authority is malformed") from error
    expected_preparation = [
        "configure_tests", "configure_fuzz", "build_tests", "build_fuzz"
    ]
    preparation = value.get("preparation")
    if (
        not isinstance(preparation, list)
        or [item.get("name") for item in preparation if isinstance(item, dict)]
        != expected_preparation
        or any(item.get("exit_code") != 0 for item in preparation)
    ):
        raise StabilityError("sanitizer preparation matrix failed")
    expected_gate_codes = {
        "focused_serial_worker": 0,
        "ctest_complete": 0,
        "single_process_complete": 0,
        "analyzer_clean": 0,
        "analyzer_finding": 1,
        "analyzer_invalid_input": 2,
        "analyzer_whole_program": 0,
        "mcp_sequential": 0,
        "fuzz_smoke": 0,
    }
    expected_gate_names = {"runtime_tripwire", *expected_gate_codes}
    gates = value.get("gates")
    if not isinstance(gates, list) or len(gates) != len(expected_gate_names):
        raise StabilityError("sanitizer gate matrix is incomplete")
    observed_gate_codes: dict[str, Any] = {}
    for gate in gates:
        if not isinstance(gate, dict):
            raise StabilityError("sanitizer gate record is malformed")
        name = gate.get("name")
        if not isinstance(name, str) or name not in expected_gate_names:
            raise StabilityError("sanitizer gate matrix failed")
        if name in observed_gate_codes:
            raise StabilityError("sanitizer gate matrix contains duplicates")
        observed_gate_codes[name] = gate.get("exit_code")
    tripwire_code = observed_gate_codes.get("runtime_tripwire")
    if (
        set(observed_gate_codes) != expected_gate_names
        or type(tripwire_code) is not int
        or tripwire_code == 0
        or any(
            type(observed_gate_codes.get(name)) is not int
            or observed_gate_codes.get(name) != code
            for name, code in expected_gate_codes.items()
        )
    ):
        raise StabilityError("sanitizer gate matrix failed")
    tsan = value.get("tsan")
    if (
        not isinstance(tsan, dict)
        or tsan.get("joined") is not True
        or tsan.get("max_active") != 1
        or tsan.get("worker_threads") != 1
    ):
        raise StabilityError("sanitizer serial-worker authority failed")
    return {
        "schema": SANITIZER_PROJECTION_SCHEMA,
        "profile": expected_value["profile"],
        "source_revision": expected_value["source_revision"],
        "source_manifest_sha256": expected_value["source_manifest_sha256"],
        "builds_sha256": builds_sha,
        "test_binary_sha256": test_binary_sha,
        "gate_matrix_sha256": digest_json(observed_gate_codes),
    }


def _https_url(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("https://"):
        raise StabilityError(f"{label} URL is malformed")
    return value


def _evidence_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StabilityError(f"{label} path is malformed")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise StabilityError(f"{label} path is inadmissible")
    return value


def project_hosted_exact_head_receipt(
    receipt: Any, *, repository: str, revision: str,
) -> dict[str, Any]:
    if not isinstance(repository, str) or not repository or "\x00" in repository:
        raise StabilityError("hosted repository identity is malformed")
    if not isinstance(revision, str) or GIT_SHA1.fullmatch(revision) is None:
        raise StabilityError("hosted source revision is malformed")
    value = _exact_dict(
        receipt,
        {
            "schema", "status", "failures", "source", "required_gates",
            "gates", "runs", "logs", "artifacts", "snapshots",
        },
        "hosted exact-head receipt",
    )
    if (
        value["schema"] != HOSTED_EXACT_HEAD_SCHEMA
        or value["status"] != "accepted"
        or value["failures"] != []
    ):
        raise StabilityError("hosted exact-head receipt is not accepted")
    source = _exact_dict(
        value["source"], {"repository", "revision", "tree_sha1"},
        "hosted source",
    )
    if (
        source.get("repository") != repository
        or source.get("revision") != revision
        or not isinstance(source.get("tree_sha1"), str)
        or GIT_SHA1.fullmatch(source["tree_sha1"]) is None
    ):
        raise StabilityError("hosted exact-head source identity drift")
    if value["required_gates"] != REQUIRED_HOSTED_GATES:
        raise StabilityError("hosted required-gate policy drift")

    runs = value["runs"]
    if not isinstance(runs, list) or not runs:
        raise StabilityError("hosted workflow run authority is empty")
    run_ids: set[int] = set()
    normalized_runs: list[dict[str, Any]] = []
    for raw in runs:
        run = _exact_dict(
            raw,
            {
                "workflow_path", "workflow_file_sha256", "run_id",
                "run_attempt", "event", "head_sha", "conclusion", "url",
            },
            "hosted workflow run",
        )
        run_id = _integer(run["run_id"], "hosted workflow run ID", 1)
        if run_id in run_ids:
            raise StabilityError("hosted workflow run IDs are duplicated")
        run_ids.add(run_id)
        _integer(run["run_attempt"], "hosted workflow run attempt", 1)
        _evidence_relative(run["workflow_path"], "hosted workflow")
        _valid_sha(run["workflow_file_sha256"], "hosted workflow file")
        if (
            run["head_sha"] != revision
            or run["conclusion"] != "success"
            or run["event"] not in {"push", "workflow_dispatch"}
        ):
            raise StabilityError("hosted workflow run is not exact-head success")
        _https_url(run["url"], "hosted workflow run")
        normalized_runs.append(copy.deepcopy(run))

    gates = value["gates"]
    if not isinstance(gates, list) or len(gates) != len(REQUIRED_HOSTED_GATES):
        raise StabilityError("hosted gate matrix is incomplete")
    normalized_gates: list[dict[str, Any]] = []
    check_ids: set[int] = set()
    for expected_gate, raw in zip(REQUIRED_HOSTED_GATES, gates, strict=True):
        gate = _exact_dict(
            raw,
            {
                "gate_id", "provider_name", "check_run_id", "conclusion",
                "url", "workflow_run_id", "status_ref", "status_ref_target",
            },
            "hosted gate",
        )
        check_id = _integer(gate["check_run_id"], "hosted check-run ID", 1)
        workflow_run_id = _integer(
            gate["workflow_run_id"], "hosted gate workflow run ID", 1
        )
        if check_id in check_ids:
            raise StabilityError("hosted check-run IDs are duplicated")
        check_ids.add(check_id)
        if (
            gate["gate_id"] != expected_gate
            or gate["provider_name"] != "github-actions"
            or gate["conclusion"] != "success"
            or workflow_run_id not in run_ids
            or gate["status_ref"]
            != f"refs/status/{revision}/{expected_gate}/success"
            or gate["status_ref_target"] != revision
        ):
            raise StabilityError("hosted gate is not an exact-head success")
        _https_url(gate["url"], "hosted gate")
        normalized_gates.append(copy.deepcopy(gate))

    logs = value["logs"]
    if not isinstance(logs, list) or not logs:
        raise StabilityError("hosted retained logs are empty")
    log_runs: set[int] = set()
    normalized_logs: list[dict[str, Any]] = []
    for raw in logs:
        record = _exact_dict(
            raw, {"run_id", "path", "sha256", "size"}, "hosted retained log"
        )
        run_id = _integer(record["run_id"], "hosted retained log run ID", 1)
        if run_id not in run_ids:
            raise StabilityError("hosted retained log has an unknown run")
        log_runs.add(run_id)
        _evidence_relative(record["path"], "hosted retained log")
        _valid_sha(record["sha256"], "hosted retained log")
        _integer(record["size"], "hosted retained log size", 1)
        normalized_logs.append(copy.deepcopy(record))
    if log_runs != run_ids:
        raise StabilityError("hosted retained logs do not cover every workflow run")

    artifacts = value["artifacts"]
    if not isinstance(artifacts, list):
        raise StabilityError("hosted artifact inventory is malformed")
    artifact_ids: set[int] = set()
    normalized_artifacts: list[dict[str, Any]] = []
    for raw in artifacts:
        record = _exact_dict(
            raw,
            {
                "id", "name", "provider_digest", "url", "archive_path",
                "archive_sha256", "size", "run_id",
            },
            "hosted artifact",
        )
        artifact_id = _integer(record["id"], "hosted artifact ID", 1)
        run_id = _integer(record["run_id"], "hosted artifact run ID", 1)
        if artifact_id in artifact_ids or run_id not in run_ids:
            raise StabilityError("hosted artifact identity is invalid")
        artifact_ids.add(artifact_id)
        if not isinstance(record["name"], str) or not record["name"]:
            raise StabilityError("hosted artifact name is malformed")
        _valid_sha(record["provider_digest"], "hosted provider artifact digest")
        _https_url(record["url"], "hosted artifact")
        _evidence_relative(record["archive_path"], "hosted artifact archive")
        _valid_sha(record["archive_sha256"], "hosted artifact archive")
        _integer(record["size"], "hosted artifact size", 1)
        normalized_artifacts.append(copy.deepcopy(record))
    snapshots = value["snapshots"]
    if not isinstance(snapshots, list) or not snapshots:
        raise StabilityError("hosted raw authority snapshots are empty")
    normalized_snapshots: list[dict[str, Any]] = []
    for raw in snapshots:
        record = _exact_dict(
            raw, {"path", "sha256", "size"}, "hosted raw authority snapshot"
        )
        _evidence_relative(record["path"], "hosted raw authority snapshot")
        _valid_sha(record["sha256"], "hosted raw authority snapshot")
        _integer(record["size"], "hosted raw authority snapshot size", 1)
        normalized_snapshots.append(copy.deepcopy(record))
    return {
        "schema": HOSTED_EXACT_HEAD_PROJECTION_SCHEMA,
        "repository": repository,
        "revision": revision,
        "gate_count": len(normalized_gates),
        "workflow_run_count": len(normalized_runs),
        "gates_sha256": digest_json(normalized_gates),
        "runs_sha256": digest_json(normalized_runs),
        "logs_sha256": digest_json(normalized_logs),
        "artifacts_sha256": digest_json(normalized_artifacts),
        "snapshots_sha256": digest_json(normalized_snapshots),
        "source_tree_sha1": source["tree_sha1"],
    }


def verify_determinism_evidence(
    evidence_root: Path,
    manifest_path: Path,
    baseline_path: Path,
    repository_root: Path,
    baseline_authority_root: Path,
    expected: dict[str, Any],
    *,
    verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    receipt_path = evidence_root / "receipt.json"
    receipt_before = sha256_file(receipt_path)
    if verifier is None:
        try:
            import run_determinism_qualification as determinism
        except ImportError as error:
            raise StabilityError(
                f"determinism authority verifier is unavailable: {error}"
            ) from error
        verifier = determinism.verify_receipt
    try:
        receipt = verifier(
            evidence_root,
            manifest_path,
            baseline_path,
            repository_root,
            baseline_authority_root,
        )
    except Exception as error:
        raise StabilityError(
            f"determinism authority verification failed: {error}"
        ) from error
    receipt_after = sha256_file(receipt_path)
    if receipt_after != receipt_before:
        raise StabilityError("determinism receipt changed during verification")
    projection = project_determinism_receipt(receipt, expected)
    return {
        "receipt_sha256": receipt_before,
        "projection": projection,
    }


def verify_realworld_shard(
    manifest_path: Path,
    receipt_path: Path,
    *,
    project_id: str,
    repetition: Any,
    expected_analyzer_sha256: str,
    mode: str,
) -> dict[str, Any]:
    """Re-derive one retained shard before its action receipt is sealed."""

    if mode not in {"cold", "warm"}:
        raise StabilityError("real-world shard mode is malformed")
    repetition_value = _integer(repetition, "real-world shard repetition", 1)
    if repetition_value > 3:
        raise StabilityError("real-world shard repetition is outside the fixed matrix")
    analyzer_sha = _valid_sha(
        expected_analyzer_sha256, "real-world shard expected analyzer"
    )
    shard_root = receipt_path.parent
    bundle_before = directory_identity(shard_root, "real-world shard evidence")
    before = sha256_file(receipt_path)
    try:
        manifest = realworld.validate_manifest(
            realworld.load_manifest(manifest_path)
        )
        campaign = manifest["campaigns"].get("release-candidate")
        if (
            not isinstance(campaign, dict)
            or campaign.get("projects") != REQUIRED_MATRIX_PROJECTS
            or campaign.get("repetitions") != 3
            or project_id not in REQUIRED_MATRIX_PROJECTS
        ):
            raise realworld.EvidenceError(
                "real-world shard is outside the exact release-candidate matrix"
            )
        project = realworld.project_by_id(manifest, project_id)
        receipt = realworld.load_verified_receipt(receipt_path)
        if set(receipt) != {
            "schema", "status", "project", "repetition", "identity",
            "semantic", "execution", "failures",
        }:
            raise realworld.EvidenceError("real-world shard receipt shape drift")
        if (
            receipt.get("status") != "accepted"
            or receipt.get("project") != project_id
            or receipt.get("repetition") != repetition_value
            or receipt.get("failures") != []
        ):
            raise realworld.EvidenceError("real-world shard is not accepted")
        expected_identity = realworld.receipt_identity(
            manifest,
            project,
            repetition_value,
            analyzer_sha,
            project["expected"]["translation_unit_sha256"],
        )
        if receipt.get("identity") != expected_identity:
            raise realworld.EvidenceError("real-world shard identity drift")
        semantic = receipt.get("semantic")
        realworld._validate_semantic(project, semantic)  # noqa: SLF001
        plan = realworld._validate_execution(  # noqa: SLF001
            project, semantic, receipt.get("execution"), require_plan=True
        )
        report = _load_json(shard_root / "report.json", "real-world shard report")
        path_data = _read_regular_bytes(
            shard_root / "translation-units.txt", MAX_DOCUMENT_BYTES
        )
        try:
            path_text = path_data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise realworld.EvidenceError(
                "real-world translation-unit inventory is not UTF-8"
            ) from error
        path_lines = path_text.splitlines()
        if (
            not path_lines
            or any(not line or "\x00" in line for line in path_lines)
            or path_data != ("\n".join(path_lines) + "\n").encode("utf-8")
        ):
            raise realworld.EvidenceError(
                "real-world translation-unit inventory is malformed"
            )
        expected_paths = [Path(line) for line in path_lines]
        rederived_semantic = realworld.semantic_from_report(
            project,
            semantic["exit_code"],
            report,
            semantic["translation_units"]["count"],
            semantic["translation_units"]["sha256"],
            expected_timeout_seconds=TU_TIMEOUT_SECONDS,
            expected_memory_mib=TU_MEMORY_MIB,
        )
        if rederived_semantic != semantic:
            raise realworld.EvidenceError(
                "real-world shard semantic differs from retained report"
            )
        rederived_plan = realworld.translation_unit_plan(
            report,
            semantic["translation_units"]["count"],
            semantic["coverage"]["analyzed_tus"],
            expected_paths,
            whole_program="--whole-program" in project["analyzer_args"],
            expected_timeout_seconds=TU_TIMEOUT_SECONDS,
            expected_memory_mib=TU_MEMORY_MIB,
        )
        if rederived_plan != plan:
            raise realworld.EvidenceError(
                "real-world shard plan differs from retained report"
            )
        resources = realworld.translation_unit_resource_summary(
            report,
            expected_timeout_seconds=TU_TIMEOUT_SECONDS,
            expected_memory_mib=TU_MEMORY_MIB,
        )
    except realworld.CampaignError as error:
        raise StabilityError(
            f"real-world shard authority verification failed: {error}"
        ) from error
    if plan is None:
        raise StabilityError("real-world shard translation-unit plan is unavailable")
    resumed = receipt["execution"]["resumed"]
    requested = plan["count"]
    executed = plan["executed"]
    checkpoint = plan["checkpoint"]
    if mode == "cold" and (
        checkpoint != 0 or executed != requested or resumed is not False
    ):
        raise StabilityError("cold real-world shard used restart evidence")
    if mode == "warm" and (
        checkpoint != requested or executed != 0 or resumed is not True
    ):
        raise StabilityError(
            "warm real-world shard lacks complete restart evidence"
        )
    after = sha256_file(receipt_path)
    if after != before:
        raise StabilityError("real-world shard receipt changed during verification")
    if directory_identity(
        shard_root, "real-world shard evidence"
    ) != bundle_before:
        raise StabilityError("real-world shard evidence changed during verification")
    duration_seconds = receipt["execution"]["duration_seconds"]
    duration_ms = int(round(duration_seconds * 1000))
    return {
        "schema": REALWORLD_SHARD_PROJECTION_SCHEMA,
        "mode": mode,
        "project": project_id,
        "repetition": repetition_value,
        "analyzer_sha256": analyzer_sha,
        "semantic_sha256": digest_json(semantic),
        "requested_tus": requested,
        "executed_tus": executed,
        "checkpoint_tus": checkpoint,
        "resumed": resumed,
        "translation_unit_plan_sha256": plan["sha256"],
        "receipt_sha256": before,
        "duration_ms": duration_ms,
        "resources": resources,
    }


def verify_realworld_cycle(
    manifest_path: Path,
    tier: str,
    receipt_root: Path,
    aggregate_path: Path,
    *,
    expected_analyzer_sha256: str,
    mode: str,
) -> dict[str, Any]:
    analyzer_sha = _valid_sha(
        expected_analyzer_sha256, "real-world expected analyzer"
    )
    if mode not in {"cold", "warm"}:
        raise StabilityError("real-world cycle mode is malformed")
    try:
        manifest = realworld.validate_manifest(
            realworld.load_manifest(manifest_path)
        )
        recomputed = realworld.aggregate_receipts(
            manifest, tier, receipt_root
        )
        retained = realworld.load_verified_receipt(aggregate_path)
    except realworld.CampaignError as error:
        raise StabilityError(
            f"real-world authority verification failed: {error}"
        ) from error
    if retained != recomputed:
        raise StabilityError("real-world aggregate differs from its nine shards")
    if (
        retained.get("status") != "accepted"
        or retained.get("campaign") != tier
        or retained.get("manifest_sha256") != realworld.digest_json(manifest)
        or not isinstance(retained.get("projects"), dict)
    ):
        raise StabilityError("real-world aggregate authority is malformed")

    campaign = manifest["campaigns"].get(tier)
    if (
        not isinstance(campaign, dict)
        or campaign.get("projects") != REQUIRED_MATRIX_PROJECTS
        or campaign.get("repetitions") != 3
    ):
        raise StabilityError("real-world aggregate is not the exact 3x3 matrix")
    requested_total = 0
    completed_total = 0
    executed_total = 0
    checkpoint_total = 0
    broken_total = 0
    duration_total = 0
    maximum_peak_memory = 0
    shard_records: list[dict[str, Any]] = []
    plan_material: list[dict[str, Any]] = []
    resource_material: list[dict[str, Any]] = []
    semantic_projects: list[dict[str, Any]] = []
    for project_id in REQUIRED_MATRIX_PROJECTS:
        project_summary = retained["projects"].get(project_id)
        if (
            not isinstance(project_summary, dict)
            or project_summary.get("analyzer_sha256") != analyzer_sha
        ):
            raise StabilityError("real-world aggregate analyzer identity drift")
        semantic_projects.append({
            "project": project_id,
            "summary": copy.deepcopy(project_summary),
        })
        for repetition in (1, 2, 3):
            path = (
                receipt_root / project_id / f"repeat-{repetition}"
                / "receipt.json"
            )
            try:
                receipt = realworld.load_verified_receipt(path)
            except realworld.CampaignError as error:
                raise StabilityError(
                    f"real-world shard authority failed: {error}"
                ) from error
            identity = receipt.get("identity")
            semantic = receipt.get("semantic")
            execution = receipt.get("execution")
            if not all(
                isinstance(item, dict)
                for item in (identity, semantic, execution)
            ):
                raise StabilityError("real-world shard authority is malformed")
            if identity.get("analyzer_sha256") != analyzer_sha:
                raise StabilityError("real-world shard analyzer identity drift")
            shard_projection = verify_realworld_shard(
                manifest_path,
                path,
                project_id=project_id,
                repetition=repetition,
                expected_analyzer_sha256=analyzer_sha,
                mode=mode,
            )
            coverage = semantic.get("coverage")
            plan = execution.get("translation_unit_plan")
            if not isinstance(coverage, dict) or not isinstance(plan, dict):
                raise StabilityError("real-world shard coverage is malformed")
            count = shard_projection["requested_tus"]
            executed = shard_projection["executed_tus"]
            checkpoint = shard_projection["checkpoint_tus"]
            if executed + checkpoint != count:
                raise StabilityError("real-world shard TU coverage is incomplete")
            if mode == "cold" and (
                checkpoint != 0
                or executed != count
                or execution.get("resumed") is not False
            ):
                raise StabilityError("cold real-world shard used restart evidence")
            if mode == "warm" and (
                checkpoint != count
                or executed != 0
                or execution.get("resumed") is not True
            ):
                raise StabilityError(
                    "warm real-world shard lacks complete restart evidence"
                )
            broken = _integer(
                coverage.get("broken_tus"), "real-world broken TU"
            )
            if broken != 0:
                raise StabilityError("real-world shard has broken TU coverage")
            plan_sha = shard_projection["translation_unit_plan_sha256"]
            resources = shard_projection["resources"]
            duration_ms = shard_projection["duration_ms"]
            requested_total += count
            completed_total += executed + checkpoint
            executed_total += executed
            checkpoint_total += checkpoint
            broken_total += broken
            duration_total += duration_ms
            maximum_peak_memory = max(
                maximum_peak_memory,
                resources["maximum_peak_memory_kib"],
            )
            plan_material.append({
                "project": project_id,
                "repetition": repetition,
                "count": count,
                "sha256": plan_sha,
            })
            shard_records.append({
                "project": project_id,
                "repetition": repetition,
                "path": path.as_posix(),
                "sha256": sha256_file(path),
                "requested_tus": count,
                "executed_tus": executed,
                "checkpoint_tus": checkpoint,
                "duration_ms": duration_ms,
                "resources": copy.deepcopy(resources),
            })
            resource_material.append({
                "project": project_id,
                "repetition": repetition,
                "duration_ms": duration_ms,
                "resources": copy.deepcopy(resources),
            })
    missing_total = requested_total - completed_total
    if missing_total != 0:
        raise StabilityError("real-world cycle has missing TU coverage")
    semantic_material = {
        "schema": REALWORLD_PROJECTION_SCHEMA,
        "projects": semantic_projects,
    }
    plan_projection = {
        "schema": "codeskeptic-stability-realworld-plan-v1",
        "plans": plan_material,
    }
    return {
        "schema": REALWORLD_PROJECTION_SCHEMA,
        "mode": mode,
        "slot_count": len(shard_records),
        "manifest_file_sha256": sha256_file(manifest_path),
        "manifest_identity_sha256": realworld.digest_json(manifest),
        "aggregate_sha256": sha256_file(aggregate_path),
        "analyzer_sha256": analyzer_sha,
        "requested_tus": requested_total,
        "completed_tus": completed_total,
        "executed_tus": executed_total,
        "checkpoint_tus": checkpoint_total,
        "broken_tus": broken_total,
        "missing_tus": missing_total,
        "semantic_sha256": digest_json(semantic_material),
        "translation_unit_plan_sha256": digest_json(plan_projection),
        "duration_ms": duration_total,
        "maximum_peak_memory_kib": maximum_peak_memory,
        "resource_observations_sha256": digest_json(resource_material),
        "shards": shard_records,
    }


def _default_action_command_executor(
    argv: list[str], cwd: Path, env: dict[str, str],
) -> int:
    """Run below the already-supervised wrapper process group."""

    try:
        result = subprocess.run(
            argv,
            cwd=os.fspath(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise StabilityError(f"cannot execute planned inner action: {error}") from error
    if type(result.returncode) is not int:
        raise StabilityError("planned inner action returned a malformed exit code")
    return result.returncode


def verify_planned_action_projection(
    config: dict[str, Any],
    plan: dict[str, Any],
    action: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    """Perform the long semantic verification while the wrapper stays alive."""

    source = Path(config["source"]["root"])
    scripts = source / "scripts"
    kind = action["kind"]
    if kind == "qualification":
        expected = {
            "source_revision": config["source"]["revision"],
            "source_manifest_sha256": config["source"]["manifest_sha256"],
            "analyzer_sha256": config["analyzer"]["sha256"],
            "hardware_class": config["qualification"]["hardware_class"],
            "manifest_sha256": sha256_file(
                scripts / "determinism_workloads.json"
            ),
            "baseline_sha256": sha256_file(
                scripts / "determinism_baseline.json"
            ),
        }
        verified = verify_determinism_evidence(
            spec["receipt_root"],
            scripts / "determinism_workloads.json",
            scripts / "determinism_baseline.json",
            source,
            Path(config["qualification"]["baseline_authority"]["root"]),
            expected,
        )
        return verified["projection"]
    if kind == "fault-injection":
        fault_config = config["fault_injection"]
        try:
            verified = fault_injection.verify_evidence(
                spec["receipt_root"],
                source_revision=config["source"]["revision"],
                binary=Path(fault_config["test_binary"]),
                binary_sha256=fault_config["test_binary_sha256"],
            )
        except fault_injection.FaultInjectionError as error:
            raise StabilityError(
                f"fault-injection evidence rejected: {error}"
            ) from error
        results = verified["results"]
        return {
            "schema": FAULT_INJECTION_PROJECTION_SCHEMA,
            "status": "pass",
            "source_revision": verified["source_revision"],
            "test_binary_path": verified["binary"]["path"],
            "test_binary_sha256": verified["binary"]["sha256"],
            "receipt_sha256": sha256_file(spec["receipt_path"]),
            "test_count": results["test_count"],
            "tests": list(results["tests"]),
        }
    if kind == "realworld":
        parameters = action["parameters"]
        return verify_realworld_shard(
            scripts / "realworld_manifest.json",
            spec["receipt_path"],
            project_id=parameters["project"],
            repetition=parameters["repetition"],
            expected_analyzer_sha256=config["analyzer"]["sha256"],
            mode=plan["mode"],
        )
    if kind == "aggregate":
        cycle_root = spec["receipt_root"].parents[1]
        return verify_realworld_cycle(
            scripts / "realworld_manifest.json",
            "release-candidate",
            cycle_root / "realworld",
            spec["receipt_path"],
            expected_analyzer_sha256=config["analyzer"]["sha256"],
            mode=plan["mode"],
        )
    raise StabilityError("planned action kind is unsupported")


def execute_planned_action(
    config: dict[str, Any],
    plan: dict[str, Any],
    action: dict[str, Any],
    *,
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
    command_executor: Callable[[list[str], Path, dict[str, str]], int] | None = None,
    projection_verifier: Callable[..., dict[str, Any]] | None = None,
) -> Path:
    """Execute, semantically verify, and seal one immutable planned action."""

    config_value = validate_runtime_config(config)
    spec = build_action_spec(
        config_value,
        plan,
        action,
        evidence_root=evidence_root,
        runtime_root=runtime_root,
    )
    action_receipt_path = spec["action_receipt_path"]
    for candidate in (
        spec["receipt_path"],
        Path(f"{spec['receipt_path']}.sha256"),
        action_receipt_path,
    ):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise StabilityError(
                f"cannot inspect planned action output {candidate}: {error}"
            ) from error
        raise StabilityError(f"planned action output already exists: {candidate}")

    log_root = spec["log_root"]
    try:
        log_root.mkdir(parents=True, exist_ok=True)
        metadata = log_root.lstat()
    except OSError as error:
        raise StabilityError(f"cannot establish action log directory: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise StabilityError("action log root is not a real directory")

    executor = (
        _default_action_command_executor
        if command_executor is None else command_executor
    )
    if not callable(executor):
        raise StabilityError("planned action command executor is unavailable")
    if action["kind"] == "fault-injection":
        try:
            spec["receipt_root"].mkdir(parents=False, exist_ok=False)
        except OSError as error:
            raise StabilityError(
                f"cannot create fresh fault-injection output: {error}"
            ) from error
    try:
        exit_code = executor(spec["argv"], spec["cwd"], spec["env"])
    except StabilityError:
        raise
    except Exception as error:
        raise StabilityError(f"planned inner action execution failed: {error}") from error
    if type(exit_code) is not int:
        raise StabilityError("planned inner action returned a malformed exit code")
    if exit_code != 0:
        raise StabilityError(f"planned inner action failed with exit code {exit_code}")

    verifier = (
        verify_planned_action_projection
        if projection_verifier is None else projection_verifier
    )
    if not callable(verifier):
        raise StabilityError("planned action projection verifier is unavailable")
    try:
        projection = verifier(config_value, plan, action, spec)
    except StabilityError:
        raise
    except Exception as error:
        raise StabilityError(f"planned action projection verification failed: {error}") from error
    receipt = build_action_receipt(
        config_value,
        plan,
        action,
        projection,
        evidence_root=evidence_root,
        runtime_root=runtime_root,
    )
    _atomic_create(action_receipt_path, canonical_document(receipt))
    verify_action_receipt(
        action_receipt_path,
        config_value,
        plan,
        action,
        evidence_root=evidence_root,
        runtime_root=runtime_root,
    )
    return action_receipt_path


def _qualification_cycle_record(inner: dict[str, Any]) -> dict[str, Any]:
    projection = inner["projection"]
    return {
        "receipt_path": inner["receipt_path"],
        "receipt_sha256": inner["receipt_sha256"],
        "status": "accepted",
        "performance_policy": "required",
        "performance_gate": projection["performance_gate"],
        "semantic_sha256": projection["semantic_sha256"],
        "source_revision": projection["source_revision"],
        "analyzer_sha256": projection["analyzer_sha256"],
        "hardware_class": projection["hardware_class"],
    }


def _validate_fault_injection_cycle_record(
    raw: Any,
    evidence_root: Path,
    identity: dict[str, Any],
) -> dict[str, Any]:
    record = _exact_dict(
        raw,
        {
            "receipt_path", "receipt_sha256", "status", "source_revision",
            "test_binary_path", "test_binary_sha256", "test_count", "tests",
        },
        "cycle fault-injection receipt",
    )
    _linked_regular_sha(
        evidence_root,
        record["receipt_path"],
        record["receipt_sha256"],
        "cycle fault-injection receipt",
    )
    binary = _exact_dict(
        identity["fault_injection_test_binary"],
        {"path", "sha256", "sanitizer_profile", "sanitizer_receipt_sha256"},
        "cycle fault-injection session binary",
    )
    if (
        record["status"] != "accepted"
        or record["source_revision"] != identity["source_revision"]
        or record["test_binary_path"] != binary["path"]
        or record["test_binary_sha256"] != binary["sha256"]
        or record["tests"] != fault_injection.CANONICAL_TESTS
    ):
        raise StabilityError("cycle fault-injection authority drift")
    _fixed_integer(
        record["test_count"],
        len(fault_injection.CANONICAL_TESTS),
        "cycle fault-injection test count",
    )
    return copy.deepcopy(record)


def _fault_injection_cycle_record(
    inner: dict[str, Any],
    evidence_root: Path,
    identity: dict[str, Any],
) -> dict[str, Any]:
    projection = inner["projection"]
    if projection["receipt_sha256"] != inner["receipt_sha256"]:
        raise StabilityError("cycle fault-injection inner receipt identity drift")
    return _validate_fault_injection_cycle_record(
        {
            "receipt_path": inner["receipt_path"],
            "receipt_sha256": inner["receipt_sha256"],
            "status": "accepted",
            "source_revision": projection["source_revision"],
            "test_binary_path": projection["test_binary_path"],
            "test_binary_sha256": projection["test_binary_sha256"],
            "test_count": projection["test_count"],
            "tests": list(projection["tests"]),
        },
        evidence_root,
        identity,
    )


def seal_cycle_receipt(
    config: dict[str, Any],
    plan: dict[str, Any],
    session: dict[str, Any],
    *,
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
) -> Path:
    """Seal one cycle only from all accepted planned action receipts."""

    config_value = validate_runtime_config(config)
    session_value = _validate_session_record(session)
    identity = session_value["identity"]
    if (
        identity["source_revision"] != config_value["source"]["revision"]
        or identity["source_manifest_sha256"]
        != config_value["source"]["manifest_sha256"]
        or identity["analyzer_sha256"] != config_value["analyzer"]["sha256"]
        or identity["fault_injection_test_binary"]
        != {
            "path": config_value["fault_injection"]["test_binary"],
            "sha256": config_value["fault_injection"]["test_binary_sha256"],
            "sanitizer_profile": "undefined",
            "sanitizer_receipt_sha256": config_value["sanitizers"][
                "undefined"
            ]["receipt_sha256"],
        }
        or identity["hardware_class"]
        != config_value["qualification"]["hardware_class"]
    ):
        raise StabilityError("cycle session differs from its runtime config")
    plan_value = _exact_dict(
        plan,
        {
            "schema", "id", "ordinal", "mode", "schedule_sha256",
            "action_count", "actions", "plan_sha256",
        },
        "cycle sealer plan",
    )
    ordinal = _integer(plan_value["ordinal"], "cycle sealer ordinal", 1)
    expected_mode = "cold" if ordinal == 1 else "warm"
    if (
        plan_value["schema"] != CYCLE_PLAN_SCHEMA
        or plan_value["mode"] != expected_mode
        or plan_value["id"]
        != cycle_identity(
            session_value["id"], ordinal, plan_value["schedule_sha256"]
        )
        or digest_json(plan_value["actions"]) != plan_value["plan_sha256"]
        or plan_value["action_count"] != len(plan_value["actions"])
    ):
        raise StabilityError("cycle sealer plan identity drift")
    cycle_root = evidence_root / "cycles" / f"{ordinal:06d}"
    plan_path = cycle_root / "plan.json"
    if _load_document(plan_path, "retained cycle plan") != plan_value:
        raise StabilityError("retained cycle plan differs from the executor plan")

    retained: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for action in plan_value["actions"]:
        spec = build_action_spec(
            config_value,
            plan_value,
            action,
            evidence_root=evidence_root,
            runtime_root=runtime_root,
        )
        verify_action_receipt(
            spec["action_receipt_path"],
            config_value,
            plan_value,
            action,
            evidence_root=evidence_root,
            runtime_root=runtime_root,
        )
        retained.append((action, _load_document(
            spec["action_receipt_path"], "retained action receipt"
        )))

    qualifications = [
        (action, receipt)
        for action, receipt in retained
        if action["kind"] == "qualification"
    ]
    if len(qualifications) != 1:
        raise StabilityError("cycle qualification bracket action count drift")
    previous: dict[str, Any] | None = None
    if ordinal == 1:
        pre_action, pre_receipt = qualifications[0]
        if pre_action["parameters"] != {"phase": "pre"}:
            raise StabilityError("cycle pre-qualification action drift")
        pre_qualification = _qualification_cycle_record(pre_receipt["inner"])
        qualification = None
    else:
        post_action, post_receipt = qualifications[0]
        if post_action["parameters"] != {"phase": "post"}:
            raise StabilityError("cycle post-qualification action drift")
        qualification = _qualification_cycle_record(post_receipt["inner"])
        previous_path = (
            evidence_root / "cycles" / f"{ordinal - 1:06d}" / "cycle.json"
        )
        previous = _load_document(previous_path, "previous cycle receipt")
        try:
            previous_identity = _exact_dict(
                previous.get("identity"),
                {"id", "session_id", "ordinal", "schedule_sha256"},
                "previous cycle identity",
            )
        except StabilityError as error:
            raise StabilityError(
                "previous cycle receipt is not authoritative"
            ) from error
        if (
            previous.get("schema") != CYCLE_SCHEMA
            or previous.get("status") != "accepted"
            or previous.get("failures") != []
            or previous_identity["session_id"] != session_value["id"]
            or previous_identity["ordinal"] != ordinal - 1
        ):
            raise StabilityError("previous cycle receipt is not authoritative")
        pre_qualification = copy.deepcopy(previous.get("pre_qualification"))

    fault_pairs = [
        (action, receipt)
        for action, receipt in retained
        if action["kind"] == "fault-injection"
    ]
    if ordinal == 1:
        if len(fault_pairs) != 1:
            raise StabilityError("cold cycle fault-injection action count drift")
        fault_action, fault_receipt = fault_pairs[0]
        if fault_action["parameters"] != {
            "test_count": len(fault_injection.CANONICAL_TESTS)
        }:
            raise StabilityError("cold cycle fault-injection action drift")
        fault_record = _fault_injection_cycle_record(
            fault_receipt["inner"], evidence_root, identity
        )
    else:
        if fault_pairs:
            raise StabilityError("warm cycle repeated the cold-only fault gate")
        if previous is None:
            raise StabilityError("warm cycle fault-injection predecessor is missing")
        fault_record = _validate_fault_injection_cycle_record(
            previous.get("fault_injection"), evidence_root, identity
        )

    realworld_actions = [
        (action, receipt)
        for action, receipt in retained
        if action["kind"] == "realworld"
    ]
    if len(realworld_actions) != 9:
        raise StabilityError("cycle real-world action count drift")
    aggregate_pairs = [
        (action, receipt)
        for action, receipt in retained
        if action["kind"] == "aggregate"
    ]
    if len(aggregate_pairs) != 1:
        raise StabilityError("cycle aggregate action count drift")
    aggregate_action, aggregate_receipt = aggregate_pairs[0]
    aggregate = aggregate_receipt["inner"]["projection"]
    if aggregate_action["parameters"] != {
        "checkpoint_mode": expected_mode,
        "slot_count": 9,
        "tier": "release-candidate",
    }:
        raise StabilityError("cycle aggregate action parameters drift")
    if aggregate["aggregate_sha256"] != aggregate_receipt["inner"][
        "receipt_sha256"
    ]:
        raise StabilityError("cycle aggregate inner receipt identity drift")

    expected_shards: list[dict[str, Any]] = []
    for action, receipt in realworld_actions:
        projection = receipt["inner"]["projection"]
        expected_shards.append({
            "project": projection["project"],
            "repetition": projection["repetition"],
            "path": (
                evidence_root / receipt["inner"]["receipt_path"]
            ).as_posix(),
            "sha256": receipt["inner"]["receipt_sha256"],
            "requested_tus": projection["requested_tus"],
            "executed_tus": projection["executed_tus"],
            "checkpoint_tus": projection["checkpoint_tus"],
            "duration_ms": projection["duration_ms"],
            "resources": copy.deepcopy(projection["resources"]),
        })
        if projection["receipt_sha256"] != receipt["inner"]["receipt_sha256"]:
            raise StabilityError("cycle shard inner receipt identity drift")
    if aggregate["shards"] != expected_shards:
        raise StabilityError("cycle aggregate differs from its action receipts")

    realworld_record = {
        "aggregate_path": aggregate_receipt["inner"]["receipt_path"],
        "aggregate_sha256": aggregate["aggregate_sha256"],
        "slot_count": aggregate["slot_count"],
        "requested_tus": aggregate["requested_tus"],
        "completed_tus": aggregate["completed_tus"],
        "broken_tus": aggregate["broken_tus"],
        "missing_tus": aggregate["missing_tus"],
        "executed_tus": aggregate["executed_tus"],
        "checkpoint_tus": aggregate["checkpoint_tus"],
        "semantic_sha256": aggregate["semantic_sha256"],
        "translation_unit_plan_sha256": aggregate[
            "translation_unit_plan_sha256"
        ],
        "duration_ms": aggregate["duration_ms"],
        "maximum_peak_memory_kib": aggregate["maximum_peak_memory_kib"],
        "resource_observations_sha256": aggregate[
            "resource_observations_sha256"
        ],
    }
    document = {
        "schema": CYCLE_SCHEMA,
        "status": "accepted",
        "failures": [],
        "identity": {
            "id": plan_value["id"],
            "session_id": session_value["id"],
            "ordinal": ordinal,
            "schedule_sha256": plan_value["schedule_sha256"],
        },
        "mode": expected_mode,
        "source_revision": identity["source_revision"],
        "analyzer_sha256": identity["analyzer_sha256"],
        "realworld": realworld_record,
        "fault_injection": fault_record,
        "pre_qualification": pre_qualification,
        "qualification": qualification,
    }
    cycle_path = cycle_root / "cycle.json"
    _atomic_create(cycle_path, canonical_document(document))
    if _load_document(cycle_path, "sealed cycle receipt") != document:
        raise StabilityError("sealed cycle receipt changed during publication")
    return cycle_path


def _raise_after_independent_cleanup(
    primary_error: BaseException | None,
    cleanup_errors: list[str],
    context: str,
) -> None:
    if primary_error is not None:
        if cleanup_errors:
            raise StabilityError(
                f"{context} failed: {primary_error}; cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from primary_error
        raise primary_error
    if cleanup_errors:
        raise StabilityError(
            f"{context} cleanup failed: " + "; ".join(cleanup_errors)
        )


def execute_production_cycle(
    writer: JournalWriter,
    config: dict[str, Any],
    session: dict[str, Any],
    plan: dict[str, Any],
    *,
    config_path: Path = Path("/config/runtime.json"),
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
    runner: CommandRunner | None = None,
    supervisor: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute one exact cycle through supervised, heartbeat-visible wrappers."""

    config_value = validate_runtime_config(config)
    session_value = _validate_session_record(session)
    ordinal = _integer(plan.get("ordinal"), "production cycle ordinal", 1)
    cycle_root = evidence_root / "cycles" / f"{ordinal:06d}"
    try:
        cycle_root.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        raise StabilityError(f"cannot create fresh cycle output: {error}") from error
    plan_path = cycle_root / "plan.json"
    _atomic_create(plan_path, canonical_document(plan))
    command_runner = (
        SubprocessCommandRunner(
            evidence_root=evidence_root,
            runtime_root=runtime_root,
        )
        if runner is None else runner
    )
    supervise = supervise_action if supervisor is None else supervisor
    result: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        result = _execute_production_cycle_actions(
            writer,
            command_runner,
            supervise,
            config_value,
            session_value,
            plan,
            ordinal=ordinal,
            config_path=config_path,
            plan_path=plan_path,
            evidence_root=evidence_root,
            runtime_root=runtime_root,
        )
    except BaseException as error:
        primary_error = error
    cleanup_errors: list[str] = []
    if runner is None:
        try:
            command_runner.close()
        except BaseException as error:
            cleanup_errors.append(f"owned action runner close: {error}")
    _raise_after_independent_cleanup(
        primary_error, cleanup_errors, "production cycle execution"
    )
    if result is None:
        raise StabilityError("production cycle returned no result")
    return result


def _execute_production_cycle_actions(
    writer: JournalWriter,
    command_runner: CommandRunner,
    supervise: Callable[..., dict[str, Any]],
    config: dict[str, Any],
    session: dict[str, Any],
    plan: dict[str, Any],
    *,
    ordinal: int,
    config_path: Path,
    plan_path: Path,
    evidence_root: Path,
    runtime_root: Path,
) -> dict[str, Any]:
    if not callable(supervise):
        raise StabilityError("production action supervisor is unavailable")

    for action in plan["actions"]:
        wrapper = build_action_wrapper_spec(
            config,
            plan,
            action,
            config_path=config_path,
            plan_path=plan_path,
            evidence_root=evidence_root,
            runtime_root=runtime_root,
        )
        try:
            wrapper["log_root"].mkdir(parents=True, exist_ok=True)
            log_metadata = wrapper["log_root"].lstat()
        except OSError as error:
            raise StabilityError(
                f"cannot create fresh action log output: {error}"
            ) from error
        if not stat.S_ISDIR(log_metadata.st_mode):
            raise StabilityError("action log output is not a real directory")

        def verify_receipt(
            path: Path,
            *,
            planned_action: dict[str, Any] = action,
        ) -> str:
            return verify_action_receipt(
                path,
                config,
                plan,
                planned_action,
                evidence_root=evidence_root,
                runtime_root=runtime_root,
            )

        result = supervise(
            writer,
            command_runner,
            action_id=action["id"],
            kind=action["kind"],
            cycle_ordinal=ordinal,
            action_ordinal=action["ordinal"],
            timeout_seconds=action["timeout_seconds"],
            argv=wrapper["argv"],
            cwd=wrapper["cwd"],
            env=wrapper["env"],
            stdout_path=wrapper["stdout_path"],
            stderr_path=wrapper["stderr_path"],
            receipt_path=wrapper["receipt_path"],
            verify_receipt=verify_receipt,
        )
        normalized = _exact_dict(
            result,
            {"action_id", "exit_code", "kind", "receipt_sha256"},
            "production action result",
        )
        if (
            normalized["action_id"] != action["id"]
            or normalized["kind"] != action["kind"]
            or normalized["exit_code"] != 0
            or normalized["receipt_sha256"]
            != sha256_file(wrapper["receipt_path"])
        ):
            raise StabilityError("production action result differs from its plan")

    cycle_path = seal_cycle_receipt(
        config,
        plan,
        session,
        evidence_root=evidence_root,
        runtime_root=runtime_root,
    )
    return {
        "cycle_id": plan["id"],
        "mode": plan["mode"],
        "receipt_path": cycle_path,
        "receipt_sha256": sha256_file(cycle_path),
        "slot_count": 9,
    }


def verify_cycle_action_authorities(
    config: dict[str, Any],
    session: dict[str, Any],
    policy: dict[str, Any],
    schedule: dict[str, Any],
    *,
    evidence_root: Path = Path("/evidence"),
    runtime_root: Path = Path("/runtime"),
    projection_verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Re-derive every action and compare it with the sealed cycle claims."""

    config_value = validate_runtime_config(config)
    session_value = _validate_session_record(session)
    verifier = (
        verify_planned_action_projection
        if projection_verifier is None else projection_verifier
    )
    if not callable(verifier):
        raise StabilityError("cycle action authority verifier is unavailable")
    documents: list[dict[str, Any]] = []
    campaign_pre_qualification: dict[str, Any] | None = None
    previous_fault_injection: dict[str, Any] | None = None
    for ordinal in range(1, policy["completion"]["required_complete_rounds"] + 1):
        plan = build_cycle_plan(
            policy, schedule, session_value["id"], ordinal
        )
        cycle_root = evidence_root / "cycles" / f"{ordinal:06d}"
        retained_plan = _load_document(
            cycle_root / "plan.json", "retained cycle plan"
        )
        if retained_plan != plan:
            raise StabilityError("retained cycle plan differs from fixed policy")
        action_records: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for action in plan["actions"]:
            spec = build_action_spec(
                config_value,
                plan,
                action,
                evidence_root=evidence_root,
                runtime_root=runtime_root,
            )
            verify_action_receipt(
                spec["action_receipt_path"],
                config_value,
                plan,
                action,
                evidence_root=evidence_root,
                runtime_root=runtime_root,
            )
            receipt = _load_document(
                spec["action_receipt_path"], "retained action receipt"
            )
            try:
                rederived = verifier(config_value, plan, action, spec)
            except StabilityError:
                raise
            except Exception as error:
                raise StabilityError(
                    f"cannot rederive planned action authority: {error}"
                ) from error
            normalized = _validate_action_projection(
                rederived, config_value, action
            )
            if normalized != receipt["inner"]["projection"]:
                raise StabilityError(
                    "retained action projection differs from rederived authority"
                )
            if sha256_file(spec["receipt_path"]) != receipt["inner"][
                "receipt_sha256"
            ]:
                raise StabilityError("retained inner action receipt checksum drift")
            action_records.append((action, receipt))

        qualifications = [
            (action, receipt)
            for action, receipt in action_records
            if action["kind"] == "qualification"
        ]
        if len(qualifications) != 1:
            raise StabilityError("strict qualification action count drift")
        if ordinal == 1:
            pre_action, pre_receipt = qualifications[0]
            if pre_action["parameters"] != {"phase": "pre"}:
                raise StabilityError("strict pre-qualification phase drift")
            pre_qualification = _qualification_cycle_record(
                pre_receipt["inner"]
            )
            qualification = None
            campaign_pre_qualification = copy.deepcopy(pre_qualification)
        else:
            post_action, post_receipt = qualifications[0]
            if post_action["parameters"] != {"phase": "post"}:
                raise StabilityError("strict post-qualification phase drift")
            qualification = _qualification_cycle_record(post_receipt["inner"])
            if campaign_pre_qualification is None:
                raise StabilityError("strict qualification predecessor is missing")
            pre_qualification = copy.deepcopy(campaign_pre_qualification)

        fault_records = [
            (action, receipt)
            for action, receipt in action_records
            if action["kind"] == "fault-injection"
        ]
        if ordinal == 1:
            if len(fault_records) != 1:
                raise StabilityError(
                    "strict cold fault-injection action count drift"
                )
            fault_action, fault_receipt = fault_records[0]
            if fault_action["parameters"] != {
                "test_count": len(fault_injection.CANONICAL_TESTS)
            }:
                raise StabilityError("strict fault-injection action drift")
            fault_record = _fault_injection_cycle_record(
                fault_receipt["inner"],
                evidence_root,
                session_value["identity"],
            )
        else:
            if fault_records:
                raise StabilityError(
                    "strict warm cycle repeated the cold-only fault gate"
                )
            if previous_fault_injection is None:
                raise StabilityError(
                    "strict fault-injection predecessor is missing"
                )
            fault_record = copy.deepcopy(previous_fault_injection)

        aggregate_records = [
            (action, receipt)
            for action, receipt in action_records
            if action["kind"] == "aggregate"
        ]
        realworld_records = [
            (action, receipt)
            for action, receipt in action_records
            if action["kind"] == "realworld"
        ]
        if len(aggregate_records) != 1 or len(realworld_records) != 9:
            raise StabilityError("strict real-world action matrix drift")
        _, aggregate_receipt = aggregate_records[0]
        aggregate = aggregate_receipt["inner"]["projection"]
        expected_shards = [
            {
                "project": receipt["inner"]["projection"]["project"],
                "repetition": receipt["inner"]["projection"]["repetition"],
                "path": (
                    evidence_root / receipt["inner"]["receipt_path"]
                ).as_posix(),
                "sha256": receipt["inner"]["receipt_sha256"],
                "requested_tus": receipt["inner"]["projection"][
                    "requested_tus"
                ],
                "executed_tus": receipt["inner"]["projection"][
                    "executed_tus"
                ],
                "checkpoint_tus": receipt["inner"]["projection"][
                    "checkpoint_tus"
                ],
                "duration_ms": receipt["inner"]["projection"]["duration_ms"],
                "resources": copy.deepcopy(
                    receipt["inner"]["projection"]["resources"]
                ),
            }
            for _, receipt in realworld_records
        ]
        if aggregate["shards"] != expected_shards:
            raise StabilityError(
                "rederived aggregate differs from individual action authorities"
            )
        realworld_record = {
            "aggregate_path": aggregate_receipt["inner"]["receipt_path"],
            "aggregate_sha256": aggregate["aggregate_sha256"],
            "slot_count": aggregate["slot_count"],
            "requested_tus": aggregate["requested_tus"],
            "completed_tus": aggregate["completed_tus"],
            "broken_tus": aggregate["broken_tus"],
            "missing_tus": aggregate["missing_tus"],
            "executed_tus": aggregate["executed_tus"],
            "checkpoint_tus": aggregate["checkpoint_tus"],
            "semantic_sha256": aggregate["semantic_sha256"],
            "translation_unit_plan_sha256": aggregate[
                "translation_unit_plan_sha256"
            ],
            "duration_ms": aggregate["duration_ms"],
            "maximum_peak_memory_kib": aggregate["maximum_peak_memory_kib"],
            "resource_observations_sha256": aggregate[
                "resource_observations_sha256"
            ],
        }
        expected_cycle = {
            "schema": CYCLE_SCHEMA,
            "status": "accepted",
            "failures": [],
            "identity": {
                "id": plan["id"],
                "session_id": session_value["id"],
                "ordinal": ordinal,
                "schedule_sha256": plan["schedule_sha256"],
            },
            "mode": plan["mode"],
            "source_revision": session_value["identity"]["source_revision"],
            "analyzer_sha256": session_value["identity"]["analyzer_sha256"],
            "realworld": realworld_record,
            "fault_injection": fault_record,
            "pre_qualification": pre_qualification,
            "qualification": qualification,
        }
        retained_cycle = _load_document(
            cycle_root / "cycle.json", "retained cycle receipt"
        )
        if retained_cycle != expected_cycle:
            raise StabilityError(
                "retained cycle receipt differs from rederived action authorities"
            )
        documents.append(retained_cycle)
        previous_fault_injection = fault_record
    return validate_cycle_documents(
        documents, evidence_root, session_value, schedule, policy
    )


def _linked_regular_sha(
    evidence_root: Path, relative_value: Any, expected_sha: Any, label: str,
) -> str:
    if not isinstance(relative_value, str) or not relative_value:
        raise StabilityError(f"{label} path is malformed")
    relative = Path(relative_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise StabilityError(f"{label} path escapes the evidence root")
    actual = sha256_file(evidence_root / relative)
    expected = _valid_sha(expected_sha, label)
    if actual != expected:
        raise StabilityError(f"{label} checksum mismatch")
    return actual


def _validate_session_record(session: Any) -> dict[str, Any]:
    value = _exact_dict(
        session, {"id", "controller_id", "identity"}, "session record"
    )
    expected_id = build_session_identity(value["identity"])
    if value["id"] != expected_id:
        raise StabilityError("session identity does not match its authorities")
    _valid_sha(value["controller_id"], "session controller")
    return value


def validate_cycle_documents(
    documents: Any,
    evidence_root: Path,
    session: dict[str, Any],
    schedule: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(documents, list) or not documents:
        raise StabilityError("cycle evidence is empty")
    session_value = _validate_session_record(session)
    if schedule.get("slot_count") != 9:
        raise StabilityError("cycle schedule is not the exact 3x3 matrix")
    schedule_sha = _valid_sha(schedule.get("schedule_sha256"), "cycle schedule")
    identity = session_value["identity"]
    cycle_fields = {
        "schema", "status", "failures", "identity", "mode",
        "source_revision", "analyzer_sha256", "realworld", "qualification",
        "pre_qualification", "fault_injection",
    }
    realworld_fields = {
        "aggregate_path", "aggregate_sha256", "slot_count", "requested_tus",
        "completed_tus", "broken_tus", "missing_tus", "executed_tus",
        "checkpoint_tus", "semantic_sha256", "translation_unit_plan_sha256",
        "duration_ms", "maximum_peak_memory_kib",
        "resource_observations_sha256",
    }
    qualification_fields = {
        "receipt_path", "receipt_sha256", "status", "performance_policy",
        "performance_gate", "semantic_sha256", "source_revision",
        "analyzer_sha256", "hardware_class",
    }
    semantic_reference: str | None = None
    plan_reference: str | None = None
    qualification_reference: str | None = None
    fault_injection_reference: dict[str, Any] | None = None
    campaign_pre_qualification: dict[str, Any] | None = None
    requested_total = 0
    completed_total = 0
    executed_total = 0
    checkpoint_total = 0
    realworld_durations: list[dict[str, Any]] = []
    maximum_peak_memory = 0
    resource_observations: list[str] = []

    def validate_qualification(
        raw: Any, label: str,
    ) -> tuple[dict[str, Any], str]:
        qualification = _exact_dict(raw, qualification_fields, label)
        _linked_regular_sha(
            evidence_root,
            qualification["receipt_path"],
            qualification["receipt_sha256"],
            f"{label} receipt",
        )
        if (
            qualification["status"] != "accepted"
            or qualification["performance_policy"] != "required"
            or qualification["performance_gate"] != "pass"
        ):
            raise StabilityError("cycle performance qualification is not accepted")
        if qualification["source_revision"] != identity["source_revision"]:
            raise StabilityError("qualification source identity drift")
        if qualification["analyzer_sha256"] != identity["analyzer_sha256"]:
            raise StabilityError("qualification analyzer identity drift")
        if qualification["hardware_class"] != identity["hardware_class"]:
            raise StabilityError("qualification hardware identity drift")
        semantic = _valid_sha(
            qualification["semantic_sha256"], "qualification semantic"
        )
        return qualification, semantic

    for index, document in enumerate(documents):
        ordinal = index + 1
        cycle = _exact_dict(document, cycle_fields, "cycle receipt")
        if (
            cycle["schema"] != CYCLE_SCHEMA
            or cycle["status"] != "accepted"
            or cycle["failures"] != []
        ):
            raise StabilityError("cycle receipt is not accepted")
        cycle_identity_value = _exact_dict(
            cycle["identity"],
            {"id", "session_id", "ordinal", "schedule_sha256"},
            "cycle identity",
        )
        expected_cycle_id = cycle_identity(
            session_value["id"], ordinal, schedule_sha
        )
        if cycle_identity_value != {
            "id": expected_cycle_id,
            "session_id": session_value["id"],
            "ordinal": ordinal,
            "schedule_sha256": schedule_sha,
        }:
            raise StabilityError("cycle identity drift")
        expected_mode = "cold" if ordinal == 1 else "warm"
        if cycle["mode"] != expected_mode:
            raise StabilityError("cold-to-warm cycle order is invalid")
        if cycle["source_revision"] != identity["source_revision"]:
            raise StabilityError("cycle source identity drift")
        if cycle["analyzer_sha256"] != identity["analyzer_sha256"]:
            raise StabilityError("cycle analyzer identity drift")

        fault_record = _validate_fault_injection_cycle_record(
            cycle["fault_injection"], evidence_root, identity
        )
        if fault_injection_reference is None:
            fault_injection_reference = fault_record
        elif fault_record != fault_injection_reference:
            raise StabilityError("cold-only fault-injection receipt is not reused")

        realworld_value = _exact_dict(
            cycle["realworld"], realworld_fields, "cycle real-world receipt"
        )
        _linked_regular_sha(
            evidence_root,
            realworld_value["aggregate_path"],
            realworld_value["aggregate_sha256"],
            "real-world aggregate",
        )
        _fixed_integer(realworld_value["slot_count"], 9, "cycle slot count")
        requested = _integer(
            realworld_value["requested_tus"], "cycle requested TU count", 1
        )
        completed = _integer(
            realworld_value["completed_tus"], "cycle completed TU count"
        )
        broken = _integer(realworld_value["broken_tus"], "cycle broken TU count")
        missing = _integer(realworld_value["missing_tus"], "cycle missing TU count")
        executed = _integer(
            realworld_value["executed_tus"], "cycle executed TU count"
        )
        checkpoint = _integer(
            realworld_value["checkpoint_tus"], "cycle checkpoint TU count"
        )
        if (
            completed != requested
            or broken != 0
            or missing != 0
            or executed + checkpoint != requested
        ):
            raise StabilityError("cycle requested-unit coverage is incomplete")
        if ordinal == 1 and (checkpoint != 0 or executed != requested):
            raise StabilityError("cold cycle contains checkpoint evidence")
        if ordinal > 1 and (
            checkpoint != requested or executed != 0
        ):
            raise StabilityError(
                "warm cycle lacks complete checkpoint restart evidence"
            )
        semantic = _valid_sha(
            realworld_value["semantic_sha256"], "cycle semantic"
        )
        plan = _valid_sha(
            realworld_value["translation_unit_plan_sha256"],
            "cycle translation-unit plan",
        )
        duration_ms = _integer(
            realworld_value["duration_ms"], "cycle real-world duration"
        )
        peak_memory = _integer(
            realworld_value["maximum_peak_memory_kib"],
            "cycle real-world peak memory",
        )
        resource_sha = _valid_sha(
            realworld_value["resource_observations_sha256"],
            "cycle real-world resource observations",
        )
        if semantic_reference is None:
            semantic_reference = semantic
            plan_reference = plan
        elif semantic != semantic_reference:
            raise StabilityError("cycle semantic fingerprint drift")
        elif plan != plan_reference:
            raise StabilityError("cycle translation-unit plan drift")

        pre_qualification, pre_semantic = validate_qualification(
            cycle["pre_qualification"], "cycle pre-qualification"
        )
        if ordinal == 1:
            if cycle["qualification"] is not None:
                raise StabilityError(
                    "cold cycle contains an intermediate post-qualification"
                )
            campaign_pre_qualification = copy.deepcopy(pre_qualification)
            qualification_semantics = (pre_semantic,)
        else:
            if pre_qualification != campaign_pre_qualification:
                raise StabilityError("qualification bracket is not contiguous")
            _, post_semantic = validate_qualification(
                cycle["qualification"], "cycle post-qualification"
            )
            qualification_semantics = (post_semantic,)
        for semantic in qualification_semantics:
            if qualification_reference is None:
                qualification_reference = semantic
            elif semantic != qualification_reference:
                raise StabilityError("qualification semantic fingerprint drift")

        requested_total += requested
        completed_total += completed
        executed_total += executed
        checkpoint_total += checkpoint
        realworld_durations.append({
            "mode": expected_mode,
            "duration_ms": duration_ms,
        })
        maximum_peak_memory = max(maximum_peak_memory, peak_memory)
        resource_observations.append(resource_sha)

    if len(documents) != policy["completion"]["required_complete_rounds"]:
        raise StabilityError("cycle evidence is not the exact cold/warm scope")
    if fault_injection_reference is None:
        raise StabilityError("cycle fault-injection evidence is missing")
    return {
        "cycles": len(documents),
        "slot_count": len(documents) * 9,
        "requested_tus": requested_total,
        "completed_tus": completed_total,
        "executed_tus": executed_total,
        "checkpoint_tus": checkpoint_total,
        "semantic_sha256": semantic_reference,
        "translation_unit_plan_sha256": plan_reference,
        "qualification_semantic_sha256": qualification_reference,
        "realworld_durations": realworld_durations,
        "maximum_peak_memory_kib": maximum_peak_memory,
        "resource_observations_sha256": digest_json(resource_observations),
        "fault_injection_receipt_sha256": fault_injection_reference[
            "receipt_sha256"
        ],
        "fault_injection_test_count": fault_injection_reference["test_count"],
        "performance_scope": PERFORMANCE_SCOPE,
        "performance_gate": "pass",
    }


def _validate_utc(value: Any) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise StabilityError("event UTC metadata is malformed")
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise StabilityError("event UTC metadata is malformed") from error


def _validate_event_payload(event_type: str, payload: Any) -> None:
    if event_type == "session-start":
        value = _exact_dict(payload, {"policy_sha256", "status"}, "session start")
        _valid_sha(value["policy_sha256"], "policy")
        if value["status"] != "running":
            raise StabilityError("session start status is malformed")
        return
    if event_type == "heartbeat":
        value = _exact_dict(
            payload,
            {
                "stage", "child_pid", "action_id", "cycle_ordinal",
                "action_ordinal",
            },
            "heartbeat",
        )
        if not isinstance(value["stage"], str) or not value["stage"]:
            raise StabilityError("heartbeat stage is malformed")
        _integer(value["child_pid"], "heartbeat child PID", 1)
        _valid_sha(value["action_id"], "heartbeat action identity")
        _integer(value["cycle_ordinal"], "heartbeat cycle ordinal", 1)
        _integer(value["action_ordinal"], "heartbeat action ordinal")
        return
    if event_type == "action-start":
        value = _exact_dict(
            payload,
            {
                "action_id", "kind", "cycle_ordinal", "action_ordinal",
                "timeout_seconds", "child_pid",
            },
            "action start",
        )
        _valid_sha(value["action_id"], "action identity")
        if value["kind"] not in {
            "qualification", "fault-injection", "realworld", "aggregate"
        }:
            raise StabilityError("action kind is unsupported")
        _integer(value["cycle_ordinal"], "action cycle ordinal", 1)
        _integer(value["action_ordinal"], "action ordinal")
        _integer(value["timeout_seconds"], "action timeout", 1)
        _integer(value["child_pid"], "action child PID", 1)
        return
    if event_type == "cycle-finish":
        value = _exact_dict(
            payload,
            {
                "accepted", "mode", "ordinal", "slot_count", "cycle_id",
                "receipt_sha256",
            },
            "cycle finish",
        )
        if value["accepted"] is not True:
            raise StabilityError("cycle is not accepted")
        if value["mode"] not in {"cold", "warm"}:
            raise StabilityError("cycle mode is malformed")
        _integer(value["ordinal"], "cycle ordinal", 1)
        _fixed_integer(value["slot_count"], 9, "cycle slot count")
        _valid_sha(value["cycle_id"], "cycle event identity")
        _valid_sha(value["receipt_sha256"], "cycle event receipt")
        return
    if event_type == "action-finish":
        value = _exact_dict(
            payload,
            {
                "accepted", "exit_code", "kind", "action_id", "outcome",
                "receipt_sha256", "child_pid", "cycle_ordinal",
                "action_ordinal",
            },
            "action finish",
        )
        _valid_sha(value["action_id"], "action identity")
        receipt_sha256 = value["receipt_sha256"]
        if receipt_sha256 is not None:
            _valid_sha(receipt_sha256, "action receipt")
            if receipt_sha256 == ZERO_SHA256:
                raise StabilityError("action receipt uses the missing-hash sentinel")
        if type(value["accepted"]) is not bool:
            raise StabilityError("action acceptance is malformed")
        if type(value["exit_code"]) is not int:
            raise StabilityError("action exit code is malformed")
        if value["kind"] not in {
            "qualification", "fault-injection", "realworld", "aggregate"
        }:
            raise StabilityError("action kind is unsupported")
        _integer(value["child_pid"], "action child PID", 1)
        _integer(value["cycle_ordinal"], "action cycle ordinal", 1)
        _integer(value["action_ordinal"], "action ordinal")
        outcome = value["outcome"]
        if outcome == "normal":
            if (
                value["accepted"] is not True
                or value["exit_code"] != 0
                or receipt_sha256 is None
            ):
                raise StabilityError("accepted action result is malformed")
        elif outcome == "nonzero-exit":
            if (
                value["accepted"] is not False
                or value["exit_code"] == 0
            ):
                raise StabilityError("nonzero action result is malformed")
        elif outcome == "outer-timeout":
            if (
                value["accepted"] is not False
                or value["exit_code"] != 124
            ):
                raise StabilityError("timed-out action result is malformed")
        elif outcome == "receipt-rejected":
            if (
                value["accepted"] is not False
                or value["exit_code"] != 0
            ):
                raise StabilityError("rejected action receipt result is malformed")
        elif outcome == "supervision-error":
            if value["accepted"] is not False or value["exit_code"] != 125:
                raise StabilityError("action supervision result is malformed")
        else:
            raise StabilityError("action outcome is unsupported")
        return
    if event_type == "session-finish":
        value = _exact_dict(payload, {"status"}, "session finish")
        if value["status"] not in {"accepted", "rejected"}:
            raise StabilityError("session finish status is malformed")
        return
    raise StabilityError(f"unsupported journal event type: {event_type}")


def _utc_text(value: dt.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise StabilityError("clock UTC metadata is timezone-naive")
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


class JournalWriter:
    """Append-only, fsynced single-controller journal writer."""

    def __init__(
        self,
        path: Path,
        policy: dict[str, Any],
        session_id: str,
        controller_id: str,
        policy_sha256: str,
        clock: StabilityClock,
    ) -> None:
        self.path = path
        self.policy = policy
        self.session_id = _valid_sha(session_id, "journal session identity")
        self.controller_id = _valid_sha(
            controller_id, "journal controller identity"
        )
        self.policy_sha256 = _valid_sha(policy_sha256, "journal policy")
        self.clock = clock
        self.expected_boot_id = clock.boot_id()
        if BOOT_ID.fullmatch(self.expected_boot_id) is None:
            raise StabilityError("journal boot identity is malformed")
        self._events: list[dict[str, Any]] = []
        self._terminal = False
        self._closed = False
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self._descriptor = os.open(path, flags, 0o600)
        except FileExistsError as error:
            raise StabilityError(
                f"refusing to resume or replace existing journal: {path}"
            ) from error
        except OSError as error:
            raise StabilityError(f"cannot create stability journal: {error}") from error
        self._device_inode = os.fstat(self._descriptor).st_dev, os.fstat(
            self._descriptor
        ).st_ino
        try:
            self._append("session-start", {
                "policy_sha256": self.policy_sha256,
                "status": "running",
            })
        except Exception:
            self.close()
            raise

    def _snapshot(self) -> tuple[int, int, str, str]:
        monotonic_ns = self.clock.monotonic_ns()
        boottime_ns = self.clock.boottime_ns()
        boot_id = self.clock.boot_id()
        utc = _utc_text(self.clock.utc_now())
        _integer(monotonic_ns, "clock monotonic time")
        _integer(boottime_ns, "clock boot time")
        if boot_id != self.expected_boot_id:
            raise StabilityError("boot identity changed during the live session")
        if self._events:
            previous = self._events[-1]
            monotonic_delta = monotonic_ns - previous["monotonic_ns"]
            boottime_delta = boottime_ns - previous["boottime_ns"]
            if monotonic_delta < 0:
                raise StabilityError("monotonic clock regressed")
            if boottime_delta < 0:
                raise StabilityError("boot clock regressed")
            if (
                monotonic_delta
                > self.policy["heartbeat"]["maximum_gap_seconds"]
                * 1_000_000_000
            ):
                raise StabilityError("heartbeat gap exceeds the fixed maximum")
            if (
                abs(boottime_delta - monotonic_delta)
                > self.policy["heartbeat"]["maximum_suspend_delta_seconds"]
                * 1_000_000_000
            ):
                raise StabilityError("suspend delta exceeds the fixed maximum")
        return monotonic_ns, boottime_ns, boot_id, utc

    def _write_line(self, line: bytes) -> None:
        try:
            current = self.path.lstat()
            opened = os.fstat(self._descriptor)
        except OSError as error:
            raise StabilityError(f"cannot inspect live journal: {error}") from error
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != self._device_inode
            or (opened.st_dev, opened.st_ino) != self._device_inode
        ):
            raise StabilityError("live journal path identity changed")
        view = memoryview(line)
        try:
            while view:
                written = os.write(self._descriptor, view)
                if written <= 0:
                    raise StabilityError("short write to stability journal")
                view = view[written:]
            os.fsync(self._descriptor)
        except OSError as error:
            raise StabilityError(f"cannot persist stability journal: {error}") from error

    def _append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        monotonic_ns, boottime_ns, boot_id, utc = self._snapshot()
        _validate_event_payload(event_type, payload)
        material = {
            "schema": EVENT_SCHEMA,
            "seq": len(self._events),
            "previous_event_sha256": (
                self._events[-1]["event_sha256"] if self._events else ZERO_SHA256
            ),
            "event_type": event_type,
            "session_id": self.session_id,
            "controller_id": self.controller_id,
            "boot_id": boot_id,
            "monotonic_ns": monotonic_ns,
            "boottime_ns": boottime_ns,
            "utc": utc,
            "payload": copy.deepcopy(payload),
        }
        event = {**material, "event_sha256": digest_json(material)}
        self._write_line(canonical_json(event) + b"\n")
        self._events.append(event)
        if event_type == "session-finish":
            self._terminal = True
        return copy.deepcopy(event)

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._terminal:
            raise StabilityError("journal already has a terminal event")
        if self._closed:
            raise StabilityError("journal writer is closed")
        return self._append(event_type, payload)

    @property
    def events(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._events)

    def close(self) -> None:
        if not self._closed:
            os.close(self._descriptor)
            self._closed = True


def _validate_command_inputs(
    argv: Any,
    cwd: Path,
    env: Any,
    stdout_path: Path,
    stderr_path: Path,
    receipt_path: Path,
) -> tuple[list[str], dict[str, str]]:
    if (
        not isinstance(argv, list)
        or not argv
        or any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in argv
        )
    ):
        raise StabilityError("action command is malformed")
    if not isinstance(env, dict) or any(
        not isinstance(key, str)
        or not key
        or "\x00" in key
        or "=" in key
        or not isinstance(value, str)
        or "\x00" in value
        for key, value in env.items()
    ):
        raise StabilityError("action environment is malformed")
    try:
        cwd_metadata = cwd.lstat()
    except OSError as error:
        raise StabilityError(f"cannot inspect action working directory: {error}") from error
    if not stat.S_ISDIR(cwd_metadata.st_mode):
        raise StabilityError("action working directory is not a regular directory")
    if len({stdout_path, stderr_path, receipt_path}) != 3:
        raise StabilityError("action output paths are not distinct")
    for path in (stdout_path, stderr_path, receipt_path):
        try:
            parent = path.parent.lstat()
        except OSError as error:
            raise StabilityError(f"cannot inspect action output directory: {error}") from error
        if not stat.S_ISDIR(parent.st_mode):
            raise StabilityError("action output parent is not a regular directory")
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise StabilityError(f"cannot inspect action output path: {error}") from error
        else:
            raise StabilityError(f"action output already exists: {path}")
    return list(argv), dict(env)


def _append_action_finish(
    writer: JournalWriter,
    *,
    accepted: bool,
    exit_code: int,
    kind: str,
    action_id: str,
    outcome: str,
    receipt_sha256: str | None,
    child_pid: int,
    cycle_ordinal: int,
    action_ordinal: int,
) -> None:
    writer.append("action-finish", {
        "accepted": accepted,
        "exit_code": exit_code,
        "kind": kind,
        "action_id": action_id,
        "outcome": outcome,
        "receipt_sha256": receipt_sha256,
        "child_pid": child_pid,
        "cycle_ordinal": cycle_ordinal,
        "action_ordinal": action_ordinal,
    })


def _release_action_disk_reserve(handle: CommandHandle) -> None:
    release = getattr(handle, "release_disk_reserve", None)
    if callable(release):
        release()


def _action_process_tree_clean(handle: CommandHandle) -> bool:
    """Accept an exited action only after kernel-authoritative ECHILD."""

    # A /proc snapshot alone has a fork/exit/reparent race. As the dedicated
    # controller is a subreaper and had no children before launch, ECHILD after
    # the Popen leader was reaped proves that no owned action descendant can be
    # waiting, running, or become adopted after this point.
    if not handle.wait_unexpected(ACTION_EXIT_CONVERGENCE_SECONDS):
        return False
    return not handle.group_alive() and not handle.unexpected_pids()


def _stop_process_group(
    handle: CommandHandle, *, release_reserve: bool = True,
) -> None:
    try:
        handle.terminate_group()
        handle.terminate_unexpected()
        exit_code = handle.wait(10.0)
        if handle.group_alive() or handle.unexpected_pids():
            handle.kill_group()
            handle.kill_unexpected()
            killed_exit = handle.wait(10.0)
            if exit_code is None:
                exit_code = killed_exit
        group_stopped = handle.wait_group(10.0)
        namespace_stopped = handle.wait_unexpected(10.0)
    except Exception as error:
        # Retain the recovery reserve whenever exact quiescence/reaping cannot
        # be proved. A surviving writer must never observe that extent.
        raise StabilityError(
            f"cannot stop timed-out action process group: {error}"
        ) from error
    if exit_code is None:
        raise StabilityError("timed-out action leader was not reaped")
    if type(exit_code) is not int:
        raise StabilityError("action process group returned a malformed exit code")
    if (
        not group_stopped
        or handle.group_alive()
        or not namespace_stopped
        or handle.unexpected_pids()
    ):
        raise StabilityError(
            "timed-out action process group or PID-namespace descendant "
            "survived SIGKILL"
        )
    if release_reserve:
        _release_action_disk_reserve(handle)


def supervise_action(
    writer: JournalWriter,
    runner: CommandRunner,
    *,
    action_id: str,
    kind: str,
    cycle_ordinal: Any,
    action_ordinal: Any,
    timeout_seconds: Any,
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
    receipt_path: Path,
    verify_receipt: Callable[[Path], str],
) -> dict[str, Any]:
    """Run one child authority with live heartbeats and fail-closed cleanup."""

    action_id_value = _valid_sha(action_id, "action identity")
    if kind not in {
        "qualification", "fault-injection", "realworld", "aggregate"
    }:
        raise StabilityError("action kind is unsupported")
    cycle_value = _integer(cycle_ordinal, "action cycle ordinal", 1)
    action_value = _integer(action_ordinal, "action ordinal")
    timeout_value = _integer(timeout_seconds, "action timeout", 1)
    command, environment = _validate_command_inputs(
        argv, cwd, env, stdout_path, stderr_path, receipt_path
    )
    if not callable(verify_receipt):
        raise StabilityError("action receipt verifier is unavailable")

    try:
        handle = runner.start(
            command,
            cwd=cwd,
            env=environment,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
    except Exception as error:
        raise StabilityError(f"cannot launch action: {error}") from error
    if type(handle.pid) is not int or handle.pid < 1:
        _stop_process_group(handle)
        raise StabilityError("action child PID is malformed")

    try:
        start_event = writer.append("action-start", {
            "action_id": action_id_value,
            "kind": kind,
            "cycle_ordinal": cycle_value,
            "action_ordinal": action_value,
            "timeout_seconds": timeout_value,
            "child_pid": handle.pid,
        })
    except BaseException:
        _stop_process_group(handle)
        raise

    def diagnostic_receipt_sha() -> str | None:
        try:
            return sha256_file(receipt_path)
        except StabilityError:
            return None

    def seal_failure(outcome: str, exit_code: int) -> None:
        _append_action_finish(
            writer,
            accepted=False,
            exit_code=exit_code,
            kind=kind,
            action_id=action_id_value,
            outcome=outcome,
            receipt_sha256=diagnostic_receipt_sha(),
            child_pid=handle.pid,
            cycle_ordinal=cycle_value,
            action_ordinal=action_value,
        )

    interval = writer.policy["heartbeat"]["interval_seconds"]
    deadline_ns = start_event["monotonic_ns"] + timeout_value * 1_000_000_000
    exit_code: int | None = None
    while exit_code is None:
        before_ns = writer.clock.monotonic_ns()
        remaining_ns = deadline_ns - before_ns
        if remaining_ns <= 0:
            break
        wait_seconds = min(interval, remaining_ns / 1_000_000_000)
        try:
            candidate = handle.wait(wait_seconds)
        except BaseException as error:
            try:
                _stop_process_group(handle)
            finally:
                seal_failure("supervision-error", 125)
            if isinstance(error, Exception):
                raise StabilityError(f"cannot wait for action: {error}") from error
            raise
        if candidate is not None and type(candidate) is not int:
            try:
                _stop_process_group(handle)
            finally:
                seal_failure("supervision-error", 125)
            raise StabilityError("action returned a malformed exit code")
        exit_code = candidate
        if exit_code is not None:
            break
        after_ns = writer.clock.monotonic_ns()
        if after_ns <= before_ns:
            try:
                _stop_process_group(handle)
            finally:
                seal_failure("supervision-error", 125)
            raise StabilityError("action wait made no monotonic progress")
        if after_ns >= deadline_ns:
            break
        try:
            writer.append("heartbeat", {
                "stage": kind,
                "child_pid": handle.pid,
                "action_id": action_id_value,
                "cycle_ordinal": cycle_value,
                "action_ordinal": action_value,
            })
        except BaseException:
            _stop_process_group(handle)
            raise

    if exit_code is None:
        cleanup_error: StabilityError | None = None
        try:
            _stop_process_group(handle)
        except StabilityError as error:
            cleanup_error = error
        seal_failure("outer-timeout", 124)
        if cleanup_error is not None:
            raise StabilityError(
                f"action outer timeout and cleanup failed: {cleanup_error}"
            ) from cleanup_error
        raise StabilityError("action exceeded its outer timeout")

    output_error_getter = getattr(handle, "output_error", None)
    output_error = (
        output_error_getter() if callable(output_error_getter) else None
    )
    resource_error_getter = getattr(handle, "resource_error", None)
    resource_error = (
        resource_error_getter() if callable(resource_error_getter) else None
    )
    supervision_error = resource_error or output_error
    if supervision_error is not None:
        cleanup_error: StabilityError | None = None
        try:
            _stop_process_group(handle)
        except StabilityError as error:
            cleanup_error = error
        seal_failure("supervision-error", 125)
        if cleanup_error is not None:
            raise StabilityError(
                f"{supervision_error}; cleanup failed: {cleanup_error}"
            ) from cleanup_error
        raise StabilityError(supervision_error)

    try:
        process_tree_clean = _action_process_tree_clean(handle)
    except Exception as error:
        cleanup_error: StabilityError | None = None
        try:
            _stop_process_group(handle)
        except StabilityError as cleanup:
            cleanup_error = cleanup
        seal_failure("supervision-error", 125)
        message = f"cannot prove action descendant cleanup: {error}"
        if cleanup_error is not None:
            message += f"; cleanup failed: {cleanup_error}"
        raise StabilityError(message) from error

    if exit_code != 0:
        cleanup_error: StabilityError | None = None
        try:
            if not process_tree_clean:
                _stop_process_group(handle)
            else:
                _release_action_disk_reserve(handle)
        except StabilityError as error:
            cleanup_error = error
        seal_failure("nonzero-exit", exit_code)
        if cleanup_error is not None:
            raise StabilityError(
                f"action failed with exit code {exit_code}; "
                f"cleanup failed: {cleanup_error}"
            ) from cleanup_error
        raise StabilityError(f"action failed with exit code {exit_code}")

    if not process_tree_clean:
        _stop_process_group(handle)
        seal_failure("supervision-error", 125)
        raise StabilityError(
            "action left a live process-group or PID-namespace descendant"
        )

    try:
        receipt_before = sha256_file(receipt_path)
        verified_sha = _valid_sha(
            verify_receipt(receipt_path), "verified action receipt"
        )
        receipt_after = sha256_file(receipt_path)
        if verified_sha != receipt_before or receipt_after != receipt_before:
            raise StabilityError("action receipt changed during verification")
    except BaseException as error:
        cleanup_error: StabilityError | None = None
        try:
            _release_action_disk_reserve(handle)
        except StabilityError as release_error:
            cleanup_error = release_error
        seal_failure("receipt-rejected", 0)
        if cleanup_error is not None:
            raise StabilityError(
                f"action receipt verification failed: {error}; "
                f"cleanup failed: {cleanup_error}"
            ) from cleanup_error
        if isinstance(error, StabilityError):
            raise StabilityError(f"action receipt verification failed: {error}") from error
        if isinstance(error, Exception):
            raise StabilityError(f"action receipt verification failed: {error}") from error
        raise

    _append_action_finish(
        writer,
        accepted=True,
        exit_code=0,
        kind=kind,
        action_id=action_id_value,
        outcome="normal",
        receipt_sha256=receipt_before,
        child_pid=handle.pid,
        cycle_ordinal=cycle_value,
        action_ordinal=action_value,
    )
    return {
        "action_id": action_id_value,
        "exit_code": 0,
        "kind": kind,
        "receipt_sha256": receipt_before,
    }


def _validate_planned_action_events(
    events: list[dict[str, Any]], plan: dict[str, Any],
) -> None:
    allowed = {"action-start", "heartbeat", "action-finish"}
    if not events or any(event.get("event_type") not in allowed for event in events):
        raise StabilityError("cycle executor emitted an unsupported journal event")
    starts = [event["payload"] for event in events if event["event_type"] == "action-start"]
    finishes = [
        event["payload"] for event in events
        if event["event_type"] == "action-finish"
    ]
    actions = plan["actions"]
    if len(starts) != len(actions) or len(finishes) != len(actions):
        raise StabilityError("cycle executor did not complete its exact action plan")
    for expected, start, finish in zip(actions, starts, finishes, strict=True):
        common = {
            "action_id": expected["id"],
            "kind": expected["kind"],
            "cycle_ordinal": plan["ordinal"],
            "action_ordinal": expected["ordinal"],
        }
        if any(start[field] != value for field, value in common.items()):
            raise StabilityError("cycle action start differs from the fixed plan")
        if start["timeout_seconds"] != expected["timeout_seconds"]:
            raise StabilityError("cycle action timeout differs from the fixed plan")
        if any(finish[field] != value for field, value in common.items()):
            raise StabilityError("cycle action finish differs from the fixed plan")
        if (
            start["child_pid"] != finish["child_pid"]
            or finish["accepted"] is not True
            or finish["exit_code"] != 0
            or finish["outcome"] != "normal"
            or finish["receipt_sha256"] is None
        ):
            raise StabilityError("cycle action did not finish as accepted")


def _run_campaign(
    writer: JournalWriter,
    policy: dict[str, Any],
    schedule: dict[str, Any],
    execute_cycle: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Run the exact cold/warm scope; elapsed time is evidence, not a gate."""

    if writer.policy != policy:
        raise StabilityError("controller policy differs from the journal policy")
    if not callable(execute_cycle):
        raise StabilityError("cycle executor is unavailable")
    initial_events = writer.events
    if (
        len(initial_events) != 1
        or initial_events[0]["event_type"] != "session-start"
    ):
        raise StabilityError("campaign controller requires a fresh journal")
    required_cycles = policy["completion"]["required_complete_rounds"]
    cycle_records: list[dict[str, Any]] = []

    for ordinal in range(1, required_cycles + 1):
        plan = build_cycle_plan(
            policy, schedule, writer.session_id, ordinal
        )
        event_start = len(writer.events)
        cycle_start_ns = writer.clock.monotonic_ns()
        raw_result = execute_cycle(copy.deepcopy(plan))
        cycle_end_ns = writer.clock.monotonic_ns()
        if cycle_end_ns <= cycle_start_ns:
            raise StabilityError("cycle executor made no monotonic progress")
        emitted = writer.events[event_start:]
        _validate_planned_action_events(emitted, plan)

        result = _exact_dict(
            raw_result,
            {
                "cycle_id", "mode", "receipt_path", "receipt_sha256",
                "slot_count",
            },
            "cycle executor result",
        )
        if result["cycle_id"] != plan["id"]:
            raise StabilityError("cycle executor identity differs from the fixed plan")
        if result["mode"] != plan["mode"]:
            raise StabilityError("cycle executor mode differs from the fixed plan")
        _fixed_integer(result["slot_count"], 9, "cycle executor slot count")
        if not isinstance(result["receipt_path"], Path):
            raise StabilityError("cycle executor receipt path is malformed")
        receipt_sha = _valid_sha(
            result["receipt_sha256"], "cycle executor receipt"
        )
        if receipt_sha == ZERO_SHA256:
            raise StabilityError("cycle executor receipt hash is unavailable")
        if sha256_file(result["receipt_path"]) != receipt_sha:
            raise StabilityError("cycle executor receipt checksum mismatch")

        writer.append("cycle-finish", {
            "accepted": True,
            "mode": plan["mode"],
            "ordinal": ordinal,
            "slot_count": 9,
            "cycle_id": plan["id"],
            "receipt_sha256": receipt_sha,
        })
        cycle_records.append({
            "cycle_id": plan["id"],
            "mode": plan["mode"],
            "ordinal": ordinal,
            "plan_sha256": plan["plan_sha256"],
            "receipt_path": os.fspath(result["receipt_path"]),
            "receipt_sha256": receipt_sha,
        })
    writer.append("session-finish", {"status": "accepted"})
    timeline = verify_journal(
        writer.events,
        policy,
        expected_session_id=writer.session_id,
        expected_controller_id=writer.controller_id,
        expected_boot_id=writer.expected_boot_id,
        expected_schedule=schedule,
    )
    return {"cycles": cycle_records, "timeline": timeline}


def run_campaign(
    writer: JournalWriter,
    policy: dict[str, Any],
    schedule: dict[str, Any],
    execute_cycle: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    try:
        return _run_campaign(writer, policy, schedule, execute_cycle)
    except BaseException:
        events = writer.events
        if not events or events[-1]["event_type"] != "session-finish":
            try:
                writer.append("session-finish", {"status": "rejected"})
            except StabilityError:
                pass
        raise


def verify_journal(
    events: Any,
    policy: dict[str, Any],
    *,
    expected_session_id: str,
    expected_controller_id: str,
    expected_boot_id: str,
    expected_schedule: dict[str, Any],
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(events, list) or len(events) < 4:
        raise StabilityError("journal is incomplete")
    _valid_sha(expected_session_id, "session identity")
    _valid_sha(expected_controller_id, "controller identity")
    if not isinstance(expected_boot_id, str) or BOOT_ID.fullmatch(expected_boot_id) is None:
        raise StabilityError("expected boot identity is malformed")
    expected_plans = [
        build_cycle_plan(
            policy, expected_schedule, expected_session_id, ordinal
        )
        for ordinal in range(
            1, policy["completion"]["required_complete_rounds"] + 1
        )
    ]

    previous_hash = ZERO_SHA256
    previous_monotonic: int | None = None
    previous_boottime: int | None = None
    maximum_gap_ns = 0
    maximum_suspend_ns = 0
    maximum_transition_ns = 0
    cycles: list[dict[str, Any]] = []
    active_action: dict[str, Any] | None = None
    active_action_start_ns: int | None = None
    seen_action_ids: set[str] = set()
    completed_action_count = 0
    open_cycle_action_count = 0
    next_action_ordinal = 0
    transition_anchor_ns: int | None = None

    event_fields = {
        "schema", "seq", "previous_event_sha256", "event_type", "session_id",
        "controller_id", "boot_id", "monotonic_ns", "boottime_ns", "utc",
        "payload", "event_sha256",
    }
    for expected_seq, event in enumerate(events):
        value = _exact_dict(event, event_fields, "journal event")
        if value["schema"] != EVENT_SCHEMA:
            raise StabilityError("journal event schema is unsupported")
        if value["seq"] != expected_seq:
            raise StabilityError("journal event sequence is not contiguous")
        if value["previous_event_sha256"] != previous_hash:
            raise StabilityError("journal hash chain is broken")
        claimed_hash = _valid_sha(value["event_sha256"], "event")
        material = {key: item for key, item in value.items() if key != "event_sha256"}
        if digest_json(material) != claimed_hash:
            raise StabilityError("journal event hash mismatch")
        if value["session_id"] != expected_session_id:
            raise StabilityError("journal session identity drift")
        if value["controller_id"] != expected_controller_id:
            raise StabilityError("controller identity changed during the session")
        if value["boot_id"] != expected_boot_id:
            raise StabilityError("boot identity changed during the session")
        monotonic_ns = _integer(value["monotonic_ns"], "event monotonic time")
        boottime_ns = _integer(value["boottime_ns"], "event boot time")
        _validate_utc(value["utc"])
        _validate_event_payload(value["event_type"], value["payload"])
        if value["event_type"] == "action-finish" and (
            not value["payload"]["accepted"]
            or value["payload"]["exit_code"] != 0
        ):
            raise StabilityError("action failed or is unavailable")

        if previous_monotonic is not None and previous_boottime is not None:
            monotonic_delta = monotonic_ns - previous_monotonic
            boottime_delta = boottime_ns - previous_boottime
            if monotonic_delta < 0:
                raise StabilityError("monotonic clock regressed")
            if boottime_delta < 0:
                raise StabilityError("boot clock regressed")
            maximum_gap_ns = max(maximum_gap_ns, monotonic_delta)
            suspend_ns = abs(boottime_delta - monotonic_delta)
            maximum_suspend_ns = max(maximum_suspend_ns, suspend_ns)
            if monotonic_delta > policy["heartbeat"]["maximum_gap_seconds"] * 1_000_000_000:
                raise StabilityError("heartbeat gap exceeds the fixed maximum")
            if suspend_ns > policy["heartbeat"]["maximum_suspend_delta_seconds"] * 1_000_000_000:
                raise StabilityError("suspend delta exceeds the fixed maximum")

        event_type = value["event_type"]
        payload = value["payload"]
        transition_limit_ns = (
            policy["heartbeat"]["maximum_action_transition_seconds"]
            * 1_000_000_000
        )

        def check_transition(label: str) -> None:
            nonlocal maximum_transition_ns
            if transition_anchor_ns is None:
                raise StabilityError(f"{label} has no prior action transition")
            transition_ns = monotonic_ns - transition_anchor_ns
            if transition_ns < 0:
                raise StabilityError("action transition clock regressed")
            maximum_transition_ns = max(maximum_transition_ns, transition_ns)
            if transition_ns > transition_limit_ns:
                raise StabilityError(
                    f"{label} exceeds the fixed action transition maximum"
                )

        if event_type == "session-start":
            if expected_seq != 0:
                raise StabilityError("journal has duplicate session start")
            transition_anchor_ns = monotonic_ns
        elif event_type == "action-start":
            if active_action is not None:
                raise StabilityError("nested action start is forbidden")
            check_transition("action start transition")
            expected_cycle = len(cycles) + 1
            if payload["cycle_ordinal"] != expected_cycle:
                raise StabilityError("action cycle ordinal is not contiguous")
            if payload["action_ordinal"] != next_action_ordinal:
                raise StabilityError("action ordinal is not contiguous")
            if payload["action_id"] in seen_action_ids:
                raise StabilityError("duplicate action identity")
            if expected_cycle > len(expected_plans):
                raise StabilityError(
                    "journal has a cycle outside the fixed plan"
                )
            plan = expected_plans[expected_cycle - 1]
            if next_action_ordinal >= len(plan["actions"]):
                raise StabilityError(
                    "journal has an action outside the fixed plan"
                )
            expected_action = plan["actions"][next_action_ordinal]
            if payload != {
                "action_id": expected_action["id"],
                "kind": expected_action["kind"],
                "cycle_ordinal": expected_cycle,
                "action_ordinal": expected_action["ordinal"],
                "timeout_seconds": expected_action["timeout_seconds"],
                "child_pid": payload["child_pid"],
            }:
                raise StabilityError(
                    "journal action start differs from the fixed plan"
                )
            seen_action_ids.add(payload["action_id"])
            active_action = payload
            active_action_start_ns = monotonic_ns
            transition_anchor_ns = None
            next_action_ordinal += 1
        elif event_type == "heartbeat":
            if active_action is None:
                raise StabilityError("heartbeat has no active action")
            expected_heartbeat = {
                "stage": active_action["kind"],
                "child_pid": active_action["child_pid"],
                "action_id": active_action["action_id"],
                "cycle_ordinal": active_action["cycle_ordinal"],
                "action_ordinal": active_action["action_ordinal"],
            }
            if payload != expected_heartbeat:
                raise StabilityError("heartbeat does not match its active action")
        elif event_type == "action-finish":
            if active_action is None or active_action_start_ns is None:
                raise StabilityError("action finish has no active action")
            for field in (
                "action_id", "kind", "child_pid", "cycle_ordinal",
                "action_ordinal",
            ):
                if payload[field] != active_action[field]:
                    raise StabilityError("action finish does not match its active action")
            elapsed_ns = monotonic_ns - active_action_start_ns
            if elapsed_ns < 0:
                raise StabilityError("action duration clock regressed")
            if elapsed_ns > active_action["timeout_seconds"] * 1_000_000_000:
                raise StabilityError("action exceeded its declared timeout")
            cycle_index = active_action["cycle_ordinal"] - 1
            action_index = active_action["action_ordinal"]
            plan = expected_plans[cycle_index]
            expected_action = plan["actions"][action_index]
            if any(
                payload[field] != expected
                for field, expected in {
                    "action_id": expected_action["id"],
                    "kind": expected_action["kind"],
                    "cycle_ordinal": plan["ordinal"],
                    "action_ordinal": expected_action["ordinal"],
                }.items()
            ):
                raise StabilityError(
                    "journal action finish differs from the fixed plan"
                )
            if evidence_root is not None:
                receipt_path = (
                    evidence_root / "cycles" / f"{plan['ordinal']:06d}"
                    / "actions"
                    / (
                        f"{expected_action['ordinal']:02d}-"
                        f"{expected_action['kind']}"
                    )
                    / "receipt.json"
                )
                before = sha256_file(receipt_path)
                if payload["receipt_sha256"] != before:
                    raise StabilityError(
                        "journal action receipt checksum mismatch"
                    )
                retained = _load_document(
                    receipt_path, "terminal action receipt"
                )
                identity = _exact_dict(
                    retained.get("identity"),
                    {
                        "action_id", "cycle_id", "cycle_ordinal",
                        "action_ordinal", "kind", "plan_sha256",
                    },
                    "terminal action receipt identity",
                )
                if (
                    retained.get("schema") != ACTION_RECEIPT_SCHEMA
                    or retained.get("status") != "accepted"
                    or retained.get("failures") != []
                    or identity != {
                        "action_id": expected_action["id"],
                        "cycle_id": plan["id"],
                        "cycle_ordinal": plan["ordinal"],
                        "action_ordinal": expected_action["ordinal"],
                        "kind": expected_action["kind"],
                        "plan_sha256": plan["plan_sha256"],
                    }
                    or sha256_file(receipt_path) != before
                ):
                    raise StabilityError(
                        "journal action receipt identity drift"
                    )
            active_action = None
            active_action_start_ns = None
            completed_action_count += 1
            open_cycle_action_count += 1
            transition_anchor_ns = monotonic_ns
        elif event_type == "cycle-finish":
            if active_action is not None:
                raise StabilityError("cycle finished with an active action")
            if open_cycle_action_count < 1:
                raise StabilityError("cycle has no completed action")
            expected_plan = expected_plans[len(cycles)]
            if open_cycle_action_count != len(expected_plan["actions"]):
                raise StabilityError(
                    "cycle did not complete its exact fixed plan"
                )
            check_transition("cycle finish transition")
            transition_anchor_ns = monotonic_ns
            open_cycle_action_count = 0
            next_action_ordinal = 0
        elif event_type == "session-finish":
            if active_action is not None:
                raise StabilityError("session finished with an active action")
            if open_cycle_action_count != 0:
                raise StabilityError("session finished before sealing its cycle")
            check_transition("session finish transition")

        if event_type == "cycle-finish":
            cycle = payload
            ordinal = len(cycles) + 1
            if cycle["ordinal"] != ordinal:
                raise StabilityError("cycle ordinals are missing or duplicated")
            expected_mode = "cold" if ordinal == 1 else "warm"
            if cycle["mode"] != expected_mode:
                raise StabilityError("cold-to-warm cycle order is invalid")
            plan = expected_plans[ordinal - 1]
            if (
                cycle["cycle_id"] != plan["id"]
                or cycle["ordinal"] != plan["ordinal"]
            ):
                raise StabilityError(
                    "cycle event differs from its fixed plan"
                )
            cycles.append(cycle)

        previous_hash = claimed_hash
        previous_monotonic = monotonic_ns
        previous_boottime = boottime_ns

    if events[0]["event_type"] != "session-start":
        raise StabilityError("journal does not start with session-start")
    if events[-1]["event_type"] != "session-finish":
        raise StabilityError("journal does not end with session-finish")
    if sum(event["event_type"] == "session-start" for event in events) != 1:
        raise StabilityError("journal has duplicate session start")
    if sum(event["event_type"] == "session-finish" for event in events) != 1:
        raise StabilityError("journal has duplicate session finish")
    if events[-1]["payload"]["status"] != "accepted":
        raise StabilityError("session is explicitly rejected")

    start_ns = events[0]["monotonic_ns"]
    finish_ns = events[-1]["monotonic_ns"]
    duration_ns = finish_ns - start_ns
    completion = policy["completion"]
    if len(cycles) != completion["required_complete_rounds"]:
        raise StabilityError("journal does not contain the exact cold/warm scope")
    if sum(cycle["mode"] == "cold" for cycle in cycles) != completion[
        "required_cold_rounds"
    ]:
        raise StabilityError("journal cold round count drift")
    if sum(cycle["mode"] == "warm" for cycle in cycles) != completion[
        "required_warm_rounds"
    ]:
        raise StabilityError("journal warm restart round count drift")

    duration_seconds: int | float
    if duration_ns % 1_000_000_000 == 0:
        duration_seconds = duration_ns // 1_000_000_000
    else:
        duration_seconds = duration_ns / 1_000_000_000
    return {
        "active_duration_seconds": duration_seconds,
        "cycles": len(cycles),
        "cold_cycles": sum(cycle["mode"] == "cold" for cycle in cycles),
        "warm_cycles": sum(cycle["mode"] == "warm" for cycle in cycles),
        "event_count": len(events),
        "action_count": completed_action_count,
        "journal_sha256": digest_json(events),
        "maximum_gap_seconds": maximum_gap_ns / 1_000_000_000,
        "maximum_suspend_delta_seconds": maximum_suspend_ns / 1_000_000_000,
        "maximum_action_transition_seconds": (
            maximum_transition_ns / 1_000_000_000
        ),
        "terminal_event_sha256": previous_hash,
    }


def _atomic_create(path: Path, data: bytes) -> None:
    try:
        parent = path.parent
        parent_metadata = parent.lstat()
    except OSError as error:
        raise StabilityError(f"cannot inspect output directory {path.parent}: {error}") from error
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise StabilityError(f"output parent is not a directory: {path.parent}")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise StabilityError(f"cannot inspect output path {path}: {error}") from error
    else:
        raise StabilityError(f"refusing to replace existing evidence file: {path}")

    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    linked = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StabilityError(f"short write while creating {path}")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, path)
        linked = True
        os.unlink(temporary)
        if os.name == "posix":
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except (OSError, StabilityError) as error:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        if linked:
            try:
                path.unlink()
            except OSError:
                pass
        if isinstance(error, StabilityError):
            raise
        raise StabilityError(f"cannot atomically create evidence file {path}: {error}") from error


def _artifact_file_limit(maximum_file_bytes: int | None) -> int:
    limit = (
        MAX_ARTIFACT_FILE_BYTES
        if maximum_file_bytes is None
        else maximum_file_bytes
    )
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise StabilityError("artifact file size limit is invalid")
    return limit


def _regular_files(
    root: Path, *, maximum_file_bytes: int | None = None,
) -> list[str]:
    file_limit = _artifact_file_limit(maximum_file_bytes)
    try:
        metadata = root.lstat()
    except OSError as error:
        raise StabilityError(f"cannot inspect evidence root {root}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise StabilityError("evidence root is not a directory")
    result: list[str] = []
    directory_count = 1
    byte_count = 0
    pending = [root]
    while pending:
        current_path = pending.pop()
        try:
            iterator = os.scandir(current_path)
        except OSError as error:
            raise StabilityError(
                f"cannot enumerate evidence directory {current_path}: {error}"
            ) from error
        with iterator:
            for entry in iterator:
                path = Path(entry.path)
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise StabilityError(
                        f"cannot inspect evidence path {path}: {error}"
                    ) from error
                if stat.S_ISDIR(metadata.st_mode):
                    directory_count += 1
                    if directory_count > MAX_ARTIFACT_DIRECTORIES:
                        raise StabilityError(
                            "evidence directory count exceeds the fixed limit"
                        )
                    pending.append(path)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise StabilityError(
                        f"evidence path is not a regular file: {path}"
                    )
                if metadata.st_size > file_limit:
                    raise StabilityError(
                        f"evidence file exceeds the fixed size limit: {path}"
                    )
                byte_count += metadata.st_size
                if byte_count > MAX_ARTIFACT_BYTES:
                    raise StabilityError(
                        "evidence byte count exceeds the fixed limit"
                    )
                result.append(path.relative_to(root).as_posix())
                if len(result) > MAX_ARTIFACTS:
                    raise StabilityError(
                        "evidence file count exceeds the fixed limit"
                    )
    return sorted(result)


def directory_identity(
    root: Path,
    label: str,
    *,
    maximum_file_bytes: int | None = None,
) -> dict[str, Any]:
    file_limit = _artifact_file_limit(maximum_file_bytes)
    paths = _regular_files(root, maximum_file_bytes=file_limit)
    if not paths:
        raise StabilityError(f"{label} directory is empty")
    if len(paths) > MAX_ARTIFACTS:
        raise StabilityError(f"{label} file count exceeds the fixed limit")
    entries = [
        _artifact_entry(
            root, relative, maximum_file_bytes=file_limit
        )
        for relative in paths
    ]
    total_size = sum(entry["size"] for entry in entries)
    if total_size > MAX_ARTIFACT_BYTES:
        raise StabilityError(f"{label} byte count exceeds the fixed limit")
    return {
        "schema": "codeskeptic-stability-directory-identity-v1",
        "file_count": len(entries),
        "byte_count": total_size,
        "entries_sha256": digest_json(entries),
    }


def verify_build_authority_evidence(
    authority_root: Path,
    expected: dict[str, Any],
    *,
    source_root: Path | None = None,
    build_path: Path | None = None,
    verifier: Callable[[Path], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    before = directory_identity(authority_root, "build authority")
    if verifier is None:
        try:
            import analyzer_build_authority as build_authority
        except ImportError as error:
            raise StabilityError(
                f"build authority verifier is unavailable: {error}"
            ) from error

        if source_root is None or build_path is None:
            raise StabilityError(
                "full build authority verification requires source and build paths"
            )

        def static_verifier(root: Path) -> dict[str, Any]:
            return build_authority.verify_authority_in_current_runtime(
                root, source_root, build_path
            )

        verifier = static_verifier
    try:
        receipt = verifier(authority_root)
    except Exception as error:
        raise StabilityError(f"build authority verification failed: {error}") from error
    after = directory_identity(authority_root, "build authority")
    if after != before:
        raise StabilityError("build authority changed during verification")
    projection_expected = {
        field: expected[field]
        for field in (
            "source_revision", "source_manifest_sha256", "analyzer_sha256"
        )
    }
    projection = project_build_authority_receipt(receipt, projection_expected)
    receipt_sha = sha256_file(authority_root / "receipt.json")
    return {
        "bundle": before,
        "receipt_sha256": receipt_sha,
        "projection": projection,
    }


def verify_quality_floor_evidence(
    package: Path,
    source_root: Path,
    expected: dict[str, Any],
    *,
    verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    before = directory_identity(package, "quality-floor package")
    if verifier is None:
        try:
            import run_quality_floor_campaign as quality_floor
        except ImportError as error:
            raise StabilityError(
                f"quality-floor verifier is unavailable: {error}"
            ) from error
        verifier = quality_floor.verify_retained_package
    try:
        receipt = verifier(
            package, require_accepted=True, source_root=source_root
        )
    except Exception as error:
        raise StabilityError(f"quality-floor verification failed: {error}") from error
    after = directory_identity(package, "quality-floor package")
    if after != before:
        raise StabilityError("quality-floor package changed during verification")
    projection_expected = {
        field: expected[field]
        for field in (
            "source_revision", "source_manifest_sha256", "analyzer_sha256"
        )
    }
    projection = project_quality_floor_receipt(receipt, projection_expected)
    retained_build_path = package / "raw" / "build-authority" / "receipt.json"
    retained_build = _load_document(
        retained_build_path, "quality-floor retained build authority"
    )
    build_projection = project_build_authority_receipt(
        retained_build, projection_expected
    )
    expected_build_identity = expected.get("build_identity_sha256")
    if (
        expected_build_identity is not None
        and build_projection["build_identity_sha256"] != expected_build_identity
    ):
        raise StabilityError("quality-floor build authority identity drift")
    return {
        "bundle": before,
        "receipt_sha256": sha256_file(package / "receipt.json"),
        "projection": projection,
        "build_authority_projection": build_projection,
    }


def verify_sanitizer_evidence(
    evidence_root: Path,
    test_build: Path,
    fuzz_build: Path,
    expected: dict[str, Any],
    *,
    verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    before = directory_identity(evidence_root, "sanitizer evidence")
    if verifier is None:
        try:
            import run_sanitizer_matrix as sanitizer
        except ImportError as error:
            raise StabilityError(
                f"sanitizer verifier is unavailable: {error}"
            ) from error
        verifier = sanitizer.verify_receipt
    try:
        receipt = verifier(evidence_root, test_build, fuzz_build)
    except Exception as error:
        raise StabilityError(f"sanitizer verification failed: {error}") from error
    after = directory_identity(evidence_root, "sanitizer evidence")
    if after != before:
        raise StabilityError("sanitizer evidence changed during verification")
    return {
        "bundle": before,
        "receipt_sha256": sha256_file(evidence_root / "receipt.json"),
        "projection": project_sanitizer_receipt(receipt, expected),
    }


def verify_fault_injection_test_binary_authority(
    config: dict[str, Any], sanitizer_results: Any,
) -> dict[str, Any]:
    """Link the live fault binary to the verified undefined sanitizer receipt."""

    value = validate_runtime_config(config)
    results = _exact_dict(
        sanitizer_results,
        {"address", "undefined"},
        "fault-injection sanitizer authorities",
    )
    undefined = results["undefined"]
    if not isinstance(undefined, dict):
        raise StabilityError("undefined sanitizer authority is malformed")
    projection = undefined.get("projection")
    if not isinstance(projection, dict):
        raise StabilityError("undefined sanitizer projection is malformed")
    receipt_sha = _valid_sha(
        undefined.get("receipt_sha256"), "undefined sanitizer receipt"
    )
    configured_receipt_sha = value["sanitizers"]["undefined"][
        "receipt_sha256"
    ]
    receipt_binary_sha = _valid_sha(
        projection.get("test_binary_sha256"),
        "undefined sanitizer codeskeptic_tests binary",
    )
    configured = value["fault_injection"]
    binary_path = Path(configured["test_binary"])
    if (
        receipt_sha != configured_receipt_sha
        or receipt_binary_sha != configured["test_binary_sha256"]
        or fault_injection.sha256_binary(binary_path) != receipt_binary_sha
    ):
        raise StabilityError(
            "fault-injection binary differs from undefined sanitizer authority"
        )
    return {
        "schema": "codeskeptic-stability-fault-injection-binary-authority-v1",
        "path": binary_path.as_posix(),
        "sha256": receipt_binary_sha,
        "sanitizer_profile": "undefined",
        "sanitizer_receipt_sha256": receipt_sha,
        "sanitizer_builds_sha256": _valid_sha(
            projection.get("builds_sha256"),
            "undefined sanitizer build authority",
        ),
    }


def _load_hosted_exact_head_document(path: Path, label: str) -> dict[str, Any]:
    """Load the compact ASCII-canonical document emitted by its authority."""

    data = _read_regular_bytes(path, MAX_DOCUMENT_BYTES)
    try:
        value = json.loads(data.decode("ascii"))
        canonical = (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (
        UnicodeDecodeError,
        UnicodeEncodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise StabilityError(f"{label} JSON is malformed: {error}") from error
    if not isinstance(value, dict) or canonical != data:
        raise StabilityError(f"{label} is not canonical JSON")
    return value


def _verify_hosted_record_file(root: Path, record: dict[str, Any], label: str) -> str:
    path_value = _evidence_relative(record.get("path"), label)
    path = root / path_value
    expected_sha = _valid_sha(record.get("sha256"), label)
    expected_size = _integer(record.get("size"), f"{label} size", 1)
    try:
        size = path.lstat().st_size
    except OSError as error:
        raise StabilityError(f"cannot inspect {label}: {error}") from error
    if size != expected_size or sha256_file(path) != expected_sha:
        raise StabilityError(f"{label} checksum mismatch")
    return path_value


def verify_hosted_exact_head_evidence(
    root: Path, *, repository: str, revision: str,
) -> dict[str, Any]:
    before = directory_identity(root, "hosted exact-head evidence")
    receipt = _load_hosted_exact_head_document(
        root / "receipt.json", "hosted exact-head receipt"
    )
    receipt_data = _read_regular_bytes(root / "receipt.json", MAX_DOCUMENT_BYTES)
    expected_sidecar = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("utf-8")
    if _read_regular_bytes(root / "receipt.json.sha256", 1024) != expected_sidecar:
        raise StabilityError("hosted exact-head receipt checksum mismatch")
    projection = project_hosted_exact_head_receipt(
        receipt, repository=repository, revision=revision
    )
    referenced: list[str] = []
    for index, record in enumerate(receipt["logs"]):
        referenced.append(
            _verify_hosted_record_file(
                root, record, f"hosted retained log {index + 1}"
            )
        )
    for index, record in enumerate(receipt["artifacts"]):
        translated = {
            "path": record.get("archive_path"),
            "sha256": record.get("archive_sha256"),
            "size": record.get("size"),
        }
        referenced.append(
            _verify_hosted_record_file(
                root, translated, f"hosted artifact archive {index + 1}"
            )
        )
    for index, record in enumerate(receipt["snapshots"]):
        referenced.append(
            _verify_hosted_record_file(
                root, record, f"hosted raw authority snapshot {index + 1}"
            )
        )
    if len(referenced) != len(set(referenced)):
        raise StabilityError("hosted retained file inventory contains duplicates")
    referenced = sorted(referenced)
    expected_files = [
        "SHA256SUMS", "receipt.json", "receipt.json.sha256", *referenced
    ]
    if _regular_files(root) != sorted(expected_files):
        raise StabilityError("hosted exact-head file set drift")
    manifest_paths = sorted(
        ["receipt.json", "receipt.json.sha256", *referenced]
    )
    expected_manifest = b"".join(
        f"{sha256_file(root / path)}  {path}\n".encode("utf-8")
        for path in manifest_paths
    )
    if _read_regular_bytes(root / "SHA256SUMS", MAX_DOCUMENT_BYTES) != expected_manifest:
        raise StabilityError("hosted exact-head SHA256SUMS mismatch")
    after = directory_identity(root, "hosted exact-head evidence")
    if after != before:
        raise StabilityError("hosted exact-head evidence changed during verification")
    return {
        "bundle": before,
        "receipt_sha256": sha256_file(root / "receipt.json"),
        "projection": projection,
    }


def verify_hosted_exact_head_authority(
    root: Path,
    source_root: Path,
    *,
    repository: str,
    revision: str,
) -> dict[str, Any]:
    """Re-derive retained GitHub data and exact Git blobs from scratch."""

    before = directory_identity(root, "hosted exact-head authority")
    try:
        import seal_hosted_exact_head as hosted
    except ImportError as error:
        raise StabilityError(
            f"hosted exact-head full verifier is unavailable: {error}"
        ) from error
    try:
        rederived = hosted.verify_evidence(
            root,
            repository=repository,
            revision=revision,
            source=hosted.GitSourceAuthority(
                source_root, repository=repository
            ),
        )
    except Exception as error:
        raise StabilityError(
            f"hosted exact-head full verification failed: {error}"
        ) from error
    structural = verify_hosted_exact_head_evidence(
        root, repository=repository, revision=revision
    )
    retained = _load_hosted_exact_head_document(
        root / "receipt.json", "hosted exact-head receipt"
    )
    if rederived != retained:
        raise StabilityError("hosted exact-head rederived receipt drift")
    after = directory_identity(root, "hosted exact-head authority")
    if after != before or structural["bundle"] != before:
        raise StabilityError("hosted exact-head authority changed during verification")
    return structural


def verify_realworld_mirror_authority(
    authority_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    """Verify every exact release-candidate bundle without a network fallback."""

    root = authority_path.parent
    before = directory_identity(
        root,
        "real-world mirror authority",
        maximum_file_bytes=realworld.MAX_MIRROR_BUNDLE_BYTES,
    )
    try:
        manifest = realworld.validate_manifest(realworld.load_manifest(manifest_path))
        campaign = manifest["campaigns"].get("release-candidate")
        if (
            not isinstance(campaign, dict)
            or campaign.get("projects") != REQUIRED_MATRIX_PROJECTS
            or campaign.get("repetitions") != 3
        ):
            raise realworld.ManifestError(
                "release-candidate mirror selection differs from the exact matrix"
            )
        projects: list[dict[str, Any]] = []
        for project_id in REQUIRED_MATRIX_PROJECTS:
            selected, selected_root = realworld.load_mirror_authority(
                authority_path,
                manifest,
                project_id,
                expected_project_ids=REQUIRED_MATRIX_PROJECTS,
            )
            if selected.get("id") != project_id or selected_root != root.absolute():
                raise realworld.EvidenceError(
                    "mirror verifier returned a different project authority"
                )
            projects.append(copy.deepcopy(selected))
    except realworld.CampaignError as error:
        raise StabilityError(
            f"real-world mirror authority verification failed: {error}"
        ) from error
    after = directory_identity(
        root,
        "real-world mirror authority",
        maximum_file_bytes=realworld.MAX_MIRROR_BUNDLE_BYTES,
    )
    if after != before:
        raise StabilityError("real-world mirror authority changed during verification")
    return {
        "bundle": before,
        "authority_sha256": sha256_file(authority_path),
        "projects_sha256": digest_json(projects),
    }


def verify_runtime_source_and_policy(
    config: dict[str, Any],
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    """Re-derive source, analyzer, policy, and exact schedule in-container."""

    value = validate_runtime_config(config)
    source = Path(value["source"]["root"])
    policy_path = Path(value["policy"]["path"])
    if sha256_file(policy_path) != value["policy"]["sha256"]:
        raise StabilityError("runtime policy differs from its configured checksum")
    policy = validate_policy(
        _load_json(policy_path, "stability policy"), source
    )
    try:
        import run_determinism_qualification as determinism
    except ImportError as error:
        raise StabilityError(f"source authority verifier is unavailable: {error}") from error
    try:
        source_now = determinism.source_manifest(source)
    except Exception as error:
        raise StabilityError(f"cannot derive runtime source manifest: {error}") from error
    if (
        source_now.get("revision") != value["source"]["revision"]
        or source_now.get("manifest_sha256")
        != value["source"]["manifest_sha256"]
    ):
        raise StabilityError("runtime source identity drift")
    try:
        tree_process = subprocess.run(
            ["git", "--no-replace-objects", "rev-parse", "HEAD^{tree}"],
            cwd=source,
            env=determinism._git_authority_environment(source),  # noqa: SLF001
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise StabilityError(f"cannot derive runtime source tree: {error}") from error
    try:
        tree = tree_process.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise StabilityError("runtime source tree is not ASCII") from error
    if (
        tree_process.returncode != 0
        or GIT_SHA1.fullmatch(tree) is None
        or tree != value["source"]["tree_sha1"]
    ):
        raise StabilityError("runtime source tree identity drift")
    if sha256_file(Path(value["analyzer"]["path"])) != value["analyzer"]["sha256"]:
        raise StabilityError("runtime analyzer checksum drift")
    fault_binary = value["fault_injection"]
    if (
        fault_injection.sha256_binary(Path(fault_binary["test_binary"]))
        != fault_binary["test_binary_sha256"]
    ):
        raise StabilityError("runtime fault-injection test binary checksum drift")
    schedule = build_schedule(policy, source)
    return policy, schedule, source_now


def _determinism_baseline_projection_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise StabilityError(
            f"determinism baseline projection is not canonical: {error}"
        ) from error


def verify_determinism_baseline_authority(
    source_root: Path,
    manifest_path: Path,
    baseline_path: Path,
    hardware_class: str,
) -> dict[str, Any]:
    """Verify and project the promoted baseline used by both live gates."""

    source = Path(source_root).absolute()
    manifest_file = Path(manifest_path).absolute()
    baseline_file = Path(baseline_path).absolute()
    try:
        source_metadata = source.lstat()
    except OSError as error:
        raise StabilityError(
            f"cannot inspect determinism baseline authority root: {error}"
        ) from error
    if not stat.S_ISDIR(source_metadata.st_mode) or source.resolve() != source:
        raise StabilityError(
            "determinism baseline authority root is not a canonical real directory"
        )
    canonical_manifest = source / "scripts" / "determinism_workloads.json"
    canonical_baseline = source / "scripts" / "determinism_baseline.json"
    if manifest_file != canonical_manifest or baseline_file != canonical_baseline:
        raise StabilityError(
            "determinism baseline authority files are not canonical"
        )
    if not isinstance(hardware_class, str) or not hardware_class:
        raise StabilityError("determinism baseline hardware class is malformed")

    determinism = _load_private_determinism_authority()

    try:
        manifest_sha = sha256_file(manifest_file)
        baseline_sha = sha256_file(baseline_file)
        manifest = determinism.load_manifest(manifest_file)
        baseline = determinism.load_baseline(
            baseline_file, determinism.digest_json(manifest)
        )
        profiles = baseline.get("profiles")
        if not isinstance(profiles, dict) or hardware_class not in profiles:
            raise StabilityError(
                "determinism baseline hardware class is absent"
            )
        profile = profiles[hardware_class]
        provenance = profile["provenance"]
        calibration = provenance["calibration"]
        evidence_path = calibration["evidence_path"]
        calibration_root = source / evidence_path
        try:
            calibration_metadata = calibration_root.lstat()
        except OSError as error:
            raise StabilityError(
                f"cannot inspect determinism calibration authority: {error}"
            ) from error
        if (
            not stat.S_ISDIR(calibration_metadata.st_mode)
            or calibration_root.resolve() != calibration_root
        ):
            raise StabilityError(
                "determinism calibration authority is not canonical"
            )
        calibration_receipt = calibration_root / "receipt.json"
        calibration_sums = calibration_root / "SHA256SUMS"
        identity_before = {
            "manifest_sha256": manifest_sha,
            "baseline_sha256": baseline_sha,
            "calibration_receipt_sha256": sha256_file(calibration_receipt),
            "calibration_sha256sums_sha256": sha256_file(calibration_sums),
        }
        if (
            identity_before["calibration_receipt_sha256"]
            != calibration["receipt_sha256"]
        ):
            raise StabilityError(
                "determinism calibration receipt differs from baseline provenance"
            )
        determinism.verify_baseline_authority(
            baseline,
            source,
            manifest_file,
            toolchain_verification_mode=(
                determinism.TOOLCHAIN_VERIFICATION_HISTORICAL_RETAINED
            ),
        )
        identity_after = {
            "manifest_sha256": sha256_file(manifest_file),
            "baseline_sha256": sha256_file(baseline_file),
            "calibration_receipt_sha256": sha256_file(calibration_receipt),
            "calibration_sha256sums_sha256": sha256_file(calibration_sums),
        }
        if identity_after != identity_before:
            raise StabilityError(
                "determinism baseline authority changed during verification"
            )
    except StabilityError:
        raise
    except Exception as error:
        raise StabilityError(
            f"determinism baseline authority verification failed: {error}"
        ) from error

    promotion = provenance["promotion"]
    projection = {
        "schema": DETERMINISM_BASELINE_AUTHORITY_SCHEMA,
        "hardware_class": hardware_class,
        "manifest_sha256": manifest_sha,
        "baseline_sha256": baseline_sha,
        "semantic_reference_sha256": digest_json(
            baseline["semantic_reference"]
        ),
        "profile_source_revision": provenance["source_revision"],
        "toolchain_sha256": digest_json(provenance["toolchain"]),
        "hardware_sha256": digest_json(profile["hardware"]),
        "workloads_sha256": digest_json(profile["workloads"]),
        "calibration": {
            "evidence_path": evidence_path,
            "receipt_sha256": calibration["receipt_sha256"],
            "sha256sums_sha256": identity_before[
                "calibration_sha256sums_sha256"
            ],
        },
        "promotion": {
            "previous_baseline_sha256": promotion[
                "previous_baseline_sha256"
            ],
            "previous_profile_sha256": promotion[
                "previous_profile_sha256"
            ],
            "reason_sha256": hashlib.sha256(
                promotion["reason"].encode("utf-8")
            ).hexdigest(),
        },
    }
    return {
        "projection": projection,
        "projection_sha256": hashlib.sha256(
            _determinism_baseline_projection_bytes(projection)
        ).hexdigest(),
        "identity": identity_before,
    }


def verify_release_candidate_authority(
    release_root: Path,
    source_root: Path,
    mirror_root: Path,
    revision: str,
    expected_receipt_sha256: str,
) -> dict[str, Any]:
    """Re-derive and bind the immutable release-candidate authority."""

    release_before = directory_identity(
        release_root, "release-candidate authority"
    )
    receipt_path = release_root / "receipt.json"
    receipt_before = sha256_file(receipt_path)
    if receipt_before != expected_receipt_sha256:
        raise StabilityError("configured release-candidate authority drift")
    try:
        import provision_stability_authorities as provision

        projection = provision.verify_release_authority_in_current_runtime(
            release_root,
            source_root,
            mirror_root,
            revision,
        )
    except Exception as error:
        raise StabilityError(
            f"release-candidate authority verification failed: {error}"
        ) from error
    release_after = directory_identity(
        release_root, "release-candidate authority"
    )
    receipt_after = sha256_file(receipt_path)
    if (
        release_after != release_before
        or receipt_after != receipt_before
        or receipt_after != expected_receipt_sha256
    ):
        raise StabilityError(
            "release-candidate authority changed during verification"
        )
    if not isinstance(projection, dict):
        raise StabilityError(
            "release-candidate authority projection is malformed"
        )
    return {
        "bundle": release_before,
        "receipt_sha256": receipt_before,
        "projection": projection,
    }


def verify_runtime_static_authorities(
    config: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Fully re-verify every prerequisite before the live scope begins."""

    value = validate_runtime_config(config)
    source = Path(value["source"]["root"])
    expected = {
        "source_revision": value["source"]["revision"],
        "source_manifest_sha256": value["source"]["manifest_sha256"],
        "analyzer_sha256": value["analyzer"]["sha256"],
    }
    build = verify_build_authority_evidence(
        Path(value["build_authority"]["root"]),
        expected,
        source_root=source,
        build_path=Path(value["build_authority"]["build_path"]),
    )
    if build["receipt_sha256"] != value["build_authority"]["receipt_sha256"]:
        raise StabilityError("configured build authority receipt drift")
    expected_with_build = {
        **expected,
        "build_identity_sha256": build["projection"][
            "build_identity_sha256"
        ],
    }
    quality = verify_quality_floor_evidence(
        Path(value["prerequisites"]["quality_floor"]["root"]),
        source,
        expected_with_build,
    )
    if quality["receipt_sha256"] != value["prerequisites"]["quality_floor"][
        "receipt_sha256"
    ]:
        raise StabilityError("configured quality-floor receipt drift")
    baseline_authority = verify_determinism_baseline_authority(
        Path(value["qualification"]["baseline_authority"]["root"]),
        source / policy["qualification"]["manifest"],
        source / policy["qualification"]["baseline"],
        value["qualification"]["hardware_class"],
    )
    configured_baseline = value["qualification"]["baseline_authority"]
    if (
        baseline_authority["projection"]["manifest_sha256"]
        != configured_baseline["manifest_sha256"]
        or baseline_authority["projection"]["baseline_sha256"]
        != configured_baseline["baseline_sha256"]
        or baseline_authority["projection_sha256"]
        != configured_baseline["projection_sha256"]
    ):
        raise StabilityError("configured determinism baseline authority drift")
    hosted_config = value["prerequisites"]["hosted_exact_head"]
    hosted = verify_hosted_exact_head_authority(
        Path(hosted_config["root"]),
        source,
        repository=hosted_config["repository"],
        revision=value["source"]["revision"],
    )
    if (
        hosted["receipt_sha256"] != hosted_config["receipt_sha256"]
        or hosted["projection"]["source_tree_sha1"]
        != value["source"]["tree_sha1"]
    ):
        raise StabilityError("configured hosted exact-head authority drift")
    sanitizers: dict[str, Any] = {}
    for profile in ("address", "undefined"):
        record = value["sanitizers"][profile]
        result = verify_sanitizer_evidence(
            Path(record["root"]),
            Path(record["test_build"]),
            Path(record["fuzz_build"]),
            {
                "profile": profile,
                "source_revision": expected["source_revision"],
                "source_manifest_sha256": expected[
                    "source_manifest_sha256"
                ],
            },
        )
        if result["receipt_sha256"] != record["receipt_sha256"]:
            raise StabilityError(f"configured {profile} sanitizer receipt drift")
        sanitizers[profile] = result
    fault_binary = verify_fault_injection_test_binary_authority(
        value, sanitizers
    )
    mirror = verify_realworld_mirror_authority(
        Path(value["realworld"]["mirror_authority"]),
        source / policy["matrix"]["manifest"],
    )
    if mirror["authority_sha256"] != value["realworld"][
        "mirror_authority_sha256"
    ]:
        raise StabilityError("configured real-world mirror authority drift")
    release = verify_release_candidate_authority(
        Path(value["qualification"]["release_source"]).parent,
        source,
        Path(value["realworld"]["mirror_authority"]).parent,
        value["source"]["revision"],
        value["qualification"]["release_receipt_sha256"],
    )
    return {
        "build_authority": build,
        "quality_floor": quality,
        "determinism_baseline": baseline_authority,
        "hosted_exact_head": hosted,
        "sanitizers": sanitizers,
        "fault_injection_test_binary": fault_binary,
        "realworld_mirror": mirror,
        "release_candidate": release,
    }


def _create_private_directory(path: Path, label: str) -> None:
    try:
        path.mkdir(parents=True, exist_ok=False, mode=0o700)
        metadata = path.lstat()
    except OSError as error:
        raise StabilityError(f"cannot create {label}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise StabilityError(f"{label} is not a real directory")


def _stage_regular_file(
    source: Path, destination: Path, label: str,
) -> dict[str, Any]:
    data = _read_regular_bytes(source, MAX_DOCUMENT_BYTES)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_metadata = destination.parent.lstat()
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise StabilityError(f"{label} staging parent is not a real directory")
    _atomic_create(destination, data)
    return {
        "path": destination.as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def runtime_establishment_sources(
    config_path: Path, config: dict[str, Any],
) -> dict[str, tuple[Path, str]]:
    """Return the one fixed external-to-retained establishment mapping."""

    value = validate_runtime_config(config)
    source = Path(value["source"]["root"])
    launch_path = Path(value["runtime"]["launch_receipt"])
    return {
        "runtime_config": (
            config_path, "runtime/runtime.json",
        ),
        "runtime_config_checksum": (
            Path(f"{config_path}.sha256"), "runtime/runtime.json.sha256",
        ),
        "runtime_launch": (
            launch_path, "runtime/launch-receipt.json",
        ),
        "runtime_launch_checksum": (
            Path(f"{launch_path}.sha256"),
            "runtime/launch-receipt.json.sha256",
        ),
        "policy": (
            Path(value["policy"]["path"]),
            "policy/stability_manifest.json",
        ),
        "realworld_manifest": (
            source / "scripts" / "realworld_manifest.json",
            "policy/realworld_manifest.json",
        ),
        "determinism_manifest": (
            source / "scripts" / "determinism_workloads.json",
            "policy/determinism_workloads.json",
        ),
        "determinism_baseline": (
            source / "scripts" / "determinism_baseline.json",
            "policy/determinism_baseline.json",
        ),
        "build_authority": (
            Path(value["build_authority"]["root"]) / "receipt.json",
            "authorities/build_authority.json",
        ),
        "hosted_exact_head": (
            Path(value["prerequisites"]["hosted_exact_head"]["root"])
            / "receipt.json",
            "authorities/hosted_exact_head.json",
        ),
        "quality_floor": (
            Path(value["prerequisites"]["quality_floor"]["root"])
            / "receipt.json",
            "authorities/quality_floor.json",
        ),
        "sanitizer_address": (
            Path(value["sanitizers"]["address"]["root"]) / "receipt.json",
            "authorities/sanitizer_address.json",
        ),
        "sanitizer_undefined": (
            Path(value["sanitizers"]["undefined"]["root"]) / "receipt.json",
            "authorities/sanitizer_undefined.json",
        ),
        "realworld_mirror": (
            Path(value["realworld"]["mirror_authority"]),
            "authorities/realworld_mirror.json",
        ),
        "release_candidate": (
            Path(value["qualification"]["release_source"]).parent
            / "receipt.json",
            "authorities/release_candidate.json",
        ),
    }


def stage_runtime_establishment(
    evidence_root: Path,
    config_path: Path,
    config: dict[str, Any],
    session: dict[str, Any],
    source_identity: dict[str, Any],
    static_authorities: dict[str, Any],
    runtime_resources: dict[str, Any],
) -> dict[str, Any]:
    """Retain compact copies and projections of every external authority."""

    value = validate_runtime_config(config)
    session_value = _validate_session_record(session)
    establishment_root = evidence_root / "establishment"
    _create_private_directory(establishment_root, "establishment output")
    staged: dict[str, dict[str, Any]] = {}

    def stage(name: str, source: Path, relative: str) -> None:
        destination = establishment_root / relative
        record = _stage_regular_file(source, destination, name)
        record["path"] = _relative_evidence_path(
            destination, evidence_root, f"staged {name}"
        )
        staged[name] = record

    for name, (source_path, relative) in runtime_establishment_sources(
        config_path, value
    ).items():
        stage(name, source_path, relative)

    baseline_result = static_authorities.get("determinism_baseline")
    if not isinstance(baseline_result, dict):
        raise StabilityError("determinism baseline authority result is malformed")
    baseline_projection = baseline_result.get("projection")
    if not isinstance(baseline_projection, dict):
        raise StabilityError("determinism baseline projection is malformed")
    baseline_data = _determinism_baseline_projection_bytes(
        baseline_projection
    )
    baseline_projection_sha = hashlib.sha256(baseline_data).hexdigest()
    if (
        baseline_result.get("projection_sha256") != baseline_projection_sha
        or value["qualification"]["baseline_authority"]["projection_sha256"]
        != baseline_projection_sha
    ):
        raise StabilityError("determinism baseline projection identity drift")
    baseline_destination = (
        establishment_root / "authorities" / "determinism_baseline.json"
    )
    baseline_destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        baseline_parent_metadata = baseline_destination.parent.lstat()
    except OSError as error:
        raise StabilityError(
            f"cannot inspect determinism baseline staging parent: {error}"
        ) from error
    if not stat.S_ISDIR(baseline_parent_metadata.st_mode):
        raise StabilityError(
            "determinism baseline staging parent is not a real directory"
        )
    _atomic_create(baseline_destination, baseline_data)
    staged["determinism_baseline"] = {
        "path": _relative_evidence_path(
            baseline_destination,
            evidence_root,
            "staged determinism baseline",
        ),
        "sha256": baseline_projection_sha,
        "size": len(baseline_data),
    }

    establishment = {
        "schema": ESTABLISHMENT_SCHEMA,
        "status": "accepted",
        "failures": [],
        "session": session_value,
        "source": copy.deepcopy(source_identity),
        "static_authorities": copy.deepcopy(static_authorities),
        "runtime_resources": copy.deepcopy(runtime_resources),
        "staged": copy.deepcopy(staged),
    }
    establishment_path = establishment_root / "receipt.json"
    _atomic_create(establishment_path, canonical_document(establishment))
    establishment_sha = sha256_file(establishment_path)

    authority_names = (
        "build_authority", "determinism_baseline",
        "hosted_exact_head", "quality_floor", "release_candidate",
    )
    authorities = {
        name: {
            "path": staged[name]["path"],
            "sha256": staged[name]["sha256"],
        }
        for name in authority_names
    }
    diagnostics = {
        profile: {
            "path": staged[f"sanitizer_{profile}"]["path"],
            "sha256": staged[f"sanitizer_{profile}"]["sha256"],
        }
        for profile in ("address", "undefined")
    }
    return {
        "path": _relative_evidence_path(
            establishment_path, evidence_root, "establishment receipt"
        ),
        "sha256": establishment_sha,
        "authorities": authorities,
        "diagnostics": diagnostics,
    }


def verify_runtime_establishment(
    evidence_root: Path,
    config_path: Path,
    config: dict[str, Any],
    session: dict[str, Any],
    source_identity: dict[str, Any],
    static_authorities: dict[str, Any],
    runtime_resources: dict[str, Any],
    *,
    source_records: dict[str, tuple[Path, str]] | None = None,
) -> dict[str, Any]:
    """Compare every retained establishment file with its live authority."""

    session_value = _validate_session_record(session)
    records = (
        runtime_establishment_sources(config_path, config)
        if source_records is None else source_records
    )
    if not isinstance(records, dict) or not records:
        raise StabilityError("runtime establishment source map is malformed")
    include_baseline_projection = source_records is None
    establishment_path = evidence_root / "establishment" / "receipt.json"
    retained = _load_document(
        establishment_path, "runtime establishment receipt"
    )
    value = _exact_dict(
        retained,
        {
            "schema", "status", "failures", "session", "source",
            "static_authorities", "runtime_resources", "staged",
        },
        "runtime establishment receipt",
    )
    if (
        value["schema"] != ESTABLISHMENT_SCHEMA
        or value["status"] != "accepted"
        or value["failures"] != []
        or value["session"] != session_value
        or value["source"] != source_identity
        or value["static_authorities"] != static_authorities
        or value["runtime_resources"] != runtime_resources
    ):
        raise StabilityError(
            "runtime establishment differs from rederived authorities"
        )
    staged = value["staged"]
    expected_names = set(records)
    if include_baseline_projection:
        expected_names.add("determinism_baseline")
    if not isinstance(staged, dict) or set(staged) != expected_names:
        raise StabilityError("runtime establishment staged inventory drift")
    normalized_staged: dict[str, dict[str, Any]] = {}
    for name, source_record in records.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(source_record, tuple)
            or len(source_record) != 2
        ):
            raise StabilityError(
                "runtime establishment source map entry is malformed"
            )
        source_path, relative_value = source_record
        if not isinstance(source_path, Path) or not isinstance(relative_value, str):
            raise StabilityError(
                "runtime establishment source map entry is malformed"
            )
        relative = Path(relative_value)
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or relative.as_posix() != relative_value
        ):
            raise StabilityError(
                "runtime establishment retained path is malformed"
            )
        record = _exact_dict(
            staged[name], {"path", "sha256", "size"},
            f"staged runtime authority {name}",
        )
        expected_path = f"establishment/{relative_value}"
        expected_sha = sha256_file(source_path)
        try:
            source_size = source_path.lstat().st_size
        except OSError as error:
            raise StabilityError(
                f"cannot inspect runtime establishment source {name}: {error}"
            ) from error
        if (
            record["path"] != expected_path
            or record["sha256"] != expected_sha
            or record["size"] != source_size
        ):
            raise StabilityError(
                f"staged runtime authority differs from its source: {name}"
            )
        retained_path = evidence_root / expected_path
        try:
            retained_size = retained_path.lstat().st_size
        except OSError as error:
            raise StabilityError(
                f"cannot inspect staged runtime authority {name}: {error}"
            ) from error
        if retained_size != source_size or sha256_file(retained_path) != expected_sha:
            raise StabilityError(
                f"staged runtime authority checksum mismatch: {name}"
            )
        normalized_staged[name] = copy.deepcopy(record)
    if include_baseline_projection:
        baseline_result = static_authorities.get("determinism_baseline")
        if not isinstance(baseline_result, dict):
            raise StabilityError(
                "determinism baseline authority result is malformed"
            )
        baseline_projection = baseline_result.get("projection")
        if not isinstance(baseline_projection, dict):
            raise StabilityError("determinism baseline projection is malformed")
        baseline_data = _determinism_baseline_projection_bytes(
            baseline_projection
        )
        baseline_sha = hashlib.sha256(baseline_data).hexdigest()
        if baseline_result.get("projection_sha256") != baseline_sha:
            raise StabilityError("determinism baseline projection identity drift")
        record = _exact_dict(
            staged["determinism_baseline"],
            {"path", "sha256", "size"},
            "staged determinism baseline authority",
        )
        expected_path = (
            "establishment/authorities/determinism_baseline.json"
        )
        retained_path = evidence_root / expected_path
        if (
            record["path"] != expected_path
            or record["sha256"] != baseline_sha
            or record["size"] != len(baseline_data)
            or _read_regular_bytes(retained_path, MAX_DOCUMENT_BYTES)
            != baseline_data
        ):
            raise StabilityError(
                "staged determinism baseline authority checksum mismatch"
            )
        normalized_staged["determinism_baseline"] = copy.deepcopy(record)
    if normalized_staged != staged:
        raise StabilityError("runtime establishment staged inventory drift")
    return {
        "path": _relative_evidence_path(
            establishment_path, evidence_root, "runtime establishment receipt"
        ),
        "sha256": sha256_file(establishment_path),
        "staged": normalized_staged,
    }


def verify_runtime_static_authority_identities(
    config: dict[str, Any], static_authorities: dict[str, Any],
) -> None:
    """Ensure no prerequisite bundle changed after its semantic verification."""

    value = validate_runtime_config(config)
    expected = _exact_dict(
        static_authorities,
        {
            "build_authority", "quality_floor", "determinism_baseline",
            "hosted_exact_head", "sanitizers", "realworld_mirror",
            "fault_injection_test_binary", "release_candidate",
        },
        "runtime static authority results",
    )
    roots = {
        "build_authority": Path(value["build_authority"]["root"]),
        "quality_floor": Path(value["prerequisites"]["quality_floor"]["root"]),
        "hosted_exact_head": Path(
            value["prerequisites"]["hosted_exact_head"]["root"]
        ),
        "realworld_mirror": Path(
            value["realworld"]["mirror_authority"]
        ).parent,
        "release_candidate": Path(
            value["qualification"]["release_source"]
        ).parent,
    }
    for name, root in roots.items():
        result = expected[name]
        if not isinstance(result, dict) or "bundle" not in result:
            raise StabilityError(f"runtime {name} authority result is malformed")
        identity_options = (
            {
                "maximum_file_bytes": (
                    realworld.MAX_MIRROR_BUNDLE_BYTES
                )
            }
            if name == "realworld_mirror"
            else {}
        )
        if directory_identity(
            root, f"runtime {name} authority", **identity_options
        ) != result["bundle"]:
            raise StabilityError(f"runtime {name} authority changed after verification")
    baseline = verify_determinism_baseline_authority(
        Path(value["qualification"]["baseline_authority"]["root"]),
        Path(value["source"]["root"])
        / "scripts"
        / "determinism_workloads.json",
        Path(value["source"]["root"])
        / "scripts"
        / "determinism_baseline.json",
        value["qualification"]["hardware_class"],
    )
    if baseline != expected["determinism_baseline"]:
        raise StabilityError(
            "runtime determinism baseline authority changed after verification"
        )
    sanitizers = _exact_dict(
        expected["sanitizers"], {"address", "undefined"},
        "runtime sanitizer authority results",
    )
    for profile in ("address", "undefined"):
        result = sanitizers[profile]
        if not isinstance(result, dict) or "bundle" not in result:
            raise StabilityError(
                f"runtime {profile} sanitizer authority result is malformed"
            )
        root = Path(value["sanitizers"][profile]["root"])
        if directory_identity(
            root, f"runtime {profile} sanitizer authority"
        ) != result["bundle"]:
            raise StabilityError(
                f"runtime {profile} sanitizer authority changed after verification"
            )
    fault_binary = verify_fault_injection_test_binary_authority(
        value, sanitizers
    )
    if expected["fault_injection_test_binary"] != fault_binary:
        raise StabilityError(
            "runtime fault-injection binary authority changed after verification"
        )


def run_production_session(
    config_path: Path,
    evidence_root: Path,
    *,
    clock: StabilityClock | None = None,
) -> dict[str, Any]:
    """Run and seal one fresh exact cold/warm stability session."""

    clock_value: StabilityClock = LinuxClock() if clock is None else clock
    try:
        output_metadata = evidence_root.lstat()
    except OSError as error:
        raise StabilityError(f"cannot inspect evidence output: {error}") from error
    if not stat.S_ISDIR(output_metadata.st_mode):
        raise StabilityError("evidence output is not a real directory")
    try:
        if any(evidence_root.iterdir()):
            raise StabilityError("evidence output is not empty")
    except OSError as error:
        raise StabilityError(f"cannot enumerate evidence output: {error}") from error

    config = load_runtime_config_file(config_path)
    source = Path(config["source"]["root"])
    boot_id = clock_value.boot_id()
    launch_path = Path(config["runtime"]["launch_receipt"])
    launch = load_runtime_launch_receipt(
        launch_path,
        config,
        runtime_config_sha256=sha256_file(config_path),
        boot_id=boot_id,
    )
    policy, schedule, source_identity = verify_runtime_source_and_policy(config)
    runtime_resources = verify_runtime_resource_limits(policy)
    static_authorities = verify_runtime_static_authorities(config, policy)
    session = build_runtime_session_record(
        config,
        runtime_config_sha256=sha256_file(config_path),
        runtime_launch_receipt_sha256=sha256_file(launch_path),
        boot_id=boot_id,
        controller_id=secrets.token_hex(32),
        repository_root=source,
    )
    if launch["boot_id"] != session["identity"]["boot_id"]:
        raise StabilityError("runtime launch and session boot identities differ")
    establishment = stage_runtime_establishment(
        evidence_root,
        config_path,
        config,
        session,
        source_identity,
        static_authorities,
        runtime_resources,
    )
    writer = JournalWriter(
        evidence_root / "journal.jsonl",
        policy,
        session["id"],
        session["controller_id"],
        config["policy"]["sha256"],
        clock_value,
    )
    command_runner: SubprocessCommandRunner | None = None
    campaign: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        command_runner = SubprocessCommandRunner(
            evidence_root=evidence_root,
            runtime_root=Path("/runtime"),
        )
        campaign = run_campaign(
            writer,
            policy,
            schedule,
            lambda plan: execute_production_cycle(
                writer,
                config,
                session,
                plan,
                config_path=config_path,
                evidence_root=evidence_root,
                runtime_root=Path("/runtime"),
                runner=command_runner,
            ),
        )
    except BaseException as error:
        primary_error = error
    cleanup_errors: list[str] = []
    if command_runner is not None:
        try:
            command_runner.close()
        except BaseException as error:
            cleanup_errors.append(f"action runner close: {error}")
    try:
        writer.close()
    except BaseException as error:
        cleanup_errors.append(f"journal close: {error}")
    _raise_after_independent_cleanup(
        primary_error, cleanup_errors, "production session"
    )
    if campaign is None:
        raise StabilityError("production campaign returned no result")

    cycle_records: list[dict[str, str]] = []
    cycle_documents: list[dict[str, Any]] = []
    for ordinal in range(1, policy["completion"]["required_complete_rounds"] + 1):
        path = evidence_root / "cycles" / f"{ordinal:06d}" / "cycle.json"
        cycle_records.append({
            "path": _relative_evidence_path(path, evidence_root, "cycle receipt"),
            "sha256": sha256_file(path),
        })
        cycle_documents.append(_load_document(path, "cycle receipt"))
    cycle_summary = validate_cycle_documents(
        cycle_documents, evidence_root, session, schedule, policy
    )
    base_receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "accepted",
        "policy": {
            "path": Path(config["policy"]["path"]).relative_to(source).as_posix(),
            "sha256": config["policy"]["sha256"],
        },
        "session": session,
        "schedule": schedule,
        "timeline": campaign["timeline"],
        "cycles": cycle_records,
        "cycle_summary": cycle_summary,
        "establishment": {
            "path": establishment["path"],
            "sha256": establishment["sha256"],
        },
        "authorities": establishment["authorities"],
        "diagnostics": establishment["diagnostics"],
        "gates": {
            "scope": "pass",
            "crash_hang": "pass",
            "semantic": "pass",
            "performance": "pass",
            "performance_scope": PERFORMANCE_SCOPE,
            "coverage": "pass",
            "restart": "pass",
            "sanitizer": "pass",
            "fault_injection": "pass",
            "resources": "pass",
            "orphan_free": "pass",
        },
        "failures": [],
    }
    receipt = finalize_evidence(evidence_root, base_receipt)
    verified = verify_production_evidence(
        config_path, evidence_root, runtime_root=Path("/runtime")
    )
    if verified != receipt:
        raise StabilityError("final stability receipt changed after publication")
    return receipt


def _load_document(path: Path, label: str) -> dict[str, Any]:
    data = _read_regular_bytes(path, MAX_DOCUMENT_BYTES)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StabilityError(f"{label} JSON is malformed: {error}") from error
    if not isinstance(value, dict) or canonical_document(value) != data:
        raise StabilityError(f"{label} is not canonical JSON")
    return value


def _artifact_entry(
    root: Path,
    relative: str,
    *,
    maximum_file_bytes: int | None = None,
) -> dict[str, Any]:
    file_limit = _artifact_file_limit(maximum_file_bytes)
    path = root / relative
    try:
        size = path.lstat().st_size
    except OSError as error:
        raise StabilityError(f"cannot inspect artifact {relative}: {error}") from error
    if size > file_limit:
        raise StabilityError(
            f"artifact exceeds the fixed size limit: {relative}"
        )
    return {
        "path": relative,
        "sha256": sha256_file(path, maximum_size=file_limit),
        "size": size,
    }


def finalize_evidence(root: Path, base_receipt: Any) -> dict[str, Any]:
    base_fields = {
        "schema", "status", "policy", "session", "schedule", "timeline",
        "cycles", "cycle_summary", "establishment", "authorities",
        "diagnostics", "gates", "failures",
    }
    base = _exact_dict(base_receipt, base_fields, "stability receipt")
    for reserved in ("receipt.json", "receipt.json.sha256", "SHA256SUMS"):
        if (root / reserved).exists() or (root / reserved).is_symlink():
            raise StabilityError(f"reserved evidence output already exists: {reserved}")
    artifact_paths = _regular_files(root)
    if len(artifact_paths) > MAX_ARTIFACTS:
        raise StabilityError("evidence artifact count exceeds the fixed limit")
    artifacts = [_artifact_entry(root, relative) for relative in artifact_paths]
    if sum(item["size"] for item in artifacts) > MAX_ARTIFACT_BYTES:
        raise StabilityError("evidence artifact bytes exceed the fixed limit")
    receipt = {**copy.deepcopy(base), "artifacts": artifacts}
    receipt_data = canonical_document(receipt)
    sidecar_data = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("utf-8")
    _atomic_create(root / "receipt.json", receipt_data)
    _atomic_create(root / "receipt.json.sha256", sidecar_data)
    manifest_paths = [
        "receipt.json", "receipt.json.sha256", *artifact_paths
    ]
    checksum_data = b"".join(
        f"{sha256_file(root / relative)}  {relative}\n".encode("utf-8")
        for relative in manifest_paths
    )
    _atomic_create(root / "SHA256SUMS", checksum_data)
    return receipt


def _validate_artifact_inventory(
    root: Path, receipt: dict[str, Any], actual_files: list[str],
) -> None:
    inventory = receipt.get("artifacts")
    if not isinstance(inventory, list) or len(inventory) > MAX_ARTIFACTS:
        raise StabilityError("receipt artifact inventory is malformed")
    paths: list[str] = []
    total_size = 0
    for item in inventory:
        value = _exact_dict(item, {"path", "sha256", "size"}, "receipt artifact")
        relative_value = value["path"]
        if not isinstance(relative_value, str) or not relative_value:
            raise StabilityError("receipt artifact path is malformed")
        relative = Path(relative_value)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative_value in {"receipt.json", "receipt.json.sha256", "SHA256SUMS"}
        ):
            raise StabilityError("receipt artifact path is inadmissible")
        _valid_sha(value["sha256"], "receipt artifact")
        size = _integer(value["size"], "receipt artifact size")
        if size > MAX_ARTIFACT_FILE_BYTES:
            raise StabilityError("receipt artifact exceeds the fixed size limit")
        paths.append(relative.as_posix())
        total_size += size
    if paths != sorted(set(paths)):
        raise StabilityError("receipt artifact inventory is not sorted and unique")
    if total_size > MAX_ARTIFACT_BYTES:
        raise StabilityError("receipt artifact bytes exceed the fixed limit")
    expected_files = sorted({
        "receipt.json", "receipt.json.sha256", "SHA256SUMS", *paths
    })
    if actual_files != expected_files:
        raise StabilityError("evidence file set differs from the receipt")
    for item in inventory:
        path = root / item["path"]
        try:
            size = path.lstat().st_size
        except OSError as error:
            raise StabilityError(f"cannot inspect receipt artifact: {error}") from error
        if size != item["size"] or sha256_file(path) != item["sha256"]:
            raise StabilityError(f"artifact checksum mismatch: {item['path']}")


def verify_evidence_structure(
    root: Path, policy_path: Path, repository_root: Path,
) -> dict[str, Any]:
    actual_files = _regular_files(root)
    receipt = _load_document(root / "receipt.json", "stability receipt")
    receipt_data = _read_regular_bytes(root / "receipt.json", MAX_DOCUMENT_BYTES)
    expected_sidecar = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("utf-8")
    if _read_regular_bytes(root / "receipt.json.sha256", 1024) != expected_sidecar:
        raise StabilityError("stability receipt checksum mismatch")
    receipt_fields = {
        "schema", "status", "policy", "session", "schedule", "timeline",
        "cycles", "cycle_summary", "establishment", "authorities",
        "diagnostics", "gates", "failures", "artifacts",
    }
    _exact_dict(receipt, receipt_fields, "stability receipt")
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["status"] != "accepted"
        or receipt["failures"] != []
    ):
        raise StabilityError("stability receipt is not accepted")
    _validate_artifact_inventory(root, receipt, actual_files)
    manifest_paths = [
        "receipt.json", "receipt.json.sha256",
        *[item["path"] for item in receipt["artifacts"]],
    ]
    expected_manifest = b"".join(
        f"{sha256_file(root / relative)}  {relative}\n".encode("utf-8")
        for relative in manifest_paths
    )
    if _read_regular_bytes(root / "SHA256SUMS", MAX_DOCUMENT_BYTES) != expected_manifest:
        raise StabilityError("outer SHA256SUMS checksum manifest mismatch")

    policy_record = _exact_dict(
        receipt["policy"], {"path", "sha256"}, "receipt policy"
    )
    try:
        expected_policy_relative = policy_path.relative_to(repository_root).as_posix()
    except ValueError as error:
        raise StabilityError("policy path is outside the repository") from error
    if policy_record["path"] != expected_policy_relative:
        raise StabilityError("receipt policy path drift")
    if policy_record["sha256"] != sha256_file(policy_path):
        raise StabilityError("receipt policy checksum drift")
    policy = validate_policy(_load_json(policy_path, "stability policy"), repository_root)
    session = _validate_session_record(receipt["session"])
    session_identity = session["identity"]
    if session_identity["policy_sha256"] != policy_record["sha256"]:
        raise StabilityError("session policy identity drift")
    for field, relative in (
        ("realworld_manifest_sha256", policy["matrix"]["manifest"]),
        ("determinism_manifest_sha256", policy["qualification"]["manifest"]),
        ("baseline_sha256", policy["qualification"]["baseline"]),
    ):
        if session_identity[field] != sha256_file(repository_root / relative):
            raise StabilityError(f"session {field} authority drift")

    schedule = build_schedule(policy, repository_root)
    if receipt["schedule"] != schedule:
        raise StabilityError("receipt schedule differs from the exact matrix")
    establishment = _exact_dict(
        receipt["establishment"], {"path", "sha256"},
        "receipt establishment",
    )
    _linked_regular_sha(
        root,
        establishment["path"],
        establishment["sha256"],
        "runtime establishment receipt",
    )
    authorities = _exact_dict(
        receipt["authorities"],
        {
            "build_authority", "determinism_baseline",
            "hosted_exact_head", "quality_floor", "release_candidate",
        },
        "receipt authorities",
    )
    for authority in (
        "build_authority", "determinism_baseline",
        "hosted_exact_head", "quality_floor", "release_candidate",
    ):
        record = _exact_dict(
            authorities[authority], {"path", "sha256"},
            f"{authority} authority",
        )
        _linked_regular_sha(
            root, record["path"], record["sha256"], f"{authority} authority"
        )
        if authority == "build_authority":
            if record["sha256"] != session_identity["build_authority_receipt_sha256"]:
                raise StabilityError("build authority session identity mismatch")
        elif authority == "determinism_baseline":
            if (
                record["sha256"]
                != session_identity["baseline_authority_projection_sha256"]
            ):
                raise StabilityError(
                    "determinism baseline session identity mismatch"
                )
        elif authority == "release_candidate":
            if (
                record["sha256"]
                != session_identity["release_candidate_receipt_sha256"]
            ):
                raise StabilityError(
                    "release-candidate session identity mismatch"
                )
        elif record["sha256"] != session_identity["prerequisite_receipts"][authority]:
            raise StabilityError(f"prerequisite {authority} session identity mismatch")
    diagnostics = _exact_dict(
        receipt["diagnostics"], {"address", "undefined"},
        "receipt sanitizer diagnostics",
    )
    for profile in ("address", "undefined"):
        record = _exact_dict(
            diagnostics[profile], {"path", "sha256"},
            f"{profile} sanitizer diagnostic",
        )
        _linked_regular_sha(
            root, record["path"], record["sha256"],
            f"{profile} sanitizer diagnostic",
        )
        if record["sha256"] != session_identity["sanitizer_receipts"][profile]:
            raise StabilityError(f"sanitizer {profile} session identity mismatch")

    events = load_journal(root / "journal.jsonl")
    timeline = verify_journal(
        events,
        policy,
        expected_session_id=session["id"],
        expected_controller_id=session["controller_id"],
        expected_boot_id=session_identity["boot_id"],
        expected_schedule=schedule,
        evidence_root=root,
    )
    if receipt["timeline"] != timeline:
        raise StabilityError("receipt timeline differs from the journal")

    cycle_records = receipt["cycles"]
    if not isinstance(cycle_records, list):
        raise StabilityError("receipt cycle index is malformed")
    cycle_documents: list[dict[str, Any]] = []
    for ordinal, item in enumerate(cycle_records, 1):
        record = _exact_dict(item, {"path", "sha256"}, "receipt cycle index")
        expected_path = f"cycles/{ordinal:06d}/cycle.json"
        if record["path"] != expected_path:
            raise StabilityError("receipt cycle index is not contiguous")
        _linked_regular_sha(
            root, record["path"], record["sha256"], "cycle receipt"
        )
        cycle_documents.append(
            _load_document(root / record["path"], "cycle receipt")
        )
    cycle_summary = validate_cycle_documents(
        cycle_documents, root, session, schedule, policy
    )
    if receipt["cycle_summary"] != cycle_summary:
        raise StabilityError("receipt cycle summary differs from child evidence")
    if timeline["cycles"] != cycle_summary["cycles"]:
        raise StabilityError("timeline and cycle evidence counts differ")
    journal_cycles = [
        event["payload"] for event in events
        if event["event_type"] == "cycle-finish"
    ]
    expected_journal_cycles = [
        {
            "accepted": True,
            "mode": cycle["mode"],
            "ordinal": ordinal,
            "slot_count": 9,
            "cycle_id": cycle["identity"]["id"],
            "receipt_sha256": cycle_records[ordinal - 1]["sha256"],
        }
        for ordinal, cycle in enumerate(cycle_documents, 1)
    ]
    if journal_cycles != expected_journal_cycles:
        raise StabilityError("journal cycle events differ from sealed cycle evidence")

    gates = _exact_dict(
        receipt["gates"],
        {
            "scope", "crash_hang", "semantic", "performance",
            "performance_scope", "coverage", "restart", "sanitizer",
            "fault_injection", "resources", "orphan_free",
        },
        "stability gates",
    )
    if gates["performance_scope"] != PERFORMANCE_SCOPE or any(
        value != "pass"
        for name, value in gates.items()
        if name != "performance_scope"
    ):
        raise StabilityError("stability gate is not passing")
    return receipt


def verify_production_evidence(
    config_path: Path,
    evidence_root: Path,
    *,
    runtime_root: Path = Path("/runtime"),
    source_policy_verifier: Callable[
        [dict[str, Any]], tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
    ] | None = None,
    static_authority_verifier: Callable[
        [dict[str, Any], dict[str, Any]], dict[str, Any]
    ] | None = None,
    cycle_authority_verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Re-derive a completed production bundle from every live authority."""

    config = load_runtime_config_file(config_path)
    source = Path(config["source"]["root"])
    policy_path = Path(config["policy"]["path"])
    receipt = verify_evidence_structure(evidence_root, policy_path, source)
    session = _validate_session_record(receipt["session"])
    identity = session["identity"]
    config_sha = sha256_file(config_path)
    launch_path = Path(config["runtime"]["launch_receipt"])
    load_runtime_launch_receipt(
        launch_path,
        config,
        runtime_config_sha256=config_sha,
        boot_id=identity["boot_id"],
    )
    expected_session = build_runtime_session_record(
        config,
        runtime_config_sha256=config_sha,
        runtime_launch_receipt_sha256=sha256_file(launch_path),
        boot_id=identity["boot_id"],
        controller_id=session["controller_id"],
        repository_root=source,
    )
    if expected_session != session:
        raise StabilityError("production session differs from runtime authorities")

    source_verifier = (
        verify_runtime_source_and_policy
        if source_policy_verifier is None else source_policy_verifier
    )
    static_verifier = (
        verify_runtime_static_authorities
        if static_authority_verifier is None else static_authority_verifier
    )
    cycle_verifier = (
        verify_cycle_action_authorities
        if cycle_authority_verifier is None else cycle_authority_verifier
    )
    if not callable(source_verifier):
        raise StabilityError("runtime source verifier is unavailable")
    if not callable(static_verifier):
        raise StabilityError("runtime static authority verifier is unavailable")
    if not callable(cycle_verifier):
        raise StabilityError("runtime cycle authority verifier is unavailable")

    policy, schedule, source_identity = source_verifier(config)
    runtime_resources = verify_runtime_resource_limits(policy)
    if receipt["schedule"] != schedule:
        raise StabilityError("production schedule differs from source authority")
    static_authorities = static_verifier(config, policy)
    establishment = verify_runtime_establishment(
        evidence_root,
        config_path,
        config,
        session,
        source_identity,
        static_authorities,
        runtime_resources,
    )
    if receipt["establishment"] != {
        "path": establishment["path"],
        "sha256": establishment["sha256"],
    }:
        raise StabilityError(
            "production establishment index differs from rederived receipt"
        )
    staged = establishment["staged"]
    for authority in (
        "build_authority", "determinism_baseline",
        "hosted_exact_head", "quality_floor", "release_candidate",
    ):
        expected_record = {
            "path": staged[authority]["path"],
            "sha256": staged[authority]["sha256"],
        }
        if receipt["authorities"][authority] != expected_record:
            raise StabilityError(
                f"production {authority} index differs from establishment"
            )
    for profile in ("address", "undefined"):
        staged_name = f"sanitizer_{profile}"
        expected_record = {
            "path": staged[staged_name]["path"],
            "sha256": staged[staged_name]["sha256"],
        }
        if receipt["diagnostics"][profile] != expected_record:
            raise StabilityError(
                f"production {profile} sanitizer index differs from establishment"
            )

    try:
        strict_cycle_summary = cycle_verifier(
            config,
            session,
            policy,
            schedule,
            evidence_root=evidence_root,
            runtime_root=runtime_root,
        )
    except StabilityError:
        raise
    except Exception as error:
        raise StabilityError(
            f"production cycle authority verification failed: {error}"
        ) from error
    if strict_cycle_summary != receipt["cycle_summary"]:
        raise StabilityError(
            "production cycle summary differs from rederived action authorities"
        )

    verify_runtime_static_authority_identities(config, static_authorities)
    final_policy, final_schedule, final_source_identity = source_verifier(config)
    if (
        final_policy != policy
        or final_schedule != schedule
        or final_source_identity != source_identity
        or sha256_file(config_path) != config_sha
        or sha256_file(launch_path)
        != session["identity"]["runtime_launch_receipt_sha256"]
    ):
        raise StabilityError(
            "runtime authority changed during production evidence verification"
        )
    final_receipt = verify_evidence_structure(evidence_root, policy_path, source)
    if final_receipt != receipt:
        raise StabilityError(
            "production evidence changed during strict verification"
        )
    return receipt


_HOST_COMMAND_SUPERVISOR = r"""
import ctypes
import json
import os
import subprocess
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    os._exit(125)
argv = json.loads(sys.argv[1])
child = subprocess.Popen(
    argv, stdin=subprocess.DEVNULL, close_fds=True
)
return_code = child.wait()
while True:
    try:
        pid, _status = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        break
    if pid == 0:
        time.sleep(0.02)
if return_code < 0:
    return_code = 128 + min(127, -return_code)
os._exit(return_code if return_code <= 255 else 125)
"""


def _proc_process_record(pid: int) -> tuple[int, int, str] | None:
    try:
        data = (Path("/proc") / str(pid) / "stat").read_text(
            encoding="ascii"
        )
        fields = data.rsplit(")", 1)[1].strip().split()
        return int(fields[1]), int(fields[19]), fields[0]
    except (FileNotFoundError, OSError, UnicodeDecodeError, ValueError, IndexError):
        return None


def _proc_process_identity(pid: int) -> tuple[int, int] | None:
    record = _proc_process_record(pid)
    if record is None:
        return None
    return record[0], record[1]


def _owned_host_descendants(root_pid: int) -> dict[int, int]:
    try:
        names = os.listdir("/proc")
    except OSError as error:
        raise StabilityError(
            f"cannot enumerate host observation descendants: {error}"
        ) from error
    identities: dict[int, tuple[int, int]] = {}
    children: dict[int, list[int]] = {}
    for name in names:
        if not name.isascii() or not name.isdigit():
            continue
        pid = int(name)
        identity = _proc_process_identity(pid)
        if identity is None:
            continue
        identities[pid] = identity
        children.setdefault(identity[0], []).append(pid)
    result: dict[int, int] = {}
    pending = list(children.get(root_pid, []))
    while pending:
        pid = pending.pop()
        if pid in result or pid not in identities:
            continue
        result[pid] = identities[pid][1]
        pending.extend(children.get(pid, []))
    return result


def _signal_owned_pid(pid: int, start_time: int, signal_number: int) -> None:
    identity = _proc_process_identity(pid)
    if identity is None or identity[1] != start_time:
        return
    try:
        os.kill(pid, signal_number)
    except ProcessLookupError:
        return
    except PermissionError as error:
        raise StabilityError(
            f"cannot signal owned host observation PID {pid}: {error}"
        ) from error


def _kill_owned_host_command(process: subprocess.Popen[bytes]) -> None:
    """Quiesce the host-command subreaper tree and reap it to ECHILD."""

    root_pid = process.pid
    root_identity = _proc_process_identity(root_pid)
    if root_identity is None:
        try:
            process.wait(timeout=0.0)
        except subprocess.TimeoutExpired as error:
            raise StabilityError(
                "host observation supervisor identity disappeared"
            ) from error
        return
    root_start_time = root_identity[1]
    known: dict[int, int] = {}
    deadline = time.monotonic() + 5.0
    try:
        _signal_owned_pid(root_pid, root_start_time, signal.SIGSTOP)
        while True:
            if time.monotonic() >= deadline:
                raise StabilityError(
                    "host observation descendants did not quiesce during cleanup"
                )
            root_record = _proc_process_record(root_pid)
            if root_record is None or root_record[1] != root_start_time:
                break
            try:
                root_tasks = _action_task_states(root_pid, root_start_time)
            except _ActionTaskInventoryUnavailable as error:
                raise StabilityError(
                    "host observation supervisor thread inventory is unavailable"
                ) from error
            except _ActionTaskSnapshotChanged:
                _signal_owned_pid(root_pid, root_start_time, signal.SIGSTOP)
                time.sleep(0.01)
                continue
            if root_tasks is None:
                break
            if any(
                state not in _QUIESCED_ACTION_TASK_STATES
                for state in root_tasks.values()
            ):
                _signal_owned_pid(root_pid, root_start_time, signal.SIGSTOP)
                time.sleep(0.01)
                continue

            descendants = _owned_host_descendants(root_pid)
            known.update(descendants)
            live = False
            for pid, start_time in descendants.items():
                try:
                    task_states = _action_task_states(pid, start_time)
                except _ActionTaskInventoryUnavailable:
                    # The stopped subreaper owns this exact TGID. Kill its
                    # hidden thread group and rediscover any adopted forks.
                    live = True
                    _signal_owned_pid(pid, start_time, signal.SIGKILL)
                    continue
                except _ActionTaskSnapshotChanged:
                    live = True
                    _signal_owned_pid(pid, start_time, signal.SIGSTOP)
                    continue
                if task_states is None:
                    continue
                active_states = [
                    state for state in task_states.values()
                    if state not in _DEAD_ACTION_TASK_STATES
                ]
                if not active_states:
                    continue
                live = True
                if all(state in {"T", "t"} for state in active_states):
                    # Only an observably stopped process is killed. It cannot
                    # fork between this observation and uncatchable SIGKILL.
                    _signal_owned_pid(pid, start_time, signal.SIGSTOP)
                    _signal_owned_pid(pid, start_time, signal.SIGKILL)
                else:
                    # Rediscover after SIGSTOP delivery; a fixed number of
                    # snapshots misses cleanup-time forks and new sessions.
                    _signal_owned_pid(pid, start_time, signal.SIGSTOP)
            if not live:
                break
            time.sleep(0.01)

        root_record = _proc_process_record(root_pid)
        if root_record is not None and root_record[1] == root_start_time:
            if known:
                # The wrapper's waitpid(-1, WNOHANG) loop is the ECHILD
                # authority. Let it reap every stopped/killed descendant.
                _signal_owned_pid(root_pid, root_start_time, signal.SIGCONT)
            else:
                # With an observably stopped wrapper and no descendants, no
                # target can appear after this exact snapshot.
                _signal_owned_pid(root_pid, root_start_time, signal.SIGKILL)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StabilityError(
                "host observation supervisor cleanup deadline expired"
            )
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise StabilityError(
                "host observation subreaper did not reap descendants to ECHILD"
            ) from error
        survivors = {
            pid: start_time
            for pid, start_time in known.items()
            if (
                (identity := _proc_process_identity(pid)) is not None
                and identity[1] == start_time
            )
        }
        if survivors:
            raise StabilityError(
                "host observation owned descendants survived convergent cleanup"
            )
    except Exception as cleanup_error:
        # Fallback signals remain PID/starttime-exact. Never use a raw PGID:
        # it could have been reused by an unrelated shared-host process.
        for pid, start_time in known.items():
            _signal_owned_pid(pid, start_time, signal.SIGKILL)
        _signal_owned_pid(root_pid, root_start_time, signal.SIGKILL)
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired as error:
            raise StabilityError(
                f"{cleanup_error}; host observation supervisor survived SIGKILL"
            ) from error
        if isinstance(cleanup_error, StabilityError):
            raise
        raise StabilityError(
            f"cannot converge host observation cleanup: {cleanup_error}"
        ) from cleanup_error


def _bounded_host_command(
    argv: list[str],
    maximum_stdout: int,
    *,
    timeout_seconds: int = HOST_COMMAND_TIMEOUT_SECONDS,
) -> bytes:
    """Run one fixed host observation without permitting unbounded pipes."""

    if (
        not argv
        or any(not isinstance(item, str) or not item for item in argv)
        or not Path(argv[0]).is_absolute()
        or maximum_stdout < 0
    ):
        raise StabilityError("host observation command is malformed")
    environment = {
        "HOME": "/root",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }
    if not sys.platform.startswith("linux") or not Path("/proc/self/stat").is_file():
        raise StabilityError(
            "host observation descendant containment requires Linux /proc"
        )
    supervisor_argv = [
        os.path.realpath(sys.executable),
        "-I",
        "-c",
        _HOST_COMMAND_SUPERVISOR,
        json.dumps(argv, ensure_ascii=True, separators=(",", ":")),
    ]
    try:
        process = subprocess.Popen(
            supervisor_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        raise StabilityError(
            f"cannot start host observation {argv[0]}: {error}"
        ) from error
    selector: selectors.BaseSelector | None = None
    stdout = process.stdout
    stderr = process.stderr
    streams: dict[int, tuple[str, int, bytearray]] = {}
    stdout_fd: int | None = None
    stderr_fd: int | None = None
    return_code: int | None = None
    failure: str | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        if stdout is None or stderr is None:
            raise StabilityError("host observation pipes are unavailable")
        selector = selectors.DefaultSelector()
        stdout_fd = stdout.fileno()
        stderr_fd = stderr.fileno()
        streams = {
            stdout_fd: ("stdout", maximum_stdout, bytearray()),
            stderr_fd: (
                "stderr", MAX_HOST_COMMAND_STDERR_BYTES, bytearray()
            ),
        }
        for descriptor in streams:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "host observation timed out"
                _kill_owned_host_command(process)
                break
            if not selector.get_map():
                if process.poll() is not None:
                    break
                time.sleep(min(0.05, remaining))
                continue
            events = selector.select(min(0.25, remaining))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in list(selector.get_map().values())
                ]
            for key, _mask in events:
                descriptor = key.fd
                try:
                    block = os.read(descriptor, 64 * 1024)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(descriptor)
                    continue
                name, limit, buffer = streams[descriptor]
                if len(buffer) + len(block) > limit:
                    failure = f"host observation {name} exceeds its size limit"
                    _kill_owned_host_command(process)
                    break
                buffer.extend(block)
            if failure is not None:
                break
        if failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "host observation timed out"
                _kill_owned_host_command(process)
                return_code = process.returncode
            else:
                try:
                    return_code = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = "host observation timed out"
                    _kill_owned_host_command(process)
                    return_code = process.returncode
        else:
            return_code = process.returncode
    except BaseException as error:
        primary_error = error
        try:
            _kill_owned_host_command(process)
        except Exception as cleanup_error:
            cleanup_errors.append(f"process cleanup: {cleanup_error}")
    finally:
        if selector is not None:
            try:
                selector.close()
            except Exception as error:
                cleanup_errors.append(f"selector close: {error}")
        for label, stream in (("stdout", stdout), ("stderr", stderr)):
            if stream is None:
                continue
            try:
                stream.close()
            except Exception as error:
                cleanup_errors.append(f"{label} close: {error}")
    if primary_error is not None:
        suffix = (
            "; cleanup failed: " + "; ".join(cleanup_errors)
            if cleanup_errors else ""
        )
        if isinstance(primary_error, StabilityError):
            raise StabilityError(f"{primary_error}{suffix}") from primary_error
        if isinstance(primary_error, Exception):
            raise StabilityError(
                f"host observation supervision failed: {primary_error}{suffix}"
            ) from primary_error
        if cleanup_errors:
            raise StabilityError(
                "host observation interrupted; cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from primary_error
        raise primary_error
    if cleanup_errors:
        raise StabilityError(
            "host observation cleanup failed: " + "; ".join(cleanup_errors)
        )
    if failure is not None:
        raise StabilityError(failure)
    if stdout_fd is None or stderr_fd is None:
        raise StabilityError("host observation pipe identity is unavailable")
    stdout = bytes(streams[stdout_fd][2])
    stderr = bytes(streams[stderr_fd][2])
    if return_code != 0:
        raise StabilityError(
            f"host observation returned nonzero exit {return_code}: {argv[0]}"
        )
    if stderr:
        raise StabilityError(f"host observation wrote stderr: {argv[0]}")
    return stdout


HostCommandRunner = Callable[[list[str], int], bytes]


def _host_command_bytes(
    argv: list[str], maximum_size: int,
    command_runner: HostCommandRunner | None,
) -> bytes:
    if command_runner is None:
        data = _bounded_host_command(argv, maximum_size)
    else:
        try:
            data = command_runner(copy.deepcopy(argv), maximum_size)
        except StabilityError:
            raise
        except Exception as error:
            raise StabilityError(
                f"host observation runner failed: {argv[0]}: {error}"
            ) from error
    if not isinstance(data, bytes) or len(data) > maximum_size:
        raise StabilityError("host observation output exceeds its size limit")
    return data


def _host_raw_files(phase: str) -> dict[str, str]:
    if phase == "pre":
        return HOST_SNAPSHOT_PRE_RAW_FILES
    if phase == "post":
        return HOST_SNAPSHOT_POST_RAW_FILES
    raise StabilityError("host snapshot phase is malformed")


def _user_journal_command_prefix(
    target_user: str, target_uid: int, target_home: str,
) -> list[str]:
    user_runtime = f"/run/user/{target_uid}"
    return [
        "/usr/bin/runuser", "-u", target_user, "--",
        "/usr/bin/env", "-i",
        f"HOME={target_home}", f"USER={target_user}",
        f"LOGNAME={target_user}", "PATH=/usr/sbin:/usr/bin",
        "LC_ALL=C", "LANG=C", f"XDG_RUNTIME_DIR={user_runtime}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={user_runtime}/bus",
        "/usr/bin/journalctl", "--user", "--quiet", "--no-pager",
    ]


def _host_commands(
    target_user: str,
    target_uid: int,
    target_home: str,
    boot_id: str,
    phase: str,
    *,
    system_cursor: str | None = None,
    user_cursor: str | None = None,
) -> dict[str, list[str]]:
    machine = f"{target_user}@.host"
    common = ["--no-pager", "--no-legend", "--plain", "--full"]
    boot_id_compact = boot_id.replace("-", "")
    user_journal = _user_journal_command_prefix(
        target_user, target_uid, target_home
    )
    endpoints = {
        "system_helpers": [
            "/usr/bin/systemctl", "--system", *common, "list-units", "--all",
            "systemd-coredump@*.service",
            "drkonqi-coredump-processor@*.service",
        ],
        "user_launchers": [
            "/usr/bin/systemctl", "--user", f"--machine={machine}", *common,
            "list-units", "--all", "drkonqi-coredump-launcher@*.service",
        ],
        "failed_system": [
            "/usr/bin/systemctl", "--system", *common, "list-units", "--all",
            "--state=failed",
        ],
        "failed_user": [
            "/usr/bin/systemctl", "--user", f"--machine={machine}", *common,
            "list-units", "--all", "--state=failed",
        ],
        "user_socket": [
            "/usr/bin/systemctl", "--user", f"--machine={machine}",
            "--no-pager", "show", "drkonqi-coredump-launcher.socket",
            f"--property={','.join(HOST_SOCKET_PROPERTIES)}",
        ],
    }
    coredumpctl = [
        "/usr/bin/coredumpctl", "--quiet", "--no-pager", "--no-legend",
        "--json=short", "list",
    ]
    if phase == "pre":
        if system_cursor is not None or user_cursor is not None:
            raise StabilityError("pre host snapshot cannot consume a journal cursor")
        return {
            "system_journal": [
                "/usr/bin/journalctl", "--system", "--quiet", "--no-pager",
                "--show-cursor", "-n", "0", f"_BOOT_ID={boot_id_compact}",
            ],
            "user_journal": [
                *user_journal, "--show-cursor", "-n", "0",
                f"_BOOT_ID={boot_id_compact}",
            ],
            **endpoints,
            "coredumpctl": coredumpctl,
        }
    if phase != "post" or not system_cursor or not user_cursor:
        raise StabilityError("post host snapshot requires both journal cursors")
    system_filters = [
        *(f"MESSAGE_ID={value}" for value in SYSTEMD_LIFECYCLE_MESSAGE_IDS),
        f"MESSAGE_ID={SYSTEMD_COREDUMP_MESSAGE_ID}",
    ]
    user_filters = [
        *(f"MESSAGE_ID={value}" for value in SYSTEMD_LIFECYCLE_MESSAGE_IDS),
    ]
    return {
        **endpoints,
        "system_journal_sync": [
            "/usr/bin/journalctl", "--system", "--quiet", "--no-pager",
            "--sync",
        ],
        "user_journal_sync": [*user_journal, "--sync"],
        "system_journal_anchor": [
            "/usr/bin/journalctl", "--system", "--quiet", "--no-pager",
            f"--cursor={system_cursor}", "-n", "1", "-o", "json",
            "--output-fields=__CURSOR",
        ],
        "user_journal_anchor": [
            *user_journal, f"--cursor={user_cursor}", "-n", "1",
            "-o", "json", "--output-fields=__CURSOR",
        ],
        "system_journal": [
            "/usr/bin/journalctl", "--system", "--quiet", "--no-pager",
            f"--after-cursor={system_cursor}", "-o", "json",
            f"--output-fields={JOURNAL_OUTPUT_FIELDS}",
            *system_filters, f"_BOOT_ID={boot_id_compact}",
        ],
        "user_journal": [
            *user_journal, f"--after-cursor={user_cursor}", "-o", "json",
            f"--output-fields={JOURNAL_OUTPUT_FIELDS}",
            *user_filters, f"_BOOT_ID={boot_id_compact}",
        ],
        # Keep this last: every preceding observation is inside both journal
        # deltas, and the final endpoint inventory is the last fallible probe.
        "coredumpctl": coredumpctl,
    }


def _validate_target_user(
    target_user: Any,
    target_uid: Any,
    identity_verifier: Callable[[str, int], bool] | None = None,
) -> tuple[str, int, str]:
    if (
        not isinstance(target_user, str)
        or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", target_user) is None
        or isinstance(target_uid, bool)
        or not isinstance(target_uid, int)
        or target_uid < 1
    ):
        raise StabilityError("target user identity is malformed")
    target_home: str
    if identity_verifier is None:
        try:
            import pwd

            by_name = pwd.getpwnam(target_user)
            by_uid = pwd.getpwuid(target_uid)
            accepted = (
                by_name.pw_uid == target_uid
                and by_uid.pw_name == target_user
                and by_name.pw_dir == by_uid.pw_dir
            )
            target_home = by_name.pw_dir
        except (ImportError, KeyError):
            accepted = False
            target_home = ""
    else:
        try:
            accepted = identity_verifier(target_user, target_uid)
        except Exception as error:
            raise StabilityError(
                f"cannot verify target user identity: {error}"
            ) from error
        target_home = f"/home/{target_user}"
    if accepted is not True:
        raise StabilityError("target user identity does not resolve exactly")
    home_path = PurePosixPath(target_home)
    if (
        not target_home.startswith("/")
        or target_home != home_path.as_posix()
        or target_home == "/"
        or any(ord(character) < 0x20 or ord(character) == 0x7F
               for character in target_home)
    ):
        raise StabilityError("target user home is malformed")
    return target_user, target_uid, target_home


def _validate_host_text(data: bytes, label: str) -> None:
    if b"\0" in data:
        raise StabilityError(f"{label} contains NUL bytes")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise StabilityError(f"{label} is not UTF-8") from error
    if data and not data.endswith(b"\n"):
        raise StabilityError(f"{label} lacks its terminal newline")


def _validate_coredump_inventory(data: bytes) -> None:
    _validate_host_text(data, "coredump inventory")
    if not data:
        return
    for ordinal, line in enumerate(data[:-1].split(b"\n"), 1):
        if not line:
            raise StabilityError("coredump inventory contains an empty record")
        try:
            value = json.loads(line.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StabilityError(
                f"coredump inventory record {ordinal} is malformed"
            ) from error
        if not isinstance(value, dict):
            raise StabilityError("coredump inventory record is not an object")


def _parse_journal_cursor(data: bytes, label: str) -> str:
    if len(data) > MAX_HOST_CURSOR_BYTES:
        raise StabilityError(f"{label} cursor exceeds its size limit")
    _validate_host_text(data, f"{label} cursor")
    prefix = b"-- cursor: "
    if (
        not data.startswith(prefix)
        or not data.endswith(b"\n")
        or data.count(b"\n") != 1
    ):
        raise StabilityError(f"{label} cursor is malformed")
    token_data = data[len(prefix):-1]
    if not token_data:
        raise StabilityError(f"{label} cursor is empty")
    try:
        token = token_data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise StabilityError(f"{label} cursor is not UTF-8") from error
    if (
        token != token.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F
               for character in token)
    ):
        raise StabilityError(f"{label} cursor contains control or edge whitespace")
    return token


def _validate_journal_delta(data: bytes, scope: str, boot_id: str) -> None:
    if scope not in {"system", "user"}:
        raise StabilityError("journal scope is malformed")
    _validate_host_text(data, f"{scope} journal delta")
    expected_boot = boot_id.replace("-", "")
    if not data:
        return
    allowed_message_ids = set(SYSTEMD_LIFECYCLE_MESSAGE_IDS)
    if scope == "system":
        allowed_message_ids.add(SYSTEMD_COREDUMP_MESSAGE_ID)
    for ordinal, line in enumerate(data[:-1].split(b"\n"), 1):
        if not line:
            raise StabilityError(f"{scope} journal delta contains an empty record")
        try:
            value = json.loads(line.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StabilityError(
                f"{scope} journal delta JSON record {ordinal} is malformed"
            ) from error
        if not isinstance(value, dict):
            raise StabilityError(f"{scope} journal delta record is not an object")
        message_id = value.get("MESSAGE_ID")
        if message_id not in allowed_message_ids:
            raise StabilityError(f"{scope} journal message identity drift")
        if value.get("_BOOT_ID") != expected_boot:
            raise StabilityError(f"{scope} journal boot identity drift")
        if message_id == SYSTEMD_COREDUMP_MESSAGE_ID:
            raise StabilityError("system journal contains a direct coredump event")
        unit_values = [
            item for item in (value.get("UNIT"), value.get("USER_UNIT"))
            if item is not None
        ]
        if (
            not unit_values
            or any(not isinstance(item, str) or not item for item in unit_values)
            or len(set(unit_values)) != 1
        ):
            raise StabilityError(f"{scope} journal lifecycle unit is malformed")
        unit = unit_values[0]
        if scope == "system" and (
            unit == "systemd-coredump.socket"
            or re.fullmatch(
                r"(?:systemd-coredump|drkonqi-coredump-processor)@"
                r"[^/\s]+[.]service",
                unit,
            ) is not None
        ):
            raise StabilityError(
                f"system journal contains a coredump helper activation: {unit}"
            )
        if scope == "user" and (
            unit == "drkonqi-coredump-launcher.socket"
            or re.fullmatch(
                r"drkonqi-coredump-launcher@[^/\s]+[.]service", unit
            ) is not None
        ):
            raise StabilityError(
                f"user journal contains a DrKonqi launcher activation: {unit}"
            )


def _validate_journal_anchor(data: bytes, expected_cursor: str, scope: str) -> None:
    """Prove that a previously sealed cursor still names an exact record."""

    if scope not in {"system", "user"}:
        raise StabilityError("journal anchor scope is malformed")
    if len(data) > MAX_HOST_CURSOR_BYTES:
        raise StabilityError(f"{scope} journal anchor exceeds its size limit")
    _validate_host_text(data, f"{scope} journal anchor")
    if not data or data.count(b"\n") != 1:
        raise StabilityError(f"{scope} journal anchor is missing or ambiguous")
    try:
        value = json.loads(data[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StabilityError(f"{scope} journal anchor is malformed") from error
    if not isinstance(value, dict) or value.get("__CURSOR") != expected_cursor:
        raise StabilityError(f"{scope} journal cursor anchor identity drift")


def _parse_socket_properties(data: bytes) -> dict[str, str | int]:
    _validate_host_text(data, "DrKonqi socket properties")
    if not data:
        raise StabilityError("DrKonqi socket properties are empty")
    result: dict[str, str | int] = {}
    for line in data[:-1].split(b"\n"):
        try:
            text = line.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise StabilityError("DrKonqi socket property is malformed") from error
        name, separator, value = text.partition("=")
        if separator != "=" or name not in HOST_SOCKET_PROPERTIES or name in result:
            raise StabilityError("DrKonqi socket property inventory is malformed")
        result[name] = value
    if set(result) != set(HOST_SOCKET_PROPERTIES):
        raise StabilityError("DrKonqi socket property inventory is incomplete")
    if result["Id"] != "drkonqi-coredump-launcher.socket":
        raise StabilityError("DrKonqi socket identity drift")
    accepted = result["NAccepted"]
    if not isinstance(accepted, str) or re.fullmatch(r"[0-9]+", accepted) is None:
        raise StabilityError("DrKonqi socket NAccepted is malformed")
    result["NAccepted"] = int(accepted)
    return result


def _snapshot_manifest(root: Path, paths: list[str]) -> bytes:
    return b"".join(
        f"{sha256_file(root / relative)}  {relative}\n".encode("ascii")
        for relative in sorted(paths)
    )


def capture_host_snapshot(
    output_root: Path,
    boot_id: str,
    target_user: str,
    target_uid: int,
    *,
    command_runner: HostCommandRunner | None = None,
    live_boot_id: str | None = None,
    identity_verifier: Callable[[str, int], bool] | None = None,
    require_root: bool = True,
) -> dict[str, Any]:
    """Capture one bounded pre/post host snapshot with exact raw bytes."""

    if require_root and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        raise StabilityError("host snapshot capture requires root")
    phase = output_root.name
    if phase not in {"pre", "post"} or output_root.parent.name != "host":
        raise StabilityError("host snapshot output must be host/pre or host/post")
    if not isinstance(boot_id, str) or BOOT_ID.fullmatch(boot_id) is None:
        raise StabilityError("host snapshot boot identity is malformed")
    if live_boot_id is None:
        try:
            live_boot_id = _read_regular_bytes(
                LinuxClock.BOOT_ID_PATH, 128
            ).decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise StabilityError("live boot identity is malformed") from error
    if live_boot_id != boot_id:
        raise StabilityError("host snapshot boot identity differs from the live boot")
    target_user, target_uid, target_home = _validate_target_user(
        target_user, target_uid, identity_verifier
    )
    system_cursor: str | None = None
    user_cursor: str | None = None
    if phase == "post":
        pre_root = output_root.parent / "pre"
        pre = verify_host_snapshot(
            pre_root,
            expected_boot_id=boot_id,
            expected_target_user=target_user,
            expected_target_uid=target_uid,
            expected_target_home=target_home,
        )
        del pre
        system_cursor = _parse_journal_cursor(
            _read_regular_bytes(
                pre_root / HOST_SNAPSHOT_PRE_RAW_FILES["system_journal"],
                MAX_HOST_CURSOR_BYTES,
            ),
            "system journal",
        )
        user_cursor = _parse_journal_cursor(
            _read_regular_bytes(
                pre_root / HOST_SNAPSHOT_PRE_RAW_FILES["user_journal"],
                MAX_HOST_CURSOR_BYTES,
            ),
            "user journal",
        )
    commands = _host_commands(
        target_user, target_uid, target_home, boot_id, phase,
        system_cursor=system_cursor, user_cursor=user_cursor,
    )
    raw_files = _host_raw_files(phase)
    outputs: dict[str, bytes] = {}
    for name, argv in commands.items():
        if name == "coredumpctl":
            limit = MAX_HOST_COREDUMP_BYTES
        elif phase == "pre" and name in {"system_journal", "user_journal"}:
            limit = MAX_HOST_CURSOR_BYTES
        else:
            limit = MAX_HOST_COMMAND_BYTES
        outputs[name] = _host_command_bytes(argv, limit, command_runner)
    _validate_coredump_inventory(outputs["coredumpctl"])
    for name in (
        "system_helpers", "user_launchers", "failed_system", "failed_user"
    ):
        _validate_host_text(outputs[name], name.replace("_", " "))
        if phase == "pre" and outputs[name]:
            raise StabilityError(
                f"host {name.replace('_', ' ')} baseline is not empty"
            )
    socket = _parse_socket_properties(outputs["user_socket"])
    if phase == "pre":
        _parse_journal_cursor(outputs["system_journal"], "system journal")
        _parse_journal_cursor(outputs["user_journal"], "user journal")
    else:
        if outputs["system_journal_sync"] or outputs["user_journal_sync"]:
            raise StabilityError("journal sync unexpectedly wrote output")
        assert system_cursor is not None and user_cursor is not None
        _validate_journal_anchor(
            outputs["system_journal_anchor"], system_cursor, "system"
        )
        _validate_journal_anchor(
            outputs["user_journal_anchor"], user_cursor, "user"
        )
        _validate_journal_delta(outputs["system_journal"], "system", boot_id)
        _validate_journal_delta(outputs["user_journal"], "user", boot_id)

    _create_private_directory(output_root, "host snapshot directory")
    for name, relative in raw_files.items():
        _atomic_create(output_root / relative, outputs[name])
    command_records = {
        name: {
            "argv": commands[name],
            "path": raw_files[name],
            "sha256": hashlib.sha256(outputs[name]).hexdigest(),
            "size": len(outputs[name]),
        }
        for name in sorted(commands)
    }
    snapshot = {
        "schema": HOST_SNAPSHOT_SCHEMA,
        "status": "captured",
        "phase": phase,
        "identity": {
            "boot_id": boot_id,
            "target_uid": target_uid,
            "target_user": target_user,
            "target_home": target_home,
            "user_machine": f"{target_user}@.host",
        },
        "commands": command_records,
        "socket": socket,
    }
    snapshot_data = canonical_document(snapshot)
    _atomic_create(output_root / "snapshot.json", snapshot_data)
    _atomic_create(
        output_root / "snapshot.json.sha256",
        (
            f"{hashlib.sha256(snapshot_data).hexdigest()}  snapshot.json\n"
        ).encode("ascii"),
    )
    manifest_paths = [
        *raw_files.values(),
        "snapshot.json",
        "snapshot.json.sha256",
    ]
    _atomic_create(
        output_root / "SHA256SUMS",
        _snapshot_manifest(output_root, manifest_paths),
    )
    return verify_host_snapshot(
        output_root,
        expected_boot_id=boot_id,
        expected_target_user=target_user,
        expected_target_uid=target_uid,
        expected_target_home=target_home,
    )


def verify_host_snapshot(
    root: Path,
    *,
    expected_boot_id: str | None = None,
    expected_target_user: str | None = None,
    expected_target_uid: int | None = None,
    expected_target_home: str | None = None,
) -> dict[str, Any]:
    phase = root.name
    raw_files = _host_raw_files(phase)
    expected_files = sorted({
        *raw_files.values(),
        "snapshot.json", "snapshot.json.sha256", "SHA256SUMS",
    })
    if _regular_files(root) != expected_files:
        raise StabilityError("host snapshot file inventory is not exact")
    snapshot = _load_document(root / "snapshot.json", "host snapshot")
    _exact_dict(
        snapshot,
        {"schema", "status", "phase", "identity", "commands", "socket"},
        "host snapshot",
    )
    if (
        snapshot["schema"] != HOST_SNAPSHOT_SCHEMA
        or snapshot["status"] != "captured"
        or snapshot["phase"] != root.name
        or snapshot["phase"] not in {"pre", "post"}
    ):
        raise StabilityError("host snapshot claim is malformed")
    identity = _exact_dict(
        snapshot["identity"],
        {
            "boot_id", "target_uid", "target_user", "target_home",
            "user_machine",
        },
        "host snapshot identity",
    )
    boot_id = identity["boot_id"]
    if not isinstance(boot_id, str) or BOOT_ID.fullmatch(boot_id) is None:
        raise StabilityError("host snapshot boot identity is malformed")
    user = identity["target_user"]
    uid = identity["target_uid"]
    home = identity["target_home"]
    home_path = PurePosixPath(home) if isinstance(home, str) else None
    if (
        not isinstance(user, str)
        or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) is None
        or isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 1
        or not isinstance(home, str)
        or not home.startswith("/")
        or home == "/"
        or home_path is None
        or home != home_path.as_posix()
        or any(ord(character) < 0x20 or ord(character) == 0x7F
               for character in home)
        or identity["user_machine"] != f"{user}@.host"
    ):
        raise StabilityError("host snapshot target identity is malformed")
    if expected_boot_id is not None and boot_id != expected_boot_id:
        raise StabilityError("host snapshot boot identity drift")
    if expected_target_user is not None and user != expected_target_user:
        raise StabilityError("host snapshot target user drift")
    if expected_target_uid is not None and uid != expected_target_uid:
        raise StabilityError("host snapshot target UID drift")
    if expected_target_home is not None and home != expected_target_home:
        raise StabilityError("host snapshot target home drift")

    system_cursor: str | None = None
    user_cursor: str | None = None
    if phase == "post":
        pre_root = root.parent / "pre"
        verify_host_snapshot(
            pre_root,
            expected_boot_id=boot_id,
            expected_target_user=user,
            expected_target_uid=uid,
            expected_target_home=home,
        )
        system_cursor = _parse_journal_cursor(
            _read_regular_bytes(
                pre_root / HOST_SNAPSHOT_PRE_RAW_FILES["system_journal"],
                MAX_HOST_CURSOR_BYTES,
            ),
            "system journal",
        )
        user_cursor = _parse_journal_cursor(
            _read_regular_bytes(
                pre_root / HOST_SNAPSHOT_PRE_RAW_FILES["user_journal"],
                MAX_HOST_CURSOR_BYTES,
            ),
            "user journal",
        )
    expected_commands = _host_commands(
        user, uid, home, boot_id, phase,
        system_cursor=system_cursor, user_cursor=user_cursor,
    )
    records = snapshot["commands"]
    if not isinstance(records, dict) or set(records) != set(expected_commands):
        raise StabilityError("host snapshot command inventory is malformed")
    for name in sorted(expected_commands):
        record = _exact_dict(
            records[name], {"argv", "path", "sha256", "size"},
            "host snapshot command",
        )
        relative = raw_files[name]
        if record["argv"] != expected_commands[name] or record["path"] != relative:
            raise StabilityError("host snapshot command authority drift")
        _valid_sha(record["sha256"], "host snapshot artifact")
        if name == "coredumpctl":
            maximum = MAX_HOST_COREDUMP_BYTES
        elif phase == "pre" and name in {"system_journal", "user_journal"}:
            maximum = MAX_HOST_CURSOR_BYTES
        else:
            maximum = MAX_HOST_COMMAND_BYTES
        size = _integer(record["size"], "host snapshot artifact size")
        data = _read_regular_bytes(root / relative, maximum)
        if size != len(data) or record["sha256"] != hashlib.sha256(data).hexdigest():
            raise StabilityError("host snapshot artifact identity drift")
        if name == "coredumpctl":
            _validate_coredump_inventory(data)
        elif name in {"system_journal_sync", "user_journal_sync"}:
            if data:
                raise StabilityError("host snapshot journal sync output drift")
        elif name == "system_journal_anchor":
            if system_cursor is None:
                raise StabilityError("system journal anchor lacks its pre cursor")
            _validate_journal_anchor(data, system_cursor, "system")
        elif name == "user_journal_anchor":
            if user_cursor is None:
                raise StabilityError("user journal anchor lacks its pre cursor")
            _validate_journal_anchor(data, user_cursor, "user")
        elif name == "system_journal":
            if phase == "pre":
                _parse_journal_cursor(data, "system journal")
            else:
                _validate_journal_delta(data, "system", boot_id)
        elif name == "user_journal":
            if phase == "pre":
                _parse_journal_cursor(data, "user journal")
            else:
                _validate_journal_delta(data, "user", boot_id)
        elif name == "user_socket":
            if snapshot["socket"] != _parse_socket_properties(data):
                raise StabilityError("host snapshot socket projection drift")
        else:
            _validate_host_text(data, name.replace("_", " "))
    _exact_dict(
        snapshot["socket"], set(HOST_SOCKET_PROPERTIES),
        "host snapshot socket projection",
    )
    sidecar = (
        f"{sha256_file(root / 'snapshot.json')}  snapshot.json\n"
    ).encode("ascii")
    if _read_regular_bytes(root / "snapshot.json.sha256", 1024) != sidecar:
        raise StabilityError("host snapshot checksum sidecar mismatch")
    manifest_paths = [
        *raw_files.values(),
        "snapshot.json", "snapshot.json.sha256",
    ]
    if _read_regular_bytes(root / "SHA256SUMS", MAX_DOCUMENT_BYTES) != (
        _snapshot_manifest(root, manifest_paths)
    ):
        raise StabilityError("host snapshot checksum manifest mismatch")
    return snapshot


def _host_pair_projection(
    session_root: Path,
    pre: dict[str, Any],
    post: dict[str, Any],
) -> dict[str, Any]:
    pre_root = session_root / "host" / "pre"
    post_root = session_root / "host" / "post"
    if pre["identity"] != post["identity"]:
        raise StabilityError("host pre/post identity drift")
    for name in (
        "system_helpers", "user_launchers", "failed_system", "failed_user"
    ):
        pre_data = _read_regular_bytes(
            pre_root / HOST_SNAPSHOT_PRE_RAW_FILES[name], MAX_HOST_COMMAND_BYTES
        )
        post_data = _read_regular_bytes(
            post_root / HOST_SNAPSHOT_POST_RAW_FILES[name], MAX_HOST_COMMAND_BYTES
        )
        if pre_data or post_data:
            raise StabilityError(f"host {name.replace('_', ' ')} inventory is not empty")
    pre_coredump = _read_regular_bytes(
        pre_root / HOST_SNAPSHOT_PRE_RAW_FILES["coredumpctl"],
        MAX_HOST_COREDUMP_BYTES,
    )
    post_coredump = _read_regular_bytes(
        post_root / HOST_SNAPSHOT_POST_RAW_FILES["coredumpctl"],
        MAX_HOST_COREDUMP_BYTES,
    )
    if pre_coredump != post_coredump:
        raise StabilityError("host coredump inventory changed during the campaign")
    if pre["socket"] != post["socket"]:
        raise StabilityError("host DrKonqi socket identity changed during the campaign")
    boot_id = pre["identity"]["boot_id"]
    _validate_journal_delta(
        _read_regular_bytes(
            post_root / HOST_SNAPSHOT_POST_RAW_FILES["system_journal"],
            MAX_HOST_COMMAND_BYTES,
        ),
        "system",
        boot_id,
    )
    _validate_journal_delta(
        _read_regular_bytes(
            post_root / HOST_SNAPSHOT_POST_RAW_FILES["user_journal"],
            MAX_HOST_COMMAND_BYTES,
        ),
        "user",
        boot_id,
    )
    return {
        "boot_user_identity": "pass",
        "coredump_inventory_unchanged": "pass",
        "failed_inventories_empty": "pass",
        "helper_inventories_empty": "pass",
        "launcher_inventory_empty": "pass",
        "journal_delta_clean": "pass",
        "socket_identity_unchanged": "pass",
        "socket_naccepted_unchanged": "pass",
    }


def _inner_campaign_inventory(campaign_root: Path) -> dict[str, Any]:
    actual_files = _regular_files(campaign_root)
    receipt = _load_document(campaign_root / "receipt.json", "inner campaign receipt")
    _exact_dict(
        receipt,
        {
            "schema", "status", "policy", "session", "schedule", "timeline",
            "cycles", "cycle_summary", "establishment", "authorities",
            "diagnostics", "gates", "failures", "artifacts",
        },
        "inner campaign receipt",
    )
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["status"] != "accepted"
        or receipt["failures"] != []
    ):
        raise StabilityError("inner campaign receipt is not accepted")
    _validate_artifact_inventory(campaign_root, receipt, actual_files)
    receipt_data = _read_regular_bytes(
        campaign_root / "receipt.json", MAX_DOCUMENT_BYTES
    )
    expected_sidecar = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("ascii")
    if _read_regular_bytes(
        campaign_root / "receipt.json.sha256", 1024
    ) != expected_sidecar:
        raise StabilityError("inner campaign receipt checksum mismatch")
    manifest_paths = [
        "receipt.json", "receipt.json.sha256",
        *[item["path"] for item in receipt["artifacts"]],
    ]
    expected_manifest = b"".join(
        f"{sha256_file(campaign_root / relative)}  {relative}\n".encode("utf-8")
        for relative in manifest_paths
    )
    manifest = _read_regular_bytes(
        campaign_root / "SHA256SUMS", MAX_DOCUMENT_BYTES
    )
    if manifest != expected_manifest:
        raise StabilityError("inner campaign SHA256SUMS inventory mismatch")
    session = _validate_session_record(receipt["session"])
    session_identity = session["identity"]
    entries = [_artifact_entry(campaign_root, relative) for relative in actual_files]
    return {
        "root": "campaign",
        "receipt": {
            "path": "campaign/receipt.json",
            "sha256": hashlib.sha256(receipt_data).hexdigest(),
            "size": len(receipt_data),
        },
        "receipt_sidecar": {
            "path": "campaign/receipt.json.sha256",
            "sha256": sha256_file(campaign_root / "receipt.json.sha256"),
        },
        "checksum_manifest": {
            "path": "campaign/SHA256SUMS",
            "sha256": hashlib.sha256(manifest).hexdigest(),
            "size": len(manifest),
        },
        "inventory": {
            "byte_count": sum(item["size"] for item in entries),
            "entries_sha256": digest_json(entries),
            "file_count": len(entries),
        },
        "session_id": session["id"],
        "boot_id": session_identity["boot_id"],
        "runtime_config_sha256": session_identity["runtime_config_sha256"],
        "runtime_launch_receipt_sha256": session_identity[
            "runtime_launch_receipt_sha256"
        ],
    }


def _path_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError as error:
        raise StabilityError(f"cannot inspect cleanup path {path}: {error}") from error
    return False


def _read_pseudofile(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            data = os.read(descriptor, maximum + 1)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise StabilityError(f"cannot read cleanup cgroup file {path}: {error}") from error
    if len(data) > maximum:
        raise StabilityError("cleanup cgroup file exceeds its size limit")
    return data


def _cgroup_absent_or_empty(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return True
    except OSError as error:
        raise StabilityError(f"cannot inspect cleanup cgroup {path}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise StabilityError("cleanup cgroup path is not a real directory")
    if _read_pseudofile(path / "cgroup.procs", 1024 * 1024).strip():
        return False
    events_data = _read_pseudofile(path / "cgroup.events", 4096)
    try:
        events = dict(
            line.split() for line in events_data.decode("ascii", errors="strict").splitlines()
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise StabilityError("cleanup cgroup events are malformed") from error
    return events.get("populated") == "0" and events.get("frozen") == "0"


def _expected_cgroup_authority_intent(
    session: str, source_revision: str,
) -> dict[str, Any]:
    if not isinstance(source_revision, str) or GIT_SHA1.fullmatch(source_revision) is None:
        raise StabilityError("cgroup authority source revision is malformed")
    return {
        "schema": CGROUP_AUTHORITY_INTENT_SCHEMA,
        "status": "armed",
        "source_revision": source_revision,
        "session": session,
        "exclusive_cpus": "0-3",
        "system_slice_cgroup": RUNTIME_SYSTEM_SLICE_CGROUP,
        "service_cgroup": RUNTIME_SERVICE_CGROUP,
        "payload_cgroup": f"/sys/fs/cgroup{RUNTIME_CGROUP_PARENT}",
        "measurement_cgroup": RUNTIME_MEASUREMENT_CGROUP,
        "original_root_isolated_cpus": "",
        "original_system_slice_exclusive_cpus": "",
        "original_service_exclusive_cpus": "",
    }


def _validate_cgroup_authority_intent(
    path: Path, *, session: str, source_revision: str,
) -> dict[str, Any]:
    raw = _read_regular_bytes(path, MAX_DOCUMENT_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StabilityError("cgroup authority intent JSON is malformed") from error
    expected = _expected_cgroup_authority_intent(session, source_revision)
    if not isinstance(value, dict) or value != expected:
        raise StabilityError("cgroup authority intent claims drift")
    if raw != canonical_json(value) + b"\n":
        raise StabilityError("cgroup authority intent is not canonical JSON")
    return value


def _validate_host_recovery_intent(
    path: Path,
    *,
    boot_id: str,
    session: str,
    session_nonce: str,
    source_revision: str,
    source_tree_sha1: str,
    source_manifest_sha256: str,
    runtime_config_sha256: str,
) -> dict[str, Any]:
    raw = _read_regular_bytes(path, MAX_DOCUMENT_BYTES)
    try:
        value = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StabilityError("host recovery intent JSON is malformed") from error
    intent = _exact_dict(
        value,
        {
            "boot_id", "containers", "installation", "mode", "schema",
            "session", "session_nonce", "status",
        },
        "host recovery intent",
    )
    if (
        intent["schema"] != HOST_RECOVERY_INTENT_SCHEMA
        or intent["status"] != "armed"
        or intent["mode"] != "campaign"
        or intent["boot_id"] != boot_id
        or intent["session"] != session
        or intent["session_nonce"] != session_nonce
    ):
        raise StabilityError("host recovery intent session claims drift")
    containers = _exact_dict(
        intent["containers"],
        {"campaign", "preflight", "verifier"},
        "host recovery container authority",
    )
    expected_containers = {
        "campaign": f"codeskeptic-p10-09-{session_nonce}",
        "preflight": f"codeskeptic-p10-09-preflight-{session_nonce}",
        "verifier": f"codeskeptic-p10-09-verifier-{session_nonce}",
    }
    if containers != expected_containers:
        raise StabilityError("host recovery container authority drift")
    installation = _exact_dict(
        intent["installation"],
        {
            "bundle_inventory_sha256", "bundle_receipt_sha256",
            "bundle_revision", "image_archive_sha256", "image_digest",
            "image_id", "image_reference", "installation_receipt_sha256",
            "installation_authority_sha256", "installed_inventory_sha256",
            "runtime_config_sha256", "source_manifest_sha256",
            "source_tree_sha1",
        },
        "host recovery installation authority",
    )
    if (
        installation["bundle_revision"] != source_revision
        or installation["source_tree_sha1"] != source_tree_sha1
        or installation["source_manifest_sha256"]
        != source_manifest_sha256
        or installation["runtime_config_sha256"]
        != runtime_config_sha256
        or installation["image_id"] != PINNED_EVIDENCE_IMAGE_ID
        or installation["image_digest"] != PINNED_EVIDENCE_IMAGE_DIGEST
        or installation["image_reference"] != PINNED_EVIDENCE_IMAGE
        or not isinstance(installation["source_tree_sha1"], str)
        or GIT_SHA1.fullmatch(installation["source_tree_sha1"]) is None
    ):
        raise StabilityError("host recovery installation identity drift")
    for field in (
        "bundle_inventory_sha256",
        "bundle_receipt_sha256",
        "image_archive_sha256",
        "installation_authority_sha256",
        "installation_receipt_sha256",
        "installed_inventory_sha256",
        "runtime_config_sha256",
        "source_manifest_sha256",
    ):
        digest = installation[field]
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise StabilityError("host recovery installation digest is malformed")
    if (
        installation["bundle_inventory_sha256"]
        != installation["installed_inventory_sha256"]
    ):
        raise StabilityError("host recovery installed inventory identity drift")
    bundle_receipt = {
        "image_archive_sha256": installation["image_archive_sha256"],
        "image_digest": PINNED_EVIDENCE_IMAGE_DIGEST,
        "image_id": PINNED_EVIDENCE_IMAGE_ID,
        "image_reference": PINNED_EVIDENCE_IMAGE,
        "inventory_sha256": installation["bundle_inventory_sha256"],
        "revision": source_revision,
        "runtime_config_sha256": runtime_config_sha256,
        "schema": BUNDLE_RECEIPT_SCHEMA,
        "source_manifest_sha256": source_manifest_sha256,
        "source_tree_sha1": source_tree_sha1,
    }
    bundle_receipt_sha256 = hashlib.sha256(
        canonical_document(bundle_receipt)
    ).hexdigest()
    if installation["bundle_receipt_sha256"] != bundle_receipt_sha256:
        raise StabilityError("host recovery bundle receipt identity drift")
    installation_authority = {
        "bundle_receipt_sha256": bundle_receipt_sha256,
        "bundle_revision": source_revision,
        "schema": INSTALLATION_AUTHORITY_SCHEMA,
    }
    if installation["installation_authority_sha256"] != hashlib.sha256(
        canonical_document(installation_authority)
    ).hexdigest():
        raise StabilityError("host recovery installation authority drift")
    installation_receipt = {
        "authority_root": "/opt/codeskeptic-p10-09/authority",
        "bundle_inventory_sha256": installation["bundle_inventory_sha256"],
        "bundle_receipt_sha256": bundle_receipt_sha256,
        "bundle_revision": source_revision,
        "config_path": "/etc/codeskeptic-p10-09/runtime.json",
        "image": {
            "archive_sha256": installation["image_archive_sha256"],
            "digest": PINNED_EVIDENCE_IMAGE_DIGEST,
            "id": PINNED_EVIDENCE_IMAGE_ID,
            "reference": PINNED_EVIDENCE_IMAGE,
        },
        "installed_inventory_sha256": installation[
            "installed_inventory_sha256"
        ],
        "operator_root": "/opt/codeskeptic-p10-09/operator",
        "schema": INSTALLATION_RECEIPT_SCHEMA,
        "unit_path": (
            "/etc/systemd/system/codeskeptic-stability.service"
        ),
    }
    if installation["installation_receipt_sha256"] != hashlib.sha256(
        canonical_document(installation_receipt)
    ).hexdigest():
        raise StabilityError("host recovery installation receipt identity drift")
    if raw != canonical_json(intent) + b"\n":
        raise StabilityError("host recovery intent is not canonical JSON")
    return intent


def _live_cgroup_path(claimed: str, cgroup_root: Path) -> Path:
    try:
        relative = Path(claimed).relative_to("/sys/fs/cgroup")
    except (TypeError, ValueError) as error:
        raise StabilityError("cleanup live cgroup path escapes its authority") from error
    return cgroup_root / relative


def _cleanup_cgroup_value(path: Path, label: str) -> str:
    raw = _read_pseudofile(path, 4096)
    try:
        return raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise StabilityError(f"{label} is malformed") from error


def _live_cgroup_restoration(
    cgroups: dict[str, Any], cgroup_root: Path,
) -> dict[str, Any]:
    root = _live_cgroup_path(cgroups["root"], cgroup_root)
    result: dict[str, Any] = {
        "root": {
            "cpuset_cpus_isolated": _cleanup_cgroup_value(
                root / "cpuset.cpus.isolated", "root isolated CPUs"
            )
        }
    }
    for name in ("system_slice", "service"):
        path = _live_cgroup_path(cgroups[name], cgroup_root)
        try:
            metadata = path.lstat()
        except OSError as error:
            raise StabilityError(f"cannot inspect restored {name} cgroup") from error
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise StabilityError(f"restored {name} cgroup is not an exact directory")
        result[name] = {
            "cpuset_cpus_partition": _cleanup_cgroup_value(
                path / "cpuset.cpus.partition", f"{name} partition"
            ),
            "cpuset_cpus_exclusive": _cleanup_cgroup_value(
                path / "cpuset.cpus.exclusive", f"{name} exclusive CPUs"
            ),
            "cpuset_cpus_exclusive_effective": _cleanup_cgroup_value(
                path / "cpuset.cpus.exclusive.effective",
                f"{name} effective exclusive CPUs",
            ),
            "cpuset_cpus_effective": _cleanup_cgroup_value(
                path / "cpuset.cpus.effective", f"{name} effective CPUs"
            ),
        }
    return result


def _validate_cleanup_record(
    path: Path,
    *,
    session_root: Path,
    boot_id: str,
    session_nonce: str,
    target_user: str,
    target_uid: int,
    operator_path: Path,
    expected_source_revision: str,
    expected_source_tree_sha1: str,
    expected_source_manifest_sha256: str,
    expected_runtime_config_sha256: str,
    verify_live: bool,
    command_runner: HostCommandRunner | None = None,
    live_cgroup_root: Path = Path("/sys/fs/cgroup"),
    live_state_root: Path = Path("/var/lib/codeskeptic-p10-09"),
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    cleanup = _load_document(path, "host cleanup record")
    _exact_dict(
        cleanup,
        {
            "schema", "boot_id", "session", "session_nonce", "target_user",
            "target_uid", "podman", "container", "verifier_container",
            "completion", "cgroup_authority", "host_recovery", "cgroups",
            "cgroup_restoration", "runtime", "gates",
        },
        "host cleanup record",
    )
    if (
        cleanup["schema"] != HOST_CLEANUP_SCHEMA
        or cleanup["boot_id"] != boot_id
        or cleanup["session"] != session_root.name
        or cleanup["session_nonce"] != session_nonce
        or cleanup["target_user"] != target_user
        or cleanup["target_uid"] != target_uid
    ):
        raise StabilityError("host cleanup session identity drift")
    completion = _exact_dict(
        cleanup["completion"],
        {"campaign", "cleanup", "exec_stop_post_recovery"},
        "host cleanup completion",
    )
    if (
        completion["campaign"] != "inner-verified"
        or completion["cleanup"] != "authoritative-runner"
        or completion["exec_stop_post_recovery"] is not False
    ):
        raise StabilityError("ExecStopPost recovery is not campaign acceptance")
    container = _exact_dict(
        cleanup["container"], {"id", "name", "cidfile", "image_id", "command"},
        "host cleanup container",
    )
    if (
        not isinstance(container["id"], str)
        or SHA256.fullmatch(container["id"]) is None
        or container["name"] != f"codeskeptic-p10-09-{session_nonce}"
        or container["cidfile"]
        != f"/run/codeskeptic-p10-09/{session_root.name}.cid"
        or container["image_id"] != PINNED_EVIDENCE_IMAGE_ID
        or container["command"] != RUNTIME_CONTROLLER_COMMAND
    ):
        raise StabilityError("host cleanup container identity drift")
    verifier_container = _exact_dict(
        cleanup["verifier_container"],
        {"id", "name", "cidfile", "image_id", "command"},
        "host cleanup verifier container",
    )
    if (
        not isinstance(verifier_container["id"], str)
        or SHA256.fullmatch(verifier_container["id"]) is None
        or verifier_container["id"] == container["id"]
        or verifier_container["name"]
        != f"codeskeptic-p10-09-verifier-{session_nonce}"
        or verifier_container["cidfile"]
        != (
            f"/run/codeskeptic-p10-09/{session_root.name}.verifier.cid"
        )
        or verifier_container["image_id"] != PINNED_EVIDENCE_IMAGE_ID
        or verifier_container["command"] != RUNTIME_VERIFIER_COMMAND
    ):
        raise StabilityError("host cleanup verifier container identity drift")
    podman = _exact_dict(
        cleanup["podman"],
        {
            "executable", "root", "runroot", "storage_driver",
            "cgroup_manager", "events_backend", "hooks_dir", "runtime", "conmon",
            "containers_conf", "environment_launcher", "environment_reset",
            "environment", "version",
        },
        "host cleanup Podman authority",
    )
    expected_podman = {
        "executable": "/usr/bin/podman",
        "root": "/var/lib/codeskeptic-p10-09/podman-root",
        "runroot": "/run/codeskeptic-p10-09/podman-runroot",
        "storage_driver": "overlay",
        "cgroup_manager": "cgroupfs",
        "events_backend": "none",
        "hooks_dir": operator_path.parent.as_posix(),
        "runtime": "/usr/bin/crun",
        "conmon": "/usr/bin/conmon",
        "containers_conf": (operator_path.parent / "containers.conf").as_posix(),
        "environment_launcher": "/usr/bin/env",
        "environment_reset": "ignore-all-ambient",
        "environment": {
            "CONTAINERS_CONF": (
                operator_path.parent / "containers.conf"
            ).as_posix(),
            "HOME": "/var/lib/codeskeptic-p10-09/podman-environment/home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": (
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ),
            "TZ": "UTC",
            "XDG_DATA_HOME": (
                "/var/lib/codeskeptic-p10-09/podman-environment/data"
            ),
            "XDG_CACHE_HOME": (
                "/var/lib/codeskeptic-p10-09/podman-environment/cache"
            ),
            "XDG_CONFIG_HOME": (
                "/var/lib/codeskeptic-p10-09/podman-environment/config"
            ),
            "XDG_RUNTIME_DIR": (
                "/var/lib/codeskeptic-p10-09/podman-environment/runtime"
            ),
            "TMPDIR": "/var/lib/codeskeptic-p10-09/podman-environment/tmp",
        },
        "version": PINNED_PODMAN_VERSION,
    }
    if podman != expected_podman:
        raise StabilityError("host cleanup Podman authority drift")
    cgroup_authority = _exact_dict(
        cleanup["cgroup_authority"], {"intent", "marker", "temporary_marker"},
        "host cleanup cgroup authority",
    )
    intent_claim = _exact_dict(
        cgroup_authority["intent"], {"path", "sha256"},
        "host cleanup cgroup authority intent",
    )
    if (
        intent_claim["path"] != CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH
        or not isinstance(intent_claim["sha256"], str)
        or SHA256.fullmatch(intent_claim["sha256"]) is None
        or cgroup_authority["marker"] != CGROUP_AUTHORITY_MARKER
        or cgroup_authority["temporary_marker"] != CGROUP_AUTHORITY_MARKER_TEMP
    ):
        raise StabilityError("host cleanup cgroup authority identity drift")
    intent_path = session_root / CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH
    _validate_cgroup_authority_intent(
        intent_path,
        session=session_root.name,
        source_revision=expected_source_revision,
    )
    intent_sha256 = sha256_file(intent_path, MAX_DOCUMENT_BYTES)
    if intent_sha256 != intent_claim["sha256"]:
        raise StabilityError("host cleanup cgroup authority intent checksum drift")
    host_recovery = _exact_dict(
        cleanup["host_recovery"], {"intent", "marker", "temporary_marker"},
        "host cleanup recovery authority",
    )
    host_recovery_claim = _exact_dict(
        host_recovery["intent"], {"path", "sha256"},
        "host cleanup recovery intent",
    )
    if (
        host_recovery_claim["path"] != HOST_RECOVERY_INTENT_EVIDENCE_PATH
        or not isinstance(host_recovery_claim["sha256"], str)
        or SHA256.fullmatch(host_recovery_claim["sha256"]) is None
        or host_recovery["marker"] != HOST_RECOVERY_MARKER
        or host_recovery["temporary_marker"] != HOST_RECOVERY_MARKER_TEMP
    ):
        raise StabilityError("host cleanup recovery identity drift")
    host_recovery_path = session_root / HOST_RECOVERY_INTENT_EVIDENCE_PATH
    _validate_host_recovery_intent(
        host_recovery_path,
        boot_id=boot_id,
        session=session_root.name,
        session_nonce=session_nonce,
        source_revision=expected_source_revision,
        source_tree_sha1=expected_source_tree_sha1,
        source_manifest_sha256=expected_source_manifest_sha256,
        runtime_config_sha256=expected_runtime_config_sha256,
    )
    host_recovery_sha256 = sha256_file(
        host_recovery_path, MAX_DOCUMENT_BYTES
    )
    if host_recovery_sha256 != host_recovery_claim["sha256"]:
        raise StabilityError("host cleanup recovery intent checksum drift")
    cgroups = _exact_dict(
        cleanup["cgroups"],
        {"root", "system_slice", "service", "measurement", "payload"},
        "host cleanup cgroups",
    )
    expected_cgroups = {
        "root": "/sys/fs/cgroup",
        "system_slice": RUNTIME_SYSTEM_SLICE_CGROUP,
        "service": RUNTIME_SERVICE_CGROUP,
        "measurement": RUNTIME_MEASUREMENT_CGROUP,
        "payload": f"/sys/fs/cgroup{RUNTIME_CGROUP_PARENT}",
    }
    if cgroups != expected_cgroups:
        raise StabilityError("host cleanup cgroup identity drift")
    expected_restoration = {
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
    }
    restoration = _exact_dict(
        cleanup["cgroup_restoration"], {"root", "system_slice", "service"},
        "host cleanup cgroup restoration",
    )
    for name, fields in expected_restoration.items():
        exact = _exact_dict(
            restoration[name], set(fields), f"host cleanup {name} restoration"
        )
        if exact != fields:
            raise StabilityError(f"host cleanup {name} restoration drift")
    runtime = _exact_dict(
        cleanup["runtime"], {"identity_marker", "tree"},
        "host cleanup runtime",
    )
    expected_runtime = {
        "identity_marker": (
            "/var/lib/codeskeptic-p10-09/runtime-identities/"
            f"{session_root.name}.json"
        ),
        "tree": f"/var/lib/codeskeptic-p10-09/runtime/{session_root.name}",
    }
    if runtime != expected_runtime:
        raise StabilityError("host cleanup runtime identity drift")
    expected_gates = {
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
    }
    gates = _exact_dict(cleanup["gates"], set(expected_gates), "cleanup gates")
    if gates != expected_gates:
        raise StabilityError("host cleanup gate is not passing")
    if verify_live:
        for item, label in (
            (container["cidfile"], "container ID file"),
            (verifier_container["cidfile"], "verifier container ID file"),
            (runtime["tree"], "campaign runtime"),
            (runtime["identity_marker"], "campaign runtime identity"),
        ):
            if not _path_absent(Path(item)):
                raise StabilityError(f"{label} survived cleanup")
        for marker_name in ("marker", "temporary_marker"):
            marker = live_state_root / Path(cgroup_authority[marker_name]).name
            if not _path_absent(marker):
                raise StabilityError(
                    f"cgroup authority {marker_name.replace('_', ' ')} survived cleanup"
                )
        for marker_name in ("marker", "temporary_marker"):
            marker = live_state_root / Path(host_recovery[marker_name]).name
            if not _path_absent(marker):
                raise StabilityError(
                    f"host recovery {marker_name.replace('_', ' ')} survived cleanup"
                )
        observed_restoration = _live_cgroup_restoration(cgroups, live_cgroup_root)
        if observed_restoration != expected_restoration:
            raise StabilityError("live cgroup restoration differs from cleanup evidence")
        for name in ("payload", "measurement"):
            live_path = _live_cgroup_path(cgroups[name], live_cgroup_root)
            if not _cgroup_absent_or_empty(live_path):
                raise StabilityError(f"{name} cgroup is not empty after cleanup")
        # Direct post-marker Podman access is forbidden: even a read-only CLI
        # command may create runroot locks.  The recovery helper publishes its
        # dedicated inspection marker first, validates the exact clean Podman
        # environment/version/image/inventory, clears runroot, and removes the
        # inspection marker last.
        recovery_argv = [
            "/usr/bin/python3",
            "-B",
            (operator_path.parent / "host-recovery.py").as_posix(),
            "recover",
        ]
        recovery = _host_command_bytes(
            recovery_argv, 64, command_runner
        )
        if recovery != b"already-clean\n":
            raise StabilityError("live host recovery revalidation drift")
        for name in (
            "podman-inspection-intent.json",
            ".podman-inspection-intent.tmp",
        ):
            if not _path_absent(live_state_root / name):
                raise StabilityError(
                    "Podman inspection authority survived live revalidation"
                )
    intent_record = {
        "path": CGROUP_AUTHORITY_INTENT_EVIDENCE_PATH,
        "sha256": intent_sha256,
        "size": intent_path.lstat().st_size,
    }
    host_recovery_record = {
        "path": HOST_RECOVERY_INTENT_EVIDENCE_PATH,
        "sha256": host_recovery_sha256,
        "size": host_recovery_path.lstat().st_size,
    }
    return cleanup, expected_gates, intent_record, host_recovery_record


def _payload_inventory(root: Path, paths: list[str]) -> dict[str, Any]:
    entries = [_artifact_entry(root, relative) for relative in sorted(paths)]
    if len(entries) > MAX_ARTIFACTS:
        raise StabilityError("operator payload file count exceeds the fixed limit")
    byte_count = sum(item["size"] for item in entries)
    if byte_count > MAX_ARTIFACT_BYTES:
        raise StabilityError("operator payload bytes exceed the fixed limit")
    return {
        "byte_count": byte_count,
        "entries_sha256": digest_json(entries),
        "file_count": len(entries),
    }


def _authority_file_record(path: Path, label: str) -> dict[str, Any]:
    try:
        size = path.lstat().st_size
    except OSError as error:
        raise StabilityError(f"cannot inspect {label}: {error}") from error
    if size > MAX_DOCUMENT_BYTES:
        raise StabilityError(f"{label} exceeds its size limit")
    return {"path": path.as_posix(), "sha256": sha256_file(path), "size": size}


def _build_operator_receipt(
    session_root: Path,
    config_path: Path,
    launch_receipt_path: Path,
    operator_path: Path,
    boot_id: str,
    session_nonce: str,
    inner_verifier_log: Path,
    *,
    verify_live_cleanup: bool,
    cleanup_command_runner: HostCommandRunner | None = None,
    cleanup_live_cgroup_root: Path = Path("/sys/fs/cgroup"),
    cleanup_live_state_root: Path = Path("/var/lib/codeskeptic-p10-09"),
) -> dict[str, Any]:
    if not isinstance(boot_id, str) or BOOT_ID.fullmatch(boot_id) is None:
        raise StabilityError("operator receipt boot identity is malformed")
    if not isinstance(session_nonce, str) or BOOT_ID.fullmatch(session_nonce) is None:
        raise StabilityError("operator receipt session nonce is malformed")
    if re.fullmatch(
        rf"[0-9]{{8}}T[0-9]{{6}}Z-{re.escape(boot_id)}-"
        rf"{re.escape(session_nonce)}",
        session_root.name,
    ) is None:
        raise StabilityError("operator receipt session directory identity drift")
    host_root = session_root / "host"
    campaign_root = session_root / "campaign"
    expected_log = host_root / "inner-verification.log"
    if inner_verifier_log != expected_log:
        raise StabilityError("inner verifier log path is not canonical")
    pre = verify_host_snapshot(
        host_root / "pre", expected_boot_id=boot_id
    )
    identity = pre["identity"]
    post = verify_host_snapshot(
        host_root / "post",
        expected_boot_id=boot_id,
        expected_target_user=identity["target_user"],
        expected_target_uid=identity["target_uid"],
    )
    host_gates = _host_pair_projection(session_root, pre, post)
    inner = _inner_campaign_inventory(campaign_root)
    log_data = _read_regular_bytes(inner_verifier_log, 4096)
    expected_log_data = (
        "CODESKEPTIC_STABILITY_VERIFIED "
        f"{inner['receipt']['sha256']} {inner['session_id']}\n"
    ).encode("ascii")
    if log_data != expected_log_data:
        raise StabilityError("strict inner verifier success log is not exact")

    config = load_runtime_config_file(config_path)
    source_revision = config.get("source", {}).get("revision")
    source_tree_sha1 = config.get("source", {}).get("tree_sha1")
    source_manifest_sha256 = config.get("source", {}).get("manifest_sha256")
    if (
        not isinstance(source_revision, str)
        or GIT_SHA1.fullmatch(source_revision) is None
        or not isinstance(source_tree_sha1, str)
        or GIT_SHA1.fullmatch(source_tree_sha1) is None
        or not isinstance(source_manifest_sha256, str)
        or SHA256.fullmatch(source_manifest_sha256) is None
    ):
        raise StabilityError("runtime config source identity is malformed")
    config_record = _authority_file_record(config_path, "runtime config")
    config_sidecar_path = Path(f"{config_path}.sha256")
    config_sidecar_record = _authority_file_record(
        config_sidecar_path, "runtime config checksum"
    )
    load_runtime_launch_receipt(
        launch_receipt_path,
        config,
        runtime_config_sha256=config_record["sha256"],
        boot_id=boot_id,
    )
    launch_record = _authority_file_record(
        launch_receipt_path, "runtime launch receipt"
    )
    launch_sidecar_record = _authority_file_record(
        Path(f"{launch_receipt_path}.sha256"), "runtime launch checksum"
    )
    if (
        inner["boot_id"] != boot_id
        or inner["runtime_config_sha256"] != config_record["sha256"]
        or inner["runtime_launch_receipt_sha256"] != launch_record["sha256"]
    ):
        raise StabilityError("inner campaign authority differs from outer envelope")
    operator_record = _authority_file_record(operator_path, "host operator")
    runner_path = Path(__file__).resolve(strict=True)
    runner_record = _authority_file_record(runner_path, "stability runner")

    cleanup_path = host_root / "cleanup.json"
    (
        cleanup,
        cleanup_gates,
        cgroup_intent_record,
        host_recovery_intent_record,
    ) = _validate_cleanup_record(
        cleanup_path,
        session_root=session_root,
        boot_id=boot_id,
        session_nonce=session_nonce,
        target_user=identity["target_user"],
        target_uid=identity["target_uid"],
        operator_path=operator_path,
        expected_source_revision=source_revision,
        expected_source_tree_sha1=source_tree_sha1,
        expected_source_manifest_sha256=source_manifest_sha256,
        expected_runtime_config_sha256=config_record["sha256"],
        verify_live=verify_live_cleanup,
        command_runner=cleanup_command_runner,
        live_cgroup_root=cleanup_live_cgroup_root,
        live_state_root=cleanup_live_state_root,
    )
    del cleanup

    all_files = _regular_files(session_root)
    reserved = {"receipt.json", "receipt.json.sha256", "SHA256SUMS"}
    payload_paths = [relative for relative in all_files if relative not in reserved]
    expected_host_files = {
        "host/cgroup-authority-intent.json", "host/host-recovery-intent.json",
        "host/cleanup.json",
        "host/inner-verification.log",
        *{
            f"host/pre/{relative}"
            for relative in {
                *HOST_SNAPSHOT_PRE_RAW_FILES.values(),
                "snapshot.json", "snapshot.json.sha256", "SHA256SUMS",
            }
        },
        *{
            f"host/post/{relative}"
            for relative in {
                *HOST_SNAPSHOT_POST_RAW_FILES.values(),
                "snapshot.json", "snapshot.json.sha256", "SHA256SUMS",
            }
        },
    }
    actual_host_files = {
        relative for relative in payload_paths if relative.startswith("host/")
    }
    if actual_host_files != expected_host_files:
        raise StabilityError("operator host evidence inventory is not exact")
    if any(
        not relative.startswith(("campaign/", "host/"))
        for relative in payload_paths
    ):
        raise StabilityError("operator payload contains an inadmissible root file")
    campaign_paths = {
        f"campaign/{relative}" for relative in _regular_files(campaign_root)
    }
    if {p for p in payload_paths if p.startswith("campaign/")} != campaign_paths:
        raise StabilityError("operator inner campaign inventory drift")
    payload_inventory = _payload_inventory(session_root, payload_paths)
    def snapshot_record(phase: str) -> dict[str, Any]:
        snapshot = pre if phase == "pre" else post
        raw_files = _host_raw_files(phase)
        return {
        "checksum_manifest": {
            "path": f"host/{phase}/SHA256SUMS",
            "sha256": sha256_file(host_root / phase / "SHA256SUMS"),
        },
        "coredump": {
            "path": f"host/{phase}/{raw_files['coredumpctl']}",
            "sha256": snapshot["commands"]["coredumpctl"]["sha256"],
            "size": snapshot["commands"]["coredumpctl"]["size"],
        },
        "journals": {
            scope: {
                "kind": "cursor" if phase == "pre" else "delta",
                "path": f"host/{phase}/{raw_files[f'{scope}_journal']}",
                "sha256": snapshot["commands"][f"{scope}_journal"]["sha256"],
                "size": snapshot["commands"][f"{scope}_journal"]["size"],
            }
            for scope in ("system", "user")
        },
        "snapshot": {
            "path": f"host/{phase}/snapshot.json",
            "sha256": sha256_file(host_root / phase / "snapshot.json"),
        },
        }
    return {
        "schema": OPERATOR_RECEIPT_SCHEMA,
        "status": "accepted",
        "session": {
            "boot_id": boot_id,
            "name": session_root.name,
            "nonce": session_nonce,
            "target_uid": identity["target_uid"],
            "target_user": identity["target_user"],
            "target_home": identity["target_home"],
        },
        "authorities": {
            "cgroup_intent": cgroup_intent_record,
            "host_recovery_intent": host_recovery_intent_record,
            "config": config_record,
            "config_checksum": config_sidecar_record,
            "launch_receipt": launch_record,
            "launch_checksum": launch_sidecar_record,
            "operator": operator_record,
            "runner": runner_record,
            "pinned_image": {
                "digest": PINNED_EVIDENCE_IMAGE_DIGEST,
                "id": PINNED_EVIDENCE_IMAGE_ID,
                "reference": PINNED_EVIDENCE_IMAGE,
            },
        },
        "inner_campaign": inner,
        "inner_semantic_verification": {
            "command": RUNTIME_VERIFIER_COMMAND,
            "execution": "separate-pinned-container",
            "log": {
                "path": "host/inner-verification.log",
                "sha256": hashlib.sha256(log_data).hexdigest(),
                "size": len(log_data),
            },
            "status": "pass",
        },
        "host": {
            "cleanup": {
                "path": "host/cleanup.json",
                "sha256": sha256_file(cleanup_path),
                "gates": cleanup_gates,
            },
            "comparison": host_gates,
            "post": snapshot_record("post"),
            "pre": snapshot_record("pre"),
        },
        "payload_inventory": payload_inventory,
        "gates": {
            "cleanup": "pass",
            "host_contamination": "pass",
            "inner_checksum_inventory": "pass",
            "inner_semantic_verifier": "pass",
            "outer_checksum_inventory": "pass",
        },
        "failures": [],
    }


def seal_operator_evidence(
    session_root: Path,
    config_path: Path,
    launch_receipt_path: Path,
    operator_path: Path,
    boot_id: str,
    session_nonce: str,
    inner_verifier_log: Path,
    *,
    cleanup_command_runner: HostCommandRunner | None = None,
    cleanup_live_cgroup_root: Path = Path("/sys/fs/cgroup"),
    cleanup_live_state_root: Path = Path("/var/lib/codeskeptic-p10-09"),
) -> dict[str, Any]:
    for reserved in ("receipt.json", "receipt.json.sha256", "SHA256SUMS"):
        if (session_root / reserved).exists() or (session_root / reserved).is_symlink():
            raise StabilityError(f"operator evidence is already sealed: {reserved}")
    receipt = _build_operator_receipt(
        session_root, config_path, launch_receipt_path, operator_path,
        boot_id, session_nonce, inner_verifier_log,
        verify_live_cleanup=True,
        cleanup_command_runner=cleanup_command_runner,
        cleanup_live_cgroup_root=cleanup_live_cgroup_root,
        cleanup_live_state_root=cleanup_live_state_root,
    )
    receipt_data = canonical_document(receipt)
    _atomic_create(session_root / "receipt.json", receipt_data)
    _atomic_create(
        session_root / "receipt.json.sha256",
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n".encode("ascii"),
    )
    manifest_paths = sorted(
        relative for relative in _regular_files(session_root)
        if relative != "SHA256SUMS"
    )
    manifest = _snapshot_manifest(session_root, manifest_paths)
    if len(manifest) > MAX_DOCUMENT_BYTES:
        raise StabilityError("operator checksum manifest exceeds its size limit")
    _atomic_create(session_root / "SHA256SUMS", manifest)
    return verify_operator_evidence(
        session_root, config_path, launch_receipt_path, operator_path
    )


def verify_operator_evidence(
    session_root: Path,
    config_path: Path,
    launch_receipt_path: Path,
    operator_path: Path,
) -> dict[str, Any]:
    actual_files = _regular_files(session_root)
    required = {"receipt.json", "receipt.json.sha256", "SHA256SUMS"}
    if not required.issubset(actual_files):
        raise StabilityError("operator evidence envelope is incomplete")
    receipt = _load_document(session_root / "receipt.json", "operator receipt")
    _exact_dict(
        receipt,
        {
            "schema", "status", "session", "authorities", "inner_campaign",
            "inner_semantic_verification", "host", "payload_inventory", "gates",
            "failures",
        },
        "operator receipt",
    )
    if (
        receipt["schema"] != OPERATOR_RECEIPT_SCHEMA
        or receipt["status"] != "accepted"
        or receipt["failures"] != []
    ):
        raise StabilityError("operator receipt is not accepted")
    session = _exact_dict(
        receipt["session"],
        {
            "boot_id", "name", "nonce", "target_uid", "target_user",
            "target_home",
        },
        "operator receipt session",
    )
    if session["name"] != session_root.name:
        raise StabilityError("operator receipt session name drift")
    expected = _build_operator_receipt(
        session_root, config_path, launch_receipt_path, operator_path,
        session["boot_id"], session["nonce"],
        session_root / "host" / "inner-verification.log",
        verify_live_cleanup=False,
    )
    if receipt != expected:
        raise StabilityError("operator receipt differs from rederived evidence")
    receipt_data = _read_regular_bytes(
        session_root / "receipt.json", MAX_DOCUMENT_BYTES
    )
    expected_sidecar = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("ascii")
    if _read_regular_bytes(
        session_root / "receipt.json.sha256", 1024
    ) != expected_sidecar:
        raise StabilityError("operator receipt checksum mismatch")
    manifest_paths = sorted(
        relative for relative in actual_files if relative != "SHA256SUMS"
    )
    expected_manifest = _snapshot_manifest(session_root, manifest_paths)
    if _read_regular_bytes(
        session_root / "SHA256SUMS", MAX_DOCUMENT_BYTES
    ) != expected_manifest:
        raise StabilityError("operator outer checksum inventory mismatch")
    return receipt


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    seal_launch = subparsers.add_parser(
        "seal-launch", help="seal the fixed rootful-Podman launch claim"
    )
    seal_launch.add_argument("--config", type=Path, required=True)
    seal_launch.add_argument("--output", type=Path, required=True)
    seal_launch.add_argument("--boot-id", required=True)

    verify_launch = subparsers.add_parser(
        "verify-launch", help="verify the fixed config/launch pair"
    )
    verify_launch.add_argument("--config", type=Path, required=True)
    verify_launch.add_argument("--receipt", type=Path, required=True)
    verify_launch.add_argument("--boot-id", required=True)

    run = subparsers.add_parser(
        "run", help="execute one fresh authoritative cold/warm session"
    )
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser(
        "verify", help="strictly rederive one completed production session"
    )
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--evidence", type=Path, required=True)

    capture_host = subparsers.add_parser(
        "capture-host", help="capture one bounded pre/post host snapshot"
    )
    capture_host.add_argument("--output", type=Path, required=True)
    capture_host.add_argument("--boot-id", required=True)
    capture_host.add_argument("--target-user", required=True)
    capture_host.add_argument("--target-uid", type=int, required=True)

    seal_operator = subparsers.add_parser(
        "seal-operator", help="seal the host and inner campaign envelope"
    )
    seal_operator.add_argument("--session-root", type=Path, required=True)
    seal_operator.add_argument("--config", type=Path, required=True)
    seal_operator.add_argument("--launch-receipt", type=Path, required=True)
    seal_operator.add_argument("--operator", type=Path, required=True)
    seal_operator.add_argument("--boot-id", required=True)
    seal_operator.add_argument("--session-nonce", required=True)
    seal_operator.add_argument("--inner-verifier-log", type=Path, required=True)

    verify_operator = subparsers.add_parser(
        "verify-operator", help="rederive a sealed operator envelope"
    )
    verify_operator.add_argument("--session-root", type=Path, required=True)
    verify_operator.add_argument("--config", type=Path, required=True)
    verify_operator.add_argument("--launch-receipt", type=Path, required=True)
    verify_operator.add_argument("--operator", type=Path, required=True)

    action = subparsers.add_parser("_action", help=argparse.SUPPRESS)
    action.add_argument("--config", type=Path, required=True)
    action.add_argument("--plan", type=Path, required=True)
    action.add_argument("--action-ordinal", type=int, required=True)
    action.add_argument("--evidence", type=Path, required=True)
    action.add_argument("--runtime", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        if arguments.command == "seal-launch":
            receipt = seal_runtime_launch_receipt(
                arguments.config, arguments.output, arguments.boot_id
            )
            print(
                "CODESKEPTIC_STABILITY_LAUNCH_SEALED "
                f"{sha256_file(arguments.output / 'receipt.json')} "
                f"{receipt['boot_id']}"
            )
            return 0
        if arguments.command == "verify-launch":
            receipt = verify_runtime_launch_files(
                arguments.config, arguments.receipt, arguments.boot_id
            )
            print(
                "CODESKEPTIC_STABILITY_LAUNCH_VERIFIED "
                f"{sha256_file(arguments.receipt)} {receipt['boot_id']}"
            )
            return 0
        if arguments.command == "run":
            if (
                arguments.config != Path("/config/runtime.json")
                or arguments.output != Path("/evidence")
            ):
                raise StabilityError("runtime command paths differ from fixed mounts")
            receipt = run_production_session(arguments.config, arguments.output)
            print(
                "CODESKEPTIC_STABILITY_ACCEPTED "
                f"{sha256_file(arguments.output / 'receipt.json')} "
                f"{receipt['session']['id']}"
            )
            return 0
        if arguments.command == "verify":
            if (
                arguments.config != Path("/config/runtime.json")
                or arguments.evidence != Path("/evidence")
            ):
                raise StabilityError("verification paths differ from fixed mounts")
            receipt = verify_production_evidence(
                arguments.config, arguments.evidence,
                runtime_root=Path("/runtime"),
            )
            print(
                "CODESKEPTIC_STABILITY_VERIFIED "
                f"{sha256_file(arguments.evidence / 'receipt.json')} "
                f"{receipt['session']['id']}"
            )
            return 0
        if arguments.command == "capture-host":
            snapshot = capture_host_snapshot(
                arguments.output,
                arguments.boot_id,
                arguments.target_user,
                arguments.target_uid,
            )
            print(
                "CODESKEPTIC_HOST_SNAPSHOT_CAPTURED "
                f"{snapshot['phase']} "
                f"{sha256_file(arguments.output / 'snapshot.json')}"
            )
            return 0
        if arguments.command == "seal-operator":
            receipt = seal_operator_evidence(
                arguments.session_root,
                arguments.config,
                arguments.launch_receipt,
                arguments.operator,
                arguments.boot_id,
                arguments.session_nonce,
                arguments.inner_verifier_log,
            )
            print(
                "CODESKEPTIC_OPERATOR_EVIDENCE_SEALED "
                f"{sha256_file(arguments.session_root / 'receipt.json')} "
                f"{receipt['inner_campaign']['session_id']}"
            )
            return 0
        if arguments.command == "verify-operator":
            receipt = verify_operator_evidence(
                arguments.session_root,
                arguments.config,
                arguments.launch_receipt,
                arguments.operator,
            )
            print(
                "CODESKEPTIC_OPERATOR_EVIDENCE_VERIFIED "
                f"{sha256_file(arguments.session_root / 'receipt.json')} "
                f"{receipt['inner_campaign']['session_id']}"
            )
            return 0
        if arguments.command == "_action":
            if (
                arguments.config != Path("/config/runtime.json")
                or arguments.evidence != Path("/evidence")
                or arguments.runtime != Path("/runtime")
            ):
                raise StabilityError("internal action paths differ from fixed mounts")
            config = load_runtime_config_file(arguments.config)
            plan = _load_document(arguments.plan, "internal action plan")
            expected_plan_path = (
                arguments.evidence / "cycles"
                / f"{_integer(plan.get('ordinal'), 'internal action cycle', 1):06d}"
                / "plan.json"
            )
            if arguments.plan != expected_plan_path:
                raise StabilityError("internal action plan path drift")
            ordinal = _integer(
                arguments.action_ordinal, "internal action ordinal"
            )
            actions = plan.get("actions")
            if not isinstance(actions, list) or ordinal >= len(actions):
                raise StabilityError("internal action ordinal is outside its plan")
            output = execute_planned_action(
                config,
                plan,
                actions[ordinal],
                evidence_root=arguments.evidence,
                runtime_root=arguments.runtime,
            )
            print(
                "CODESKEPTIC_STABILITY_ACTION_ACCEPTED "
                f"{actions[ordinal]['id']} {sha256_file(output)}"
            )
            return 0
        raise StabilityError("stability command is unsupported")
    except StabilityError as error:
        print(f"CODESKEPTIC_STABILITY_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
