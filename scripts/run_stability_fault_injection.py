#!/usr/bin/env python3
"""Run and verify the fixed Phase 10.9 product fault-injection gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


SCHEMA = "codeskeptic-stability-fault-injection-v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 2 * 1024 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_XML_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_FILES = 8
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
TIMEOUT_SECONDS = 900
REQUIRED_TESTS = [
    "ResourceSupervisorTest.TimeoutKillsChildWithinBound",
    "ResourceSupervisorTest.MemoryCeilingIsIndependentlyTriggerable",
    "BudgetedAnalysisTest.TimeoutPreservesCompletedReceiptsAndContinues",
    "BudgetedAnalysisTest.ExpectedCheckpointCorruptionIsWorkerFailure",
    "BudgetedAnalysisTest.MemoryCeilingFailsExactTranslationUnitClosed",
    "UnitEvidenceStoreTest.ExpectedEntryCorruptionFailsClosed",
]
CANONICAL_TESTS = sorted(REQUIRED_TESTS)


class FaultInjectionError(RuntimeError):
    """The fixed fault-injection evidence is unavailable or malformed."""


class _FaultTaskSnapshotChanged(FaultInjectionError):
    """A TGID's task set changed during exact cleanup inspection."""


class _FaultTaskInventoryUnavailable(_FaultTaskSnapshotChanged):
    """The kernel exposes a TGID identity but not its thread inventory."""


def canonical_document(value: Any) -> bytes:
    return (
        json.dumps(
            value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
        )
        + "\n"
    ).encode("utf-8")


def _read_regular(path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise FaultInjectionError(f"cannot inspect regular file {path}: {error}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise FaultInjectionError(f"inadmissible regular file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino, opened.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
            ):
                raise FaultInjectionError(f"regular file changed while opening: {path}")
            blocks: list[bytes] = []
            total = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise FaultInjectionError(f"regular file exceeds limit: {path}")
                blocks.append(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except FaultInjectionError:
        raise
    except OSError as error:
        raise FaultInjectionError(f"cannot read regular file {path}: {error}") from error
    if (
        (after.st_dev, after.st_ino, after.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
    ):
        raise FaultInjectionError(f"regular file changed while reading: {path}")
    return b"".join(blocks)


def _sha256_regular(path: Path, maximum: int) -> str:
    """Hash one stable regular file in bounded blocks without loading it."""

    try:
        before = path.lstat()
    except OSError as error:
        raise FaultInjectionError(f"cannot inspect regular file {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size < 0
        or before.st_size > maximum
    ):
        raise FaultInjectionError(f"regular file exceeds hash limit: {path}")
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
                or (opened.st_dev, opened.st_ino, opened.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
            ):
                raise FaultInjectionError(f"regular file changed while opening: {path}")
            total = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise FaultInjectionError(f"regular file exceeds hash limit: {path}")
                digest.update(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except FaultInjectionError:
        raise
    except OSError as error:
        raise FaultInjectionError(f"cannot hash regular file {path}: {error}") from error
    if (
        total != before.st_size
        or (after.st_dev, after.st_ino, after.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
    ):
        raise FaultInjectionError(f"regular file changed while hashing: {path}")
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    return _sha256_regular(path, MAX_FILE_BYTES)


def sha256_binary(path: Path) -> str:
    return _sha256_regular(path, MAX_BINARY_BYTES)


def _atomic_create(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise FaultInjectionError(f"short write: {path}")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError as error:
        raise FaultInjectionError(f"output already exists: {path}") from error
    except FaultInjectionError:
        raise
    except OSError as error:
        raise FaultInjectionError(f"cannot publish {path}: {error}") from error


def _exact_dict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise FaultInjectionError(f"{label} shape drift")
    return value


def _positive_int_text(value: str | None, label: str) -> int:
    if value is None or not value.isascii() or not value.isdigit():
        raise FaultInjectionError(f"{label} is malformed")
    result = int(value)
    if result < 0:
        raise FaultInjectionError(f"{label} is malformed")
    return result


def parse_gtest_xml(path: Path) -> dict[str, Any]:
    data = _read_regular(path, MAX_XML_BYTES)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise FaultInjectionError(f"gtest XML is malformed: {error}") from error
    if root.tag != "testsuites":
        raise FaultInjectionError("gtest XML root drift")
    declared = {
        name: _positive_int_text(root.get(name), f"gtest {name}")
        for name in ("tests", "failures", "disabled", "errors")
    }
    observed: list[str] = []
    for suite in root.findall("testsuite"):
        suite_name = suite.get("name")
        if not isinstance(suite_name, str) or not suite_name:
            raise FaultInjectionError("gtest suite name is malformed")
        for case in suite.findall("testcase"):
            case_name = case.get("name")
            if (
                not isinstance(case_name, str)
                or not case_name
                or case.get("status") != "run"
                or case.get("result") != "completed"
                or list(case)
            ):
                raise FaultInjectionError("gtest case is not an exact success")
            observed.append(f"{suite_name}.{case_name}")
    if (
        declared != {
            "tests": len(REQUIRED_TESTS),
            "failures": 0,
            "disabled": 0,
            "errors": 0,
        }
        or len(observed) != len(set(observed))
        or sorted(observed) != CANONICAL_TESTS
    ):
        raise FaultInjectionError("gtest fault-injection inventory drift")
    return {
        "test_count": len(observed),
        "tests": list(CANONICAL_TESTS),
        "failures": 0,
        "disabled": 0,
        "errors": 0,
    }


def _inventory(root: Path) -> list[str]:
    try:
        iterator = os.scandir(root)
    except OSError as error:
        raise FaultInjectionError(f"cannot enumerate evidence root: {error}") from error
    result: list[str] = []
    byte_count = 0
    with iterator:
        for entry in iterator:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise FaultInjectionError(
                    f"cannot inspect evidence member: {error}"
                ) from error
            if not stat.S_ISREG(metadata.st_mode):
                raise FaultInjectionError(
                    "fault-injection evidence contains a non-regular member"
                )
            if entry.name == "gtest.log":
                maximum = MAX_LOG_BYTES
            elif entry.name == "gtest.xml":
                maximum = MAX_XML_BYTES
            else:
                maximum = MAX_FILE_BYTES
            if metadata.st_size > maximum:
                raise FaultInjectionError(
                    f"fault-injection {entry.name} exceeds its size limit"
                )
            byte_count += metadata.st_size
            if byte_count > MAX_EVIDENCE_BYTES:
                raise FaultInjectionError(
                    "fault-injection evidence bytes exceed the fixed limit"
                )
            result.append(entry.name)
            if len(result) > MAX_EVIDENCE_FILES:
                raise FaultInjectionError(
                    "fault-injection evidence file count exceeds the fixed limit"
                )
    return sorted(result)


def verify_evidence(
    root: Path, *, source_revision: str, binary: Path, binary_sha256: str,
) -> dict[str, Any]:
    if GIT_SHA1.fullmatch(source_revision) is None:
        raise FaultInjectionError("source revision is malformed")
    if SHA256.fullmatch(binary_sha256) is None:
        raise FaultInjectionError("test binary checksum is malformed")
    if sha256_binary(binary) != binary_sha256:
        raise FaultInjectionError("test binary checksum drift")
    expected_files = [
        "SHA256SUMS", "gtest.log", "gtest.xml", "receipt.json",
        "receipt.json.sha256",
    ]
    if _inventory(root) != expected_files:
        raise FaultInjectionError("fault-injection evidence file set drift")
    receipt_data = _read_regular(root / "receipt.json")
    try:
        receipt = json.loads(receipt_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FaultInjectionError(f"fault-injection receipt is malformed: {error}") from error
    if not isinstance(receipt, dict) or canonical_document(receipt) != receipt_data:
        raise FaultInjectionError("fault-injection receipt is not canonical")
    value = _exact_dict(
        receipt,
        {
            "schema", "status", "failures", "source_revision", "binary",
            "command", "results", "artifacts",
        },
        "fault-injection receipt",
    )
    binary_record = _exact_dict(
        value["binary"], {"path", "sha256"}, "fault-injection binary"
    )
    command = _exact_dict(
        value["command"], {"filter", "timeout_seconds"},
        "fault-injection command",
    )
    results = _exact_dict(
        value["results"],
        {"test_count", "tests", "failures", "disabled", "errors"},
        "fault-injection results",
    )
    artifacts = _exact_dict(
        value["artifacts"], {"gtest.log", "gtest.xml"},
        "fault-injection artifacts",
    )
    if (
        value["schema"] != SCHEMA
        or value["status"] != "accepted"
        or value["failures"] != []
        or value["source_revision"] != source_revision
        or binary_record != {"path": binary.as_posix(), "sha256": binary_sha256}
        or command != {
            "filter": ":".join(REQUIRED_TESTS),
            "timeout_seconds": TIMEOUT_SECONDS,
        }
        or results != parse_gtest_xml(root / "gtest.xml")
    ):
        raise FaultInjectionError("fault-injection authority drift")
    for name in ("gtest.log", "gtest.xml"):
        record = _exact_dict(
            artifacts[name], {"sha256", "size"},
            f"fault-injection {name}",
        )
        data = _read_regular(
            root / name,
            MAX_LOG_BYTES if name == "gtest.log" else MAX_XML_BYTES,
        )
        if record != {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }:
            raise FaultInjectionError(f"fault-injection {name} checksum drift")
    expected_sidecar = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("ascii")
    if _read_regular(root / "receipt.json.sha256", 1024) != expected_sidecar:
        raise FaultInjectionError("fault-injection receipt checksum drift")
    manifest_paths = [
        "receipt.json", "receipt.json.sha256", "gtest.log", "gtest.xml"
    ]
    expected_manifest = b"".join(
        f"{sha256_file(root / name)}  {name}\n".encode("ascii")
        for name in manifest_paths
    )
    if _read_regular(root / "SHA256SUMS") != expected_manifest:
        raise FaultInjectionError("fault-injection checksum manifest drift")
    return value


_COMMAND_SUPERVISOR = r"""
import ctypes
import json
import os
import resource
import signal
import subprocess
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    os._exit(125)
argv = json.loads(sys.argv[1])
file_size_limit = int(sys.argv[2])
resource.setrlimit(
    resource.RLIMIT_FSIZE, (file_size_limit, file_size_limit)
)
signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
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


def _proc_record(pid: int) -> tuple[int, int, str] | None:
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
        return int(fields[1]), int(fields[19]), state
    except (FileNotFoundError, OSError, UnicodeDecodeError, ValueError, IndexError):
        return None


_DEAD_TASK_STATES = frozenset({"Z", "X", "x"})
_QUIESCED_TASK_STATES = frozenset({"T", "t", "Z", "X", "x"})


def _proc_task_states(pid: int, start_time: int) -> dict[int, str] | None:
    """Return one stable all-thread snapshot for an exact TGID."""

    before = _proc_record(pid)
    if before is None or before[1] != start_time:
        return None
    task_root = Path("/proc") / str(pid) / "task"
    try:
        before_names = {
            name for name in os.listdir(task_root)
            if name.isascii() and name.isdigit()
        }
    except FileNotFoundError:
        after = _proc_record(pid)
        if after is None or after[1] != start_time:
            return None
        raise _FaultTaskInventoryUnavailable(
            f"fault-injection TGID {pid} task directory changed"
        )
    except OSError as error:
        raise FaultInjectionError(
            f"cannot enumerate fault-injection TGID {pid} tasks: {error}"
        ) from error
    if not before_names or str(pid) not in before_names:
        raise _FaultTaskInventoryUnavailable(
            f"fault-injection TGID {pid} task inventory is incomplete"
        )

    states: dict[int, str] = {}
    for name in before_names:
        try:
            fields = (
                (task_root / name / "stat")
                .read_text(encoding="ascii")
                .rsplit(")", 1)[1]
                .strip()
                .split()
            )
            state = fields[0]
            if len(state) != 1:
                raise ValueError("malformed task state")
        except FileNotFoundError as error:
            raise _FaultTaskSnapshotChanged(
                f"fault-injection TGID {pid} task inventory changed"
            ) from error
        except (OSError, UnicodeDecodeError, ValueError, IndexError) as error:
            raise FaultInjectionError(
                f"cannot inspect fault-injection task {pid}/{name}: {error}"
            ) from error
        states[int(name)] = state

    try:
        after_names = {
            name for name in os.listdir(task_root)
            if name.isascii() and name.isdigit()
        }
    except FileNotFoundError as error:
        after = _proc_record(pid)
        if after is None or after[1] != start_time:
            return None
        raise _FaultTaskInventoryUnavailable(
            f"fault-injection TGID {pid} task directory changed"
        ) from error
    except OSError as error:
        raise FaultInjectionError(
            f"cannot re-enumerate fault-injection TGID {pid} tasks: {error}"
        ) from error
    after = _proc_record(pid)
    if after is None or after[1] != start_time:
        return None
    if before_names != after_names:
        raise _FaultTaskSnapshotChanged(
            f"fault-injection TGID {pid} task inventory changed"
        )
    return states


def _proc_identity(pid: int) -> tuple[int, int] | None:
    record = _proc_record(pid)
    return None if record is None else record[:2]


def _owned_descendants(root_pid: int) -> dict[int, int]:
    try:
        names = os.listdir("/proc")
    except OSError as error:
        raise FaultInjectionError(
            f"cannot enumerate owned fault descendants: {error}"
        ) from error
    identities: dict[int, tuple[int, int]] = {}
    children: dict[int, list[int]] = {}
    for name in names:
        if not name.isascii() or not name.isdigit():
            continue
        pid = int(name)
        identity = _proc_identity(pid)
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


def _signal_owned(pid: int, start_time: int, signal_number: int) -> None:
    identity = _proc_identity(pid)
    if identity is None or identity[1] != start_time:
        return
    try:
        os.kill(pid, signal_number)
    except ProcessLookupError:
        return
    except PermissionError as error:
        raise FaultInjectionError(
            f"cannot signal owned fault PID {pid}: {error}"
        ) from error


def _kill_owned_command(process: subprocess.Popen[bytes]) -> None:
    """Quiesce the subreaper tree, kill children, then let it reap to ECHILD."""

    root_pid = process.pid
    root_identity = _proc_identity(root_pid)
    if root_identity is None:
        process.wait(timeout=2.0)
        return
    root_start_time = root_identity[1]
    known: dict[int, int] = {}
    deadline = time.monotonic() + 5.0
    try:
        _signal_owned(root_pid, root_start_time, signal.SIGSTOP)
        while True:
            if time.monotonic() >= deadline:
                raise FaultInjectionError(
                    "fault-injection descendants did not quiesce during cleanup"
                )
            root_record = _proc_record(root_pid)
            if root_record is None or root_record[1] != root_start_time:
                break
            try:
                root_tasks = _proc_task_states(root_pid, root_start_time)
            except _FaultTaskInventoryUnavailable as error:
                raise FaultInjectionError(
                    "fault-injection supervisor thread inventory is unavailable"
                ) from error
            except _FaultTaskSnapshotChanged:
                _signal_owned(root_pid, root_start_time, signal.SIGSTOP)
                time.sleep(0.01)
                continue
            if root_tasks is None:
                break
            if any(
                state not in _QUIESCED_TASK_STATES
                for state in root_tasks.values()
            ):
                _signal_owned(root_pid, root_start_time, signal.SIGSTOP)
                time.sleep(0.01)
                continue

            descendants = _owned_descendants(root_pid)
            known.update(descendants)
            live = False
            for pid, start_time in descendants.items():
                try:
                    task_states = _proc_task_states(pid, start_time)
                except _FaultTaskInventoryUnavailable:
                    # The stopped subreaper owns this exact TGID. Kill its
                    # hidden thread group and rediscover any adopted forks.
                    live = True
                    _signal_owned(pid, start_time, signal.SIGKILL)
                    continue
                except _FaultTaskSnapshotChanged:
                    live = True
                    _signal_owned(pid, start_time, signal.SIGSTOP)
                    continue
                if task_states is None:
                    continue
                active_states = [
                    state for state in task_states.values()
                    if state not in _DEAD_TASK_STATES
                ]
                if not active_states:
                    continue
                live = True
                if all(state in {"T", "t"} for state in active_states):
                    # A verified stopped process cannot fork between this
                    # observation and the uncatchable SIGKILL.
                    _signal_owned(pid, start_time, signal.SIGSTOP)
                    _signal_owned(pid, start_time, signal.SIGKILL)
                else:
                    # Never kill a merely signalled process yet: it may fork
                    # before SIGSTOP is delivered.  Rediscover after it is
                    # observably stopped, closing the fixed-snapshot race.
                    _signal_owned(pid, start_time, signal.SIGSTOP)
            if not live:
                break
            time.sleep(0.01)

        root_record = _proc_record(root_pid)
        if root_record is not None and root_record[1] == root_start_time:
            if known:
                # The wrapper is the subreaper authority. Once its known
                # descendants are killed, resume it only so its waitpid loop
                # can prove ECHILD and exit.
                _signal_owned(root_pid, root_start_time, signal.SIGCONT)
            else:
                # The exact wrapper is observably stopped and has never had a
                # discovered target. Kill it while stopped so selector/setup
                # failure cannot resume it into a post-snapshot spawn.
                _signal_owned(root_pid, root_start_time, signal.SIGKILL)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FaultInjectionError(
                "fault-injection supervisor cleanup deadline expired"
            )
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise FaultInjectionError(
                "fault-injection subreaper did not reap descendants to ECHILD"
            ) from error
        survivors = {
            pid: start_time
            for pid, start_time in known.items()
            if (
                (identity := _proc_identity(pid)) is not None
                and identity[1] == start_time
            )
        }
        if survivors:
            raise FaultInjectionError(
                "fault-injection owned descendants survived convergent cleanup"
            )
    except Exception as cleanup_error:
        for pid, start_time in known.items():
            _signal_owned(pid, start_time, signal.SIGKILL)
        _signal_owned(root_pid, root_start_time, signal.SIGKILL)
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired as error:
            raise FaultInjectionError(
                f"{cleanup_error}; fault-injection supervisor survived SIGKILL"
            ) from error
        if isinstance(cleanup_error, FaultInjectionError):
            raise
        raise FaultInjectionError(
            f"cannot converge fault-injection cleanup: {cleanup_error}"
        ) from cleanup_error

def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise FaultInjectionError("short write to bounded gtest log")
        view = view[written:]


def _run_bounded_gtest(
    command: list[str], root: Path, log_path: Path, timeout_seconds: int,
) -> int:
    if not sys.platform.startswith("linux") or not Path("/proc/self/stat").is_file():
        raise FaultInjectionError(
            "fault-injection descendant containment requires Linux /proc"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(log_path, flags, 0o600)
    supervisor = [
        os.path.realpath(sys.executable),
        "-I",
        "-c",
        _COMMAND_SUPERVISOR,
        json.dumps(command, ensure_ascii=True, separators=(",", ":")),
        str(MAX_XML_BYTES),
    ]
    try:
        process = subprocess.Popen(
            supervisor,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
        )
    except Exception as error:
        try:
            os.close(descriptor)
        except OSError as close_error:
            raise FaultInjectionError(
                f"cannot start fault-injection command: {error}; "
                f"log close failed: {close_error}"
            ) from error
        raise FaultInjectionError(
            f"cannot start fault-injection command: {error}"
        ) from error
    selector: selectors.BaseSelector | None = None
    output_pipe = process.stdout
    total = 0
    failure: str | None = None
    return_code: int | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        if output_pipe is None:
            raise FaultInjectionError(
                "fault-injection output pipe is unavailable"
            )
        selector = selectors.DefaultSelector()
        pipe_descriptor = output_pipe.fileno()
        os.set_blocking(pipe_descriptor, False)
        selector.register(pipe_descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "fault-injection command timed out"
                _kill_owned_command(process)
                break
            try:
                _inventory(root)
            except FaultInjectionError as error:
                failure = str(error)
                _kill_owned_command(process)
                break
            if not selector.get_map():
                if process.poll() is not None:
                    break
                time.sleep(min(0.05, remaining))
                continue
            events = selector.select(min(0.05, remaining))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in list(selector.get_map().values())
                ]
            for key, _mask in events:
                try:
                    block = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fd)
                    continue
                available = MAX_LOG_BYTES - total
                if available < len(block):
                    if available > 0:
                        _write_all(descriptor, block[:available])
                        total += available
                    failure = "fault-injection gtest.log exceeds its size limit"
                    _kill_owned_command(process)
                    break
                _write_all(descriptor, block)
                total += len(block)
            if failure is not None:
                break
        if failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "fault-injection command timed out"
                _kill_owned_command(process)
            else:
                try:
                    return_code = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = "fault-injection command timed out"
                    _kill_owned_command(process)
        os.fsync(descriptor)
    except BaseException as error:
        primary_error = error
        try:
            _kill_owned_command(process)
        except Exception as cleanup_error:
            cleanup_errors.append(f"process cleanup: {cleanup_error}")
    finally:
        if selector is not None:
            try:
                selector.close()
            except Exception as error:
                cleanup_errors.append(f"selector close: {error}")
        if output_pipe is not None:
            try:
                output_pipe.close()
            except Exception as error:
                cleanup_errors.append(f"output pipe close: {error}")
        try:
            os.close(descriptor)
        except OSError as error:
            cleanup_errors.append(f"log close: {error}")
    if primary_error is not None:
        suffix = (
            "; cleanup failed: " + "; ".join(cleanup_errors)
            if cleanup_errors else ""
        )
        if isinstance(primary_error, FaultInjectionError):
            raise FaultInjectionError(
                f"{primary_error}{suffix}"
            ) from primary_error
        if isinstance(primary_error, Exception):
            raise FaultInjectionError(
                f"fault-injection supervision failed: {primary_error}{suffix}"
            ) from primary_error
        if cleanup_errors:
            raise FaultInjectionError(
                "fault-injection interrupted; cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from primary_error
        raise primary_error
    if cleanup_errors:
        raise FaultInjectionError(
            "fault-injection cleanup failed: " + "; ".join(cleanup_errors)
        )
    if failure is not None:
        raise FaultInjectionError(failure)
    if type(return_code) is not int:
        raise FaultInjectionError("fault-injection return code is malformed")
    return return_code


def run_gate(
    root: Path, *, source_revision: str, binary: Path, binary_sha256: str,
) -> dict[str, Any]:
    if GIT_SHA1.fullmatch(source_revision) is None:
        raise FaultInjectionError("source revision is malformed")
    if SHA256.fullmatch(binary_sha256) is None or sha256_binary(binary) != binary_sha256:
        raise FaultInjectionError("test binary checksum drift")
    try:
        metadata = root.lstat()
        entries = list(root.iterdir())
    except OSError as error:
        raise FaultInjectionError(f"cannot inspect output directory: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or entries:
        raise FaultInjectionError("fault-injection output must be a fresh empty directory")
    xml_path = root / "gtest.xml"
    log_path = root / "gtest.log"
    filter_value = ":".join(REQUIRED_TESTS)
    command = [
        binary.as_posix(),
        f"--gtest_filter={filter_value}",
        "--gtest_color=no",
        f"--gtest_output=xml:{xml_path}",
    ]
    try:
        return_code = _run_bounded_gtest(
            command, root, log_path, TIMEOUT_SECONDS
        )
    except FaultInjectionError:
        raise
    except OSError as error:
        raise FaultInjectionError(
            f"fault-injection command failed: {error}"
        ) from error
    if return_code != 0:
        if return_code == 128 + signal.SIGXFSZ:
            raise FaultInjectionError(
                "fault-injection artifact exceeds its size limit"
            )
        try:
            xml_metadata = xml_path.lstat()
        except FileNotFoundError:
            xml_metadata = None
        except OSError as error:
            raise FaultInjectionError(
                f"cannot inspect failed gtest XML: {error}"
            ) from error
        if (
            xml_metadata is not None
            and stat.S_ISREG(xml_metadata.st_mode)
            and xml_metadata.st_size >= MAX_XML_BYTES
        ):
            raise FaultInjectionError(
                "fault-injection gtest.xml exceeds its size limit"
            )
        raise FaultInjectionError(
            f"fault-injection command returned {return_code}"
        )
    results = parse_gtest_xml(xml_path)
    artifacts: dict[str, dict[str, Any]] = {}
    for name in ("gtest.log", "gtest.xml"):
        data = _read_regular(
            root / name,
            MAX_LOG_BYTES if name == "gtest.log" else MAX_XML_BYTES,
        )
        artifacts[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    receipt = {
        "schema": SCHEMA,
        "status": "accepted",
        "failures": [],
        "source_revision": source_revision,
        "binary": {"path": binary.as_posix(), "sha256": binary_sha256},
        "command": {
            "filter": filter_value,
            "timeout_seconds": TIMEOUT_SECONDS,
        },
        "results": results,
        "artifacts": artifacts,
    }
    receipt_data = canonical_document(receipt)
    _atomic_create(root / "receipt.json", receipt_data)
    _atomic_create(
        root / "receipt.json.sha256",
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n".encode(
            "ascii"
        ),
    )
    manifest_paths = [
        "receipt.json", "receipt.json.sha256", "gtest.log", "gtest.xml"
    ]
    _atomic_create(
        root / "SHA256SUMS",
        b"".join(
            f"{sha256_file(root / name)}  {name}\n".encode("ascii")
            for name in manifest_paths
        ),
    )
    return verify_evidence(
        root,
        source_revision=source_revision,
        binary=binary,
        binary_sha256=binary_sha256,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "verify"):
        child = subparsers.add_parser(name)
        child.add_argument("--source-revision", required=True)
        child.add_argument("--binary", type=Path, required=True)
        child.add_argument("--binary-sha256", required=True)
        child.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            receipt = run_gate(
                args.output,
                source_revision=args.source_revision,
                binary=args.binary,
                binary_sha256=args.binary_sha256,
            )
        else:
            receipt = verify_evidence(
                args.output,
                source_revision=args.source_revision,
                binary=args.binary,
                binary_sha256=args.binary_sha256,
            )
        print(
            "CODESKEPTIC_FAULT_INJECTION_ACCEPTED "
            f"{sha256_file(args.output / 'receipt.json')} "
            f"{receipt['results']['test_count']}"
        )
        return 0
    except FaultInjectionError as error:
        print(f"CODESKEPTIC_FAULT_INJECTION_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
