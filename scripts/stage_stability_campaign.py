#!/usr/bin/env python3
"""Prepare, seal, verify, and install the exact P10-09 runtime bundle."""

from __future__ import annotations

import argparse
import copy
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import fcntl
except ModuleNotFoundError:  # Windows can inspect portable source contracts.
    fcntl = None


TOOL_VERSION = "4"
BUNDLE_RECEIPT_SCHEMA = "codeskeptic-stability-staging-bundle-v1"
INVENTORY_SCHEMA = "codeskeptic-stability-staging-inventory-v1"
INSTALLATION_RECEIPT_SCHEMA = "codeskeptic-stability-installation-v1"
INSTALLATION_AUTHORITY_SCHEMA = "codeskeptic-stability-installation-authority-v1"
RUNTIME_CONFIG_SCHEMA = "codeskeptic-stability-runtime-v3"
AUTHORITY_OPERATION_MARKERS = frozenset({
    ".p10-09-authority-operation.json",
    ".p10-09-authority-operation.json.cleanup",
    ".p10-09-authority-transaction.json",
    ".p10-09-authority-transaction.json.cleanup",
})

BUNDLE_RECEIPT_FIELDS = frozenset({
    "schema", "revision", "source_tree_sha1", "source_manifest_sha256",
    "inventory_sha256", "runtime_config_sha256", "image_archive_sha256",
    "image_reference", "image_digest", "image_id",
})
INSTALLATION_RECEIPT_FIELDS = frozenset({
    "schema", "bundle_revision", "bundle_receipt_sha256", "bundle_inventory_sha256",
    "installed_inventory_sha256", "authority_root", "operator_root",
    "config_path", "unit_path", "image",
})
DIRECTORY_INVENTORY_FIELDS = frozenset({"path", "type", "mode"})
FILE_INVENTORY_FIELDS = frozenset({
    "path", "type", "mode", "size", "sha256",
})

CONTAINER_AUTHORITY_ROOT = PurePosixPath("/authority")
CONTAINER_SOURCE_ROOT = CONTAINER_AUTHORITY_ROOT / "source"
CONTAINER_BUILD_ROOT = CONTAINER_AUTHORITY_ROOT / "build"
SANITIZER_WORK_ROOT = Path("build/p10-09-sanitizers")
SANITIZER_PROFILES = ("address", "undefined")
RUNTIME_SOURCE_FILES = (
    "CMakeLists.txt", ".gitattributes", "Dockerfile", "action.yml",
)
RUNTIME_SOURCE_DIRECTORIES = (
    ".github/workflows", "src", "fuzz", "scripts", "tests", "docs",
    "profiles", "third_party",
)
RUNTIME_SOURCE_IGNORED_PREFIXES = (
    "docs/evidence/", "docs/devlog/changelog.md",
    "scripts/determinism_baseline.json",
)
RUNTIME_MEASUREMENT_CGROUP = (
    "/sys/fs/cgroup/system.slice/codeskeptic-stability.service/"
    "codeskeptic-p10-09/measurement"
)

PINNED_EVIDENCE_IMAGE_DIGEST = (
    "sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
)
PINNED_EVIDENCE_IMAGE = (
    "localhost/codeskeptic-p10-07-evidence@"
    + PINNED_EVIDENCE_IMAGE_DIGEST
)
PINNED_EVIDENCE_IMAGE_ID = (
    "sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5"
)

AUTHORITY_ROOT = Path("/opt/codeskeptic-p10-09/authority")
OPERATOR_ROOT = Path("/opt/codeskeptic-p10-09/operator")
CONFIG_PATH = Path("/etc/codeskeptic-p10-09/runtime.json")
UNIT_PATH = Path("/etc/systemd/system/codeskeptic-stability.service")
INSTALLATION_ROOT = Path("/opt/codeskeptic-p10-09/installation")
INSTALLATION_RECEIPT_PATH = INSTALLATION_ROOT / "receipt.json"
STATE_ROOT = Path("/var/lib/codeskeptic-p10-09")
INSTALLATION_AUTHORITY_PATH = STATE_ROOT / "installation-authority.json"
PODMAN_ROOT = STATE_ROOT / "podman-root"
PODMAN_RUNROOT = Path("/run/codeskeptic-p10-09/podman-runroot")
PODMAN_ENVIRONMENT_NAME = "podman-environment"
PODMAN_ENVIRONMENT_DIRECTORIES = (
    "home", "data", "cache", "config", "runtime", "tmp",
)
PINNED_ARCHIVE_NAME = "pinned-evidence-image.oci.tar"
UNIT_NAME = "codeskeptic-stability.service"
STABILITY_EXEC_START = (
    "ExecStart=/usr/bin/systemd-inhibit --what=sleep "
    "--who=CodeSkeptic-P10-09 "
    "--why=authoritative-scope-bound-stability-evidence-session "
    "--mode=block --no-ask-password /usr/bin/prlimit --nofile=4096:4096 -- "
    "/opt/codeskeptic-p10-09/operator/run-authoritative-stability.sh"
)
STABILITY_UNIT_REQUIRED_LINES = frozenset({
    "Before=shutdown.target rescue.target emergency.target",
    "Conflicts=shutdown.target rescue.target emergency.target",
    "IgnoreOnIsolate=yes",
    "Type=exec",
    (
        "ExecStartPre=/opt/codeskeptic-p10-09/operator/"
        "post-stop.sh --startup-recovery"
    ),
    STABILITY_EXEC_START,
    "ExecStopPost=/opt/codeskeptic-p10-09/operator/post-stop.sh",
    "KillMode=control-group",
    "TimeoutStopSec=2min",
    "Delegate=cpu cpuset memory pids",
    "DelegateSubgroup=controller",
    "StateDirectory=codeskeptic-p10-09",
    "ProtectControlGroups=no",
})
PODMAN = Path("/usr/bin/podman")
CONMON = Path("/usr/bin/conmon")
CRUN = Path("/usr/bin/crun")
IMAGE_PROBE_MARKER = b"CODESKEPTIC_STAGING_IMAGE_PROBE_OK\n"
STATIC_AUTHORITY_MARKER = b"CODESKEPTIC_STAGING_STATIC_AUTHORITIES_OK\n"

STATIC_AUTHORITY_VERIFIER = r"""
from pathlib import Path
import sys

sys.path.insert(0, "/authority/source/scripts")
import run_stability_campaign as stability

config = stability.load_runtime_config_file(Path("/config/runtime.json"))
policy, _schedule, _source = stability.verify_runtime_source_and_policy(config)
authorities = stability.verify_runtime_static_authorities(config, policy)
stability.verify_runtime_static_authority_identities(config, authorities)
print("CODESKEPTIC_STAGING_STATIC_AUTHORITIES_OK")
""".strip()

SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
HOSTED_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_INVENTORY_ENTRIES = 1_000_000
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
EXTERNAL_COMMAND_TIMEOUT_SECONDS = 900
IMAGE_LOAD_TIMEOUT_SECONDS = 1800
LARGE_TEMPORARY_RESERVE_BYTES = 4 * 1024 * 1024 * 1024
VFS_ARCHIVE_EXPANSION_FACTOR = 10


class StagingError(RuntimeError):
    """The staging or installed authority violates its fixed contract."""


def canonical_document(value: Any) -> bytes:
    return (
        json.dumps(
            value, indent=2, sort_keys=True, ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _stat_time_ns(metadata: os.stat_result, field: str) -> int:
    nanoseconds = getattr(metadata, field + "_ns", None)
    if nanoseconds is not None:
        return int(nanoseconds)
    return int(float(getattr(metadata, field)) * 1_000_000_000)


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        _stat_time_ns(metadata, "st_mtime"),
        _stat_time_ns(metadata, "st_ctime"),
    )


def _same_file_identity(
    left: os.stat_result, right: os.stat_result
) -> bool:
    return os.path.samestat(left, right)


def _valid_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise StagingError(f"{label} is malformed")
    return value


def _valid_git_sha1(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA1.fullmatch(value) is None:
        raise StagingError(f"{label} is malformed")
    return value


def _exact_dict(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise StagingError(f"{label} fields are malformed")
    return value


def validate_bundle_receipt(value: Any) -> dict[str, Any]:
    receipt = _exact_dict(value, BUNDLE_RECEIPT_FIELDS, "bundle receipt")
    if receipt["schema"] != BUNDLE_RECEIPT_SCHEMA:
        raise StagingError("bundle receipt schema drift")
    _valid_git_sha1(receipt["revision"], "bundle revision")
    _valid_git_sha1(receipt["source_tree_sha1"], "bundle source tree")
    for field in (
        "source_manifest_sha256", "inventory_sha256",
        "runtime_config_sha256", "image_archive_sha256",
    ):
        _valid_sha256(receipt[field], f"bundle {field}")
    if (
        receipt["image_reference"] != PINNED_EVIDENCE_IMAGE
        or receipt["image_digest"] != PINNED_EVIDENCE_IMAGE_DIGEST
        or receipt["image_id"] != PINNED_EVIDENCE_IMAGE_ID
    ):
        raise StagingError("bundle image identity drift")
    return copy.deepcopy(receipt)


def validate_installation_receipt(value: Any) -> dict[str, Any]:
    receipt = _exact_dict(
        value, INSTALLATION_RECEIPT_FIELDS, "installation receipt"
    )
    if receipt["schema"] != INSTALLATION_RECEIPT_SCHEMA:
        raise StagingError("installation receipt schema drift")
    _valid_git_sha1(receipt["bundle_revision"], "installation bundle revision")
    for field in (
        "bundle_receipt_sha256", "bundle_inventory_sha256",
        "installed_inventory_sha256",
    ):
        _valid_sha256(receipt[field], f"installation {field}")
    if receipt["bundle_inventory_sha256"] != receipt[
        "installed_inventory_sha256"
    ]:
        raise StagingError("installed inventory differs from the sealed bundle")
    if receipt["authority_root"] != AUTHORITY_ROOT.as_posix():
        raise StagingError("installed authority root drift")
    if receipt["operator_root"] != OPERATOR_ROOT.as_posix():
        raise StagingError("installed operator root drift")
    if receipt["config_path"] != CONFIG_PATH.as_posix():
        raise StagingError("installed config path drift")
    if receipt["unit_path"] != UNIT_PATH.as_posix():
        raise StagingError("installed unit path drift")
    image = _exact_dict(
        receipt["image"],
        frozenset({"reference", "digest", "id", "archive_sha256"}),
        "installation image",
    )
    if (
        image["reference"] != PINNED_EVIDENCE_IMAGE
        or image["digest"] != PINNED_EVIDENCE_IMAGE_DIGEST
        or image["id"] != PINNED_EVIDENCE_IMAGE_ID
    ):
        raise StagingError("installed image identity drift")
    _valid_sha256(image["archive_sha256"], "installation image archive")
    return copy.deepcopy(receipt)


def _sha256_regular(path: Path, maximum: int = MAX_FILE_BYTES) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise StagingError(f"cannot inspect regular file {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise StagingError(f"inadmissible regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
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
                raise StagingError(f"regular file changed while opening: {path}")
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except StagingError:
        raise
    except OSError as error:
        raise StagingError(f"cannot read regular file {path}: {error}") from error
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
    ):
        raise StagingError(f"regular file changed while reading: {path}")
    return digest.hexdigest()


def _inventory_mode(metadata: os.stat_result) -> str:
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def collect_inventory(root: Path) -> list[dict[str, Any]]:
    """Collect an exact lexical inventory without following any link."""

    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise StagingError(f"cannot inspect inventory root {root}: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise StagingError("inventory root is not a real directory")
    entries: list[dict[str, Any]] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise StagingError(f"cannot enumerate inventory: {error}") from error
        child_directories: list[Path] = []
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            if not relative or ".." in PurePosixPath(relative).parts:
                raise StagingError("inventory path is not canonical relative")
            try:
                metadata = path.lstat()
            except OSError as error:
                raise StagingError(f"cannot inspect inventory path: {error}") from error
            if stat.S_ISDIR(metadata.st_mode):
                entries.append({
                    "path": relative,
                    "type": "directory",
                    "mode": _inventory_mode(metadata),
                })
                child_directories.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise StagingError(f"inventory file has a hard link: {relative}")
                entries.append({
                    "path": relative,
                    "type": "file",
                    "mode": _inventory_mode(metadata),
                    "size": metadata.st_size,
                    "sha256": _sha256_regular(path),
                })
            else:
                raise StagingError(f"inventory contains a special or linked node: {relative}")
            if len(entries) > MAX_INVENTORY_ENTRIES:
                raise StagingError("inventory entry count exceeds its fixed limit")
        stack.extend(reversed(child_directories))
    return sorted(entries, key=lambda item: item["path"])


def _validate_inventory_document(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_INVENTORY_ENTRIES:
        raise StagingError("inventory is malformed")
    previous = ""
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise StagingError("inventory entry is malformed")
        item_type = item.get("type")
        fields = (
            DIRECTORY_INVENTORY_FIELDS
            if item_type == "directory" else FILE_INVENTORY_FIELDS
        )
        entry = _exact_dict(item, fields, "inventory entry")
        path = entry["path"]
        if (
            not isinstance(path, str)
            or not path
            or path <= previous
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or PurePosixPath(path).as_posix() != path
        ):
            raise StagingError("inventory path ordering or spelling is malformed")
        previous = path
        mode = entry["mode"]
        if not isinstance(mode, str) or re.fullmatch(r"[0-7]{4}", mode) is None:
            raise StagingError("inventory mode is malformed")
        if item_type == "file":
            if (
                isinstance(entry["size"], bool)
                or not isinstance(entry["size"], int)
                or entry["size"] < 0
                or entry["size"] > MAX_FILE_BYTES
            ):
                raise StagingError("inventory file size is malformed")
            _valid_sha256(entry["sha256"], "inventory file checksum")
        result.append(copy.deepcopy(entry))
    return result


def verify_inventory(root: Path, inventory: Any) -> None:
    expected = _validate_inventory_document(inventory)
    if collect_inventory(root) != expected:
        raise StagingError("filesystem differs from its sealed inventory")


def _owned_process_group_members(
    process_group: int, session_id: int,
) -> list[int]:
    """Return live Linux processes still in our exact new session/group."""

    members: list[int] = []
    try:
        proc_entries = list(Path("/proc").iterdir())
    except OSError as error:
        raise StagingError(
            f"cannot inspect bounded command process group: {error}"
        ) from error
    for entry in proc_entries:
        if not entry.name.isdecimal():
            continue
        try:
            data = (entry / "stat").read_text(
                encoding="ascii", errors="strict"
            )
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, UnicodeDecodeError) as error:
            raise StagingError(
                f"cannot inspect bounded command process identity: {error}"
            ) from error
        closing = data.rfind(")")
        if closing < 0:
            raise StagingError("bounded command process identity is malformed")
        fields = data[closing + 2:].split()
        if len(fields) < 4:
            raise StagingError("bounded command process identity is malformed")
        try:
            pid = int(entry.name)
            pgrp = int(fields[2])
            session = int(fields[3])
        except ValueError as error:
            raise StagingError(
                "bounded command process identity is malformed"
            ) from error
        state = fields[0]
        if (
            pgrp == process_group
            and session == session_id
            and state != "Z"
        ):
            members.append(pid)
    return sorted(members)


def _bounded_command(
    argv: list[str],
    *,
    environment: dict[str, str],
    cwd: Path | None,
    maximum_output: int,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    """Capture one process group with one shared hard output and wall bound."""

    if (
        isinstance(maximum_output, bool)
        or not isinstance(maximum_output, int)
        or maximum_output < 0
        or maximum_output > MAX_DOCUMENT_BYTES
    ):
        raise StagingError("external command output bound is malformed")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
        or timeout_seconds > IMAGE_LOAD_TIMEOUT_SECONDS
    ):
        raise StagingError("external command timeout is malformed")
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout_seconds

    def terminate_group() -> None:
        if process is None:
            return
        # Cleanup begins after the command deadline on the timeout path, so it
        # needs its own grace period.  Reusing the already-expired execution
        # deadline can observe a just-signalled task for one scheduler tick and
        # falsely report that SIGKILL failed before the kernel can reap it.
        kill_deadline = time.monotonic() + 5
        while True:
            members = _owned_process_group_members(
                process.pid, process.pid
            )
            if not members:
                return
            for pid in members:
                pidfd: int | None = None
                try:
                    pidfd = os.pidfd_open(pid, 0)
                    # Revalidate after pinning the PID identity. A recycled
                    # PID outside the owned session is never signalled.
                    if pid not in _owned_process_group_members(
                        process.pid, process.pid
                    ):
                        continue
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except (ProcessLookupError, FileNotFoundError):
                    continue
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        raise StagingError(
                            f"cannot terminate bounded command: {error}"
                        ) from error
                finally:
                    if pidfd is not None:
                        os.close(pidfd)
            if time.monotonic() >= kill_deadline:
                remaining = _owned_process_group_members(
                    process.pid, process.pid
                )
                if remaining:
                    raise StagingError(
                        "bounded command process group could not be terminated"
                    )
                return
            try:
                time.sleep(0.01)
            except InterruptedError:
                continue

    def require_group_empty() -> None:
        if process is None:
            return
        while _owned_process_group_members(process.pid, process.pid):
            if time.monotonic() >= deadline:
                terminate_group()
                raise StagingError(
                    f"staging command timed out: {argv[0]}"
                )
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))

    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
    except OSError as error:
        raise StagingError(
            f"cannot execute staging command {argv[0]}: {error}"
        ) from error
    assert process.stdout is not None and process.stderr is not None
    streams = ((process.stdout, stdout), (process.stderr, stderr))
    try:
        for stream, destination in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_group()
                raise StagingError(f"staging command timed out: {argv[0]}")
            events = selector.select(min(remaining, 1.0))
            if not events and process.poll() is not None:
                # A descendant can retain either pipe after the leader exits.
                continue
            for key, _mask in events:
                stream = key.fileobj
                destination = key.data
                try:
                    block = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(stream)
                    continue
                destination.extend(block)
                if len(stdout) + len(stderr) > maximum_output:
                    terminate_group()
                    raise StagingError(
                        f"staging command output is oversized: {argv[0]}"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            terminate_group()
            raise StagingError(f"staging command timed out: {argv[0]}")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            terminate_group()
            raise StagingError(
                f"staging command timed out: {argv[0]}"
            ) from error
        require_group_empty()
    finally:
        selector.close()
        if _owned_process_group_members(process.pid, process.pid):
            terminate_group()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            terminate_group()
            process.wait()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        copy.deepcopy(argv), return_code, bytes(stdout), bytes(stderr)
    )


def _git(source: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": os.fspath(source.resolve()),
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": os.devnull,
        "GIT_CONFIG_KEY_2": "core.fsmonitor",
        "GIT_CONFIG_VALUE_2": "false",
        "GIT_CONFIG_KEY_3": "core.commitGraph",
        "GIT_CONFIG_VALUE_3": "false",
        "HOME": os.fspath(source),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin",
    }
    return _bounded_command(
        ["/usr/bin/git", "--no-replace-objects", "-C", os.fspath(source),
         *arguments],
        environment=environment,
        cwd=None,
        maximum_output=MAX_DOCUMENT_BYTES,
        timeout_seconds=300,
    )


def _git_text(source: Path, *arguments: str) -> str:
    completed = _git(source, *arguments)
    if completed.returncode != 0:
        raise StagingError(
            "Git source check failed: "
            + completed.stderr.decode("utf-8", errors="replace")[-1000:].strip()
        )
    try:
        return completed.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise StagingError("Git source output is not ASCII") from error


def _validate_tracked_source_files(source: Path) -> None:
    completed = _git(source, "ls-files", "-z", "--cached")
    if completed.returncode != 0 or not completed.stdout.endswith(b"\0"):
        raise StagingError("cannot enumerate tracked source files")
    paths = completed.stdout[:-1].split(b"\0")
    for encoded in paths:
        try:
            relative = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise StagingError("tracked source path is not UTF-8") from error
        path = source / relative
        _sha256_regular(path)


def _reject_python_bytecode(source: Path) -> None:
    """Reject every lexical Python bytecode/cache node in staged authority."""

    stack = [source]
    seen = 0
    while stack:
        directory = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise StagingError(
                f"cannot inspect staged source for Python bytecode: {error}"
            ) from error
        descendants: list[Path] = []
        for child in children:
            seen += 1
            if seen > MAX_INVENTORY_ENTRIES:
                raise StagingError(
                    "staged source bytecode scan exceeds its fixed entry limit"
                )
            path = Path(child.path)
            if child.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}:
                raise StagingError(
                    f"staged source contains forbidden Python bytecode: "
                    f"{path.relative_to(source).as_posix()}"
                )
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise StagingError(
                    f"cannot inspect staged source bytecode path: {error}"
                ) from error
            if stat.S_ISDIR(metadata.st_mode):
                descendants.append(path)
        stack.extend(reversed(descendants))


def _runtime_source_manifest(source: Path) -> str:
    """Reproduce the determinism source-manifest scope without importing it."""

    entries: list[dict[str, str]] = []
    for relative in RUNTIME_SOURCE_FILES:
        path = source / relative
        entries.append({"path": relative, "sha256": _sha256_regular(path)})
    for root_relative in RUNTIME_SOURCE_DIRECTORIES:
        root = source / root_relative
        try:
            root_metadata = root.lstat()
        except OSError as error:
            raise StagingError(
                f"runtime source root is unavailable: {root_relative}: {error}"
            ) from error
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise StagingError(
                f"runtime source root is not a directory: {root_relative}"
            )
        stack = [root]
        while stack:
            directory = stack.pop()
            try:
                children = sorted(
                    os.scandir(directory), key=lambda item: item.name
                )
            except OSError as error:
                raise StagingError(
                    f"cannot enumerate runtime source: {error}"
                ) from error
            descendants: list[Path] = []
            for child in children:
                path = Path(child.path)
                relative_path = path.relative_to(source)
                relative = relative_path.as_posix()
                if (
                    "__pycache__" in relative_path.parts
                    or path.suffix in {".pyc", ".pyo"}
                    or any(
                        relative.startswith(prefix)
                        for prefix in RUNTIME_SOURCE_IGNORED_PREFIXES
                    )
                ):
                    continue
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    descendants.append(path)
                elif stat.S_ISREG(metadata.st_mode):
                    entries.append({
                        "path": relative,
                        "sha256": _sha256_regular(path),
                    })
                else:
                    raise StagingError(
                        f"runtime source path is not regular: {relative}"
                    )
            stack.extend(reversed(descendants))
    entries.sort(key=lambda item: item["path"])
    return hashlib.sha256(canonical_document(entries)).hexdigest()


def _source_file_manifest(source: Path) -> str:
    _validate_tracked_source_files(source)
    return _runtime_source_manifest(source)


def validate_staged_source(source: Path, revision: str) -> dict[str, str]:
    revision = _valid_git_sha1(revision, "staged source revision")
    try:
        source_metadata = source.lstat()
        dot_git = (source / ".git").lstat()
    except OSError as error:
        raise StagingError(f"staged source is unavailable: {error}") from error
    if not stat.S_ISDIR(source_metadata.st_mode) or not stat.S_ISDIR(dot_git.st_mode):
        raise StagingError("staged source is not a standalone Git repository")
    _reject_python_bytecode(source)
    git_dir = Path(_git_text(source, "rev-parse", "--absolute-git-dir"))
    common_dir = Path(_git_text(source, "rev-parse", "--git-common-dir"))
    if not common_dir.is_absolute():
        common_dir = source / common_dir
    expected_git = (source / ".git").resolve()
    if git_dir.resolve() != expected_git or common_dir.resolve() != expected_git:
        raise StagingError("staged source is not a standalone repository")
    head = _git_text(source, "rev-parse", "HEAD")
    if head != revision:
        raise StagingError("staged source differs from exact HEAD")
    symbolic = _git(source, "symbolic-ref", "-q", "HEAD")
    if symbolic.returncode == 0 or symbolic.returncode not in {0, 1}:
        raise StagingError("staged source HEAD is not detached")
    status_result = _git(
        source, "status", "--porcelain=v2", "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status_result.returncode != 0 or status_result.stdout:
        raise StagingError("staged source is not clean")
    for path, label in (
        (source / ".git" / "shallow", "shallow boundary"),
        (source / ".git" / "info" / "grafts", "grafts"),
        (source / ".git" / "objects" / "info" / "alternates", "alternates"),
    ):
        if path.exists() or path.is_symlink():
            raise StagingError(f"staged source contains {label}")
    replace = _git_text(source, "for-each-ref", "--format=%(refname)", "refs/replace")
    if replace:
        raise StagingError("staged source contains replacement refs")
    tree = _git_text(source, "rev-parse", "HEAD^{tree}")
    _valid_git_sha1(tree, "staged source tree")
    return {
        "revision": revision,
        "tree_sha1": tree,
        "manifest_sha256": _source_file_manifest(source),
    }


def verify_static_unit(path: Path) -> None:
    try:
        metadata = path.lstat()
        data = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as error:
        raise StagingError(f"cannot read static service unit: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise StagingError("service unit is not a standalone regular file")
    lines = [line.strip() for line in data.splitlines()]
    sections = [
        line.casefold()
        for line in lines
        if line.strip().startswith("[") and line.strip().endswith("]")
    ]
    if sections != ["[unit]", "[service]"]:
        raise StagingError("service unit is not static")
    for required in STABILITY_UNIT_REQUIRED_LINES:
        if lines.count(required) != 1:
            raise StagingError("service unit lifecycle contract drift")
    singleton_prefixes = (
        "Before=", "Conflicts=", "IgnoreOnIsolate=", "ExecStartPre=", "ExecStart=",
        "ExecStopPost=", "Type=", "KillMode=", "TimeoutStopSec=",
        "Delegate=", "DelegateSubgroup=", "StateDirectory=",
        "ProtectControlGroups=",
    )
    for prefix in singleton_prefixes:
        if sum(line.startswith(prefix) for line in lines) != 1:
            raise StagingError("service unit lifecycle authority is ambiguous")
    if any(
        line.startswith(("ConditionKernelCommandLine=", "WantedBy=", "RequiredBy="))
        for line in lines
    ):
        raise StagingError("service unit contains a forbidden lifecycle authority")


def reject_dropin_authority(unit_root: Path, unit_name: str) -> None:
    if unit_name != UNIT_NAME:
        raise StagingError("service unit identity drift")
    dropin = unit_root / f"{unit_name}.d"
    try:
        dropin.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise StagingError(f"cannot inspect service drop-in authority: {error}") from error
    raise StagingError("service drop-in authority is forbidden")


def _rename_noreplace_at(
    source_directory: int,
    source: str,
    destination_directory: int,
    destination: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            source_directory,
            os.fsencode(source),
            destination_directory,
            os.fsencode(destination),
            1,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number != errno.ENOSYS:
            raise OSError(error_number, os.strerror(error_number), destination)
    raise OSError(
        errno.ENOSYS,
        "atomic no-replace publication is unavailable",
        destination,
    )


def _rename_noreplace(source: Path, destination: Path) -> None:
    _rename_noreplace_at(
        -100, os.fspath(source), -100, os.fspath(destination)
    )


def _make_tree_removable_at(parent_descriptor: int, name: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) | 0o700)
        for child in os.listdir(descriptor):
            child_metadata = os.stat(
                child, dir_fd=descriptor, follow_symlinks=False
            )
            if stat.S_ISDIR(child_metadata.st_mode):
                _make_tree_removable_at(descriptor, child)
    finally:
        os.close(descriptor)


def _require_published_identity(
    path: Path,
    device: int,
    inode: int,
    is_directory: bool,
    label: str,
) -> None:
    metadata = path.lstat()
    expected_type = (
        stat.S_ISDIR(metadata.st_mode)
        if is_directory
        else stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    )
    if (
        not expected_type
        or metadata.st_dev != device
        or metadata.st_ino != inode
    ):
        raise StagingError(f"{label} identity changed")


def _open_identity_pin(
    path: Path,
    device: int,
    inode: int,
    is_directory: bool,
    label: str,
) -> int:
    """Pin one inode so unlink/recreate cannot reuse its identity mid-commit."""

    flags = getattr(os, "O_PATH", os.O_RDONLY)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if is_directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise StagingError(f"cannot pin {label}: {error}") from error
    expected_type = (
        stat.S_ISDIR(metadata.st_mode)
        if is_directory
        else stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    )
    if (
        not expected_type
        or metadata.st_dev != device
        or metadata.st_ino != inode
    ):
        os.close(descriptor)
        raise StagingError(f"{label} identity changed while pinning")
    return descriptor


class _CreatedNode:
    """A rollback record that keeps its original filesystem object pinned."""

    __slots__ = ("path", "device", "inode", "is_directory", "descriptor")

    def __init__(
        self,
        path: Path,
        device: int,
        inode: int,
        is_directory: bool,
        descriptor: int,
    ) -> None:
        self.path = path
        self.device = device
        self.inode = inode
        self.is_directory = is_directory
        self.descriptor = descriptor

    def __iter__(self):
        yield self.path
        yield self.device
        yield self.inode
        yield self.is_directory

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)


def _remove_created_identity(
    path: Path, device: int, inode: int, is_directory: bool,
) -> None:
    """Atomically quarantine and remove only this invocation's exact node."""

    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    parent_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    owned_descriptor: int | None = None
    quarantine_name: str | None = None
    rename_completed = False
    deletion_started = False
    try:
        parent_descriptor = os.open(path.parent, parent_flags)
        owned_flags = getattr(os, "O_PATH", os.O_RDONLY)
        owned_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        owned_descriptor = os.open(
            path.name, owned_flags, dir_fd=parent_descriptor
        )
        pinned = os.fstat(owned_descriptor)
        expected_type = (
            stat.S_ISDIR(pinned.st_mode)
            if is_directory
            else stat.S_ISREG(pinned.st_mode) and pinned.st_nlink == 1
        )
        if (
            not expected_type
            or pinned.st_dev != device
            or pinned.st_ino != inode
        ):
            raise StagingError(f"created path identity changed: {path}")

        for _attempt in range(128):
            candidate = f".codeskeptic-cleanup-{secrets.token_hex(16)}"
            quarantine_name = candidate
            try:
                _rename_noreplace_at(
                    parent_descriptor,
                    path.name,
                    parent_descriptor,
                    candidate,
                )
            except FileExistsError:
                quarantine_name = None
                continue
            rename_completed = True
            break
        if quarantine_name is None:
            raise StagingError("cleanup quarantine name budget exhausted")
        os.fsync(parent_descriptor)

        metadata = os.stat(
            quarantine_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        pinned = os.fstat(owned_descriptor)
        expected_type = (
            stat.S_ISDIR(metadata.st_mode)
            if is_directory
            else stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        )
        if (
            not expected_type
            or metadata.st_dev != device
            or metadata.st_ino != inode
            or metadata.st_dev != pinned.st_dev
            or metadata.st_ino != pinned.st_ino
        ):
            _rename_noreplace_at(
                parent_descriptor,
                quarantine_name,
                parent_descriptor,
                path.name,
            )
            quarantine_name = None
            rename_completed = False
            os.fsync(parent_descriptor)
            raise StagingError(f"created path identity changed: {path}")

        if is_directory:
            deletion_started = True
            _make_tree_removable_at(parent_descriptor, quarantine_name)
            shutil.rmtree(quarantine_name, dir_fd=parent_descriptor)
        else:
            deletion_started = True
            os.unlink(quarantine_name, dir_fd=parent_descriptor)
        quarantine_name = None
        rename_completed = False
        os.fsync(parent_descriptor)
    except BaseException as error:
        cleanup_errors: list[BaseException] = []
        if (
            not deletion_started
            and parent_descriptor is not None
            and quarantine_name is not None
        ):
            try:
                quarantined = os.stat(
                    quarantine_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                quarantined = None
            except BaseException as restore_error:
                cleanup_errors.append(restore_error)
                quarantined = None
            if quarantined is not None:
                quarantine_is_owned = (
                    quarantined.st_dev == device
                    and quarantined.st_ino == inode
                )
                try:
                    os.stat(
                        path.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    original_missing = False
                except FileNotFoundError:
                    original_missing = True
                except BaseException as restore_error:
                    original_missing = False
                    cleanup_errors.append(restore_error)
                if quarantine_is_owned or original_missing:
                    try:
                        _rename_noreplace_at(
                            parent_descriptor,
                            quarantine_name,
                            parent_descriptor,
                            path.name,
                        )
                        os.fsync(parent_descriptor)
                        quarantine_name = None
                        rename_completed = False
                    except BaseException as restore_error:
                        cleanup_errors.append(restore_error)
                elif rename_completed:
                    cleanup_errors.append(StagingError(
                        "quarantined replacement could not be restored without "
                        f"overwriting {path}"
                    ))
        elif deletion_started and parent_descriptor is not None:
            quarantined = None
            if quarantine_name is not None:
                try:
                    quarantined = os.stat(
                        quarantine_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    quarantine_name = None
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if quarantined is not None:
                exact_quarantine = (
                    quarantined.st_dev == device
                    and quarantined.st_ino == inode
                    and (
                        stat.S_ISDIR(quarantined.st_mode)
                        if is_directory
                        else stat.S_ISREG(quarantined.st_mode)
                        and quarantined.st_nlink == 1
                    )
                )
                if not exact_quarantine:
                    cleanup_errors.append(StagingError(
                        "quarantined created path identity changed"
                    ))
                else:
                    try:
                        if is_directory:
                            _make_tree_removable_at(
                                parent_descriptor, quarantine_name
                            )
                            shutil.rmtree(
                                quarantine_name,
                                dir_fd=parent_descriptor,
                            )
                        else:
                            os.unlink(
                                quarantine_name,
                                dir_fd=parent_descriptor,
                            )
                        quarantine_name = None
                        rename_completed = False
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
            try:
                os.fsync(parent_descriptor)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            retained = (
                os.fspath(path.parent / quarantine_name)
                if quarantine_name is not None
                else "none; parent durability sync failed"
            )
            raise StagingError(
                "created path cleanup failed; retained quarantine: "
                f"{retained}; primary failure: {error}; "
                f"cleanup failure: {cleanup_errors[0]}"
            ) from error
        if isinstance(error, OSError):
            raise StagingError(
                f"cannot remove created path {path}: {error}"
            ) from error
        raise
    finally:
        if owned_descriptor is not None:
            os.close(owned_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _publish_tree_noreplace(source: Path, destination: Path) -> None:
    """Publish and parent-fsync one tree, self-cleaning any partial commit."""

    metadata = source.lstat()
    descriptor = _open_identity_pin(
        source,
        metadata.st_dev,
        metadata.st_ino,
        True,
        "tree publication source",
    )
    try:
        try:
            _rename_noreplace(source, destination)
            _fsync_directory(destination.parent)
            _require_published_identity(
                destination,
                metadata.st_dev,
                metadata.st_ino,
                True,
                "published tree",
            )
        except BaseException as error:
            try:
                remaining_source = source.lstat()
            except FileNotFoundError:
                remaining_source = None
            if remaining_source is not None:
                if (
                    remaining_source.st_dev == metadata.st_dev
                    and remaining_source.st_ino == metadata.st_ino
                ):
                    raise
                try:
                    _remove_created_identity(
                        destination,
                        metadata.st_dev,
                        metadata.st_ino,
                        True,
                    )
                except Exception as cleanup_error:
                    raise StagingError(
                        "tree publication source identity changed and "
                        f"published-tree cleanup failed: {cleanup_error}"
                    ) from error
                raise StagingError(
                    "tree publication source identity changed"
                ) from error
            try:
                _remove_created_identity(
                    destination, metadata.st_dev, metadata.st_ino, True
                )
            except Exception as cleanup_error:
                raise StagingError(
                    "tree publication failed and cleanup failed: "
                    f"{error}; {cleanup_error}"
                ) from error
            raise
    finally:
        os.close(descriptor)


def _create_directory_create_new(
    path: Path,
    mode: int,
    owner_uid: int,
    owner_gid: int,
    *,
    created_nodes: list[_CreatedNode] | None = None,
) -> None:
    """Prepare ownership off-path, then publish and immediately register."""

    temporary, temporary_metadata, temporary_descriptor = (
        _create_private_temporary_directory(
            path.parent,
            f".{path.name}.directory-",
            "private directory staging tree creation failed",
        )
    )
    published_identity: tuple[int, int] | None = None
    record: _CreatedNode | None = None
    primary: BaseException | None = None
    collision = False
    try:
        os.chmod(temporary, mode)
        os.chown(temporary, owner_uid, owner_gid)
        _fsync_directory(temporary)
        metadata = temporary.lstat()
        if (
            metadata.st_dev != temporary_metadata.st_dev
            or metadata.st_ino != temporary_metadata.st_ino
        ):
            raise StagingError("private directory staging identity changed")
        published_identity = (metadata.st_dev, metadata.st_ino)
        record = _CreatedNode(
            path,
            metadata.st_dev,
            metadata.st_ino,
            True,
            temporary_descriptor,
        )
        temporary_descriptor = None
        _rename_noreplace(temporary, path)
        if created_nodes is not None:
            created_nodes.append(record)
        _fsync_directory(path.parent)
        _require_published_identity(
            path,
            published_identity[0],
            published_identity[1],
            True,
            "published private directory",
        )
    except BaseException as error:
        if isinstance(error, FileExistsError):
            primary = StagingError(f"directory appeared concurrently: {path}")
            collision = True
        elif isinstance(error, OSError):
            primary = StagingError(
                f"cannot create private directory {path}: {error}"
            )
        else:
            primary = error
    registered = (
        record is not None
        and created_nodes is not None
        and record in created_nodes
    )
    if primary is None:
        if record is not None and not registered:
            record.close()
        return
    cleanup_errors: list[Exception] = []
    if published_identity is not None and not registered:
        try:
            try:
                published_metadata = path.lstat()
            except FileNotFoundError:
                published_metadata = None
            if not collision and published_metadata is not None and (
                published_metadata.st_dev,
                published_metadata.st_ino,
            ) == published_identity:
                _remove_created_identity(
                    path,
                    published_identity[0],
                    published_identity[1],
                    True,
                )
            elif published_metadata is not None and not collision:
                raise StagingError("published private directory identity changed")
        except Exception as cleanup_error:
            cleanup_errors.append(cleanup_error)
    try:
        try:
            remaining_temporary = temporary.lstat()
        except FileNotFoundError:
            remaining_temporary = None
        if remaining_temporary is not None:
            _remove_created_identity(
                temporary,
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
                True,
            )
    except Exception as cleanup_error:
        cleanup_errors.append(cleanup_error)
    if record is not None and not registered:
        try:
            record.close()
        except OSError as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if temporary_descriptor is not None:
        try:
            os.close(temporary_descriptor)
        except OSError as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if cleanup_errors:
        _raise_primary_and_cleanup(
            primary, cleanup_errors, "directory publication failed"
        )
    raise primary


def _regular_file_create_new(
    destination: Path,
    mode: int,
    owner_uid: int | None,
    owner_gid: int | None,
    write_payload: Any,
    *,
    created_nodes: list[_CreatedNode] | None = None,
    label: str,
) -> None:
    """Build a regular file privately, then publish and register its inode."""

    if (owner_uid is None) != (owner_gid is None):
        raise StagingError("staging file ownership is incomplete")
    temporary, temporary_metadata, temporary_descriptor = (
        _create_private_temporary_directory(
            destination.parent,
            ".codeskeptic-file-",
            f"{label} private file staging creation failed",
        )
    )
    staged = temporary / "payload"
    staged_identity: tuple[int, int] | None = None
    published_identity: tuple[int, int] | None = None
    record: _CreatedNode | None = None
    descriptor: int | None = None
    primary: BaseException | None = None
    cleanup_errors: list[Exception] = []
    collision = False
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(staged, flags, 0o600)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise StagingError(f"{label} private file authority drift")
        staged_identity = (opened.st_dev, opened.st_ino)
        write_payload(descriptor)
        os.fchmod(descriptor, mode)
        if owner_uid is not None and owner_gid is not None:
            os.fchown(descriptor, owner_uid, owner_gid)
        os.fsync(descriptor)
        staged_metadata = staged.lstat()
        if (
            not stat.S_ISREG(staged_metadata.st_mode)
            or staged_metadata.st_nlink != 1
            or (staged_metadata.st_dev, staged_metadata.st_ino)
            != staged_identity
        ):
            raise StagingError(f"{label} private file identity changed")
        published_identity = staged_identity
        record = _CreatedNode(
            destination,
            published_identity[0],
            published_identity[1],
            False,
            descriptor,
        )
        descriptor = None
        _rename_noreplace(staged, destination)
        if created_nodes is not None:
            created_nodes.append(record)
        _fsync_directory(destination.parent)
        _require_published_identity(
            destination,
            published_identity[0],
            published_identity[1],
            False,
            "published file",
        )
    except BaseException as error:
        if isinstance(error, FileExistsError):
            primary = StagingError(f"file appeared concurrently: {destination}")
            collision = True
        elif isinstance(error, OSError):
            primary = StagingError(f"{label}: {error}")
        else:
            primary = error
    registered = (
        record is not None
        and created_nodes is not None
        and record in created_nodes
    )
    if staged_identity is not None:
        try:
            try:
                remaining_staged = staged.lstat()
            except FileNotFoundError:
                remaining_staged = None
            if remaining_staged is not None:
                _remove_created_identity(
                    staged,
                    staged_identity[0],
                    staged_identity[1],
                    False,
                )
        except Exception as cleanup_error:
            cleanup_errors.append(cleanup_error)
    try:
        try:
            remaining_temporary = temporary.lstat()
        except FileNotFoundError:
            remaining_temporary = None
        if remaining_temporary is not None:
            _remove_created_identity(
                temporary,
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
                True,
            )
    except Exception as cleanup_error:
        cleanup_errors.append(cleanup_error)
    try:
        os.close(temporary_descriptor)
    except OSError as cleanup_error:
        cleanup_errors.append(cleanup_error)
    if (
        (primary is not None or cleanup_errors)
        and published_identity is not None
        and not registered
    ):
        try:
            try:
                published_metadata = destination.lstat()
            except FileNotFoundError:
                published_metadata = None
            if not collision and published_metadata is not None and (
                published_metadata.st_dev,
                published_metadata.st_ino,
            ) == published_identity:
                _remove_created_identity(
                    destination,
                    published_identity[0],
                    published_identity[1],
                    False,
                )
            elif published_metadata is not None and not collision:
                raise StagingError("published file identity changed")
        except Exception as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if record is not None and not registered:
        try:
            record.close()
        except OSError as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if descriptor is not None:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            cleanup_errors.append(StagingError(
                "private file descriptor cleanup failed: "
                f"{cleanup_error}"
            ))
    _raise_primary_and_cleanup(primary, cleanup_errors, label)


def _copy_regular_create_new(
    source: Path, destination: Path, mode: int, owner_uid: int, owner_gid: int,
    *,
    created_nodes: list[_CreatedNode] | None = None,
) -> None:
    try:
        source_metadata = source.lstat()
    except OSError as error:
        raise StagingError(f"cannot inspect installation source: {error}") from error
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or source_metadata.st_size > MAX_FILE_BYTES
    ):
        raise StagingError("installation source is not an admissible regular file")
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    source_flags |= getattr(os, "O_NOFOLLOW", 0)

    def copy_payload(destination_descriptor: int) -> None:
        source_descriptor = os.open(source, source_flags)
        try:
            opened_source = os.fstat(source_descriptor)
            if (
                not stat.S_ISREG(opened_source.st_mode)
                or opened_source.st_dev != source_metadata.st_dev
                or opened_source.st_ino != source_metadata.st_ino
                or opened_source.st_size != source_metadata.st_size
            ):
                raise StagingError("installation source changed while opening")
            while True:
                block = os.read(source_descriptor, 1024 * 1024)
                if not block:
                    break
                offset = 0
                while offset < len(block):
                    written = os.write(destination_descriptor, block[offset:])
                    if written <= 0:
                        raise OSError("short installation write")
                    offset += written
            after_source = os.fstat(source_descriptor)
            if (
                after_source.st_dev != source_metadata.st_dev
                or after_source.st_ino != source_metadata.st_ino
                or after_source.st_size != source_metadata.st_size
            ):
                raise StagingError("installation source changed while copying")
        finally:
            os.close(source_descriptor)

    _regular_file_create_new(
        destination,
        mode,
        owner_uid,
        owner_gid,
        copy_payload,
        created_nodes=created_nodes,
        label="installation copy failed",
    )


def _verify_installed_ownership(
    root: Path, inventory: list[dict[str, Any]], owner_uid: int, owner_gid: int,
) -> None:
    for relative in ["", *[item["path"] for item in inventory]]:
        path = root if not relative else root / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise StagingError(f"cannot inspect installed ownership: {error}") from error
        if metadata.st_uid != owner_uid or metadata.st_gid != owner_gid:
            raise StagingError("installed ownership drift")


def install_tree_create_new(
    source: Path,
    destination: Path,
    inventory: Any,
    *,
    owner_uid: int = 0,
    owner_gid: int = 0,
    created_nodes: list[_CreatedNode] | None = None,
) -> str:
    expected = _validate_inventory_document(inventory)
    verify_inventory(source, expected)
    if destination.exists() or destination.is_symlink():
        try:
            verify_inventory(destination, expected)
            if stat.S_IMODE(destination.lstat().st_mode) != stat.S_IMODE(
                source.lstat().st_mode
            ):
                raise StagingError("installed root mode drift")
            _verify_installed_ownership(
                destination, expected, owner_uid, owner_gid
            )
        except StagingError as error:
            raise StagingError(
                "pre-existing installation differs and will not be overwritten"
            ) from error
        return "reused"
    try:
        parent_metadata = destination.parent.lstat()
    except OSError as error:
        raise StagingError(
            f"installation destination parent is unavailable: {error}"
        ) from error
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise StagingError("installation destination parent is not a directory")
    temporary, staging_metadata, staging_descriptor = (
        _create_private_temporary_directory(
            destination.parent,
            f".{destination.name}.install-",
            "installation tree staging creation failed",
        )
    )
    published_identity: tuple[int, int] | None = None
    record: _CreatedNode | None = None
    primary: BaseException | None = None
    collision = False
    try:
        os.chown(temporary, owner_uid, owner_gid)
        directories = [item for item in expected if item["type"] == "directory"]
        files = [item for item in expected if item["type"] == "file"]
        for item in directories:
            path = temporary / item["path"]
            path.mkdir(mode=0o700)
            os.chown(path, owner_uid, owner_gid)
        for item in files:
            _copy_regular_create_new(
                source / item["path"], temporary / item["path"],
                int(item["mode"], 8), owner_uid, owner_gid,
            )
        for item in reversed(directories):
            os.chmod(temporary / item["path"], int(item["mode"], 8))
        os.chmod(temporary, stat.S_IMODE(source.lstat().st_mode))
        verify_inventory(temporary, expected)
        _verify_installed_ownership(temporary, expected, owner_uid, owner_gid)
        _fsync_tree(temporary)
        temporary_metadata = temporary.lstat()
        if (
            temporary_metadata.st_dev != staging_metadata.st_dev
            or temporary_metadata.st_ino != staging_metadata.st_ino
        ):
            raise StagingError("installation staging tree identity changed")
        published_identity = (
            temporary_metadata.st_dev, temporary_metadata.st_ino
        )
        record = _CreatedNode(
            destination,
            temporary_metadata.st_dev,
            temporary_metadata.st_ino,
            True,
            staging_descriptor,
        )
        staging_descriptor = None
        _rename_noreplace(temporary, destination)
        if created_nodes is not None:
            created_nodes.append(record)
        _fsync_directory(destination.parent)
        _require_published_identity(
            destination,
            published_identity[0],
            published_identity[1],
            True,
            "published installation tree",
        )
    except BaseException as error:
        if isinstance(error, FileExistsError):
            primary = StagingError(
                "installation destination appeared concurrently"
            )
            collision = True
        elif isinstance(error, OSError):
            primary = StagingError(f"cannot create installation tree: {error}")
        else:
            primary = error
    registered = (
        record is not None
        and created_nodes is not None
        and record in created_nodes
    )
    if primary is None:
        if record is not None and not registered:
            record.close()
        return "created"
    cleanup_errors: list[Exception] = []
    if published_identity is not None and not registered:
        try:
            try:
                published_metadata = destination.lstat()
            except FileNotFoundError:
                published_metadata = None
            if not collision and published_metadata is not None and (
                published_metadata.st_dev,
                published_metadata.st_ino,
            ) == published_identity:
                _remove_created_identity(
                    destination,
                    published_identity[0],
                    published_identity[1],
                    True,
                )
            elif published_metadata is not None and not collision:
                raise StagingError("published installation tree identity changed")
        except Exception as cleanup_error:
            cleanup_errors.append(cleanup_error)
    try:
        try:
            remaining_temporary = temporary.lstat()
        except FileNotFoundError:
            remaining_temporary = None
        if remaining_temporary is not None:
            _remove_created_identity(
                temporary,
                staging_metadata.st_dev,
                staging_metadata.st_ino,
                True,
            )
    except Exception as cleanup_error:
        cleanup_errors.append(cleanup_error)
    if record is not None and not registered:
        try:
            record.close()
        except OSError as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if staging_descriptor is not None:
        try:
            os.close(staging_descriptor)
        except OSError as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if cleanup_errors:
        _raise_primary_and_cleanup(
            primary, cleanup_errors, "installation tree publication failed"
        )
    raise primary


def _require_root() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise StagingError("root authority is required for installation")


def _offline_image_contract_tokens() -> tuple[str, ...]:
    """Return the fixed archive-only Podman verbs used by install/verify."""

    return (
        "image", "load", "--input", PINNED_ARCHIVE_NAME,
        "run", "--pull=never", PINNED_EVIDENCE_IMAGE,
    )


def _external_output(
    argv: list[str], maximum: int,
    command_runner: Any | None = None,
    *,
    timeout_seconds: int = EXTERNAL_COMMAND_TIMEOUT_SECONDS,
) -> bytes:
    """Run one noninteractive command with hard wall/output bounds."""

    if command_runner is not None:
        try:
            output = command_runner(
                copy.deepcopy(argv), maximum=maximum,
                timeout_seconds=timeout_seconds,
            )
        except StagingError:
            raise
        except Exception as error:
            raise StagingError(f"staging command failed: {argv[0]}: {error}") from error
        if not isinstance(output, bytes) or len(output) > maximum:
            raise StagingError("staging command runner returned malformed output")
        return output
    environment = {
        "HOME": "/root" if os.geteuid() == 0 else os.fspath(Path.cwd()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin",
    }
    if argv and Path(argv[0]) == PODMAN:
        roots = [
            Path(argv[index + 1])
            for index, token in enumerate(argv[:-1])
            if token == "--root"
        ]
        if len(roots) != 1 or not roots[0].is_absolute():
            raise StagingError("Podman command omits its exact private root")
        environment_root = roots[0].parent / PODMAN_ENVIRONMENT_NAME
        _verify_podman_environment(
            roots[0], os.geteuid(), os.getegid()
        )
        environment.update({
            "HOME": os.fspath(environment_root / "home"),
            "XDG_DATA_HOME": os.fspath(environment_root / "data"),
            "XDG_CACHE_HOME": os.fspath(environment_root / "cache"),
            "XDG_CONFIG_HOME": os.fspath(environment_root / "config"),
            "XDG_RUNTIME_DIR": os.fspath(environment_root / "runtime"),
            "TMPDIR": os.fspath(environment_root / "tmp"),
        })
    completed = _bounded_command(
        argv,
        environment=environment,
        cwd=None,
        maximum_output=maximum,
        timeout_seconds=timeout_seconds,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode(
            "utf-8", errors="replace"
        )[-1000:].strip()
        raise StagingError(
            f"staging command failed ({completed.returncode}): {argv[0]}: {detail}"
        )
    return completed.stdout


def _remove_private_tree(path: Path) -> None:
    """Make one producer-owned temporary tree removable, then remove it."""

    if not path.exists() or path.is_symlink():
        return
    for candidate in [path, *path.rglob("*")]:
        try:
            metadata = candidate.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                os.chmod(candidate, stat.S_IMODE(metadata.st_mode) | 0o700)
            elif stat.S_ISREG(metadata.st_mode):
                os.chmod(candidate, stat.S_IMODE(metadata.st_mode) | 0o600)
        except FileNotFoundError:
            continue
    shutil.rmtree(path)


def _regular_tree_size(root: Path) -> int:
    """Bound the bytes copied into one private bundle snapshot."""

    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise StagingError(
            f"cannot inspect temporary-space input tree: {error}"
        ) from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise StagingError("temporary-space input tree is not a real directory")
    total = 0
    seen = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            children = sorted(
                os.scandir(directory), key=lambda item: item.name
            )
        except OSError as error:
            raise StagingError(
                f"cannot enumerate temporary-space input tree: {error}"
            ) from error
        descendants: list[Path] = []
        for child in children:
            seen += 1
            if seen > MAX_INVENTORY_ENTRIES:
                raise StagingError(
                    "temporary-space input tree exceeds its entry limit"
                )
            path = Path(child.path)
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise StagingError(
                    f"cannot inspect temporary-space input: {error}"
                ) from error
            if stat.S_ISDIR(metadata.st_mode):
                descendants.append(path)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                total += metadata.st_size
            else:
                raise StagingError(
                    "temporary-space input contains a linked or special node"
                )
        stack.extend(reversed(descendants))
    return total


def _temporary_available_bytes(path: Path) -> int:
    try:
        filesystem = os.statvfs(path)
    except OSError as error:
        raise StagingError(
            f"cannot inspect temporary root capacity: {error}"
        ) from error
    return filesystem.f_bavail * filesystem.f_frsize


def _temporary_capacity(path: Path, required_bytes: int) -> None:
    available = _temporary_available_bytes(path)
    if available < required_bytes:
        raise StagingError(
            "temporary root has insufficient free space: "
            f"requires {required_bytes} bytes, found {available}"
        )


def _temporary_inventory_capacity(
    path: Path,
    required_bytes: int,
    required_inodes: int,
) -> None:
    """Keep cleanup space and inode capacity ahead of untrusted creates."""

    try:
        filesystem = os.statvfs(path)
    except OSError as error:
        raise StagingError(
            f"cannot inspect temporary root inventory capacity: {error}"
        ) from error
    available_bytes = filesystem.f_bavail * filesystem.f_frsize
    total_inodes = filesystem.f_files
    available_inodes = filesystem.f_favail
    # Btrfs reports both fields as zero because its inode capacity is dynamic.
    # Every other inode report remains an enforceable, fail-closed ceiling.
    inode_capacity_unreported = total_inodes == 0 and available_inodes == 0
    if (
        available_bytes < required_bytes
        or (
            not inode_capacity_unreported
            and available_inodes < required_inodes
        )
    ):
        raise StagingError(
            "temporary root has insufficient free space or inodes for "
            "the bundle snapshot reserve"
        )


def _create_private_temporary_directory(
    parent: Path,
    prefix: str,
    label: str,
) -> tuple[Path, os.stat_result, int]:
    """Create and identity-pin a preselected private directory safely."""

    for _attempt in range(128):
        candidate = parent / f"{prefix}{secrets.token_hex(16)}"
        mkdir_returned = False
        created_metadata: os.stat_result | None = None
        descriptor: int | None = None
        try:
            os.mkdir(candidate, 0o700)
            mkdir_returned = True
            metadata = candidate.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise StagingError(f"{label} authority drift")
            created_metadata = metadata
            descriptor = _open_identity_pin(
                candidate,
                metadata.st_dev,
                metadata.st_ino,
                True,
                label,
            )
            _fsync_directory(parent)
            return candidate, metadata, descriptor
        except FileExistsError:
            continue
        except BaseException as error:
            cleanup_errors: list[Exception] = []
            # A pathname cannot safely identify the mkdir result until its
            # inode is pinned. If pinning failed, an unlink/recreate attacker
            # may have installed a foreign object with even the same recycled
            # inode number. Preserve that path instead of guessing ownership.
            if descriptor is not None and created_metadata is not None:
                try:
                    _remove_created_identity(
                        candidate,
                        created_metadata.st_dev,
                        created_metadata.st_ino,
                        True,
                    )
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            elif mkdir_returned or not isinstance(error, Exception):
                cleanup_errors.append(StagingError(
                    "private directory cleanup withheld because its original "
                    f"identity was not pinned; retained path may be {candidate}"
                ))
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            _raise_primary_and_cleanup(error, cleanup_errors, label)
    raise StagingError(f"cannot allocate a unique {label}")


def _bundle_temporary_requirement(
    bundle: Path, *, include_snapshot: bool,
) -> int:
    archive = bundle / "image" / PINNED_ARCHIVE_NAME
    try:
        metadata = archive.lstat()
    except OSError as error:
        raise StagingError(
            f"cannot inspect pinned image archive size: {error}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise StagingError("pinned image archive is inadmissible")
    snapshot_bytes = _regular_tree_size(bundle) if include_snapshot else 0
    return (
        snapshot_bytes
        + metadata.st_size * VFS_ARCHIVE_EXPANSION_FACTOR
        + LARGE_TEMPORARY_RESERVE_BYTES
    )


@contextlib.contextmanager
def _large_temporary_workspace(
    temporary_root: Path | None,
    fallback_root: Path,
    *,
    required_bytes: int,
    forbidden_tree: Path,
):
    """Create one identity-bound large workspace outside ambient TMPDIR."""

    explicit = temporary_root is not None
    selected = temporary_root if explicit else fallback_root.absolute()
    assert selected is not None
    if explicit and not selected.is_absolute():
        raise StagingError("temporary root must be an absolute path")
    root = selected.absolute()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
        forbidden = forbidden_tree.resolve(strict=True)
    except OSError as error:
        raise StagingError(f"cannot inspect temporary root: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or resolved != root
        or root == forbidden
        or forbidden in root.parents
    ):
        raise StagingError(
            "temporary root must be a real directory outside the input tree"
        )
    if explicit:
        try:
            names = list(root.iterdir())
        except OSError as error:
            raise StagingError(
                f"cannot enumerate temporary root: {error}"
            ) from error
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or names
        ):
            raise StagingError(
                "explicit temporary root must be empty, mode 0700, and owned "
                "by the invoking user"
            )
    _temporary_capacity(root, required_bytes)
    root_identity = (metadata.st_dev, metadata.st_ino)
    root_descriptor = _open_identity_pin(
        root,
        metadata.st_dev,
        metadata.st_ino,
        True,
        "temporary root",
    )
    workspace: Path | None = None
    workspace_metadata: os.stat_result | None = None
    workspace_descriptor: int | None = None
    cleanup_root_identity = root_identity
    primary: BaseException | None = None
    try:
        workspace, workspace_metadata, workspace_descriptor = (
            _create_private_temporary_directory(
                root,
                "codeskeptic-stability-work-",
                "private temporary workspace creation failed",
            )
        )
        workspace_parent = root.lstat()
        workspace_parent_identity = (
            workspace_parent.st_dev, workspace_parent.st_ino
        )
        cleanup_root_identity = workspace_parent_identity
        if workspace_parent_identity != root_identity:
            raise StagingError(
                "temporary root identity changed during workspace creation"
            )
        if explicit:
            names = sorted(path.name for path in root.iterdir())
            if (
                workspace_parent.st_uid != os.geteuid()
                or workspace_parent.st_gid != os.getegid()
                or stat.S_IMODE(workspace_parent.st_mode) != 0o700
                or names != [workspace.name]
            ):
                raise StagingError(
                    "explicit temporary root authority changed during "
                    "workspace creation"
                )
        _temporary_capacity(root, required_bytes)
        if (
            not stat.S_ISDIR(workspace_metadata.st_mode)
            or workspace_metadata.st_uid != os.geteuid()
            or workspace_metadata.st_gid != os.getegid()
            or stat.S_IMODE(workspace_metadata.st_mode) != 0o700
        ):
            raise StagingError("private temporary workspace authority drift")
        _fsync_directory(root)
        yield workspace
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    root_matches = False
    if workspace is not None and workspace_metadata is not None:
        try:
            after = root.lstat()
            root_matches = (
                after.st_dev, after.st_ino
            ) == cleanup_root_identity
            if not root_matches:
                raise StagingError("temporary root identity changed")
        except Exception as error:
            cleanup_errors.append(error)
        if root_matches:
            try:
                _remove_created_identity(
                    workspace,
                    workspace_metadata.st_dev,
                    workspace_metadata.st_ino,
                    True,
                )
            except Exception as error:
                cleanup_errors.append(error)
            if explicit:
                try:
                    if any(root.iterdir()):
                        raise StagingError(
                            "explicit temporary root retained unexpected entries"
                        )
                except Exception as error:
                    cleanup_errors.append(error)
    for descriptor, label in (
        (workspace_descriptor, "temporary workspace"),
        (root_descriptor, "temporary root"),
    ):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_errors.append(
                    StagingError(f"cannot close {label} identity pin: {error}")
                )
    _raise_primary_and_cleanup(
        primary, cleanup_errors, "large temporary workspace lifecycle failed"
    )


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise StagingError(f"cannot durably sync directory {path}: {error}") from error


@contextlib.contextmanager
def _authority_lifecycle_lock(staging_root: Path):
    """Exclude authority recovery/production while configuring or sealing."""

    if fcntl is None:
        raise StagingError(
            "authority lifecycle lock requires POSIX fcntl support"
        )

    root = staging_root.absolute()
    parent = root.parent
    try:
        root_metadata = root.lstat()
        parent_metadata = parent.lstat()
        root_is_canonical = root.resolve() == root
        parent_is_canonical = parent.resolve() == parent
    except OSError as error:
        raise StagingError(f"cannot inspect authority lifecycle root: {error}") from error
    if (
        root == parent
        or not root.name
        or not stat.S_ISDIR(root_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or not root_is_canonical
        or not parent_is_canonical
    ):
        raise StagingError("authority lifecycle root is not one real directory")
    suffix = hashlib.sha256(root.as_posix().encode("utf-8")).hexdigest()[:32]
    lock_name = f".codeskeptic-p10-09-{suffix}.lock"
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    root_descriptor: int | None = None
    lock_descriptor: int | None = None
    locked = False

    def identity(metadata: os.stat_result) -> tuple[int, int]:
        return metadata.st_dev, metadata.st_ino

    try:
        parent_descriptor = os.open(parent, directory_flags)
        opened_parent = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(opened_parent.st_mode)
            or identity(opened_parent) != identity(parent_metadata)
        ):
            raise StagingError("authority lifecycle parent identity drift")
        root_descriptor = os.open(
            root.name,
            directory_flags,
            dir_fd=parent_descriptor,
        )
        opened_root = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or identity(opened_root) != identity(root_metadata)
        ):
            raise StagingError("authority lifecycle root identity drift")
        lock_descriptor = os.open(
            lock_name, lock_flags, 0o600, dir_fd=parent_descriptor
        )
        lock_metadata = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
        ):
            raise StagingError("authority lifecycle lock identity drift")
        os.fsync(lock_descriptor)
        os.fsync(parent_descriptor)
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StagingError("authority provisioning is still active") from error
        locked = True

        try:
            current_parent = parent.lstat()
            current_root = root.lstat()
            pinned_root = os.stat(
                root.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            pinned_lock = os.stat(
                lock_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            current_lock = os.fstat(lock_descriptor)
            root_is_canonical = root.resolve() == root
            parent_is_canonical = parent.resolve() == parent
        except OSError as error:
            raise StagingError(
                f"authority lifecycle identity changed after lock: {error}"
            ) from error
        if (
            identity(current_parent) != identity(opened_parent)
            or not stat.S_ISDIR(current_parent.st_mode)
            or not parent_is_canonical
        ):
            raise StagingError("authority lifecycle parent identity drift")
        if (
            identity(current_root) != identity(opened_root)
            or identity(pinned_root) != identity(opened_root)
            or not stat.S_ISDIR(current_root.st_mode)
            or not stat.S_ISDIR(pinned_root.st_mode)
            or not root_is_canonical
        ):
            raise StagingError("authority lifecycle root identity drift")
        if (
            identity(pinned_lock) != identity(lock_metadata)
            or identity(current_lock) != identity(lock_metadata)
            or not stat.S_ISREG(pinned_lock.st_mode)
            or pinned_lock.st_nlink != 1
            or pinned_lock.st_uid != os.geteuid()
            or stat.S_IMODE(pinned_lock.st_mode) != 0o600
            or current_lock.st_nlink != 1
            or current_lock.st_uid != os.geteuid()
            or stat.S_IMODE(current_lock.st_mode) != 0o600
        ):
            raise StagingError("authority lifecycle lock identity drift")
        yield
    except StagingError:
        raise
    except OSError as error:
        raise StagingError(f"cannot hold authority lifecycle lock: {error}") from error
    finally:
        if lock_descriptor is not None:
            if locked:
                try:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(lock_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _reject_unresolved_authority_lifecycle(staging_root: Path) -> None:
    authority = staging_root / "authority"
    try:
        top = {entry.name for entry in authority.iterdir()}
    except OSError as error:
        raise StagingError(f"cannot inspect authority lifecycle state: {error}") from error
    unresolved = sorted(
        name for name in top
        if name in AUTHORITY_OPERATION_MARKERS
        or name.startswith(".p10-09-authority-operation.json.")
        or name.startswith(".p10-09-authority-transaction.json.")
        or name.startswith(".sanitizers.")
        or name.startswith(".release.")
    )
    build_root = authority / "source" / "build"
    if build_root.is_dir() and not build_root.is_symlink():
        try:
            unresolved.extend(
                f"source/build/{entry.name}"
                for entry in build_root.iterdir()
                if entry.name.startswith(".p10-09-sanitizers.")
            )
        except OSError as error:
            raise StagingError(
                f"cannot inspect authority build lifecycle state: {error}"
            ) from error
    if unresolved:
        raise StagingError(
            "unresolved authority provisioning lifecycle: "
            + ", ".join(sorted(unresolved))
        )


def _fsync_tree(root: Path) -> None:
    inventory = collect_inventory(root)
    for entry in inventory:
        if entry["type"] != "file":
            continue
        path = root / entry["path"]
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise StagingError(
                f"cannot durably sync file {path}: {error}"
            ) from error
    directories = [
        root / entry["path"] for entry in inventory
        if entry["type"] == "directory"
    ]
    for directory in sorted(
        directories, key=lambda path: len(path.parts), reverse=True
    ):
        _fsync_directory(directory)
    _fsync_directory(root)


def _pinned_bundle_archive_size(source_fd: int) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
    nofollow_flags = flags | getattr(os, "O_NOFOLLOW", 0)
    try:
        image_before = os.stat(
            "image", dir_fd=source_fd, follow_symlinks=False
        )
        image_fd = os.open(
            "image",
            directory_flags | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=source_fd,
        )
        try:
            image_opened = os.fstat(image_fd)
            if (
                not stat.S_ISDIR(image_before.st_mode)
                or image_opened.st_dev != image_before.st_dev
                or image_opened.st_ino != image_before.st_ino
            ):
                raise StagingError(
                    "bundle image directory changed while opening"
                )
            archive_before = os.stat(
                PINNED_ARCHIVE_NAME,
                dir_fd=image_fd,
                follow_symlinks=False,
            )
            archive_fd = os.open(
                PINNED_ARCHIVE_NAME, nofollow_flags, dir_fd=image_fd
            )
            try:
                archive_opened = os.fstat(archive_fd)
                if (
                    not stat.S_ISREG(archive_opened.st_mode)
                    or archive_opened.st_dev != archive_before.st_dev
                    or archive_opened.st_ino != archive_before.st_ino
                    or archive_opened.st_size != archive_before.st_size
                    or archive_opened.st_nlink != 1
                    or archive_opened.st_size > MAX_FILE_BYTES
                ):
                    raise StagingError(
                        "pinned image archive changed while opening"
                    )
                return archive_opened.st_size
            finally:
                os.close(archive_fd)
        finally:
            os.close(image_fd)
    except StagingError:
        raise
    except OSError as error:
        raise StagingError(
            f"cannot pin bundle image archive size: {error}"
        ) from error


def _copy_snapshot_directory(
    source_fd: int,
    destination: Path,
    budget: dict[str, Any],
) -> None:
    try:
        names = sorted(os.listdir(source_fd))
    except OSError as error:
        raise StagingError(f"cannot enumerate bundle snapshot input: {error}") from error
    for name in names:
        budget["entries"] += 1
        if budget["entries"] > MAX_INVENTORY_ENTRIES:
            raise StagingError("bundle snapshot exceeds its entry budget")
        _temporary_inventory_capacity(
            budget["temporary_workspace"],
            budget["reserve_bytes"],
            2,
        )
        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\x00" in name
        ):
            raise StagingError("bundle snapshot contains a malformed name")
        try:
            before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as error:
            raise StagingError(f"cannot inspect bundle snapshot input: {error}") from error
        target = destination / name
        if stat.S_ISDIR(before.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                child_fd = os.open(name, flags, dir_fd=source_fd)
            except OSError as error:
                raise StagingError(
                    f"cannot open bundle snapshot directory: {error}"
                ) from error
            try:
                opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or not _same_file_identity(before, opened)
                ):
                    raise StagingError(
                        "bundle snapshot directory changed while opening"
                    )
                target.mkdir(mode=0o700)
                _temporary_inventory_capacity(
                    budget["temporary_workspace"],
                    budget["reserve_bytes"],
                    1,
                )
                _copy_snapshot_directory(child_fd, target, budget)
                after = os.fstat(child_fd)
                path_after = os.stat(
                    name, dir_fd=source_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(path_after.st_mode)
                    or _stat_fingerprint(opened)
                    != _stat_fingerprint(after)
                    or _stat_fingerprint(before)
                    != _stat_fingerprint(path_after)
                    or not _same_file_identity(after, path_after)
                ):
                    raise StagingError(
                        "bundle snapshot directory changed while copying"
                    )
                os.chmod(target, stat.S_IMODE(before.st_mode))
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
            )
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                source_file = os.open(name, flags, dir_fd=source_fd)
                opened = os.fstat(source_file)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not _same_file_identity(before, opened)
                    or opened.st_nlink != 1
                    or opened.st_size > MAX_FILE_BYTES
                ):
                    raise StagingError(
                        "bundle snapshot file changed while opening"
                    )
                if opened.st_size > budget["remaining_bytes"]:
                    raise StagingError(
                        "bundle snapshot exceeds its pinned byte budget"
                    )
                _temporary_capacity(
                    budget["temporary_workspace"],
                    opened.st_size + budget["reserve_bytes"],
                )
                budget["remaining_bytes"] -= opened.st_size
                destination_flags = (
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_BINARY", 0)
                )
                destination_file = os.open(target, destination_flags, 0o600)
                try:
                    total = 0
                    while True:
                        block = os.read(source_file, 1024 * 1024)
                        if not block:
                            break
                        total += len(block)
                        offset = 0
                        while offset < len(block):
                            written = os.write(destination_file, block[offset:])
                            if written <= 0:
                                raise OSError("short bundle snapshot write")
                            offset += written
                    os.fchmod(destination_file, stat.S_IMODE(before.st_mode))
                    os.fsync(destination_file)
                finally:
                    os.close(destination_file)
                after = os.fstat(source_file)
                path_after = os.stat(
                    name, dir_fd=source_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISREG(path_after.st_mode)
                    or path_after.st_nlink != 1
                    or _stat_fingerprint(opened)
                    != _stat_fingerprint(after)
                    or _stat_fingerprint(before)
                    != _stat_fingerprint(path_after)
                    or not _same_file_identity(after, path_after)
                    or total != after.st_size
                ):
                    raise StagingError(
                        "bundle snapshot file changed while copying"
                    )
            except StagingError:
                raise
            except OSError as error:
                raise StagingError(
                    f"cannot copy bundle snapshot file: {error}"
                ) from error
            finally:
                if "source_file" in locals():
                    os.close(source_file)
                    del source_file
        else:
            raise StagingError(
                "bundle snapshot contains a linked or special node"
            )
    _fsync_directory(destination)


@contextlib.contextmanager
def _trusted_bundle_snapshot(bundle: Path, temporary_workspace: Path):
    """Pin an untrusted pathname into a private tree before parsing/execution."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(bundle, flags)
    except OSError as error:
        raise StagingError(f"cannot open sealed bundle root: {error}") from error
    snapshot: Path | None = None
    snapshot_metadata: os.stat_result | None = None
    snapshot_descriptor: int | None = None
    primary: BaseException | None = None
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise StagingError("sealed bundle root is not a directory")
        archive_size = _pinned_bundle_archive_size(source_fd)
        reserve_bytes = (
            archive_size * VFS_ARCHIVE_EXPANSION_FACTOR
            + LARGE_TEMPORARY_RESERVE_BYTES
        )
        available_bytes = _temporary_available_bytes(temporary_workspace)
        if available_bytes < reserve_bytes:
            raise StagingError(
                "temporary root has insufficient free space for the pinned "
                "image store reserve"
            )
        budget = {
            "entries": 0,
            "remaining_bytes": available_bytes - reserve_bytes,
            "reserve_bytes": reserve_bytes,
            "temporary_workspace": temporary_workspace,
        }
        snapshot, snapshot_metadata, snapshot_descriptor = (
            _create_private_temporary_directory(
                temporary_workspace,
                "bundle-snapshot-",
                "trusted bundle snapshot creation failed",
            )
        )
        _copy_snapshot_directory(source_fd, snapshot, budget)
        after = os.fstat(source_fd)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise StagingError("sealed bundle root changed while snapshotting")
        os.chmod(snapshot, stat.S_IMODE(before.st_mode))
        _fsync_directory(temporary_workspace)
        try:
            yield snapshot
        except BaseException as error:
            primary = error
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    try:
        os.close(source_fd)
    except Exception as error:
        cleanup_errors.append(error)
    if snapshot is not None and snapshot_metadata is not None:
        try:
            _remove_created_identity(
                snapshot,
                snapshot_metadata.st_dev,
                snapshot_metadata.st_ino,
                True,
            )
        except Exception as error:
            cleanup_errors.append(error)
    if snapshot_descriptor is not None:
        try:
            os.close(snapshot_descriptor)
        except OSError as error:
            cleanup_errors.append(error)
    _raise_primary_and_cleanup(
        primary, cleanup_errors, "trusted bundle snapshot lifecycle failed"
    )


def _safe_mount_path(path: Path, label: str) -> str:
    value = path.absolute().as_posix()
    if any(character in value for character in ("\x00", "\n", "\r", ":")):
        raise StagingError(f"{label} is unsafe for an OCI bind mount")
    return value


def _podman_global_options(
    root: Path, runroot: Path, hooks: Path, *, storage_driver: str,
) -> list[str]:
    if storage_driver not in {"overlay", "vfs"}:
        raise StagingError("Podman storage driver is unsupported")
    return [
        os.fspath(PODMAN),
        "--root", _safe_mount_path(root, "Podman root"),
        "--runroot", _safe_mount_path(runroot, "Podman runroot"),
        f"--storage-driver={storage_driver}",
        "--cgroup-manager=cgroupfs",
        f"--conmon={CONMON}",
        "--events-backend=none",
        f"--hooks-dir={_safe_mount_path(hooks, 'OCI hooks directory')}",
        f"--runtime={CRUN}",
    ]


def _ensure_private_directory(
    path: Path, owner_uid: int, owner_gid: int,
    *,
    created_nodes: list[_CreatedNode] | None = None,
) -> bool:
    existed = path.exists() or path.is_symlink()
    if not existed:
        _create_directory_create_new(
            path,
            0o700,
            owner_uid,
            owner_gid,
            created_nodes=created_nodes,
        )
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StagingError(
            f"cannot establish private directory {path}: {error}"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
    ):
        raise StagingError(f"private directory authority drift: {path}")
    return not existed


def _verify_private_directory(
    path: Path, owner_uid: int, owner_gid: int,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StagingError(f"private directory is unavailable: {path}: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
    ):
        raise StagingError(f"private directory authority drift: {path}")


def _ensure_podman_environment(
    podman_root: Path, owner_uid: int, owner_gid: int,
) -> Path:
    environment_root = podman_root.parent / PODMAN_ENVIRONMENT_NAME
    _ensure_private_directory(environment_root, owner_uid, owner_gid)
    for name in PODMAN_ENVIRONMENT_DIRECTORIES:
        _ensure_private_directory(
            environment_root / name, owner_uid, owner_gid
        )
    _verify_podman_environment(podman_root, owner_uid, owner_gid)
    return environment_root


def _verify_podman_environment(
    podman_root: Path, owner_uid: int, owner_gid: int,
) -> Path:
    environment_root = podman_root.parent / PODMAN_ENVIRONMENT_NAME
    _verify_private_directory(environment_root, owner_uid, owner_gid)
    try:
        names = sorted(path.name for path in environment_root.iterdir())
    except OSError as error:
        raise StagingError(
            f"cannot inspect private Podman environment: {error}"
        ) from error
    if names != sorted(PODMAN_ENVIRONMENT_DIRECTORIES):
        raise StagingError("private Podman environment inventory drift")
    for name in PODMAN_ENVIRONMENT_DIRECTORIES:
        _verify_private_directory(
            environment_root / name, owner_uid, owner_gid
        )
    return environment_root


@contextlib.contextmanager
def _fixed_podman_runroot(owner_uid: int, owner_gid: int):
    """Create-new the one runroot pathname shared by install and service."""

    created: list[_CreatedNode] = []
    primary: BaseException | None = None
    try:
        parent = PODMAN_RUNROOT.parent
        if not parent.exists() and not parent.is_symlink():
            if not _ensure_private_directory(
                parent, owner_uid, owner_gid, created_nodes=created
            ):
                raise StagingError("fixed Podman runtime root appeared concurrently")
        else:
            _verify_private_directory(parent, owner_uid, owner_gid)
        if PODMAN_RUNROOT.exists() or PODMAN_RUNROOT.is_symlink():
            raise StagingError("fixed Podman runroot must be previously absent")
        if not _ensure_private_directory(
            PODMAN_RUNROOT,
            owner_uid,
            owner_gid,
            created_nodes=created,
        ):
            raise StagingError("fixed Podman runroot appeared concurrently")
        yield PODMAN_RUNROOT
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    try:
        _rollback_created(created)
    except Exception as error:
        cleanup_errors.append(error)
    _raise_primary_and_cleanup(
        primary, cleanup_errors, "fixed Podman runroot lifecycle failed"
    )


def _reset_persistent_podman_store(
    command_runner: Any | None, owner_uid: int, owner_gid: int,
) -> None:
    """Reset a failed persistent store through its exact lexical runroot."""

    with _fixed_podman_runroot(owner_uid, owner_gid) as runroot:
        options = _podman_global_options(
            PODMAN_ROOT, runroot, OPERATOR_ROOT, storage_driver="overlay"
        )
        _external_output(
            [*options, "system", "reset", "--force"],
            64 * 1024,
            command_runner,
            timeout_seconds=300,
        )


def _reject_operator_hooks(operator_root: Path) -> None:
    try:
        metadata = operator_root.lstat()
        entries = list(operator_root.iterdir())
    except OSError as error:
        raise StagingError(f"cannot inspect closed OCI hooks directory: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or any(
        path.name.endswith(".json") for path in entries
    ):
        raise StagingError("operator OCI hooks directory is not closed")


def _normalize_image_id(value: str) -> str:
    candidate = value if value.startswith("sha256:") else f"sha256:{value}"
    if candidate != PINNED_EVIDENCE_IMAGE_ID:
        raise StagingError("dedicated Podman image ID drift")
    return candidate


def _container_probe_limits() -> list[str]:
    return [
        "--cgroups=enabled",
        "--cpus=2",
        "--memory=2147483648",
        "--memory-swap=2147483648",
        "--pids-limit=128",
        "--ulimit=nofile=4096:4096",
        "--cap-drop=all",
    ]


def _verify_pinned_image_store(
    options: list[str], command_runner: Any | None,
    *, run_probe: bool,
) -> None:
    identity = _external_output(
        [
            *options, "image", "inspect", "--format", "{{.Id}}|{{.Digest}}",
            PINNED_EVIDENCE_IMAGE,
        ],
        4096,
        command_runner,
    )
    try:
        identity_text = identity.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise StagingError("dedicated Podman image identity is not ASCII") from error
    if identity_text.count("|") != 1:
        raise StagingError("dedicated Podman image identity is malformed")
    image_id, digest = identity_text.split("|", 1)
    _normalize_image_id(image_id)
    if digest != PINNED_EVIDENCE_IMAGE_DIGEST:
        raise StagingError("dedicated Podman image digest drift")
    inventory = _external_output(
        [*options, "image", "list", "--all", "--no-trunc", "--format", "{{.ID}}"],
        1024 * 1024,
        command_runner,
    )
    try:
        image_ids = {
            _normalize_image_id(line)
            for line in inventory.decode("ascii", errors="strict").splitlines()
            if line
        }
    except UnicodeDecodeError as error:
        raise StagingError("dedicated Podman image inventory is not ASCII") from error
    if image_ids != {PINNED_EVIDENCE_IMAGE_ID}:
        raise StagingError("dedicated Podman image inventory is not exact")
    containers = _external_output(
        [
            *options, "container", "list", "--all", "--no-trunc",
            "--format", "{{.ID}}|{{.Names}}",
        ],
        1024 * 1024,
        command_runner,
    )
    if containers:
        raise StagingError("dedicated Podman container inventory is not empty")
    if run_probe:
        probe = _external_output(
            [
                *options, "run", "--rm", "--pull=never", "--network=none",
                *_container_probe_limits(), "--pid=private", "--read-only",
                "--read-only-tmpfs=false", "--user=0:0", "--http-proxy=false",
                "--env-host=false", "--image-volume=ignore",
                "--security-opt=label=disable",
                "--security-opt=no-new-privileges",
                PINNED_EVIDENCE_IMAGE, "/usr/bin/python3", "-B", "-c",
                "print('CODESKEPTIC_STAGING_IMAGE_PROBE_OK')",
            ],
            4096,
            command_runner,
        )
        if probe != IMAGE_PROBE_MARKER:
            raise StagingError("pinned image archive-only probe output drift")
        if _external_output(
            [
                *options, "container", "list", "--all", "--no-trunc",
                "--format", "{{.ID}}|{{.Names}}",
            ],
            1024 * 1024,
            command_runner,
        ):
            raise StagingError("pinned image probe retained a container")


def _load_and_verify_image_archive(
    archive: Path,
    *,
    podman_root: Path,
    podman_runroot: Path,
    hooks: Path,
    storage_driver: str,
    command_runner: Any | None,
    owner_uid: int,
    owner_gid: int,
) -> list[str]:
    _sha256_regular(archive)
    _reject_operator_hooks(hooks)
    _ensure_private_directory(podman_root, owner_uid, owner_gid)
    _ensure_private_directory(podman_runroot, owner_uid, owner_gid)
    _ensure_podman_environment(podman_root, owner_uid, owner_gid)
    options = _podman_global_options(
        podman_root, podman_runroot, hooks, storage_driver=storage_driver
    )
    _external_output(
        [*options, "image", "load", "--input", _safe_mount_path(archive, "image archive")],
        1024 * 1024,
        command_runner,
        timeout_seconds=IMAGE_LOAD_TIMEOUT_SECONDS,
    )
    _verify_pinned_image_store(options, command_runner, run_probe=True)
    return options


def _verify_static_authorities_in_image(
    options: list[str],
    authority_root: Path,
    config_path: Path,
    command_runner: Any | None,
) -> None:
    config_sidecar = Path(f"{config_path}.sha256")
    output = _external_output(
        [
            *options, "run", "--rm", "--pull=never", "--network=none",
            *_container_probe_limits(), "--pid=private", "--read-only",
            "--read-only-tmpfs=false", "--user=0:0", "--http-proxy=false",
            "--env-host=false", "--image-volume=ignore",
            "--security-opt=label=disable",
            "--security-opt=no-new-privileges", "--workdir=/authority/source",
            "--env=HOME=/tmp", "--env=TMPDIR=/tmp", "--env=LANG=C",
            "--env=LC_ALL=C", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864",
            "--volume",
            f"{_safe_mount_path(authority_root, 'authority root')}:/authority:ro",
            "--volume",
            f"{_safe_mount_path(config_path, 'runtime config')}:/config/runtime.json:ro",
            "--volume",
            f"{_safe_mount_path(config_sidecar, 'runtime config sidecar')}:/config/runtime.json.sha256:ro",
            PINNED_EVIDENCE_IMAGE, "/usr/bin/python3", "-B", "-c",
            STATIC_AUTHORITY_VERIFIER,
        ],
        64 * 1024,
        command_runner,
    )
    if output != STATIC_AUTHORITY_MARKER:
        raise StagingError("static authority verifier output drift")


def _read_regular(path: Path, maximum: int = MAX_DOCUMENT_BYTES) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StagingError(f"cannot inspect required file {path}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        raise StagingError(f"required file is inadmissible: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size
            ):
                raise StagingError(f"required file changed while opening: {path}")
            blocks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                block = os.read(descriptor, min(1024 * 1024, remaining))
                if not block:
                    break
                blocks.append(block)
                remaining -= len(block)
            data = b"".join(blocks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except StagingError:
        raise
    except OSError as error:
        raise StagingError(f"cannot read required file {path}: {error}") from error
    if (
        len(data) > maximum
        or after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
    ):
        raise StagingError(f"required file changed while reading: {path}")
    return data


def _write_new(
    path: Path,
    data: bytes,
    mode: int = 0o600,
    *,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    created_nodes: list[_CreatedNode] | None = None,
) -> None:
    def write_payload(descriptor: int) -> None:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short staging write")
            offset += written

    _regular_file_create_new(
        path,
        mode,
        owner_uid,
        owner_gid,
        write_payload,
        created_nodes=created_nodes,
        label=f"cannot create staging file {path}",
    )


def _load_canonical_document(path: Path, label: str) -> dict[str, Any]:
    data = _read_regular(path)
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StagingError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict) or data != canonical_document(value):
        raise StagingError(f"{label} is not canonical")
    return value


def _require_absent(path: Path, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise StagingError(f"cannot inspect {label}: {error}") from error
    raise StagingError(f"{label} must be previously absent")


def _run_checked(
    argv: list[str], *, cwd: Path | None = None,
    maximum_output: int = 1024 * 1024,
    timeout_seconds: int = EXTERNAL_COMMAND_TIMEOUT_SECONDS,
) -> bytes:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": os.fspath(cwd or Path("/")),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin",
    }
    completed = _bounded_command(
        argv,
        environment=environment,
        cwd=cwd,
        maximum_output=maximum_output,
        timeout_seconds=timeout_seconds,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-1000:].strip()
        raise StagingError(
            f"staging command failed ({completed.returncode}): {argv[0]}: {detail}"
        )
    return completed.stdout


def _copy_regular_exact(
    source: Path | str, destination: Path | str, mode: int | None = None,
) -> None:
    source = Path(source)
    destination = Path(destination)
    metadata = source.lstat()
    selected_mode = stat.S_IMODE(metadata.st_mode) if mode is None else mode
    _copy_regular_create_new(
        source, destination, selected_mode, os.getuid(), os.getgid()
    )


def _prepare_operator(source_root: Path, output: Path) -> None:
    systemd = source_root / "scripts" / "stability-systemd"
    files = {
        "README.md": systemd / "README.md",
        "cgroup-authority.py": systemd / "cgroup-authority.py",
        "container-entry.py": systemd / "container-entry.py",
        "containers.conf": systemd / "containers.conf",
        "host-recovery.py": systemd / "host-recovery.py",
        "guided-stability.sh": systemd / "guided-stability.sh",
        "post-stop.sh": systemd / "post-stop.sh",
        "run-authoritative-stability.sh": (
            systemd / "run-authoritative-stability.sh"
        ),
        UNIT_NAME: systemd / UNIT_NAME,
        "stage_stability_campaign.py": (
            source_root / "scripts" / "stage_stability_campaign.py"
        ),
    }
    output.mkdir(mode=0o700)
    for name, source in files.items():
        mode = 0o500 if name.endswith((".sh", ".py")) else 0o400
        _copy_regular_exact(source, output / name, mode)
    if any(path.suffix == ".json" for path in output.iterdir()):
        raise StagingError("operator OCI hooks directory contains JSON")


def _verify_operator_exact_head(
    authority_root: Path,
    operator_root: Path,
    retained_unit: Path,
    *,
    immutable: bool,
) -> None:
    """Bind every root-executed operator byte to the exact staged source."""

    source_root = authority_root / "source"
    systemd = source_root / "scripts" / "stability-systemd"
    expected = {
        "README.md": systemd / "README.md",
        "cgroup-authority.py": systemd / "cgroup-authority.py",
        "container-entry.py": systemd / "container-entry.py",
        "containers.conf": systemd / "containers.conf",
        "host-recovery.py": systemd / "host-recovery.py",
        "guided-stability.sh": systemd / "guided-stability.sh",
        "post-stop.sh": systemd / "post-stop.sh",
        "run-authoritative-stability.sh": (
            systemd / "run-authoritative-stability.sh"
        ),
        UNIT_NAME: systemd / UNIT_NAME,
        "stage_stability_campaign.py": (
            source_root / "scripts" / "stage_stability_campaign.py"
        ),
    }
    try:
        actual_names = sorted(path.name for path in operator_root.iterdir())
        unit_names = sorted(path.name for path in retained_unit.parent.iterdir())
    except OSError as error:
        raise StagingError(f"cannot inspect exact-head operator: {error}") from error
    if actual_names != sorted(expected) or unit_names != [UNIT_NAME]:
        raise StagingError("operator exact-head inventory drift")
    for name, source in expected.items():
        operator = operator_root / name
        source_bytes = _read_regular(source)
        if _read_regular(operator) != source_bytes:
            raise StagingError(f"operator {name} differs from exact-head source")
        metadata = operator.lstat()
        executable = name.endswith((".sh", ".py"))
        expected_mode = (
            0o555 if immutable and executable
            else 0o444 if immutable
            else 0o500 if executable
            else 0o400
        )
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise StagingError(f"operator {name} mode drift")
    if _read_regular(retained_unit) != _read_regular(systemd / UNIT_NAME):
        raise StagingError("retained unit differs from exact-head source")
    expected_unit_mode = 0o444 if immutable else 0o400
    if stat.S_IMODE(retained_unit.lstat().st_mode) != expected_unit_mode:
        raise StagingError("retained unit mode drift")


def prepare_staging(
    source: Path, revision: str, image_archive: Path, output: Path,
) -> dict[str, str]:
    """Create a new mutable exact-head authority-layout workspace."""

    revision = _valid_git_sha1(revision, "prepare revision")
    validate_staged_source(source, revision)
    archive_sha256 = _sha256_regular(image_archive)
    _require_absent(output, "prepare output")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary, temporary_metadata, temporary_descriptor = (
        _create_private_temporary_directory(
            output.parent,
            f".{output.name}.prepare-",
            "prepare staging tree creation failed",
        )
    )
    publication_identity: tuple[int, int] | None = None
    staged_identity: dict[str, str] | None = None
    primary: BaseException | None = None
    collision = False
    try:
        for name in ("authority", "image", "unit"):
            (temporary / name).mkdir(mode=0o700)
        authority = temporary / "authority"
        staged_source = authority / "source"
        _run_checked([
            "/usr/bin/git", "clone", "--no-local", "--no-checkout",
            "--", os.fspath(source), os.fspath(staged_source),
        ], cwd=temporary)
        _run_checked([
            "/usr/bin/git", "--no-replace-objects", "-C",
            os.fspath(staged_source), "checkout", "--detach", "--force",
            revision,
        ], cwd=temporary)
        _run_checked([
            "/usr/bin/git", "--no-replace-objects", "-C",
            os.fspath(staged_source), "remote", "remove", "origin",
        ], cwd=temporary)
        staged_identity = validate_staged_source(staged_source, revision)
        for relative in ("build", "build-authority", "prerequisites"):
            (authority / relative).mkdir(parents=True, mode=0o700, exist_ok=True)
        _prepare_operator(staged_source, temporary / "operator")
        _copy_regular_exact(
            staged_source / "scripts" / "stability-systemd" / UNIT_NAME,
            temporary / "unit" / UNIT_NAME,
            0o400,
        )
        _copy_regular_exact(
            image_archive, temporary / "image" / PINNED_ARCHIVE_NAME, 0o400
        )
        _fsync_tree(temporary)
        publication_metadata = temporary.lstat()
        if (
            publication_metadata.st_dev != temporary_metadata.st_dev
            or publication_metadata.st_ino != temporary_metadata.st_ino
        ):
            raise StagingError("prepare staging tree identity changed")
        publication_identity = (
            publication_metadata.st_dev,
            publication_metadata.st_ino,
        )
        _publish_tree_noreplace(temporary, output)
    except FileExistsError as error:
        primary = StagingError("prepare output appeared concurrently")
        collision = True
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    try:
        try:
            remaining_temporary = temporary.lstat()
        except FileNotFoundError:
            remaining_temporary = None
        if remaining_temporary is not None:
            _remove_created_identity(
                temporary,
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
                True,
            )
    except Exception as error:
        cleanup_errors.append(error)
    if (
        (primary is not None or cleanup_errors)
        and publication_identity is not None
    ):
        try:
            try:
                published_metadata = output.lstat()
            except FileNotFoundError:
                published_metadata = None
            if not collision and published_metadata is not None and (
                published_metadata.st_dev,
                published_metadata.st_ino,
            ) == publication_identity:
                _remove_created_identity(
                    output,
                    publication_identity[0],
                    publication_identity[1],
                    True,
                )
            elif published_metadata is not None and not collision:
                raise StagingError("published prepare output identity changed")
        except Exception as error:
            cleanup_errors.append(error)
    try:
        os.close(temporary_descriptor)
    except OSError as error:
        cleanup_errors.append(error)
    _raise_primary_and_cleanup(
        primary, cleanup_errors, "prepare publication failed"
    )
    assert staged_identity is not None
    return {
        **staged_identity,
        "image_archive_sha256": archive_sha256,
    }


def _payload_roots(root: Path) -> list[Path]:
    expected = ["authority", "config", "image", "operator", "unit"]
    try:
        actual = sorted(path.name for path in root.iterdir() if path.name != "bundle")
    except OSError as error:
        raise StagingError(f"cannot enumerate staging root: {error}") from error
    if actual != expected:
        raise StagingError("staging payload root inventory is not exact")
    roots = [root / name for name in expected]
    if any(not path.is_dir() or path.is_symlink() for path in roots):
        raise StagingError("staging payload root is not a real directory")
    return roots


def _collect_payload_inventory(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for payload_root in _payload_roots(root):
        metadata = payload_root.lstat()
        entries.append({
            "path": payload_root.name,
            "type": "directory",
            "mode": _inventory_mode(metadata),
        })
        for item in collect_inventory(payload_root):
            prefixed = copy.deepcopy(item)
            prefixed["path"] = f"{payload_root.name}/{item['path']}"
            entries.append(prefixed)
    return sorted(entries, key=lambda item: item["path"])


def _verify_payload_inventory(root: Path, inventory: Any) -> None:
    expected = _validate_inventory_document(inventory)
    if _collect_payload_inventory(root) != expected:
        raise StagingError("staging payload differs from its sealed inventory")


def _config_path(
    value: Any,
    root: PurePosixPath,
    label: str,
    *,
    exact: PurePosixPath | None = None,
) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StagingError(f"{label} path is malformed")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
        or (path != root and root not in path.parents)
    ):
        raise StagingError(f"{label} path is not canonical under {root}")
    if exact is not None and path != exact:
        raise StagingError(f"{label} path differs from its fixed location")
    return value


def _fixed_config_integer(value: Any, expected: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise StagingError(f"{label} differs from its fixed value")
    return value


def _validate_runtime_config_contract(raw: Any) -> dict[str, Any]:
    """Validate the data-only runtime schema without executing staged code."""

    value = _exact_dict(
        raw,
        frozenset({
            "schema", "policy", "source", "runtime", "analyzer",
            "build_authority", "realworld", "fault_injection",
            "qualification", "prerequisites", "sanitizers",
        }),
        "stability runtime config",
    )
    if value["schema"] != RUNTIME_CONFIG_SCHEMA:
        raise StagingError("stability runtime config schema is unsupported")
    authority = PurePosixPath("/authority")
    source_root = authority / "source"

    policy = _exact_dict(
        value["policy"], frozenset({"path", "sha256"}), "runtime policy"
    )
    _config_path(
        policy["path"], authority, "runtime policy",
        exact=source_root / "scripts" / "stability_manifest.json",
    )
    _valid_sha256(policy["sha256"], "runtime policy")

    source = _exact_dict(
        value["source"],
        frozenset({"root", "revision", "tree_sha1", "manifest_sha256"}),
        "runtime source",
    )
    _config_path(
        source["root"], authority, "runtime source", exact=source_root
    )
    _valid_git_sha1(source["revision"], "runtime source revision")
    _valid_git_sha1(source["tree_sha1"], "runtime source tree")
    _valid_sha256(source["manifest_sha256"], "runtime source manifest")

    runtime = _exact_dict(
        value["runtime"],
        frozenset({
            "image_reference", "image_digest", "image_id", "launch_receipt",
        }),
        "runtime authority",
    )
    if runtime != {
        "image_reference": PINNED_EVIDENCE_IMAGE,
        "image_digest": PINNED_EVIDENCE_IMAGE_DIGEST,
        "image_id": PINNED_EVIDENCE_IMAGE_ID,
        "launch_receipt": "/launch/receipt.json",
    }:
        raise StagingError("pinned runtime authority drift")

    analyzer = _exact_dict(
        value["analyzer"], frozenset({"path", "sha256"}),
        "runtime analyzer",
    )
    _config_path(
        analyzer["path"], authority, "runtime analyzer",
        exact=authority / "build" / "src" / "codeskeptic",
    )
    _valid_sha256(analyzer["sha256"], "runtime analyzer")

    build = _exact_dict(
        value["build_authority"],
        frozenset({"root", "receipt_sha256", "build_path"}),
        "runtime build authority",
    )
    _config_path(
        build["root"], authority, "runtime build authority root",
        exact=authority / "build-authority",
    )
    _config_path(
        build["build_path"], authority, "runtime build authority build",
        exact=authority / "build",
    )
    _valid_sha256(build["receipt_sha256"], "runtime build receipt")

    realworld = _exact_dict(
        value["realworld"],
        frozenset({"mirror_authority", "mirror_authority_sha256"}),
        "runtime real-world authority",
    )
    _config_path(
        realworld["mirror_authority"], authority,
        "runtime real-world mirror authority",
        exact=authority / "mirrors" / "authority.json",
    )
    _valid_sha256(
        realworld["mirror_authority_sha256"],
        "runtime real-world mirror authority",
    )

    fault = _exact_dict(
        value["fault_injection"],
        frozenset({"test_binary", "test_binary_sha256"}),
        "runtime fault-injection authority",
    )
    _config_path(
        fault["test_binary"], authority, "runtime fault-injection test binary"
    )
    _valid_sha256(
        fault["test_binary_sha256"], "runtime fault-injection test binary"
    )

    qualification = _exact_dict(
        value["qualification"],
        frozenset({
            "hardware_class", "measurement_cgroup",
            "baseline_authority", "release_source", "release_build",
            "release_receipt_sha256", "jobs", "tools",
        }),
        "runtime qualification",
    )
    if (
        qualification["hardware_class"]
        != "fedora44-i5-1235u-exclusive-pcores-0-3"
    ):
        raise StagingError("runtime hardware class drift")
    _config_path(
        qualification["measurement_cgroup"],
        PurePosixPath("/sys/fs/cgroup"),
        "runtime measurement cgroup",
        exact=PurePosixPath(RUNTIME_MEASUREMENT_CGROUP),
    )
    baseline_authority = _exact_dict(
        qualification["baseline_authority"],
        frozenset({
            "root", "manifest_sha256", "baseline_sha256",
            "projection_sha256",
        }),
        "runtime determinism baseline authority",
    )
    _config_path(
        baseline_authority["root"], authority,
        "runtime determinism baseline authority root", exact=source_root,
    )
    for field in (
        "manifest_sha256", "baseline_sha256", "projection_sha256"
    ):
        _valid_sha256(
            baseline_authority[field],
            f"runtime determinism baseline authority {field}",
        )
    for field, exact in {
        "release_source": authority / "release" / "source",
        "release_build": authority / "release" / "build",
    }.items():
        _config_path(
            qualification[field], authority,
            f"runtime qualification {field}", exact=exact,
        )
    _valid_sha256(
        qualification["release_receipt_sha256"],
        "runtime qualification release receipt",
    )
    _fixed_config_integer(
        qualification["jobs"], 2, "runtime qualification jobs"
    )
    tools = _exact_dict(
        qualification["tools"],
        frozenset({
            "clang", "time", "cmake", "ninja", "c_compiler",
            "cxx_compiler",
        }),
        "runtime qualification tools",
    )
    if tools != {
        "clang": "/usr/bin/clang-20",
        "time": "/usr/bin/time",
        "cmake": "/usr/bin/cmake",
        "ninja": "/usr/bin/ninja",
        "c_compiler": "/usr/bin/clang-20",
        "cxx_compiler": "/usr/bin/clang++-20",
    }:
        raise StagingError("runtime qualification tool paths drift")

    prerequisites = _exact_dict(
        value["prerequisites"],
        frozenset({"hosted_exact_head", "quality_floor"}),
        "runtime prerequisites",
    )
    quality = _exact_dict(
        prerequisites["quality_floor"],
        frozenset({"root", "receipt_sha256"}),
        "runtime prerequisite quality_floor",
    )
    _config_path(
        quality["root"], authority, "runtime prerequisite quality_floor",
        exact=authority / "prerequisites" / "quality",
    )
    _valid_sha256(
        quality["receipt_sha256"], "runtime prerequisite quality_floor receipt"
    )
    hosted = _exact_dict(
        prerequisites["hosted_exact_head"],
        frozenset({"root", "receipt_sha256", "repository"}),
        "runtime prerequisite hosted exact-head",
    )
    _config_path(
        hosted["root"], authority, "runtime hosted exact-head",
        exact=authority / "prerequisites" / "hosted",
    )
    _valid_sha256(hosted["receipt_sha256"], "runtime hosted receipt")
    repository = hosted["repository"]
    repository_components = (
        repository.split("/", 1) if isinstance(repository, str) else []
    )
    if (
        not isinstance(repository, str)
        or HOSTED_REPOSITORY.fullmatch(repository) is None
        or repository.endswith(".git")
        or any(component in {".", ".."} for component in repository_components)
    ):
        raise StagingError("runtime hosted repository identity is malformed")

    sanitizers = _exact_dict(
        value["sanitizers"], frozenset(SANITIZER_PROFILES),
        "runtime sanitizers",
    )
    for profile in SANITIZER_PROFILES:
        record = _exact_dict(
            sanitizers[profile],
            frozenset({"root", "receipt_sha256", "test_build", "fuzz_build"}),
            f"runtime sanitizer {profile}",
        )
        exact_paths = {
            "root": authority / "sanitizers" / profile,
            "test_build": (
                source_root / SANITIZER_WORK_ROOT.as_posix()
                / f"{profile}-tests"
            ),
            "fuzz_build": (
                source_root / SANITIZER_WORK_ROOT.as_posix()
                / f"{profile}-fuzz"
            ),
        }
        for field, exact in exact_paths.items():
            _config_path(
                record[field], authority,
                f"runtime sanitizer {profile} {field}", exact=exact,
            )
        _valid_sha256(
            record["receipt_sha256"], f"runtime sanitizer {profile} receipt"
        )
    expected_fault = (
        PurePosixPath(sanitizers["undefined"]["test_build"])
        / "tests" / "codeskeptic_tests"
    )
    if PurePosixPath(fault["test_binary"]) != expected_fault:
        raise StagingError(
            "runtime fault binary is not the undefined sanitizer test binary"
        )
    return copy.deepcopy(value)


def _runtime_config_at(
    path: Path, authority_host_root: Path,
) -> tuple[dict[str, Any], bytes]:
    data = _read_regular(path, MAX_DOCUMENT_BYTES)
    sidecar = _read_regular(Path(f"{path}.sha256"), 1024)
    expected_sidecar = (
        f"{hashlib.sha256(data).hexdigest()}  runtime.json\n"
    ).encode("ascii")
    if sidecar != expected_sidecar:
        raise StagingError("runtime config checksum sidecar mismatch")
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StagingError(f"runtime config is malformed: {error}") from error
    if not isinstance(value, dict) or data != canonical_document(value):
        raise StagingError("runtime config is not canonical")
    # authority_host_root is retained in this API because installed and bundle
    # callers use different lexical roots; validation itself is data-only.
    if not isinstance(authority_host_root, Path):
        raise StagingError("runtime authority host root is malformed")
    return _validate_runtime_config_contract(value), data


def _runtime_config(root: Path) -> tuple[dict[str, Any], bytes]:
    return _runtime_config_at(
        root / "config" / "runtime.json", root / "authority"
    )


def _map_authority_path(authority_host_root: Path, value: str) -> Path:
    pure = PurePosixPath(value)
    try:
        relative = pure.relative_to(CONTAINER_AUTHORITY_ROOT)
    except ValueError as error:
        raise StagingError("runtime authority path escapes /authority") from error
    return authority_host_root / Path(*relative.parts)


def _verify_runtime_static_files_at(
    authority_host_root: Path, config: dict[str, Any],
) -> None:
    checks: list[tuple[Path, str, str]] = [
        (
            _map_authority_path(authority_host_root, config["policy"]["path"]),
            config["policy"]["sha256"], "policy",
        ),
        (
            _map_authority_path(authority_host_root, config["analyzer"]["path"]),
            config["analyzer"]["sha256"], "analyzer",
        ),
        (
            _map_authority_path(
                authority_host_root, config["fault_injection"]["test_binary"]
            ),
            config["fault_injection"]["test_binary_sha256"], "fault binary",
        ),
        (
            _map_authority_path(
                authority_host_root, config["realworld"]["mirror_authority"]
            ),
            config["realworld"]["mirror_authority_sha256"], "mirror authority",
        ),
    ]
    baseline_authority = config["qualification"]["baseline_authority"]
    baseline_root = _map_authority_path(
        authority_host_root, baseline_authority["root"]
    )
    checks.extend((
        (
            baseline_root / "scripts/determinism_workloads.json",
            baseline_authority["manifest_sha256"],
            "determinism manifest",
        ),
        (
            baseline_root / "scripts/determinism_baseline.json",
            baseline_authority["baseline_sha256"],
            "determinism baseline",
        ),
    ))
    checks.append((
        authority_host_root / "release" / "receipt.json",
        config["qualification"]["release_receipt_sha256"],
        "release candidate receipt",
    ))
    for section in ("quality_floor", "hosted_exact_head"):
        record = config["prerequisites"][section]
        checks.append((
            _map_authority_path(authority_host_root, record["root"])
            / "receipt.json",
            record["receipt_sha256"], f"{section} receipt",
        ))
    checks.append((
        _map_authority_path(
            authority_host_root, config["build_authority"]["root"]
        )
        / "receipt.json",
        config["build_authority"]["receipt_sha256"],
        "build authority receipt",
    ))
    for profile in SANITIZER_PROFILES:
        record = config["sanitizers"][profile]
        checks.append((
            _map_authority_path(authority_host_root, record["root"])
            / "receipt.json",
            record["receipt_sha256"], f"{profile} sanitizer receipt",
        ))
    for path, expected, label in checks:
        if _sha256_regular(path) != expected:
            raise StagingError(f"{label} checksum drift")


def _verify_runtime_static_files(root: Path, config: dict[str, Any]) -> None:
    _verify_runtime_static_files_at(root / "authority", config)


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StagingError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise StagingError(f"{label} is not a real directory")


def _load_trusted_sibling_module(module_name: str, filename: str) -> Any:
    """Execute pinned sibling bytes without a path-reopen or module cache."""

    if (
        not isinstance(module_name, str)
        or not module_name
        or not isinstance(filename, str)
        or Path(filename).name != filename
    ):
        raise StagingError("trusted Python dependency identity is malformed")
    path = Path(__file__).resolve(strict=True).with_name(filename)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StagingError(
            f"trusted Python dependency is unavailable: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= 16 * 1024 * 1024
        ):
            raise StagingError(
                "trusted Python dependency is not a bounded standalone "
                "regular file"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise StagingError("trusted Python dependency was truncated")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise StagingError("trusted Python dependency grew while loading")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        pathname = path.lstat()
    except OSError as error:
        raise StagingError(
            f"cannot recheck trusted Python dependency: {error}"
        ) from error

    def identity(
        metadata: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    if identity(before) != identity(after) or identity(after) != identity(pathname):
        raise StagingError("trusted Python dependency changed while loading")
    raw = b"".join(chunks)
    try:
        code = compile(raw, os.fspath(path), "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as error:
        raise StagingError("cannot compile trusted Python dependency") from error
    module = types.ModuleType(module_name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    try:
        exec(code, module.__dict__)
    except Exception as error:
        raise StagingError(
            f"cannot initialize trusted Python dependency: {error}"
        ) from error
    return module


def _trusted_baseline_authority_verifier() -> Any:
    """Load the exact sibling verifier, never Python from the staged checkout."""

    name = "codeskeptic_staging_baseline_authority_verifier"
    dependency_names = (
        "run_realworld_campaign",
        "run_stability_fault_injection",
    )
    dependencies = {
        dependency: _load_trusted_sibling_module(
            f"codeskeptic_staging_{dependency}", f"{dependency}.py"
        )
        for dependency in dependency_names
    }
    missing = object()
    previous = {
        dependency: sys.modules.get(dependency, missing)
        for dependency in dependency_names
    }
    sys.modules.update(dependencies)
    try:
        module = _load_trusted_sibling_module(
            name, "run_stability_campaign.py"
        )
    finally:
        for dependency, prior in previous.items():
            if prior is missing:
                sys.modules.pop(dependency, None)
            else:
                sys.modules[dependency] = prior
    verifier = getattr(module, "verify_determinism_baseline_authority", None)
    if (
        getattr(module, "RUNTIME_CONFIG_SCHEMA", None) != RUNTIME_CONFIG_SCHEMA
        or not callable(verifier)
    ):
        raise StagingError("trusted baseline authority verifier contract drift")
    def invoke(*args: Any, **kwargs: Any) -> Any:
        # The verifier imports its exact sibling determinism module lazily.
        # Keep that sibling directory authoritative for the whole call, not
        # merely while the stability module itself is loaded.
        scripts = os.fspath(Path(__file__).resolve(strict=True).parent)
        call_inserted = not sys.path or sys.path[0] != scripts
        if call_inserted:
            sys.path.insert(0, scripts)
        try:
            return verifier(*args, **kwargs)
        finally:
            if call_inserted:
                try:
                    sys.path.remove(scripts)
                except ValueError:
                    pass

    return invoke


def _derive_baseline_authority_config(
    source: Path,
    hardware_class: str,
    verifier: Any | None,
) -> dict[str, str]:
    manifest_path = source / "scripts" / "determinism_workloads.json"
    baseline_path = source / "scripts" / "determinism_baseline.json"
    manifest_sha = _sha256_regular(manifest_path)
    baseline_sha = _sha256_regular(baseline_path)
    selected = _trusted_baseline_authority_verifier() if verifier is None else verifier
    if not callable(selected):
        raise StagingError("baseline authority verifier is not callable")
    try:
        verified = selected(
            source, manifest_path, baseline_path, hardware_class
        )
    except StagingError:
        raise
    except Exception as error:
        raise StagingError(
            f"determinism baseline authority verification failed: {error}"
        ) from error
    if not isinstance(verified, dict):
        raise StagingError("baseline authority verifier result is malformed")
    projection = verified.get("projection")
    projection_sha = verified.get("projection_sha256")
    if not isinstance(projection, dict):
        raise StagingError("baseline authority projection is malformed")
    try:
        derived_projection_sha = hashlib.sha256(
            canonical_json(projection)
        ).hexdigest()
    except (TypeError, ValueError) as error:
        raise StagingError("baseline authority projection is malformed") from error
    if projection_sha != derived_projection_sha:
        raise StagingError("baseline authority projection checksum drift")
    if (
        projection.get("schema")
        != "codeskeptic-determinism-baseline-authority-v1"
        or projection.get("hardware_class") != hardware_class
        or projection.get("manifest_sha256") != manifest_sha
        or projection.get("baseline_sha256") != baseline_sha
    ):
        raise StagingError("baseline authority projection identity drift")
    return {
        "root": "/authority/source",
        "manifest_sha256": manifest_sha,
        "baseline_sha256": baseline_sha,
        "projection_sha256": projection_sha,
    }


def _configure_staging_unlocked(
    staging: Path,
    revision: str,
    *,
    repository: str,
    baseline_authority_verifier: Any | None = None,
) -> dict[str, Any]:
    """Publish the canonical runtime config from fixed authority bytes."""

    revision = _valid_git_sha1(revision, "configure revision")
    config_root = staging / "config"
    _require_absent(config_root, "runtime config output")
    try:
        staging_metadata = staging.lstat()
        names = sorted(path.name for path in staging.iterdir())
    except OSError as error:
        raise StagingError(f"cannot inspect configure staging: {error}") from error
    if (
        not stat.S_ISDIR(staging_metadata.st_mode)
        or names != ["authority", "image", "operator", "unit"]
    ):
        raise StagingError("configure staging layout is not exact")
    for name in names:
        _require_real_directory(staging / name, f"staging {name} root")

    authority = staging / "authority"
    source = authority / "source"
    source_identity = validate_staged_source(source, revision)
    _verify_operator_exact_head(
        authority,
        staging / "operator",
        staging / "unit" / UNIT_NAME,
        immutable=False,
    )
    verify_static_unit(staging / "unit" / UNIT_NAME)
    if _read_regular(staging / "unit" / UNIT_NAME) != _read_regular(
        staging / "operator" / UNIT_NAME
    ):
        raise StagingError("operator and staged service units differ")

    required_directories = (
        authority / "build",
        authority / "build-authority",
        authority / "mirrors",
        authority / "release/source",
        authority / "release/build",
        authority / "prerequisites/hosted",
        authority / "prerequisites/quality",
        authority / "sanitizers/address",
        authority / "sanitizers/undefined",
        source / SANITIZER_WORK_ROOT / "address-tests",
        source / SANITIZER_WORK_ROOT / "address-fuzz",
        source / SANITIZER_WORK_ROOT / "undefined-tests",
        source / SANITIZER_WORK_ROOT / "undefined-fuzz",
    )
    for path in required_directories:
        _require_real_directory(path, "runtime authority directory")

    def digest(relative: str) -> str:
        return _sha256_regular(authority / relative)

    undefined_test_binary = (
        source / SANITIZER_WORK_ROOT / "undefined-tests"
        / "tests/codeskeptic_tests"
    )
    hardware_class = "fedora44-i5-1235u-exclusive-pcores-0-3"
    baseline_authority = _derive_baseline_authority_config(
        source, hardware_class, baseline_authority_verifier
    )
    config = _validate_runtime_config_contract({
        "schema": RUNTIME_CONFIG_SCHEMA,
        "policy": {
            "path": "/authority/source/scripts/stability_manifest.json",
            "sha256": digest("source/scripts/stability_manifest.json"),
        },
        "source": {
            "root": "/authority/source",
            "revision": revision,
            "tree_sha1": source_identity["tree_sha1"],
            "manifest_sha256": source_identity["manifest_sha256"],
        },
        "runtime": {
            "image_reference": PINNED_EVIDENCE_IMAGE,
            "image_digest": PINNED_EVIDENCE_IMAGE_DIGEST,
            "image_id": PINNED_EVIDENCE_IMAGE_ID,
            "launch_receipt": "/launch/receipt.json",
        },
        "analyzer": {
            "path": "/authority/build/src/codeskeptic",
            "sha256": digest("build/src/codeskeptic"),
        },
        "build_authority": {
            "root": "/authority/build-authority",
            "receipt_sha256": digest("build-authority/receipt.json"),
            "build_path": "/authority/build",
        },
        "realworld": {
            "mirror_authority": "/authority/mirrors/authority.json",
            "mirror_authority_sha256": digest("mirrors/authority.json"),
        },
        "fault_injection": {
            "test_binary": (
                "/authority/source/build/p10-09-sanitizers/"
                "undefined-tests/tests/codeskeptic_tests"
            ),
            "test_binary_sha256": _sha256_regular(undefined_test_binary),
        },
        "qualification": {
            "hardware_class": hardware_class,
            "measurement_cgroup": RUNTIME_MEASUREMENT_CGROUP,
            "baseline_authority": baseline_authority,
            "release_source": "/authority/release/source",
            "release_build": "/authority/release/build",
            "release_receipt_sha256": digest("release/receipt.json"),
            "jobs": 2,
            "tools": {
                "clang": "/usr/bin/clang-20",
                "time": "/usr/bin/time",
                "cmake": "/usr/bin/cmake",
                "ninja": "/usr/bin/ninja",
                "c_compiler": "/usr/bin/clang-20",
                "cxx_compiler": "/usr/bin/clang++-20",
            },
        },
        "prerequisites": {
            "hosted_exact_head": {
                "root": "/authority/prerequisites/hosted",
                "receipt_sha256": digest(
                    "prerequisites/hosted/receipt.json"
                ),
                "repository": repository,
            },
            "quality_floor": {
                "root": "/authority/prerequisites/quality",
                "receipt_sha256": digest(
                    "prerequisites/quality/receipt.json"
                ),
            },
        },
        "sanitizers": {
            profile: {
                "root": f"/authority/sanitizers/{profile}",
                "receipt_sha256": digest(
                    f"sanitizers/{profile}/receipt.json"
                ),
                "test_build": (
                    "/authority/source/build/p10-09-sanitizers/"
                    f"{profile}-tests"
                ),
                "fuzz_build": (
                    "/authority/source/build/p10-09-sanitizers/"
                    f"{profile}-fuzz"
                ),
            }
            for profile in SANITIZER_PROFILES
        },
    })
    _verify_runtime_static_files_at(authority, config)
    data = canonical_document(config)
    sidecar = (
        f"{hashlib.sha256(data).hexdigest()}  runtime.json\n"
    ).encode("ascii")

    temporary, temporary_metadata, temporary_descriptor = (
        _create_private_temporary_directory(
            staging,
            ".config.runtime-",
            "runtime config staging tree creation failed",
        )
    )
    publication_identity: tuple[int, int] | None = None
    primary: BaseException | None = None
    publication_collision = False
    try:
        _write_new(temporary / "runtime.json", data, 0o600)
        _write_new(temporary / "runtime.json.sha256", sidecar, 0o600)
        _fsync_tree(temporary)
        metadata = temporary.lstat()
        publication_identity = (metadata.st_dev, metadata.st_ino)
        _publish_tree_noreplace(temporary, config_root)
        reloaded, reloaded_data = _runtime_config(staging)
        if reloaded != config or reloaded_data != data:
            raise StagingError("published runtime config identity drift")
        _verify_runtime_static_files(staging, reloaded)
    except FileExistsError as error:
        primary = StagingError("runtime config output appeared concurrently")
        publication_collision = True
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    if temporary != config_root:
        try:
            try:
                remaining_temporary = temporary.lstat()
            except FileNotFoundError:
                remaining_temporary = None
            if remaining_temporary is not None:
                _remove_created_identity(
                    temporary,
                    temporary_metadata.st_dev,
                    temporary_metadata.st_ino,
                    True,
                )
        except Exception as error:
            cleanup_errors.append(error)
    if (
        (primary is not None or cleanup_errors)
        and publication_identity is not None
    ):
        try:
            try:
                published_metadata = config_root.lstat()
            except FileNotFoundError:
                published_metadata = None
            if (
                not publication_collision
                and published_metadata is not None
                and (
                    published_metadata.st_dev,
                    published_metadata.st_ino,
                ) == publication_identity
            ):
                _remove_created_identity(
                    config_root,
                    publication_identity[0],
                    publication_identity[1],
                    True,
                )
            elif published_metadata is not None and not publication_collision:
                raise StagingError(
                    "published runtime config identity changed"
                )
        except Exception as error:
            cleanup_errors.append(error)
    try:
        os.close(temporary_descriptor)
    except OSError as error:
        cleanup_errors.append(error)
    _raise_primary_and_cleanup(
        primary, cleanup_errors, "runtime config publication failed"
    )
    return config


def _normalize_payload_modes(root: Path) -> None:
    for payload_root in _payload_roots(root):
        paths = [payload_root, *sorted(payload_root.rglob("*"), reverse=True)]
        for path in paths:
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                os.chmod(path, 0o555)
            elif stat.S_ISREG(metadata.st_mode):
                executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
                if payload_root.name == "config":
                    mode = 0o400
                else:
                    mode = 0o555 if executable else 0o444
                os.chmod(path, mode)
            else:
                raise StagingError("payload normalization found a special node")


def _seal_staging_unlocked(
    staging: Path,
    revision: str,
    output: Path,
    *,
    command_runner: Any | None = None,
    temporary_root: Path | None = None,
) -> dict[str, Any]:
    """Seal a fully populated authority-layout workspace without replacing."""

    _require_absent(output, "sealed bundle output")
    revision = _valid_git_sha1(revision, "seal revision")
    source_identity = validate_staged_source(
        staging / "authority" / "source", revision
    )
    _verify_operator_exact_head(
        staging / "authority",
        staging / "operator",
        staging / "unit" / UNIT_NAME,
        immutable=False,
    )
    config, config_data = _runtime_config(staging)
    if (
        config["source"]["revision"] != revision
        or config["source"]["tree_sha1"] != source_identity["tree_sha1"]
    ):
        raise StagingError("runtime source identity differs from exact staging HEAD")
    _verify_runtime_static_files(staging, config)
    verify_static_unit(staging / "unit" / UNIT_NAME)
    if _read_regular(staging / "unit" / UNIT_NAME) != _read_regular(
        staging / "operator" / UNIT_NAME
    ):
        raise StagingError("operator and staged service units differ")
    archive = staging / "image" / PINNED_ARCHIVE_NAME
    archive_sha = _sha256_regular(archive)
    # Reject every link, special node, or hard link before copytree has any
    # opportunity to follow or normalize it.
    _collect_payload_inventory(staging)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary, temporary_metadata, temporary_descriptor = (
        _create_private_temporary_directory(
            output.parent,
            f".{output.name}.seal-",
            "sealed bundle staging tree creation failed",
        )
    )
    publication_identity: tuple[int, int] | None = None
    receipt: dict[str, Any] | None = None
    primary: BaseException | None = None
    publication_collision = False
    try:
        for payload_root in _payload_roots(staging):
            shutil.copytree(
                payload_root,
                temporary / payload_root.name,
                symlinks=True,
                copy_function=_copy_regular_exact,
            )
        _normalize_payload_modes(temporary)
        inventory = _collect_payload_inventory(temporary)
        inventory_document = {
            "schema": INVENTORY_SCHEMA,
            "entries": inventory,
        }
        inventory_data = canonical_document(inventory_document)
        inventory_sha = hashlib.sha256(inventory_data).hexdigest()
        receipt = validate_bundle_receipt({
            "schema": BUNDLE_RECEIPT_SCHEMA,
            "revision": revision,
            "source_tree_sha1": source_identity["tree_sha1"],
            "source_manifest_sha256": config["source"]["manifest_sha256"],
            "inventory_sha256": inventory_sha,
            "runtime_config_sha256": hashlib.sha256(config_data).hexdigest(),
            "image_archive_sha256": archive_sha,
            "image_reference": PINNED_EVIDENCE_IMAGE,
            "image_digest": PINNED_EVIDENCE_IMAGE_DIGEST,
            "image_id": PINNED_EVIDENCE_IMAGE_ID,
        })
        metadata = temporary / "bundle"
        metadata.mkdir(mode=0o700)
        receipt_data = canonical_document(receipt)
        _write_new(metadata / "inventory.json", inventory_data, 0o400)
        _write_new(
            metadata / "inventory.json.sha256",
            f"{inventory_sha}  inventory.json\n".encode("ascii"), 0o400,
        )
        receipt_sha = hashlib.sha256(receipt_data).hexdigest()
        _write_new(metadata / "receipt.json", receipt_data, 0o400)
        _write_new(
            metadata / "receipt.json.sha256",
            f"{receipt_sha}  receipt.json\n".encode("ascii"), 0o400,
        )
        sums = b"".join(
            f"{_sha256_regular(metadata / name)}  {name}\n".encode("ascii")
            for name in (
                "inventory.json", "inventory.json.sha256", "receipt.json",
                "receipt.json.sha256",
            )
        )
        _write_new(metadata / "SHA256SUMS", sums, 0o400)
        os.chmod(metadata, 0o500)
        with _large_temporary_workspace(
            temporary_root,
            output.parent,
            required_bytes=_bundle_temporary_requirement(
                temporary, include_snapshot=False
            ),
            forbidden_tree=staging,
        ) as temporary_workspace:
            _verify_trusted_bundle(
                temporary,
                expected_revision=revision,
                expected_bundle_receipt_sha256=receipt_sha,
                command_runner=command_runner,
                temporary_workspace=temporary_workspace,
            )
        _fsync_tree(temporary)
        publication_metadata = temporary.lstat()
        if (
            publication_metadata.st_dev != temporary_metadata.st_dev
            or publication_metadata.st_ino != temporary_metadata.st_ino
        ):
            raise StagingError("sealed bundle staging tree identity changed")
        publication_identity = (
            publication_metadata.st_dev,
            publication_metadata.st_ino,
        )
        _publish_tree_noreplace(temporary, output)
    except FileExistsError as error:
        primary = StagingError("sealed bundle output appeared concurrently")
        publication_collision = True
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    try:
        try:
            remaining_temporary = temporary.lstat()
        except FileNotFoundError:
            remaining_temporary = None
        if remaining_temporary is not None:
            _remove_created_identity(
                temporary,
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
                True,
            )
    except Exception as error:
        cleanup_errors.append(error)
    if (
        (primary is not None or cleanup_errors)
        and publication_identity is not None
    ):
        try:
            try:
                published_metadata = output.lstat()
            except FileNotFoundError:
                published_metadata = None
            if (
                not publication_collision
                and published_metadata is not None
                and (
                    published_metadata.st_dev,
                    published_metadata.st_ino,
                ) == publication_identity
            ):
                _remove_created_identity(
                    output,
                    publication_identity[0],
                    publication_identity[1],
                    True,
                )
            elif (
                published_metadata is not None
                and not publication_collision
            ):
                raise StagingError("published sealed bundle identity changed")
        except Exception as error:
            cleanup_errors.append(error)
    try:
        os.close(temporary_descriptor)
    except OSError as error:
        cleanup_errors.append(error)
    _raise_primary_and_cleanup(
        primary, cleanup_errors, "sealed bundle publication failed"
    )
    assert receipt is not None
    return receipt


def configure_staging(
    staging: Path,
    revision: str,
    *,
    repository: str,
    baseline_authority_verifier: Any | None = None,
) -> dict[str, Any]:
    """Publish runtime config only while authority lifecycle is quiescent."""

    with _authority_lifecycle_lock(staging):
        _reject_unresolved_authority_lifecycle(staging)
        result = _configure_staging_unlocked(
            staging,
            revision,
            repository=repository,
            baseline_authority_verifier=baseline_authority_verifier,
        )
        _reject_unresolved_authority_lifecycle(staging)
        return result


def seal_staging(
    staging: Path,
    revision: str,
    output: Path,
    *,
    command_runner: Any | None = None,
    temporary_root: Path | None = None,
) -> dict[str, Any]:
    """Seal only a quiescent authority tree under the lifecycle lock."""

    with _authority_lifecycle_lock(staging):
        _reject_unresolved_authority_lifecycle(staging)
        result = _seal_staging_unlocked(
            staging,
            revision,
            output,
            command_runner=command_runner,
            temporary_root=temporary_root,
        )
        _reject_unresolved_authority_lifecycle(staging)
        return result


def _verify_bundle_metadata(
    metadata: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Rederive the exact standalone metadata directory."""

    try:
        metadata_stat = metadata.lstat()
        names = sorted(path.name for path in metadata.iterdir())
    except OSError as error:
        raise StagingError(f"cannot inspect bundle metadata: {error}") from error
    if (
        not stat.S_ISDIR(metadata_stat.st_mode)
        or stat.S_IMODE(metadata_stat.st_mode) != 0o500
        or names != [
            "SHA256SUMS", "inventory.json", "inventory.json.sha256",
            "receipt.json", "receipt.json.sha256",
        ]
    ):
        raise StagingError("bundle metadata inventory is not exact")
    for name in names:
        file_metadata = (metadata / name).lstat()
        if (
            not stat.S_ISREG(file_metadata.st_mode)
            or file_metadata.st_nlink != 1
            or stat.S_IMODE(file_metadata.st_mode) != 0o400
        ):
            raise StagingError("bundle metadata file mode or type drift")
    receipt_data = _read_regular(metadata / "receipt.json")
    receipt = validate_bundle_receipt(
        _load_canonical_document(metadata / "receipt.json", "bundle receipt")
    )
    receipt_sha = hashlib.sha256(receipt_data).hexdigest()
    if _read_regular(metadata / "receipt.json.sha256", 1024) != (
        f"{receipt_sha}  receipt.json\n".encode("ascii")
    ):
        raise StagingError("bundle receipt sidecar mismatch")
    inventory_data = _read_regular(metadata / "inventory.json")
    inventory_document = _load_canonical_document(
        metadata / "inventory.json", "bundle inventory"
    )
    if set(inventory_document) != {"schema", "entries"} or (
        inventory_document["schema"] != INVENTORY_SCHEMA
    ):
        raise StagingError("bundle inventory schema drift")
    inventory = _validate_inventory_document(inventory_document["entries"])
    inventory_sha = hashlib.sha256(inventory_data).hexdigest()
    if (
        inventory_sha != receipt["inventory_sha256"]
        or _read_regular(metadata / "inventory.json.sha256", 1024)
        != f"{inventory_sha}  inventory.json\n".encode("ascii")
    ):
        raise StagingError("bundle inventory identity drift")
    expected_sums = b"".join(
        f"{_sha256_regular(metadata / name)}  {name}\n".encode("ascii")
        for name in (
            "inventory.json", "inventory.json.sha256", "receipt.json",
            "receipt.json.sha256",
        )
    )
    if _read_regular(metadata / "SHA256SUMS") != expected_sums:
        raise StagingError("bundle metadata checksum manifest mismatch")
    return receipt, inventory


def _verify_bundle_structure(bundle: Path) -> dict[str, Any]:
    """Rederive all sealed bytes without invoking the container runtime."""

    _payload_roots(bundle)
    receipt, inventory = _verify_bundle_metadata(bundle / "bundle")
    _verify_payload_inventory(bundle, inventory)
    source_identity = validate_staged_source(
        bundle / "authority" / "source", receipt["revision"]
    )
    _verify_operator_exact_head(
        bundle / "authority",
        bundle / "operator",
        bundle / "unit" / UNIT_NAME,
        immutable=True,
    )
    if source_identity["tree_sha1"] != receipt["source_tree_sha1"]:
        raise StagingError("bundle source tree identity drift")
    config, config_data = _runtime_config(bundle)
    if (
        hashlib.sha256(config_data).hexdigest()
        != receipt["runtime_config_sha256"]
        or config["source"]["manifest_sha256"]
        != receipt["source_manifest_sha256"]
    ):
        raise StagingError("bundle runtime/source identity drift")
    if _sha256_regular(bundle / "image" / PINNED_ARCHIVE_NAME) != receipt[
        "image_archive_sha256"
    ]:
        raise StagingError("bundle image archive drift")
    _verify_runtime_static_files(bundle, config)
    verify_static_unit(bundle / "unit" / UNIT_NAME)
    if _read_regular(bundle / "unit" / UNIT_NAME) != _read_regular(
        bundle / "operator" / UNIT_NAME
    ):
        raise StagingError("operator and bundled service units differ")
    return receipt


def _assert_expected_bundle_identity(
    bundle: Path,
    expected_revision: str,
    expected_bundle_receipt_sha256: str,
) -> dict[str, Any]:
    """Bind untrusted bundle claims to operator-supplied authority."""

    expected_revision = _valid_git_sha1(
        expected_revision, "expected bundle revision"
    )
    expected_bundle_receipt_sha256 = _valid_sha256(
        expected_bundle_receipt_sha256,
        "expected bundle receipt checksum",
    )
    receipt_path = bundle / "bundle" / "receipt.json"
    if _sha256_regular(receipt_path, MAX_DOCUMENT_BYTES) != (
        expected_bundle_receipt_sha256
    ):
        raise StagingError("bundle receipt differs from out-of-band authority")
    receipt = validate_bundle_receipt(
        _load_canonical_document(receipt_path, "bundle receipt")
    )
    if receipt["revision"] != expected_revision:
        raise StagingError("bundle revision differs from out-of-band authority")
    return receipt


def _raise_primary_and_cleanup(
    primary: BaseException | None,
    cleanup_errors: list[Exception],
    label: str,
) -> None:
    if primary is not None and cleanup_errors:
        cleanup = "; ".join(str(error) for error in cleanup_errors)
        raise StagingError(
            f"{label}: primary failure: {primary}; cleanup failure: {cleanup}"
        ) from primary
    if primary is not None:
        if isinstance(primary, StagingError):
            raise primary
        if not isinstance(primary, Exception):
            raise primary
        raise StagingError(f"{label}: {primary}") from primary
    if cleanup_errors:
        cleanup = "; ".join(str(error) for error in cleanup_errors)
        raise StagingError(f"{label}: cleanup failure: {cleanup}") from cleanup_errors[0]


def _verify_trusted_bundle(
    bundle: Path,
    *,
    expected_revision: str,
    expected_bundle_receipt_sha256: str,
    command_runner: Any | None,
    temporary_workspace: Path,
) -> dict[str, Any]:
    """Verify one caller-pinned private bundle snapshot."""

    trusted_receipt = _assert_expected_bundle_identity(
        bundle, expected_revision, expected_bundle_receipt_sha256
    )
    receipt = _verify_bundle_structure(bundle)
    if receipt != trusted_receipt:
        raise StagingError("bundle receipt changed after authority binding")
    archive = bundle / "image" / PINNED_ARCHIVE_NAME
    try:
        archive_size = archive.lstat().st_size
    except OSError as error:
        raise StagingError(
            f"cannot inspect pinned image archive size: {error}"
        ) from error
    _temporary_capacity(
        temporary_workspace,
        archive_size * VFS_ARCHIVE_EXPANSION_FACTOR
        + LARGE_TEMPORARY_RESERVE_BYTES,
    )
    image_runtime, image_runtime_metadata, image_runtime_descriptor = (
        _create_private_temporary_directory(
            temporary_workspace,
            "image-runtime-",
            "cannot create private staging image store",
        )
    )
    options: list[str] | None = None
    primary: BaseException | None = None
    try:
        options = _podman_global_options(
            image_runtime / "root",
            image_runtime / "runroot",
            bundle / "operator",
            storage_driver="vfs",
        )
        options = _load_and_verify_image_archive(
            archive,
            podman_root=image_runtime / "root",
            podman_runroot=image_runtime / "runroot",
            hooks=bundle / "operator",
            storage_driver="vfs",
            command_runner=command_runner,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
        _verify_static_authorities_in_image(
            options,
            bundle / "authority",
            bundle / "config" / "runtime.json",
            command_runner,
        )
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    if options is not None:
        try:
            _external_output(
                [*options, "system", "reset", "--force"],
                64 * 1024,
                command_runner,
                timeout_seconds=300,
            )
        except Exception as error:
            cleanup_errors.append(error)
    try:
        _remove_created_identity(
            image_runtime,
            image_runtime_metadata.st_dev,
            image_runtime_metadata.st_ino,
            True,
        )
    except Exception as error:
        cleanup_errors.append(error)
    try:
        os.close(image_runtime_descriptor)
    except OSError as error:
        cleanup_errors.append(error)
    _raise_primary_and_cleanup(
        primary, cleanup_errors, "cannot clean private staging image store"
    )
    return receipt


def verify_bundle(
    bundle: Path,
    *,
    expected_revision: str,
    expected_bundle_receipt_sha256: str,
    command_runner: Any | None = None,
    temporary_root: Path | None = None,
) -> dict[str, Any]:
    """Snapshot and verify a bundle against out-of-band authority."""

    requirement = _bundle_temporary_requirement(
        bundle, include_snapshot=True
    )
    with _large_temporary_workspace(
        temporary_root,
        bundle.parent,
        required_bytes=requirement,
        forbidden_tree=bundle,
    ) as temporary_workspace:
        with _trusted_bundle_snapshot(
            bundle, temporary_workspace
        ) as trusted_bundle:
            return _verify_trusted_bundle(
                trusted_bundle,
                expected_revision=expected_revision,
                expected_bundle_receipt_sha256=(
                    expected_bundle_receipt_sha256
                ),
                command_runner=command_runner,
                temporary_workspace=temporary_workspace,
            )


def _payload_inventory_parts(
    inventory: list[dict[str, Any]],
) -> dict[str, tuple[dict[str, Any], list[dict[str, Any]]]]:
    roots = {name: None for name in ("authority", "config", "image", "operator", "unit")}
    children: dict[str, list[dict[str, Any]]] = {name: [] for name in roots}
    for entry in inventory:
        path = PurePosixPath(entry["path"])
        name = path.parts[0]
        if name not in roots:
            raise StagingError("bundle inventory contains an unknown payload root")
        if len(path.parts) == 1:
            if roots[name] is not None or entry["type"] != "directory":
                raise StagingError("bundle payload root inventory is malformed")
            roots[name] = copy.deepcopy(entry)
            continue
        projected = copy.deepcopy(entry)
        projected["path"] = PurePosixPath(*path.parts[1:]).as_posix()
        children[name].append(projected)
    result: dict[str, tuple[dict[str, Any], list[dict[str, Any]]]] = {}
    for name in roots:
        root_entry = roots[name]
        if root_entry is None:
            raise StagingError(f"bundle inventory omits payload root {name}")
        result[name] = (
            root_entry,
            _validate_inventory_document(children[name]),
        )
    return result


def _installed_payload_roots() -> dict[str, Path]:
    return {
        "authority": AUTHORITY_ROOT,
        "config": CONFIG_PATH.parent,
        "image": INSTALLATION_ROOT / "image",
        "operator": OPERATOR_ROOT,
        "unit": INSTALLATION_ROOT / "unit",
    }


def _collect_mapped_payload_inventory() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for name, root in _installed_payload_roots().items():
        try:
            metadata = root.lstat()
        except OSError as error:
            raise StagingError(f"installed payload root is unavailable: {error}") from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise StagingError("installed payload root is not a real directory")
        entries.append({
            "path": name,
            "type": "directory",
            "mode": _inventory_mode(metadata),
        })
        for item in collect_inventory(root):
            projected = copy.deepcopy(item)
            projected["path"] = f"{name}/{item['path']}"
            entries.append(projected)
    return sorted(entries, key=lambda item: item["path"])


def _verify_mapped_payload_ownership(
    inventory: list[dict[str, Any]], owner_uid: int, owner_gid: int,
) -> None:
    parts = _payload_inventory_parts(inventory)
    for name, destination in _installed_payload_roots().items():
        _root_entry, children = parts[name]
        _verify_installed_ownership(
            destination, children, owner_uid, owner_gid
        )


def _preflight_tree_destination(
    source: Path,
    destination: Path,
    inventory: list[dict[str, Any]],
    owner_uid: int,
    owner_gid: int,
) -> None:
    if not destination.exists() and not destination.is_symlink():
        return
    try:
        verify_inventory(destination, inventory)
        if stat.S_IMODE(destination.lstat().st_mode) != stat.S_IMODE(
            source.lstat().st_mode
        ):
            raise StagingError("pre-existing installation root mode drift")
        _verify_installed_ownership(
            destination, inventory, owner_uid, owner_gid
        )
    except StagingError as error:
        raise StagingError(
            f"pre-existing installation destination differs: {destination}"
        ) from error


def _install_regular_create_new_or_reuse(
    source: Path,
    destination: Path,
    owner_uid: int,
    owner_gid: int,
    *,
    created_nodes: list[_CreatedNode] | None = None,
) -> str:
    source_metadata = source.lstat()
    mode = stat.S_IMODE(source_metadata.st_mode)
    if destination.exists() or destination.is_symlink():
        try:
            destination_metadata = destination.lstat()
            if (
                not stat.S_ISREG(destination_metadata.st_mode)
                or destination_metadata.st_nlink != 1
                or destination_metadata.st_uid != owner_uid
                or destination_metadata.st_gid != owner_gid
                or stat.S_IMODE(destination_metadata.st_mode) != mode
                or destination_metadata.st_size != source_metadata.st_size
                or _sha256_regular(destination) != _sha256_regular(source)
            ):
                raise StagingError("installed regular file identity drift")
        except OSError as error:
            raise StagingError(f"cannot verify installed regular file: {error}") from error
        return "reused"
    try:
        parent_metadata = destination.parent.lstat()
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise StagingError(
                "installation file parent is not a directory"
            )
        _copy_regular_create_new(
            source, destination, mode, owner_uid, owner_gid,
            created_nodes=created_nodes,
        )
    except FileExistsError as error:
        raise StagingError("installation file appeared concurrently") from error
    except OSError as error:
        raise StagingError(f"cannot install regular file: {error}") from error
    return "created"


def _preflight_installation(
    bundle: Path,
    inventory: list[dict[str, Any]],
    owner_uid: int,
    owner_gid: int,
) -> None:
    parts = _payload_inventory_parts(inventory)
    for name, destination in _installed_payload_roots().items():
        _root_entry, children = parts[name]
        _preflight_tree_destination(
            bundle / name, destination, children, owner_uid, owner_gid
        )
    metadata_destination = INSTALLATION_ROOT / "bundle"
    _preflight_tree_destination(
        bundle / "bundle", metadata_destination,
        collect_inventory(bundle / "bundle"), owner_uid, owner_gid,
    )
    retained_unit = INSTALLATION_ROOT / "unit" / UNIT_NAME
    if UNIT_PATH.exists() or UNIT_PATH.is_symlink():
        _install_regular_create_new_or_reuse(
            retained_unit if retained_unit.exists() else bundle / "unit" / UNIT_NAME,
            UNIT_PATH,
            owner_uid,
            owner_gid,
        )
    reject_dropin_authority(UNIT_PATH.parent, UNIT_NAME)
    if INSTALLATION_ROOT.exists() or INSTALLATION_ROOT.is_symlink():
        try:
            metadata = INSTALLATION_ROOT.lstat()
            names = {path.name for path in INSTALLATION_ROOT.iterdir()}
        except OSError as error:
            raise StagingError(f"cannot inspect installation metadata root: {error}") from error
        allowed = {
            "SHA256SUMS", "bundle", "image", "receipt.json",
            "receipt.json.sha256", "unit",
        }
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode)
            not in ({0o500} if "receipt.json" in names else {0o700})
            or not names <= allowed
        ):
            raise StagingError("installation metadata root contains a collision")


def _preflight_fresh_installation() -> None:
    targets = {
        AUTHORITY_ROOT,
        OPERATOR_ROOT,
        CONFIG_PATH.parent,
        UNIT_PATH,
        INSTALLATION_ROOT,
        STATE_ROOT,
    }
    for path in sorted(targets, key=lambda item: len(item.parts)):
        if path.exists() or path.is_symlink():
            raise StagingError(
                f"fresh installation target must be absent: {path}"
            )


def _rollback_created(
    created: list[_CreatedNode],
) -> None:
    failures: list[str] = []
    retained_descendants: list[Path] = []
    for record in reversed(created):
        path, device, inode, is_directory = record
        try:
            if any(
                retained != path and path in retained.parents
                for retained in retained_descendants
            ):
                retained_descendants.append(path)
                failures.append(
                    f"{path}: retained because descendant cleanup failed"
                )
                continue
            _remove_created_identity(
                path, device, inode, is_directory
            )
        except StagingError as error:
            if isinstance(error.__cause__, FileNotFoundError):
                continue
            retained_descendants.append(path)
            failures.append(f"{path}: {error}")
        except OSError as error:
            retained_descendants.append(path)
            failures.append(f"{path}: {error}")
        finally:
            try:
                record.close()
            except OSError as error:
                failures.append(f"{path}: cannot close identity pin: {error}")
    created.clear()
    if failures:
        raise StagingError(
            "installation rollback was incomplete: " + "; ".join(failures)
        )


def _release_created(created: list[_CreatedNode]) -> None:
    failures: list[str] = []
    for record in created:
        try:
            record.close()
        except OSError as error:
            failures.append(f"{record.path}: {error}")
    created.clear()
    if failures:
        raise StagingError(
            "installed identity-pin release was incomplete: "
            + "; ".join(failures)
        )


def _installation_manifest_from_bytes(
    root: Path, receipt_data: bytes, sidecar_data: bytes,
) -> bytes:
    overrides = {
        "receipt.json": hashlib.sha256(receipt_data).hexdigest(),
        "receipt.json.sha256": hashlib.sha256(sidecar_data).hexdigest(),
    }
    paths = (
        "bundle/SHA256SUMS",
        "bundle/inventory.json",
        "bundle/inventory.json.sha256",
        "bundle/receipt.json",
        "bundle/receipt.json.sha256",
        f"image/{PINNED_ARCHIVE_NAME}",
        "receipt.json",
        "receipt.json.sha256",
        f"unit/{UNIT_NAME}",
    )
    lines: list[bytes] = []
    for relative in paths:
        digest = (
            overrides[relative]
            if relative in overrides
            else _sha256_regular(root / relative)
        )
        lines.append(f"{digest}  {relative}\n".encode("ascii"))
    return b"".join(lines)


def _installation_manifest(root: Path) -> bytes:
    paths = (
        "bundle/SHA256SUMS",
        "bundle/inventory.json",
        "bundle/inventory.json.sha256",
        "bundle/receipt.json",
        "bundle/receipt.json.sha256",
        f"image/{PINNED_ARCHIVE_NAME}",
        "receipt.json",
        "receipt.json.sha256",
        f"unit/{UNIT_NAME}",
    )
    return b"".join(
        f"{_sha256_regular(root / relative)}  {relative}\n".encode("ascii")
        for relative in paths
    )


def _preflight_install_base(owner_uid: int, owner_gid: int) -> None:
    base = AUTHORITY_ROOT.parent
    if OPERATOR_ROOT.parent != base or INSTALLATION_ROOT.parent != base:
        raise StagingError("installed /opt payload roots do not share one fixed base")
    if not base.exists() and not base.is_symlink():
        return
    try:
        metadata = base.lstat()
    except OSError as error:
        raise StagingError(f"cannot inspect installed payload base: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) not in {0o555, 0o755}
    ):
        raise StagingError("installed payload base authority drift")


def _ensure_install_base(
    owner_uid: int,
    owner_gid: int,
    created_nodes: list[_CreatedNode],
) -> bool:
    _preflight_install_base(owner_uid, owner_gid)
    base = AUTHORITY_ROOT.parent
    created = False
    if not base.exists() and not base.is_symlink():
        _create_directory_create_new(
            base,
            0o755,
            owner_uid,
            owner_gid,
            created_nodes=created_nodes,
        )
        created = True
    if not created and stat.S_IMODE(base.lstat().st_mode) == 0o555:
        os.chmod(base, 0o755)
    return created


def _installation_receipt_files(
    owner_uid: int, owner_gid: int,
) -> tuple[dict[str, Any], bytes]:
    receipt_path = INSTALLATION_RECEIPT_PATH
    for path in (receipt_path, Path(f"{receipt_path}.sha256")):
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != 0o400
        ):
            raise StagingError("installation receipt file authority drift")
    receipt_data = _read_regular(receipt_path)
    receipt = validate_installation_receipt(
        _load_canonical_document(receipt_path, "installation receipt")
    )
    expected_sidecar = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("ascii")
    if _read_regular(Path(f"{receipt_path}.sha256"), 1024) != expected_sidecar:
        raise StagingError("installation receipt checksum sidecar mismatch")
    return receipt, receipt_data


def _installation_authority_files(
    owner_uid: int, owner_gid: int,
) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = INSTALLATION_AUTHORITY_PATH.lstat()
    except OSError as error:
        raise StagingError(
            f"installation out-of-band authority is unavailable: {error}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise StagingError("installation out-of-band authority metadata drift")
    data = _read_regular(INSTALLATION_AUTHORITY_PATH, 4096)
    value = _load_canonical_document(
        INSTALLATION_AUTHORITY_PATH, "installation out-of-band authority"
    )
    authority = _exact_dict(
        value,
        {"bundle_receipt_sha256", "bundle_revision", "schema"},
        "installation out-of-band authority",
    )
    if authority["schema"] != INSTALLATION_AUTHORITY_SCHEMA:
        raise StagingError("installation out-of-band authority schema drift")
    _valid_git_sha1(authority["bundle_revision"], "authority bundle revision")
    _valid_sha256(
        authority["bundle_receipt_sha256"], "authority bundle receipt checksum"
    )
    if data != canonical_document(authority):
        raise StagingError("installation out-of-band authority is not canonical")
    return copy.deepcopy(authority), data


def install_bundle(
    bundle: Path,
    *,
    expected_revision: str,
    expected_bundle_receipt_sha256: str,
    command_runner: Any | None = None,
    require_root: bool = True,
    owner_uid: int = 0,
    owner_gid: int = 0,
    temporary_root: Path | None = None,
) -> dict[str, Any]:
    """Install a sealed bundle create-new, or verify an exact prior install."""

    if require_root:
        _require_root()
    expected_revision = _valid_git_sha1(
        expected_revision, "expected bundle revision"
    )
    expected_bundle_receipt_sha256 = _valid_sha256(
        expected_bundle_receipt_sha256,
        "expected bundle receipt checksum",
    )
    requirement = _bundle_temporary_requirement(
        bundle, include_snapshot=True
    )
    with _large_temporary_workspace(
        temporary_root,
        bundle.parent,
        required_bytes=requirement,
        forbidden_tree=bundle,
    ) as temporary_workspace, _trusted_bundle_snapshot(
        bundle, temporary_workspace
    ) as trusted_bundle:
        trusted_receipt = _assert_expected_bundle_identity(
            trusted_bundle,
            expected_revision,
            expected_bundle_receipt_sha256,
        )
        receipt = _verify_bundle_structure(trusted_bundle)
        if receipt != trusted_receipt:
            raise StagingError("bundle receipt changed after authority binding")
        _receipt_check, inventory = _verify_bundle_metadata(
            trusted_bundle / "bundle"
        )
        _preflight_installation(
            trusted_bundle, inventory, owner_uid, owner_gid
        )
        _preflight_install_base(owner_uid, owner_gid)
        if (
            INSTALLATION_RECEIPT_PATH.exists()
            or INSTALLATION_RECEIPT_PATH.is_symlink()
        ):
            return verify_installation(
                INSTALLATION_RECEIPT_PATH,
                expected_revision=expected_revision,
                expected_bundle_receipt_sha256=(
                    expected_bundle_receipt_sha256
                ),
                command_runner=command_runner,
                require_root=False,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        _preflight_fresh_installation()

        # Exercise the sealed archive and all static authorities in a private
        # vfs store before changing any fixed host path.
        _verify_trusted_bundle(
            trusted_bundle,
            expected_revision=expected_revision,
            expected_bundle_receipt_sha256=expected_bundle_receipt_sha256,
            command_runner=command_runner,
            temporary_workspace=temporary_workspace,
        )

        created: list[_CreatedNode] = []
        base_created = False
        persistent_store_touched = False
        verified_installation: dict[str, Any] | None = None
        try:
            base_created = _ensure_install_base(
                owner_uid, owner_gid, created
            )
            _create_directory_create_new(
                INSTALLATION_ROOT,
                0o700,
                owner_uid,
                owner_gid,
                created_nodes=created,
            )

            parts = _payload_inventory_parts(inventory)
            for name, destination in _installed_payload_roots().items():
                _root_entry, children = parts[name]
                result = install_tree_create_new(
                    trusted_bundle / name,
                    destination,
                    children,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                    created_nodes=created,
                )
                if result != "created":
                    raise StagingError(
                        "fresh installation unexpectedly reused a payload"
                    )
            metadata_destination = INSTALLATION_ROOT / "bundle"
            result = install_tree_create_new(
                trusted_bundle / "bundle",
                metadata_destination,
                collect_inventory(trusted_bundle / "bundle"),
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                created_nodes=created,
            )
            if result != "created":
                raise StagingError(
                    "fresh installation unexpectedly reused bundle metadata"
                )

            retained_unit = INSTALLATION_ROOT / "unit" / UNIT_NAME
            if _install_regular_create_new_or_reuse(
                retained_unit, UNIT_PATH, owner_uid, owner_gid,
                created_nodes=created,
            ) != "created":
                raise StagingError(
                    "fresh installation unexpectedly reused the live unit"
                )
            _fsync_directory(UNIT_PATH.parent)
            reject_dropin_authority(UNIT_PATH.parent, UNIT_NAME)

            for private in (STATE_ROOT, PODMAN_ROOT):
                if not _ensure_private_directory(
                    private, owner_uid, owner_gid,
                    created_nodes=created,
                ):
                    raise StagingError(
                        "fresh installation unexpectedly reused runtime state"
                    )
            authority_data = canonical_document({
                "bundle_receipt_sha256": expected_bundle_receipt_sha256,
                "bundle_revision": expected_revision,
                "schema": INSTALLATION_AUTHORITY_SCHEMA,
            })
            _write_new(
                INSTALLATION_AUTHORITY_PATH,
                authority_data,
                0o400,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                created_nodes=created,
            )
            _fsync_directory(STATE_ROOT)
            persistent_store_touched = True
            with _fixed_podman_runroot(owner_uid, owner_gid) as runroot:
                options = _load_and_verify_image_archive(
                    trusted_bundle / "image" / PINNED_ARCHIVE_NAME,
                    podman_root=PODMAN_ROOT,
                    podman_runroot=runroot,
                    hooks=OPERATOR_ROOT,
                    storage_driver="overlay",
                    command_runner=command_runner,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                )
                _verify_static_authorities_in_image(
                    options, AUTHORITY_ROOT, CONFIG_PATH, command_runner
                )
            _external_output(
                ["/usr/bin/systemctl", "daemon-reload"], 4096,
                command_runner,
            )
            installed_inventory = _collect_mapped_payload_inventory()
            if installed_inventory != inventory:
                raise StagingError(
                    "installed payload differs from the sealed inventory"
                )
            inventory_sha = hashlib.sha256(canonical_document({
                "schema": INVENTORY_SCHEMA,
                "entries": installed_inventory,
            })).hexdigest()
            if inventory_sha != receipt["inventory_sha256"]:
                raise StagingError(
                    "installed payload inventory checksum drift"
                )
            installation_receipt = validate_installation_receipt({
                "schema": INSTALLATION_RECEIPT_SCHEMA,
                "bundle_revision": expected_revision,
                "bundle_receipt_sha256": _sha256_regular(
                    INSTALLATION_ROOT / "bundle" / "receipt.json"
                ),
                "bundle_inventory_sha256": receipt["inventory_sha256"],
                "installed_inventory_sha256": inventory_sha,
                "authority_root": AUTHORITY_ROOT.as_posix(),
                "operator_root": OPERATOR_ROOT.as_posix(),
                "config_path": CONFIG_PATH.as_posix(),
                "unit_path": UNIT_PATH.as_posix(),
                "image": {
                    "reference": PINNED_EVIDENCE_IMAGE,
                    "digest": PINNED_EVIDENCE_IMAGE_DIGEST,
                    "id": PINNED_EVIDENCE_IMAGE_ID,
                    "archive_sha256": _sha256_regular(
                        INSTALLATION_ROOT / "image" / PINNED_ARCHIVE_NAME
                    ),
                },
            })
            receipt_data = canonical_document(installation_receipt)
            sidecar_data = (
                f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
            ).encode("ascii")
            sidecar_path = Path(f"{INSTALLATION_RECEIPT_PATH}.sha256")
            _write_new(
                sidecar_path,
                sidecar_data,
                0o400,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                created_nodes=created,
            )
            sums_path = INSTALLATION_ROOT / "SHA256SUMS"
            _write_new(
                sums_path,
                _installation_manifest_from_bytes(
                    INSTALLATION_ROOT, receipt_data, sidecar_data
                ),
                0o400,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                created_nodes=created,
            )
            # The receipt is the final create-new commit marker.
            _write_new(
                INSTALLATION_RECEIPT_PATH,
                receipt_data,
                0o400,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                created_nodes=created,
            )
            _fsync_directory(INSTALLATION_ROOT)
            os.chmod(INSTALLATION_ROOT, 0o500)
            os.chmod(AUTHORITY_ROOT.parent, 0o555)
            _fsync_directory(AUTHORITY_ROOT.parent)
            verified_installation = verify_installation(
                INSTALLATION_RECEIPT_PATH,
                expected_revision=expected_revision,
                expected_bundle_receipt_sha256=(
                    expected_bundle_receipt_sha256
                ),
                command_runner=command_runner,
                require_root=False,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        except BaseException as error:
            base = AUTHORITY_ROOT.parent
            live_unit_was_created = any(
                path == UNIT_PATH for path, _device, _inode, _directory in created
            )
            cleanup_errors: list[Exception] = []
            if persistent_store_touched:
                try:
                    _reset_persistent_podman_store(
                        command_runner, owner_uid, owner_gid
                    )
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if base.exists() and not base.is_symlink():
                try:
                    os.chmod(base, 0o755)
                except OSError as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            try:
                _rollback_created(created)
            except Exception as cleanup_error:
                cleanup_errors.append(cleanup_error)
            if live_unit_was_created:
                try:
                    _external_output(
                        ["/usr/bin/systemctl", "daemon-reload"],
                        4096,
                        command_runner,
                        timeout_seconds=30,
                    )
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if not base_created and base.exists() and not base.is_symlink():
                try:
                    os.chmod(base, 0o555)
                    _fsync_directory(base.parent)
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            _raise_primary_and_cleanup(
                error, cleanup_errors, "installation failed"
            )
        # Verification above is the commit boundary. Releasing identity pins
        # can report a descriptor-close failure, but must never re-enter the
        # destructive rollback path after the committed receipt was accepted.
        _release_created(created)
        assert verified_installation is not None
        return verified_installation


def verify_installation_filesystem(
    receipt_path: Path,
    *,
    expected_revision: str,
    expected_bundle_receipt_sha256: str,
    require_root: bool = True,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> dict[str, Any]:
    """Rederive the fixed installation without touching Podman or runroot."""

    if require_root:
        _require_root()
    expected_revision = _valid_git_sha1(
        expected_revision, "expected bundle revision"
    )
    expected_bundle_receipt_sha256 = _valid_sha256(
        expected_bundle_receipt_sha256,
        "expected bundle receipt checksum",
    )
    if receipt_path != INSTALLATION_RECEIPT_PATH:
        raise StagingError("installation receipt path differs from its fixed location")
    receipt, _receipt_data = _installation_receipt_files(
        owner_uid, owner_gid
    )
    if (
        receipt["bundle_revision"] != expected_revision
        or receipt["bundle_receipt_sha256"]
        != expected_bundle_receipt_sha256
    ):
        raise StagingError(
            "installation differs from out-of-band bundle authority"
        )
    authority, _authority_data = _installation_authority_files(
        owner_uid, owner_gid
    )
    expected_authority = {
        "bundle_receipt_sha256": expected_bundle_receipt_sha256,
        "bundle_revision": expected_revision,
        "schema": INSTALLATION_AUTHORITY_SCHEMA,
    }
    if authority != expected_authority or (
        authority["bundle_revision"] != receipt["bundle_revision"]
        or authority["bundle_receipt_sha256"]
        != receipt["bundle_receipt_sha256"]
    ):
        raise StagingError("installation out-of-band authority identity drift")
    try:
        metadata = INSTALLATION_ROOT.lstat()
        names = sorted(path.name for path in INSTALLATION_ROOT.iterdir())
    except OSError as error:
        raise StagingError(f"cannot inspect installed metadata: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != 0o500
        or names != [
            "SHA256SUMS", "bundle", "image", "receipt.json",
            "receipt.json.sha256", "unit",
        ]
    ):
        raise StagingError("installed metadata inventory is not exact")
    base_metadata = AUTHORITY_ROOT.parent.lstat()
    if (
        not stat.S_ISDIR(base_metadata.st_mode)
        or base_metadata.st_uid != owner_uid
        or base_metadata.st_gid != owner_gid
        or stat.S_IMODE(base_metadata.st_mode) != 0o555
    ):
        raise StagingError("installed payload base authority drift")
    for name in ("SHA256SUMS", "receipt.json", "receipt.json.sha256"):
        file_metadata = (INSTALLATION_ROOT / name).lstat()
        if (
            not stat.S_ISREG(file_metadata.st_mode)
            or file_metadata.st_nlink != 1
            or file_metadata.st_uid != owner_uid
            or file_metadata.st_gid != owner_gid
            or stat.S_IMODE(file_metadata.st_mode) != 0o400
        ):
            raise StagingError("installed metadata file authority drift")
    bundle_receipt, inventory = _verify_bundle_metadata(
        INSTALLATION_ROOT / "bundle"
    )
    _verify_installed_ownership(
        INSTALLATION_ROOT / "bundle",
        collect_inventory(INSTALLATION_ROOT / "bundle"),
        owner_uid,
        owner_gid,
    )
    if (
        receipt["bundle_receipt_sha256"]
        != _sha256_regular(INSTALLATION_ROOT / "bundle" / "receipt.json")
        or receipt["bundle_inventory_sha256"]
        != bundle_receipt["inventory_sha256"]
    ):
        raise StagingError("installation receipt differs from bundle metadata")
    if bundle_receipt["revision"] != expected_revision:
        raise StagingError("installed bundle revision authority drift")
    installed_inventory = _collect_mapped_payload_inventory()
    if installed_inventory != inventory:
        raise StagingError("installed payload inventory drift")
    installed_sha = hashlib.sha256(canonical_document({
        "schema": INVENTORY_SCHEMA,
        "entries": installed_inventory,
    })).hexdigest()
    if installed_sha != receipt["installed_inventory_sha256"]:
        raise StagingError("installed inventory checksum drift")
    _verify_mapped_payload_ownership(inventory, owner_uid, owner_gid)
    source_identity = validate_staged_source(
        AUTHORITY_ROOT / "source", bundle_receipt["revision"]
    )
    if source_identity["tree_sha1"] != bundle_receipt["source_tree_sha1"]:
        raise StagingError("installed source tree identity drift")
    config, config_data = _runtime_config_at(CONFIG_PATH, AUTHORITY_ROOT)
    if (
        hashlib.sha256(config_data).hexdigest()
        != bundle_receipt["runtime_config_sha256"]
        or config["source"]["manifest_sha256"]
        != bundle_receipt["source_manifest_sha256"]
    ):
        raise StagingError("installed runtime/source identity drift")
    _verify_runtime_static_files_at(AUTHORITY_ROOT, config)
    archive = INSTALLATION_ROOT / "image" / PINNED_ARCHIVE_NAME
    archive_sha = _sha256_regular(archive)
    if (
        archive_sha != bundle_receipt["image_archive_sha256"]
        or archive_sha != receipt["image"]["archive_sha256"]
    ):
        raise StagingError("installed image archive identity drift")
    retained_unit = INSTALLATION_ROOT / "unit" / UNIT_NAME
    _verify_operator_exact_head(
        AUTHORITY_ROOT, OPERATOR_ROOT, retained_unit, immutable=True
    )
    verify_static_unit(retained_unit)
    if (
        _read_regular(retained_unit) != _read_regular(OPERATOR_ROOT / UNIT_NAME)
        or _read_regular(retained_unit) != _read_regular(UNIT_PATH)
    ):
        raise StagingError("installed service unit identity drift")
    unit_metadata = UNIT_PATH.lstat()
    if (
        unit_metadata.st_uid != owner_uid
        or unit_metadata.st_gid != owner_gid
        or stat.S_IMODE(unit_metadata.st_mode)
        != stat.S_IMODE(retained_unit.lstat().st_mode)
    ):
        raise StagingError("installed live service unit authority drift")
    reject_dropin_authority(UNIT_PATH.parent, UNIT_NAME)
    _reject_operator_hooks(OPERATOR_ROOT)
    _verify_private_directory(STATE_ROOT, owner_uid, owner_gid)
    _verify_private_directory(PODMAN_ROOT, owner_uid, owner_gid)
    _verify_podman_environment(PODMAN_ROOT, owner_uid, owner_gid)
    if _read_regular(INSTALLATION_ROOT / "SHA256SUMS") != (
        _installation_manifest(INSTALLATION_ROOT)
    ):
        raise StagingError("installation checksum manifest mismatch")
    return receipt


def verify_installation(
    receipt_path: Path,
    *,
    expected_revision: str,
    expected_bundle_receipt_sha256: str,
    command_runner: Any | None = None,
    require_root: bool = True,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> dict[str, Any]:
    """Rederive the exact fixed installation and offline runtime authority."""

    receipt = verify_installation_filesystem(
        receipt_path,
        expected_revision=expected_revision,
        expected_bundle_receipt_sha256=expected_bundle_receipt_sha256,
        require_root=require_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    with _fixed_podman_runroot(owner_uid, owner_gid) as runroot:
        options = _podman_global_options(
            PODMAN_ROOT, runroot, OPERATOR_ROOT,
            storage_driver="overlay",
        )
        _verify_pinned_image_store(options, command_runner, run_probe=True)
        _verify_static_authorities_in_image(
            options, AUTHORITY_ROOT, CONFIG_PATH, command_runner
        )
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="version",
        version=f"CodeSkeptic P10-09 staging producer {TOOL_VERSION}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare", help="prepare exact-head staging")
    prepare.add_argument("--source", type=Path, required=True)
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--image-archive", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)

    configure = commands.add_parser(
        "configure", help="materialize the canonical runtime config"
    )
    configure.add_argument("--staging", type=Path, required=True)
    configure.add_argument("--revision", required=True)
    configure.add_argument("--repository", required=True)

    seal = commands.add_parser("seal", help="seal a populated staging tree")
    seal.add_argument("--staging", type=Path, required=True)
    seal.add_argument("--revision", required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--temporary-root", type=Path, required=True)

    verify = commands.add_parser("verify", help="verify a sealed staging bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-revision", required=True)
    verify.add_argument(
        "--expected-bundle-receipt-sha256", required=True
    )
    verify.add_argument("--temporary-root", type=Path, required=True)

    install = commands.add_parser("install", help="install a verified bundle")
    install.add_argument("--bundle", type=Path, required=True)
    install.add_argument("--expected-revision", required=True)
    install.add_argument(
        "--expected-bundle-receipt-sha256", required=True
    )
    install.add_argument("--temporary-root", type=Path, required=True)

    verify_install = commands.add_parser(
        "verify-install", help="verify the fixed installed receipt"
    )
    verify_install.add_argument("--receipt", type=Path, required=True)
    verify_install.add_argument("--expected-revision", required=True)
    verify_install.add_argument(
        "--expected-bundle-receipt-sha256", required=True
    )
    verify_install_filesystem = commands.add_parser(
        "verify-install-filesystem",
        help="verify installed immutable bytes without touching Podman",
    )
    verify_install_filesystem.add_argument(
        "--receipt", type=Path, required=True
    )
    verify_install_filesystem.add_argument("--expected-revision", required=True)
    verify_install_filesystem.add_argument(
        "--expected-bundle-receipt-sha256", required=True
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "prepare":
            prepare_staging(
                arguments.source, arguments.revision,
                arguments.image_archive, arguments.output,
            )
            print(f"CODESKEPTIC_STAGING_PREPARED {arguments.output}")
            return 0
        if arguments.command == "configure":
            configure_staging(
                arguments.staging,
                arguments.revision,
                repository=arguments.repository,
            )
            print(
                "CODESKEPTIC_STAGING_CONFIGURED "
                f"{arguments.staging / 'config' / 'runtime.json'}"
            )
            return 0
        if arguments.command == "seal":
            seal_staging(
                arguments.staging,
                arguments.revision,
                arguments.output,
                temporary_root=arguments.temporary_root,
            )
            print(f"CODESKEPTIC_STAGING_SEALED {arguments.output}")
            return 0
        if arguments.command == "verify":
            verify_bundle(
                arguments.bundle,
                expected_revision=arguments.expected_revision,
                expected_bundle_receipt_sha256=(
                    arguments.expected_bundle_receipt_sha256
                ),
                temporary_root=arguments.temporary_root,
            )
            print(f"CODESKEPTIC_STAGING_VERIFIED {arguments.bundle}")
            return 0
        if arguments.command == "install":
            install_bundle(
                arguments.bundle,
                expected_revision=arguments.expected_revision,
                expected_bundle_receipt_sha256=(
                    arguments.expected_bundle_receipt_sha256
                ),
                temporary_root=arguments.temporary_root,
            )
            print(f"CODESKEPTIC_STAGING_INSTALLED {INSTALLATION_RECEIPT_PATH}")
            return 0
        if arguments.command == "verify-install":
            verify_installation(
                arguments.receipt,
                expected_revision=arguments.expected_revision,
                expected_bundle_receipt_sha256=(
                    arguments.expected_bundle_receipt_sha256
                ),
            )
            print(f"CODESKEPTIC_INSTALLATION_VERIFIED {arguments.receipt}")
            return 0
        if arguments.command == "verify-install-filesystem":
            verify_installation_filesystem(
                arguments.receipt,
                expected_revision=arguments.expected_revision,
                expected_bundle_receipt_sha256=(
                    arguments.expected_bundle_receipt_sha256
                ),
            )
            print(
                "CODESKEPTIC_INSTALLATION_FILESYSTEM_VERIFIED "
                f"{arguments.receipt}"
            )
            return 0
        raise StagingError("staging lifecycle command is unsupported")
    except StagingError as error:
        print(f"CODESKEPTIC_STAGING_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
