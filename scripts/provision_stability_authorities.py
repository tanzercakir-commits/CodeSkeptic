#!/usr/bin/env python3
"""Provision the create-new P10-09 sanitizer and release authorities.

The public commands are deliberately narrow.  They accept one prepared
staging tree and one exact source revision, then launch only the pinned local
evidence image with networking disabled.  Producer and verifier containers
are separate, and final paths are published with Linux no-replace renames.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Any, Iterable

import analyzer_build_authority as build_authority
import run_determinism_qualification as determinism
import run_realworld_campaign as realworld
import run_sanitizer_matrix as sanitizer
import stage_stability_campaign as staging


TOOL_VERSION = "1"
RELEASE_RECEIPT_SCHEMA = "codeskeptic-stability-release-authority-v1"
TRANSACTION_SCHEMA = "codeskeptic-stability-authority-transaction-v1"
TRANSACTION_NAME = ".p10-09-authority-transaction.json"
TRANSACTION_CLEANUP_NAME = TRANSACTION_NAME + ".cleanup"
TRANSACTION_STAGING_SUFFIX = ".staging"
OPERATION_SCHEMA = "codeskeptic-stability-authority-operation-v1"
OPERATION_NAME = ".p10-09-authority-operation.json"
OPERATION_CLEANUP_NAME = OPERATION_NAME + ".cleanup"
OPERATION_STAGING_SUFFIX = ".staging"
WORKSPACE_OWNERSHIP_SCHEMA = "codeskeptic-stability-workspace-ownership-v1"
REJECTION_EVIDENCE_SCHEMA = "codeskeptic-stability-authority-rejection-v1"
PROFILES = ("address", "undefined")
REVISION = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_JSON_BYTES = 8 << 20
MAX_TREE_FILES = 131_072
MAX_TREE_DIRECTORIES = 32_768
MAX_TREE_FILE_BYTES = 512 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 * 1024 * 1024
MAX_CONTAINER_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_REJECTION_MESSAGE_BYTES = 16 * 1024
SANITIZER_CONTAINER_TIMEOUT_SECONDS = 210 * 60
RELEASE_MATERIALIZATION_TIMEOUT_SECONDS = 30 * 60
RELEASE_PREPARATION_TIMEOUT_SECONDS = 330 * 60
RELEASE_CHECKOUT_AND_STARTUP_MARGIN_SECONDS = 30 * 60
RELEASE_POSTPROCESS_TIMEOUT_SECONDS = 60 * 60
RELEASE_CONTAINER_TIMEOUT_SECONDS = (
    RELEASE_MATERIALIZATION_TIMEOUT_SECONDS
    + RELEASE_PREPARATION_TIMEOUT_SECONDS
    + RELEASE_CHECKOUT_AND_STARTUP_MARGIN_SECONDS
    + RELEASE_POSTPROCESS_TIMEOUT_SECONDS
)
CONTAINER_CLEANUP_TIMEOUT_SECONDS = 60
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
SANITIZER_MEMORY_BYTES = 8 * 1024 * 1024 * 1024
RELEASE_MEMORY_BYTES = 12 * 1024 * 1024 * 1024
CONTAINER_CPUS = 4
CONTAINER_PIDS = 512
CONTAINER_NOFILE = 4096
CONTAINER_FILE_BYTES = MAX_TREE_FILE_BYTES
SANITIZER_CONTAINER_FILE_BYTES = max(
    CONTAINER_FILE_BYTES,
    realworld.MAX_PROCESS_FILE_BYTES,
    staging.MAX_FILE_BYTES,
)
RELEASE_CONTAINER_FILE_BYTES = max(
    CONTAINER_FILE_BYTES,
    realworld.SHARD_EMERGENCY_RESERVE_BYTES,
)
RELEASE_CONTAINER_TMPFS_BYTES = staging.LARGE_TEMPORARY_RESERVE_BYTES
SANITIZER_CONTAINER_TMPFS_BYTES = RELEASE_CONTAINER_TMPFS_BYTES + (1 << 30)
SANITIZER_VERIFIER_CTEST_TMPFS_BYTES = 16 * 1024 * 1024
MAX_CONTAINER_WRITABLE_BYTES = MAX_TREE_BYTES
MAX_CONTAINER_WRITABLE_INODES = MAX_TREE_FILES + MAX_TREE_DIRECTORIES
MINIMUM_HOST_FREE_BYTES = 4 * 1024 * 1024 * 1024
WORKSPACE_SCAN_INTERVAL_SECONDS = 2.0
FREE_SPACE_SCAN_INTERVAL_SECONDS = 0.25

CONTAINER_SOURCE = Path("/authority/source")
CONTAINER_MIRRORS = Path("/authority/mirrors")
CONTAINER_RELEASE = Path("/authority/release")
CONTAINER_RELEASE_SOURCE = CONTAINER_RELEASE / "source"
CONTAINER_RELEASE_BUILD = CONTAINER_RELEASE / "build"
CONTAINER_SANITIZER_WORK = CONTAINER_SOURCE / "build/p10-09-sanitizers"
CONTAINER_SANITIZERS = Path("/authority/sanitizers")
CONTAINER_SCRATCH = Path("/work")

CM = Path("/usr/bin/cmake")
NINJA = Path("/usr/bin/ninja")
C_COMPILER = Path("/usr/bin/clang-20")
CXX_COMPILER = Path("/usr/bin/clang++-20")
LLVM_PREFIX = Path("/usr/lib/llvm-20")

KNOWN_AUTHORITY_ENTRIES = {
    "build",
    "build-authority",
    "mirrors",
    "prerequisites",
    "release",
    "sanitizers",
    "source",
}


class ProvisionError(RuntimeError):
    """A create-new authority could not be produced or verified."""


def _tmpfs_mount(capacity_bytes: int) -> str:
    gibibyte = 1 << 30
    if capacity_bytes <= 0 or capacity_bytes % gibibyte != 0:
        raise ProvisionError("container tmpfs capacity is not exact whole GiB")
    return f"/tmp:rw,size={capacity_bytes // gibibyte}g,mode=1777"


RELEASE_CONTAINER_TMPFS = _tmpfs_mount(RELEASE_CONTAINER_TMPFS_BYTES)
SANITIZER_CONTAINER_TMPFS = _tmpfs_mount(SANITIZER_CONTAINER_TMPFS_BYTES)


def _sanitizer_verifier_ctest_tmpfs(profile: str) -> str:
    if profile not in PROFILES:
        raise ProvisionError("sanitizer verifier profile is unsupported")
    mebibyte = 1 << 20
    if SANITIZER_VERIFIER_CTEST_TMPFS_BYTES % mebibyte != 0:
        raise ProvisionError("sanitizer verifier CTest tmpfs is not exact MiB")
    target = (
        CONTAINER_SANITIZER_WORK
        / f"{profile}-tests/Testing/Temporary"
    )
    return (
        f"{target}:rw,nosuid,nodev,"
        f"size={SANITIZER_VERIFIER_CTEST_TMPFS_BYTES // mebibyte}m,mode=1777"
    )


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_file(path: Path, maximum: int | None = None) -> str:
    try:
        return build_authority._hash_regular(
            path,
            MAX_TREE_FILE_BYTES if maximum is None else maximum,
        )
    except Exception as error:
        raise ProvisionError(f"cannot hash regular file {path}: {error}") from error


def _kind(path: Path) -> str:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except OSError as error:
        raise ProvisionError(f"cannot inspect {path}: {error}") from error
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def _real_directory(path: Path, label: str) -> Path:
    path = path.absolute()
    if _kind(path) != "directory" or path.resolve() != path:
        raise ProvisionError(f"{label} is not one real directory")
    return path


def _require_empty_directory(path: Path, label: str) -> Path:
    path = _real_directory(path, label)
    try:
        if next(path.iterdir(), None) is not None:
            raise ProvisionError(f"{label} must be empty")
    except OSError as error:
        raise ProvisionError(f"cannot enumerate {label}: {error}") from error
    return path


def _require_missing(path: Path, label: str) -> None:
    if _kind(path) != "missing":
        raise ProvisionError(f"{label} must be absent")


def _canonical_release_tool(path: Path, label: str) -> Path:
    """Match the determinism runner's canonical executable spelling."""

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ProvisionError(f"cannot resolve release {label}: {error}") from error
    if _kind(resolved) != "regular":
        raise ProvisionError(f"release {label} is not a regular file")
    return resolved


def _tree_identity(root: Path, label: str) -> dict[str, Any]:
    """Bind every regular file and directory without following links."""

    root = _real_directory(root, label)
    entries: list[dict[str, Any]] = []
    file_count = 0
    directory_count = 1
    byte_count = 0

    def fingerprint(value: os.stat_result) -> tuple[int, ...]:
        return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        )

    def hash_file(
        directory_descriptor: int,
        name: str,
        metadata: os.stat_result,
        relative: str,
    ) -> str:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        digest = hashlib.sha256()
        total = 0
        try:
            if fingerprint(os.fstat(descriptor)) != fingerprint(metadata):
                raise ProvisionError(
                    f"{label} file changed while opening: {relative}"
                )
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_TREE_FILE_BYTES:
                    raise ProvisionError(
                        f"{label} contains an oversized file: {relative}"
                    )
                digest.update(block)
            if (
                total != metadata.st_size
                or fingerprint(os.fstat(descriptor)) != fingerprint(metadata)
            ):
                raise ProvisionError(
                    f"{label} file changed while hashing: {relative}"
                )
        finally:
            os.close(descriptor)
        return digest.hexdigest()

    def walk(
        descriptor: int,
        relative_root: str,
        root_device: int,
    ) -> None:
        nonlocal file_count, directory_count, byte_count
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode) or before.st_dev != root_device:
            raise ProvisionError(f"{label} directory authority drift")
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as error:
            raise ProvisionError(f"cannot enumerate {label}: {error}") from error
        for name in names:
            if name in {"", ".", ".."} or "/" in name or "\x00" in name:
                raise ProvisionError(f"{label} contains an unsafe path component")
            relative = name if not relative_root else f"{relative_root}/{name}"
            try:
                metadata = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ProvisionError(
                    f"cannot inspect {label} entry {relative}: {error}"
                ) from error
            mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
            if stat.S_ISDIR(metadata.st_mode):
                directory_count += 1
                if directory_count > MAX_TREE_DIRECTORIES:
                    raise ProvisionError(f"{label} exceeds its directory bound")
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    if fingerprint(os.fstat(child)) != fingerprint(metadata):
                        raise ProvisionError(
                            f"{label} directory changed while opening: {relative}"
                        )
                    entries.append({
                        "path": relative,
                        "type": "directory",
                        "mode": mode,
                    })
                    walk(child, relative, root_device)
                    if fingerprint(os.fstat(child)) != fingerprint(metadata):
                        raise ProvisionError(
                            f"{label} directory changed while reading: {relative}"
                        )
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ProvisionError(
                    f"{label} contains a linked or special node: {relative}"
                )
            if metadata.st_nlink != 1:
                raise ProvisionError(
                    f"{label} contains a hard-linked file: {relative}"
                )
            if metadata.st_size > MAX_TREE_FILE_BYTES:
                raise ProvisionError(
                    f"{label} contains an oversized file: {relative}"
                )
            file_count += 1
            if file_count > MAX_TREE_FILES:
                raise ProvisionError(f"{label} exceeds its file bound")
            byte_count += metadata.st_size
            if byte_count > MAX_TREE_BYTES:
                raise ProvisionError(f"{label} exceeds its byte bound")
            entries.append({
                "path": relative,
                "type": "file",
                "mode": mode,
                "size": metadata.st_size,
                "sha256": hash_file(descriptor, name, metadata, relative),
            })
        try:
            final_names = sorted(os.listdir(descriptor))
            after = os.fstat(descriptor)
        except OSError as error:
            raise ProvisionError(f"cannot recheck {label}: {error}") from error
        if final_names != names or fingerprint(after) != fingerprint(before):
            raise ProvisionError(f"{label} changed during inventory")

    try:
        root_before = root.lstat()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_descriptor = os.open(root, flags)
    except OSError as error:
        raise ProvisionError(f"cannot inspect {label}: {error}") from error
    try:
        if fingerprint(os.fstat(root_descriptor)) != fingerprint(root_before):
            raise ProvisionError(f"{label} changed while opening")
        walk(root_descriptor, "", root_before.st_dev)
        root_after = os.fstat(root_descriptor)
        if fingerprint(root_after) != fingerprint(root_before):
            raise ProvisionError(f"{label} changed during inventory")
    finally:
        os.close(root_descriptor)
    try:
        if fingerprint(root.lstat()) != fingerprint(root_after):
            raise ProvisionError(f"{label} root changed after inventory")
    except OSError as error:
        raise ProvisionError(f"cannot re-inspect {label}: {error}") from error
    entries.sort(key=lambda item: item["path"])
    return {
        "schema": "codeskeptic-stability-tree-identity-v1",
        "root_mode": f"{stat.S_IMODE(root_after.st_mode):04o}",
        "entry_count": len(entries),
        "file_count": file_count,
        "directory_count": directory_count - 1,
        "byte_count": byte_count,
        "entries_sha256": digest_json(entries),
    }


def _validate_staging_root(
    root: Path, revision: str,
) -> tuple[Path, Path, dict[str, str]]:
    if REVISION.fullmatch(revision) is None:
        raise ProvisionError("source revision is malformed")
    root = _real_directory(root, "prepared staging root")
    expected = {"authority", "image", "operator", "unit"}
    try:
        actual = {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise ProvisionError(f"cannot enumerate prepared staging root: {error}") from error
    if actual != expected:
        raise ProvisionError("prepared staging root inventory drift")
    authority = _real_directory(root / "authority", "staging authority root")
    try:
        names = {entry.name for entry in authority.iterdir()}
    except OSError as error:
        raise ProvisionError(f"cannot enumerate staging authority root: {error}") from error
    if "source" not in names or not names <= KNOWN_AUTHORITY_ENTRIES:
        raise ProvisionError("staging authority root inventory drift")
    for name in names:
        _real_directory(authority / name, f"authority {name}")
    source = authority / "source"
    try:
        source_identity = staging.validate_staged_source(source, revision)
    except Exception as error:
        raise ProvisionError(f"staged source authority failed: {error}") from error
    return authority, source, source_identity


@contextmanager
def _lifecycle_lock(staging_root: Path) -> Iterable[None]:
    """Serialize recovery and production for one prepared staging path."""

    root = _real_directory(staging_root, "prepared staging root")
    root_before = root.lstat()
    parent = _real_directory(root.parent, "prepared staging parent")
    parent_before = parent.lstat()
    suffix = hashlib.sha256(root.as_posix().encode("utf-8")).hexdigest()[:32]
    lock_name = f".codeskeptic-p10-09-{suffix}.lock"
    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    parent_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_flags = getattr(os, "O_PATH", os.O_RDONLY)
    root_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_flags |= getattr(os, "O_DIRECTORY", 0)
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    root_descriptor: int | None = None
    descriptor: int | None = None
    locked = False
    try:
        parent_descriptor = os.open(parent, parent_flags)
        opened_parent = os.fstat(parent_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_before.st_dev, parent_before.st_ino
        ):
            raise ProvisionError("authority lifecycle lock parent identity drift")
        root_descriptor = os.open(
            root.name, root_flags, dir_fd=parent_descriptor
        )
        opened_root = os.fstat(root_descriptor)
        if (opened_root.st_dev, opened_root.st_ino) != (
            root_before.st_dev, root_before.st_ino
        ):
            raise ProvisionError("authority lifecycle lock root identity drift")
        descriptor = os.open(
            lock_name,
            lock_flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ProvisionError("authority lifecycle lock identity drift")
        os.fsync(descriptor)
        os.fsync(parent_descriptor)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ProvisionError(
                "authority provisioning is already active for this staging tree"
            ) from error
        locked = True
        current_parent = parent.lstat()
        current_root = os.stat(
            root.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (current_parent.st_dev, current_parent.st_ino) != (
            opened_parent.st_dev, opened_parent.st_ino
        ):
            raise ProvisionError("authority lifecycle lock parent changed")
        if (current_root.st_dev, current_root.st_ino) != (
            opened_root.st_dev, opened_root.st_ino
        ):
            raise ProvisionError("authority lifecycle lock root changed")
        nominal_root = root.lstat()
        if (nominal_root.st_dev, nominal_root.st_ino) != (
            opened_root.st_dev, opened_root.st_ino
        ):
            raise ProvisionError("authority lifecycle lock path changed")
        yield
    except ProvisionError:
        raise
    except OSError as error:
        raise ProvisionError(f"cannot hold authority lifecycle lock: {error}") from error
    finally:
        if descriptor is not None:
            if locked:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _common_container_argv(mode: str) -> list[str]:
    if mode.startswith("sanitizer-"):
        temporary_mount = SANITIZER_CONTAINER_TMPFS
    elif mode.startswith("release-"):
        temporary_mount = RELEASE_CONTAINER_TMPFS
    else:
        raise ProvisionError("container resource mode is unsupported")
    return [
        "$PODMAN",
        "--cgroup-manager=cgroupfs",
        "--conmon=/usr/bin/conmon",
        "--events-backend=none",
        "--hooks-dir=/usr/share/empty",
        "--runtime=/usr/bin/crun",
        "run",
        "--pull=never",
        "--network=none",
        "--http-proxy=false",
        "--env-host=false",
        "--image-volume=ignore",
        "--read-only",
        "--pid=private",
        "--cap-drop=all",
        "--security-opt",
        "label=disable",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        temporary_mount,
        "--workdir",
        os.fspath(CONTAINER_SOURCE),
        "-e",
        "GIT_CONFIG_COUNT=2",
        "-e",
        "GIT_CONFIG_KEY_0=safe.directory",
        "-e",
        f"GIT_CONFIG_VALUE_0={CONTAINER_SOURCE}",
        "-e",
        "GIT_CONFIG_KEY_1=safe.directory",
        "-e",
        f"GIT_CONFIG_VALUE_1={CONTAINER_RELEASE_SOURCE}",
        "-e",
        "GIT_OPTIONAL_LOCKS=0",
        "-e",
        "HOME=/tmp/home",
        "-e",
        "LANG=C",
        "-e",
        "LC_ALL=C",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "TZ=UTC",
        "-e",
        "XDG_CACHE_HOME=/tmp/xdg-cache",
    ]


def _resource_container_argv(mode: str) -> list[str]:
    if mode.startswith("sanitizer-"):
        memory = SANITIZER_MEMORY_BYTES
        file_bytes = SANITIZER_CONTAINER_FILE_BYTES
    elif mode.startswith("release-"):
        memory = RELEASE_MEMORY_BYTES
        file_bytes = RELEASE_CONTAINER_FILE_BYTES
    else:
        raise ProvisionError("container resource mode is unsupported")
    return [
        f"--memory={memory}",
        f"--memory-swap={memory}",
        f"--cpus={CONTAINER_CPUS}",
        f"--pids-limit={CONTAINER_PIDS}",
        f"--ulimit=nofile={CONTAINER_NOFILE}:{CONTAINER_NOFILE}",
        f"--ulimit=fsize={file_bytes}:{file_bytes}",
    ]


def _normalized_container_argv(mode: str, profile: str | None = None) -> list[str]:
    command = _common_container_argv(mode)
    command.extend(_resource_container_argv(mode))
    script = CONTAINER_SOURCE / "scripts/provision_stability_authorities.py"
    if mode in {"sanitizer-produce", "sanitizer-verify"}:
        if profile not in PROFILES:
            raise ProvisionError("sanitizer container profile is unsupported")
        test_build = CONTAINER_SANITIZER_WORK / f"{profile}-tests"
        fuzz_build = CONTAINER_SANITIZER_WORK / f"{profile}-fuzz"
        output = CONTAINER_SANITIZERS / profile
        writable = mode == "sanitizer-produce"
        if not writable:
            # CTest show-only discovery still creates LastTest.log.  Keep the
            # authority build read-only while giving that single verifier-only
            # scratch directory an ephemeral, bounded write target.
            command.extend([
                "--tmpfs", _sanitizer_verifier_ctest_tmpfs(profile)
            ])
        command.extend([
            "-v", f"$SOURCE:{CONTAINER_SOURCE}:ro",
            "-v", f"$TEST_BUILD:{test_build}:{'rw' if writable else 'ro'}",
            "-v", f"$FUZZ_BUILD:{fuzz_build}:{'rw' if writable else 'ro'}",
            "-v", f"$OUTPUT:{output}:{'rw' if writable else 'ro'}",
            build_authority.PINNED_IMAGE,
            "/usr/bin/python3",
            os.fspath(script),
            f"_inner-{mode}",
            "--profile", profile,
        ])
        command.extend(["--revision", "$REVISION"])
        return command
    if mode in {"release-produce", "release-verify"}:
        writable = mode == "release-produce"
        command.extend([
            "-v", f"$SOURCE:{CONTAINER_SOURCE}:ro",
            "-v", f"$MIRRORS:{CONTAINER_MIRRORS}:ro",
            "-v", f"$RELEASE:{CONTAINER_RELEASE}:{'rw' if writable else 'ro'}",
        ])
        if writable:
            command.extend(["-v", f"$SCRATCH:{CONTAINER_SCRATCH}:rw"])
        command.extend([
            build_authority.PINNED_IMAGE,
            "/usr/bin/python3",
            os.fspath(script),
            f"_inner-{mode}",
            "--revision", "$REVISION",
        ])
        return command
    raise ProvisionError("container launch mode is unsupported")


def _expand_argv(tokens: Iterable[str], bindings: dict[str, str]) -> list[str]:
    result: list[str] = []
    for token in tokens:
        expanded = token
        for marker, replacement in bindings.items():
            expanded = expanded.replace(marker, replacement)
        if "$" in expanded:
            raise ProvisionError(f"unbound container argument: {expanded}")
        result.append(expanded)
    return result


def _mount(path: Path, label: str) -> str:
    try:
        return build_authority._mount_path(path, label)
    except Exception as error:
        raise ProvisionError(str(error)) from error


def _sanitizer_container_command(
    mode: str,
    profile: str,
    source: Path,
    test_build: Path,
    fuzz_build: Path,
    output: Path,
    revision: str,
) -> list[str]:
    return _expand_argv(
        _normalized_container_argv(mode, profile),
        {
            "$PODMAN": os.fspath(build_authority.DEFAULT_PODMAN),
            "$SOURCE": _mount(source, "source"),
            "$TEST_BUILD": _mount(test_build, "sanitizer test build"),
            "$FUZZ_BUILD": _mount(fuzz_build, "sanitizer fuzz build"),
            "$OUTPUT": _mount(output, "sanitizer output"),
            "$REVISION": revision,
        },
    )


def _release_container_command(
    mode: str,
    source: Path,
    mirrors: Path,
    release: Path,
    revision: str,
    scratch: Path | None = None,
) -> list[str]:
    bindings = {
        "$PODMAN": os.fspath(build_authority.DEFAULT_PODMAN),
        "$SOURCE": _mount(source, "source"),
        "$MIRRORS": _mount(mirrors, "mirrors"),
        "$RELEASE": _mount(release, "release"),
        "$REVISION": revision,
    }
    if mode == "release-produce":
        if scratch is None:
            raise ProvisionError("release producer scratch is missing")
        bindings["$SCRATCH"] = _mount(scratch, "release scratch")
    return _expand_argv(_normalized_container_argv(mode), bindings)


def _write_container_log(log: Path, data: bytes) -> None:
    if len(data) > MAX_CONTAINER_OUTPUT_BYTES:
        raise ProvisionError("container operator log is oversized")
    try:
        with log.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ProvisionError(f"cannot retain container operator log: {error}") from error


def _container_name(token: str, role: str) -> str:
    if SHA256.fullmatch(token) is None or re.fullmatch(r"[a-z0-9-]+", role) is None:
        raise ProvisionError("provisioner container identity is malformed")
    return f"codeskeptic-p10-09-{token[:16]}-{role}"


def _podman_command(argv: list[str], podman: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return staging._bounded_command(
            [podman, "--events-backend=none", *argv],
            environment=build_authority._podman_environment(),
            cwd=None,
            maximum_output=MAX_CONTAINER_OUTPUT_BYTES,
            timeout_seconds=CONTAINER_CLEANUP_TIMEOUT_SECONDS,
        )
    except Exception as error:
        raise ProvisionError(f"cannot inspect provisioner container: {error}") from error


def _inspect_container(
    reference: str,
    podman: str,
) -> dict[str, Any] | None:
    completed = _podman_command(
        ["container", "inspect", "--format", "{{json .}}", reference],
        podman,
    )
    if completed.returncode != 0:
        exists = _podman_command(["container", "exists", reference], podman)
        if exists.returncode == 1:
            return None
        detail = (completed.stdout + completed.stderr)[-4000:].decode(
            "utf-8", errors="replace"
        )
        raise ProvisionError(f"cannot inspect provisioner container: {detail}")
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"provisioner container inspection is malformed: {error}") from error
    if not isinstance(value, dict):
        raise ProvisionError("provisioner container inspection is malformed")
    return value


def _container_identity(
    value: dict[str, Any],
    token: str,
) -> tuple[str, str]:
    container_id = value.get("Id")
    name = value.get("Name")
    config = value.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(container_id, str)
        or CONTAINER_ID.fullmatch(container_id) is None
        or not isinstance(name, str)
        or not isinstance(labels, dict)
        or labels.get("codeskeptic.provision.token") != token
    ):
        raise ProvisionError("provisioner container ownership drift")
    return container_id, name.removeprefix("/")


def _cleanup_named_container(
    name: str,
    podman: str,
    token: str,
    expected_cid: str | None = None,
) -> None:
    matched_cid = False
    if expected_cid is not None:
        inspected = _inspect_container(expected_cid, podman)
        if inspected is not None:
            container_id, _ = _container_identity(inspected, token)
            if container_id != expected_cid:
                raise ProvisionError("container ID file identity drift")
            matched_cid = True
        else:
            inspected = _inspect_container(name, podman)
    else:
        inspected = _inspect_container(name, podman)
    if inspected is None:
        return
    container_id, inspected_name = _container_identity(inspected, token)
    if not matched_cid and inspected_name != name:
        raise ProvisionError("provisioner container name drift")
    completed = _podman_command(
        ["rm", "--force", "--ignore", container_id],
        podman,
    )
    if completed.returncode != 0:
        raise ProvisionError(
            "cannot clean provisioner container: "
            + (completed.stdout + completed.stderr)[-4000:].decode(
                "utf-8", errors="replace"
            )
        )
    if _inspect_container(container_id, podman) is not None:
        raise ProvisionError("provisioner container survived cleanup")
    replacement = _inspect_container(name, podman)
    if replacement is not None:
        _container_identity(replacement, token)
        raise ProvisionError("provisioner container name was replaced during cleanup")


def _cleanup_container_cidfile(
    cidfile: Path,
    podman: str,
    name: str,
    token: str,
) -> None:
    expected_cid: str | None = None
    if _kind(cidfile) == "missing":
        metadata = None
    else:
        try:
            metadata = cidfile.lstat()
            raw = build_authority._read_regular(cidfile, 128)
            text = raw.decode("ascii")
        except Exception as error:
            raise ProvisionError(f"container ID file is malformed: {error}") from error
        if CONTAINER_ID.fullmatch(text) is None:
            raise ProvisionError("container ID file is malformed")
        expected_cid = text
    _cleanup_named_container(name, podman, token, expected_cid)
    if metadata is not None:
        try:
            _unlink_journaled_file(
                cidfile,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
        except Exception as error:
            raise ProvisionError(f"cannot remove container ID file: {error}") from error


def _writable_bind_roots(command: list[str]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for index, token in enumerate(command[:-1]):
        if token != "-v":
            continue
        fields = command[index + 1].rsplit(":", 2)
        if len(fields) != 3 or fields[2] != "rw":
            continue
        root = Path(fields[0])
        if not root.is_absolute():
            raise ProvisionError("writable container bind is not absolute")
        roots.append(root)
    unique = tuple(dict.fromkeys(roots))
    for root in unique:
        _real_directory(root, "writable container workspace")
    return unique


def _workspace_allocation(roots: tuple[Path, ...]) -> tuple[int, int]:
    allocated = 0
    inodes = 0
    for root in roots:
        try:
            root_metadata = root.lstat()
        except OSError as error:
            raise ProvisionError(
                f"cannot inspect writable container workspace: {error}"
            ) from error
        if not stat.S_ISDIR(root_metadata.st_mode) or root.resolve() != root:
            raise ProvisionError("writable container workspace identity drift")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_descriptor = os.open(root, flags)
        except OSError as error:
            raise ProvisionError(
                f"cannot inspect writable container workspace: {error}"
            ) from error
        try:
            opened_root = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or (opened_root.st_dev, opened_root.st_ino)
                != (root_metadata.st_dev, root_metadata.st_ino)
            ):
                raise ProvisionError("writable container workspace identity drift")

            def revalidate_root() -> None:
                try:
                    final_root = root.lstat()
                except OSError as error:
                    raise ProvisionError(
                        f"cannot inspect writable container workspace: {error}"
                    ) from error
                if (
                    not stat.S_ISDIR(final_root.st_mode)
                    or (final_root.st_dev, final_root.st_ino)
                    != (opened_root.st_dev, opened_root.st_ino)
                ):
                    raise ProvisionError(
                        "writable container workspace identity drift"
                    )

            root_device = opened_root.st_dev
            stack = [root]
            while stack:
                directory = stack.pop()
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            try:
                                metadata = entry.stat(follow_symlinks=False)
                            except FileNotFoundError:
                                # Compilers atomically publish and unlink temporary
                                # object files while this periodic budget scan is
                                # walking the mutable bind.  A vanished entry no
                                # longer consumes blocks or an inode; the next scan
                                # observes the current tree.
                                continue
                            if metadata.st_dev != root_device:
                                raise ProvisionError(
                                    "writable container workspace crosses a filesystem"
                                )
                            inodes += 1
                            allocated += max(
                                metadata.st_size, metadata.st_blocks * 512
                            )
                            if inodes > MAX_CONTAINER_WRITABLE_INODES:
                                revalidate_root()
                                return allocated, inodes
                            if allocated > MAX_CONTAINER_WRITABLE_BYTES:
                                revalidate_root()
                                return allocated, inodes
                            if stat.S_ISDIR(metadata.st_mode):
                                stack.append(Path(entry.path))
                except ProvisionError:
                    raise
                except FileNotFoundError as error:
                    if directory != root:
                        # A queued build directory may be atomically replaced or
                        # removed after its parent DirEntry was accounted.  The
                        # authority root itself remains an identity requirement.
                        continue
                    raise ProvisionError(
                        f"cannot inventory writable container workspace: {error}"
                    ) from error
                except OSError as error:
                    raise ProvisionError(
                        f"cannot inventory writable container workspace: {error}"
                    ) from error
            revalidate_root()
        finally:
            os.close(root_descriptor)
    return allocated, inodes


def _workspace_failure_monitor(
    roots: tuple[Path, ...],
) -> Any:
    filesystems: dict[int, Path] = {}
    for root in roots:
        metadata = root.lstat()
        filesystems.setdefault(metadata.st_dev, root)
    for root in filesystems.values():
        filesystem = os.statvfs(root)
        available = filesystem.f_bavail * filesystem.f_frsize
        if available < MINIMUM_HOST_FREE_BYTES + MAX_CONTAINER_WRITABLE_BYTES:
            raise ProvisionError(
                "insufficient emergency reserve for writable container workspace"
            )

    last_free_scan = 0.0
    last_tree_scan = 0.0

    def monitor() -> str | None:
        nonlocal last_free_scan, last_tree_scan
        now = time.monotonic()
        if now - last_free_scan >= FREE_SPACE_SCAN_INTERVAL_SECONDS:
            last_free_scan = now
            try:
                for root in filesystems.values():
                    filesystem = os.statvfs(root)
                    available = filesystem.f_bavail * filesystem.f_frsize
                    if available < MINIMUM_HOST_FREE_BYTES:
                        return "writable workspace exhausted host free-space reserve"
            except OSError as error:
                return f"cannot monitor host free-space reserve: {error}"
        if now - last_tree_scan >= WORKSPACE_SCAN_INTERVAL_SECONDS:
            last_tree_scan = now
            try:
                allocated, inodes = _workspace_allocation(roots)
            except ProvisionError as error:
                return str(error)
            if allocated > MAX_CONTAINER_WRITABLE_BYTES:
                return "writable workspace exceeds allocated-byte limit"
            if inodes > MAX_CONTAINER_WRITABLE_INODES:
                return "writable workspace exceeds inode limit"
        return None

    initial = monitor()
    if initial is not None:
        raise ProvisionError(initial)
    return monitor


def _run_bounded_container(
    command: list[str],
    log: Path,
    cidfile: Path,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    if timeout_seconds <= staging.IMAGE_LOAD_TIMEOUT_SECONDS:
        return staging._bounded_command(
            command,
            environment=build_authority._podman_environment(),
            cwd=None,
            maximum_output=MAX_CONTAINER_OUTPUT_BYTES,
            timeout_seconds=timeout_seconds,
        )
    stdout_path = log.with_suffix(log.suffix + ".stdout.partial")
    stderr_path = log.with_suffix(log.suffix + ".stderr.partial")
    _require_missing(stdout_path, "container stdout staging file")
    _require_missing(stderr_path, "container stderr staging file")
    writable_roots = _writable_bind_roots(command)
    workspace_monitor = (
        _workspace_failure_monitor(writable_roots)
        if writable_roots
        else None
    )
    completed = determinism._run_bounded_process(
        command,
        build_authority._podman_environment(),
        timeout_seconds,
        stdout_path,
        stderr_path,
        [cidfile],
        maximum_bytes=MAX_CONTAINER_OUTPUT_BYTES,
        file_size_limit_bytes=None,
        failure_monitor=workspace_monitor,
    )
    for path in (stdout_path, stderr_path):
        metadata = path.lstat()
        _unlink_journaled_file(
            path,
            expected_device=metadata.st_dev,
            expected_inode=metadata.st_ino,
        )
    return completed


def _execute_container(
    command: list[str],
    log: Path,
    *,
    timeout_seconds: int = SANITIZER_CONTAINER_TIMEOUT_SECONDS,
    invocation_token: str | None = None,
    container_role: str = "operation",
) -> None:
    cidfile = log.with_suffix(log.suffix + ".cid")
    _require_missing(log, "container operator log")
    _require_missing(cidfile, "container ID file")
    try:
        run_index = command.index("run")
    except ValueError as error:
        raise ProvisionError("container command omits podman run") from error
    token = secrets.token_hex(32) if invocation_token is None else invocation_token
    name = _container_name(token, container_role)
    launched = [
        *command[:run_index + 1],
        "--cidfile", os.fspath(cidfile),
        "--name", name,
        "--label", f"codeskeptic.provision.token={token}",
        *command[run_index + 1:],
    ]
    primary: BaseException | None = None
    completed: subprocess.CompletedProcess[bytes] | None = None
    try:
        completed = _run_bounded_container(
            launched,
            log,
            cidfile,
            timeout_seconds,
        )
        output = completed.stdout + completed.stderr
        _write_container_log(log, output)
        if completed.returncode != 0:
            primary = ProvisionError(
                f"pinned authority container failed with exit {completed.returncode}"
            )
    except BaseException as error:
        primary = error
        if _kind(log) == "missing":
            try:
                _write_container_log(
                    log,
                    (f"container execution failed: {error}\n").encode(
                        "utf-8", errors="replace"
                    ),
                )
            except Exception as log_error:
                primary = ProvisionError(
                    f"container execution and log retention failed: {error}; {log_error}"
                )
    cleanup_error: Exception | None = None
    try:
        _cleanup_container_cidfile(cidfile, command[0], name, token)
    except Exception as error:
        cleanup_error = error
    if primary is not None:
        if (
            isinstance(primary, (KeyboardInterrupt, SystemExit))
            and cleanup_error is None
        ):
            raise primary
        if cleanup_error is not None:
            raise ProvisionError(
                f"container execution failed: {primary}; cleanup failed: {cleanup_error}"
            ) from primary
        if isinstance(primary, ProvisionError):
            raise primary
        raise ProvisionError(f"container execution failed: {primary}") from primary
    if completed is None:
        raise ProvisionError("container execution produced no result")
    if cleanup_error is not None:
        raise cleanup_error
    if _kind(log) != "regular" or not 0 < log.stat().st_size <= MAX_CONTAINER_OUTPUT_BYTES:
        raise ProvisionError("container operator log is empty or oversized")


def _sanitizer_configure_commands(
    profile: str, test_build: Path, fuzz_build: Path, source: Path = CONTAINER_SOURCE,
) -> tuple[list[str], list[str]]:
    if profile not in PROFILES:
        raise ProvisionError("sanitizer profile is unsupported")
    common = [
        os.fspath(CM),
        "-S", os.fspath(source),
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        f"-DCMAKE_MAKE_PROGRAM={NINJA}",
        f"-DCMAKE_C_COMPILER={C_COMPILER}",
        f"-DCMAKE_CXX_COMPILER={CXX_COMPILER}",
        f"-DCMAKE_PREFIX_PATH={LLVM_PREFIX}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DCODESKEPTIC_SANITIZER={profile}",
    ]
    tests = [
        *common[:3], "-B", os.fspath(test_build), *common[3:],
        "-DCODESKEPTIC_BUILD_TESTS=ON",
        "-DCODESKEPTIC_BUILD_FUZZERS=OFF",
    ]
    fuzz = [
        *common[:3], "-B", os.fspath(fuzz_build), *common[3:],
        "-DCODESKEPTIC_BUILD_TESTS=OFF",
        "-DCODESKEPTIC_BUILD_FUZZERS=ON",
    ]
    return tests, fuzz


def _run_configure(command: list[str], source: Path) -> None:
    try:
        completed = subprocess.run(
            command,
            cwd=source,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProvisionError(f"sanitizer configure could not run: {error}") from error
    if completed.returncode != 0:
        raise ProvisionError(
            "sanitizer configure failed: "
            + completed.stdout[-4000:].decode("utf-8", errors="replace")
        )


def _inner_populate_sanitizer(profile: str, revision: str) -> dict[str, Any]:
    if profile not in PROFILES or REVISION.fullmatch(revision) is None:
        raise ProvisionError("inner sanitizer authority arguments are invalid")
    test_build = CONTAINER_SANITIZER_WORK / f"{profile}-tests"
    fuzz_build = CONTAINER_SANITIZER_WORK / f"{profile}-fuzz"
    output = CONTAINER_SANITIZERS / profile
    for path, label in (
        (test_build, "sanitizer test build"),
        (fuzz_build, "sanitizer fuzz build"),
        (output, "sanitizer output"),
    ):
        _require_empty_directory(path, label)
    commands = _sanitizer_configure_commands(profile, test_build, fuzz_build)
    for command in commands:
        _run_configure(command, CONTAINER_SOURCE)
    try:
        produced = sanitizer.execute(profile, test_build, fuzz_build, output)
        verified = sanitizer.verify_receipt(output, test_build, fuzz_build)
    except Exception as error:
        raise ProvisionError(f"sanitizer authority rejected: {error}") from error
    if produced != verified:
        raise ProvisionError("sanitizer producer and verifier projections differ")
    source = verified.get("source", {})
    if source.get("base_commit") != revision or verified.get("profile") != profile:
        raise ProvisionError("sanitizer receipt exact source/profile drift")
    print(f"CODESKEPTIC_SANITIZER_AUTHORITY_OK {profile}")
    return verified


def _inner_verify_sanitizer(profile: str, revision: str) -> dict[str, Any]:
    if profile not in PROFILES or REVISION.fullmatch(revision) is None:
        raise ProvisionError("inner sanitizer verifier profile is invalid")
    test_build = CONTAINER_SANITIZER_WORK / f"{profile}-tests"
    fuzz_build = CONTAINER_SANITIZER_WORK / f"{profile}-fuzz"
    output = CONTAINER_SANITIZERS / profile
    try:
        receipt = sanitizer.verify_receipt(output, test_build, fuzz_build)
    except Exception as error:
        raise ProvisionError(f"sanitizer authority verification failed: {error}") from error
    if (
        receipt.get("profile") != profile
        or receipt.get("source", {}).get("base_commit") != revision
    ):
        raise ProvisionError("sanitizer verifier source/profile drift")
    print(f"CODESKEPTIC_SANITIZER_AUTHORITY_VERIFIED {profile}")
    return receipt


def _load_release_inputs(repo: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest_path = repo / "scripts/determinism_workloads.json"
    raw_manifest = determinism.load_manifest(manifest_path)
    workload = next(
        (item for item in raw_manifest["workloads"] if item["kind"] == "release-candidate"),
        None,
    )
    if workload is None:
        raise ProvisionError("determinism manifest omits release-candidate workload")
    realworld_path = repo / workload["input"]["realworld_manifest"]
    realworld_manifest = realworld.load_manifest(realworld_path)
    project = realworld.project_by_id(
        realworld_manifest, workload["input"]["project"]
    )
    return raw_manifest, workload, project


def _release_projection(
    repo: Path,
    release_root: Path,
    mirror_root: Path,
    revision: str,
) -> dict[str, Any]:
    if REVISION.fullmatch(revision) is None:
        raise ProvisionError("release source revision is malformed")
    repo = _real_directory(repo, "CodeSkeptic source authority")
    release_root = _real_directory(release_root, "release authority root")
    mirror_root = _real_directory(mirror_root, "mirror authority root")
    source = _real_directory(release_root / "source", "release source")
    build = _real_directory(release_root / "build", "release build")
    try:
        source_identity = determinism.source_manifest(repo)
        if source_identity["revision"] != revision:
            raise ProvisionError("release authority CodeSkeptic revision drift")
        raw_manifest, workload, project = _load_release_inputs(repo)
        realworld_manifest = realworld.load_manifest(
            repo / workload["input"]["realworld_manifest"]
        )
        release_campaign = realworld_manifest["campaigns"]["release-candidate"]
        mirror_project, selected_root = realworld.load_mirror_authority(
            mirror_root / "authority.json",
            realworld_manifest,
            project["id"],
            expected_project_ids=release_campaign["projects"],
        )
        if selected_root != mirror_root:
            raise ProvisionError("release mirror root identity drift")
        release_identity = determinism._release_identity(repo, workload, source)
        if determinism._git_output(
            source,
            ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        ):
            raise ProvisionError("release checkout is not clean")
        tree = determinism._git_output(source, ["rev-parse", "HEAD^{tree}"])
        if tree != mirror_project["tree"]:
            raise ProvisionError("release checkout tree differs from mirror authority")
        entries = determinism._load_compile_database(build / "compile_commands.json")
        sources = [
            determinism._inside(source, relative, "release-candidate TU")
            for relative in workload["input"]["translation_units"]
        ]
        roots = determinism._normalization_roots(
            repo, "release-candidate", source, build
        )
        extra = dict(release_identity)
        extra["selected_compile_commands_sha256"] = determinism._compile_identity(
            entries, sources, roots
        )
        build_toolchain = determinism._build_toolchain_identity(
            build, source, CM, NINJA, C_COMPILER, CXX_COMPILER
        )
        extra["build_toolchain"] = build_toolchain
        input_receipt = determinism._input_receipt(
            "release-candidate", sources, source, entries, roots, extra
        )
        manifest_sha = determinism.digest_json(raw_manifest)
        baseline_path = repo / "scripts/determinism_baseline.json"
        baseline = determinism.load_baseline(baseline_path, manifest_sha)
        reference = baseline["semantic_reference"]["release-candidate"]
        comparisons = {
            "input_identity_sha256": input_receipt["identity_sha256"],
            "translation_unit_sha256": input_receipt["translation_unit_sha256"],
            "translation_unit_plan_sha256": input_receipt[
                "translation_unit_plan_sha256"
            ],
        }
        for field, actual in comparisons.items():
            if actual != reference[field]:
                raise ProvisionError(f"release baseline {field} drift")
        inventories = {
            "source": _tree_identity(source, "release source"),
            "build": _tree_identity(build, "release build"),
        }
    except ProvisionError:
        raise
    except Exception as error:
        raise ProvisionError(f"cannot derive release authority: {error}") from error

    receipt = {
        "schema": RELEASE_RECEIPT_SCHEMA,
        "status": "prepared",
        "source": source_identity,
        "image": {
            "reference": build_authority.PINNED_IMAGE,
            "digest": build_authority.PINNED_IMAGE_DIGEST,
            "id": build_authority.PINNED_IMAGE_ID,
        },
        "manifests": {
            "determinism_sha256": manifest_sha,
            "baseline_sha256": sha256_file(baseline_path, MAX_JSON_BYTES),
            "realworld_sha256": determinism.digest_json(realworld_manifest),
            "workload_sha256": determinism.digest_json(workload),
        },
        "mirror": {
            "authority_sha256": sha256_file(
                mirror_root / "authority.json", realworld.MAX_MIRROR_AUTHORITY_BYTES
            ),
            "project_sha256": realworld.digest_json(mirror_project),
        },
        "release": {
            **release_identity,
            "tree": tree,
        },
        "layout": {
            "source": os.fspath(CONTAINER_RELEASE_SOURCE),
            "build": os.fspath(CONTAINER_RELEASE_BUILD),
            "jobs": 2,
        },
        "compile": {
            "database_sha256": sha256_file(
                build / "compile_commands.json", determinism.MAX_JSON_BYTES
            ),
            "input_identity_sha256": input_receipt["identity_sha256"],
            "translation_units": input_receipt["translation_units"],
            "translation_unit_sha256": input_receipt["translation_unit_sha256"],
            "translation_unit_plan_sha256": input_receipt[
                "translation_unit_plan_sha256"
            ],
            "selected_compile_commands_sha256": input_receipt["extra"][
                "selected_compile_commands_sha256"
            ],
        },
        "build_toolchain": build_toolchain,
        "inventories": inventories,
    }
    return receipt


def _write_release_receipt(release_root: Path, receipt: dict[str, Any]) -> None:
    data = canonical_json(receipt)
    receipt_path = release_root / "receipt.json"
    sidecar_path = release_root / "receipt.json.sha256"
    try:
        with receipt_path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        sidecar = f"{hashlib.sha256(data).hexdigest()}  receipt.json\n".encode("ascii")
        with sidecar_path.open("xb") as stream:
            stream.write(sidecar)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ProvisionError(f"cannot publish release receipt: {error}") from error


def _normalize_release_payload_modes(release_root: Path) -> None:
    """Apply the exact modes that sealing will retain for release payloads."""

    for root in (
        release_root / "source",
        release_root / "build",
    ):
        root = _real_directory(root, "release payload")
        paths = [root, *sorted(root.rglob("*"), reverse=True)]
        for path in paths:
            try:
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    os.chmod(path, 0o555, follow_symlinks=False)
                elif stat.S_ISREG(metadata.st_mode):
                    executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
                    os.chmod(
                        path,
                        0o555 if executable else 0o444,
                        follow_symlinks=False,
                    )
                else:
                    raise ProvisionError(
                        f"release payload contains a linked or special node: {path}"
                    )
            except ProvisionError:
                raise
            except OSError as error:
                raise ProvisionError(
                    f"cannot normalize release payload mode {path}: {error}"
                ) from error


def _read_release_receipt(release_root: Path) -> dict[str, Any]:
    expected_names = {"build", "source", "receipt.json", "receipt.json.sha256"}
    try:
        names = {entry.name for entry in release_root.iterdir()}
    except OSError as error:
        raise ProvisionError(f"cannot enumerate release authority: {error}") from error
    if names != expected_names:
        raise ProvisionError("release authority root inventory drift")
    receipt_path = release_root / "receipt.json"
    try:
        raw = build_authority._read_regular(receipt_path, MAX_JSON_BYTES)
        sidecar = build_authority._read_regular(
            release_root / "receipt.json.sha256", 256
        )
    except Exception as error:
        raise ProvisionError(f"cannot read release receipt: {error}") from error
    if len(raw) > MAX_JSON_BYTES:
        raise ProvisionError("release receipt is oversized")
    expected_sidecar = f"{hashlib.sha256(raw).hexdigest()}  receipt.json\n".encode(
        "ascii"
    )
    if sidecar != expected_sidecar:
        raise ProvisionError("release receipt sidecar mismatch")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"release receipt is malformed: {error}") from error
    if raw != canonical_json(payload):
        raise ProvisionError("release receipt is not canonical JSON")
    return payload


def verify_release_authority_in_current_runtime(
    release_root: Path,
    repo: Path,
    mirror_root: Path,
    revision: str,
) -> dict[str, Any]:
    """Re-derive the full release receipt inside the pinned runtime."""

    release_root = _real_directory(release_root, "release authority root")
    before = _read_release_receipt(release_root)
    if before.get("schema") != RELEASE_RECEIPT_SCHEMA or before.get("status") != "prepared":
        raise ProvisionError("release receipt status or schema drift")
    expected = _release_projection(repo, release_root, mirror_root, revision)
    if before != expected:
        raise ProvisionError("release receipt differs from re-derived authority")
    after = _read_release_receipt(release_root)
    if after != before:
        raise ProvisionError("release authority changed during verification")
    final_inventories = {
        "source": _tree_identity(release_root / "source", "release source"),
        "build": _tree_identity(release_root / "build", "release build"),
    }
    if final_inventories != before.get("inventories"):
        raise ProvisionError("release authority inventory changed during verification")
    return before


def _inner_populate_release(revision: str) -> dict[str, Any]:
    if REVISION.fullmatch(revision) is None:
        raise ProvisionError("inner release revision is malformed")
    _require_empty_directory(CONTAINER_RELEASE_SOURCE, "release source")
    _require_empty_directory(CONTAINER_RELEASE_BUILD, "release build")
    _require_empty_directory(CONTAINER_SCRATCH, "release scratch")
    raw_manifest, workload, project = _load_release_inputs(CONTAINER_SOURCE)
    realworld_manifest = realworld.load_manifest(
        CONTAINER_SOURCE / workload["input"]["realworld_manifest"]
    )
    campaign = realworld_manifest["campaigns"]["release-candidate"]
    mirror_project, mirror_root = realworld.load_mirror_authority(
        CONTAINER_MIRRORS / "authority.json",
        realworld_manifest,
        project["id"],
        expected_project_ids=campaign["projects"],
    )
    log_path = CONTAINER_SCRATCH / "mirror-materialization.log"
    cmake = _canonical_release_tool(CM, "CMake")
    ninja = _canonical_release_tool(NINJA, "Ninja")
    c_compiler = _canonical_release_tool(C_COMPILER, "C compiler")
    cxx_compiler = _canonical_release_tool(CXX_COMPILER, "C++ compiler")
    try:
        with realworld._bounded_shard_workspace(CONTAINER_SCRATCH) as private:
            repositories = realworld._materialize_offline_repositories(
                project,
                mirror_project,
                mirror_root,
                private / "transport",
                time.monotonic() + RELEASE_MATERIALIZATION_TIMEOUT_SECONDS,
                log_path,
            )
            checkout_repository = repositories[project["repository"]].absolute().as_uri()
            determinism.prepare_release_candidate(
                CONTAINER_SOURCE,
                workload,
                None,
                2,
                cmake,
                ninja,
                c_compiler,
                cxx_compiler,
                release_source=CONTAINER_RELEASE_SOURCE,
                release_build=CONTAINER_RELEASE_BUILD,
                checkout_repository=checkout_repository,
            )
    except Exception as error:
        raise ProvisionError(f"offline release preparation failed: {error}") from error
    _normalize_release_payload_modes(CONTAINER_RELEASE)
    receipt = _release_projection(
        CONTAINER_SOURCE, CONTAINER_RELEASE, CONTAINER_MIRRORS, revision
    )
    _write_release_receipt(CONTAINER_RELEASE, receipt)
    verified = verify_release_authority_in_current_runtime(
        CONTAINER_RELEASE, CONTAINER_SOURCE, CONTAINER_MIRRORS, revision
    )
    print("CODESKEPTIC_RELEASE_AUTHORITY_OK")
    return verified


def _inner_verify_release(revision: str) -> dict[str, Any]:
    receipt = verify_release_authority_in_current_runtime(
        CONTAINER_RELEASE, CONTAINER_SOURCE, CONTAINER_MIRRORS, revision
    )
    print("CODESKEPTIC_RELEASE_AUTHORITY_VERIFIED")
    return receipt


def _remove_tree_entry_at(
    parent_descriptor: int,
    name: str,
    root_device: int,
    *,
    expected_device: int | None = None,
    expected_inode: int | None = None,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != root_device
            or (
                expected_device is not None
                and metadata.st_dev != expected_device
            )
            or (
                expected_inode is not None
                and metadata.st_ino != expected_inode
            )
        ):
            raise ProvisionError("journaled workspace identity drift")
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) | 0o700)
        for child in os.listdir(descriptor):
            child_metadata = os.stat(
                child, dir_fd=descriptor, follow_symlinks=False
            )
            if child_metadata.st_dev != root_device:
                raise ProvisionError(
                    "journaled workspace crosses a filesystem boundary"
                )
            if stat.S_ISDIR(child_metadata.st_mode):
                _remove_tree_entry_at(
                    descriptor,
                    child,
                    root_device,
                )
            else:
                os.unlink(child, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_descriptor)


def _remove_journaled_tree(
    path: Path,
    *,
    expected_device: int | None = None,
    expected_inode: int | None = None,
    cleanup_path: Path | None = None,
) -> None:
    cleanup = (
        path.with_name(path.name + ".cleanup")
        if cleanup_path is None
        else cleanup_path
    )
    if cleanup.parent != path.parent or cleanup == path:
        raise ProvisionError("journaled workspace cleanup path drift")
    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    parent_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    owned_flags = getattr(os, "O_PATH", os.O_RDONLY)
    owned_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    owned_flags |= getattr(os, "O_DIRECTORY", 0)
    parent_descriptor: int | None = None
    owned_descriptor: int | None = None
    try:
        parent_descriptor = os.open(path.parent, parent_flags)
        source_present = _kind(path) != "missing"
        cleanup_present = _kind(cleanup) != "missing"
        if source_present and cleanup_present:
            raise ProvisionError("both workspace and cleanup quarantine exist")
        if not source_present and not cleanup_present:
            return
        selected = path.name if source_present else cleanup.name
        owned_descriptor = os.open(
            selected, owned_flags, dir_fd=parent_descriptor
        )
        pinned = os.fstat(owned_descriptor)
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or (
                expected_device is not None
                and pinned.st_dev != expected_device
            )
            or (
                expected_inode is not None
                and pinned.st_ino != expected_inode
            )
        ):
            raise ProvisionError("journaled workspace identity drift")
        if source_present:
            staging._rename_noreplace_at(
                parent_descriptor,
                path.name,
                parent_descriptor,
                cleanup.name,
            )
            os.fsync(parent_descriptor)
        quarantined = os.stat(
            cleanup.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(quarantined.st_mode)
            or (quarantined.st_dev, quarantined.st_ino)
            != (pinned.st_dev, pinned.st_ino)
        ):
            raise ProvisionError("journaled workspace quarantine identity drift")
        _remove_tree_entry_at(
            parent_descriptor,
            cleanup.name,
            pinned.st_dev,
            expected_device=pinned.st_dev,
            expected_inode=pinned.st_ino,
        )
        os.fsync(parent_descriptor)
    except ProvisionError:
        raise
    except OSError as error:
        raise ProvisionError(
            f"cannot remove journaled workspace {path}: {error}"
        ) from error
    finally:
        if owned_descriptor is not None:
            os.close(owned_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _unlink_journaled_file(
    path: Path,
    *,
    expected_device: int | None = None,
    expected_inode: int | None = None,
    cleanup_path: Path | None = None,
) -> None:
    cleanup = (
        path.with_name(path.name + ".cleanup")
        if cleanup_path is None
        else cleanup_path
    )
    if cleanup.parent != path.parent or cleanup == path:
        raise ProvisionError("journaled file cleanup path drift")
    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    parent_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = getattr(os, "O_PATH", os.O_RDONLY)
    file_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = os.open(path.parent, parent_flags)
        source_present = _kind(path) != "missing"
        cleanup_present = _kind(cleanup) != "missing"
        if source_present and cleanup_present:
            raise ProvisionError("both journaled file paths exist")
        if not source_present and not cleanup_present:
            return
        selected = path.name if source_present else cleanup.name
        descriptor = os.open(selected, file_flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (
                expected_device is not None
                and metadata.st_dev != expected_device
            )
            or (
                expected_inode is not None
                and metadata.st_ino != expected_inode
            )
        ):
            raise ProvisionError("journaled file identity drift")
        if source_present:
            staging._rename_noreplace_at(
                parent_descriptor,
                path.name,
                parent_descriptor,
                cleanup.name,
            )
            os.fsync(parent_descriptor)
        quarantined = os.stat(
            cleanup.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(quarantined.st_mode)
            or quarantined.st_nlink != 1
            or (quarantined.st_dev, quarantined.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise ProvisionError("journaled file quarantine identity drift")
        os.unlink(cleanup.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except ProvisionError:
        raise
    except OSError as error:
        raise ProvisionError(
            f"cannot remove journaled file {path}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _remove_private(record: dict[str, Any]) -> None:
    path = record["path"]
    cleanup = record["cleanup"]
    parent = record["parent"]
    prefix = record["prefix"]
    if (
        path.parent != parent
        or cleanup.parent != parent
        or not path.name.startswith(prefix)
        or cleanup.name != path.name + ".cleanup"
    ):
        raise ProvisionError("refusing to remove an unowned authority workspace")
    try:
        if _kind(path) != "missing" or _kind(cleanup) != "missing":
            _remove_journaled_tree(
                path,
                expected_device=record["device"],
                expected_inode=record["inode"],
                cleanup_path=cleanup,
            )
        ownership = record["ownership"]
        if (
            _kind(ownership["path"]) != "missing"
            or _kind(ownership["cleanup"]) != "missing"
        ):
            _unlink_journaled_file(
                ownership["path"],
                expected_device=ownership["device"],
                expected_inode=ownership["inode"],
                cleanup_path=ownership["cleanup"],
            )
    except Exception as error:
        raise ProvisionError(f"cannot remove private authority workspace: {error}") from error


def _publish_journal_file(
    source: Path,
    destination: Path,
    *,
    expected_device: int,
    expected_inode: int,
) -> None:
    if source == destination:
        raise ProvisionError("journal publication path drift")
    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    parent_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = getattr(os, "O_PATH", os.O_RDONLY)
    file_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_parent_descriptor: int | None = None
    destination_parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        source_parent_descriptor = os.open(source.parent, parent_flags)
        destination_parent_descriptor = (
            source_parent_descriptor
            if source.parent == destination.parent
            else os.open(destination.parent, parent_flags)
        )
        descriptor = os.open(
            source.name, file_flags, dir_fd=source_parent_descriptor
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (expected_device, expected_inode)
        ):
            raise ProvisionError("journal publication identity drift")
        staging._rename_noreplace_at(
            source_parent_descriptor,
            source.name,
            destination_parent_descriptor,
            destination.name,
        )
        os.fsync(source_parent_descriptor)
        if destination_parent_descriptor != source_parent_descriptor:
            os.fsync(destination_parent_descriptor)
        published = os.stat(
            destination.name,
            dir_fd=destination_parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(published.st_mode)
            or published.st_nlink != 1
            or (published.st_dev, published.st_ino)
            != (expected_device, expected_inode)
        ):
            raise ProvisionError("published journal identity drift")
    except ProvisionError:
        raise
    except FileExistsError as error:
        raise ProvisionError("journal destination appeared concurrently") from error
    except OSError as error:
        raise ProvisionError(f"cannot publish journal: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if (
            destination_parent_descriptor is not None
            and destination_parent_descriptor != source_parent_descriptor
        ):
            os.close(destination_parent_descriptor)
        if source_parent_descriptor is not None:
            os.close(source_parent_descriptor)


def _journal_staging_candidates(
    authority: Path, name: str, suffix: str,
) -> list[Path]:
    prefix = name + "."
    candidates: list[Path] = []
    try:
        entries = list(authority.iterdir())
    except OSError as error:
        raise ProvisionError(f"cannot inspect authority journals: {error}") from error
    for entry in entries:
        candidate = entry.name
        logical = (
            candidate[:-len(".cleanup")]
            if candidate.endswith(suffix + ".cleanup")
            else candidate
        )
        if not logical.startswith(prefix) or not logical.endswith(suffix):
            continue
        token = logical[len(prefix):-len(suffix)]
        if SHA256.fullmatch(token) is None:
            raise ProvisionError("authority journal staging name drift")
        logical_path = authority / logical
        if logical_path not in candidates:
            candidates.append(logical_path)
    if len(candidates) > 1:
        raise ProvisionError("multiple authority journal staging files exist")
    return candidates


def _transaction_path(authority: Path) -> Path:
    return authority / TRANSACTION_NAME


def _operation_path(authority: Path) -> Path:
    return authority / OPERATION_NAME


def _operation_workspaces(kind: str, token: str) -> list[dict[str, str]]:
    def workspace(base: str, path: str, role: str) -> dict[str, str]:
        return {
            "base": base,
            "path": path,
            "cleanup": path + ".cleanup",
            "ownership": path + ".owner.json",
            "ownership_cleanup": path + ".owner.json.cleanup",
            "ownership_staging": path + "/.codeskeptic-owner.json",
            "ownership_staging_cleanup": (
                path + "/.codeskeptic-owner.json.cleanup"
            ),
            "role": role,
        }

    if kind == "sanitizers":
        return [
            workspace(
                "authority",
                f"source/build/.p10-09-sanitizers.{token}",
                "sanitizer-build",
            ),
            workspace(
                "authority",
                f".sanitizers.{token}",
                "sanitizer-receipts",
            ),
            workspace(
                "parent",
                f".sanitizer-logs.{token}",
                "operator-logs",
            ),
        ]
    if kind == "release":
        return [
            workspace(
                "authority", f".release.{token}", "release-authority"
            ),
            workspace(
                "parent", f".release-scratch.{token}", "release-scratch"
            ),
            workspace(
                "parent", f".release-logs.{token}", "operator-logs"
            ),
        ]
    raise ProvisionError("authority operation kind is unsupported")


def _operation_container_roles(kind: str) -> tuple[str, ...]:
    if kind == "sanitizers":
        return tuple(
            f"{profile}-{mode}"
            for profile in PROFILES
            for mode in ("produce", "verify")
        )
    if kind == "release":
        return ("release-produce", "release-verify")
    raise ProvisionError("authority operation kind is unsupported")


def _operation_material(
    staging_root: Path,
    authority: Path,
    kind: str,
    revision: str,
    token: str,
    marker_device: int,
    marker_inode: int,
) -> dict[str, Any]:
    parent = staging_root.parent
    authority_metadata = authority.lstat()
    parent_metadata = parent.lstat()
    material = {
        "schema": OPERATION_SCHEMA,
        "kind": kind,
        "revision": revision,
        "token": token,
        "staging": staging_root.as_posix(),
        "authority": {
            "path": authority.as_posix(),
            "device": authority_metadata.st_dev,
            "inode": authority_metadata.st_ino,
        },
        "parent": {
            "path": parent.as_posix(),
            "device": parent_metadata.st_dev,
            "inode": parent_metadata.st_ino,
        },
        "marker": {
            "device": marker_device,
            "inode": marker_inode,
        },
        "workspaces": _operation_workspaces(kind, token),
    }
    return {**material, "identity_sha256": digest_json(material)}


def _validate_operation_payload(
    staging_root: Path,
    authority: Path,
    value: Any,
    revision: str,
) -> dict[str, Any]:
    fields = {
        "schema", "kind", "revision", "token", "staging", "authority",
        "parent", "marker", "workspaces", "identity_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ProvisionError("authority operation fields drift")
    token = value["token"]
    if (
        value["schema"] != OPERATION_SCHEMA
        or value["revision"] != revision
        or not isinstance(token, str)
        or SHA256.fullmatch(token) is None
        or value["staging"] != staging_root.as_posix()
        or not isinstance(value["identity_sha256"], str)
        or SHA256.fullmatch(value["identity_sha256"]) is None
    ):
        raise ProvisionError("authority operation identity drift")
    material = {key: value[key] for key in fields - {"identity_sha256"}}
    if value["identity_sha256"] != digest_json(material):
        raise ProvisionError("authority operation checksum drift")
    for label, path, record in (
        ("authority", authority, value["authority"]),
        ("parent", staging_root.parent, value["parent"]),
    ):
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "device", "inode"}
        ):
            raise ProvisionError(f"authority operation {label} is malformed")
        metadata = path.lstat()
        if record != {
            "path": path.as_posix(),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }:
            raise ProvisionError(f"authority operation {label} drift")
    marker = value["marker"]
    if (
        not isinstance(marker, dict)
        or set(marker) != {"device", "inode"}
        or type(marker["device"]) is not int
        or type(marker["inode"]) is not int
        or marker["device"] < 0
        or marker["inode"] <= 0
    ):
        raise ProvisionError("authority operation marker is malformed")
    expected = _operation_workspaces(value["kind"], token)
    if value["workspaces"] != expected:
        raise ProvisionError("authority operation workspace drift")
    return value


def _write_operation(
    staging_root: Path,
    authority: Path,
    kind: str,
    revision: str,
) -> dict[str, Any]:
    marker = _operation_path(authority)
    _require_missing(marker, "authority operation marker")
    _require_missing(
        authority / OPERATION_CLEANUP_NAME,
        "authority operation completed marker",
    )
    token = secrets.token_hex(32)
    staging_marker = authority / (
        f"{OPERATION_NAME}.{token}{OPERATION_STAGING_SUFFIX}"
    )
    _require_missing(staging_marker, "authority operation staging marker")
    _require_missing(
        staging_marker.with_name(staging_marker.name + ".cleanup"),
        "authority operation staging marker cleanup",
    )
    payload: dict[str, Any] | None = None
    created_identity: tuple[int, int] | None = None
    try:
        with staging_marker.open("xb") as stream:
            opened = os.fstat(stream.fileno())
            created_identity = (opened.st_dev, opened.st_ino)
            payload = _operation_material(
                staging_root,
                authority,
                kind,
                revision,
                token,
                opened.st_dev,
                opened.st_ino,
            )
            data = canonical_json(payload)
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        staging._fsync_directory(authority)
        _publish_journal_file(
            staging_marker,
            marker,
            expected_device=created_identity[0],
            expected_inode=created_identity[1],
        )
    except Exception as error:
        if created_identity is not None:
            try:
                if (
                    _kind(staging_marker) != "missing"
                    or _kind(
                        staging_marker.with_name(staging_marker.name + ".cleanup")
                    ) != "missing"
                ):
                    _unlink_journaled_file(
                        staging_marker,
                        expected_device=created_identity[0],
                        expected_inode=created_identity[1],
                    )
            except Exception as cleanup_error:
                raise ProvisionError(
                    "authority operation creation and cleanup failed: "
                    f"{error}; {cleanup_error}"
                ) from error
        raise ProvisionError(
            f"cannot create authority operation marker: {error}"
        ) from error
    assert payload is not None
    return payload


def _read_operation(
    staging_root: Path,
    authority: Path,
    revision: str,
) -> dict[str, Any] | None:
    marker = _operation_path(authority)
    candidates = _journal_staging_candidates(
        authority, OPERATION_NAME, OPERATION_STAGING_SUFFIX
    )
    if candidates:
        staged = candidates[0]
        staged_cleanup = staged.with_name(staged.name + ".cleanup")
        if (
            _kind(marker) != "missing"
            or _kind(authority / OPERATION_CLEANUP_NAME) != "missing"
        ):
            raise ProvisionError(
                "operation staging and published markers both exist"
            )
        actual = (
            staged
            if _kind(staged) != "missing"
            else staged_cleanup
        )
        metadata = actual.lstat()
        try:
            raw = build_authority._read_regular(actual, MAX_JSON_BYTES)
            payload = json.loads(raw.decode("utf-8"))
            if raw != canonical_json(payload):
                raise ProvisionError(
                    "staged authority operation marker is not canonical"
                )
            value = _validate_operation_payload(
                staging_root, authority, payload, revision
            )
            token = staged.name[
                len(OPERATION_NAME) + 1:-len(OPERATION_STAGING_SUFFIX)
            ]
            marker_identity = value["marker"]
            if (
                value["token"] != token
                or (metadata.st_dev, metadata.st_ino)
                != (marker_identity["device"], marker_identity["inode"])
            ):
                raise ProvisionError(
                    "staged authority operation marker identity drift"
                )
        except Exception:
            _unlink_journaled_file(
                staged,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
                cleanup_path=staged_cleanup,
            )
            return None
        if actual == staged_cleanup:
            _publish_journal_file(
                staged_cleanup,
                marker,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
        else:
            _publish_journal_file(
                staged,
                marker,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
    if _kind(marker) == "missing":
        cleanup = authority / OPERATION_CLEANUP_NAME
        if _kind(cleanup) == "missing":
            return None
        try:
            metadata = cleanup.lstat()
            raw = build_authority._read_regular(cleanup, MAX_JSON_BYTES)
            payload = json.loads(raw.decode("utf-8"))
        except Exception as error:
            raise ProvisionError(
                f"completed authority operation marker is unreadable: {error}"
            ) from error
        if raw != canonical_json(payload):
            raise ProvisionError(
                "completed authority operation marker is not canonical"
            )
        value = _validate_operation_payload(
            staging_root, authority, payload, revision
        )
        marker_identity = value["marker"]
        if (metadata.st_dev, metadata.st_ino) != (
            marker_identity["device"], marker_identity["inode"]
        ):
            raise ProvisionError(
                "completed authority operation marker identity drift"
            )
        _unlink_journaled_file(
            marker,
            expected_device=marker_identity["device"],
            expected_inode=marker_identity["inode"],
            cleanup_path=cleanup,
        )
        return None
    try:
        raw = build_authority._read_regular(marker, MAX_JSON_BYTES)
        payload = json.loads(raw.decode("utf-8"))
    except Exception as error:
        raise ProvisionError(
            f"authority operation marker is unreadable: {error}"
        ) from error
    if raw != canonical_json(payload):
        raise ProvisionError("authority operation marker is not canonical")
    value = _validate_operation_payload(
        staging_root, authority, payload, revision
    )
    metadata = marker.lstat()
    marker_identity = value["marker"]
    if (metadata.st_dev, metadata.st_ino) != (
        marker_identity["device"], marker_identity["inode"]
    ):
        raise ProvisionError("authority operation marker identity drift")
    return value


def _workspace_path(
    staging_root: Path,
    authority: Path,
    record: dict[str, str],
    field: str = "path",
) -> Path:
    base = authority if record["base"] == "authority" else staging_root.parent
    return base / record[field]


def _workspace_ownership_material(
    operation: dict[str, Any],
    record: dict[str, str],
    metadata: os.stat_result,
    marker_metadata: os.stat_result,
) -> dict[str, Any]:
    material = {
        "schema": WORKSPACE_OWNERSHIP_SCHEMA,
        "token": operation["token"],
        "role": record["role"],
        "path": record["path"],
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "marker": {
            "device": marker_metadata.st_dev,
            "inode": marker_metadata.st_ino,
        },
    }
    return {**material, "identity_sha256": digest_json(material)}


def _write_workspace_ownership(
    staging_root: Path,
    authority: Path,
    operation: dict[str, Any],
    record: dict[str, str],
    metadata: os.stat_result,
) -> dict[str, Any]:
    path = _workspace_path(staging_root, authority, record, "ownership")
    cleanup = _workspace_path(
        staging_root, authority, record, "ownership_cleanup"
    )
    staged = _workspace_path(
        staging_root, authority, record, "ownership_staging"
    )
    staged_cleanup = _workspace_path(
        staging_root, authority, record, "ownership_staging_cleanup"
    )
    _require_missing(path, "workspace ownership record")
    _require_missing(cleanup, "workspace ownership cleanup record")
    _require_missing(staged, "workspace ownership staging record")
    _require_missing(staged_cleanup, "workspace ownership staging cleanup record")
    payload: dict[str, Any] | None = None
    created: os.stat_result | None = None
    try:
        with staged.open("xb") as stream:
            created = os.fstat(stream.fileno())
            payload = _workspace_ownership_material(
                operation, record, metadata, created
            )
            stream.write(canonical_json(payload))
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        staging._fsync_directory(staged.parent)
        # Persist the workspace entry only after its internal ownership record
        # is durable.  The following cross-directory rename then publishes the
        # same ownership inode as the external recovery sidecar.
        staging._fsync_directory(path.parent)
        _publish_journal_file(
            staged,
            path,
            expected_device=created.st_dev,
            expected_inode=created.st_ino,
        )
    except Exception as error:
        if created is not None:
            try:
                internal_present = (
                    _kind(staged) != "missing"
                    or _kind(staged_cleanup) != "missing"
                )
                external_present = (
                    _kind(path) != "missing"
                    or _kind(cleanup) != "missing"
                )
                if internal_present and external_present:
                    raise ProvisionError(
                        "workspace ownership exists at multiple publication paths"
                    )
                if internal_present:
                    _unlink_journaled_file(
                        staged,
                        expected_device=created.st_dev,
                        expected_inode=created.st_ino,
                        cleanup_path=staged_cleanup,
                    )
                if external_present:
                    _unlink_journaled_file(
                        path,
                        expected_device=created.st_dev,
                        expected_inode=created.st_ino,
                        cleanup_path=cleanup,
                    )
            except Exception as cleanup_error:
                raise ProvisionError(
                    "workspace ownership creation and cleanup failed: "
                    f"{error}; {cleanup_error}"
                ) from error
        raise ProvisionError(
            f"cannot retain workspace ownership: {error}"
        ) from error
    assert created is not None and payload is not None
    return {
        "path": path,
        "cleanup": cleanup,
        "device": payload["marker"]["device"],
        "inode": payload["marker"]["inode"],
    }


def _validate_workspace_ownership_payload(
    operation: dict[str, Any],
    record: dict[str, str],
    payload: Any,
    raw: bytes,
    metadata: os.stat_result,
) -> dict[str, Any]:
    fields = {
        "schema", "token", "role", "path", "device", "inode", "marker",
        "identity_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ProvisionError("workspace ownership fields drift")
    material = {key: payload[key] for key in fields - {"identity_sha256"}}
    marker = payload["marker"]
    if (
        payload["schema"] != WORKSPACE_OWNERSHIP_SCHEMA
        or payload["token"] != operation["token"]
        or payload["role"] != record["role"]
        or payload["path"] != record["path"]
        or type(payload["device"]) is not int
        or type(payload["inode"]) is not int
        or payload["device"] < 0
        or payload["inode"] <= 0
        or not isinstance(marker, dict)
        or set(marker) != {"device", "inode"}
        or type(marker["device"]) is not int
        or type(marker["inode"]) is not int
        or marker["device"] < 0
        or marker["inode"] <= 0
        or (metadata.st_dev, metadata.st_ino)
        != (marker["device"], marker["inode"])
        or payload["identity_sha256"] != digest_json(material)
        or raw != canonical_json(payload)
    ):
        raise ProvisionError("workspace ownership identity drift")
    return payload


def _read_workspace_ownership(
    staging_root: Path,
    authority: Path,
    operation: dict[str, Any],
    record: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    path = _workspace_path(staging_root, authority, record, "ownership")
    cleanup = _workspace_path(
        staging_root, authority, record, "ownership_cleanup"
    )
    staged = _workspace_path(
        staging_root, authority, record, "ownership_staging"
    )
    staged_cleanup = _workspace_path(
        staging_root, authority, record, "ownership_staging_cleanup"
    )
    staged_present = [
        candidate for candidate in (staged, staged_cleanup)
        if _kind(candidate) != "missing"
    ]
    present = [candidate for candidate in (path, cleanup) if _kind(candidate) != "missing"]
    if len(staged_present) > 1 or len(present) > 1:
        raise ProvisionError("both workspace ownership paths exist")
    if staged_present and present:
        raise ProvisionError("staged and published workspace ownership both exist")
    if staged_present:
        actual = staged_present[0]
        metadata = actual.lstat()
        try:
            raw = build_authority._read_regular(actual, MAX_JSON_BYTES)
            payload = json.loads(raw.decode("utf-8"))
            value = _validate_workspace_ownership_payload(
                operation, record, payload, raw, metadata
            )
        except Exception as error:
            raise ProvisionError(
                "staged workspace ownership is invalid; workspace and marker "
                f"retained: {error}"
            ) from error
        _publish_journal_file(
            actual,
            path,
            expected_device=value["marker"]["device"],
            expected_inode=value["marker"]["inode"],
        )
        present = [path]
    if not present:
        workspace = _workspace_path(staging_root, authority, record)
        workspace_cleanup = _workspace_path(
            staging_root, authority, record, "cleanup"
        )
        if (
            _kind(workspace) != "missing"
            or _kind(workspace_cleanup) != "missing"
        ):
            raise ProvisionError(
                "workspace ownership is missing; unowned path retained: "
                f"{workspace}"
            )
        return None
    actual = present[0]
    try:
        metadata = actual.lstat()
        raw = build_authority._read_regular(actual, MAX_JSON_BYTES)
        payload = json.loads(raw.decode("utf-8"))
    except Exception as error:
        raise ProvisionError(f"workspace ownership is unreadable: {error}") from error
    payload = _validate_workspace_ownership_payload(
        operation, record, payload, raw, metadata
    )
    return payload, {
        "path": path,
        "cleanup": cleanup,
        "device": payload["marker"]["device"],
        "inode": payload["marker"]["inode"],
    }


def _create_operation_workspace(
    staging_root: Path,
    authority: Path,
    operation: dict[str, Any],
    role: str,
    owned: list[dict[str, Any]],
) -> Path:
    record = next(
        (item for item in operation["workspaces"] if item["role"] == role),
        None,
    )
    if record is None:
        raise ProvisionError(f"authority operation role is missing: {role}")
    path = _workspace_path(staging_root, authority, record)
    cleanup = _workspace_path(staging_root, authority, record, "cleanup")
    _require_missing(path, f"authority operation workspace {role}")
    _require_missing(cleanup, f"authority operation cleanup workspace {role}")
    try:
        path.mkdir(mode=0o700)
        metadata = path.lstat()
    except OSError as error:
        raise ProvisionError(
            f"cannot create authority operation workspace {role}: {error}"
        ) from error
    try:
        ownership = _write_workspace_ownership(
            staging_root, authority, operation, record, metadata
        )
    except Exception as error:
        try:
            _remove_journaled_tree(
                path,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
                cleanup_path=cleanup,
            )
        except Exception as cleanup_error:
            raise ProvisionError(
                "authority workspace ownership and exact cleanup failed: "
                f"{error}; {cleanup_error}"
            ) from error
        raise
    owned.append({
        "path": path,
        "cleanup": cleanup,
        "parent": path.parent,
        "prefix": path.name,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "ownership": ownership,
    })
    return path


def _remove_operation_marker(
    authority: Path, operation: dict[str, Any],
) -> None:
    marker = _operation_path(authority)
    marker_identity = operation["marker"]
    _unlink_journaled_file(
        marker,
        expected_device=marker_identity["device"],
        expected_inode=marker_identity["inode"],
        cleanup_path=authority / OPERATION_CLEANUP_NAME,
    )


def _abort_operation(
    staging_root: Path,
    authority: Path,
    operation: dict[str, Any],
    revision: str,
) -> None:
    value = _validate_operation_payload(
        staging_root, authority, operation, revision
    )
    failures: list[str] = []
    for role in _operation_container_roles(value["kind"]):
        try:
            _cleanup_named_container(
                _container_name(value["token"], role),
                os.fspath(build_authority.DEFAULT_PODMAN),
                value["token"],
            )
        except Exception as error:
            failures.append(str(error))
    if failures:
        raise ProvisionError(
            "authority operation container cleanup failed; marker retained: "
            + "; ".join(failures)
        )
    for record in reversed(value["workspaces"]):
        path = _workspace_path(staging_root, authority, record)
        cleanup = _workspace_path(staging_root, authority, record, "cleanup")
        try:
            ownership = _read_workspace_ownership(
                staging_root, authority, value, record
            )
            workspace_present = (
                _kind(path) != "missing" or _kind(cleanup) != "missing"
            )
            if workspace_present and ownership is None:
                raise ProvisionError(
                    f"authority operation workspace ownership is missing: {path}"
                )
            if ownership is not None:
                payload, owner = ownership
                if workspace_present:
                    _remove_journaled_tree(
                        path,
                        expected_device=payload["device"],
                        expected_inode=payload["inode"],
                        cleanup_path=cleanup,
                    )
                _unlink_journaled_file(
                    owner["path"],
                    expected_device=owner["device"],
                    expected_inode=owner["inode"],
                    cleanup_path=owner["cleanup"],
                )
        except Exception as error:
            failures.append(str(error))
    if failures:
        raise ProvisionError(
            "authority operation cleanup failed; marker retained: "
            + "; ".join(failures)
        )
    if (
        _kind(_operation_path(authority)) != "missing"
        or _kind(authority / OPERATION_CLEANUP_NAME) != "missing"
    ):
        _remove_operation_marker(authority, value)


def _transaction_material(
    authority: Path,
    kind: str,
    revision: str,
    pairs: list[tuple[Path, Path]],
    token: str,
    marker_device: int,
    marker_inode: int,
) -> dict[str, Any]:
    if kind not in {"sanitizers", "release"}:
        raise ProvisionError("publication transaction kind is unsupported")
    if REVISION.fullmatch(revision) is None:
        raise ProvisionError("publication transaction revision is malformed")
    authority_metadata = authority.lstat()
    nodes: list[dict[str, Any]] = []
    for source, destination in pairs:
        source = _real_directory(source, "publication source")
        _require_missing(destination, "publication destination")
        try:
            source_relative = source.relative_to(authority).as_posix()
            destination_relative = destination.relative_to(authority).as_posix()
            metadata = source.lstat()
        except (OSError, ValueError) as error:
            raise ProvisionError(
                f"publication path is outside the authority root: {error}"
            ) from error
        cleanup = source.with_name(source.name + ".rollback")
        _require_missing(cleanup, "publication rollback quarantine")
        nodes.append({
            "source": source_relative,
            "destination": destination_relative,
            "cleanup": cleanup.relative_to(authority).as_posix(),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "tree": _tree_identity(source, "publication source"),
        })
    material = {
        "schema": TRANSACTION_SCHEMA,
        "kind": kind,
        "revision": revision,
        "token": token,
        "authority": {
            "path": authority.as_posix(),
            "device": authority_metadata.st_dev,
            "inode": authority_metadata.st_ino,
        },
        "marker": {
            "device": marker_device,
            "inode": marker_inode,
        },
        "nodes": nodes,
    }
    return {**material, "identity_sha256": digest_json(material)}


def _validate_transaction_payload(
    authority: Path,
    value: Any,
    revision: str,
) -> dict[str, Any]:
    fields = {
        "schema", "kind", "revision", "token", "authority", "marker", "nodes",
        "identity_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ProvisionError("publication transaction fields drift")
    material = {key: value[key] for key in fields - {"identity_sha256"}}
    if (
        value["schema"] != TRANSACTION_SCHEMA
        or not isinstance(value["revision"], str)
        or value["revision"] != revision
        or not isinstance(value["token"], str)
        or SHA256.fullmatch(value["token"]) is None
        or not isinstance(value["identity_sha256"], str)
        or SHA256.fullmatch(value["identity_sha256"]) is None
        or value["identity_sha256"] != digest_json(material)
    ):
        raise ProvisionError("publication transaction identity drift")
    authority_record = value["authority"]
    if (
        not isinstance(authority_record, dict)
        or set(authority_record) != {"path", "device", "inode"}
        or not isinstance(authority_record["path"], str)
        or type(authority_record["device"]) is not int
        or type(authority_record["inode"]) is not int
    ):
        raise ProvisionError("publication transaction authority is malformed")
    metadata = authority.lstat()
    if authority_record != {
        "path": authority.as_posix(),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }:
        raise ProvisionError("publication transaction authority drift")
    marker = value["marker"]
    if (
        not isinstance(marker, dict)
        or set(marker) != {"device", "inode"}
        or type(marker["device"]) is not int
        or type(marker["inode"]) is not int
        or marker["device"] < 0
        or marker["inode"] <= 0
    ):
        raise ProvisionError("publication transaction marker is malformed")
    kind = value["kind"]
    nodes = value["nodes"]
    expected_destinations = {
        "sanitizers": ["source/build/p10-09-sanitizers", "sanitizers"],
        "release": ["release"],
    }.get(kind)
    if (
        expected_destinations is None
        or not isinstance(nodes, list)
        or len(nodes) != len(expected_destinations)
    ):
        raise ProvisionError("publication transaction node inventory drift")
    for index, (node, destination) in enumerate(
        zip(nodes, expected_destinations, strict=True)
    ):
        if (
            not isinstance(node, dict)
            or set(node)
            != {
                "source", "destination", "cleanup", "device", "inode", "tree"
            }
            or not isinstance(node["source"], str)
            or not isinstance(node["destination"], str)
            or not isinstance(node["cleanup"], str)
            or node["destination"] != destination
            or type(node["device"]) is not int
            or type(node["inode"]) is not int
            or node["device"] < 0
            or node["inode"] <= 0
        ):
            raise ProvisionError("publication transaction node drift")
        source = Path(node["source"])
        if source.is_absolute() or ".." in source.parts:
            raise ProvisionError("publication transaction source is malformed")
        admitted = (
            source.parent == Path("source/build")
            and source.name.startswith(".p10-09-sanitizers.")
            if kind == "sanitizers" and index == 0
            else source.parent == Path(".")
            and source.name.startswith(
                ".sanitizers." if kind == "sanitizers" else ".release."
            )
        )
        if not admitted:
            raise ProvisionError("publication transaction source drift")
        cleanup = Path(node["cleanup"])
        if (
            cleanup.is_absolute()
            or ".." in cleanup.parts
            or cleanup != source.with_name(source.name + ".rollback")
        ):
            raise ProvisionError("publication transaction cleanup drift")
        tree = node["tree"]
        if (
            not isinstance(tree, dict)
            or tree.get("schema")
            != "codeskeptic-stability-tree-identity-v1"
            or set(tree)
            != {
                "schema", "root_mode", "entry_count", "file_count",
                "directory_count", "byte_count", "entries_sha256",
            }
        ):
            raise ProvisionError("publication transaction tree drift")
    return value


def _write_transaction(
    authority: Path,
    kind: str,
    revision: str,
    pairs: list[tuple[Path, Path]],
) -> dict[str, Any]:
    marker = _transaction_path(authority)
    _require_missing(marker, "publication transaction marker")
    _require_missing(
        authority / TRANSACTION_CLEANUP_NAME,
        "completed publication transaction marker",
    )
    token = secrets.token_hex(32)
    staging_marker = authority / (
        f"{TRANSACTION_NAME}.{token}{TRANSACTION_STAGING_SUFFIX}"
    )
    _require_missing(staging_marker, "publication transaction staging marker")
    _require_missing(
        staging_marker.with_name(staging_marker.name + ".cleanup"),
        "publication transaction staging marker cleanup",
    )
    payload: dict[str, Any] | None = None
    created_identity: tuple[int, int] | None = None
    try:
        with staging_marker.open("xb") as stream:
            opened = os.fstat(stream.fileno())
            created_identity = (opened.st_dev, opened.st_ino)
            payload = _transaction_material(
                authority,
                kind,
                revision,
                pairs,
                token,
                opened.st_dev,
                opened.st_ino,
            )
            data = canonical_json(payload)
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        staging._fsync_directory(authority)
        _publish_journal_file(
            staging_marker,
            marker,
            expected_device=created_identity[0],
            expected_inode=created_identity[1],
        )
    except Exception as error:
        try:
            if created_identity is not None and (
                _kind(staging_marker) != "missing"
                or _kind(
                    staging_marker.with_name(staging_marker.name + ".cleanup")
                ) != "missing"
            ):
                _unlink_journaled_file(
                    staging_marker,
                    expected_device=created_identity[0],
                    expected_inode=created_identity[1],
                )
        except Exception as cleanup_error:
            raise ProvisionError(
                "publication transaction creation and cleanup failed: "
                f"{error}; {cleanup_error}"
            ) from error
        raise ProvisionError(
            f"cannot create publication transaction: {error}"
        ) from error
    assert payload is not None
    return payload


def _read_transaction(
    authority: Path, revision: str,
) -> dict[str, Any] | None:
    marker = _transaction_path(authority)
    candidates = _journal_staging_candidates(
        authority, TRANSACTION_NAME, TRANSACTION_STAGING_SUFFIX
    )
    if candidates:
        staged = candidates[0]
        staged_cleanup = staged.with_name(staged.name + ".cleanup")
        if (
            _kind(marker) != "missing"
            or _kind(authority / TRANSACTION_CLEANUP_NAME) != "missing"
        ):
            raise ProvisionError(
                "transaction staging and published markers both exist"
            )
        actual = staged if _kind(staged) != "missing" else staged_cleanup
        metadata = actual.lstat()
        try:
            raw = build_authority._read_regular(actual, MAX_JSON_BYTES)
            payload = json.loads(raw.decode("utf-8"))
            if raw != canonical_json(payload):
                raise ProvisionError(
                    "staged publication transaction is not canonical"
                )
            value = _validate_transaction_payload(authority, payload, revision)
            token = staged.name[
                len(TRANSACTION_NAME) + 1:-len(TRANSACTION_STAGING_SUFFIX)
            ]
            marker_identity = value["marker"]
            if (
                value["token"] != token
                or (metadata.st_dev, metadata.st_ino)
                != (marker_identity["device"], marker_identity["inode"])
            ):
                raise ProvisionError(
                    "staged publication transaction identity drift"
                )
        except Exception:
            _unlink_journaled_file(
                staged,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
                cleanup_path=staged_cleanup,
            )
            return None
        _publish_journal_file(
            actual,
            marker,
            expected_device=metadata.st_dev,
            expected_inode=metadata.st_ino,
        )
    if _kind(marker) == "missing":
        cleanup = authority / TRANSACTION_CLEANUP_NAME
        if _kind(cleanup) == "missing":
            return None
        try:
            metadata = cleanup.lstat()
            raw = build_authority._read_regular(cleanup, MAX_JSON_BYTES)
            payload = json.loads(raw.decode("utf-8"))
        except Exception as error:
            raise ProvisionError(
                f"completed publication transaction is unreadable: {error}"
            ) from error
        if raw != canonical_json(payload):
            raise ProvisionError(
                "completed publication transaction is not canonical"
            )
        value = _validate_transaction_payload(authority, payload, revision)
        marker_identity = value["marker"]
        if (metadata.st_dev, metadata.st_ino) != (
            marker_identity["device"], marker_identity["inode"]
        ):
            raise ProvisionError(
                "completed publication transaction marker identity drift"
            )
        _unlink_journaled_file(
            marker,
            expected_device=marker_identity["device"],
            expected_inode=marker_identity["inode"],
            cleanup_path=cleanup,
        )
        return None
    try:
        raw = build_authority._read_regular(marker, MAX_JSON_BYTES)
        payload = json.loads(raw.decode("utf-8"))
    except Exception as error:
        raise ProvisionError(
            f"publication transaction marker is unreadable: {error}"
        ) from error
    if raw != canonical_json(payload):
        raise ProvisionError("publication transaction marker is not canonical")
    value = _validate_transaction_payload(authority, payload, revision)
    metadata = marker.lstat()
    marker_identity = value["marker"]
    if (metadata.st_dev, metadata.st_ino) != (
        marker_identity["device"], marker_identity["inode"]
    ):
        raise ProvisionError("publication transaction marker identity drift")
    return value


def _remove_transaction_marker(
    authority: Path, transaction: dict[str, Any],
) -> None:
    marker = _transaction_path(authority)
    try:
        marker_identity = transaction["marker"]
        _unlink_journaled_file(
            marker,
            expected_device=marker_identity["device"],
            expected_inode=marker_identity["inode"],
            cleanup_path=authority / TRANSACTION_CLEANUP_NAME,
        )
    except ProvisionError:
        raise
    except Exception as error:
        raise ProvisionError(
            f"cannot remove publication transaction marker: {error}"
        ) from error


def _rollback_transaction(
    authority: Path,
    payload: dict[str, Any],
    revision: str,
) -> None:
    transaction = _validate_transaction_payload(authority, payload, revision)
    failures: list[str] = []
    for node in reversed(transaction["nodes"]):
        source = authority / node["source"]
        destination = authority / node["destination"]
        cleanup = authority / node["cleanup"]
        present = [
            path for path in (source, destination, cleanup)
            if _kind(path) != "missing"
        ]
        if len(present) > 1:
            failures.append(
                f"multiple publication paths exist for {node['destination']}"
            )
            continue
        if not present:
            continue
        path = present[0]
        removal_path = source if path == cleanup else path
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_dev != node["device"]
                or metadata.st_ino != node["inode"]
            ):
                raise ProvisionError(
                    f"publication node identity changed: {path}"
                )
            if _tree_identity(path, "rollback publication node") != node["tree"]:
                raise ProvisionError(
                    f"publication node content changed: {path}"
                )
            _remove_journaled_tree(
                removal_path,
                expected_device=node["device"],
                expected_inode=node["inode"],
                cleanup_path=cleanup,
            )
        except Exception as error:
            failures.append(str(error))
    if failures:
        raise ProvisionError(
            "publication rollback failed; transaction retained: "
            + "; ".join(failures)
        )
    _remove_transaction_marker(authority, transaction)


def _commit_transaction(
    authority: Path,
    payload: dict[str, Any],
    revision: str,
) -> None:
    transaction = _validate_transaction_payload(authority, payload, revision)
    for node in transaction["nodes"]:
        destination = authority / node["destination"]
        try:
            metadata = destination.lstat()
        except OSError as error:
            raise ProvisionError(
                f"published authority is missing: {destination}: {error}"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != node["device"]
            or metadata.st_ino != node["inode"]
        ):
            raise ProvisionError(f"published authority identity drift: {destination}")
        if _tree_identity(destination, "published authority") != node["tree"]:
            raise ProvisionError(f"published authority content drift: {destination}")
    _remove_transaction_marker(authority, transaction)


def _rejection_destination(
    staging_root: Path, operation: dict[str, Any]
) -> Path:
    return staging_root.parent / (
        f".codeskeptic-p10-09-rejection.{operation['kind']}."
        f"{operation['token']}"
    )


def _bounded_rejection_message(error: BaseException) -> str:
    message = str(error).encode("utf-8", errors="replace")
    if len(message) <= MAX_REJECTION_MESSAGE_BYTES:
        return message.decode("utf-8")
    suffix = b"...[truncated]"
    return (
        message[:MAX_REJECTION_MESSAGE_BYTES - len(suffix)] + suffix
    ).decode("utf-8", errors="replace")


def _rejection_log_inventory(root: Path) -> list[dict[str, Any]]:
    _tree_identity(root, "authority rejection evidence")
    metadata_names = {"receipt.json", "receipt.json.sha256", "SHA256SUMS"}
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ProvisionError("rejection evidence contains a linked node")
        if relative in metadata_names:
            continue
        entries.append({
            "path": relative,
            "bytes": metadata.st_size,
            "sha256": sha256_file(path),
        })
    return entries


def _write_rejection_file(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
    except OSError as error:
        raise ProvisionError(
            f"cannot write authority rejection evidence {path.name}: {error}"
        ) from error


def _rejection_sums(root: Path) -> bytes:
    files = [
        path for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    return "".join(
        f"{sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
        for path in files
    ).encode("ascii")


def _verify_rejection_evidence(
    root: Path,
    operation: dict[str, Any],
    revision: str,
) -> dict[str, Any]:
    root = _real_directory(root, "authority rejection evidence")
    try:
        raw = build_authority._read_regular(root / "receipt.json", MAX_JSON_BYTES)
        receipt = json.loads(raw.decode("utf-8"))
    except Exception as error:
        raise ProvisionError(
            f"authority rejection receipt is unreadable: {error}"
        ) from error
    fields = {
        "schema", "status", "kind", "revision", "operation_token",
        "failure", "logs",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) != fields
        or raw != canonical_json(receipt)
        or receipt["schema"] != REJECTION_EVIDENCE_SCHEMA
        or receipt["status"] != "rejected"
        or receipt["kind"] != operation["kind"]
        or receipt["revision"] != revision
        or receipt["operation_token"] != operation["token"]
        or not isinstance(receipt["failure"], dict)
        or set(receipt["failure"]) != {"type", "message"}
        or not all(
            isinstance(receipt["failure"][field], str)
            for field in ("type", "message")
        )
        or not isinstance(receipt["logs"], list)
    ):
        raise ProvisionError("authority rejection receipt identity drift")
    actual_logs = _rejection_log_inventory(root)
    if receipt["logs"] != actual_logs:
        raise ProvisionError("authority rejection log inventory drift")
    receipt_sha = hashlib.sha256(raw).hexdigest()
    expected_sidecar = f"{receipt_sha}  receipt.json\n".encode("ascii")
    if build_authority._read_regular(
        root / "receipt.json.sha256", MAX_JSON_BYTES
    ) != expected_sidecar:
        raise ProvisionError("authority rejection receipt checksum drift")
    if build_authority._read_regular(
        root / "SHA256SUMS", MAX_JSON_BYTES
    ) != _rejection_sums(root):
        raise ProvisionError("authority rejection checksum inventory drift")
    if stat.S_IMODE(root.lstat().st_mode) != 0o500:
        raise ProvisionError("authority rejection root mode drift")
    for path in root.rglob("*"):
        metadata = path.lstat()
        expected_mode = 0o500 if stat.S_ISDIR(metadata.st_mode) else 0o400
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ProvisionError("authority rejection payload mode drift")
    _tree_identity(root, "authority rejection evidence")
    return receipt


def _persist_rejection_evidence(
    staging_root: Path,
    authority: Path,
    operation: dict[str, Any],
    revision: str,
    failure: BaseException,
) -> Path | None:
    record = next(
        (
            item for item in operation["workspaces"]
            if item["role"] == "operator-logs"
        ),
        None,
    )
    if record is None:
        raise ProvisionError("operation log workspace is missing from the journal")
    source = _workspace_path(staging_root, authority, record)
    cleanup = _workspace_path(staging_root, authority, record, "cleanup")
    present = [
        path for path in (source, cleanup) if _kind(path) != "missing"
    ]
    destination = _rejection_destination(staging_root, operation)
    if _kind(destination) != "missing":
        if present:
            raise ProvisionError(
                "published rejection evidence and operation logs both exist"
            )
        _verify_rejection_evidence(destination, operation, revision)
        return destination
    if len(present) > 1:
        raise ProvisionError("both operation log workspace paths exist")
    if not present:
        return None
    ownership = _read_workspace_ownership(
        staging_root, authority, operation, record
    )
    if ownership is None:
        raise ProvisionError("operation log ownership is missing")
    payload, _owner = ownership
    root = present[0]
    metadata = root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (payload["device"], payload["inode"])
    ):
        raise ProvisionError("operation log workspace identity drift")
    evidence_names = {
        "receipt.json", "receipt.json.sha256", "SHA256SUMS"
    }
    existing_evidence = {
        name for name in evidence_names if _kind(root / name) != "missing"
    }
    if existing_evidence:
        if existing_evidence != evidence_names:
            raise ProvisionError(
                "partial authority rejection evidence retained"
            )
        _verify_rejection_evidence(root, operation, revision)
    else:
        receipt = {
            "schema": REJECTION_EVIDENCE_SCHEMA,
            "status": "rejected",
            "kind": operation["kind"],
            "revision": revision,
            "operation_token": operation["token"],
            "failure": {
                "type": type(failure).__name__,
                "message": _bounded_rejection_message(failure),
            },
            "logs": _rejection_log_inventory(root),
        }
        receipt_raw = canonical_json(receipt)
        _write_rejection_file(root / "receipt.json", receipt_raw)
        _write_rejection_file(
            root / "receipt.json.sha256",
            (
                f"{hashlib.sha256(receipt_raw).hexdigest()}  receipt.json\n"
            ).encode("ascii"),
        )
        _write_rejection_file(root / "SHA256SUMS", _rejection_sums(root))
        for path in sorted(root.rglob("*"), reverse=True):
            metadata = path.lstat()
            os.chmod(path, 0o500 if stat.S_ISDIR(metadata.st_mode) else 0o400)
        os.chmod(root, 0o500)
        staging._fsync_tree(root)
        _verify_rejection_evidence(root, operation, revision)
    expected_tree = _tree_identity(root, "authority rejection evidence")
    staging._publish_tree_noreplace(root, destination)
    if _tree_identity(destination, "published authority rejection") != expected_tree:
        raise ProvisionError("published authority rejection identity drift")
    _verify_rejection_evidence(destination, operation, revision)
    return destination


def _recover_transaction(staging_root: Path, revision: str) -> None:
    root = _real_directory(staging_root, "prepared staging root")
    authority = _real_directory(root / "authority", "staging authority root")
    payload = _read_transaction(authority, revision)
    if payload is not None:
        _rollback_transaction(authority, payload, revision)
    operation = _read_operation(root, authority, revision)
    if operation is not None:
        try:
            _persist_rejection_evidence(
                root,
                authority,
                operation,
                revision,
                ProvisionError("recovered interrupted authority operation"),
            )
        except Exception as error:
            raise ProvisionError(
                "interrupted authority evidence could not be sealed; operation "
                f"retained: {error}"
            ) from error
        _abort_operation(root, authority, operation, revision)


def _cleanup_owned_workspaces(
    owned: list[dict[str, Any]],
    *,
    retain: dict[str, Any] | None = None,
) -> list[str]:
    failures: list[str] = []
    for record in reversed(owned):
        if record is retain and _kind(record["path"]) != "missing":
            continue
        try:
            _remove_private(record)
        except ProvisionError as error:
            failures.append(str(error))
    return failures


def _populate_sanitizers_unlocked(staging_root: Path, revision: str) -> None:
    _recover_transaction(staging_root, revision)
    authority, source, source_before = _validate_staging_root(staging_root, revision)
    final_build = source / "build/p10-09-sanitizers"
    final_receipts = authority / "sanitizers"
    _require_missing(final_build, "sanitizer build authority")
    _require_missing(final_receipts, "sanitizer receipt authority")
    build_parent = source / "build"
    if _kind(build_parent) == "missing":
        build_parent.mkdir(mode=0o700)
    else:
        _require_empty_directory(build_parent, "staged source build root")
    operation = _write_operation(
        staging_root, authority, "sanitizers", revision
    )
    owned: list[dict[str, Any]] = []
    failure: BaseException | None = None
    try:
        log_temp = _create_operation_workspace(
            staging_root,
            authority,
            operation,
            "operator-logs",
            owned,
        )
        log_record = owned[-1]
        build_temp = _create_operation_workspace(
            staging_root,
            authority,
            operation,
            "sanitizer-build",
            owned,
        )
        receipt_temp = _create_operation_workspace(
            staging_root,
            authority,
            operation,
            "sanitizer-receipts",
            owned,
        )
        for profile in PROFILES:
            (build_temp / f"{profile}-tests").mkdir(mode=0o700)
            (build_temp / f"{profile}-fuzz").mkdir(mode=0o700)
            (receipt_temp / profile).mkdir(mode=0o700)
        runtime_before = build_authority._runtime_authority(container_layout="p10-09")
        for profile in PROFILES:
            paths = (
                build_temp / f"{profile}-tests",
                build_temp / f"{profile}-fuzz",
                receipt_temp / profile,
            )
            _execute_container(
                _sanitizer_container_command(
                    "sanitizer-produce", profile, source, *paths, revision
                ),
                log_temp / f"{profile}-produce.log",
                timeout_seconds=SANITIZER_CONTAINER_TIMEOUT_SECONDS,
                invocation_token=operation["token"],
                container_role=f"{profile}-produce",
            )
            _execute_container(
                _sanitizer_container_command(
                    "sanitizer-verify", profile, source, *paths, revision
                ),
                log_temp / f"{profile}-verify.log",
                timeout_seconds=SANITIZER_CONTAINER_TIMEOUT_SECONDS,
                invocation_token=operation["token"],
                container_role=f"{profile}-verify",
            )
        if staging.validate_staged_source(source, revision) != source_before:
            raise ProvisionError("staged source authority changed during sanitizer production")
        if build_authority._runtime_authority(container_layout="p10-09") != runtime_before:
            raise ProvisionError("pinned runtime changed during sanitizer production")
        staging._fsync_tree(build_temp)
        staging._fsync_tree(receipt_temp)
        transaction = _write_transaction(
            authority,
            "sanitizers",
            revision,
            [(build_temp, final_build), (receipt_temp, final_receipts)],
        )
        try:
            staging._publish_tree_noreplace(build_temp, final_build)
            staging._publish_tree_noreplace(receipt_temp, final_receipts)
            for profile in PROFILES:
                _execute_container(
                    _sanitizer_container_command(
                        "sanitizer-verify",
                        profile,
                        source,
                        final_build / f"{profile}-tests",
                        final_build / f"{profile}-fuzz",
                        final_receipts / profile,
                        revision,
                    ),
                    log_temp / f"{profile}-published-verify.log",
                    timeout_seconds=SANITIZER_CONTAINER_TIMEOUT_SECONDS,
                    invocation_token=operation["token"],
                    container_role=f"{profile}-verify",
                )
            cleanup_failures = _cleanup_owned_workspaces(
                owned, retain=log_record
            )
            if cleanup_failures:
                raise ProvisionError(
                    "sanitizer publication workspace cleanup failed: "
                    + "; ".join(cleanup_failures)
                )
            cleanup_failures = _cleanup_owned_workspaces([log_record])
            if cleanup_failures:
                raise ProvisionError(
                    "sanitizer operator log cleanup failed: "
                    + "; ".join(cleanup_failures)
                )
            owned.clear()
            _remove_operation_marker(authority, operation)
            _commit_transaction(authority, transaction, revision)
        except BaseException as error:
            try:
                _rollback_transaction(authority, transaction, revision)
            except Exception as rollback_error:
                raise ProvisionError(
                    "sanitizer publication and rollback failed: "
                    f"{error}; {rollback_error}"
                ) from error
            raise
    except BaseException as error:
        failure = error
    cleanup_errors: list[str] = []
    if failure is not None:
        try:
            _persist_rejection_evidence(
                staging_root, authority, operation, revision, failure
            )
        except ProvisionError as error:
            cleanup_errors.append(
                "rejection evidence could not be sealed; operation retained: "
                + str(error)
            )
        if not cleanup_errors:
            try:
                _abort_operation(
                    staging_root, authority, operation, revision
                )
            except ProvisionError as error:
                cleanup_errors.append(str(error))
    else:
        cleanup_errors = _cleanup_owned_workspaces(owned)
    if failure is not None:
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            if cleanup_errors:
                raise ProvisionError(
                    "sanitizer authority interruption cleanup failed: "
                    + "; ".join(cleanup_errors)
                ) from failure
            raise failure
        details = f"sanitizer authority provisioning failed: {failure}"
        if cleanup_errors:
            details += f"; cleanup failed: {cleanup_errors[0]}"
        raise ProvisionError(details) from failure
    if cleanup_errors:
        raise ProvisionError(
            "sanitizer authority cleanup failed: " + "; ".join(cleanup_errors)
        )
    print("CODESKEPTIC_SANITIZER_AUTHORITIES_PUBLISHED")


def _populate_release_unlocked(staging_root: Path, revision: str) -> None:
    _recover_transaction(staging_root, revision)
    authority, source, source_before = _validate_staging_root(staging_root, revision)
    mirrors = _real_directory(authority / "mirrors", "sealed mirror authority")
    final_release = authority / "release"
    _require_missing(final_release, "release authority")
    operation = _write_operation(
        staging_root, authority, "release", revision
    )
    owned: list[dict[str, Any]] = []
    failure: BaseException | None = None
    try:
        log_temp = _create_operation_workspace(
            staging_root,
            authority,
            operation,
            "operator-logs",
            owned,
        )
        log_record = owned[-1]
        release_temp = _create_operation_workspace(
            staging_root,
            authority,
            operation,
            "release-authority",
            owned,
        )
        scratch_temp = _create_operation_workspace(
            staging_root,
            authority,
            operation,
            "release-scratch",
            owned,
        )
        (release_temp / "source").mkdir(mode=0o700)
        (release_temp / "build").mkdir(mode=0o700)
        runtime_before = build_authority._runtime_authority(container_layout="p10-09")
        _execute_container(
            _release_container_command(
                "release-produce", source, mirrors, release_temp, revision, scratch_temp
            ),
            log_temp / "produce.log",
            timeout_seconds=RELEASE_CONTAINER_TIMEOUT_SECONDS,
            invocation_token=operation["token"],
            container_role="release-produce",
        )
        _execute_container(
            _release_container_command(
                "release-verify", source, mirrors, release_temp, revision
            ),
            log_temp / "verify.log",
            timeout_seconds=RELEASE_CONTAINER_TIMEOUT_SECONDS,
            invocation_token=operation["token"],
            container_role="release-verify",
        )
        if staging.validate_staged_source(source, revision) != source_before:
            raise ProvisionError("staged source authority changed during release production")
        if build_authority._runtime_authority(container_layout="p10-09") != runtime_before:
            raise ProvisionError("pinned runtime changed during release production")
        staging._fsync_tree(release_temp)
        transaction = _write_transaction(
            authority,
            "release",
            revision,
            [(release_temp, final_release)],
        )
        try:
            staging._publish_tree_noreplace(release_temp, final_release)
            _execute_container(
                _release_container_command(
                    "release-verify", source, mirrors, final_release, revision
                ),
                log_temp / "published-verify.log",
                timeout_seconds=RELEASE_CONTAINER_TIMEOUT_SECONDS,
                invocation_token=operation["token"],
                container_role="release-verify",
            )
            cleanup_failures = _cleanup_owned_workspaces(
                owned, retain=log_record
            )
            if cleanup_failures:
                raise ProvisionError(
                    "release publication workspace cleanup failed: "
                    + "; ".join(cleanup_failures)
                )
            cleanup_failures = _cleanup_owned_workspaces([log_record])
            if cleanup_failures:
                raise ProvisionError(
                    "release operator log cleanup failed: "
                    + "; ".join(cleanup_failures)
                )
            owned.clear()
            _remove_operation_marker(authority, operation)
            _commit_transaction(authority, transaction, revision)
        except BaseException as error:
            try:
                _rollback_transaction(authority, transaction, revision)
            except Exception as rollback_error:
                raise ProvisionError(
                    "release publication and rollback failed: "
                    f"{error}; {rollback_error}"
                ) from error
            raise
    except BaseException as error:
        failure = error
    cleanup_errors: list[str] = []
    if failure is not None:
        try:
            _persist_rejection_evidence(
                staging_root, authority, operation, revision, failure
            )
        except ProvisionError as error:
            cleanup_errors.append(
                "rejection evidence could not be sealed; operation retained: "
                + str(error)
            )
        if not cleanup_errors:
            try:
                _abort_operation(
                    staging_root, authority, operation, revision
                )
            except ProvisionError as error:
                cleanup_errors.append(str(error))
    else:
        cleanup_errors = _cleanup_owned_workspaces(owned)
    if failure is not None:
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            if cleanup_errors:
                raise ProvisionError(
                    "release authority interruption cleanup failed: "
                    + "; ".join(cleanup_errors)
                ) from failure
            raise failure
        details = f"release authority provisioning failed: {failure}"
        if cleanup_errors:
            details += f"; cleanup failed: {cleanup_errors[0]}"
        raise ProvisionError(details) from failure
    if cleanup_errors:
        raise ProvisionError(
            "release authority cleanup failed: " + "; ".join(cleanup_errors)
        )
    print("CODESKEPTIC_RELEASE_AUTHORITY_PUBLISHED")


def populate_sanitizers(staging_root: Path, revision: str) -> None:
    with _lifecycle_lock(staging_root):
        _populate_sanitizers_unlocked(staging_root, revision)


def populate_release(staging_root: Path, revision: str) -> None:
    with _lifecycle_lock(staging_root):
        _populate_release_unlocked(staging_root, revision)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="version",
        version=f"CodeSkeptic P10-09 authority provisioner {TOOL_VERSION}",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("populate-sanitizers", "populate-release"):
        command = commands.add_parser(name)
        command.add_argument("--staging", type=Path, required=True)
        command.add_argument("--revision", required=True)
    for name in (
        "_inner-sanitizer-produce",
        "_inner-sanitizer-verify",
    ):
        command = commands.add_parser(name)
        command.add_argument("--profile", choices=PROFILES, required=True)
        command.add_argument("--revision", required=True)
    for name in ("_inner-release-produce", "_inner-release-verify"):
        command = commands.add_parser(name)
        command.add_argument("--revision", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "populate-sanitizers":
            populate_sanitizers(args.staging, args.revision)
        elif args.command == "populate-release":
            populate_release(args.staging, args.revision)
        elif args.command == "_inner-sanitizer-produce":
            _inner_populate_sanitizer(args.profile, args.revision)
        elif args.command == "_inner-sanitizer-verify":
            _inner_verify_sanitizer(args.profile, args.revision)
        elif args.command == "_inner-release-produce":
            _inner_populate_release(args.revision)
        elif args.command == "_inner-release-verify":
            _inner_verify_release(args.revision)
        else:
            raise ProvisionError("unsupported authority command")
        return 0
    except ProvisionError as error:
        print(f"CODESKEPTIC_AUTHORITY_PROVISION_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
