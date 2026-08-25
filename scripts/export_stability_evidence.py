#!/usr/bin/env python3
"""Create and replay a portable, fail-closed P10-09 evidence export.

The external bundle carries the complete accepted outer session plus every
installed byte needed to rederive it.  Its compact ``receipt.json`` is suitable
for repository retention; ``inventory.json`` remains beside the potentially
large payload.  Verification is networkless and reconstructs the production
mount topology in a bubblewrap namespace, without reading live ``/opt`` or
``/var`` state.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import errno
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Iterator


TOOL_VERSION = "1"
RECEIPT_SCHEMA = "codeskeptic-stability-portable-export-v1"
INVENTORY_SCHEMA = "codeskeptic-stability-portable-inventory-v1"
COMPONENTS = ("authority", "bundle", "config", "launch", "operator", "session")
NAMED_COMPONENTS = frozenset({"launch", "session"})
BUNDLE_METADATA_FILES = {
    "SHA256SUMS",
    "inventory.json",
    "inventory.json.sha256",
    "receipt.json",
    "receipt.json.sha256",
}

SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")
INNER_MARKER = re.compile(
    rb"CODESKEPTIC_STABILITY_VERIFIED ([0-9a-f]{64}) ([0-9a-f]{64})\n"
)
OUTER_MARKER = re.compile(
    rb"CODESKEPTIC_OPERATOR_EVIDENCE_VERIFIED "
    rb"([0-9a-f]{64}) ([0-9a-f]{64})\n"
)

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_FILES = 262_144
MAX_DIRECTORIES = 65_536
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_SESSION_BYTES = 16 * 1024 * 1024 * 1024
MAX_EXPORT_BYTES = 128 * 1024 * 1024 * 1024
SEMANTIC_TIMEOUT_SECONDS = 30 * 60
COPY_BLOCK_BYTES = 1024 * 1024

BWRAP = Path("/usr/bin/bwrap")
PRLIMIT = Path("/usr/bin/prlimit")
PYTHON = Path("/usr/bin/python3")

FIXED_AUTHORITY_ROOT = Path("/opt/codeskeptic-p10-09/authority")
FIXED_OPERATOR_ROOT = Path("/opt/codeskeptic-p10-09/operator")
FIXED_CONFIG_ROOT = Path("/etc/codeskeptic-p10-09")
FIXED_STATE_ROOT = Path("/var/lib/codeskeptic-p10-09")
FIXED_LAUNCH_ROOT = FIXED_STATE_ROOT / "launches"
FIXED_SESSION_ROOT = FIXED_STATE_ROOT / "sessions"
FIXED_RUNNER = FIXED_AUTHORITY_ROOT / "source/scripts/run_stability_campaign.py"
FIXED_OPERATOR = FIXED_OPERATOR_ROOT / "run-authoritative-stability.sh"


class ExportError(RuntimeError):
    """The portable export or one of its authorities is inadmissible."""


@dataclasses.dataclass(frozen=True)
class SnapshotRoots:
    authority: Path
    bundle: Path
    operator: Path
    config: Path
    launch: Path
    session: Path

    def component(self, name: str) -> Path:
        if name not in COMPONENTS:
            raise ExportError(f"unknown export component: {name}")
        return Path(getattr(self, name))

    def __iter__(self) -> Iterator[Path]:
        for name in COMPONENTS:
            yield self.component(name)


@dataclasses.dataclass
class _Budget:
    files: int = 0
    directories: int = 0
    bytes: int = 0

    def add_directory(self) -> None:
        self.directories += 1
        if self.directories > MAX_DIRECTORIES:
            raise ExportError("export directory inventory exceeds its fixed limit")

    def add_file(self, size: int, *, component: str) -> None:
        if size < 0 or size > MAX_FILE_BYTES:
            raise ExportError("export regular file exceeds its fixed size limit")
        self.files += 1
        self.bytes += size
        if self.files > MAX_FILES:
            raise ExportError("export file inventory exceeds its fixed limit")
        if self.bytes > MAX_EXPORT_BYTES:
            raise ExportError("export payload exceeds its fixed byte limit")
        if component == "session" and self.component_bytes(component) > MAX_SESSION_BYTES:
            raise ExportError("export session exceeds the accepted 16-GiB limit")

    _component_totals: dict[str, int] = dataclasses.field(default_factory=dict)

    def component_bytes(self, component: str) -> int:
        return self._component_totals.get(component, 0)

    def account_component_file(self, component: str, size: int) -> None:
        self._component_totals[component] = self.component_bytes(component) + size
        self.add_file(size, component=component)


def canonical_document(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ExportError(f"cannot serialize canonical export document: {error}") from error
    return (rendered + "\n").encode("utf-8")


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ExportError(f"cannot serialize compact export document: {error}") from error


def _exact_dict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ExportError(f"{label} field inventory drift")
    return value


def _valid_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ExportError(f"{label} is not a canonical SHA-256")
    return value


def _valid_revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA1.fullmatch(value) is None:
        raise ExportError(f"{label} is not a canonical Git revision")
    return value


def _mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _safe_component_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or any(0xDC80 <= ord(character) <= 0xDCFF for character in name)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        raise ExportError("export inventory contains an inadmissible file name")


def _require_real_absolute_directory(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        path = Path(path)
    if not path.is_absolute() or Path(os.path.normpath(os.fspath(path))) != path:
        raise ExportError(f"{label} is not an absolute canonical path")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ExportError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or resolved != path:
        raise ExportError(f"{label} is not a real canonical directory")
    return path


def _require_regular_executable(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved_metadata = resolved.lstat()
    except OSError as error:
        raise ExportError(f"cannot inspect {label}: {error}") from error
    if (
        not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode))
        or not stat.S_ISREG(resolved_metadata.st_mode)
        or not resolved.is_relative_to(Path("/usr"))
        or not os.access(path, os.X_OK)
    ):
        raise ExportError(f"{label} is not a regular executable")


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise ExportError(f"cannot inspect {label}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise ExportError(f"{label} is not a bounded standalone regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _fingerprint(opened) != _fingerprint(before):
                raise ExportError(f"{label} changed while opening")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                block = os.read(descriptor, min(COPY_BLOCK_BYTES, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except ExportError:
        raise
    except OSError as error:
        raise ExportError(f"cannot read {label}: {error}") from error
    data = b"".join(chunks)
    if len(data) > maximum or _fingerprint(after) != _fingerprint(before):
        raise ExportError(f"{label} changed or exceeded its size limit")
    return data


def _sha256_regular(path: Path, maximum: int = MAX_FILE_BYTES) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise ExportError(f"cannot inspect regular file {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise ExportError(f"export path is not a bounded standalone regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    total = 0
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _fingerprint(opened) != _fingerprint(before):
                raise ExportError(f"regular file changed while opening: {path}")
            while True:
                block = os.read(descriptor, COPY_BLOCK_BYTES)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise ExportError(f"regular file exceeds its size limit: {path}")
                digest.update(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except ExportError:
        raise
    except OSError as error:
        raise ExportError(f"cannot hash regular file {path}: {error}") from error
    if total != before.st_size or _fingerprint(after) != _fingerprint(before):
        raise ExportError(f"regular file changed while hashing: {path}")
    return digest.hexdigest()


def _load_document(path: Path, maximum: int, label: str) -> dict[str, Any]:
    data = _read_regular(path, maximum, label)
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExportError(f"{label} JSON is malformed: {error}") from error
    if not isinstance(value, dict) or canonical_document(value) != data:
        raise ExportError(f"{label} is not canonical JSON")
    return value


def _load_compact_document(path: Path, maximum: int, label: str) -> dict[str, Any]:
    data = _read_regular(path, maximum, label)
    try:
        value = json.loads(data.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExportError(f"{label} JSON is malformed: {error}") from error
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != data:
        raise ExportError(f"{label} is not canonical compact JSON")
    return value


def _atomic_create(path: Path, data: bytes, mode: int = 0o444) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ExportError(f"short write while creating {path.name}")
                view = view[written:]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except ExportError:
        raise
    except OSError as error:
        raise ExportError(f"cannot atomically create {path}: {error}") from error


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ExportError(f"cannot synchronize export directory {path}: {error}") from error


def _copy_file(
    source_fd: int,
    destination_fd: int | None,
    name: str,
    metadata: os.stat_result,
) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=source_fd)
    except OSError as error:
        raise ExportError(f"cannot open export regular file {name}: {error}") from error
    output: int | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if _fingerprint(opened) != _fingerprint(metadata):
            raise ExportError(f"export regular file changed while opening: {name}")
        if destination_fd is not None:
            output_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            output = os.open(name, output_flags, 0o600, dir_fd=destination_fd)
        while True:
            block = os.read(descriptor, COPY_BLOCK_BYTES)
            if not block:
                break
            total += len(block)
            if total > MAX_FILE_BYTES:
                raise ExportError(f"export regular file exceeds its limit: {name}")
            digest.update(block)
            if output is not None:
                view = memoryview(block)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise ExportError(f"short export copy write: {name}")
                    view = view[written:]
        after = os.fstat(descriptor)
        if total != metadata.st_size or _fingerprint(after) != _fingerprint(metadata):
            raise ExportError(f"export regular file changed while copying: {name}")
        if output is not None:
            os.fchmod(output, _mode(metadata))
            os.fsync(output)
            copied = os.fstat(output)
            if (
                not stat.S_ISREG(copied.st_mode)
                or copied.st_nlink != 1
                or copied.st_size != total
                or _mode(copied) != _mode(metadata)
            ):
                raise ExportError(f"copied export file identity drift: {name}")
    except ExportError:
        raise
    except OSError as error:
        raise ExportError(f"cannot copy export regular file {name}: {error}") from error
    finally:
        if output is not None:
            os.close(output)
        os.close(descriptor)
    return digest.hexdigest()


def _walk_directory(
    source_fd: int,
    destination_fd: int | None,
    relative: str,
    component: str,
    device: int,
    budget: _Budget,
    entries: list[dict[str, Any]],
) -> None:
    before = os.fstat(source_fd)
    if not stat.S_ISDIR(before.st_mode) or before.st_dev != device:
        raise ExportError("export directory crosses or changes its filesystem authority")
    if _mode(before) & 0o7000:
        raise ExportError("export directory uses non-portable special mode bits")
    budget.add_directory()
    entries.append({"mode": f"{_mode(before):04o}", "path": relative, "type": "directory"})
    try:
        names = sorted(os.listdir(source_fd))
    except OSError as error:
        raise ExportError(f"cannot enumerate export directory: {error}") from error
    for name in names:
        _safe_component_name(name)
        child_relative = name if relative == "." else f"{relative}/{name}"
        try:
            metadata = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as error:
            raise ExportError(
                f"cannot inspect export inventory path {child_relative}: {error}"
            ) from error
        if metadata.st_dev != device:
            raise ExportError("export inventory crosses a filesystem boundary")
        if stat.S_ISDIR(metadata.st_mode):
            if destination_fd is not None:
                try:
                    os.mkdir(name, 0o700, dir_fd=destination_fd)
                    child_destination = os.open(
                        name,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=destination_fd,
                    )
                except OSError as error:
                    raise ExportError(
                        f"cannot create export directory {child_relative}: {error}"
                    ) from error
            else:
                child_destination = None
            try:
                child_source = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=source_fd,
                )
            except OSError as error:
                if child_destination is not None:
                    os.close(child_destination)
                raise ExportError(
                    f"cannot open export directory {child_relative}: {error}"
                ) from error
            try:
                opened = os.fstat(child_source)
                if _fingerprint(opened) != _fingerprint(metadata):
                    raise ExportError(f"export directory changed while opening: {child_relative}")
                _walk_directory(
                    child_source,
                    child_destination,
                    child_relative,
                    component,
                    device,
                    budget,
                    entries,
                )
                after = os.fstat(child_source)
                if _fingerprint(after) != _fingerprint(metadata):
                    raise ExportError(f"export directory changed while reading: {child_relative}")
                if child_destination is not None:
                    os.fchmod(child_destination, _mode(metadata))
                    os.fsync(child_destination)
            finally:
                os.close(child_source)
                if child_destination is not None:
                    os.close(child_destination)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ExportError(
                f"export inventory path is not a regular file or directory: {child_relative}"
            )
        if metadata.st_nlink != 1:
            raise ExportError(f"export regular file has a hard-link alias: {child_relative}")
        if _mode(metadata) & 0o7000:
            raise ExportError("export regular file uses non-portable special mode bits")
        budget.account_component_file(component, metadata.st_size)
        digest = _copy_file(source_fd, destination_fd, name, metadata)
        entries.append(
            {
                "mode": f"{_mode(metadata):04o}",
                "path": child_relative,
                "sha256": digest,
                "size": metadata.st_size,
                "type": "file",
            }
        )
    try:
        final_names = sorted(os.listdir(source_fd))
        after = os.fstat(source_fd)
    except OSError as error:
        raise ExportError(f"cannot recheck export directory: {error}") from error
    if final_names != names or _fingerprint(after) != _fingerprint(before):
        raise ExportError("export directory inventory changed during traversal")
    if destination_fd is not None:
        os.fsync(destination_fd)


def _component_document(
    source: Path,
    component: str,
    budget: _Budget,
    destination: Path | None = None,
    root_path: str = ".",
) -> dict[str, Any]:
    source = _require_real_absolute_directory(source, f"{component} root")
    if root_path != ".":
        _safe_component_name(root_path)
    try:
        metadata = source.lstat()
    except OSError as error:
        raise ExportError(f"cannot inspect {component} root: {error}") from error
    if destination is not None:
        try:
            destination.mkdir(mode=0o700)
        except OSError as error:
            raise ExportError(f"cannot create copied {component} root: {error}") from error
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    source_fd = os.open(source, source_flags)
    destination_fd: int | None = None
    try:
        if _fingerprint(os.fstat(source_fd)) != _fingerprint(metadata):
            raise ExportError(f"{component} root changed while opening")
        if destination is not None:
            destination_fd = os.open(destination, source_flags)
        entries: list[dict[str, Any]] = []
        before_files = budget.files
        before_directories = budget.directories
        before_bytes = budget.bytes
        _walk_directory(
            source_fd,
            destination_fd,
            root_path,
            component,
            metadata.st_dev,
            budget,
            entries,
        )
        if destination_fd is not None:
            os.fchmod(destination_fd, _mode(metadata))
            os.fsync(destination_fd)
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)
    entries.sort(key=lambda item: (item["path"], item["type"]))
    return {
        "byte_count": budget.bytes - before_bytes,
        "directory_count": budget.directories - before_directories,
        "entries": entries,
        "entries_sha256": hashlib.sha256(canonical_document(entries)).hexdigest(),
        "file_count": budget.files - before_files,
        "name": component,
    }


def _require_exact_children(root: Path, expected: set[str], label: str) -> None:
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ExportError(f"cannot inspect {label} inventory: {error}") from error
    names = {entry.name for entry in entries}
    if names != expected or len(entries) != len(expected):
        raise ExportError(f"{label} inventory is not exact")
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ExportError(f"{label} inventory contains a non-regular file")


def _copy_payload(roots: SnapshotRoots, payload: Path) -> dict[str, Any]:
    _require_exact_children(
        roots.bundle, BUNDLE_METADATA_FILES, "bundle metadata root"
    )
    _require_exact_children(
        roots.config, {"runtime.json", "runtime.json.sha256"}, "config root"
    )
    _require_exact_children(
        roots.launch, {"receipt.json", "receipt.json.sha256"}, "launch root"
    )
    try:
        payload.mkdir(mode=0o700)
    except OSError as error:
        raise ExportError(f"cannot create export payload root: {error}") from error
    budget = _Budget()
    components: list[dict[str, Any]] = []
    for name in COMPONENTS:
        source = roots.component(name)
        destination = payload / name
        root_path = "."
        wrapper: Path | None = None
        if name in NAMED_COMPONENTS:
            _safe_component_name(source.name)
            wrapper = destination
            try:
                wrapper.mkdir(mode=0o700)
            except OSError as error:
                raise ExportError(
                    f"cannot create portable {name} name wrapper: {error}"
                ) from error
            destination = wrapper / source.name
            root_path = source.name
        components.append(
            _component_document(
                source,
                name,
                budget,
                destination,
                root_path,
            )
        )
        if wrapper is not None:
            wrapper.chmod(0o555)
            _fsync_directory(wrapper)
    payload.chmod(0o555)
    return {
        "schema": INVENTORY_SCHEMA,
        "components": components,
        "totals": {
            "byte_count": budget.bytes,
            "directory_count": budget.directories,
            "file_count": budget.files,
        },
    }


def _portable_component_roots(payload: Path) -> dict[str, Path]:
    payload = _require_real_absolute_directory(payload, "portable payload root")
    try:
        entries = list(os.scandir(payload))
    except OSError as error:
        raise ExportError(f"cannot inspect portable payload inventory: {error}") from error
    if sorted(entry.name for entry in entries) != list(COMPONENTS) or any(
        not stat.S_ISDIR(entry.stat(follow_symlinks=False).st_mode) for entry in entries
    ):
        raise ExportError("portable payload component inventory drift")
    roots: dict[str, Path] = {}
    for name in COMPONENTS:
        component = payload / name
        if name not in NAMED_COMPONENTS:
            roots[name] = _require_real_absolute_directory(
                component, f"portable {name} root"
            )
            continue
        try:
            metadata = component.lstat()
            children = list(os.scandir(component))
        except OSError as error:
            raise ExportError(
                f"cannot inspect portable {name} name wrapper: {error}"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _mode(metadata) != 0o555
            or len(children) != 1
        ):
            raise ExportError(
                f"portable {name} name wrapper inventory or mode drift"
            )
        child = children[0]
        _safe_component_name(child.name)
        child_metadata = child.stat(follow_symlinks=False)
        if not stat.S_ISDIR(child_metadata.st_mode):
            raise ExportError(f"portable {name} named root is not a directory")
        roots[name] = _require_real_absolute_directory(
            component / child.name, f"portable named {name} root"
        )
    return roots


def _scan_payload(payload: Path) -> dict[str, Any]:
    roots = _portable_component_roots(payload)
    _require_exact_children(
        roots["bundle"], BUNDLE_METADATA_FILES, "portable bundle metadata root"
    )
    _require_exact_children(
        roots["config"],
        {"runtime.json", "runtime.json.sha256"},
        "portable config root",
    )
    _require_exact_children(
        roots["launch"],
        {"receipt.json", "receipt.json.sha256"},
        "portable launch root",
    )
    budget = _Budget()
    components = [
        _component_document(
            roots[name],
            name,
            budget,
            root_path=(roots[name].name if name in NAMED_COMPONENTS else "."),
        )
        for name in COMPONENTS
    ]
    return {
        "schema": INVENTORY_SCHEMA,
        "components": components,
        "totals": {
            "byte_count": budget.bytes,
            "directory_count": budget.directories,
            "file_count": budget.files,
        },
    }


def _payload_summary(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        item["name"]: {
            "byte_count": item["byte_count"],
            "directory_count": item["directory_count"],
            "entries_sha256": item["entries_sha256"],
            "file_count": item["file_count"],
        }
        for item in inventory["components"]
    }


def _snapshot_roots(payload: Path) -> SnapshotRoots:
    return SnapshotRoots(**_portable_component_roots(payload))


def _load_stage_module():
    path = Path(__file__).resolve(strict=True).with_name("stage_stability_campaign.py")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ExportError(f"trusted staging verifier is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ExportError("trusted staging verifier is not a standalone regular file")
    specification = importlib.util.spec_from_file_location(
        "codeskeptic_export_trusted_staging", path
    )
    if specification is None or specification.loader is None:
        raise ExportError("cannot load trusted staging verifier")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    previous_bytecode_policy = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        specification.loader.exec_module(module)
    except Exception as error:
        raise ExportError(f"cannot initialize trusted staging verifier: {error}") from error
    finally:
        sys.dont_write_bytecode = previous_bytecode_policy
    return module


def _verify_operator_snapshot(stage: Any, roots: SnapshotRoots) -> None:
    source = roots.authority / "source"
    systemd = source / "scripts" / "stability-systemd"
    expected = {
        "README.md": systemd / "README.md",
        "cgroup-authority.py": systemd / "cgroup-authority.py",
        "container-entry.py": systemd / "container-entry.py",
        "containers.conf": systemd / "containers.conf",
        "host-recovery.py": systemd / "host-recovery.py",
        "guided-stability.sh": systemd / "guided-stability.sh",
        "post-stop.sh": systemd / "post-stop.sh",
        "run-authoritative-stability.sh": systemd / "run-authoritative-stability.sh",
        stage.UNIT_NAME: systemd / stage.UNIT_NAME,
        "stage_stability_campaign.py": source / "scripts" / "stage_stability_campaign.py",
    }
    try:
        actual = sorted(path.name for path in roots.operator.iterdir())
    except OSError as error:
        raise ExportError(f"cannot inspect exported operator: {error}") from error
    if actual != sorted(expected):
        raise ExportError("exported operator exact-head inventory drift")
    for name, source_path in expected.items():
        operator_path = roots.operator / name
        maximum = MAX_DOCUMENT_BYTES if name != stage.UNIT_NAME else 1024 * 1024
        if _read_regular(
            operator_path, maximum, f"operator {name}"
        ) != _read_regular(
            source_path,
            maximum,
            f"source operator {name}",
        ):
            raise ExportError(f"exported operator {name} differs from exact-head source")
        expected_mode = 0o555 if name.endswith((".sh", ".py")) else 0o444
        if _mode(operator_path.lstat()) != expected_mode:
            raise ExportError(f"exported operator {name} mode drift")
    try:
        stage.verify_static_unit(roots.operator / stage.UNIT_NAME)
        stage._reject_operator_hooks(roots.operator)  # noqa: SLF001
    except Exception as error:
        raise ExportError(f"exported operator semantic verification failed: {error}") from error


def _verify_installed_roots_against_bundle(
    stage: Any,
    roots: SnapshotRoots,
    inventory: list[dict[str, Any]],
) -> None:
    try:
        parts = stage._payload_inventory_parts(inventory)  # noqa: SLF001
        for name in ("authority", "config", "operator"):
            expected_root, expected_children = parts[name]
            copied_root = roots.component(name)
            metadata = copied_root.lstat()
            actual_root = {
                "path": name,
                "type": "directory",
                "mode": f"{_mode(metadata):04o}",
            }
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or actual_root != expected_root
                or stage.collect_inventory(copied_root) != expected_children
            ):
                raise ExportError(
                    f"installed {name} differs from sealed bundle inventory"
                )
    except ExportError:
        raise
    except Exception as error:
        raise ExportError(
            f"installed root inventory verification failed: {error}"
        ) from error


def bootstrap_authorities(
    roots: SnapshotRoots,
    expected_source_revision: str,
    expected_bundle_receipt_sha256: str,
    scratch_root: Path,
) -> dict[str, Any]:
    """Bind copied installed authorities to the two out-of-band identities."""

    del scratch_root
    revision = _valid_revision(expected_source_revision, "expected source revision")
    bundle_sha = _valid_sha256(
        expected_bundle_receipt_sha256, "expected bundle receipt checksum"
    )
    stage = _load_stage_module()
    try:
        bundle_receipt, bundle_inventory = stage._verify_bundle_metadata(  # noqa: SLF001
            roots.bundle
        )
        bundle_receipt_data = _read_regular(
            roots.bundle / "receipt.json",
            MAX_DOCUMENT_BYTES,
            "retained sealed bundle receipt",
        )
        if (
            hashlib.sha256(bundle_receipt_data).hexdigest() != bundle_sha
            or bundle_receipt["revision"] != revision
        ):
            raise ExportError(
                "retained sealed bundle differs from out-of-band authority"
            )
        _verify_installed_roots_against_bundle(
            stage, roots, bundle_inventory
        )
        config, config_data = stage._runtime_config_at(  # noqa: SLF001
            roots.config / "runtime.json", roots.authority
        )
        source_identity = stage.validate_staged_source(
            roots.authority / "source", revision
        )
    except Exception as error:
        raise ExportError(f"installed authority bootstrap verification failed: {error}") from error
    source = config.get("source")
    if not isinstance(source, dict) or source != {
        "root": "/authority/source",
        "revision": revision,
        "tree_sha1": source_identity["tree_sha1"],
        "manifest_sha256": source_identity["manifest_sha256"],
    }:
        raise ExportError("installed source differs from out-of-band authority")
    config_sha = hashlib.sha256(config_data).hexdigest()
    if (
        bundle_receipt["runtime_config_sha256"] != config_sha
        or bundle_receipt["source_manifest_sha256"]
        != source_identity["manifest_sha256"]
        or bundle_receipt["source_tree_sha1"] != source_identity["tree_sha1"]
    ):
        raise ExportError("installed roots differ from retained sealed bundle")
    _verify_operator_snapshot(stage, roots)

    outer = _load_document(
        roots.session / "receipt.json", MAX_DOCUMENT_BYTES, "outer operator receipt"
    )
    outer_session = outer.get("session")
    if not isinstance(outer_session, dict) or outer_session.get("name") != roots.session.name:
        raise ExportError("outer operator session identity drift")
    intent = _load_compact_document(
        roots.session / "host" / "host-recovery-intent.json",
        MAX_DOCUMENT_BYTES,
        "host recovery intent",
    )
    installation = intent.get("installation")
    expected_installation_fields = {
        "bundle_inventory_sha256",
        "bundle_receipt_sha256",
        "bundle_revision",
        "image_archive_sha256",
        "image_digest",
        "image_id",
        "image_reference",
        "installation_receipt_sha256",
        "installation_authority_sha256",
        "installed_inventory_sha256",
        "runtime_config_sha256",
        "source_manifest_sha256",
        "source_tree_sha1",
    }
    installation = _exact_dict(
        installation, expected_installation_fields, "host recovery installation"
    )
    installation_authority = {
        "bundle_receipt_sha256": bundle_sha,
        "bundle_revision": revision,
        "schema": stage.INSTALLATION_AUTHORITY_SCHEMA,
    }
    installation_receipt = stage.validate_installation_receipt({
        "authority_root": stage.AUTHORITY_ROOT.as_posix(),
        "bundle_inventory_sha256": bundle_receipt["inventory_sha256"],
        "bundle_receipt_sha256": bundle_sha,
        "bundle_revision": revision,
        "config_path": stage.CONFIG_PATH.as_posix(),
        "image": {
            "archive_sha256": bundle_receipt["image_archive_sha256"],
            "digest": stage.PINNED_EVIDENCE_IMAGE_DIGEST,
            "id": stage.PINNED_EVIDENCE_IMAGE_ID,
            "reference": stage.PINNED_EVIDENCE_IMAGE,
        },
        "installed_inventory_sha256": bundle_receipt["inventory_sha256"],
        "operator_root": stage.OPERATOR_ROOT.as_posix(),
        "schema": stage.INSTALLATION_RECEIPT_SCHEMA,
        "unit_path": stage.UNIT_PATH.as_posix(),
    })
    expected_installation = {
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
        "source_manifest_sha256": bundle_receipt["source_manifest_sha256"],
        "source_tree_sha1": bundle_receipt["source_tree_sha1"],
    }
    if installation != expected_installation:
        raise ExportError(
            "host recovery installation differs from retained sealed bundle"
        )

    launch_path = FIXED_LAUNCH_ROOT / roots.launch.name / "receipt.json"
    authorities = outer.get("authorities")
    if not isinstance(authorities, dict):
        raise ExportError("outer operator authority inventory drift")
    fixed_records = {
        "config": (FIXED_CONFIG_ROOT / "runtime.json", roots.config / "runtime.json"),
        "config_checksum": (
            FIXED_CONFIG_ROOT / "runtime.json.sha256",
            roots.config / "runtime.json.sha256",
        ),
        "launch_receipt": (launch_path, roots.launch / "receipt.json"),
        "launch_checksum": (
            Path(f"{launch_path}.sha256"),
            roots.launch / "receipt.json.sha256",
        ),
        "operator": (FIXED_OPERATOR, roots.operator / FIXED_OPERATOR.name),
        "runner": (FIXED_RUNNER, roots.authority / "source/scripts/run_stability_campaign.py"),
    }
    for name, (fixed_path, copied_path) in fixed_records.items():
        record = authorities.get(name)
        if (
            not isinstance(record, dict)
            or record.get("path") != fixed_path.as_posix()
            or record.get("sha256") != _sha256_regular(copied_path)
            or record.get("size") != copied_path.lstat().st_size
        ):
            raise ExportError(f"outer {name} authority differs from copied root")
    return {
        "bundle_receipt_sha256": bundle_sha,
        "runtime_config_sha256": config_sha,
        "session_name": roots.session.name,
        "source_manifest_sha256": source_identity["manifest_sha256"],
        "source_revision": revision,
        "source_tree_sha1": source_identity["tree_sha1"],
    }


def _namespace_prefix(roots: SnapshotRoots) -> list[str]:
    launch_name = roots.launch.name
    session_name = roots.session.name
    if SAFE_NAME.fullmatch(launch_name) is None or SAFE_NAME.fullmatch(session_name) is None:
        raise ExportError("portable launch or session directory name is inadmissible")
    campaign = roots.session / "campaign"
    _require_real_absolute_directory(campaign, "portable inner campaign root")
    fixed_launch = FIXED_LAUNCH_ROOT / launch_name
    fixed_session = FIXED_SESSION_ROOT / session_name
    return [
        BWRAP.as_posix(),
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--clearenv",
        "--setenv", "HOME", "/root",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "LC_ALL", "C.UTF-8",
        "--setenv", "PATH", "/usr/bin:/usr/sbin",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--setenv", "GIT_CONFIG_NOSYSTEM", "1",
        "--setenv", "GIT_CONFIG_GLOBAL", "/dev/null",
        "--setenv", "GIT_OPTIONAL_LOCKS", "0",
        "--setenv", "GIT_TERMINAL_PROMPT", "0",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/sbin", "/sbin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--tmpfs", "/etc",
        "--tmpfs", "/run",
        "--tmpfs", "/runtime",
        "--dir", "/root",
        "--dir", "/home",
        "--dir", "/authority",
        "--dir", "/config",
        "--dir", "/evidence",
        "--dir", "/launch",
        "--dir", "/opt",
        "--dir", "/opt/codeskeptic-p10-09",
        "--dir", FIXED_AUTHORITY_ROOT.as_posix(),
        "--dir", FIXED_OPERATOR_ROOT.as_posix(),
        "--dir", "/etc/codeskeptic-p10-09",
        "--dir", "/var",
        "--dir", "/var/lib",
        "--dir", FIXED_STATE_ROOT.as_posix(),
        "--dir", FIXED_LAUNCH_ROOT.as_posix(),
        "--dir", fixed_launch.as_posix(),
        "--dir", FIXED_SESSION_ROOT.as_posix(),
        "--dir", fixed_session.as_posix(),
        "--ro-bind", roots.authority.as_posix(), "/authority",
        "--ro-bind", roots.authority.as_posix(), FIXED_AUTHORITY_ROOT.as_posix(),
        "--ro-bind", roots.operator.as_posix(), FIXED_OPERATOR_ROOT.as_posix(),
        "--ro-bind", roots.config.as_posix(), "/config",
        "--ro-bind", roots.config.as_posix(), FIXED_CONFIG_ROOT.as_posix(),
        "--ro-bind", roots.launch.as_posix(), "/launch",
        "--ro-bind", roots.launch.as_posix(), fixed_launch.as_posix(),
        "--ro-bind", campaign.as_posix(), "/evidence",
        "--ro-bind", roots.session.as_posix(), fixed_session.as_posix(),
        "--chdir", "/authority/source",
    ]


def semantic_commands(roots: SnapshotRoots) -> tuple[list[str], list[str]]:
    for name in COMPONENTS:
        _require_real_absolute_directory(roots.component(name), f"portable {name} root")
    _require_regular_executable(BWRAP, "bubblewrap")
    _require_regular_executable(PRLIMIT, "prlimit")
    _require_regular_executable(PYTHON, "Python")
    prefix = _namespace_prefix(roots)
    constrained_python = [
        "--",
        PRLIMIT.as_posix(),
        "--nofile=4096:4096",
        "--",
        PYTHON.as_posix(),
        "-B",
        FIXED_RUNNER.as_posix(),
    ]
    inner = [
        *prefix,
        *constrained_python,
        "verify",
        "--config", "/config/runtime.json",
        "--evidence", "/evidence",
    ]
    outer = [
        *prefix,
        *constrained_python,
        "verify-operator",
        "--session-root", (FIXED_SESSION_ROOT / roots.session.name).as_posix(),
        "--config", (FIXED_CONFIG_ROOT / "runtime.json").as_posix(),
        "--launch-receipt", (
            FIXED_LAUNCH_ROOT / roots.launch.name / "receipt.json"
        ).as_posix(),
        "--operator", FIXED_OPERATOR.as_posix(),
    ]
    return inner, outer


def _default_command_runner(argv: list[str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExportError(f"offline semantic verifier could not complete: {error}") from error


def run_semantic_verifiers(
    roots: SnapshotRoots,
    command_runner: Callable[[list[str], int], Any] | None = None,
) -> dict[str, Any]:
    """Replay the actual inner and outer verifiers in an offline namespace."""

    runner = _default_command_runner if command_runner is None else command_runner
    if not callable(runner):
        raise ExportError("offline semantic command runner is unavailable")
    commands = semantic_commands(roots)
    parsed: list[tuple[str, str]] = []
    patterns = (INNER_MARKER, OUTER_MARKER)
    for ordinal, (command, pattern) in enumerate(zip(commands, patterns), 1):
        try:
            completed = runner(command, SEMANTIC_TIMEOUT_SECONDS)
        except ExportError:
            raise
        except Exception as error:
            raise ExportError(f"offline semantic verifier invocation failed: {error}") from error
        stdout = getattr(completed, "stdout", None)
        stderr = getattr(completed, "stderr", None)
        returncode = getattr(completed, "returncode", None)
        match = pattern.fullmatch(stdout) if isinstance(stdout, bytes) else None
        if returncode != 0 or stderr != b"" or match is None:
            detail = (
                stderr.decode("utf-8", errors="replace")[-1000:].strip()
                if isinstance(stderr, bytes)
                else "malformed verifier result"
            )
            raise ExportError(
                f"offline semantic verifier {ordinal} failed exact replay"
                + (f": {detail}" if detail else "")
            )
        parsed.append((match.group(1).decode("ascii"), match.group(2).decode("ascii")))
    if parsed[0][1] != parsed[1][1]:
        raise ExportError("inner and outer semantic verifier session identities differ")
    return {
        "inner_receipt_sha256": parsed[0][0],
        "outer_receipt_sha256": parsed[1][0],
        "session_id": parsed[0][1],
    }


def _normalize_bootstrap(value: Any) -> dict[str, Any]:
    record = _exact_dict(
        value,
        {
            "bundle_receipt_sha256",
            "runtime_config_sha256",
            "session_name",
            "source_manifest_sha256",
            "source_revision",
            "source_tree_sha1",
        },
        "export identity",
    )
    _valid_sha256(record["bundle_receipt_sha256"], "export bundle receipt")
    _valid_sha256(record["runtime_config_sha256"], "export runtime config")
    _valid_sha256(record["source_manifest_sha256"], "export source manifest")
    _valid_revision(record["source_revision"], "export source revision")
    _valid_revision(record["source_tree_sha1"], "export source tree")
    if (
        not isinstance(record["session_name"], str)
        or SAFE_NAME.fullmatch(record["session_name"]) is None
    ):
        raise ExportError("export session name is malformed")
    return dict(record)


def _normalize_semantic(value: Any) -> dict[str, str]:
    record = _exact_dict(
        value,
        {"inner_receipt_sha256", "outer_receipt_sha256", "session_id"},
        "semantic verification",
    )
    return {
        name: _valid_sha256(record[name], f"semantic {name}")
        for name in ("inner_receipt_sha256", "outer_receipt_sha256", "session_id")
    }


def _metadata_manifest(root: Path) -> bytes:
    names = (
        "inventory.json",
        "inventory.json.sha256",
        "receipt.json",
        "receipt.json.sha256",
    )
    return b"".join(
        f"{_sha256_regular(root / name, MAX_DOCUMENT_BYTES)}  {name}\n".encode("ascii")
        for name in names
    )


def _write_metadata(
    root: Path,
    inventory: dict[str, Any],
    identity: dict[str, Any],
    semantic: dict[str, str],
) -> dict[str, Any]:
    inventory_data = canonical_document(inventory)
    if len(inventory_data) > MAX_DOCUMENT_BYTES:
        raise ExportError("portable detailed inventory exceeds its fixed size limit")
    inventory_sha = hashlib.sha256(inventory_data).hexdigest()
    _atomic_create(root / "inventory.json", inventory_data)
    _atomic_create(
        root / "inventory.json.sha256",
        f"{inventory_sha}  inventory.json\n".encode("ascii"),
    )
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "accepted",
        "identity": identity,
        "inventory": {
            "path": "inventory.json",
            "sha256": inventory_sha,
            "size": len(inventory_data),
        },
        "payload": _payload_summary(inventory),
        "semantic_verification": semantic,
        "gates": {
            "bootstrap_authority": "pass",
            "inner_semantic_replay": "pass",
            "inventory": "pass",
            "outer_semantic_replay": "pass",
        },
        "failures": [],
    }
    receipt_data = canonical_document(receipt)
    if len(receipt_data) > MAX_RECEIPT_BYTES:
        raise ExportError("portable compact receipt exceeds its fixed size limit")
    receipt_sha = hashlib.sha256(receipt_data).hexdigest()
    _atomic_create(root / "receipt.json", receipt_data)
    _atomic_create(
        root / "receipt.json.sha256",
        f"{receipt_sha}  receipt.json\n".encode("ascii"),
    )
    _atomic_create(root / "SHA256SUMS", _metadata_manifest(root))
    return receipt


def _require_metadata_structure(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root = _require_real_absolute_directory(root, "portable export root")
    if _mode(root.lstat()) != 0o555:
        raise ExportError("portable export root mode drift")
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ExportError(f"cannot inspect portable export inventory: {error}") from error
    expected = {
        "SHA256SUMS",
        "inventory.json",
        "inventory.json.sha256",
        "payload",
        "receipt.json",
        "receipt.json.sha256",
    }
    if {entry.name for entry in entries} != expected or len(entries) != len(expected):
        raise ExportError("portable export root inventory drift")
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        if entry.name == "payload":
            if not stat.S_ISDIR(metadata.st_mode) or _mode(metadata) != 0o555:
                raise ExportError("portable payload inventory or mode drift")
        elif (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or _mode(metadata) != 0o444
        ):
            raise ExportError("portable metadata inventory or mode drift")
    inventory = _load_document(
        root / "inventory.json", MAX_DOCUMENT_BYTES, "portable inventory"
    )
    receipt = _load_document(root / "receipt.json", MAX_RECEIPT_BYTES, "portable receipt")
    inventory_data = _read_regular(
        root / "inventory.json", MAX_DOCUMENT_BYTES, "portable inventory"
    )
    receipt_data = _read_regular(root / "receipt.json", MAX_RECEIPT_BYTES, "portable receipt")
    if _read_regular(
        root / "inventory.json.sha256", 1024, "portable inventory sidecar"
    ) != f"{hashlib.sha256(inventory_data).hexdigest()}  inventory.json\n".encode("ascii"):
        raise ExportError("portable inventory checksum sidecar mismatch")
    if _read_regular(
        root / "receipt.json.sha256", 1024, "portable receipt sidecar"
    ) != f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n".encode("ascii"):
        raise ExportError("portable receipt checksum sidecar mismatch")
    if _read_regular(
        root / "SHA256SUMS", MAX_DOCUMENT_BYTES, "portable manifest"
    ) != _metadata_manifest(root):
        raise ExportError("portable metadata checksum manifest mismatch")
    return inventory, receipt


def _validate_inventory_document(value: Any) -> dict[str, Any]:
    document = _exact_dict(value, {"schema", "components", "totals"}, "portable inventory")
    if document["schema"] != INVENTORY_SCHEMA:
        raise ExportError("portable inventory schema drift")
    components = document["components"]
    names = [
        item.get("name") if isinstance(item, dict) else None
        for item in components
    ] if isinstance(components, list) else []
    if not isinstance(components, list) or names != list(COMPONENTS):
        raise ExportError("portable component inventory drift")
    for item in components:
        _exact_dict(
            item,
            {"byte_count", "directory_count", "entries", "entries_sha256", "file_count", "name"},
            "portable component",
        )
        entries = item["entries"]
        if (
            not isinstance(entries, list)
            or hashlib.sha256(canonical_document(entries)).hexdigest()
            != item["entries_sha256"]
        ):
            raise ExportError("portable component entries inventory drift")
    totals = _exact_dict(
        document["totals"], {"byte_count", "directory_count", "file_count"}, "portable totals"
    )
    for name in totals:
        if isinstance(totals[name], bool) or not isinstance(totals[name], int) or totals[name] < 0:
            raise ExportError("portable inventory totals are malformed")
    return document


def _validate_receipt_document(
    value: Any,
    inventory: dict[str, Any],
    expected_source_revision: str,
    expected_bundle_receipt_sha256: str,
) -> dict[str, Any]:
    receipt = _exact_dict(
        value,
        {
            "schema", "status", "identity", "inventory", "payload",
            "semantic_verification", "gates", "failures",
        },
        "portable receipt",
    )
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["status"] != "accepted"
        or receipt["failures"] != []
    ):
        raise ExportError("portable receipt is not accepted")
    identity = _normalize_bootstrap(receipt["identity"])
    if (
        identity["source_revision"] != expected_source_revision
        or identity["bundle_receipt_sha256"] != expected_bundle_receipt_sha256
    ):
        raise ExportError("portable receipt differs from out-of-band authority")
    inventory_record = _exact_dict(
        receipt["inventory"], {"path", "sha256", "size"}, "portable inventory record"
    )
    inventory_data = canonical_document(inventory)
    if inventory_record != {
        "path": "inventory.json",
        "sha256": hashlib.sha256(inventory_data).hexdigest(),
        "size": len(inventory_data),
    }:
        raise ExportError("portable receipt inventory identity drift")
    if receipt["payload"] != _payload_summary(inventory):
        raise ExportError("portable receipt payload inventory drift")
    _normalize_semantic(receipt["semantic_verification"])
    if receipt["gates"] != {
        "bootstrap_authority": "pass",
        "inner_semantic_replay": "pass",
        "inventory": "pass",
        "outer_semantic_replay": "pass",
    }:
        raise ExportError("portable receipt gate drift")
    return receipt


def _static_verify_export(
    root: Path,
    expected_source_revision: str,
    expected_bundle_receipt_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _valid_revision(expected_source_revision, "expected source revision")
    _valid_sha256(expected_bundle_receipt_sha256, "expected bundle receipt checksum")
    inventory, receipt = _require_metadata_structure(root)
    inventory = _validate_inventory_document(inventory)
    receipt = _validate_receipt_document(
        receipt, inventory, expected_source_revision, expected_bundle_receipt_sha256
    )
    actual = _scan_payload(root / "payload")
    if actual != inventory:
        raise ExportError("portable payload inventory differs from its sealed inventory")
    return inventory, receipt


def _validate_output_path(output: Path, roots: SnapshotRoots) -> Path:
    if not output.is_absolute() or Path(os.path.normpath(os.fspath(output))) != output:
        raise ExportError("export output is not an absolute canonical path")
    parent = _require_real_absolute_directory(output.parent, "export output parent")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ExportError(f"cannot inspect export output: {error}") from error
    else:
        raise ExportError("export output already exists")
    for source in roots:
        source = _require_real_absolute_directory(source, "trusted export input")
        try:
            output.relative_to(source)
        except ValueError:
            pass
        else:
            raise ExportError("export output is nested inside a trusted input root")
    return parent


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise ExportError("atomic no-replace directory publication is unavailable")
    function.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise ExportError("export output already exists")
    raise ExportError(f"cannot atomically publish export: {os.strerror(error_number)}")


def _remove_private_temporary(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ExportError(f"cannot inspect failed export temporary: {error}") from error
    if (metadata.st_dev, metadata.st_ino) != identity or not path.name.startswith("."):
        raise ExportError("failed export temporary identity changed; refusing cleanup")
    for directory, directories, files in os.walk(path, topdown=False, followlinks=False):
        directory_path = Path(directory)
        for name in files:
            child = directory_path / name
            try:
                child.chmod(0o600, follow_symlinks=False)
            except OSError:
                pass
        for name in directories:
            child = directory_path / name
            try:
                child.chmod(0o700, follow_symlinks=False)
            except OSError:
                pass
        try:
            directory_path.chmod(0o700)
        except OSError:
            pass
    try:
        shutil.rmtree(path)
    except OSError as error:
        raise ExportError(f"cannot clean failed export temporary: {error}") from error


def export_evidence(
    roots: SnapshotRoots,
    output: Path,
    *,
    expected_source_revision: str,
    expected_bundle_receipt_sha256: str,
    bootstrap_verifier: Callable[[SnapshotRoots, str, str, Path], Any] | None = None,
    semantic_verifier: Callable[[SnapshotRoots], Any] | None = None,
) -> dict[str, Any]:
    """Create one immutable, atomically published external evidence bundle."""

    revision = _valid_revision(expected_source_revision, "expected source revision")
    bundle_sha = _valid_sha256(
        expected_bundle_receipt_sha256, "expected bundle receipt checksum"
    )
    bootstrap = bootstrap_authorities if bootstrap_verifier is None else bootstrap_verifier
    semantic = run_semantic_verifiers if semantic_verifier is None else semantic_verifier
    if not callable(bootstrap) or not callable(semantic):
        raise ExportError("required export verifier is unavailable")
    roots = SnapshotRoots(**{
        name: _require_real_absolute_directory(roots.component(name), f"trusted {name} root")
        for name in COMPONENTS
    })
    parent = _validate_output_path(Path(output), roots)
    temporary = parent / f".{Path(output).name}.tmp-{secrets.token_hex(12)}"
    try:
        temporary.mkdir(mode=0o700)
        temporary_metadata = temporary.lstat()
    except OSError as error:
        raise ExportError(f"cannot create private export temporary: {error}") from error
    identity = (temporary_metadata.st_dev, temporary_metadata.st_ino)
    published = False
    try:
        inventory = _copy_payload(roots, temporary / "payload")
        copied = _snapshot_roots(temporary / "payload")
        bootstrap_record = _normalize_bootstrap(
            bootstrap(copied, revision, bundle_sha, temporary)
        )
        if (
            bootstrap_record["source_revision"] != revision
            or bootstrap_record["bundle_receipt_sha256"] != bundle_sha
        ):
            raise ExportError("bootstrap result differs from out-of-band authority")
        semantic_record = _normalize_semantic(semantic(copied))
        if _scan_payload(temporary / "payload") != inventory:
            raise ExportError("copied payload inventory changed during semantic verification")
        receipt = _write_metadata(
            temporary, inventory, bootstrap_record, semantic_record
        )
        temporary.chmod(0o555)
        _static_verify_export(temporary, revision, bundle_sha)
        _fsync_directory(temporary / "payload")
        _fsync_directory(temporary)
        _rename_noreplace(temporary, Path(output))
        published = True
        _fsync_directory(parent)
        return receipt
    except BaseException as error:
        if not published:
            try:
                _remove_private_temporary(temporary, identity)
            except Exception as cleanup_error:
                raise ExportError(
                    f"export failed: {error}; temporary cleanup failed: {cleanup_error}"
                ) from error
        if isinstance(error, ExportError):
            raise
        raise ExportError(f"portable evidence export failed: {error}") from error


def verify_export(
    bundle: Path,
    *,
    expected_source_revision: str,
    expected_bundle_receipt_sha256: str,
    bootstrap_verifier: Callable[[SnapshotRoots, str, str, Path], Any] | None = None,
    semantic_verifier: Callable[[SnapshotRoots], Any] | None = None,
) -> dict[str, Any]:
    """Replay one portable export without consulting live installed state."""

    try:
        revision = _valid_revision(
            expected_source_revision, "expected source revision"
        )
        bundle_sha = _valid_sha256(
            expected_bundle_receipt_sha256,
            "expected bundle receipt checksum",
        )
        bundle = _require_real_absolute_directory(
            Path(bundle), "portable export root"
        )
        _inventory, receipt = _static_verify_export(
            bundle, revision, bundle_sha
        )
        roots = _snapshot_roots(bundle / "payload")
        bootstrap = (
            bootstrap_authorities
            if bootstrap_verifier is None
            else bootstrap_verifier
        )
        semantic = (
            run_semantic_verifiers
            if semantic_verifier is None
            else semantic_verifier
        )
        if not callable(bootstrap) or not callable(semantic):
            raise ExportError("required offline verifier is unavailable")
        bootstrap_record = _normalize_bootstrap(
            bootstrap(roots, revision, bundle_sha, bundle.parent)
        )
        semantic_record = _normalize_semantic(semantic(roots))
        if bootstrap_record != receipt["identity"]:
            raise ExportError(
                "offline bootstrap identity differs from compact receipt"
            )
        if semantic_record != receipt["semantic_verification"]:
            raise ExportError(
                "offline semantic replay differs from compact receipt"
            )
        final_inventory, final_receipt = _static_verify_export(
            bundle, revision, bundle_sha
        )
        if final_inventory != _inventory or final_receipt != receipt:
            raise ExportError(
                "portable export changed during offline verification"
            )
        return receipt
    except ExportError:
        raise
    except Exception as error:
        raise ExportError(
            f"portable evidence verification failed: {error}"
        ) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"CodeSkeptic P10-09 evidence exporter {TOOL_VERSION}",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("export", help="create a portable evidence bundle")
    create.add_argument("--authority-root", type=Path, required=True)
    create.add_argument("--bundle-root", type=Path, required=True)
    create.add_argument("--operator-root", type=Path, required=True)
    create.add_argument("--config-root", type=Path, required=True)
    create.add_argument("--launch-root", type=Path, required=True)
    create.add_argument("--session-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--expected-source-revision", required=True)
    create.add_argument("--expected-bundle-receipt-sha256", required=True)
    verify = commands.add_parser("verify", help="replay an exported bundle offline")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-source-revision", required=True)
    verify.add_argument("--expected-bundle-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "export":
            receipt = export_evidence(
                SnapshotRoots(
                    authority=arguments.authority_root,
                    bundle=arguments.bundle_root,
                    operator=arguments.operator_root,
                    config=arguments.config_root,
                    launch=arguments.launch_root,
                    session=arguments.session_root,
                ),
                arguments.output,
                expected_source_revision=arguments.expected_source_revision,
                expected_bundle_receipt_sha256=(
                    arguments.expected_bundle_receipt_sha256
                ),
            )
            print(
                "CODESKEPTIC_STABILITY_EXPORT_CREATED "
                f"{_sha256_regular(arguments.output / 'receipt.json', MAX_RECEIPT_BYTES)} "
                f"{receipt['identity']['session_name']}"
            )
            return 0
        if arguments.command == "verify":
            receipt = verify_export(
                arguments.bundle,
                expected_source_revision=arguments.expected_source_revision,
                expected_bundle_receipt_sha256=(
                    arguments.expected_bundle_receipt_sha256
                ),
            )
            print(
                "CODESKEPTIC_STABILITY_EXPORT_VERIFIED "
                f"{_sha256_regular(arguments.bundle / 'receipt.json', MAX_RECEIPT_BYTES)} "
                f"{receipt['identity']['session_name']}"
            )
            return 0
        raise ExportError("unsupported evidence export command")
    except ExportError as error:
        print(f"CODESKEPTIC_STABILITY_EXPORT_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
