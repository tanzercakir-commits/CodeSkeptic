#!/usr/bin/env python3
"""Plan, execute, and referee deterministic real-repository campaigns."""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import ctypes
import copy
import hashlib
import json
import math
import os
import re
import selectors
import shlex
import shutil
import signal
import stat
import string
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse


SCHEMA = 1
SHA40 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PROJECT_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
FINGERPRINT = re.compile(r"csf1-[0-9a-f]{16}")
ALLOWED_COMMANDS = {"bear", "cmake", "meson"}
ALLOWED_PLACEHOLDERS = {"source", "build", "jobs"}
MESON_OPTION = re.compile(
    r"(?:--buildtype=(?:debug|release|debugoptimized|minsize)|"
    r"-D[A-Za-z0-9_-]+=[A-Za-z0-9_.+-]+)"
)
MESON_TARGET = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:+-]*")
MAKE_ASSIGNMENT = re.compile(r"[A-Z_][A-Z0-9_]*=.*")
BUILD_ENVIRONMENT = {"CC", "CXX"}
BUILD_TOOL = re.compile(r"/usr/bin/[A-Za-z0-9_.+-]+")
REQUIRED_EXPECTED = {
    "translation_units",
    "translation_unit_sha256",
    "attempted_tus",
    "analyzed_tus",
    "broken_tus",
    "incomplete_functions",
    "findings",
    "exit_code",
    "fingerprint_sha256",
}
MAX_RECEIPT_BYTES = 16 << 20
MAX_CHECKSUM_BYTES = 1024
MAX_MANIFEST_BYTES = 4 << 20
MAX_COMPILE_DATABASE_BYTES = 64 << 20
MAX_ANALYZER_REPORT_BYTES = 256 << 20
MAX_COMMAND_LOG_BYTES = 64 << 20
MAX_COMMAND_CAPTURE_BYTES = 16 << 20
# Calibrated for the pinned release-candidate scope (3 projects and 53 recursive
# submodules): 8 GiB is over 6x the largest top-level repository metadata size,
# while 96 GiB is an observed-growth ceiling with substantial scratch margin.
# This is defense in depth, not a claim of a universal filesystem quota.
MAX_PROCESS_FILE_BYTES = 8 << 30
MAX_SHARD_WORKSPACE_ALLOCATED_BYTES = 96 << 30
MIN_SHARD_FILESYSTEM_FREE_BYTES = 8 << 30
SHARD_EMERGENCY_RESERVE_BYTES = MIN_SHARD_FILESYSTEM_FREE_BYTES
MAX_SHARD_WORKSPACE_ENTRIES = 2_000_000
SHARD_WORKSPACE_POLL_SECONDS = 0.25
SHARD_RESERVE_RECOVERY_TIMEOUT_SECONDS = 2.0
SHARD_RESERVE_RECOVERY_POLL_SECONDS = 0.05
MAX_MIRROR_AUTHORITY_BYTES = 4 << 20
MAX_MIRROR_BUNDLE_BYTES = 32 << 30
MIRROR_AUTHORITY_SCHEMA = "codeskeptic-realworld-mirror-authority-v1"
DEFAULT_TU_TIMEOUT_SECONDS = 300
DEFAULT_TU_MEMORY_MIB = 4096
PR_SET_CHILD_SUBREAPER = 36
_SUBREAPER_ENABLED = False
_SUBREAPER_PID: int | None = None
_COMMAND_WORKSPACE_STATE: contextvars.ContextVar[
    tuple[Path, tuple[int, int], int, int, Path, dict[str, int | None]] | None
] = contextvars.ContextVar("codeskeptic_command_workspace", default=None)


class CampaignError(RuntimeError):
    """Base class for a fail-closed campaign error."""


class ManifestError(CampaignError):
    """The requested campaign input is not eligible."""


class EvidenceError(CampaignError):
    """Execution evidence cannot support a verdict."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def fingerprint_digest(fingerprints: list[str]) -> str:
    return digest_json(sorted(fingerprints))


def translation_unit_digest(paths: list[str]) -> str:
    normalized = sorted(path.replace("\\", "/") for path in paths)
    return digest_bytes(("\n".join(normalized) + "\n").encode("utf-8"))


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def load_manifest(path: Path | str) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        payload = json.loads(
            _read_regular_bytes(manifest_path, MAX_MANIFEST_BYTES).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
        raise ManifestError(f"cannot read manifest {manifest_path}: {error}") from error
    if not isinstance(payload, dict):
        raise ManifestError("manifest root must be an object")
    return payload


def _require_int(value: Any, field: str, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{field} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        bound = f"{minimum}..{maximum}" if maximum is not None else f">={minimum}"
        raise ManifestError(f"{field} must be {bound}")
    return value


def _require_relative(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ManifestError(f"{field} must be a nonempty relative path")
    path = Path(value)
    if path.is_absolute() or value.startswith(("/", "\\")) or ".." in path.parts:
        raise ManifestError(f"{field} must stay inside its declared root")
    return value.replace("\\", "/")


def _placeholders(token: str, field: str) -> None:
    try:
        names = {
            name
            for _, name, _, _ in string.Formatter().parse(token)
            if name is not None
        }
    except ValueError as error:
        raise ManifestError(f"{field} has malformed placeholders") from error
    unknown = names - ALLOWED_PLACEHOLDERS
    if unknown:
        raise ManifestError(f"{field} has unsupported placeholder {sorted(unknown)[0]!r}")


def _validate_command_shape(tokens: list[str], field: str, group: str) -> None:
    executable = tokens[0]
    if executable == "cmake":
        return
    if executable == "meson":
        if group == "configure":
            if (
                len(tokens) < 4
                or tokens[:4] != ["meson", "setup", "{build}", "{source}"]
                or any(not MESON_OPTION.fullmatch(token) for token in tokens[4:])
            ):
                raise ManifestError(f"{field} has an invalid meson configure shape")
            return
        if (
            group != "build"
            or len(tokens) < 4
            or tokens[:4] != ["meson", "compile", "-C", "{build}"]
            or any(not MESON_TARGET.fullmatch(token) for token in tokens[4:])
        ):
            raise ManifestError(f"{field} has an invalid meson build shape")
        return
    if executable == "bear":
        prefix = [
            "bear",
            "--output",
            "{build}/compile_commands.json",
            "--",
            "make",
            "-C",
            "{source}",
        ]
        if (
            group != "build"
            or tokens[: len(prefix)] != prefix
            or len(tokens) <= len(prefix)
            or any(
                token != "-j{jobs}" and not MAKE_ASSIGNMENT.fullmatch(token)
                for token in tokens[len(prefix) :]
            )
        ):
            raise ManifestError(f"{field} has an invalid bear build shape")
        return
    raise ManifestError(f"{field} command executable {executable!r} is not admitted")


def _validate_tokens(
    tokens: Any, field: str, *, command: bool, command_group: str = ""
) -> list[str]:
    if not isinstance(tokens, list) or not tokens:
        raise ManifestError(f"{field} must be a nonempty token array")
    if any(not isinstance(token, str) or not token or "\x00" in token or "\n" in token for token in tokens):
        raise ManifestError(f"{field} contains an invalid token")
    if command and tokens[0] not in ALLOWED_COMMANDS:
        raise ManifestError(
            f"{field} command executable {tokens[0]!r} is not admitted"
        )
    for token in tokens:
        _placeholders(token, field)
    if command:
        _validate_command_shape(tokens, field, command_group)
    return list(tokens)


def _validate_project(raw: Any, index: int) -> dict[str, Any]:
    field = f"projects[{index}]"
    if not isinstance(raw, dict):
        raise ManifestError(f"{field} must be an object")
    project = copy.deepcopy(raw)
    project_id = project.get("id")
    if not isinstance(project_id, str) or not PROJECT_ID.fullmatch(project_id):
        raise ManifestError(f"{field}.id is invalid")
    if not isinstance(project.get("label"), str) or not project["label"]:
        raise ManifestError(f"project {project_id} label must be nonempty")

    repository = project.get("repository")
    if not isinstance(repository, str):
        raise ManifestError(f"project {project_id} repository must be HTTPS")
    parsed = urlparse(repository)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or not parsed.path.endswith(".git")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ManifestError(f"project {project_id} repository must be an exact GitHub HTTPS URL")
    revision = project.get("revision")
    if not isinstance(revision, str) or not SHA40.fullmatch(revision):
        raise ManifestError(f"project {project_id} revision must be an immutable 40-hex commit")

    _require_int(project.get("timeout_minutes"), f"project {project_id} timeout_minutes", 1, 330)
    _require_int(project.get("memory_mb"), f"project {project_id} memory_mb", 512, 65536)

    environment = project.get("environment", {})
    if (
        not isinstance(environment, dict)
        or not set(environment).issubset(BUILD_ENVIRONMENT)
        or any(
            not isinstance(value, str) or BUILD_TOOL.fullmatch(value) is None
            for value in environment.values()
        )
    ):
        raise ManifestError(f"project {project_id} environment is invalid")
    if environment:
        project["environment"] = dict(sorted(environment.items()))
    else:
        project.pop("environment", None)

    commands = project.get("commands")
    if not isinstance(commands, dict) or set(commands) != {"configure", "build"}:
        raise ManifestError(f"project {project_id} commands must contain configure and build")
    for group in ("configure", "build"):
        rows = commands[group]
        if not isinstance(rows, list) or not rows:
            raise ManifestError(f"project {project_id} commands.{group} must be nonempty")
        commands[group] = [
            _validate_tokens(
                row,
                f"project {project_id} commands.{group}[{row_index}]",
                command=True,
                command_group=group,
            )
            for row_index, row in enumerate(rows)
        ]

    checkout = project.get(
        "checkout",
        {
            "submodules": "none",
            "expected_count": 0,
            "expected_sha256": digest_json([]),
        },
    )
    if not isinstance(checkout, dict) or set(checkout) != {
        "submodules",
        "expected_count",
        "expected_sha256",
    }:
        raise ManifestError(f"project {project_id} checkout fields are invalid")
    if checkout["submodules"] not in ("none", "recursive"):
        raise ManifestError(f"project {project_id} checkout mode is invalid")
    _require_int(
        checkout["expected_count"],
        f"project {project_id} checkout.expected_count",
        0,
    )
    if (
        not isinstance(checkout["expected_sha256"], str)
        or not SHA256.fullmatch(checkout["expected_sha256"])
    ):
        raise ManifestError(
            f"project {project_id} checkout.expected_sha256 must be SHA-256"
        )
    if checkout["submodules"] == "none" and (
        checkout["expected_count"] != 0
        or checkout["expected_sha256"] != digest_json([])
    ):
        raise ManifestError(f"project {project_id} empty checkout identity is invalid")
    if checkout["submodules"] == "recursive" and checkout["expected_count"] < 1:
        raise ManifestError(f"project {project_id} recursive checkout identity is empty")

    copies = project.get("copies")
    if not isinstance(copies, list):
        raise ManifestError(f"project {project_id} copies must be an array")
    for copy_index, operation in enumerate(copies):
        if not isinstance(operation, dict) or set(operation) != {"from", "to"}:
            raise ManifestError(f"project {project_id} copies[{copy_index}] is invalid")
        operation["from"] = _require_relative(
            operation["from"], f"project {project_id} copies[{copy_index}].from"
        )
        operation["to"] = _require_relative(
            operation["to"], f"project {project_id} copies[{copy_index}].to"
        )

    compile_database = project.get("compile_database")
    if not isinstance(compile_database, str) or not compile_database:
        raise ManifestError(f"project {project_id} compile_database must be nonempty")
    _placeholders(compile_database, f"project {project_id} compile_database")

    sources = project.get("sources")
    if not isinstance(sources, dict) or set(sources) != {"roots", "extensions", "fallback_globs"}:
        raise ManifestError(f"project {project_id} sources has an invalid shape")
    if not isinstance(sources["roots"], list) or not sources["roots"]:
        raise ManifestError(f"project {project_id} source roots must be nonempty")
    sources["roots"] = [
        _require_relative(root, f"project {project_id} source root")
        for root in sources["roots"]
    ]
    extensions = sources["extensions"]
    if (
        not isinstance(extensions, list)
        or not extensions
        or any(not isinstance(ext, str) or not re.fullmatch(r"\.[A-Za-z0-9+]+", ext) for ext in extensions)
    ):
        raise ManifestError(f"project {project_id} extensions are invalid")
    sources["extensions"] = sorted(set(extensions))
    if not isinstance(sources["fallback_globs"], list):
        raise ManifestError(f"project {project_id} fallback_globs must be an array")
    sources["fallback_globs"] = [
        _require_relative(pattern, f"project {project_id} fallback glob")
        for pattern in sources["fallback_globs"]
    ]

    project["analyzer_args"] = _validate_tokens(
        project.get("analyzer_args"), f"project {project_id} analyzer_args", command=False
    )

    expected = project.get("expected")
    if not isinstance(expected, dict) or set(expected) != REQUIRED_EXPECTED:
        raise ManifestError(f"project {project_id} expected fields are invalid")
    for name in (
        "translation_units",
        "attempted_tus",
        "analyzed_tus",
        "broken_tus",
        "incomplete_functions",
        "findings",
    ):
        _require_int(expected.get(name), f"project {project_id} expected.{name}", 0)
    if expected["translation_units"] == 0:
        raise ManifestError(f"project {project_id} translation_units must be positive")
    for name in ("translation_unit_sha256", "fingerprint_sha256"):
        value = expected.get(name)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise ManifestError(f"project {project_id} expected.{name} must be SHA-256")
        if value.startswith("0" * 60):
            raise ManifestError(
                f"project {project_id} expected.{name} is a placeholder SHA-256"
            )
    if expected.get("exit_code") not in (0, 1):
        raise ManifestError(f"project {project_id} expected exit is an unavailable verdict")
    if (
        expected["attempted_tus"] != expected["translation_units"]
        or expected["analyzed_tus"] < expected["attempted_tus"]
        or expected["broken_tus"] != 0
        or expected["incomplete_functions"] != 0
    ):
        raise ManifestError(f"project {project_id} expected coverage is not exact")
    return project


def validate_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema") != SCHEMA:
        raise ManifestError(f"manifest schema must be {SCHEMA}")
    if set(raw) != {"schema", "campaigns", "projects"}:
        raise ManifestError("manifest root fields are invalid")
    projects_raw = raw.get("projects")
    if not isinstance(projects_raw, list) or not projects_raw:
        raise ManifestError("projects must be a nonempty array")
    projects = [_validate_project(project, index) for index, project in enumerate(projects_raw)]
    project_ids = [project["id"] for project in projects]
    duplicates = sorted({project_id for project_id in project_ids if project_ids.count(project_id) > 1})
    if duplicates:
        raise ManifestError(f"duplicate project {duplicates[0]}")

    campaigns_raw = raw.get("campaigns")
    if not isinstance(campaigns_raw, dict) or not campaigns_raw:
        raise ManifestError("campaigns must be a nonempty object")
    campaigns: dict[str, Any] = {}
    referenced: list[str] = []
    for name, campaign in campaigns_raw.items():
        if not isinstance(name, str) or not PROJECT_ID.fullmatch(name) or not isinstance(campaign, dict):
            raise ManifestError("campaign name or shape is invalid")
        if set(campaign) != {"window_minutes", "repetitions", "projects"}:
            raise ManifestError(f"campaign {name} fields are invalid")
        window = _require_int(campaign["window_minutes"], f"campaign {name} window_minutes", 1, 4320)
        repetitions = _require_int(campaign["repetitions"], f"campaign {name} repetitions", 3, 3)
        selected = campaign["projects"]
        if not isinstance(selected, list) or not selected or any(not isinstance(item, str) for item in selected):
            raise ManifestError(f"campaign {name} projects must be nonempty")
        if len(selected) != len(set(selected)):
            raise ManifestError(f"campaign {name} has duplicate project identities")
        unknown = sorted(set(selected) - set(project_ids))
        if unknown:
            raise ManifestError(f"campaign {name} references unknown project {unknown[0]}")
        if name == "nightly" and window > 720:
            raise ManifestError("nightly campaign window exceeds 12 hours")
        if name == "weekend" and not 2160 <= window <= 2880:
            raise ManifestError("weekend campaign window must be 36..48 hours")
        campaigns[name] = {
            "window_minutes": window,
            "repetitions": repetitions,
            "projects": list(selected),
        }
        referenced.extend(selected)
    unreferenced = sorted(set(project_ids) - set(referenced))
    if unreferenced:
        raise ManifestError(f"unreferenced project {unreferenced[0]}")
    return {"schema": SCHEMA, "campaigns": campaigns, "projects": projects}


def project_by_id(manifest: dict[str, Any], project_id: str) -> dict[str, Any]:
    matches = [project for project in manifest["projects"] if project["id"] == project_id]
    if len(matches) != 1:
        raise ManifestError(f"unknown project {project_id}")
    return matches[0]


def project_recipe(project: dict[str, Any]) -> dict[str, Any]:
    recipe = {
        key: project[key]
        for key in (
            "repository",
            "revision",
            "commands",
            "copies",
            "compile_database",
            "sources",
            "analyzer_args",
            "timeout_minutes",
            "memory_mb",
        )
    }
    if project.get("environment"):
        recipe["environment"] = project["environment"]
    return recipe


def receipt_identity(
    manifest: dict[str, Any],
    project: dict[str, Any],
    repetition: int,
    analyzer_sha256: str,
    translation_unit_sha256: str,
    submodules: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if submodules is None:
        submodules = _expected_submodules(project)
    return {
        "manifest_sha256": digest_json(manifest),
        "project_revision": project["revision"],
        "recipe_sha256": digest_json(project_recipe(project)),
        "analyzer_sha256": analyzer_sha256,
        "translation_unit_sha256": translation_unit_sha256,
        "submodules": copy.deepcopy(submodules),
        "repetition": repetition,
    }


def plan_matrix(manifest: dict[str, Any], tier: str) -> dict[str, Any]:
    campaign = manifest["campaigns"].get(tier)
    if campaign is None:
        raise ManifestError(f"unknown campaign {tier}")
    include = []
    for project_id in campaign["projects"]:
        project = project_by_id(manifest, project_id)
        for repetition in range(1, campaign["repetitions"] + 1):
            include.append(
                {
                    "project": project_id,
                    "repetition": repetition,
                    "timeout_minutes": project["timeout_minutes"],
                }
            )
    return {"include": include}


def _sidecar(path: Path) -> Path:
    return Path(f"{path}.sha256")


def _path_kind(path: Path) -> str:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except OSError as error:
        raise EvidenceError(f"cannot inspect evidence path {path}: {error}") from error
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    return "non-regular"


def _read_regular_bytes(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(f"evidence path is not a readable regular file: {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise EvidenceError(f"evidence path is not a regular file: {path}")
        if metadata.st_size > maximum:
            raise EvidenceError(f"evidence file exceeds size limit: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1 << 20, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > maximum:
                raise EvidenceError(f"evidence file exceeds size limit: {path}")
        after = os.fstat(descriptor)
        pathname = path.lstat()
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_nlink, value.st_mtime_ns, value.st_ctime_ns,
        )
        if identity(metadata) != identity(after) or identity(metadata) != identity(pathname):
            raise EvidenceError(f"evidence file changed while reading: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise EvidenceError(
                f"mirror authority path is unavailable: {current}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(
                f"mirror authority path contains a symlink: {current}"
            )


def _require_immutable_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(
            f"mirror authority directory is unavailable: {path}: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError(f"mirror authority directory is not real: {path}")
    if metadata.st_mode & 0o222:
        raise EvidenceError(f"mirror authority directory is not immutable: {path}")


def _immutable_file_digest(
    path: Path, *, maximum: int | None = None, capture: bool = False
) -> tuple[str, bytes | None]:
    with _open_immutable_file(path, maximum=maximum, capture=capture) as opened:
        _descriptor, digest, payload = opened
        return digest, payload


def _immutable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_immutable_metadata(metadata: os.stat_result, path: Path) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"immutable mirror path is not a regular file: {path}")
    if metadata.st_nlink != 1:
        raise EvidenceError(f"immutable mirror file has a hard link: {path}")
    if metadata.st_mode & 0o222:
        raise EvidenceError(f"mirror authority file is not immutable: {path}")


@contextlib.contextmanager
def _open_immutable_file(
    path: Path, *, maximum: int | None = None, capture: bool = False
):
    """Keep one validated inode open through its complete consumer use."""

    _reject_symlink_components(path)
    try:
        preliminary = path.lstat()
    except OSError as error:
        raise EvidenceError(
            f"immutable mirror file is unavailable: {path}: {error}"
        ) from error
    _validate_immutable_metadata(preliminary, path)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(
            f"immutable mirror file is unavailable: {path}: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        _validate_immutable_metadata(before, path)
        if _immutable_identity(preliminary) != _immutable_identity(before):
            raise EvidenceError(f"immutable mirror file changed while opening: {path}")
        if maximum is not None and before.st_size > maximum:
            raise EvidenceError(f"mirror authority file exceeds size limit: {path}")
        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 1 << 20)
            if not block:
                break
            total += len(block)
            if maximum is not None and total > maximum:
                raise EvidenceError(
                    f"mirror authority file exceeds size limit: {path}"
                )
            hasher.update(block)
            if capture:
                chunks.append(block)
        digest = hasher.hexdigest()
        payload = b"".join(chunks) if capture else None
        yield descriptor, digest, payload
        after = os.fstat(descriptor)
        try:
            pathname_after = path.lstat()
        except OSError as error:
            raise EvidenceError(
                f"immutable mirror file changed while in use: {path}: {error}"
            ) from error
        expected = _immutable_identity(before)
        if (
            _immutable_identity(after) != expected
            or _immutable_identity(pathname_after) != expected
        ):
            raise EvidenceError(f"immutable mirror file changed while in use: {path}")
        _validate_immutable_metadata(after, path)
        _validate_immutable_metadata(pathname_after, path)
    except OSError as error:
        raise EvidenceError(f"cannot read immutable mirror file {path}: {error}") from error
    finally:
        os.close(descriptor)


def _mirror_relative_path(root: Path, value: Any, field: str) -> Path:
    relative = _mirror_require_relative(value, field)
    path = root / relative
    current = root
    for component in Path(relative).parts[:-1]:
        current /= component
        _require_immutable_directory(current)
    return path


def _mirror_require_relative(value: Any, field: str) -> str:
    try:
        relative = _require_relative(value, field)
    except ManifestError as error:
        raise EvidenceError(str(error)) from error
    path = Path(relative)
    if (
        value != relative
        or not path.parts
        or path.as_posix() != relative
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        raise EvidenceError(f"{field} must be a canonical relative path")
    return relative


def _validate_upstream_url(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{field} must be an exact HTTPS repository URL")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise EvidenceError(f"{field} must be an exact HTTPS repository URL") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or any(character in value for character in ("\x00", "\r", "\n"))
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise EvidenceError(f"{field} must be an exact HTTPS repository URL")
    return value


def _validate_mirror_bundle_record(
    raw: Any, field: str, *, submodule: bool
) -> dict[str, Any]:
    required = {
        "path",
        "repository",
        "revision",
        "tree",
        "bundle",
        "bundle_sha256",
    } if submodule else {
        "id",
        "repository",
        "revision",
        "tree",
        "bundle",
        "bundle_sha256",
        "submodules",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise EvidenceError(f"{field} fields are invalid")
    normalized = copy.deepcopy(raw)
    if submodule:
        normalized["path"] = _mirror_require_relative(raw["path"], f"{field}.path")
    normalized["repository"] = _validate_upstream_url(
        raw["repository"], f"{field}.repository"
    )
    for name in ("revision", "tree"):
        if not isinstance(raw[name], str) or not SHA40.fullmatch(raw[name]):
            raise EvidenceError(f"{field}.{name} must be an immutable Git identity")
    normalized["bundle"] = _mirror_require_relative(raw["bundle"], f"{field}.bundle")
    if (
        not isinstance(raw["bundle_sha256"], str)
        or not SHA256.fullmatch(raw["bundle_sha256"])
    ):
        raise EvidenceError(f"{field}.bundle_sha256 must be SHA-256")
    return normalized


def load_mirror_authority(
    path: Path | str,
    manifest: dict[str, Any],
    project_id: str,
    *,
    expected_project_ids: list[str] | tuple[str, ...] | None = None,
) -> tuple[dict[str, Any], Path]:
    authority_path = Path(path).absolute()
    root = authority_path.parent
    _reject_symlink_components(root)
    _require_immutable_directory(root)
    authority_digest, authority_bytes = _immutable_file_digest(
        authority_path, maximum=MAX_MIRROR_AUTHORITY_BYTES, capture=True
    )
    sidecar = _sidecar(authority_path)
    _, sidecar_bytes = _immutable_file_digest(
        sidecar, maximum=MAX_CHECKSUM_BYTES, capture=True
    )
    expected_sidecar = f"{authority_digest}  {authority_path.name}\n".encode("ascii")
    if sidecar_bytes != expected_sidecar:
        raise EvidenceError(f"mirror authority checksum is malformed: {sidecar}")
    if authority_bytes is None:
        raise EvidenceError(f"mirror authority could not be captured: {authority_path}")
    try:
        payload = json.loads(authority_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise EvidenceError(f"mirror authority is malformed: {authority_path}: {error}") from error
    try:
        canonical_authority = canonical_bytes(payload) + b"\n"
    except (TypeError, ValueError, RecursionError) as error:
        raise EvidenceError(f"mirror authority is malformed: {authority_path}: {error}") from error
    if canonical_authority != authority_bytes:
        raise EvidenceError("mirror authority is not canonical JSON")
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema", "manifest_sha256", "projects"}
        or payload.get("schema") != MIRROR_AUTHORITY_SCHEMA
    ):
        raise EvidenceError("mirror authority root fields are invalid")
    if payload.get("manifest_sha256") != digest_json(manifest):
        raise EvidenceError("mirror authority manifest identity does not match")
    raw_projects = payload.get("projects")
    if not isinstance(raw_projects, list) or not raw_projects:
        raise EvidenceError("mirror authority projects must be a nonempty array")
    manifest_projects = {project["id"]: project for project in manifest["projects"]}
    normalized_projects: dict[str, dict[str, Any]] = {}
    upstream_bundles: dict[str, tuple[str, str]] = {}
    bundle_upstreams: dict[str, str] = {}
    for index, raw_project in enumerate(raw_projects):
        field = f"mirror projects[{index}]"
        project = _validate_mirror_bundle_record(raw_project, field, submodule=False)
        candidate_id = project.get("id")
        if not isinstance(candidate_id, str) or candidate_id not in manifest_projects:
            raise EvidenceError(f"{field}.id is unknown")
        if candidate_id in normalized_projects:
            raise EvidenceError(f"mirror authority duplicates project {candidate_id}")
        expected_project = manifest_projects[candidate_id]
        if project["repository"] != expected_project["repository"]:
            raise EvidenceError(f"mirror project {candidate_id} repository does not match")
        if project["revision"] != expected_project["revision"]:
            raise EvidenceError(f"mirror project {candidate_id} revision does not match")
        raw_submodules = project.get("submodules")
        if not isinstance(raw_submodules, list):
            raise EvidenceError(f"mirror project {candidate_id} submodules must be an array")
        submodules = [
            _validate_mirror_bundle_record(
                raw_submodule,
                f"mirror project {candidate_id} submodules[{submodule_index}]",
                submodule=True,
            )
            for submodule_index, raw_submodule in enumerate(raw_submodules)
        ]
        paths = [entry["path"] for entry in submodules]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise EvidenceError(
                f"mirror project {candidate_id} submodule paths are not canonical"
            )
        expected_submodules = _expected_submodules(expected_project)
        actual_submodule_identity = [
            {"path": entry["path"], "revision": entry["revision"]}
            for entry in submodules
        ]
        if (
            len(actual_submodule_identity) != expected_submodules["count"]
            or digest_json(actual_submodule_identity) != expected_submodules["sha256"]
        ):
            raise EvidenceError(
                f"mirror project {candidate_id} submodule identity does not match"
            )
        project["submodules"] = submodules
        normalized_projects[candidate_id] = project
        for record in (project, *submodules):
            upstream = record["repository"]
            binding = (record["bundle"], record["bundle_sha256"])
            prior = upstream_bundles.setdefault(upstream, binding)
            if prior != binding:
                raise EvidenceError(
                    f"mirror authority maps upstream {upstream} inconsistently"
                )
            prior_upstream = bundle_upstreams.setdefault(record["bundle"], upstream)
            if prior_upstream != upstream:
                raise EvidenceError(
                    f"mirror authority reuses one bundle for different upstreams"
                )
    expected_order = [
        project_id
        for project_id in manifest_projects
        if project_id in normalized_projects
    ]
    if list(normalized_projects) != expected_order:
        raise EvidenceError("mirror authority project order is not canonical")
    if expected_project_ids is None:
        release_candidate = manifest.get("campaigns", {}).get("release-candidate")
        if (
            isinstance(release_candidate, dict)
            and project_id in release_candidate.get("projects", [])
        ):
            expected_project_ids = release_candidate["projects"]
    if expected_project_ids is not None:
        expected_scope = list(expected_project_ids)
        if (
            not expected_scope
            or len(expected_scope) != len(set(expected_scope))
            or any(project not in manifest_projects for project in expected_scope)
        ):
            raise EvidenceError("mirror authority expected project set is malformed")
        if set(normalized_projects) != set(expected_scope):
            raise EvidenceError("mirror authority project set is not exact")
    selected = normalized_projects.get(project_id)
    if selected is None:
        raise EvidenceError(f"mirror authority has no project {project_id}")
    checked: set[tuple[str, str]] = set()
    for project in normalized_projects.values():
        for record in (project, *project["submodules"]):
            identity = (record["bundle"], record["bundle_sha256"])
            if identity in checked:
                continue
            checked.add(identity)
            bundle_path = _mirror_relative_path(
                root, record["bundle"], f"mirror project {project['id']} bundle"
            )
            actual_digest, _ = _immutable_file_digest(
                bundle_path, maximum=MAX_MIRROR_BUNDLE_BYTES
            )
            if actual_digest != record["bundle_sha256"]:
                raise EvidenceError(f"mirror bundle checksum mismatch: {bundle_path}")
    return selected, root


def _offline_base_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith("GIT_"):
            environment.pop(key)
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_CONFIG_COUNT": "0",
        }
    )
    return environment


def offline_git_environment(
    mirror_project: dict[str, Any], repositories: dict[str, Path]
) -> dict[str, str]:
    environment = _offline_base_environment()
    expected_upstreams = {
        record["repository"]
        for record in (mirror_project, *mirror_project["submodules"])
    }
    if set(repositories) != expected_upstreams:
        raise EvidenceError("offline materialized repository mapping is incomplete")
    mappings = {
        upstream: path.absolute().as_uri()
        for upstream, path in repositories.items()
    }
    environment["GIT_CONFIG_COUNT"] = str(len(mappings))
    for index, (upstream, bundle_uri) in enumerate(sorted(mappings.items())):
        environment[f"GIT_CONFIG_KEY_{index}"] = f"url.{bundle_uri}.insteadOf"
        environment[f"GIT_CONFIG_VALUE_{index}"] = upstream
    return environment


def _write_new_regular_staging(path: Path, payload: bytes) -> None:
    kind = _path_kind(path)
    if kind not in {"missing", "regular"}:
        raise EvidenceError(f"evidence staging path is non-regular: {path}")
    if kind == "regular":
        try:
            path.unlink()
        except OSError as error:
            raise EvidenceError(f"cannot recover evidence staging file {path}: {error}") from error
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise EvidenceError(f"cannot create evidence staging file {path}: {error}") from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short evidence staging write")
            offset += written
        os.fsync(descriptor)
    except OSError as error:
        raise EvidenceError(f"cannot write evidence staging file {path}: {error}") from error
    finally:
        os.close(descriptor)


def _unlink_regular_target(path: Path) -> None:
    kind = _path_kind(path)
    if kind not in {"missing", "regular"}:
        raise EvidenceError(f"evidence publication target is non-regular: {path}")
    if kind == "regular":
        try:
            path.unlink()
        except OSError as error:
            raise EvidenceError(f"cannot replace evidence target {path}: {error}") from error


def write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _path_kind(path.parent) != "directory":
        raise EvidenceError(f"evidence parent is not a real directory: {path.parent}")
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise EvidenceError(f"receipt exceeds size limit: {path}")
    temporary = path.with_name(f".{path.name}.tmp")
    _write_new_regular_staging(temporary, encoded)
    digest = digest_bytes(encoded)
    sidecar = _sidecar(path)
    sidecar_temporary = sidecar.with_name(f".{sidecar.name}.tmp")
    checksum = f"{digest}  {path.name}\n".encode("ascii")
    try:
        _write_new_regular_staging(sidecar_temporary, checksum)
        # Publish from an empty pair so an interruption leaves either no
        # checkpoint or one recognizable regular orphan. The loader removes
        # that orphan and continues through the per-TU evidence store.
        if (_path_kind(path) not in {"missing", "regular"} or
                _path_kind(sidecar) not in {"missing", "regular"}):
            raise EvidenceError(f"evidence publication target is non-regular: {path}")
        _unlink_regular_target(path)
        _unlink_regular_target(sidecar)
        os.replace(sidecar_temporary, sidecar)
        os.replace(temporary, path)
    finally:
        for candidate in (temporary, sidecar_temporary):
            if _path_kind(candidate) == "regular":
                candidate.unlink()


def load_verified_receipt(path: Path) -> dict[str, Any]:
    sidecar = _sidecar(path)
    receipt_kind = _path_kind(path)
    checksum_kind = _path_kind(sidecar)
    if (receipt_kind not in {"missing", "regular"} or
            checksum_kind not in {"missing", "regular"}):
        raise EvidenceError(f"receipt or checksum is not a regular file: {path}")
    if receipt_kind != "regular" or checksum_kind != "regular":
        raise EvidenceError(f"missing receipt or checksum: {path}")
    try:
        receipt_bytes = _read_regular_bytes(path, MAX_RECEIPT_BYTES)
        checksum_bytes = _read_regular_bytes(sidecar, MAX_CHECKSUM_BYTES)
        checksum_text = checksum_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"malformed receipt checksum: {sidecar}") from error
    fields = checksum_text.strip().split()
    if len(fields) != 2 or fields[1] != path.name or not SHA256.fullmatch(fields[0]):
        raise EvidenceError(f"malformed receipt checksum: {sidecar}")
    actual = digest_bytes(receipt_bytes)
    if actual != fields[0]:
        raise EvidenceError(f"receipt checksum mismatch: {path}")
    try:
        payload = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"malformed receipt: {path}: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise EvidenceError(f"unsupported receipt schema: {path}")
    return payload


def checkpoint_matches(receipt: dict[str, Any], identity: dict[str, Any]) -> bool:
    return (
        receipt.get("schema") == SCHEMA
        and receipt.get("status") == "accepted"
        and receipt.get("identity") == identity
        and receipt.get("failures") == []
    )


def load_matching_checkpoint(
    checkpoint: Path, identity: dict[str, Any], project: dict[str, Any]
) -> dict[str, Any] | None:
    sidecar = _sidecar(checkpoint)
    receipt_kind = _path_kind(checkpoint)
    checksum_kind = _path_kind(sidecar)
    if (receipt_kind not in {"missing", "regular"} or
            checksum_kind not in {"missing", "regular"}):
        raise EvidenceError(f"explicit checkpoint path is non-regular: {checkpoint}")
    if receipt_kind == "missing" and checksum_kind == "missing":
        return None
    if receipt_kind != checksum_kind:
        orphan = checkpoint if receipt_kind == "regular" else sidecar
        try:
            orphan.unlink()
        except OSError as error:
            raise EvidenceError(
                f"cannot recover incomplete explicit checkpoint: {checkpoint}: {error}"
            ) from error
        return None
    receipt = load_verified_receipt(checkpoint)
    if not checkpoint_matches(receipt, identity):
        raise EvidenceError(
            f"explicit checkpoint is incompatible with this exact shard: {checkpoint}"
        )
    if set(receipt) != {
        "schema",
        "status",
        "project",
        "repetition",
        "identity",
        "semantic",
        "execution",
        "failures",
    }:
        raise EvidenceError("explicit checkpoint receipt shape is malformed")
    if (
        receipt.get("project") != project["id"]
        or receipt.get("repetition") != identity.get("repetition")
    ):
        raise EvidenceError("explicit checkpoint shard identity is malformed")
    semantic = receipt.get("semantic")
    _validate_semantic(project, semantic)
    _validate_execution(project, semantic, receipt.get("execution"))
    return receipt


def analyzer_checkpoint_arguments(checkpoint: Path | None) -> list[str]:
    if checkpoint is None:
        return []
    unit_directory = checkpoint.parent / "unit-evidence"
    return ["--checkpoint-dir", str(unit_directory)]


TRANSLATION_UNIT_RECEIPT_FIELDS = {
    "path",
    "compile_command_sha256",
    "command_ordinal",
    "phase",
    "status",
    "duration_ms",
    "peak_memory_kib",
    "timeout_seconds",
    "memory_mib",
    "origin",
    "checkpoint_key_sha256",
    "payload_sha256",
}


def translation_unit_resource_summary(
    report: dict[str, Any],
    *,
    expected_timeout_seconds: int | None = None,
    expected_memory_mib: int | None = None,
) -> dict[str, Any]:
    """Validate and retain exact per-TU time and RSS budget observations."""

    if not isinstance(report, dict):
        raise EvidenceError("report root is not an object")
    receipts = report.get("translation_units")
    if not isinstance(receipts, list) or not receipts:
        raise EvidenceError("report has no translation-unit receipt plan")
    observations: list[list[Any]] = []
    total_duration = 0
    maximum_duration = 0
    maximum_peak_memory = 0
    duration_budget_violations = 0
    memory_budget_violations = 0
    observed_timeout: int | None = None
    observed_memory: int | None = None
    for receipt in receipts:
        if not isinstance(receipt, dict) or set(receipt) != TRANSLATION_UNIT_RECEIPT_FIELDS:
            raise EvidenceError("translation-unit receipt is malformed")
        for field in (
            "duration_ms", "peak_memory_kib", "timeout_seconds", "memory_mib"
        ):
            value = receipt[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EvidenceError(
                    f"translation-unit receipt field {field} is invalid"
                )
        duration = receipt["duration_ms"]
        peak_memory = receipt["peak_memory_kib"]
        timeout = receipt["timeout_seconds"]
        memory = receipt["memory_mib"]
        if timeout == 0 or memory == 0:
            raise EvidenceError("translation-unit receipt budgets are invalid")
        if observed_timeout is None:
            observed_timeout = timeout
            observed_memory = memory
        elif timeout != observed_timeout or memory != observed_memory:
            raise EvidenceError("translation-unit receipt budgets are not uniform")
        if expected_timeout_seconds is not None and timeout != expected_timeout_seconds:
            raise EvidenceError("translation-unit timeout budget differs from policy")
        if expected_memory_mib is not None and memory != expected_memory_mib:
            raise EvidenceError("translation-unit memory budget differs from policy")
        if duration > timeout * 1000:
            duration_budget_violations += 1
        if peak_memory > memory * 1024:
            memory_budget_violations += 1
        total_duration += duration
        maximum_duration = max(maximum_duration, duration)
        maximum_peak_memory = max(maximum_peak_memory, peak_memory)
        observations.append([
            receipt["path"],
            receipt["compile_command_sha256"],
            receipt["command_ordinal"],
            receipt["phase"],
            receipt["origin"],
            duration,
            peak_memory,
            timeout,
            memory,
        ])
    if duration_budget_violations:
        raise EvidenceError("translation-unit duration budget was exceeded")
    if memory_budget_violations:
        raise EvidenceError("translation-unit memory budget was exceeded")
    return {
        "schema": "codeskeptic-realworld-tu-resources-v1",
        "translation_units": len(receipts),
        "total_duration_ms": total_duration,
        "maximum_duration_ms": maximum_duration,
        "maximum_peak_memory_kib": maximum_peak_memory,
        "timeout_seconds": observed_timeout,
        "memory_mib": observed_memory,
        "duration_budget_violations": duration_budget_violations,
        "memory_budget_violations": memory_budget_violations,
        "observations_sha256": digest_json(observations),
    }


def translation_unit_plan(
    report: dict[str, Any],
    requested_translation_units: int,
    analyzed_executions: int,
    expected_paths: list[Path] | None = None,
    whole_program: bool = False,
    *,
    expected_timeout_seconds: int | None = None,
    expected_memory_mib: int | None = None,
) -> dict[str, Any]:
    receipts = report.get("translation_units")
    if not isinstance(receipts, list) or not receipts:
        raise EvidenceError("report has no translation-unit receipt plan")
    resources = translation_unit_resource_summary(
        report,
        expected_timeout_seconds=expected_timeout_seconds,
        expected_memory_mib=expected_memory_mib,
    )
    path_indexes: dict[str, int] = {}
    if expected_paths is not None:
        path_indexes = {
            str(path.resolve()): index for index, path in enumerate(expected_paths)
        }
        if len(path_indexes) != requested_translation_units:
            raise EvidenceError("requested translation-unit paths are not unique")

    normalized: list[list[Any]] = []
    identities_by_phase: dict[str, set[tuple[str, str, int]]] = {}
    origins = {"executed": 0, "checkpoint": 0}
    seen: set[tuple[str, str, int, str]] = set()
    phase_order: list[str] = []
    for receipt in receipts:
        if (
            not isinstance(receipt, dict)
            or set(receipt) != TRANSLATION_UNIT_RECEIPT_FIELDS
        ):
            raise EvidenceError("translation-unit receipt is malformed")
        path = receipt["path"]
        command_sha = receipt["compile_command_sha256"]
        ordinal = receipt["command_ordinal"]
        phase = receipt["phase"]
        origin = receipt["origin"]
        key = receipt["checkpoint_key_sha256"]
        payload = receipt["payload_sha256"]
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(command_sha, str)
            or not SHA256.fullmatch(command_sha)
            or isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or phase not in ("summary-harvest", "analysis")
            or receipt["status"] != "completed"
            or origin not in origins
        ):
            raise EvidenceError("translation-unit receipt identity is invalid")
        for field in (
            "duration_ms",
            "peak_memory_kib",
            "timeout_seconds",
            "memory_mib",
        ):
            value = receipt[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EvidenceError(
                    f"translation-unit receipt field {field} is invalid"
                )
        if receipt["timeout_seconds"] == 0 or receipt["memory_mib"] == 0:
            raise EvidenceError("translation-unit receipt budgets are invalid")
        digests_present = (
            isinstance(key, str)
            and isinstance(payload, str)
            and SHA256.fullmatch(key) is not None
            and SHA256.fullmatch(payload) is not None
        )
        if origin == "checkpoint" and not digests_present:
            raise EvidenceError("checkpoint receipt lacks exact payload identity")
        if not digests_present and (key != "" or payload != ""):
            raise EvidenceError("translation-unit payload identity is malformed")

        canonical = str(Path(path).resolve())
        if path_indexes and canonical not in path_indexes:
            raise EvidenceError("translation-unit receipt path was not requested")
        base = (canonical, command_sha, ordinal)
        exact = (*base, phase)
        if exact in seen:
            raise EvidenceError("translation-unit receipt plan contains a duplicate")
        seen.add(exact)
        identities_by_phase.setdefault(phase, set()).add(base)
        if not phase_order or phase_order[-1] != phase:
            phase_order.append(phase)
        normalized.append(
            [
                path_indexes.get(canonical, canonical),
                command_sha,
                ordinal,
                phase,
            ]
        )
        origins[origin] += 1

    expected_phases = (
        ["summary-harvest", "analysis"] if whole_program else ["analysis"]
    )
    if phase_order != expected_phases:
        raise EvidenceError("translation-unit receipt phases are out of order")
    for phase in expected_phases:
        if len(identities_by_phase.get(phase, set())) != analyzed_executions:
            raise EvidenceError("translation-unit receipt plan has omission")
        if path_indexes and {
            identity[0] for identity in identities_by_phase[phase]
        } != set(path_indexes):
            raise EvidenceError("translation-unit receipt plan has path omission")
    if whole_program and (
        identities_by_phase["summary-harvest"]
        != identities_by_phase["analysis"]
    ):
        raise EvidenceError("whole-program receipt phases bind different units")
    if resources["translation_units"] != len(receipts):
        raise EvidenceError("translation-unit resource inventory drift")
    return {
        "count": len(receipts),
        "sha256": digest_json(normalized),
        "executed": origins["executed"],
        "checkpoint": origins["checkpoint"],
    }


def _report_semantic(
    process_exit: int,
    report: dict[str, Any],
    translation_units: int,
    translation_unit_sha256: str,
    whole_program: bool = False,
    *,
    expected_timeout_seconds: int | None = None,
    expected_memory_mib: int | None = None,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise EvidenceError("analyzer report root is not an object")
    if process_exit not in (0, 1) or report.get("exit_code") not in (0, 1):
        raise EvidenceError("unavailable verdict exit 2")
    if report.get("exit_code") != process_exit:
        raise EvidenceError("process/report exit classification mismatch")
    if report.get("complete") is not True:
        raise EvidenceError("report does not contain a complete verdict")
    coverage = report.get("coverage")
    if not isinstance(coverage, dict):
        raise EvidenceError("report has no coverage evidence")
    normalized_coverage: dict[str, int] = {}
    for key in ("attempted_tus", "analyzed_tus", "broken_tus", "incomplete_functions"):
        value = coverage.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EvidenceError(f"coverage field {key} is invalid")
        normalized_coverage[key] = value
    if (
        normalized_coverage["attempted_tus"] != translation_units
        or normalized_coverage["analyzed_tus"] < normalized_coverage["attempted_tus"]
        or normalized_coverage["broken_tus"] != 0
        or normalized_coverage["incomplete_functions"] != 0
    ):
        raise EvidenceError("report does not prove exact TU coverage")
    translation_unit_plan(
        report,
        translation_units,
        normalized_coverage["analyzed_tus"],
        whole_program=whole_program,
        expected_timeout_seconds=expected_timeout_seconds,
        expected_memory_mib=expected_memory_mib,
    )
    diagnostics = report.get("diagnostics")
    total = report.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0 or not isinstance(diagnostics, list):
        raise EvidenceError("report finding evidence is invalid")
    if len(diagnostics) != total:
        raise EvidenceError("report finding count does not match diagnostics")
    fingerprints: list[str] = []
    for diagnostic in diagnostics:
        fingerprint = diagnostic.get("fingerprint") if isinstance(diagnostic, dict) else None
        if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
            raise EvidenceError("report contains a malformed finding fingerprint")
        fingerprints.append(fingerprint)
    fingerprints.sort()
    return {
        "translation_units": {
            "count": translation_units,
            "sha256": translation_unit_sha256,
        },
        "coverage": normalized_coverage,
        "findings": total,
        "exit_code": process_exit,
        "fingerprints": fingerprints,
        "fingerprint_sha256": fingerprint_digest(fingerprints),
    }


def _validate_semantic(project: dict[str, Any], semantic: dict[str, Any]) -> None:
    if not isinstance(semantic, dict) or set(semantic) != {
        "translation_units",
        "coverage",
        "findings",
        "exit_code",
        "fingerprints",
        "fingerprint_sha256",
    }:
        raise EvidenceError(f"project {project['id']} semantic evidence is malformed")
    translation_units = semantic.get("translation_units")
    coverage = semantic.get("coverage")
    if (
        not isinstance(translation_units, dict)
        or set(translation_units) != {"count", "sha256"}
        or not isinstance(coverage, dict)
        or set(coverage)
        != {"attempted_tus", "analyzed_tus", "broken_tus", "incomplete_functions"}
    ):
        raise EvidenceError(f"project {project['id']} coverage evidence is malformed")
    numeric_values = [
        translation_units.get("count"),
        coverage.get("attempted_tus"),
        coverage.get("analyzed_tus"),
        coverage.get("broken_tus"),
        coverage.get("incomplete_functions"),
        semantic.get("findings"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in numeric_values):
        raise EvidenceError(f"project {project['id']} numeric evidence is malformed")
    if (
        not isinstance(translation_units.get("sha256"), str)
        or not SHA256.fullmatch(translation_units["sha256"])
        or not isinstance(semantic.get("fingerprint_sha256"), str)
        or not SHA256.fullmatch(semantic["fingerprint_sha256"])
    ):
        raise EvidenceError(f"project {project['id']} digest evidence is malformed")
    fingerprints = semantic.get("fingerprints")
    if (
        not isinstance(fingerprints, list)
        or any(not isinstance(item, str) or not FINGERPRINT.fullmatch(item) for item in fingerprints)
        or fingerprints != sorted(fingerprints)
        or len(fingerprints) != semantic["findings"]
        or fingerprint_digest(fingerprints) != semantic["fingerprint_sha256"]
    ):
        raise EvidenceError(f"project {project['id']} fingerprint evidence is inconsistent")
    exit_code = semantic.get("exit_code")
    if (
        exit_code not in (0, 1)
        or (exit_code == 0 and semantic["findings"] != 0)
        or (exit_code == 1 and semantic["findings"] == 0)
    ):
        raise EvidenceError(f"project {project['id']} verdict evidence is inconsistent")

    expected = project["expected"]
    actual = {
        "translation_units": translation_units["count"],
        "translation_unit_sha256": translation_units["sha256"],
        "attempted_tus": coverage["attempted_tus"],
        "analyzed_tus": coverage["analyzed_tus"],
        "broken_tus": coverage["broken_tus"],
        "incomplete_functions": coverage["incomplete_functions"],
        "findings": semantic["findings"],
        "exit_code": exit_code,
        "fingerprint_sha256": semantic["fingerprint_sha256"],
    }
    drift = [name for name in REQUIRED_EXPECTED if actual[name] != expected[name]]
    if drift:
        details = ", ".join(
            f"{name}={actual[name]!r} expected={expected[name]!r}" for name in sorted(drift)
        )
        raise EvidenceError(f"project {project['id']} expectation drift: {details}")


def _validate_execution(
    project: dict[str, Any],
    semantic: dict[str, Any],
    execution: dict[str, Any],
    require_plan: bool = True,
) -> dict[str, Any] | None:
    if not isinstance(execution, dict):
        raise EvidenceError(
            f"project {project['id']} execution evidence is malformed"
        )
    expected_fields = {"duration_seconds", "resumed", "translation_unit_plan"}
    legacy_fields = {"duration_seconds", "resumed"}
    allowed_fields = (
        (expected_fields,) if require_plan else (expected_fields, legacy_fields)
    )
    if not any(set(execution) == fields for fields in allowed_fields):
        raise EvidenceError(
            f"project {project['id']} execution evidence is malformed"
        )
    duration = execution.get("duration_seconds")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration < 0
        or not isinstance(execution.get("resumed"), bool)
    ):
        raise EvidenceError(
            f"project {project['id']} execution evidence is malformed"
        )
    if "translation_unit_plan" not in execution:
        return None
    plan = execution.get("translation_unit_plan")
    if (
        not isinstance(plan, dict)
        or set(plan) != {"count", "sha256", "executed", "checkpoint"}
        or isinstance(plan.get("count"), bool)
        or not isinstance(plan.get("count"), int)
        or plan["count"] <= 0
        or not isinstance(plan.get("sha256"), str)
        or not SHA256.fullmatch(plan["sha256"])
        or any(
            isinstance(plan.get(name), bool)
            or not isinstance(plan.get(name), int)
            or plan[name] < 0
            for name in ("executed", "checkpoint")
        )
        or plan["executed"] + plan["checkpoint"] != plan["count"]
    ):
        raise EvidenceError(
            f"project {project['id']} translation-unit plan is malformed"
        )
    phases = 2 if "--whole-program" in project["analyzer_args"] else 1
    expected_count = semantic["coverage"]["analyzed_tus"] * phases
    if plan["count"] != expected_count:
        raise EvidenceError(
            f"project {project['id']} translation-unit plan is inconsistent"
        )
    return plan


def semantic_from_report(
    project: dict[str, Any],
    process_exit: int,
    report: dict[str, Any],
    translation_units: int,
    translation_unit_sha256: str,
    *,
    expected_timeout_seconds: int | None = None,
    expected_memory_mib: int | None = None,
) -> dict[str, Any]:
    semantic = _report_semantic(
        process_exit,
        report,
        translation_units,
        translation_unit_sha256,
        whole_program="--whole-program" in project["analyzer_args"],
        expected_timeout_seconds=expected_timeout_seconds,
        expected_memory_mib=expected_memory_mib,
    )
    _validate_semantic(project, semantic)
    return semantic


def validate_receipt_group(
    manifest: dict[str, Any],
    tier: str,
    project_id: str,
    receipts: list[dict[str, Any]],
    *,
    require_execution_plan: bool = True,
) -> dict[str, Any]:
    """Validate one project's full repetition set with the campaign referee."""
    campaign = manifest["campaigns"].get(tier)
    if campaign is None:
        raise ManifestError(f"unknown campaign {tier}")
    if project_id not in campaign["projects"]:
        raise EvidenceError(f"project {project_id} is not in campaign {tier}")
    repetitions = campaign["repetitions"]
    if len(receipts) != repetitions:
        raise EvidenceError(
            f"project {project_id} requires {repetitions} repetitions"
        )

    project = project_by_id(manifest, project_id)
    plan_digests: set[str] = set()
    plan_presence: set[bool] = set()
    for repetition, receipt in enumerate(receipts, 1):
        if (
            receipt.get("status") != "accepted"
            or receipt.get("project") != project_id
            or receipt.get("repetition") != repetition
            or receipt.get("failures") != []
        ):
            raise EvidenceError(
                f"project {project_id} repetition {repetition} is unavailable"
            )

    semantic_digests = {
        digest_json(receipt.get("semantic")) for receipt in receipts
    }
    if len(semantic_digests) != 1:
        raise EvidenceError(f"project {project_id} repetitions are nondeterministic")
    analyzer_digests = {
        receipt.get("identity", {}).get("analyzer_sha256")
        for receipt in receipts
        if isinstance(receipt.get("identity"), dict)
    }
    if len(analyzer_digests) != 1:
        raise EvidenceError(
            f"project {project_id} analyzer identity is nondeterministic"
        )
    analyzer_digest = next(iter(analyzer_digests))
    if not isinstance(analyzer_digest, str) or not SHA256.fullmatch(
        analyzer_digest
    ):
        raise EvidenceError(f"project {project_id} analyzer identity is malformed")

    for repetition, receipt in enumerate(receipts, 1):
        identity = receipt.get("identity")
        expected_identity = receipt_identity(
            manifest,
            project,
            repetition,
            analyzer_digest,
            project["expected"]["translation_unit_sha256"],
        )
        if not checkpoint_matches(receipt, expected_identity):
            raise EvidenceError(
                f"project {project_id} repetition {repetition} identity mismatch"
            )
        semantic = receipt.get("semantic")
        _validate_semantic(project, semantic)
        plan = _validate_execution(
            project,
            semantic,
            receipt.get("execution"),
            require_plan=require_execution_plan,
        )
        plan_presence.add(plan is not None)
        if plan is not None:
            plan_digests.add(plan["sha256"])
    if len(plan_presence) != 1:
        raise EvidenceError(
            f"project {project_id} execution schemas are nondeterministic"
        )
    if plan_digests and len(plan_digests) != 1:
        raise EvidenceError(
            f"project {project_id} translation-unit plans are nondeterministic"
        )
    semantic = receipts[0]["semantic"]
    return {
        "repetitions": len(receipts),
        "semantic_sha256": next(iter(semantic_digests)),
        "analyzer_sha256": analyzer_digest,
        "translation_unit_sha256": semantic["translation_units"]["sha256"],
        "findings": semantic["findings"],
        "exit_code": semantic["exit_code"],
        "fingerprint_sha256": semantic["fingerprint_sha256"],
    }


def aggregate_receipts(
    manifest: dict[str, Any], tier: str, receipt_root: Path
) -> dict[str, Any]:
    campaign = manifest["campaigns"].get(tier)
    if campaign is None:
        raise ManifestError(f"unknown campaign {tier}")
    summary: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "accepted",
        "campaign": tier,
        "manifest_sha256": digest_json(manifest),
        "projects": {},
    }
    campaign_analyzer_digests: set[str] = set()
    for project_id in campaign["projects"]:
        project = project_by_id(manifest, project_id)
        receipts: list[dict[str, Any]] = []
        for repetition in range(1, campaign["repetitions"] + 1):
            path = receipt_root / project_id / f"repeat-{repetition}" / "receipt.json"
            if not path.is_file() or not _sidecar(path).is_file():
                raise EvidenceError(f"project {project_id} missing repetition {repetition}")
            receipt = load_verified_receipt(path)
            if (
                receipt.get("status") != "accepted"
                or receipt.get("project") != project_id
                or receipt.get("repetition") != repetition
                or receipt.get("failures") != []
            ):
                raise EvidenceError(f"project {project_id} repetition {repetition} is unavailable")
            receipts.append(receipt)

        project_summary = validate_receipt_group(
            manifest, tier, project_id, receipts
        )
        analyzer_digest = project_summary["analyzer_sha256"]
        campaign_analyzer_digests.add(analyzer_digest)
        if len(campaign_analyzer_digests) != 1:
            raise EvidenceError("campaign analyzer identity is nondeterministic")
        summary["projects"][project_id] = project_summary
    return summary


def _expand(tokens: list[str], values: dict[str, str]) -> list[str]:
    return [token.format(**values) for token in tokens]


def _inside(root: Path, candidate: Path, field: str) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise EvidenceError(f"{field} escapes {resolved_root}")
    return resolved


def _workspace_directory_identity(path: Path) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(f"cannot inspect shard workspace: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.resolve() != path.absolute():
        raise EvidenceError("shard workspace must be one real directory")
    return metadata.st_dev, metadata.st_ino


def _shard_workspace_allocated_bytes(root: Path) -> int:
    total = 0
    pending = [root]
    entries = 0
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as stream:
                for entry in stream:
                    entries += 1
                    if entries > MAX_SHARD_WORKSPACE_ENTRIES:
                        raise EvidenceError(
                            "shard workspace entry count exceeds the safety limit"
                        )
                    metadata = entry.stat(follow_symlinks=False)
                    total += metadata.st_blocks * 512
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(Path(entry.path))
        except OSError as error:
            raise EvidenceError(
                f"cannot inspect shard workspace allocation: {error}"
            ) from error
    return total


def _release_shard_emergency_reserve(*, verify_floor: bool = True) -> None:
    state = _COMMAND_WORKSPACE_STATE.get()
    if state is None:
        return
    reserve = state[5]
    descriptor = reserve["reserve"]
    if descriptor is None:
        return
    reserve["reserve"] = None
    try:
        os.close(descriptor)
        if verify_floor:
            probe = reserve["probe"]
            if probe is None:
                raise EvidenceError("shard reserve filesystem probe is unavailable")
            recovery_deadline = (
                time.monotonic() + SHARD_RESERVE_RECOVERY_TIMEOUT_SECONDS
            )
            while True:
                capacity = os.fstatvfs(probe)
                recovered = capacity.f_bavail * capacity.f_frsize
                if recovered >= MIN_SHARD_FILESYSTEM_FREE_BYTES:
                    break
                if time.monotonic() >= recovery_deadline:
                    raise EvidenceError(
                        "shard reserve release did not recover the free-space floor"
                    )
                time.sleep(SHARD_RESERVE_RECOVERY_POLL_SECONDS)
    except OSError as error:
        raise EvidenceError(f"cannot release shard disk reserve: {error}") from error


def _shard_workspace_budget_failure(message: str) -> None:
    raise EvidenceError(message)


def _check_shard_workspace_budget(required_headroom_bytes: int = 0) -> None:
    state = _COMMAND_WORKSPACE_STATE.get()
    if state is None:
        return
    root, identity, baseline_allocated, baseline_free, _temporary, _reserve = state
    try:
        current_identity = _workspace_directory_identity(root)
    except EvidenceError as error:
        _shard_workspace_budget_failure(str(error))
    if current_identity != identity:
        _shard_workspace_budget_failure(
            "shard workspace identity changed during execution"
        )
    try:
        allocated = _shard_workspace_allocated_bytes(root)
    except EvidenceError as error:
        _shard_workspace_budget_failure(str(error))
    if allocated - baseline_allocated > MAX_SHARD_WORKSPACE_ALLOCATED_BYTES:
        _shard_workspace_budget_failure(
            "shard workspace allocation exceeds the safety limit"
        )
    try:
        free = shutil.disk_usage(root).free
    except OSError as error:
        _shard_workspace_budget_failure(
            f"cannot inspect shard filesystem capacity: {error}"
        )
    if free < MIN_SHARD_FILESYSTEM_FREE_BYTES:
        _shard_workspace_budget_failure(
            "shard filesystem free-space reserve was crossed"
        )
    if free < MIN_SHARD_FILESYSTEM_FREE_BYTES + required_headroom_bytes:
        _shard_workspace_budget_failure(
            "shard filesystem lacks bounded command write headroom"
        )
    if baseline_free - free > MAX_SHARD_WORKSPACE_ALLOCATED_BYTES:
        _shard_workspace_budget_failure(
            "shard filesystem allocation delta exceeds the safety limit"
        )


@contextlib.contextmanager
def _bounded_shard_workspace(root: Path):
    root = root.absolute()
    identity = _workspace_directory_identity(root)
    temporary = root / ".codeskeptic-tmp"
    reserve_path = root / ".codeskeptic-emergency-reserve"
    reserve_descriptor = -1
    probe_descriptor = -1
    try:
        temporary.mkdir(mode=0o700)
        probe_descriptor = os.open(
            root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        reserve_descriptor = os.open(
            reserve_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.posix_fallocate(
            reserve_descriptor, 0, SHARD_EMERGENCY_RESERVE_BYTES
        )
        os.fsync(reserve_descriptor)
        reserve_path.unlink()
        baseline_allocated = _shard_workspace_allocated_bytes(root)
        baseline_free = shutil.disk_usage(root).free
    except (AttributeError, OSError, EvidenceError) as error:
        cleanup_failures: list[str] = []
        if reserve_descriptor >= 0:
            try:
                os.close(reserve_descriptor)
            except OSError as cleanup_error:
                cleanup_failures.append(f"reserve: {cleanup_error}")
        if probe_descriptor >= 0:
            try:
                os.close(probe_descriptor)
            except OSError as cleanup_error:
                cleanup_failures.append(f"filesystem probe: {cleanup_error}")
        try:
            reserve_path.unlink(missing_ok=True)
        except OSError as cleanup_error:
            cleanup_failures.append(f"reserve path: {cleanup_error}")
        if cleanup_failures:
            raise EvidenceError(
                f"cannot establish shard disk reserve: {error}; "
                f"cleanup failed: {'; '.join(cleanup_failures)}"
            ) from error
        raise EvidenceError(f"cannot establish shard disk reserve: {error}") from error
    token = _COMMAND_WORKSPACE_STATE.set(
        (
            root,
            identity,
            baseline_allocated,
            baseline_free,
            temporary,
            {"reserve": reserve_descriptor, "probe": probe_descriptor},
        )
    )
    try:
        _check_shard_workspace_budget()
        yield temporary
    finally:
        state = _COMMAND_WORKSPACE_STATE.get()
        teardown_failures: list[str] = []
        try:
            if not _child_table_empty():
                raise EvidenceError(
                    "shard workspace still has a live child; emergency reserve retained"
                )
            _release_shard_emergency_reserve()
        except BaseException as error:
            teardown_failures.append(f"reserve: {error}")
        try:
            if state is not None and state[5]["probe"] is not None:
                os.close(state[5]["probe"])
                state[5]["probe"] = None
        except BaseException as error:
            teardown_failures.append(f"filesystem probe: {error}")
        finally:
            _COMMAND_WORKSPACE_STATE.reset(token)
        if teardown_failures:
            raise EvidenceError(
                f"shard workspace teardown failed: {'; '.join(teardown_failures)}"
            )


def _memory_preexec(memory_mb: int, file_size_limit_bytes: int | None = None):
    if os.name == "nt":
        return None
    try:
        import resource
    except ImportError:
        return None

    limit = memory_mb * 1024 * 1024
    file_limit = (
        file_size_limit_bytes
        if file_size_limit_bytes is not None
        else MAX_PROCESS_FILE_BYTES
    )

    def apply_limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    return apply_limit


def _proc_record(pid: int) -> tuple[int, int, int] | None:
    try:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        tail = payload[payload.rfind(")") + 2 :].split()
        return int(tail[1]), int(tail[2]), int(tail[19])
    except (OSError, ValueError, IndexError):
        return None


def _enable_subreaper() -> bool:
    global _SUBREAPER_ENABLED, _SUBREAPER_PID
    current_pid = os.getpid()
    if _SUBREAPER_ENABLED and _SUBREAPER_PID == current_pid:
        return True
    if os.name != "posix" or not Path("/proc").is_dir():
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            return False
    except (AttributeError, OSError):
        return False
    _SUBREAPER_ENABLED = True
    _SUBREAPER_PID = current_pid
    return True


def _direct_children() -> set[int]:
    children: set[int] = set()
    if not Path("/proc").is_dir():
        return children
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            record = _proc_record(int(entry.name))
            if record is not None and record[0] == os.getpid():
                children.add(int(entry.name))
    return children


def _refresh_descendants(root_pid: int, known: dict[int, int]) -> None:
    if os.name != "posix" or not Path("/proc").is_dir():
        return
    records: dict[int, tuple[int, int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        record = _proc_record(pid)
        if record is not None:
            records[pid] = (record[0], record[2])
    parents = {root_pid, *known}
    changed = True
    while changed:
        changed = False
        for pid, (parent, started) in records.items():
            adopted = parent == os.getpid()
            if pid not in known and (parent in parents or adopted):
                known[pid] = started
                parents.add(pid)
                changed = True


def _pid_matches(pid: int, started: int) -> bool:
    record = _proc_record(pid)
    return record is not None and record[2] == started


def _reap_known(process: subprocess.Popen[bytes], known: dict[int, int]) -> None:
    process.poll()
    _child_table_empty()


def _child_table_empty() -> bool:
    """Reap exited children and succeed only when waitpid reports ECHILD."""

    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        except InterruptedError:
            continue
        except OSError as error:
            raise EvidenceError(f"cannot inspect command child table: {error}") from error
        if pid == 0:
            return False


def _require_empty_child_table() -> None:
    if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
        raise EvidenceError(
            "command execution requires one dedicated single-threaded controller"
        )
    if not _child_table_empty() or _direct_children():
        raise EvidenceError(
            "command execution found a pre-existing child; dedicated process authority is required"
        )


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _known_process_group_exists(pgid: int, known: dict[int, int]) -> bool:
    for pid, started in known.items():
        record = _proc_record(pid)
        if record is not None and record[2] == started and record[1] == pgid:
            return True
    return False


def _terminate_command_tree(
    process: subprocess.Popen[bytes], known: dict[int, int],
) -> None:
    _refresh_descendants(process.pid, known)
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        end = time.monotonic() + (0.25 if signal_number == signal.SIGTERM else 1.0)
        while True:
            _refresh_descendants(process.pid, known)
            if _known_process_group_exists(process.pid, known):
                try:
                    os.killpg(process.pid, signal_number)
                except ProcessLookupError:
                    pass
            for pid, started in list(known.items()):
                if pid != os.getpid() and _pid_matches(pid, started):
                    try:
                        os.kill(pid, signal_number)
                    except ProcessLookupError:
                        pass
            _reap_known(process, known)
            alive = any(_pid_matches(pid, started) for pid, started in known.items())
            child_table_empty = _child_table_empty()
            if (
                child_table_empty
                and not alive
                and not _known_process_group_exists(process.pid, known)
            ):
                return
            if time.monotonic() >= end:
                break
            time.sleep(0.01)
    if process.poll() is None:
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired as error:
            raise EvidenceError("command process leader could not be reaped") from error
    _refresh_descendants(process.pid, known)
    alive = [pid for pid, started in known.items() if _pid_matches(pid, started)]
    if (
        alive
        or _known_process_group_exists(process.pid, known)
        or not _child_table_empty()
    ):
        raise EvidenceError("command descendant cleanup was incomplete")


def _open_command_log(path: Path) -> int:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_COMMAND_LOG_BYTES
    ):
        os.close(descriptor)
        raise EvidenceError("commands log type, link count, or size is invalid")
    return descriptor


def _bounded_log_write(descriptor: int, payload: bytes) -> None:
    size = os.fstat(descriptor).st_size
    if size + len(payload) > MAX_COMMAND_LOG_BYTES:
        raise EvidenceError("commands log exceeded the safety limit")
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise EvidenceError("commands log write was incomplete")
        offset += written


def _check_watched_files(watched_files: dict[Path, int]) -> None:
    for path, maximum in watched_files.items():
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise EvidenceError(f"cannot inspect bounded output {path}: {error}") from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise EvidenceError(f"bounded output is not one regular file: {path}")
        if metadata.st_size > maximum:
            raise EvidenceError(f"bounded output exceeded the safety limit: {path}")


def _supervise_command(
    command: list[str],
    cwd: Path,
    deadline: float,
    memory_mb: int,
    log_path: Path,
    env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    *,
    capture: bool = False,
    watched_files: dict[Path, int] | None = None,
    file_size_limit_bytes: int | None = None,
) -> subprocess.CompletedProcess[str]:
    remaining = max(0.0, deadline - time.monotonic())
    if remaining <= 0:
        raise EvidenceError("project shard timed out")
    subreaper = _enable_subreaper()
    if not subreaper:
        raise EvidenceError(
            "command execution requires Linux /proc subreaper containment"
        )
    _require_empty_child_table()
    command_file_limit = (
        file_size_limit_bytes
        if file_size_limit_bytes is not None
        else MAX_PROCESS_FILE_BYTES
    )
    try:
        _check_shard_workspace_budget(required_headroom_bytes=command_file_limit)
    except EvidenceError as error:
        try:
            _release_shard_emergency_reserve()
        except EvidenceError as recovery_error:
            raise EvidenceError(f"{error}; {recovery_error}") from error
        raise
    command_environment = env
    workspace_state = _COMMAND_WORKSPACE_STATE.get()
    if workspace_state is not None:
        command_environment = dict(os.environ if env is None else env)
        command_environment["TMPDIR"] = os.fspath(workspace_state[4])
    next_workspace_check = 0.0

    def check_workspace(*, force: bool = False) -> None:
        nonlocal next_workspace_check
        now = time.monotonic()
        if force or now >= next_workspace_check:
            _check_shard_workspace_budget()
            next_workspace_check = now + SHARD_WORKSPACE_POLL_SECONDS

    try:
        log_descriptor = _open_command_log(log_path)
    except BaseException as error:
        try:
            _release_shard_emergency_reserve()
        except EvidenceError as recovery_error:
            raise EvidenceError(f"{error}; {recovery_error}") from error
        raise
    process: subprocess.Popen[bytes] | None = None
    known: dict[int, int] = {}
    output = bytearray()
    watched = watched_files or {}
    try:
        header = f"COMMAND cwd={cwd.as_posix()} argv={json.dumps(command)}\n".encode()
        _bounded_log_write(log_descriptor, header)
        process = subprocess.Popen(
            command, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=_memory_preexec(memory_mb, file_size_limit_bytes),
            env=command_environment,
            pass_fds=pass_fds, start_new_session=True,
        )
        record = _proc_record(process.pid)
        if record is not None:
            known[process.pid] = record[2]
        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                check_workspace()
                _check_watched_files(watched)
                _refresh_descendants(process.pid, known)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EvidenceError("project shard timed out")
                events = selector.select(min(remaining, 0.02))
                for key, _mask in events:
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    _bounded_log_write(log_descriptor, block)
                    if capture:
                        if len(output) + len(block) > MAX_COMMAND_CAPTURE_BYTES:
                            raise EvidenceError("command capture exceeded the safety limit")
                        output.extend(block)
            check_workspace(force=True)
            _refresh_descendants(process.pid, known)
            _check_watched_files(watched)
            while process.poll() is None:
                check_workspace()
                _refresh_descendants(process.pid, known)
                _check_watched_files(watched)
                if time.monotonic() >= deadline:
                    raise EvidenceError("project shard timed out")
                time.sleep(0.01)
            returncode = process.returncode
            assert returncode is not None
            grace = min(deadline, time.monotonic() + 0.05)
            while True:
                check_workspace()
                _check_watched_files(watched)
                _refresh_descendants(process.pid, known)
                _reap_known(process, known)
                survivors = [
                    pid for pid, started in known.items()
                    if pid != process.pid and _pid_matches(pid, started)
                ]
                if (
                    _child_table_empty()
                    and not survivors
                    and not _known_process_group_exists(process.pid, known)
                ):
                    break
                if time.monotonic() >= grace:
                    raise EvidenceError("command left an orphan descendant")
                time.sleep(0.005)
            check_workspace(force=True)
            _check_watched_files(watched)
            _bounded_log_write(log_descriptor, f"EXIT {returncode}\n".encode())
            try:
                decoded = output.decode("utf-8")
            except UnicodeDecodeError as error:
                raise EvidenceError("captured command output is not UTF-8") from error
            return subprocess.CompletedProcess(command, returncode, decoded, "")
        finally:
            selector_error = sys.exc_info()[1]
            try:
                selector.close()
            except BaseException as cleanup_error:
                if selector_error is not None:
                    raise EvidenceError(
                        f"{selector_error}; selector cleanup failed: {cleanup_error}"
                    ) from selector_error
                raise EvidenceError(
                    f"selector cleanup failed: {cleanup_error}"
                ) from cleanup_error
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceError(f"command execution failed: {error}") from error
    finally:
        active_error = sys.exc_info()[1]
        cleanup_failures: list[str] = []
        descendants_quiesced = True
        if process is not None:
            if process.poll() is None or any(
                _pid_matches(pid, started) for pid, started in known.items()
            ) or _known_process_group_exists(
                process.pid, known
            ) or not _child_table_empty():
                try:
                    _terminate_command_tree(process, known)
                except EvidenceError as cleanup_error:
                    descendants_quiesced = False
                    cleanup_failures.append(f"descendants: {cleanup_error}")
            if process.stdout is not None and not process.stdout.closed:
                try:
                    process.stdout.close()
                except OSError as cleanup_error:
                    cleanup_failures.append(f"command pipe: {cleanup_error}")
        if active_error is not None and descendants_quiesced:
            try:
                _release_shard_emergency_reserve()
            except EvidenceError as cleanup_error:
                cleanup_failures.append(f"emergency reserve: {cleanup_error}")
        try:
            os.close(log_descriptor)
        except OSError as cleanup_error:
            cleanup_failures.append(f"command log: {cleanup_error}")
        if cleanup_failures:
            detail = "; ".join(cleanup_failures)
            if active_error is not None:
                raise EvidenceError(
                    f"{active_error}; command cleanup failed: {detail}"
                ) from active_error
            raise EvidenceError(f"command cleanup failed: {detail}")


def _run_command(
    command: list[str], cwd: Path, deadline: float, memory_mb: int,
    log_path: Path, env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    *, watched_files: dict[Path, int] | None = None,
    file_size_limit_bytes: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return _supervise_command(
        command, cwd, deadline, memory_mb, log_path, env, pass_fds,
        watched_files=watched_files,
        file_size_limit_bytes=file_size_limit_bytes,
    )


def _expected_submodules(project: dict[str, Any]) -> dict[str, Any]:
    checkout = project.get(
        "checkout",
        {
            "submodules": "none",
            "expected_count": 0,
            "expected_sha256": digest_json([]),
        },
    )
    return {
        "mode": checkout["submodules"],
        "count": checkout["expected_count"],
        "sha256": checkout["expected_sha256"],
    }


def _capture_git(
    command: list[str],
    cwd: Path,
    deadline: float,
    memory_mb: int,
    log_path: Path,
    env: dict[str, str],
) -> str:
    result = _supervise_command(
        command, cwd, deadline, memory_mb, log_path, env, capture=True
    )
    if result.returncode != 0:
        raise EvidenceError(f"git command failed with exit {result.returncode}")
    return result.stdout


def _parse_submodule_status(output: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    pattern = re.compile(r" ([0-9a-f]{40}) (.+?)(?: \([^\r\n]*\))?$")
    for line in output.splitlines():
        match = pattern.fullmatch(line)
        if match is None:
            raise EvidenceError(
                "recursive submodule is uninitialized, drifted, conflicted, or malformed"
            )
        revision, path = match.groups()
        entries.append(
            {"path": _require_relative(path, "submodule path"), "revision": revision}
        )
    entries.sort(key=lambda entry: entry["path"])
    if not entries or len({entry["path"] for entry in entries}) != len(entries):
        raise EvidenceError("recursive submodule identity is empty or duplicated")
    return entries


def _resolve_submodule_repository(parent: str, raw: str, field: str) -> str:
    if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw:
        raise EvidenceError(f"{field} is malformed")
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        return _validate_upstream_url(raw, field)
    if raw.startswith("/"):
        raise EvidenceError(f"{field} must not be an absolute local path")
    resolved = urljoin(parent.rstrip("/") + "/", raw)
    return _validate_upstream_url(resolved, field)


def _gitmodule_entries(
    repository_root: Path,
    prefix: str,
    parent_repository: str,
    project_root: Path,
    deadline: float,
    memory_mb: int,
    log_path: Path,
    git_env: dict[str, str],
) -> list[dict[str, str]]:
    modules = repository_root / ".gitmodules"
    try:
        kind = _path_kind(modules)
    except EvidenceError as error:
        raise EvidenceError(f"cannot inspect checked-out .gitmodules: {error}") from error
    if kind == "missing":
        return []
    if kind != "regular":
        raise EvidenceError("checked-out .gitmodules is not a regular file")
    output = _capture_git(
        [
            "git",
            "config",
            "--file",
            str(modules),
            "--get-regexp",
            r"^submodule\..*\.(path|url)$",
        ],
        repository_root,
        deadline,
        memory_mb,
        log_path,
        git_env,
    )
    records: dict[str, dict[str, str]] = {}
    pattern = re.compile(r"submodule\.(.+)\.(path|url)")
    for line in output.splitlines():
        try:
            key, value = line.split(None, 1)
        except ValueError as error:
            raise EvidenceError("checked-out .gitmodules output is malformed") from error
        match = pattern.fullmatch(key)
        if match is None:
            raise EvidenceError("checked-out .gitmodules key is malformed")
        name, item = match.groups()
        record = records.setdefault(name, {})
        if item in record:
            raise EvidenceError("checked-out .gitmodules has a duplicate field")
        record[item] = value
    entries: list[dict[str, str]] = []
    for name, record in sorted(records.items()):
        if set(record) != {"path", "url"}:
            raise EvidenceError(
                f"checked-out .gitmodules entry {name!r} is incomplete"
            )
        relative = _mirror_require_relative(
            record["path"], f"checked-out submodule {name} path"
        )
        full_path = f"{prefix}/{relative}" if prefix else relative
        full_path = _mirror_require_relative(
            full_path, f"checked-out submodule {name} recursive path"
        )
        upstream = _resolve_submodule_repository(
            parent_repository,
            record["url"],
            f"checked-out submodule {full_path} repository",
        )
        child_root = _inside(
            project_root,
            project_root / full_path,
            "checked-out submodule path",
        )
        if not child_root.is_dir():
            raise EvidenceError(f"checked-out submodule is unavailable: {full_path}")
        entries.append({"path": full_path, "repository": upstream})
        entries.extend(
            _gitmodule_entries(
                child_root,
                full_path,
                upstream,
                project_root,
                deadline,
                memory_mb,
                log_path,
                git_env,
            )
        )
    return entries


def _verify_offline_submodule_authority(
    project: dict[str, Any],
    mirror_project: dict[str, Any],
    project_root: Path,
    status_entries: list[dict[str, str]],
    deadline: float,
    log_path: Path,
    git_env: dict[str, str],
) -> None:
    authority_entries = mirror_project["submodules"]
    authority_identity = [
        {"path": entry["path"], "revision": entry["revision"]}
        for entry in authority_entries
    ]
    if status_entries != authority_identity:
        raise EvidenceError("offline submodule revisions do not match mirror authority")
    actual_mappings = _gitmodule_entries(
        project_root,
        "",
        project["repository"],
        project_root,
        deadline,
        project["memory_mb"],
        log_path,
        git_env,
    )
    expected_mappings = [
        {"path": entry["path"], "repository": entry["repository"]}
        for entry in authority_entries
    ]
    if sorted(actual_mappings, key=lambda entry: entry["path"]) != expected_mappings:
        raise EvidenceError("offline submodule URL mapping does not match mirror authority")
    for entry in authority_entries:
        submodule_root = _inside(
            project_root,
            project_root / entry["path"],
            "checked-out submodule authority path",
        )
        tree = _capture_git(
            ["git", "rev-parse", "HEAD^{tree}"],
            submodule_root,
            deadline,
            project["memory_mb"],
            log_path,
            git_env,
        ).strip()
        if tree != entry["tree"]:
            raise EvidenceError(
                f"offline submodule tree mismatch for {entry['path']}"
            )


def _submodule_identity(
    project: dict[str, Any],
    project_root: Path,
    deadline: float,
    log_path: Path,
    mirror_project: dict[str, Any] | None = None,
    offline_repositories: dict[str, Path] | None = None,
) -> dict[str, Any]:
    expected = _expected_submodules(project)
    mode = expected["mode"]
    if (mirror_project is None) != (offline_repositories is None):
        raise EvidenceError("offline mirror transport is incomplete")
    if mirror_project is None:
        git_env = os.environ.copy()
        git_env["GIT_ALLOW_PROTOCOL"] = "https"
        git_env["GIT_TERMINAL_PROMPT"] = "0"
        file_policy = "never"
    else:
        assert offline_repositories is not None
        git_env = offline_git_environment(mirror_project, offline_repositories)
        file_policy = "always"
    stage = _capture_git(
        ["git", "ls-files", "--stage"],
        project_root,
        deadline,
        project["memory_mb"],
        log_path,
        git_env,
    )
    gitlinks = [line for line in stage.splitlines() if line.startswith("160000 ")]
    if mode == "none":
        if gitlinks:
            raise EvidenceError("project has undeclared gitlink submodules")
        return expected

    for command in (
        [
            "git",
            "-c",
            f"protocol.file.allow={file_policy}",
            "submodule",
            "sync",
            "--recursive",
        ],
        [
            "git",
            "-c",
            f"protocol.file.allow={file_policy}",
            "submodule",
            "update",
            "--init",
            "--recursive",
            "--depth",
            "1",
            "--jobs",
            "2",
        ],
    ):
        result = _run_command(
            command,
            project_root,
            deadline,
            project["memory_mb"],
            log_path,
            env=git_env,
        )
        if result.returncode != 0:
            raise EvidenceError(
                f"recursive submodule checkout failed with exit {result.returncode}"
            )

    status = _capture_git(
        ["git", "submodule", "status", "--recursive"],
        project_root,
        deadline,
        project["memory_mb"],
        log_path,
        git_env,
    )
    entries = _parse_submodule_status(status)

    clean = _capture_git(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
            "--ignore-submodules=none",
        ],
        project_root,
        deadline,
        project["memory_mb"],
        log_path,
        git_env,
    )
    if clean:
        raise EvidenceError("recursive submodule checkout is not clean")

    actual = {
        "mode": mode,
        "count": len(entries),
        "sha256": digest_json(entries),
    }
    if actual != expected:
        raise EvidenceError("recursive submodule identity does not match the manifest")
    if mirror_project is not None:
        _verify_offline_submodule_authority(
            project,
            mirror_project,
            project_root,
            entries,
            deadline,
            log_path,
            git_env,
        )
    return actual


def _materialize_offline_repositories(
    project: dict[str, Any],
    mirror_project: dict[str, Any],
    mirror_root: Path,
    transport_root: Path,
    deadline: float,
    log_path: Path,
) -> dict[str, Path]:
    if _path_kind(transport_root) == "directory":
        shutil.rmtree(transport_root)
    elif _path_kind(transport_root) != "missing":
        raise EvidenceError("offline transport staging path is not a real directory")
    transport_root.mkdir(parents=True)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in (mirror_project, *mirror_project["submodules"]):
        grouped.setdefault(record["repository"], []).append(record)
    environment = _offline_base_environment()
    repositories: dict[str, Path] = {}
    for upstream, records in sorted(grouped.items()):
        target = transport_root / f"{digest_bytes(upstream.encode('utf-8'))}.git"
        bundle = _mirror_relative_path(
            mirror_root,
            records[0]["bundle"],
            f"mirror upstream {upstream} bundle",
        ).absolute()
        with _open_immutable_file(bundle, maximum=MAX_MIRROR_BUNDLE_BYTES) as opened:
            bundle_fd, bundle_digest, _ = opened
            if bundle_digest != records[0]["bundle_sha256"]:
                raise EvidenceError(f"mirror bundle checksum mismatch: {bundle}")
            descriptor_bundle = f"/proc/self/fd/{bundle_fd}"
            if not Path("/proc/self/fd").is_dir():
                raise EvidenceError("descriptor-backed offline Git transport is unavailable")
            commands: list[list[str]] = [["git", "init", "--bare", "--quiet", str(target)]]
            revisions = sorted({record["revision"] for record in records})
            for revision in revisions:
                commands.extend(
                    [
                        [
                            "git",
                            "-c",
                            "protocol.file.allow=always",
                            "--git-dir",
                            str(target),
                            "fetch",
                            "--quiet",
                            descriptor_bundle,
                            revision,
                        ],
                        [
                            "git",
                            "--git-dir",
                            str(target),
                            "update-ref",
                            f"refs/heads/codeskeptic-{revision}",
                            revision,
                        ],
                    ]
                )
            commands.extend(
                [
                    [
                        "git",
                        "--git-dir",
                        str(target),
                        "update-ref",
                        "refs/heads/codeskeptic-offline",
                        revisions[0],
                    ],
                    [
                        "git",
                        "--git-dir",
                        str(target),
                        "symbolic-ref",
                        "HEAD",
                        "refs/heads/codeskeptic-offline",
                    ],
                ]
            )
            for command in commands:
                result = _run_command(
                    command,
                    transport_root,
                    deadline,
                    project["memory_mb"],
                    log_path,
                    env=environment,
                    pass_fds=(bundle_fd,),
                )
                if result.returncode != 0:
                    raise EvidenceError(
                        f"offline mirror materialization failed with exit {result.returncode}"
                    )
        repositories[upstream] = target
    return repositories


def _checkout_project(
    project: dict[str, Any],
    project_root: Path,
    deadline: float,
    log_path: Path,
    mirror_project: dict[str, Any] | None = None,
    mirror_root: Path | None = None,
) -> dict[str, Any]:
    if (mirror_project is None) != (mirror_root is None):
        raise EvidenceError("offline mirror transport is incomplete")
    offline_repositories: dict[str, Path] | None = None
    transport_root: Path | None = None
    try:
        if mirror_project is None:
            git_environment = None
            fetch_source = "origin"
            fetch_prefix = ["git"]
        else:
            assert mirror_root is not None
            transport_root = (
                project_root.parent / f".{project['id']}-mirror-transport"
            )
            offline_repositories = _materialize_offline_repositories(
                project,
                mirror_project,
                mirror_root,
                transport_root,
                deadline,
                log_path,
            )
            git_environment = offline_git_environment(
                mirror_project, offline_repositories
            )
            fetch_source = str(offline_repositories[project["repository"]])
            fetch_prefix = ["git", "-c", "protocol.file.allow=always"]
        project_root.mkdir(parents=True)
        commands = (
            ["git", "init", "--quiet"],
            ["git", "remote", "add", "origin", project["repository"]],
            [
                *fetch_prefix,
                "fetch",
                "--quiet",
                "--depth",
                "1",
                fetch_source,
                project["revision"],
            ],
            ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        )
        for command in commands:
            result = _run_command(
                command,
                project_root,
                deadline,
                project["memory_mb"],
                log_path,
                env=git_environment,
            )
            if result.returncode != 0:
                raise EvidenceError(
                    f"checkout command failed with exit {result.returncode}"
                )
        capture_environment = git_environment or os.environ.copy()
        resolved_revision = _capture_git(
            ["git", "rev-parse", "HEAD"],
            project_root,
            deadline,
            project["memory_mb"],
            log_path,
            capture_environment,
        ).strip()
        if resolved_revision != project["revision"]:
            raise EvidenceError(
                f"checkout revision mismatch {resolved_revision} != {project['revision']}"
            )
        if mirror_project is not None:
            resolved_tree = _capture_git(
                ["git", "rev-parse", "HEAD^{tree}"],
                project_root,
                deadline,
                project["memory_mb"],
                log_path,
                capture_environment,
            ).strip()
            if resolved_tree != mirror_project["tree"]:
                raise EvidenceError(
                    "offline checkout tree does not match mirror authority"
                )
        return _submodule_identity(
            project,
            project_root,
            deadline,
            log_path,
            mirror_project,
            offline_repositories,
        )
    finally:
        if transport_root is not None and _path_kind(transport_root) == "directory":
            shutil.rmtree(transport_root)


def _derive_translation_units(
    project: dict[str, Any], source: Path, build: Path, compile_database: Path
) -> tuple[list[Path], list[str]]:
    try:
        database = json.loads(
            _read_regular_bytes(
                compile_database, MAX_COMPILE_DATABASE_BYTES
            ).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"compile database unavailable: {compile_database}: {error}") from error
    if not isinstance(database, list):
        raise EvidenceError("compile database root is not an array")
    roots = [_inside(source, source / root, "source root") for root in project["sources"]["roots"]]
    extensions = set(project["sources"]["extensions"])
    selected: dict[str, Path] = {}
    for entry in database:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise EvidenceError("compile database contains a malformed entry")
        directory = Path(entry.get("directory", build))
        file_path = Path(entry["file"])
        if not file_path.is_absolute():
            file_path = directory / file_path
        resolved = file_path.resolve()
        if resolved.suffix not in extensions or not any(
            resolved == root or root in resolved.parents for root in roots
        ):
            continue
        _inside(source, resolved, "compile database source")
        relative = resolved.relative_to(source.resolve()).as_posix()
        selected[relative] = resolved
    for pattern in project["sources"]["fallback_globs"]:
        matches = sorted(source.glob(pattern))
        if not matches:
            raise EvidenceError(f"fallback glob matched no translation unit: {pattern}")
        for file_path in matches:
            resolved = _inside(source, file_path, "fallback source")
            if not resolved.is_file() or resolved.suffix not in extensions:
                raise EvidenceError(f"fallback is not an admitted source: {file_path}")
            selected[resolved.relative_to(source.resolve()).as_posix()] = resolved
    if not selected:
        raise EvidenceError("derived translation-unit list is empty")
    relative_paths = sorted(selected)
    return [selected[path] for path in relative_paths], relative_paths


def filter_target_translation_units(
    command_output: str,
    source: Path,
    build: Path,
    files: list[Path],
    relative_files: list[str],
) -> tuple[list[Path], list[str]]:
    if len(files) != len(relative_files):
        raise EvidenceError("translation-unit identity is malformed")
    source_root = source.resolve()
    for path in files:
        resolved = path.resolve()
        if resolved != source_root and source_root not in resolved.parents:
            raise EvidenceError(
                "translation-unit identity escapes the pinned source tree"
            )
    admitted = {
        path.resolve(): (path, relative)
        for path, relative in zip(files, relative_files, strict=True)
    }
    target_sources: set[Path] = set()
    for line in command_output.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError as error:
            raise EvidenceError(
                f"Ninja target closure contains an invalid command: {error}"
            ) from error
        compile_indexes = [index for index, token in enumerate(tokens) if token == "-c"]
        if not compile_indexes:
            continue
        if len(compile_indexes) != 1:
            raise EvidenceError(
                "Ninja target closure contains an ambiguous compile command"
            )
        command_sources: set[Path] = set()
        for token in tokens:
            if token.startswith("-"):
                continue
            path = Path(token)
            if not path.is_absolute():
                path = build / path
            resolved = path.resolve()
            if resolved in admitted:
                command_sources.add(resolved)
        if len(command_sources) > 1:
            raise EvidenceError(
                "Ninja target closure contains an ambiguous compile source"
            )
        target_sources.update(command_sources)

    selected = sorted(
        (relative, path)
        for resolved, (path, relative) in admitted.items()
        if resolved in target_sources
    )
    if not selected:
        raise EvidenceError(
            "Ninja target closure selected no admitted translation units"
        )
    return [path for _, path in selected], [relative for relative, _ in selected]


def run_shard(
    manifest: dict[str, Any],
    project_id: str,
    repetition: int,
    analyzer: Path,
    workspace: Path,
    output: Path,
    checkpoint: Path | None,
    repository_root: Path,
    mirror_authority: Path | None = None,
    *,
    tu_timeout_seconds: int = DEFAULT_TU_TIMEOUT_SECONDS,
    tu_memory_mib: int = DEFAULT_TU_MEMORY_MIB,
) -> int:
    project = project_by_id(manifest, project_id)
    if repetition < 1 or repetition > 3:
        raise ManifestError("repetition identity is outside the admitted range")
    analyzer = analyzer.resolve()
    if not analyzer.is_file():
        raise EvidenceError(f"analyzer unavailable: {analyzer}")
    analyzer_sha = file_digest(analyzer)
    mirror_project: dict[str, Any] | None = None
    mirror_root: Path | None = None
    if mirror_authority is not None:
        mirror_project, mirror_root = load_mirror_authority(
            mirror_authority, manifest, project_id
        )
    expected_submodules = _expected_submodules(project)
    expected_identity = receipt_identity(
        manifest,
        project,
        repetition,
        analyzer_sha,
        project["expected"]["translation_unit_sha256"],
        expected_submodules,
    )
    started = time.monotonic()
    output.parent.mkdir(parents=True, exist_ok=True)
    if checkpoint is not None:
        # The shard receipt validates explicit resume identity, but is not
        # verdict authority. Rebuild the current compile database and let the
        # analyzer's per-unit evidence store revalidate exact command plans.
        load_matching_checkpoint(checkpoint, expected_identity, project)

    semantic: dict[str, Any] | None = None
    unit_plan: dict[str, Any] | None = None
    actual_tu_sha = project["expected"]["translation_unit_sha256"]
    actual_submodules = expected_submodules
    failures: list[str] = []
    log_path = output.parent / "commands.log"
    if log_path.exists():
        log_path.unlink()
    deadline = started + project["timeout_minutes"] * 60
    workspace_created = False
    workspace_identity: tuple[int, int] | None = None
    workspace_budget = None
    workspace_budget_entered = False
    try:
        workspace.mkdir(parents=True, exist_ok=False)
        workspace_created = True
        workspace_identity = _workspace_directory_identity(workspace.absolute())
        workspace_budget = _bounded_shard_workspace(workspace)
        workspace_budget.__enter__()
        workspace_budget_entered = True
        project_root = _inside(workspace, workspace / project_id, "project workspace")
        actual_submodules = _checkout_project(
            project,
            project_root,
            deadline,
            log_path,
            mirror_project,
            mirror_root,
        )
        build = _inside(project_root, project_root / "build-codeskeptic", "project build")
        values = {"source": str(project_root), "build": str(build), "jobs": "2"}
        compile_database = Path(project["compile_database"].format(**values))

        for operation in project["copies"]:
            source_file = _inside(repository_root, repository_root / operation["from"], "copy source")
            destination = _inside(project_root, project_root / operation["to"], "copy destination")
            if not source_file.is_file():
                raise EvidenceError(f"copy source unavailable: {operation['from']}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, destination)
        for group in ("configure", "build"):
            for command in project["commands"][group]:
                command_environment = (
                    _offline_base_environment()
                    if mirror_project is not None
                    else os.environ.copy()
                )
                command_environment.update(project.get("environment", {}))
                result = _run_command(
                    _expand(command, values),
                    project_root,
                    deadline,
                    project["memory_mb"],
                    log_path,
                    env=command_environment,
                    watched_files={
                        compile_database: MAX_COMPILE_DATABASE_BYTES
                    },
                )
                if result.returncode != 0:
                    raise EvidenceError(f"{group} command failed with exit {result.returncode}")
        files, relative_files = _derive_translation_units(
            project, project_root, build, compile_database
        )
        ninja_target = None
        for build_command in project["commands"]["build"]:
            expanded_build_command = _expand(build_command, values)
            if "--target" not in expanded_build_command:
                continue
            target_index = expanded_build_command.index("--target")
            if target_index + 1 >= len(expanded_build_command):
                raise EvidenceError("build target is missing")
            ninja_target = expanded_build_command[target_index + 1]
            break
        target_commands = ""
        if ninja_target is not None:
            target_commands = _capture_git(
                ["ninja", "-C", str(build), "-t", "commands", ninja_target],
                project_root,
                deadline,
                project["memory_mb"],
                log_path,
                None,
            )
        if target_commands:
            files, relative_files = filter_target_translation_units(
                target_commands, project_root, build, files, relative_files
            )
        actual_tu_sha = translation_unit_digest(relative_files)
        file_list = output.parent / "translation-units.txt"
        file_list.write_text(
            "\n".join(str(path) for path in files) + "\n", encoding="utf-8", newline="\n"
        )
        (output.parent / "translation-units.relative.txt").write_text(
            "\n".join(relative_files) + "\n", encoding="utf-8", newline="\n"
        )
        if target_commands:
            if (
                len(files) != project["expected"]["translation_units"]
                or actual_tu_sha != project["expected"]["translation_unit_sha256"]
            ):
                raise EvidenceError(
                    "translation-unit expectation drift: "
                    f"count={len(files)} sha256={actual_tu_sha}"
                )
        report_path = output.parent / "report.json"
        analyzer_command = [
            str(analyzer),
            "--files",
            str(file_list),
            "--build-path",
            str(build),
            "--json",
            str(report_path),
            "--tu-timeout-seconds",
            str(tu_timeout_seconds),
            "--tu-memory-mib",
            str(tu_memory_mib),
            *analyzer_checkpoint_arguments(checkpoint),
            *_expand(project["analyzer_args"], values),
        ]
        result = _run_command(
            analyzer_command,
            repository_root,
            deadline,
            project["memory_mb"],
            log_path,
            watched_files={report_path: MAX_ANALYZER_REPORT_BYTES},
            file_size_limit_bytes=MAX_ANALYZER_REPORT_BYTES,
        )
        try:
            report = json.loads(
                _read_regular_bytes(
                    report_path, MAX_ANALYZER_REPORT_BYTES
                ).decode("utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceError(f"analyzer report is malformed: {error}") from error
        semantic = _report_semantic(
            result.returncode,
            report,
            len(files),
            actual_tu_sha,
            whole_program="--whole-program" in project["analyzer_args"],
            expected_timeout_seconds=tu_timeout_seconds,
            expected_memory_mib=tu_memory_mib,
        )
        unit_plan = translation_unit_plan(
            report,
            len(files),
            semantic["coverage"]["analyzed_tus"],
            files,
            whole_program="--whole-program" in project["analyzer_args"],
            expected_timeout_seconds=tu_timeout_seconds,
            expected_memory_mib=tu_memory_mib,
        )
        _validate_semantic(project, semantic)
    except (CampaignError, OSError, subprocess.SubprocessError) as error:
        failures.append(str(error))
    finally:
        workspace_quiesced = True
        if workspace_budget is not None and workspace_budget_entered:
            try:
                workspace_budget.__exit__(None, None, None)
            except BaseException as error:
                workspace_quiesced = False
                failures.append(f"cannot release shard disk reserve: {error}")
        if workspace_created and workspace_quiesced:
            try:
                if (
                    workspace_identity is None
                    or _workspace_directory_identity(workspace.absolute())
                    != workspace_identity
                ):
                    raise EvidenceError("shard workspace cleanup identity changed")
                shutil.rmtree(workspace)
            except (CampaignError, OSError) as error:
                failures.append(f"cannot remove shard workspace: {error}")
            if workspace.exists() or workspace.is_symlink():
                failures.append("shard workspace survived cleanup")
        elif workspace_created:
            failures.append(
                "shard workspace cleanup withheld because process quiescence was not proven"
            )

    identity = receipt_identity(
        manifest,
        project,
        repetition,
        analyzer_sha,
        actual_tu_sha,
        actual_submodules,
    )
    accepted = not failures and semantic is not None
    receipt = {
        "schema": SCHEMA,
        "status": "accepted" if accepted else "unavailable",
        "project": project_id,
        "repetition": repetition,
        "identity": identity,
        "semantic": semantic,
        "execution": {
            "duration_seconds": round(time.monotonic() - started, 3),
            "resumed": bool(
                unit_plan is not None and unit_plan["checkpoint"] > 0
            ),
            "translation_unit_plan": unit_plan,
        },
        "failures": failures or ([] if accepted else ["missing semantic evidence"]),
    }
    write_receipt(output, receipt)
    if accepted and checkpoint is not None:
        write_receipt(checkpoint, receipt)
    return 0 if accepted else 2


def _default_manifest() -> Path:
    return Path(__file__).with_name("realworld_manifest.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="validate and print a shard matrix")
    plan.add_argument("--manifest", type=Path, default=_default_manifest())
    plan.add_argument("--tier", default="nightly")

    run = subparsers.add_parser("run", help="execute one project repetition")
    run.add_argument("--manifest", type=Path, default=_default_manifest())
    run.add_argument("--project", required=True)
    run.add_argument("--repetition", required=True, type=int)
    run.add_argument("--analyzer", required=True, type=Path)
    run.add_argument("--workspace", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--checkpoint", type=Path)
    run.add_argument(
        "--tu-timeout-seconds", type=int, default=DEFAULT_TU_TIMEOUT_SECONDS
    )
    run.add_argument("--tu-memory-mib", type=int, default=DEFAULT_TU_MEMORY_MIB)
    run.add_argument(
        "--mirror-authority",
        type=Path,
        help="use one sealed local mirror authority and disable network Git transports",
    )
    run.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])

    aggregate = subparsers.add_parser("aggregate", help="verify all campaign receipts")
    aggregate.add_argument("--manifest", type=Path, default=_default_manifest())
    aggregate.add_argument("--tier", default="nightly")
    aggregate.add_argument("--receipts", required=True, type=Path)
    aggregate.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = validate_manifest(load_manifest(args.manifest))
        if args.command == "plan":
            print(json.dumps(plan_matrix(manifest, args.tier), sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "run":
            return run_shard(
                manifest,
                args.project,
                args.repetition,
                args.analyzer,
                args.workspace,
                args.output,
                args.checkpoint,
                args.repository_root,
                args.mirror_authority,
                tu_timeout_seconds=args.tu_timeout_seconds,
                tu_memory_mib=args.tu_memory_mib,
            )
        summary = aggregate_receipts(manifest, args.tier, args.receipts)
        write_receipt(args.output, summary)
        print(
            f"REALWORLD_CAMPAIGN_OK campaign={args.tier} "
            f"projects={len(summary['projects'])} repetitions=3"
        )
        return 0
    except CampaignError as error:
        if args.command == "run":
            write_receipt(
                args.output,
                {
                    "schema": SCHEMA,
                    "status": "unavailable",
                    "project": args.project,
                    "repetition": args.repetition,
                    "identity": None,
                    "semantic": None,
                    "execution": {"duration_seconds": 0.0, "resumed": False},
                    "failures": [str(error)],
                },
            )
        elif args.command == "aggregate":
            write_receipt(
                args.output,
                {
                    "schema": SCHEMA,
                    "status": "unavailable",
                    "campaign": args.tier,
                    "projects": {},
                    "failures": [str(error)],
                },
            )
        print(f"REALWORLD_CAMPAIGN_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
