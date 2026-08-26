#!/usr/bin/env python3
"""Produce and verify the exact-head Phase 10 analyzer build authority.

The producer is intentionally narrower than a general build wrapper.  It
accepts only a clean repository at the requested exact HEAD, an absent or
empty dedicated build directory, the pinned LLVM 20 Release/Ninja recipe,
and the immutable evidence image used by Phase 10.  Configure and build are
performed by the same process; a receipt is written only after both commands
and every post-build identity check succeed.

The verifier needs the original source checkout and populated build directory.
It re-derives the source manifest, normalized CMake cache, tool binaries,
analyzer binary/version, logs, receipt sidecar, and the exact inner file set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import run_determinism_qualification as determinism


RECEIPT_SCHEMA = "codeskeptic-analyzer-build-authority-v1"
INNER_RECEIPT_SCHEMA = "codeskeptic-analyzer-build-observation-v1"
TOOLCHAIN_SCHEMA = "codeskeptic-analyzer-build-toolchain-v1"
CONFIGURATION_SCHEMA = "codeskeptic-analyzer-build-configuration-v1"
RUNTIME_SCHEMA = "codeskeptic-analyzer-build-runtime-v1"
LAUNCH_SCHEMA = "codeskeptic-analyzer-build-launch-v1"
PINNED_IMAGE = (
    "localhost/codeskeptic-p10-07-evidence@sha256:"
    "3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
)
PINNED_IMAGE_DIGEST = (
    "sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
)
PINNED_IMAGE_ID = (
    "sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5"
)
VERSION_OVERRIDE = "0.4.9-dev"
ANALYZER_VERSION = f"CodeSkeptic {VERSION_OVERRIDE}"
ANALYZER_RELATIVE = "src/codeskeptic"
BUILD_LOG_NAMES = ("build.log", "configure.log")
LOG_NAMES = ("build.log", "configure.log", "operator.log")
INNER_AUTHORITY_FILES = (
    "SHA256SUMS",
    "build.log",
    "configure.log",
    "receipt.json",
    "receipt.json.sha256",
)
AUTHORITY_FILES = (
    "SHA256SUMS",
    "build.log",
    "configure.log",
    "operator.log",
    "receipt.json",
    "receipt.json.sha256",
)
TOOL_ROLES = ("cmake", "ninja", "c_compiler", "cxx_compiler")
REVISION = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_LOG_BYTES = 64 << 20
MAX_JSON_BYTES = 4 << 20
MAX_BINARY_BYTES = 1 << 30
RUNTIME_VERSION_MAX_BYTES = 1 << 16
RUNTIME_IDENTITY_TIMEOUT_SECONDS = 30.0
RUNTIME_IDENTITY_POLL_SECONDS = 0.025
RUNTIME_IDENTITY_CLEANUP_SECONDS = 0.5
DEFAULT_PODMAN = Path("/usr/bin/podman")
INNER_TOKEN_ENV = "CODESKEPTIC_BUILD_AUTHORITY_LAUNCH_SHA256"
ROOT = Path(__file__).resolve().parents[1]


class BuildAuthorityError(RuntimeError):
    """No accepted build authority can be produced or verified."""


@dataclass(frozen=True)
class _ToolPaths:
    cmake: Path
    ninja: Path
    c_compiler: Path
    cxx_compiler: Path
    llvm_prefix: Path


DEFAULT_TOOLS = _ToolPaths(
    cmake=Path("/usr/bin/cmake"),
    ninja=Path("/usr/bin/ninja"),
    c_compiler=Path("/usr/bin/clang-20"),
    cxx_compiler=Path("/usr/bin/clang++-20"),
    llvm_prefix=Path("/usr/lib/llvm-20"),
)
PINNED_PODMAN_PATH = "/usr/bin/podman"
PODMAN_CONFIG_ROOT = ROOT / "scripts" / "podman-config"
PODMAN_MOUNTS_CONFIG = b"# Intentionally empty.\n"
PODMAN_HOST_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CONTAINER_LAYOUTS = ("legacy", "p10-09")


def _container_paths(container_layout: str) -> dict[str, str]:
    if container_layout == "legacy":
        return {
            "source": "/source",
            "build": "/build",
            "authority": "/authority",
            "stage": "/authority-stage",
        }
    if container_layout == "p10-09":
        return {
            "source": "/authority/source",
            "build": "/authority/build",
            "authority": "/authority/build-authority",
            "stage": "/authority/build-authority",
        }
    raise BuildAuthorityError("container layout is unsupported")


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        target = Path(path).resolve(strict=True)
    except OSError as error:
        raise BuildAuthorityError(
            f"cannot resolve regular file {path}: {error}"
        ) from error
    return _hash_regular(target, MAX_BINARY_BYTES)


def digest_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _kind(path: Path) -> str:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except OSError as error:
        raise BuildAuthorityError(f"cannot inspect {path}: {error}") from error
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


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


def _inspect_regular(
    path: Path, maximum: int, *, collect: bool
) -> tuple[str, bytes | None]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        path_before = os.lstat(path)
        if not stat.S_ISREG(path_before.st_mode):
            raise BuildAuthorityError(f"required regular file is missing: {path}")
        if path_before.st_nlink != 1:
            raise BuildAuthorityError(f"regular file has external hard links: {path}")
        if path_before.st_size > maximum:
            raise BuildAuthorityError(f"file exceeds admitted size: {path}")
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            raise BuildAuthorityError(f"required regular file is missing: {path}")
        if opened_before.st_nlink != 1:
            raise BuildAuthorityError(f"regular file has external hard links: {path}")
        if not _same_file_identity(path_before, opened_before):
            raise BuildAuthorityError(f"regular file changed while opening: {path}")
        if opened_before.st_size > maximum:
            raise BuildAuthorityError(f"file exceeds admitted size: {path}")
        digest = hashlib.sha256()
        retained = bytearray() if collect else None
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise BuildAuthorityError(f"file exceeds admitted size: {path}")
            digest.update(block)
            if retained is not None:
                retained.extend(block)
        opened_after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if (
            not stat.S_ISREG(path_after.st_mode)
            or path_after.st_nlink != 1
        ):
            raise BuildAuthorityError(f"regular file changed while reading: {path}")
        if (
            _stat_fingerprint(opened_before)
            != _stat_fingerprint(opened_after)
            or _stat_fingerprint(path_before)
            != _stat_fingerprint(path_after)
            or not _same_file_identity(opened_after, path_after)
            or total != opened_after.st_size
        ):
            raise BuildAuthorityError(f"regular file changed while reading: {path}")
        return (
            digest.hexdigest(),
            bytes(retained) if retained is not None else None,
        )
    except BuildAuthorityError:
        raise
    except OSError as error:
        raise BuildAuthorityError(f"cannot read {path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_regular(path: Path, maximum: int) -> bytes:
    _digest, raw = _inspect_regular(path, maximum, collect=True)
    assert raw is not None
    return raw


def _hash_regular(path: Path, maximum: int) -> str:
    digest, _raw = _inspect_regular(path, maximum, collect=False)
    return digest


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _strict_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise BuildAuthorityError(f"{label} is malformed: {error}") from error


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise BuildAuthorityError(f"{label} fields are missing, extra, or malformed")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise BuildAuthorityError(f"{label} is not a lowercase SHA-256")
    return value


def _size(value: Any, label: str, maximum: int = MAX_LOG_BYTES) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise BuildAuthorityError(f"{label} is outside the admitted range")
    return value


def _git(repo: Path, arguments: list[str], *, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        env=determinism._git_authority_environment(repo),
    )
    if completed.returncode != 0:
        stderr = completed.stderr
        if isinstance(stderr, bytes):
            message = stderr.decode("utf-8", errors="replace")
        else:
            message = stderr
        raise BuildAuthorityError(
            f"git {' '.join(arguments)} failed: {message[-1000:].strip()}"
        )
    return completed.stdout


def _require_self_contained_checkout(repo: Path) -> None:
    repo = repo.resolve()
    git_dir = repo / ".git"
    if _kind(git_dir) != "directory":
        raise BuildAuthorityError(
            "production source must be a self-contained Git checkout; "
            "linked worktrees are not admitted"
        )
    if _kind(git_dir / "config") != "regular":
        raise BuildAuthorityError("self-contained Git config is missing or unsafe")
    local_config = subprocess.run(
        [
            "git", "config", "--file", str(git_dir / "config"),
            "--no-includes", "--name-only", "--list",
        ],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=determinism._git_authority_environment(repo),
    )
    if local_config.returncode != 0:
        raise BuildAuthorityError("cannot inspect self-contained Git config")
    admitted_local_config = {
        "core.bare",
        "core.filemode",
        "core.ignorecase",
        "core.logallrefupdates",
        "core.precomposeunicode",
        "core.repositoryformatversion",
        "core.symlinks",
    }
    local_names = {
        line.strip().lower()
        for line in local_config.stdout.splitlines()
        if line.strip()
    }
    if not local_names or not local_names <= admitted_local_config:
        raise BuildAuthorityError("self-contained Git config has external authority")
    resolved_git_dir = Path(str(_git(
        repo, ["rev-parse", "--path-format=absolute", "--git-dir"]
    )).strip()).resolve()
    common_dir = Path(str(_git(
        repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"]
    )).strip()).resolve()
    expected = git_dir.resolve()
    if resolved_git_dir != expected or common_dir != expected:
        raise BuildAuthorityError("Git dir/common-dir escapes the source checkout")
    if str(_git(repo, ["rev-parse", "--is-bare-repository"])).strip() != "false":
        raise BuildAuthorityError("production source repository must be non-bare")
    if str(_git(repo, ["rev-parse", "--is-shallow-repository"])).strip() != "false":
        raise BuildAuthorityError("production source repository must not be shallow")
    for path, label in (
        (git_dir / "shallow", "shallow repository marker"),
        (git_dir / "objects" / "info" / "alternates", "object alternates"),
        (git_dir / "info" / "grafts", "legacy graft authority"),
    ):
        if _kind(path) != "missing":
            raise BuildAuthorityError(f"self-contained Git checkout has {label}")
    replacement_refs = str(_git(
        repo, ["for-each-ref", "--format=%(refname)", "refs/replace"]
    )).strip()
    if replacement_refs:
        raise BuildAuthorityError("self-contained Git checkout has replacement refs")
    symbolic = subprocess.run(
        ["git", "symbolic-ref", "-q", "HEAD"],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=determinism._git_authority_environment(repo),
    )
    if symbolic.returncode == 0:
        raise BuildAuthorityError("production source HEAD must be detached")
    if symbolic.returncode != 1:
        raise BuildAuthorityError("cannot establish detached source HEAD")
    tree = _git(
        repo,
        ["ls-tree", "-r", "-z", "--full-tree", "HEAD^{commit}"],
        binary=True,
    )
    assert isinstance(tree, bytes)
    for record in tree.split(b"\x00"):
        if record and record.split(b" ", 1)[0] not in {b"100644", b"100755"}:
            raise BuildAuthorityError(
                "self-contained source contains an unsupported Git tree entry"
            )
    tracked = _git(repo, ["ls-files", "-z", "--cached"], binary=True)
    assert isinstance(tracked, bytes)
    seen: set[Path] = set()
    for raw_relative in tracked.split(b"\x00"):
        if not raw_relative:
            continue
        relative = Path(os.fsdecode(raw_relative))
        if relative.is_absolute() or ".." in relative.parts or relative in seen:
            raise BuildAuthorityError("tracked source path is malformed")
        seen.add(relative)
        cursor = repo
        for index, part in enumerate(relative.parts):
            cursor /= part
            try:
                metadata = cursor.lstat()
            except OSError as error:
                raise BuildAuthorityError(
                    f"cannot inspect tracked source path {relative}: {error}"
                ) from error
            leaf = index == len(relative.parts) - 1
            if stat.S_ISLNK(metadata.st_mode):
                raise BuildAuthorityError(
                    f"tracked source path traverses a symbolic link: {relative}"
                )
            if leaf:
                if not stat.S_ISREG(metadata.st_mode):
                    raise BuildAuthorityError(
                        f"tracked source is not a regular file: {relative}"
                    )
                if metadata.st_nlink != 1:
                    raise BuildAuthorityError(
                        f"tracked source has external hard links: {relative}"
                    )
            elif not stat.S_ISDIR(metadata.st_mode):
                raise BuildAuthorityError(
                    f"tracked source parent is not a directory: {relative}"
                )
    if not seen:
        raise BuildAuthorityError("self-contained source has no tracked files")
    _git(repo, ["fsck", "--connectivity-only", "--no-dangling", "HEAD^{commit}"])


def _source_identity(repo: Path, revision: str) -> dict[str, Any]:
    repo = repo.resolve()
    if _kind(repo) != "directory":
        raise BuildAuthorityError("source repository is missing")
    _require_self_contained_checkout(repo)
    if REVISION.fullmatch(revision) is None:
        raise BuildAuthorityError("source revision must be an exact lowercase commit")
    top = str(_git(repo, ["rev-parse", "--show-toplevel"])).strip()
    if Path(top).resolve() != repo:
        raise BuildAuthorityError("source path is not the repository root")
    head = str(_git(repo, ["rev-parse", "HEAD^{commit}"])).strip()
    resolved = str(_git(repo, ["rev-parse", f"{revision}^{{commit}}"])).strip()
    if head != revision or resolved != revision:
        raise BuildAuthorityError("source repository is not at the exact revision")
    dirty = _git(
        repo,
        [
            "status", "--porcelain=v1", "-z", "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        binary=True,
    )
    if dirty:
        raise BuildAuthorityError("source repository is dirty")
    try:
        recorded = determinism.source_manifest_at_revision(repo, revision)
        current = determinism.source_manifest(repo)
    except determinism.QualificationError as error:
        raise BuildAuthorityError(f"cannot establish source manifest: {error}") from error
    if current != recorded:
        raise BuildAuthorityError("source bytes differ from the exact revision")
    return recorded


def _verify_source_identity(repo: Path, revision: str) -> dict[str, Any]:
    """Verify retained S from a clean, source-equivalent descendant HEAD."""
    repo = repo.resolve()
    if _kind(repo) != "directory":
        raise BuildAuthorityError("source repository is missing")
    _require_self_contained_checkout(repo)
    if REVISION.fullmatch(revision) is None:
        raise BuildAuthorityError("source revision must be an exact lowercase commit")
    top = str(_git(repo, ["rev-parse", "--show-toplevel"])).strip()
    if Path(top).resolve() != repo:
        raise BuildAuthorityError("source path is not the repository root")
    dirty = _git(
        repo,
        [
            "status", "--porcelain=v1", "-z", "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        binary=True,
    )
    if dirty:
        raise BuildAuthorityError("source repository is dirty")
    try:
        recorded = determinism.source_manifest_at_revision(repo, revision)
        determinism._verify_source_authority(
            recorded, repo, "analyzer build authority"
        )
    except determinism.QualificationError as error:
        raise BuildAuthorityError(f"source authority drift: {error}") from error
    return recorded


def _paths_are_separate(source: Path, build: Path, authority: Path) -> None:
    source = source.resolve()
    build = build.resolve(strict=False)
    authority = authority.resolve(strict=False)
    if len({source, build, authority}) != 3:
        raise BuildAuthorityError("source, build, and authority paths must be distinct")
    for candidate, label in ((build, "build"), (authority, "authority")):
        if source == candidate or source in candidate.parents:
            raise BuildAuthorityError(f"{label} path must be outside the source tree")
    if build in authority.parents or authority in build.parents:
        raise BuildAuthorityError("build and authority paths must not be nested")


def _require_empty_directory(path: Path, label: str) -> None:
    kind = _kind(path)
    if kind == "missing":
        try:
            path.mkdir(parents=True)
        except OSError as error:
            raise BuildAuthorityError(f"cannot create {label} directory: {error}") from error
        return
    if kind != "directory":
        raise BuildAuthorityError(f"{label} path is not a directory")
    try:
        if next(path.iterdir(), None) is not None:
            raise BuildAuthorityError(f"{label} directory must be empty")
    except OSError as error:
        raise BuildAuthorityError(f"cannot inspect {label} directory: {error}") from error


def _tool_path_map(tools: _ToolPaths) -> dict[str, Path]:
    return {
        "cmake": tools.cmake,
        "ninja": tools.ninja,
        "c_compiler": tools.c_compiler,
        "cxx_compiler": tools.cxx_compiler,
    }


def _runtime_process_group_exists(process_group: int) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_for_runtime_process_group_exit(
    process: subprocess.Popen[bytes], timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        process.poll()
        if not _runtime_process_group_exists(process.pid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _terminate_runtime_identity_process(
    process: subprocess.Popen[bytes], label: str,
) -> None:
    """Terminate one identity probe and its process group, then reap it."""
    group_failure: str | None = None
    if os.name == "posix":
        term_error: OSError | None = None
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as error:
            term_error = error
        if not _wait_for_runtime_process_group_exit(
            process, RUNTIME_IDENTITY_CLEANUP_SECONDS
        ):
            kill_error: OSError | None = None
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                kill_error = error
            if not _wait_for_runtime_process_group_exit(
                process, RUNTIME_IDENTITY_CLEANUP_SECONDS
            ):
                signal_error = kill_error or term_error
                detail = f": {signal_error}" if signal_error is not None else ""
                group_failure = "process group remained after SIGKILL" + detail
    elif process.poll() is None:
        process.terminate()

    if process.poll() is None:
        try:
            process.wait(timeout=RUNTIME_IDENTITY_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=RUNTIME_IDENTITY_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired as error:
                raise BuildAuthorityError(
                    f"{label} cleanup failed: process could not be reaped"
                ) from error
    else:
        # ``poll`` reaps the direct child on POSIX.  ``wait`` also makes the
        # reaping contract explicit and is harmless after a completed poll.
        process.wait()
    if group_failure is not None:
        raise BuildAuthorityError(f"{label} cleanup failed: {group_failure}")


def _run_bounded_runtime_identity(
    command: list[str], environment: dict[str, str], label: str,
    *, stdout_limit: int, stderr_limit: int,
    stderr_to_stdout: bool = False,
    timeout_seconds: float | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a runtime identity probe with closed input and bounded output."""
    if timeout_seconds is None:
        timeout_seconds = RUNTIME_IDENTITY_TIMEOUT_SECONDS
    if (
        not command
        or stdout_limit <= 0
        or stderr_limit <= 0
        or timeout_seconds <= 0
    ):
        raise BuildAuthorityError(f"{label} bounded execution contract is invalid")

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    failure: str | None = None
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=(subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE),
            env=dict(environment),
            start_new_session=(os.name == "posix"),
            bufsize=0,
        )
        if process.stdout is None:
            raise BuildAuthorityError(f"{label} stdout pipe is unavailable")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        if not stderr_to_stdout:
            if process.stderr is None:
                raise BuildAuthorityError(f"{label} stderr pipe is unavailable")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")

        while selector.get_map():
            remaining = timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                failure = f"{label} timed out"
                break
            events = selector.select(
                min(RUNTIME_IDENTITY_POLL_SECONDS, remaining)
            )
            for key, _mask in events:
                stream_name = key.data
                remaining_bytes = limits[stream_name] - len(captured[stream_name])
                block = os.read(key.fd, min(65536, remaining_bytes + 1))
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(block) > remaining_bytes:
                    failure = f"{label} output exceeds size limit"
                    break
                captured[stream_name].extend(block)
            if failure is not None:
                break

        if failure is None:
            remaining = timeout_seconds - (time.monotonic() - started)
            try:
                process.wait(timeout=max(0.0, remaining))
            except subprocess.TimeoutExpired:
                failure = f"{label} timed out"
            if (
                failure is None
                and os.name == "posix"
                and _runtime_process_group_exists(process.pid)
            ):
                failure = f"{label} left live descendants"

        if failure is not None:
            try:
                _terminate_runtime_identity_process(process, label)
            except BuildAuthorityError as cleanup_error:
                raise BuildAuthorityError(
                    f"{failure}; {cleanup_error}"
                ) from cleanup_error
            raise BuildAuthorityError(failure)

        return subprocess.CompletedProcess(
            command,
            process.returncode,
            bytes(captured["stdout"]),
            bytes(captured["stderr"]),
        )
    except BaseException as error:
        if (
            process is not None
            and (
                process.poll() is None
                or (
                    os.name == "posix"
                    and _runtime_process_group_exists(process.pid)
                )
            )
        ):
            try:
                _terminate_runtime_identity_process(process, label)
            except BaseException as cleanup_error:
                raise BuildAuthorityError(
                    f"{label} interruption cleanup failed: {cleanup_error}"
                ) from error
        if isinstance(error, (BuildAuthorityError, KeyboardInterrupt, SystemExit)):
            raise
        raise BuildAuthorityError(f"cannot execute {label}: {error}") from error
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def _tool_record(
    path: Path,
    label: str,
    *,
    environment: dict[str, str] | None = None,
) -> dict[str, str]:
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise BuildAuthorityError(
            f"{label} tool is missing or not regular: {error}"
        ) from error
    # The pinned LLVM image exposes clang-20 and clang++-20 as symlinks.  The
    # command spelling is part of the recipe, while the followed executable
    # bytes and version are the tool identity.
    if not stat.S_ISREG(mode):
        raise BuildAuthorityError(f"{label} tool is missing or not regular")
    try:
        target_before = path.resolve(strict=True)
        digest_before = _hash_regular(target_before, MAX_BINARY_BYTES)
        if environment is None:
            identity = determinism._tool_identity(path, label)
        else:
            completed = _run_bounded_runtime_identity(
                [str(path), "--version"],
                environment,
                f"{label} identity",
                stdout_limit=RUNTIME_VERSION_MAX_BYTES,
                stderr_limit=RUNTIME_VERSION_MAX_BYTES,
                stderr_to_stdout=True,
            )
            raw = completed.stdout
            if (
                completed.returncode != 0
                or not raw
                or len(raw) > RUNTIME_VERSION_MAX_BYTES
            ):
                raise BuildAuthorityError(f"cannot capture {label} identity")
            version = raw.decode("utf-8").strip()
            if not version or "\x00" in version:
                raise BuildAuthorityError(f"{label} identity is malformed")
            identity = {"sha256": digest_before, "version": version}
        target_after = path.resolve(strict=True)
        digest_after = _hash_regular(target_after, MAX_BINARY_BYTES)
        if (
            target_after != target_before
            or digest_after != digest_before
            or identity["sha256"] != digest_before
        ):
            raise BuildAuthorityError(f"{label} tool changed while deriving identity")
    except (determinism.QualificationError, OSError, UnicodeDecodeError) as error:
        raise BuildAuthorityError(f"cannot establish {label} identity: {error}") from error
    return {
        "path": str(path.absolute()),
        "sha256": identity["sha256"],
        "version": identity["version"],
    }


def _toolchain_identity(tools: _ToolPaths) -> dict[str, Any]:
    if _kind(tools.llvm_prefix) != "directory":
        raise BuildAuthorityError("LLVM 20 prefix is missing or not a directory")
    records = {
        role: _tool_record(path, role.replace("_", " "))
        for role, path in _tool_path_map(tools).items()
    }
    return {
        "schema": TOOLCHAIN_SCHEMA,
        "tools": records,
        "identity_sha256": digest_json(records),
    }


def _normalized_container_argv(
    mode: str, container_layout: str = "legacy",
) -> list[str]:
    if mode not in {"produce", "verify"}:
        raise BuildAuthorityError("container launch mode is unsupported")
    paths = _container_paths(container_layout)
    common = [
        "$PODMAN",
        "--cgroup-manager=cgroupfs",
        "--conmon=/usr/bin/conmon",
        "--events-backend=none",
        "--hooks-dir=/usr/share/empty",
        "--runtime=/usr/bin/crun",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--http-proxy=false",
        "--env-host=false",
        "--image-volume=ignore",
        "--read-only",
        "--cap-drop=all",
        "--security-opt",
        "label=disable",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,size=4g,mode=1777",
        "--workdir",
        paths["source"],
        "-e",
        "GIT_CONFIG_COUNT=1",
        "-e",
        "GIT_CONFIG_KEY_0=safe.directory",
        "-e",
        f"GIT_CONFIG_VALUE_0={paths['source']}",
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
        "XDG_CACHE_HOME=/tmp/xdg-cache",
        "-v",
        f"$SOURCE:{paths['source']}:ro",
        "-v",
        f"$BUILD:{paths['build']}:{'rw' if mode == 'produce' else 'ro'}",
    ]
    if mode == "produce":
        common.extend([
            "-e",
            f"{INNER_TOKEN_ENV}=$LAUNCH_SHA256",
            "-v",
            f"$STAGE:{paths['stage']}:rw",
        ])
        inner_arguments = [
            "_inner-produce",
            "--source", paths["source"],
            "--revision", "$REVISION",
            "--build-dir", paths["build"],
            "--output", f"{paths['stage']}/inner",
            "--launch-authority", f"{paths['stage']}/launch-authority.json",
        ]
    else:
        common.extend(["-v", f"$AUTHORITY:{paths['authority']}:ro"])
        inner_arguments = [
            "_inner-verify",
            "--source", paths["source"],
            "--build-dir", paths["build"],
            "--authority", paths["authority"],
        ]
    return [
        *common,
        PINNED_IMAGE,
        "/usr/bin/python3",
        f"{paths['source']}/scripts/analyzer_build_authority.py",
        *inner_arguments,
    ]


def _container_layout_from_normalized_argv(value: Any) -> str:
    matches = [
        container_layout
        for container_layout in CONTAINER_LAYOUTS
        if value == _normalized_container_argv("produce", container_layout)
    ]
    if len(matches) != 1:
        raise BuildAuthorityError(
            "runtime normalized Podman argv does not match one exact container layout"
        )
    return matches[0]


def _container_layout_from_runtime(value: Any) -> str:
    if not isinstance(value, dict) or "normalized_argv" not in value:
        raise BuildAuthorityError("runtime container layout evidence is missing")
    return _container_layout_from_normalized_argv(value["normalized_argv"])


def _expand_argv(tokens: list[str], bindings: dict[str, str]) -> list[str]:
    expanded: list[str] = []
    for token in tokens:
        value = token
        for marker, replacement in bindings.items():
            value = value.replace(marker, replacement)
        if "$" in value:
            raise BuildAuthorityError(f"unbound container argv marker: {value}")
        expanded.append(value)
    return expanded


def _podman_environment() -> dict[str, str]:
    """Return the exact host environment admitted to every Podman process."""
    if os.name != "posix":
        raise BuildAuthorityError("Podman authority requires a POSIX host")
    try:
        import pwd

        account = pwd.getpwuid(os.getuid())
    except (ImportError, KeyError, OSError) as error:
        raise BuildAuthorityError("cannot establish Podman host account") from error
    config_root = PODMAN_CONFIG_ROOT
    containers = config_root / "containers"
    mounts = containers / "mounts.conf"
    if (
        _kind(config_root) != "directory"
        or _kind(containers) != "directory"
        or sorted(path.name for path in config_root.iterdir()) != ["containers"]
        or sorted(path.name for path in containers.iterdir()) != ["mounts.conf"]
        or _read_regular(mounts, 1024) != PODMAN_MOUNTS_CONFIG
    ):
        raise BuildAuthorityError("closed Podman configuration tree drift")
    home = Path(account.pw_dir)
    runtime = Path("/run/user") / str(os.getuid())
    if not home.is_absolute() or not runtime.is_absolute():
        raise BuildAuthorityError("Podman host account paths are not absolute")
    return {
        "CONTAINERS_CONF": os.devnull,
        "CONTAINERS_CONF_OVERRIDE": os.devnull,
        "CONTAINERS_POLICY": "/etc/containers/policy.json",
        "CONTAINERS_REGISTRIES_CONF": os.devnull,
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": account.pw_name,
        "PATH": PODMAN_HOST_PATH,
        "TMPDIR": "/tmp",
        "TZ": "UTC",
        "USER": account.pw_name,
        "XDG_CONFIG_HOME": str(config_root),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_RUNTIME_DIR": str(runtime),
    }


def _runtime_authority(
    podman: Path = DEFAULT_PODMAN,
    *,
    container_layout: str = "legacy",
) -> dict[str, Any]:
    _container_paths(container_layout)
    environment = _podman_environment()
    podman_record = _tool_record(podman, "Podman", environment=environment)
    command = [
        str(podman),
        "image",
        "inspect",
        "--format",
        "{{json .}}",
        PINNED_IMAGE,
    ]
    completed = _run_bounded_runtime_identity(
        command,
        environment,
        "pinned image inspect",
        stdout_limit=MAX_JSON_BYTES,
        stderr_limit=MAX_JSON_BYTES,
    )
    if completed.returncode != 0 or not completed.stdout:
        message = completed.stderr.decode("utf-8", errors="replace")
        raise BuildAuthorityError(
            f"pinned image inspect failed: {message[-1000:].strip()}"
        )
    inspected = _strict_json(completed.stdout, "Podman image inspect")
    if not isinstance(inspected, dict):
        raise BuildAuthorityError("Podman image inspect is not an object")
    image_id = inspected.get("Id")
    if isinstance(image_id, str) and not image_id.startswith("sha256:"):
        image_id = f"sha256:{image_id}"
    repo_digests = inspected.get("RepoDigests")
    if (
        inspected.get("Digest") != PINNED_IMAGE_DIGEST
        or image_id != PINNED_IMAGE_ID
        or not isinstance(repo_digests, list)
        or PINNED_IMAGE not in repo_digests
    ):
        raise BuildAuthorityError("pinned image digest or image ID drift")
    normalized = _normalized_container_argv("produce", container_layout)
    runtime = {
        "schema": RUNTIME_SCHEMA,
        "image": {
            "reference": PINNED_IMAGE,
            "digest": PINNED_IMAGE_DIGEST,
            "id": PINNED_IMAGE_ID,
        },
        "podman": podman_record,
        "normalized_argv": normalized,
        "normalized_argv_sha256": digest_json(normalized),
    }
    _validate_runtime(runtime, podman)
    return runtime


def _validate_runtime(value: Any, podman: Path = DEFAULT_PODMAN) -> dict[str, Any]:
    payload = _object(
        value,
        {
            "schema", "image", "podman", "normalized_argv",
            "normalized_argv_sha256",
        },
        "runtime",
    )
    if payload["schema"] != RUNTIME_SCHEMA:
        raise BuildAuthorityError("runtime schema drift")
    image = _object(
        payload["image"], {"reference", "digest", "id"}, "runtime.image"
    )
    if image != {
        "reference": PINNED_IMAGE,
        "digest": PINNED_IMAGE_DIGEST,
        "id": PINNED_IMAGE_ID,
    }:
        raise BuildAuthorityError("runtime image identity drift")
    record = _object(
        payload["podman"], {"path", "sha256", "version"}, "runtime.podman"
    )
    # A retained authority is produced by the pinned Linux image/runtime but
    # its structural contract is also checked by native Windows CI.  pathlib
    # would otherwise turn ``/usr/bin/podman`` into a drive-qualified Windows
    # path during that read-only check.  Preserve the pinned POSIX spelling;
    # caller-selected fixture/runtime paths remain resolved normally.
    expected_podman_path = (
        PINNED_PODMAN_PATH
        if podman.as_posix() == PINNED_PODMAN_PATH
        else str(podman.absolute())
    )
    if record["path"] != expected_podman_path:
        raise BuildAuthorityError("runtime Podman path drift")
    _hash(record["sha256"], "runtime Podman hash")
    if (
        not isinstance(record["version"], str)
        or not record["version"]
        or "\x00" in record["version"]
    ):
        raise BuildAuthorityError("runtime Podman version is malformed")
    normalized = payload["normalized_argv"]
    _container_layout_from_normalized_argv(normalized)
    if (
        _hash(payload["normalized_argv_sha256"], "runtime argv identity")
        != digest_json(normalized)
    ):
        raise BuildAuthorityError("runtime normalized argv digest mismatch")
    return payload


def _normalized_recipe() -> dict[str, Any]:
    return {
        "configure": [
            "$CMAKE", "-S", "$SOURCE", "-B", "$BUILD", "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_PREFIX_PATH=$LLVM20_PREFIX",
            "-DCMAKE_MAKE_PROGRAM=$NINJA",
            "-DCMAKE_C_COMPILER=$CLANG20",
            "-DCMAKE_CXX_COMPILER=$CLANGXX20",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DCODESKEPTIC_BUILD_TESTS=OFF",
            "-DCODESKEPTIC_BUILD_FUZZERS=OFF",
            "-DCODESKEPTIC_SANITIZER=none",
        ],
        "build": [
            "$CMAKE", "--build", "$BUILD", "--target", "codeskeptic",
            "--parallel", "2",
        ],
        "environment": {
            "CC": "$CLANG20",
            "CXX": "$CLANGXX20",
            "CODESKEPTIC_VERSION_OVERRIDE": VERSION_OVERRIDE,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": "$BUILD/.home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "$LLVM20_PREFIX/bin:/usr/bin:/bin",
            "TZ": "UTC",
            "XDG_CACHE_HOME": "$BUILD/.xdg-cache",
        },
    }


def _commands(
    source: Path, build: Path, tools: _ToolPaths,
) -> tuple[list[str], list[str]]:
    bindings = {
        "$CMAKE": str(tools.cmake),
        "$SOURCE": str(source),
        "$BUILD": str(build),
        "$LLVM20_PREFIX": str(tools.llvm_prefix),
        "$NINJA": str(tools.ninja),
        "$CLANG20": str(tools.c_compiler),
        "$CLANGXX20": str(tools.cxx_compiler),
    }
    recipe = _normalized_recipe()
    return (
        _expand_argv(recipe["configure"], bindings),
        _expand_argv(recipe["build"], bindings),
    )


def _build_environment(build: Path, tools: _ToolPaths) -> dict[str, str]:
    home = build / ".home"
    cache = build / ".xdg-cache"
    home.mkdir()
    cache.mkdir()
    bindings = {
        "$BUILD": str(build),
        "$LLVM20_PREFIX": str(tools.llvm_prefix),
        "$CLANG20": str(tools.c_compiler),
        "$CLANGXX20": str(tools.cxx_compiler),
    }
    environment: dict[str, str] = {}
    for name, normalized in _normalized_recipe()["environment"].items():
        expanded = _expand_argv([normalized], bindings)[0]
        environment[name] = expanded
    if environment["HOME"] != str(home) or environment["XDG_CACHE_HOME"] != str(cache):
        raise BuildAuthorityError("normalized build environment path drift")
    return environment


def _run_logged(command: list[str], cwd: Path, environment: dict[str, str], log: Path) -> None:
    try:
        with log.open("xb") as stream:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                check=False,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
    except OSError as error:
        raise BuildAuthorityError(f"cannot execute build command: {error}") from error
    if completed.returncode != 0:
        raise BuildAuthorityError(
            f"build command failed with exit {completed.returncode}: {command[0]}"
        )
    if _kind(log) != "regular" or not 0 < log.stat().st_size <= MAX_LOG_BYTES:
        raise BuildAuthorityError("build command log is empty or oversized")


def _cache_values(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildAuthorityError("CMake cache is not UTF-8") from error
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith(("#", "//")):
            continue
        if "=" not in line or ":" not in line.split("=", 1)[0]:
            raise BuildAuthorityError(
                f"malformed CMake cache entry at line {line_number}"
            )
        left, value = line.split("=", 1)
        key, _entry_type = left.split(":", 1)
        if not key or key in values or "\x00" in value:
            raise BuildAuthorityError("CMake cache contains a malformed duplicate")
        values[key] = value
    return values


def _same_path(recorded: str | None, expected: Path) -> bool:
    if not recorded:
        return False
    path = Path(recorded)
    return path.is_absolute() and path.resolve() == expected.resolve()


def _configuration_identity(
    build: Path, source: Path, tools: _ToolPaths,
) -> dict[str, Any]:
    cache = build / "CMakeCache.txt"
    compile_commands = build / "compile_commands.json"
    cache_raw = _read_regular(cache, MAX_JSON_BYTES)
    values = _cache_values(cache_raw)
    expected_values = {
        "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        "CMAKE_GENERATOR": "Ninja",
        "CMAKE_PREFIX_PATH": str(tools.llvm_prefix),
        "CODESKEPTIC_BUILD_FUZZERS": "OFF",
        "CODESKEPTIC_BUILD_TESTS": "OFF",
        "CODESKEPTIC_SANITIZER": "none",
    }
    for key, expected in expected_values.items():
        if values.get(key) != expected:
            raise BuildAuthorityError(f"CMake cache recipe drift for {key}")
    for key, expected in {
        "CMAKE_COMMAND": tools.cmake,
        "CMAKE_MAKE_PROGRAM": tools.ninja,
        "CMAKE_C_COMPILER": tools.c_compiler,
        "CMAKE_CXX_COMPILER": tools.cxx_compiler,
        "CMAKE_HOME_DIRECTORY": source,
        "CMAKE_CACHEFILE_DIR": build,
    }.items():
        if not _same_path(values.get(key), expected):
            raise BuildAuthorityError(f"CMake cache path drift for {key}")
    try:
        normalized = determinism._build_toolchain_identity(
            build,
            source,
            tools.cmake,
            tools.ninja,
            tools.c_compiler,
            tools.cxx_compiler,
        )
    except determinism.QualificationError as error:
        raise BuildAuthorityError(f"cannot normalize CMake cache: {error}") from error
    if _read_regular(cache, MAX_JSON_BYTES) != cache_raw:
        raise BuildAuthorityError("CMake cache changed while deriving identity")
    compile_raw = _read_regular(compile_commands, MAX_JSON_BYTES)
    compile_payload = _strict_json(compile_raw, "compile_commands.json")
    if not isinstance(compile_payload, list) or not compile_payload:
        raise BuildAuthorityError("compile_commands.json is empty or malformed")
    material = {
        "cmake_cache_schema": normalized["cmake_cache_schema"],
        "cmake_cache_canonical_sha256": normalized[
            "cmake_cache_canonical_sha256"
        ],
        "cmake_cache_sha256": sha256_bytes(cache_raw),
        "cmake_cache_size": len(cache_raw),
        "compile_commands_sha256": sha256_bytes(compile_raw),
        "compile_commands_size": len(compile_raw),
    }
    return {
        "schema": CONFIGURATION_SCHEMA,
        **material,
        "identity_sha256": digest_json(material),
    }


def _analyzer_identity(build: Path) -> dict[str, str]:
    path = build / ANALYZER_RELATIVE
    if _kind(path) != "regular":
        raise BuildAuthorityError("built analyzer is missing or not regular")
    if os.name == "posix" and not os.access(path, os.X_OK):
        raise BuildAuthorityError("built analyzer is not executable")
    record = _tool_record(path, "analyzer")
    if record["version"] != ANALYZER_VERSION:
        raise BuildAuthorityError("built analyzer version is not the pinned identity")
    return {
        "path": ANALYZER_RELATIVE,
        "sha256": record["sha256"],
        "version": record["version"],
    }


def _log_identity(path: Path, name: str) -> dict[str, Any]:
    raw = _read_regular(path, MAX_LOG_BYTES)
    if not raw:
        raise BuildAuthorityError(f"{name} is empty")
    return {"path": name, "sha256": sha256_bytes(raw), "size": len(raw)}


def _build_identity_material(receipt: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "image", "source", "recipe", "configuration", "toolchain",
        "analyzer", "logs",
    ]
    if "runtime" in receipt:
        fields.append("runtime")
    return {field: receipt[field] for field in fields}


def _inner_build_identity_from_final(receipt: dict[str, Any]) -> str:
    material = {
        field: receipt[field]
        for field in (
            "image", "source", "recipe", "configuration", "toolchain",
            "analyzer",
        )
    }
    material["logs"] = {
        name: receipt["logs"][name] for name in BUILD_LOG_NAMES
    }
    return digest_json(material)


def _expected_operator_log(
    inner_build_identity: str, container_layout: str = "legacy",
) -> bytes:
    _hash(inner_build_identity, "inner build identity")
    inner_output = f"{_container_paths(container_layout)['stage']}/inner"
    return (
        "CODESKEPTIC_BUILD_OBSERVATION_COMPLETE "
        f"{inner_output} {inner_build_identity}\n"
    ).encode("utf-8")


def _validate_toolchain(
    value: Any, tools: _ToolPaths | None,
) -> dict[str, Any]:
    payload = _object(
        value, {"schema", "tools", "identity_sha256"}, "toolchain"
    )
    if payload["schema"] != TOOLCHAIN_SCHEMA:
        raise BuildAuthorityError("toolchain schema drift")
    records = _object(payload["tools"], set(TOOL_ROLES), "toolchain.tools")
    expected_paths = _tool_path_map(tools) if tools is not None else None
    for role in TOOL_ROLES:
        record = _object(
            records[role], {"path", "sha256", "version"}, f"toolchain.{role}"
        )
        path_value = record["path"]
        if tools is None:
            path_valid = _is_canonical_posix_absolute_path(path_value)
        else:
            path_valid = (
                isinstance(path_value, str)
                and "\x00" not in path_value
                and Path(path_value).is_absolute()
            )
        if not path_valid:
            raise BuildAuthorityError(f"toolchain {role} path is malformed")
        if (
            expected_paths is not None
            and record["path"] != str(expected_paths[role].absolute())
        ):
            raise BuildAuthorityError(f"toolchain {role} path drift")
        _hash(record["sha256"], f"toolchain {role} hash")
        if (
            not isinstance(record["version"], str)
            or not record["version"]
            or "\x00" in record["version"]
            or len(record["version"].encode("utf-8")) > 65536
        ):
            raise BuildAuthorityError(f"toolchain {role} version is malformed")
    if _hash(payload["identity_sha256"], "toolchain identity") != digest_json(records):
        raise BuildAuthorityError("toolchain identity digest mismatch")
    return payload


def _is_canonical_posix_absolute_path(value: Any) -> bool:
    """Validate retained Linux tool spellings on every host platform."""
    if not isinstance(value, str) or "\x00" in value or value.startswith("//"):
        return False
    path = PurePosixPath(value)
    return (
        path.is_absolute()
        and str(path) == value
        and ".." not in path.parts
        and "." not in path.parts
    )


def _validate_configuration(value: Any) -> dict[str, Any]:
    fields = {
        "schema", "cmake_cache_schema", "cmake_cache_canonical_sha256",
        "cmake_cache_sha256", "cmake_cache_size",
        "compile_commands_sha256", "compile_commands_size", "identity_sha256",
    }
    payload = _object(value, fields, "configuration")
    if payload["schema"] != CONFIGURATION_SCHEMA:
        raise BuildAuthorityError("configuration schema drift")
    if payload["cmake_cache_schema"] != determinism.CMAKE_CACHE_IDENTITY_SCHEMA:
        raise BuildAuthorityError("CMake cache identity schema drift")
    material = {
        field: payload[field]
        for field in fields - {"schema", "identity_sha256"}
    }
    for field in (
        "cmake_cache_canonical_sha256", "cmake_cache_sha256",
        "compile_commands_sha256",
    ):
        _hash(payload[field], f"configuration {field}")
    _size(payload["cmake_cache_size"], "CMake cache size", MAX_JSON_BYTES)
    _size(
        payload["compile_commands_size"],
        "compile_commands.json size",
        MAX_JSON_BYTES,
    )
    if _hash(payload["identity_sha256"], "configuration identity") != digest_json(material):
        raise BuildAuthorityError("configuration identity digest mismatch")
    return payload


def _validate_receipt(
    receipt: Any,
    tools: _ToolPaths | None,
    *,
    final: bool,
    podman: Path = DEFAULT_PODMAN,
) -> dict[str, Any]:
    fields = {
        "schema", "status", "image", "source", "recipe", "configuration",
        "toolchain", "analyzer", "logs", "build_identity_sha256",
    }
    if final:
        fields.add("runtime")
    payload = _object(receipt, fields, "receipt")
    expected_schema = RECEIPT_SCHEMA if final else INNER_RECEIPT_SCHEMA
    expected_status = "accepted" if final else "observed"
    if payload["schema"] != expected_schema:
        raise BuildAuthorityError("receipt schema drift")
    if payload["status"] != expected_status:
        raise BuildAuthorityError("build authority status drift")
    if payload["image"] != PINNED_IMAGE:
        raise BuildAuthorityError("build image digest drift")
    if payload["recipe"] != _normalized_recipe():
        raise BuildAuthorityError("normalized build recipe drift")
    source = _object(
        payload["source"], {"revision", "manifest_sha256", "file_count"},
        "source",
    )
    if not isinstance(source["revision"], str) or REVISION.fullmatch(source["revision"]) is None:
        raise BuildAuthorityError("source revision is malformed")
    _hash(source["manifest_sha256"], "source manifest")
    if type(source["file_count"]) is not int or source["file_count"] <= 0:
        raise BuildAuthorityError("source file count is malformed")
    _validate_configuration(payload["configuration"])
    _validate_toolchain(payload["toolchain"], tools)
    if final:
        _validate_runtime(payload["runtime"], podman)
    analyzer = _object(
        payload["analyzer"], {"path", "sha256", "version"}, "analyzer"
    )
    if analyzer["path"] != ANALYZER_RELATIVE:
        raise BuildAuthorityError("analyzer path drift")
    _hash(analyzer["sha256"], "analyzer hash")
    if analyzer["version"] != ANALYZER_VERSION:
        raise BuildAuthorityError("analyzer version drift")
    admitted_logs = LOG_NAMES if final else BUILD_LOG_NAMES
    logs = _object(payload["logs"], set(admitted_logs), "logs")
    for name in admitted_logs:
        record = _object(logs[name], {"path", "sha256", "size"}, f"logs.{name}")
        if record["path"] != name:
            raise BuildAuthorityError(f"{name} path drift")
        _hash(record["sha256"], f"{name} hash")
        _size(record["size"], f"{name} size")
        if record["size"] == 0:
            raise BuildAuthorityError(f"{name} is empty")
    expected_build = digest_json(_build_identity_material(payload))
    if _hash(payload["build_identity_sha256"], "build identity") != expected_build:
        raise BuildAuthorityError("build identity digest mismatch")
    return payload


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o644,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _seal_artifacts(
    receipt: dict[str, Any], artifacts: dict[str, bytes],
) -> dict[str, bytes]:
    receipt_raw = canonical_json(receipt)
    files = {
        **artifacts,
        "receipt.json": receipt_raw,
        "receipt.json.sha256": (
            f"{sha256_bytes(receipt_raw)}  receipt.json\n".encode("utf-8")
        ),
    }
    files["SHA256SUMS"] = b"".join(
        f"{sha256_bytes(files[name])}  {name}\n".encode("utf-8")
        for name in sorted(files)
    )
    return files


def _bundle_bytes(receipt: dict[str, Any], build: Path) -> dict[str, bytes]:
    return _seal_artifacts(receipt, {
        "build.log": _read_regular(build / "authority-build.log", MAX_LOG_BYTES),
        "configure.log": _read_regular(
            build / "authority-configure.log", MAX_LOG_BYTES
        ),
    })


def _write_bundle(
    authority: Path, files: dict[str, bytes], expected_files: tuple[str, ...],
) -> None:
    if set(files) != set(expected_files):
        raise BuildAuthorityError("authority bundle file set is not exact")
    parent = authority.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise BuildAuthorityError(f"cannot create authority parent: {error}") from error
    staging = Path(tempfile.mkdtemp(prefix=f".{authority.name}.tmp-", dir=parent))
    try:
        for name in expected_files:
            _write_new(staging / name, files[name])
        if _kind(authority) == "directory":
            if next(authority.iterdir(), None) is not None:
                raise BuildAuthorityError("authority output is no longer empty")
            authority.rmdir()
        elif _kind(authority) != "missing":
            raise BuildAuthorityError("authority output is no longer available")
        staging.rename(authority)
    except Exception:
        if _kind(staging) == "directory":
            shutil.rmtree(staging)
        raise


def _produce_with_tools(
    source: Path,
    revision: str,
    build: Path,
    authority: Path,
    tools: _ToolPaths,
) -> dict[str, Any]:
    if os.name != "posix":
        raise BuildAuthorityError("production build authority requires POSIX")
    source = source.resolve()
    build = build.absolute()
    authority = authority.absolute()
    _paths_are_separate(source, build, authority)
    source_before = _source_identity(source, revision)
    _require_empty_directory(build, "dedicated build")
    _require_empty_directory(authority, "authority output")
    toolchain_before = _toolchain_identity(tools)
    configure, build_command = _commands(source, build, tools)
    environment = _build_environment(build, tools)
    _run_logged(
        configure,
        source,
        environment,
        build / "authority-configure.log",
    )
    _run_logged(
        build_command,
        source,
        environment,
        build / "authority-build.log",
    )
    source_after = _source_identity(source, revision)
    if source_after != source_before:
        raise BuildAuthorityError("source identity changed during the build")
    toolchain_after = _toolchain_identity(tools)
    if toolchain_after != toolchain_before:
        raise BuildAuthorityError("toolchain identity changed during the build")
    configuration = _configuration_identity(build, source, tools)
    analyzer = _analyzer_identity(build)
    logs = {
        "build.log": _log_identity(build / "authority-build.log", "build.log"),
        "configure.log": _log_identity(
            build / "authority-configure.log", "configure.log"
        ),
    }
    receipt: dict[str, Any] = {
        "schema": INNER_RECEIPT_SCHEMA,
        "status": "observed",
        "image": PINNED_IMAGE,
        "source": source_after,
        "recipe": _normalized_recipe(),
        "configuration": configuration,
        "toolchain": toolchain_after,
        "analyzer": analyzer,
        "logs": logs,
        "build_identity_sha256": "",
    }
    receipt["build_identity_sha256"] = digest_json(
        _build_identity_material(receipt)
    )
    _validate_receipt(receipt, tools, final=False)
    _write_bundle(
        authority, _bundle_bytes(receipt, build), INNER_AUTHORITY_FILES
    )
    return _verify_inner_authority_with_tools(authority, source, build, tools)


def _authority_file_names(authority: Path) -> list[str]:
    if _kind(authority) != "directory":
        raise BuildAuthorityError("build authority directory is missing")
    names: list[str] = []
    for path in authority.iterdir():
        if _kind(path) != "regular":
            raise BuildAuthorityError("authority contains a non-regular entry")
        names.append(path.name)
    return sorted(names)


def _verify_bundle_structure(
    authority: Path,
    tools: _ToolPaths | None,
    *,
    final: bool,
    podman: Path = DEFAULT_PODMAN,
) -> dict[str, Any]:
    authority = authority.absolute()
    admitted_files = AUTHORITY_FILES if final else INNER_AUTHORITY_FILES
    if _authority_file_names(authority) != sorted(admitted_files):
        raise BuildAuthorityError("authority file set differs from the exact contract")
    receipt_raw = _read_regular(authority / "receipt.json", MAX_JSON_BYTES)
    sidecar = _read_regular(authority / "receipt.json.sha256", 1024)
    expected_sidecar = (
        f"{sha256_bytes(receipt_raw)}  receipt.json\n".encode("utf-8")
    )
    if sidecar != expected_sidecar:
        raise BuildAuthorityError("receipt sidecar mismatch")
    receipt = _strict_json(receipt_raw, "receipt")
    if receipt_raw != canonical_json(receipt):
        raise BuildAuthorityError("receipt is not canonical JSON")
    payload = _validate_receipt(receipt, tools, final=final, podman=podman)
    checksum_lines: list[bytes] = []
    for name in sorted(set(admitted_files) - {"SHA256SUMS"}):
        maximum = MAX_LOG_BYTES if name in LOG_NAMES else MAX_JSON_BYTES
        digest = sha256_bytes(_read_regular(authority / name, maximum))
        checksum_lines.append(f"{digest}  {name}\n".encode("utf-8"))
    checksum = b"".join(checksum_lines)
    if _read_regular(authority / "SHA256SUMS", MAX_JSON_BYTES) != checksum:
        raise BuildAuthorityError("inner SHA256SUMS mismatch")
    admitted_logs = LOG_NAMES if final else BUILD_LOG_NAMES
    for name in admitted_logs:
        record = payload["logs"][name]
        raw = _read_regular(authority / name, MAX_LOG_BYTES)
        if len(raw) != record["size"] or sha256_bytes(raw) != record["sha256"]:
            raise BuildAuthorityError(f"{name} differs from its receipt identity")
    return payload


def _verify_with_tools(
    authority: Path,
    source: Path,
    build: Path,
    tools: _ToolPaths,
    *,
    final: bool,
    podman: Path = DEFAULT_PODMAN,
) -> dict[str, Any]:
    authority = authority.absolute()
    source = source.resolve()
    build = build.absolute()
    _paths_are_separate(source, build, authority)
    payload = _verify_bundle_structure(
        authority, tools, final=final, podman=podman
    )
    if final:
        container_layout = _container_layout_from_runtime(payload["runtime"])
        expected_operator = _expected_operator_log(
            _inner_build_identity_from_final(payload), container_layout
        )
        if _read_regular(
            authority / "operator.log", MAX_LOG_BYTES
        ) != expected_operator:
            raise BuildAuthorityError(
                "operator.log differs from the re-derived inner completion record"
            )
    for name in BUILD_LOG_NAMES:
        raw = _read_regular(authority / name, MAX_LOG_BYTES)
        producer_name = (
            "authority-build.log"
            if name == "build.log"
            else "authority-configure.log"
        )
        producer_raw = _read_regular(build / producer_name, MAX_LOG_BYTES)
        if producer_raw != raw:
            raise BuildAuthorityError(
                f"{name} differs from the producer process log"
            )
    source_now = _verify_source_identity(source, payload["source"]["revision"])
    if source_now != payload["source"]:
        raise BuildAuthorityError("source authority differs from the receipt")
    toolchain_now = _toolchain_identity(tools)
    if toolchain_now != payload["toolchain"]:
        raise BuildAuthorityError("toolchain differs from the receipt")
    configuration_now = _configuration_identity(build, source, tools)
    if configuration_now != payload["configuration"]:
        raise BuildAuthorityError("configuration differs from the receipt")
    analyzer_now = _analyzer_identity(build)
    if analyzer_now != payload["analyzer"]:
        raise BuildAuthorityError("analyzer differs from the receipt")
    # Recompute after all external identities so a forged internal digest never
    # substitutes for the actual source/build/tool files.
    if payload["build_identity_sha256"] != digest_json(
        _build_identity_material(payload)
    ):
        raise BuildAuthorityError("build identity differs from re-derived authority")
    return payload


def _verify_inner_authority_with_tools(
    authority: Path, source: Path, build: Path, tools: _ToolPaths,
) -> dict[str, Any]:
    return _verify_with_tools(
        authority, source, build, tools, final=False
    )


def verify_authority_with_tools(
    authority: Path,
    source: Path,
    build: Path,
    tools: _ToolPaths,
    *,
    podman: Path = DEFAULT_PODMAN,
) -> dict[str, Any]:
    """Inner final verifier with injectable tools for hermetic tests."""
    return _verify_with_tools(
        authority, source, build, tools, final=True, podman=podman
    )


def verify_authority_in_current_runtime(
    authority: Path,
    source: Path,
    build: Path,
) -> dict[str, Any]:
    """Re-derive final authority with the pinned runtime's fixed LLVM tools.

    This entry point is for a campaign process already launched by the public
    exact-image orchestrator.  It deliberately exposes no injectable tool or
    runtime paths and never launches nested Podman.
    """
    if os.name != "posix":
        raise BuildAuthorityError("in-runtime build verification requires POSIX")
    return verify_authority_with_tools(
        authority,
        source,
        build,
        DEFAULT_TOOLS,
        podman=DEFAULT_PODMAN,
    )


def _outer_source_identity(
    source: Path, revision: str, *, producer: bool,
) -> dict[str, Any]:
    identity = (
        _source_identity(source, revision)
        if producer
        else _verify_source_identity(source, revision)
    )
    retained_script = source / "scripts" / "analyzer_build_authority.py"
    if _kind(retained_script) != "regular":
        raise BuildAuthorityError("exact source omits the build authority script")
    executing_script = Path(__file__).resolve()
    if (
        _kind(executing_script) != "regular"
        or _hash_regular(executing_script, MAX_JSON_BYTES)
        != _hash_regular(retained_script, MAX_JSON_BYTES)
    ):
        raise BuildAuthorityError(
            "outer producer code differs from the exact source revision"
        )
    return identity


def _launch_authority(runtime: dict[str, Any]) -> bytes:
    _validate_runtime(runtime, Path(runtime["podman"]["path"]))
    return canonical_json({"schema": LAUNCH_SCHEMA, "runtime": runtime})


def _validate_launch_authority(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_JSON_BYTES)
    token = os.environ.get(INNER_TOKEN_ENV)
    if token is None or token != sha256_bytes(raw):
        raise BuildAuthorityError("inner launch authority token is missing or stale")
    payload = _strict_json(raw, "launch authority")
    if raw != canonical_json(payload):
        raise BuildAuthorityError("launch authority is not canonical JSON")
    launch = _object(payload, {"schema", "runtime"}, "launch authority")
    if launch["schema"] != LAUNCH_SCHEMA:
        raise BuildAuthorityError("launch authority schema drift")
    _validate_runtime(launch["runtime"], DEFAULT_PODMAN)
    return launch


def _mount_path(path: Path, label: str) -> str:
    value = str(path.absolute())
    if any(character in value for character in ("\x00", "\n", "\r", ":", "$")):
        raise BuildAuthorityError(f"{label} path is not safe for a Podman bind mount")
    return value


def _container_command(
    mode: str,
    podman: Path,
    source: Path,
    build: Path,
    authority_or_stage: Path,
    *,
    revision: str | None = None,
    launch_sha256: str | None = None,
    runtime: dict[str, Any] | None = None,
    container_layout: str | None = None,
) -> list[str]:
    if mode == "produce":
        if revision is None or REVISION.fullmatch(revision) is None:
            raise BuildAuthorityError("container producer revision is malformed")
        if launch_sha256 is None or SHA256.fullmatch(launch_sha256) is None:
            raise BuildAuthorityError("container launch identity is malformed")
        if runtime is None:
            raise BuildAuthorityError("container producer runtime is missing")
        validated_runtime = _validate_runtime(runtime, podman)
        retained_layout = _container_layout_from_runtime(validated_runtime)
        if container_layout is not None and container_layout != retained_layout:
            raise BuildAuthorityError(
                "container producer layout differs from runtime authority"
            )
        normalized = validated_runtime["normalized_argv"]
        bindings = {
            "$PODMAN": str(podman),
            "$SOURCE": _mount_path(source, "source"),
            "$BUILD": _mount_path(build, "build"),
            "$STAGE": _mount_path(authority_or_stage, "stage"),
            "$REVISION": revision,
            "$LAUNCH_SHA256": launch_sha256,
        }
    elif mode == "verify":
        selected_layout = "legacy" if container_layout is None else container_layout
        normalized = _normalized_container_argv("verify", selected_layout)
        bindings = {
            "$PODMAN": str(podman),
            "$SOURCE": _mount_path(source, "source"),
            "$BUILD": _mount_path(build, "build"),
            "$AUTHORITY": _mount_path(authority_or_stage, "authority"),
        }
    else:
        raise BuildAuthorityError("container command mode is unsupported")
    return _expand_argv(normalized, bindings)


def _execute_container(command: list[str], log: Path) -> None:
    try:
        with log.open("xb") as stream:
            completed = subprocess.run(
                command,
                check=False,
                stdout=stream,
                stderr=subprocess.STDOUT,
                env=_podman_environment(),
            )
    except OSError as error:
        raise BuildAuthorityError(f"cannot launch pinned build container: {error}") from error
    if completed.returncode != 0:
        raise BuildAuthorityError(
            f"pinned build container failed with exit {completed.returncode}"
        )
    if _kind(log) != "regular" or not 0 < log.stat().st_size <= MAX_LOG_BYTES:
        raise BuildAuthorityError("container operator log is empty or oversized")


def _finalize_outer_bundle(
    inner: Path,
    final: Path,
    operator_log: Path,
    runtime: dict[str, Any],
    podman: Path,
) -> dict[str, Any]:
    observation = _verify_bundle_structure(inner, None, final=False)
    operator_raw = _read_regular(operator_log, MAX_LOG_BYTES)
    container_layout = _container_layout_from_runtime(runtime)
    if operator_raw != _expected_operator_log(
        observation["build_identity_sha256"], container_layout
    ):
        raise BuildAuthorityError(
            "container operator log differs from the inner completion record"
        )
    receipt = _strict_json(canonical_json(observation), "inner observation copy")
    receipt["schema"] = RECEIPT_SCHEMA
    receipt["status"] = "accepted"
    receipt["runtime"] = runtime
    receipt["logs"]["operator.log"] = {
        "path": "operator.log",
        "sha256": sha256_bytes(operator_raw),
        "size": len(operator_raw),
    }
    receipt["build_identity_sha256"] = digest_json(
        _build_identity_material(receipt)
    )
    _validate_receipt(receipt, None, final=True, podman=podman)
    artifacts = {
        "build.log": _read_regular(inner / "build.log", MAX_LOG_BYTES),
        "configure.log": _read_regular(inner / "configure.log", MAX_LOG_BYTES),
        "operator.log": operator_raw,
    }
    _write_bundle(final, _seal_artifacts(receipt, artifacts), AUTHORITY_FILES)
    return receipt


def _promote_verified_bundle(final: Path, authority: Path) -> None:
    if _kind(final) != "directory":
        raise BuildAuthorityError("verified final authority is missing")
    if _kind(authority) == "directory":
        if next(authority.iterdir(), None) is not None:
            raise BuildAuthorityError("authority output is no longer empty")
        authority.rmdir()
    elif _kind(authority) != "missing":
        raise BuildAuthorityError("authority output is no longer available")
    try:
        final.rename(authority)
    except OSError as error:
        raise BuildAuthorityError(f"cannot promote verified authority: {error}") from error


def produce_authority(
    source: Path,
    revision: str,
    build: Path,
    authority: Path,
    *,
    podman: Path | None = None,
    container_layout: str = "legacy",
) -> dict[str, Any]:
    """Launch the exact image, build once, verify there, then publish."""
    if os.name != "posix":
        raise BuildAuthorityError("production build authority requires POSIX")
    podman = DEFAULT_PODMAN if podman is None else podman
    _container_paths(container_layout)
    source = source.resolve()
    build = build.absolute()
    authority = authority.absolute()
    _paths_are_separate(source, build, authority)
    source_before = _outer_source_identity(source, revision, producer=True)
    _require_empty_directory(build, "dedicated build")
    _require_empty_directory(authority, "authority output")
    runtime = _runtime_authority(podman, container_layout=container_layout)
    staging = Path(tempfile.mkdtemp(
        prefix=f".{authority.name}.producer-", dir=authority.parent
    ))
    try:
        container_stage = staging / "container-stage"
        container_stage.mkdir()
        launch_raw = _launch_authority(runtime)
        _write_new(container_stage / "launch-authority.json", launch_raw)
        produce_log = staging / "podman-produce.log"
        produce_command = _container_command(
            "produce",
            podman,
            source,
            build,
            container_stage,
            revision=revision,
            launch_sha256=sha256_bytes(launch_raw),
            runtime=runtime,
            container_layout=container_layout,
        )
        _execute_container(produce_command, produce_log)
        if _runtime_authority(
            podman, container_layout=container_layout
        ) != runtime:
            raise BuildAuthorityError("container runtime changed during the build")
        if _outer_source_identity(source, revision, producer=True) != source_before:
            raise BuildAuthorityError("source identity changed during container build")
        inner = container_stage / "inner"
        final = staging / "final"
        receipt = _finalize_outer_bundle(
            inner, final, produce_log, runtime, podman
        )
        verify_log = staging / "podman-verify.log"
        verify_command = _container_command(
            "verify",
            podman,
            source,
            build,
            final,
            container_layout=container_layout,
        )
        _execute_container(verify_command, verify_log)
        if _runtime_authority(
            podman, container_layout=container_layout
        ) != runtime:
            raise BuildAuthorityError("container runtime changed during verification")
        if _outer_source_identity(source, revision, producer=True) != source_before:
            raise BuildAuthorityError("source identity changed during container verification")
        _promote_verified_bundle(final, authority)
        retained = _verify_bundle_structure(
            authority, None, final=True, podman=podman
        )
        if retained != receipt:
            raise BuildAuthorityError("promoted authority differs from verified receipt")
        return retained
    finally:
        if _kind(staging) == "directory":
            shutil.rmtree(staging)


def verify_authority(
    authority: Path,
    source: Path,
    build: Path,
    *,
    podman: Path | None = None,
) -> dict[str, Any]:
    """Use the exact image to re-derive a published build authority."""
    if os.name != "posix":
        raise BuildAuthorityError("production build authority requires POSIX")
    podman = DEFAULT_PODMAN if podman is None else podman
    authority = authority.absolute()
    source = source.resolve()
    build = build.absolute()
    _paths_are_separate(source, build, authority)
    if _kind(build) != "directory":
        raise BuildAuthorityError("populated build authority directory is missing")
    payload = _verify_bundle_structure(
        authority, None, final=True, podman=podman
    )
    container_layout = _container_layout_from_runtime(payload["runtime"])
    source_before = _outer_source_identity(
        source, payload["source"]["revision"], producer=False
    )
    if source_before != payload["source"]:
        raise BuildAuthorityError("outer source differs from build authority")
    runtime_now = _runtime_authority(
        podman, container_layout=container_layout
    )
    if runtime_now != payload["runtime"]:
        raise BuildAuthorityError("container runtime differs from build authority")
    with tempfile.TemporaryDirectory(prefix="codeskeptic-authority-verify-") as directory:
        log = Path(directory) / "podman-verify.log"
        command = _container_command(
            "verify",
            podman,
            source,
            build,
            authority,
            container_layout=container_layout,
        )
        _execute_container(command, log)
    if _runtime_authority(
        podman, container_layout=container_layout
    ) != runtime_now:
        raise BuildAuthorityError("container runtime changed during verification")
    if _outer_source_identity(
        source, payload["source"]["revision"], producer=False
    ) != source_before:
        raise BuildAuthorityError("source identity changed during verification")
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    produce = subparsers.add_parser("produce", help="build and seal authority")
    produce.add_argument("--source", type=Path, required=True)
    produce.add_argument("--revision", required=True)
    produce.add_argument("--build-dir", type=Path, required=True)
    produce.add_argument("--output", type=Path, required=True)
    produce.add_argument(
        "--container-layout",
        choices=CONTAINER_LAYOUTS,
        default="legacy",
        help="exact in-container source/build/authority path layout",
    )
    verify = subparsers.add_parser("verify", help="re-derive sealed authority")
    verify.add_argument("--source", type=Path, required=True)
    verify.add_argument("--build-dir", type=Path, required=True)
    verify.add_argument("--authority", type=Path, required=True)
    inner_produce = subparsers.add_parser(
        "_inner-produce", help=argparse.SUPPRESS
    )
    inner_produce.add_argument("--source", type=Path, required=True)
    inner_produce.add_argument("--revision", required=True)
    inner_produce.add_argument("--build-dir", type=Path, required=True)
    inner_produce.add_argument("--output", type=Path, required=True)
    inner_produce.add_argument("--launch-authority", type=Path, required=True)
    inner_verify = subparsers.add_parser(
        "_inner-verify", help=argparse.SUPPRESS
    )
    inner_verify.add_argument("--source", type=Path, required=True)
    inner_verify.add_argument("--build-dir", type=Path, required=True)
    inner_verify.add_argument("--authority", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "produce":
            receipt = produce_authority(
                arguments.source,
                arguments.revision,
                arguments.build_dir,
                arguments.output,
                container_layout=arguments.container_layout,
            )
            path = arguments.output
            marker = "CODESKEPTIC_BUILD_AUTHORITY_ACCEPTED"
        elif arguments.command == "verify":
            receipt = verify_authority(
                arguments.authority,
                arguments.source,
                arguments.build_dir,
            )
            path = arguments.authority
            marker = "CODESKEPTIC_BUILD_AUTHORITY_VERIFIED"
        elif arguments.command == "_inner-produce":
            _validate_launch_authority(arguments.launch_authority)
            receipt = _produce_with_tools(
                arguments.source,
                arguments.revision,
                arguments.build_dir,
                arguments.output,
                DEFAULT_TOOLS,
            )
            path = arguments.output
            marker = "CODESKEPTIC_BUILD_OBSERVATION_COMPLETE"
        else:
            receipt = verify_authority_with_tools(
                arguments.authority,
                arguments.source,
                arguments.build_dir,
                DEFAULT_TOOLS,
            )
            path = arguments.authority
            marker = "CODESKEPTIC_BUILD_AUTHORITY_INNER_VERIFIED"
    except (BuildAuthorityError, OSError) as error:
        print(f"CODESKEPTIC_BUILD_AUTHORITY_FAIL {error}", file=sys.stderr)
        return 2
    print(f"{marker} {path} {receipt['build_identity_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
