#!/usr/bin/env python3
"""Seal the release-candidate Git inputs into one offline mirror authority."""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import ctypes
import errno
import hashlib
import importlib.util
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_PATH = SCRIPT_DIR / "run_realworld_campaign.py"
AUTHORITY_SCHEMA = "codeskeptic-realworld-mirror-authority-v1"
REQUIRED_TIER = "release-candidate"
SHA40 = re.compile(r"[0-9a-f]{40}")
MAX_RECURSION_DEPTH = 32
MAX_SUBMODULES = 4096
MAX_GITMODULE_BYTES = 4 << 20
MAX_TREE_LIST_BYTES = 256 << 20
# Calibrated for the pinned release-candidate scope (3 projects and 53 recursive
# submodules): 8 GiB is over 6x the largest top-level repository metadata size,
# while 96 GiB is an observed-growth ceiling with substantial scratch margin.
# This is defense in depth, not a claim of a universal filesystem quota.
MAX_BUNDLE_BYTES = 8 << 30
MAX_SEAL_WORKSPACE_ALLOCATED_BYTES = 96 << 30
MIN_SEAL_FILESYSTEM_FREE_BYTES = 8 << 30
EMERGENCY_RESERVE_BYTES = MIN_SEAL_FILESYSTEM_FREE_BYTES
MAX_GIT_CREATED_FILE_BYTES = 8 << 30
WORKSPACE_BUDGET_POLL_SECONDS = 0.25
RESERVE_RECOVERY_TIMEOUT_SECONDS = 2.0
RESERVE_RECOVERY_POLL_SECONDS = 0.05
DEFAULT_GIT_TIMEOUT_SECONDS = 3600
MAX_GIT_OUTPUT_BYTES = 8 << 20
GIT_EXECUTABLE = "/usr/bin/git"
AT_FDCWD = -100
RENAME_NOREPLACE = 1
_GIT_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "codeskeptic_git_deadline", default=None
)
_GIT_WORKSPACE_ROOT: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "codeskeptic_git_workspace", default=None
)
_GIT_WORKSPACE_IDENTITY: contextvars.ContextVar[tuple[int, int] | None] = (
    contextvars.ContextVar("codeskeptic_git_workspace_identity", default=None)
)
_GIT_WORKSPACE_BASELINE_ALLOCATED: contextvars.ContextVar[int | None] = (
    contextvars.ContextVar("codeskeptic_git_workspace_baseline_allocated", default=None)
)
_GIT_WORKSPACE_BASELINE_FREE: contextvars.ContextVar[int | None] = (
    contextvars.ContextVar("codeskeptic_git_workspace_baseline_free", default=None)
)
_GIT_RESERVE_STATE: contextvars.ContextVar[dict[str, int | None] | None] = (
    contextvars.ContextVar("codeskeptic_git_reserve_state", default=None)
)


def _check_global_deadline() -> None:
    deadline = _GIT_DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise SealError("mirror sealing exceeded the global deadline")


def _workspace_allocated_bytes(root: Path) -> int:
    total = 0
    pending = [root]
    entries = 0
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as stream:
                for entry in stream:
                    entries += 1
                    if entries > 1_000_000:
                        raise SealError("mirror workspace entry count exceeds the safety limit")
                    metadata = entry.stat(follow_symlinks=False)
                    total += metadata.st_blocks * 512
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(Path(entry.path))
        except OSError as error:
            raise SealError(f"cannot inspect mirror workspace allocation: {error}") from error
    return total


def _release_git_emergency_reserve(*, verify_floor: bool = True) -> None:
    state = _GIT_RESERVE_STATE.get()
    if state is None or state["reserve"] is None:
        return
    descriptor = state["reserve"]
    state["reserve"] = None
    assert descriptor is not None
    try:
        os.close(descriptor)
        if verify_floor:
            probe = state["probe"]
            if probe is None:
                raise SealError("emergency reserve filesystem probe is unavailable")
            recovery_deadline = time.monotonic() + RESERVE_RECOVERY_TIMEOUT_SECONDS
            while True:
                capacity = os.fstatvfs(probe)
                recovered = capacity.f_bavail * capacity.f_frsize
                if recovered >= MIN_SEAL_FILESYSTEM_FREE_BYTES:
                    break
                if time.monotonic() >= recovery_deadline:
                    raise SealError(
                        "emergency reserve release did not recover the free-space floor"
                    )
                time.sleep(RESERVE_RECOVERY_POLL_SECONDS)
    except OSError as error:
        raise SealError(f"cannot release emergency disk reserve: {error}") from error


def _workspace_budget_failure(message: str) -> None:
    raise SealError(message)


def _check_workspace_budget(required_headroom_bytes: int = 0) -> None:
    root = _GIT_WORKSPACE_ROOT.get()
    if root is None:
        return
    expected_identity = _GIT_WORKSPACE_IDENTITY.get()
    baseline_allocated = _GIT_WORKSPACE_BASELINE_ALLOCATED.get()
    baseline_free = _GIT_WORKSPACE_BASELINE_FREE.get()
    try:
        current_identity = _directory_identity(root)
    except SealError as error:
        _workspace_budget_failure(str(error))
    if (
        expected_identity is None
        or baseline_allocated is None
        or baseline_free is None
        or current_identity != expected_identity
    ):
        _workspace_budget_failure("mirror workspace budget authority is incomplete")
    try:
        allocated = _workspace_allocated_bytes(root)
    except SealError as error:
        _workspace_budget_failure(str(error))
    if allocated - baseline_allocated > MAX_SEAL_WORKSPACE_ALLOCATED_BYTES:
        _workspace_budget_failure("mirror workspace allocation exceeds the safety limit")
    try:
        free = shutil.disk_usage(root).free
    except OSError as error:
        _workspace_budget_failure(f"cannot inspect mirror filesystem capacity: {error}")
    if free < MIN_SEAL_FILESYSTEM_FREE_BYTES:
        _workspace_budget_failure("mirror filesystem free-space reserve was crossed")
    if free < MIN_SEAL_FILESYSTEM_FREE_BYTES + required_headroom_bytes:
        _workspace_budget_failure("mirror filesystem lacks bounded Git write headroom")
    if baseline_free - free > MAX_SEAL_WORKSPACE_ALLOCATED_BYTES:
        _workspace_budget_failure(
            "mirror filesystem allocation delta exceeds the safety limit"
        )


@contextlib.contextmanager
def _bounded_git_workspace(root: Path):
    """Make Git temporary/output growth accountable to one private filesystem root."""

    root = _real_directory(root, "Git workspace")
    temporary = root / "tmp"
    try:
        temporary.mkdir(mode=0o700)
    except OSError as error:
        raise SealError(f"cannot create private Git temporary directory: {error}") from error
    reserve_path = root / ".codeskeptic-emergency-reserve"
    reserve_descriptor = -1
    probe_descriptor = -1
    try:
        probe_descriptor = os.open(
            root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        reserve_descriptor = os.open(
            reserve_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.posix_fallocate(reserve_descriptor, 0, EMERGENCY_RESERVE_BYTES)
        os.fsync(reserve_descriptor)
        reserve_path.unlink()
        identity = _directory_identity(root)
        baseline_allocated = _workspace_allocated_bytes(root)
        baseline_free = shutil.disk_usage(root).free
    except (AttributeError, OSError, SealError) as error:
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
            raise SealError(
                f"cannot allocate emergency disk reserve: {error}; "
                f"cleanup failed: {'; '.join(cleanup_failures)}"
            ) from error
        raise SealError(f"cannot allocate emergency disk reserve: {error}") from error
    tokens = (
        (_GIT_WORKSPACE_ROOT, _GIT_WORKSPACE_ROOT.set(root)),
        (_GIT_WORKSPACE_IDENTITY, _GIT_WORKSPACE_IDENTITY.set(identity)),
        (
            _GIT_WORKSPACE_BASELINE_ALLOCATED,
            _GIT_WORKSPACE_BASELINE_ALLOCATED.set(baseline_allocated),
        ),
        (_GIT_WORKSPACE_BASELINE_FREE, _GIT_WORKSPACE_BASELINE_FREE.set(baseline_free)),
        (
            _GIT_RESERVE_STATE,
            _GIT_RESERVE_STATE.set(
                {"reserve": reserve_descriptor, "probe": probe_descriptor}
            ),
        ),
    )
    try:
        _check_workspace_budget()
        yield temporary
    finally:
        state = _GIT_RESERVE_STATE.get()
        teardown_failures: list[str] = []
        try:
            if not campaign._child_table_empty():
                raise SealError(
                    "Git workspace still has a live child; emergency reserve retained"
                )
            _release_git_emergency_reserve()
        except BaseException as error:
            teardown_failures.append(f"reserve: {error}")
        try:
            if state is not None and state["probe"] is not None:
                os.close(state["probe"])
                state["probe"] = None
        except BaseException as error:
            teardown_failures.append(f"filesystem probe: {error}")
        finally:
            for variable, token in reversed(tokens):
                variable.reset(token)
        if teardown_failures:
            raise SealError(
                f"Git workspace teardown failed: {'; '.join(teardown_failures)}"
            )


def _git_preexec(file_size_limit_bytes: int):
    if os.name != "posix":
        return None
    import resource

    def apply_limit() -> None:
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (file_size_limit_bytes, file_size_limit_bytes),
        )

    return apply_limit


def _load_campaign_module():
    spec = importlib.util.spec_from_file_location(
        "codeskeptic_realworld_campaign_for_mirror", RUNNER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load campaign runner: {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


campaign = _load_campaign_module()


class SealError(RuntimeError):
    """The requested mirror cannot be sealed without weakening its authority."""


def _git_environment(protocols: str) -> dict[str, str]:
    workspace = _GIT_WORKSPACE_ROOT.get()
    temporary = workspace / "tmp" if workspace is not None else Path("/tmp")
    return {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": os.fspath(temporary),
        "GIT_ALLOW_PROTOCOL": protocols,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "SSH_ASKPASS": "/bin/false",
    }


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    known: dict[int, int],
) -> None:
    try:
        campaign._terminate_command_tree(process, known)
    except campaign.CampaignError as error:
        raise SealError(f"Git descendant cleanup failed: {error}") from error


def _check_git_watched_files(watched_files: Mapping[Path, int]) -> None:
    for path, maximum in watched_files.items():
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise SealError(f"cannot inspect bounded Git output {path}: {error}") from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SealError(f"bounded Git output is not one regular file: {path}")
        if metadata.st_size > maximum:
            raise SealError(f"bounded Git output exceeded the safety limit: {path}")


def _invoke_git(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    protocols: str = "file",
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
    file_size_limit_bytes: int | None = None,
    stdout_limit_bytes: int | None = None,
    watched_files: Mapping[Path, int] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    file_size_limit = (
        MAX_GIT_CREATED_FILE_BYTES
        if file_size_limit_bytes is None
        else file_size_limit_bytes
    )
    if (
        isinstance(file_size_limit, bool)
        or not isinstance(file_size_limit, int)
        or file_size_limit < 1
    ):
        raise SealError("Git file-size limit must be a positive integer")
    stdout_limit = (
        MAX_GIT_OUTPUT_BYTES
        if stdout_limit_bytes is None
        else stdout_limit_bytes
    )
    if (
        isinstance(stdout_limit, bool)
        or not isinstance(stdout_limit, int)
        or stdout_limit < 1
    ):
        raise SealError("Git stdout limit must be a positive integer")
    _check_global_deadline()
    if not campaign._enable_subreaper():
        raise SealError("Git execution requires Linux /proc subreaper containment")
    try:
        campaign._require_empty_child_table()
    except campaign.CampaignError as error:
        raise SealError(str(error)) from error
    try:
        _check_workspace_budget(required_headroom_bytes=file_size_limit)
    except SealError as error:
        try:
            _release_git_emergency_reserve()
        except SealError as recovery_error:
            raise SealError(f"{error}; {recovery_error}") from error
        raise
    watched = dict(watched_files or {})
    _check_git_watched_files(watched)
    active_deadline = _GIT_DEADLINE.get()
    local_deadline = time.monotonic() + timeout_seconds
    deadline = min(local_deadline, active_deadline) if active_deadline else local_deadline
    command = [
        GIT_EXECUTABLE,
        "--no-replace-objects",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "credential.helper=",
        "-c", "init.templateDir=",
        "-c", "protocol.ext.allow=never",
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(protocols),
            preexec_fn=_git_preexec(file_size_limit),
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        try:
            _release_git_emergency_reserve()
        except SealError as recovery_error:
            raise SealError(
                f"git execution failed: {error}; {recovery_error}"
            ) from error
        raise SealError(f"git execution failed: {error}") from error
    assert process.stdout is not None and process.stderr is not None
    known: dict[int, int] = {}
    record = campaign._proc_record(process.pid)
    if record is not None:
        known[process.pid] = record[2]
    streams: selectors.BaseSelector | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    next_workspace_check = 0.0

    def inspect_live_state(*, force_workspace: bool = False) -> None:
        nonlocal next_workspace_check
        now = time.monotonic()
        if force_workspace or now >= next_workspace_check:
            _check_workspace_budget()
            next_workspace_check = now + WORKSPACE_BUDGET_POLL_SECONDS
        _check_git_watched_files(watched)
        campaign._refresh_descendants(process.pid, known)

    completed: subprocess.CompletedProcess[bytes] | None = None
    primary_error: BaseException | None = None
    try:
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, "stdout")
        streams.register(process.stderr, selectors.EVENT_READ, "stderr")
        while streams.get_map():
            inspect_live_state()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SealError("git execution exceeded the global deadline")
            events = streams.select(min(remaining, 0.02))
            if not events:
                continue
            for key, _mask in events:
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    streams.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = buffers[key.data]
                limit = stdout_limit if key.data == "stdout" else MAX_GIT_OUTPUT_BYTES
                if len(target) + len(block) > limit:
                    raise SealError(f"git {key.data} exceeded the safety limit")
                target.extend(block)
        inspect_live_state()
        while process.poll() is None:
            inspect_live_state()
            if time.monotonic() >= deadline:
                raise SealError("git execution exceeded the global deadline")
            time.sleep(0.01)
        returncode = process.returncode
        assert returncode is not None
        grace = min(deadline, time.monotonic() + 0.05)
        while True:
            inspect_live_state()
            campaign._reap_known(process, known)
            survivors = [
                pid for pid, started in known.items()
                if pid != process.pid and campaign._pid_matches(pid, started)
            ]
            if (
                campaign._child_table_empty()
                and not survivors
                and not campaign._known_process_group_exists(process.pid, known)
            ):
                break
            if time.monotonic() >= grace:
                raise SealError("git command left a detached descendant alive")
            time.sleep(0.005)
        inspect_live_state(force_workspace=True)
        completed = subprocess.CompletedProcess(
            command, returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])
        )
    except BaseException as error:
        primary_error = error

    cleanup_failures: list[str] = []
    if primary_error is not None:
        try:
            _terminate_process_group(process, known)
        except BaseException as cleanup_error:
            cleanup_failures.append(f"Git descendants: {cleanup_error}")
        if not cleanup_failures:
            try:
                _release_git_emergency_reserve()
            except BaseException as cleanup_error:
                cleanup_failures.append(f"emergency reserve: {cleanup_error}")
    if streams is not None:
        try:
            streams.close()
        except BaseException as cleanup_error:
            cleanup_failures.append(f"Git selector: {cleanup_error}")
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        if not stream.closed:
            try:
                stream.close()
            except BaseException as cleanup_error:
                cleanup_failures.append(f"Git {name} pipe: {cleanup_error}")
    if cleanup_failures:
        detail = "; ".join(cleanup_failures)
        if primary_error is not None:
            raise SealError(
                f"{primary_error}; cleanup failed: {detail}"
            ) from primary_error
        raise SealError(f"Git cleanup failed: {detail}")
    if primary_error is not None:
        if isinstance(primary_error, campaign.CampaignError):
            raise SealError(str(primary_error)) from primary_error
        raise primary_error
    if completed is None:
        raise SealError("Git execution produced no completed result")
    return completed


def _git(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    protocols: str = "file",
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
    file_size_limit_bytes: int | None = None,
    stdout_limit_bytes: int | None = None,
    watched_files: Mapping[Path, int] | None = None,
) -> bytes:
    result = _invoke_git(
        arguments,
        cwd=cwd,
        protocols=protocols,
        timeout_seconds=timeout_seconds,
        file_size_limit_bytes=file_size_limit_bytes,
        stdout_limit_bytes=stdout_limit_bytes,
        watched_files=watched_files,
    )
    if result.returncode != 0:
        _release_git_emergency_reserve()
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > 600:
            detail = detail[-600:]
        suffix = f": {detail}" if detail else ""
        raise SealError(f"git command failed with exit {result.returncode}{suffix}")
    return result.stdout


def _decode_git(payload: bytes, field: str) -> str:
    try:
        return payload.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise SealError(f"{field} is not UTF-8") from error


def _canonical_relative(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        raise SealError(f"{field} is not a canonical relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        component in {"", ".", ".."} for component in path.parts
    ):
        raise SealError(f"{field} is not a canonical relative path")
    return value


def _upstream(value: Any, field: str) -> str:
    try:
        return campaign._validate_upstream_url(value, field)
    except campaign.CampaignError as error:
        raise SealError(str(error)) from error


def _resolve_submodule_upstream(parent: str, raw: str, field: str) -> str:
    try:
        return campaign._resolve_submodule_repository(parent, raw, field)
    except campaign.CampaignError as error:
        raise SealError(str(error)) from error


def _real_directory(path: Path, field: str) -> Path:
    absolute = path.absolute()
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise SealError(f"{field} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or absolute.resolve() != absolute:
        raise SealError(f"{field} must be a real directory without symlinks")
    return absolute


def _normalize_sources(sources: Mapping[str, Path | str] | None) -> dict[str, Path]:
    normalized: dict[str, Path] = {}
    for raw_url, raw_path in (sources or {}).items():
        url = _upstream(raw_url, "source mapping URL")
        if url in normalized:
            raise SealError(f"duplicate source mapping for {url}")
        normalized[url] = _real_directory(Path(raw_path), f"source mapping for {url}")
    return normalized


def _clone_online(
    upstream: str,
    destination: Path,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> None:
    _git(
        ["clone", "--mirror", "--no-single-branch", upstream, str(destination)],
        protocols="https",
        timeout_seconds=timeout_seconds,
    )


class _SourceResolver:
    def __init__(
        self,
        sources: Mapping[str, Path | str] | None,
        fetch_online: bool,
        cache_root: Path,
        timeout_seconds: int,
    ) -> None:
        self.sources = _normalize_sources(sources)
        self.fetch_online = fetch_online
        self.cache_root = cache_root
        self.timeout_seconds = timeout_seconds
        self.used: set[str] = set()
        self.online: dict[str, Path] = {}
        if self.sources and self.fetch_online:
            raise SealError("local sources and online fetch are mutually exclusive")

    def resolve(self, upstream: str) -> Path:
        url = _upstream(upstream, "repository URL")
        if self.sources:
            source = self.sources.get(url)
            if source is None:
                raise SealError(f"source mapping is missing for {url}")
            self.used.add(url)
            return source
        if not self.fetch_online:
            raise SealError(
                f"source mapping is missing for {url}; online fetch was not enabled"
            )
        cached = self.online.get(url)
        if cached is not None:
            return cached
        destination = self.cache_root / f"{hashlib.sha256(url.encode('utf-8')).hexdigest()}.git"
        _clone_online(url, destination, self.timeout_seconds)
        self.online[url] = destination
        return destination


def _commit_and_tree(
    repository: Path,
    revision: str,
    *,
    field: str,
    timeout_seconds: int,
) -> tuple[str, str]:
    if not isinstance(revision, str) or SHA40.fullmatch(revision) is None:
        raise SealError(f"{field} revision is not immutable")
    try:
        commit = _decode_git(
            _git(
                ["-C", str(repository), "rev-parse", "--verify", f"{revision}^{{commit}}"],
                timeout_seconds=timeout_seconds,
            ),
            f"{field} revision",
        )
    except SealError as error:
        raise SealError(f"{field} revision {revision} is unavailable") from error
    if commit != revision:
        raise SealError(f"{field} revision resolved to a different commit")
    tree = _decode_git(
        _git(
            ["-C", str(repository), "rev-parse", "--verify", f"{revision}^{{tree}}"],
            timeout_seconds=timeout_seconds,
        ),
        f"{field} tree",
    )
    if SHA40.fullmatch(tree) is None:
        raise SealError(f"{field} tree is malformed")
    return commit, tree


def _gitlinks(
    repository: Path, revision: str, timeout_seconds: int
) -> dict[str, str]:
    payload = _git(
        ["-C", str(repository), "ls-tree", "-r", "-z", revision],
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=MAX_TREE_LIST_BYTES,
    )
    if len(payload) > MAX_TREE_LIST_BYTES:
        raise SealError("Git tree inventory exceeds the safety limit")
    links: dict[str, str] = {}
    for raw_entry in payload.split(b"\x00"):
        if not raw_entry:
            continue
        try:
            raw_metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, kind, revision_bytes = raw_metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
            object_revision = revision_bytes
        except (ValueError, UnicodeDecodeError) as error:
            raise SealError("Git tree entry is malformed") from error
        if mode != "160000":
            continue
        if kind != "commit" or SHA40.fullmatch(object_revision) is None:
            raise SealError("Git submodule entry is malformed")
        relative = _canonical_relative(path, "Git submodule path")
        if relative in links:
            raise SealError(f"duplicate Git submodule path: {relative}")
        links[relative] = object_revision
    return links


def _gitmodule_records(
    repository: Path,
    revision: str,
    parent_upstream: str,
    timeout_seconds: int,
) -> list[dict[str, str]]:
    existence = _invoke_git(
        ["-C", str(repository), "cat-file", "-e", f"{revision}:.gitmodules"],
        timeout_seconds=timeout_seconds,
    )
    if existence.returncode not in (0, 128):
        raise SealError("cannot determine .gitmodules authority")
    links = _gitlinks(repository, revision, timeout_seconds)
    if existence.returncode == 128:
        if links:
            raise SealError("Git tree contains undeclared submodule entries")
        return []
    tree_entry = _git(
        [
            "-C",
            str(repository),
            "ls-tree",
            "-z",
            revision,
            "--",
            ".gitmodules",
        ],
        timeout_seconds=timeout_seconds,
    )
    try:
        metadata, entry_path = tree_entry.rstrip(b"\x00").split(b"\t", 1)
        mode, kind, _ = metadata.decode("ascii").split(" ")
        decoded_path = entry_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise SealError(".gitmodules tree authority is malformed") from error
    if mode not in {"100644", "100755"} or kind != "blob" or decoded_path != ".gitmodules":
        raise SealError(".gitmodules must be one regular Git blob")
    size = _decode_git(
        _git(
            ["-C", str(repository), "cat-file", "-s", f"{revision}:.gitmodules"],
            timeout_seconds=timeout_seconds,
        ),
        ".gitmodules size",
    )
    if not size.isdecimal() or int(size) > MAX_GITMODULE_BYTES:
        raise SealError(".gitmodules exceeds the safety limit")
    include_result = _invoke_git(
        [
            "-C",
            str(repository),
            "config",
            "--no-includes",
            "--blob",
            f"{revision}:.gitmodules",
            "--get-regexp",
            r"^include(if)?\.",
        ],
        timeout_seconds=timeout_seconds,
    )
    if include_result.returncode == 0:
        raise SealError(".gitmodules must not contain external include directives")
    if include_result.returncode != 1:
        raise SealError("cannot inspect .gitmodules include authority")
    result = _invoke_git(
        [
            "-C",
            str(repository),
            "config",
            "--no-includes",
            "--blob",
            f"{revision}:.gitmodules",
            "--get-regexp",
            r"^submodule\..*\.(path|url)$",
        ],
        timeout_seconds=timeout_seconds,
    )
    if result.returncode not in (0, 1):
        raise SealError("cannot parse .gitmodules authority")
    records: dict[str, dict[str, str]] = {}
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SealError(".gitmodules authority is not UTF-8") from error
    pattern = re.compile(r"submodule\.(.+)\.(path|url)")
    for line in lines:
        try:
            key, value = line.split(None, 1)
        except ValueError as error:
            raise SealError(".gitmodules authority line is malformed") from error
        match = pattern.fullmatch(key)
        if match is None:
            raise SealError(".gitmodules authority key is malformed")
        name, item = match.groups()
        record = records.setdefault(name, {})
        if item in record:
            raise SealError(".gitmodules authority contains a duplicate field")
        record[item] = value
    modules: list[dict[str, str]] = []
    for name, record in sorted(records.items()):
        if set(record) != {"path", "url"}:
            raise SealError(f".gitmodules entry {name!r} is incomplete")
        path = _canonical_relative(record["path"], f"submodule {name} path")
        upstream = _resolve_submodule_upstream(
            parent_upstream,
            record["url"],
            f"submodule {path} repository",
        )
        modules.append({"path": path, "repository": upstream})
    module_paths = [record["path"] for record in modules]
    if len(module_paths) != len(set(module_paths)) or set(module_paths) != set(links):
        raise SealError(".gitmodules paths do not exactly match Git submodule entries")
    for record in modules:
        record["revision"] = links[record["path"]]
    return sorted(modules, key=lambda record: record["path"])


def _discover_submodules(
    *,
    repository: Path,
    upstream: str,
    revision: str,
    prefix: str,
    resolver: _SourceResolver,
    bindings: dict[str, dict[str, Any]],
    ancestry: frozenset[tuple[str, str]],
    timeout_seconds: int,
    depth: int = 0,
) -> list[dict[str, str]]:
    if depth > MAX_RECURSION_DEPTH:
        raise SealError("recursive submodule depth exceeds the safety limit")
    identity = (upstream, revision)
    if identity in ancestry:
        raise SealError("recursive submodule graph contains a cycle")
    records: list[dict[str, str]] = []
    for direct in _gitmodule_records(repository, revision, upstream, timeout_seconds):
        full_path = (
            f"{prefix}/{direct['path']}" if prefix else direct["path"]
        )
        full_path = _canonical_relative(full_path, "recursive submodule path")
        child_upstream = direct["repository"]
        child_revision = direct["revision"]
        child_repository = resolver.resolve(child_upstream)
        _, child_tree = _commit_and_tree(
            child_repository,
            child_revision,
            field=f"submodule {full_path}",
            timeout_seconds=timeout_seconds,
        )
        _register_binding(
            bindings,
            child_upstream,
            child_repository,
            child_revision,
            child_tree,
        )
        records.append(
            {
                "path": full_path,
                "repository": child_upstream,
                "revision": child_revision,
                "tree": child_tree,
            }
        )
        records.extend(
            _discover_submodules(
                repository=child_repository,
                upstream=child_upstream,
                revision=child_revision,
                prefix=full_path,
                resolver=resolver,
                bindings=bindings,
                ancestry=ancestry | {identity},
                timeout_seconds=timeout_seconds,
                depth=depth + 1,
            )
        )
        if len(records) > MAX_SUBMODULES:
            raise SealError("recursive submodule count exceeds the safety limit")
    paths = [record["path"] for record in records]
    if len(paths) != len(set(paths)):
        raise SealError("recursive submodule graph contains duplicate paths")
    return sorted(records, key=lambda record: record["path"])


def _register_binding(
    bindings: dict[str, dict[str, Any]],
    upstream: str,
    repository: Path,
    revision: str,
    tree: str,
) -> None:
    binding = bindings.setdefault(
        upstream,
        {"repository": repository, "revisions": {}},
    )
    if binding["repository"] != repository:
        raise SealError(f"repository {upstream} resolved inconsistently")
    previous = binding["revisions"].setdefault(revision, tree)
    if previous != tree:
        raise SealError(f"repository {upstream} tree identity is inconsistent")


def _bundle_name(upstream: str) -> str:
    return f"bundles/{hashlib.sha256(upstream.encode('utf-8')).hexdigest()}.bundle"


def _digest_sealed_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SealError(f"cannot open sealed bundle: {error}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > MAX_BUNDLE_BYTES
        ):
            raise SealError("sealed bundle type, link count, or size is invalid")
        hasher = hashlib.sha256()
        total = 0
        while True:
            _check_global_deadline()
            block = os.read(descriptor, 1 << 20)
            if not block:
                break
            total += len(block)
            if total > MAX_BUNDLE_BYTES:
                raise SealError("sealed bundle exceeds the safety limit")
            hasher.update(block)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_mode, before.st_size,
             before.st_nlink, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                after.st_nlink, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise SealError("sealed bundle changed while hashing")
        return hasher.hexdigest()
    except OSError as error:
        raise SealError(f"cannot hash sealed bundle: {error}") from error
    finally:
        os.close(descriptor)


def _build_bundle(
    upstream: str,
    binding: dict[str, Any],
    output_root: Path,
    scratch_root: Path,
    timeout_seconds: int,
) -> tuple[str, str]:
    relative = _bundle_name(upstream)
    destination = output_root / relative
    repository = scratch_root / f"bundle-{hashlib.sha256(upstream.encode('utf-8')).hexdigest()}.git"
    _git(["init", "--bare", "--quiet", str(repository)], timeout_seconds=timeout_seconds)
    repository_identity = _directory_identity(repository)
    references: list[str] = []
    for revision, expected_tree in sorted(binding["revisions"].items()):
        _check_global_deadline()
        _git(
            [
                "--git-dir",
                str(repository),
                "fetch",
                "--quiet",
                "--no-tags",
                str(binding["repository"]),
                revision,
            ],
            timeout_seconds=timeout_seconds,
        )
        fetched = _decode_git(
            _git(
                ["--git-dir", str(repository), "rev-parse", "FETCH_HEAD^{commit}"],
                timeout_seconds=timeout_seconds,
            ),
            "fetched bundle revision",
        )
        tree = _decode_git(
            _git(
                ["--git-dir", str(repository), "rev-parse", "FETCH_HEAD^{tree}"],
                timeout_seconds=timeout_seconds,
            ),
            "fetched bundle tree",
        )
        if fetched != revision or tree != expected_tree:
            raise SealError(f"repository {upstream} changed while creating its bundle")
        reference = f"refs/codeskeptic/revisions/{revision}"
        _git(
            ["--git-dir", str(repository), "update-ref", reference, revision],
            timeout_seconds=timeout_seconds,
        )
        references.append(reference)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _git(
        [
            "--git-dir",
            str(repository),
            "bundle",
            "create",
            str(destination),
            *references,
        ],
        timeout_seconds=timeout_seconds,
        file_size_limit_bytes=min(MAX_BUNDLE_BYTES, MAX_GIT_CREATED_FILE_BYTES),
        watched_files={destination: MAX_BUNDLE_BYTES},
    )
    _git(
        ["-C", str(repository), "bundle", "verify", str(destination)],
        timeout_seconds=timeout_seconds,
    )
    heads = _decode_git(
        _git(["bundle", "list-heads", str(destination)], timeout_seconds=timeout_seconds),
        "bundle heads",
    ).splitlines()
    expected_heads = [
        f"{revision} refs/codeskeptic/revisions/{revision}"
        for revision in sorted(binding["revisions"])
    ]
    if heads != expected_heads:
        raise SealError(f"repository {upstream} bundle advertises unexpected heads")

    verification = scratch_root / (
        f"verify-{hashlib.sha256(upstream.encode('utf-8')).hexdigest()}.git"
    )
    _git(["init", "--bare", "--quiet", str(verification)], timeout_seconds=timeout_seconds)
    verification_identity = _directory_identity(verification)
    for revision, expected_tree in sorted(binding["revisions"].items()):
        _git(
            [
                "--git-dir",
                str(verification),
                "fetch",
                "--quiet",
                str(destination),
                revision,
            ],
            timeout_seconds=timeout_seconds,
        )
        actual_tree = _decode_git(
            _git(
                ["--git-dir", str(verification), "rev-parse", "FETCH_HEAD^{tree}"],
                timeout_seconds=timeout_seconds,
            ),
            "verified bundle tree",
        )
        if actual_tree != expected_tree:
            raise SealError(f"repository {upstream} bundle tree verification failed")
    try:
        with destination.open("rb") as stream:
            os.fsync(stream.fileno())
    except OSError as error:
        raise SealError(f"cannot sync bundle {relative}: {error}") from error
    digest = _digest_sealed_file(destination)
    _remove_owned_tree(verification, verification_identity)
    _remove_owned_tree(repository, repository_identity)
    _check_workspace_budget()
    return relative, digest


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                _check_global_deadline()
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise SealError(f"cannot create sealed file {path.name}: {error}") from error


def _make_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        _check_global_deadline()
        if path.is_symlink():
            raise SealError(f"sealed output contains a symlink: {path}")
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SealError(f"cannot inspect owned directory {path}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise SealError(f"owned cleanup target is not a directory: {path}")
    return metadata.st_dev, metadata.st_ino


def _remove_owned_tree(path: Path, identity: tuple[int, int]) -> None:
    """Remove only the directory inode created by this producer."""

    if not path.exists() and not path.is_symlink():
        return
    if _directory_identity(path) != identity:
        raise SealError(f"owned cleanup target identity changed: {path}")
    try:
        path.chmod(0o700)
        directories: list[Path] = []
        for entry in path.rglob("*"):
            metadata = entry.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(entry)
        for directory in directories:
            directory.chmod(0o700)
        if _directory_identity(path) != identity:
            raise SealError(f"owned cleanup target identity changed: {path}")
        shutil.rmtree(path)
        _fsync_directory(path.parent)
    except (OSError, SealError) as error:
        if isinstance(error, SealError):
            raise
        raise SealError(f"cannot remove owned directory {path}: {error}") from error


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise SealError(f"cannot sync directory {path}: {error}") from error


def _fsync_read_only_tree(root: Path) -> None:
    directories = [root]
    for path in root.rglob("*"):
        _check_global_deadline()
        if path.is_dir():
            directories.append(path)
            continue
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise SealError(f"cannot sync sealed file {path}: {error}") from error
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _check_global_deadline()
        _fsync_directory(directory)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing any concurrent target."""
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise SealError("atomic no-replace publication is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise SealError(f"output already exists: {destination}")
    if error_number in {errno.ENOSYS, errno.EINVAL}:
        raise SealError("atomic no-replace publication is unavailable")
    raise SealError(
        f"cannot publish sealed mirror: {os.strerror(error_number)}"
    )


def seal_mirror_authority(
    manifest_path: Path | str,
    output: Path | str,
    *,
    tier: str = REQUIRED_TIER,
    sources: Mapping[str, Path | str] | None = None,
    fetch_online: bool = False,
    git_timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> Path:
    """Build and verify one immutable, self-contained authority directory."""
    if tier != REQUIRED_TIER:
        raise SealError(f"only the {REQUIRED_TIER} tier can be sealed")
    if (
        isinstance(git_timeout_seconds, bool)
        or not isinstance(git_timeout_seconds, int)
        or git_timeout_seconds < 1
    ):
        raise SealError("Git timeout must be a positive integer")
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink():
        raise SealError(f"output already exists: {destination}")
    parent = _real_directory(destination.parent, "output parent")
    try:
        manifest = campaign.validate_manifest(campaign.load_manifest(manifest_path))
    except campaign.CampaignError as error:
        raise SealError(f"manifest is not authoritative: {error}") from error
    tier_record = manifest["campaigns"].get(tier)
    if not isinstance(tier_record, dict):
        raise SealError(f"manifest has no {tier} tier")
    selected_ids = tier_record.get("projects")
    if (
        not isinstance(selected_ids, list)
        or not selected_ids
        or len(selected_ids) != len(set(selected_ids))
    ):
        raise SealError(f"manifest {tier} project set is malformed")
    selected_set = set(selected_ids)
    selected_projects = [
        project for project in manifest["projects"] if project["id"] in selected_set
    ]
    if {project["id"] for project in selected_projects} != selected_set:
        raise SealError(f"manifest {tier} project set is incomplete")

    workspace = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.mirror-work-", dir=parent)
    )
    workspace_identity = _directory_identity(workspace)
    sealed = workspace / "sealed"
    scratch = workspace / "scratch"
    cache = scratch / "online"
    try:
        sealed.mkdir()
        scratch.mkdir()
        cache.mkdir()
        budget_context = _bounded_git_workspace(workspace)
        budget_context.__enter__()
    except BaseException as error:
        try:
            _remove_owned_tree(workspace, workspace_identity)
        except BaseException as cleanup_error:
            raise SealError(
                f"{error}; workspace initialization cleanup failed: {cleanup_error}"
            ) from error
        raise
    deadline_token = _GIT_DEADLINE.set(time.monotonic() + git_timeout_seconds)
    published = False
    moved = False
    moved_identity: tuple[int, int] | None = None
    result_authority: Path | None = None
    failure: BaseException | None = None
    cleanup_failures: list[str] = []
    try:
        resolver = _SourceResolver(
            sources,
            fetch_online,
            cache,
            git_timeout_seconds,
        )
        bindings: dict[str, dict[str, Any]] = {}
        projects: list[dict[str, Any]] = []
        for project in selected_projects:
            _check_global_deadline()
            upstream = _upstream(
                project["repository"], f"project {project['id']} repository"
            )
            repository = resolver.resolve(upstream)
            revision, tree = _commit_and_tree(
                repository,
                project["revision"],
                field=f"project {project['id']}",
                timeout_seconds=git_timeout_seconds,
            )
            _register_binding(bindings, upstream, repository, revision, tree)
            submodules = _discover_submodules(
                repository=repository,
                upstream=upstream,
                revision=revision,
                prefix="",
                resolver=resolver,
                bindings=bindings,
                ancestry=frozenset(),
                timeout_seconds=git_timeout_seconds,
            )
            actual_identity = [
                {"path": record["path"], "revision": record["revision"]}
                for record in submodules
            ]
            expected = project["checkout"]
            if (
                (expected["submodules"] == "none" and actual_identity)
                or (expected["submodules"] == "recursive" and not actual_identity)
                or len(actual_identity) != expected["expected_count"]
                or campaign.digest_json(actual_identity) != expected["expected_sha256"]
            ):
                raise SealError(
                    f"project {project['id']} submodule identity does not match the manifest"
                )
            projects.append(
                {
                    "id": project["id"],
                    "repository": upstream,
                    "revision": revision,
                    "tree": tree,
                    "submodules": submodules,
                }
            )

        unused = sorted(set(resolver.sources) - resolver.used)
        if unused:
            raise SealError(f"unused source mapping: {unused[0]}")

        bundle_records: dict[str, tuple[str, str]] = {}
        for upstream, binding in sorted(bindings.items()):
            _check_global_deadline()
            bundle_records[upstream] = _build_bundle(
                upstream,
                binding,
                sealed,
                scratch,
                git_timeout_seconds,
            )
        authority_projects: list[dict[str, Any]] = []
        for project in projects:
            _check_global_deadline()
            bundle, bundle_sha256 = bundle_records[project["repository"]]
            submodules = []
            for record in project["submodules"]:
                child_bundle, child_sha256 = bundle_records[record["repository"]]
                submodules.append(
                    {
                        **record,
                        "bundle": child_bundle,
                        "bundle_sha256": child_sha256,
                    }
                )
            authority_projects.append(
                {
                    "id": project["id"],
                    "repository": project["repository"],
                    "revision": project["revision"],
                    "tree": project["tree"],
                    "bundle": bundle,
                    "bundle_sha256": bundle_sha256,
                    "submodules": submodules,
                }
            )
        authority = {
            "schema": AUTHORITY_SCHEMA,
            "manifest_sha256": campaign.digest_json(manifest),
            "projects": authority_projects,
        }
        encoded = campaign.canonical_bytes(authority) + b"\n"
        authority_path = sealed / "authority.json"
        _write_new(authority_path, encoded)
        _write_new(
            authority_path.with_suffix(".json.sha256"),
            f"{campaign.digest_bytes(encoded)}  authority.json\n".encode("ascii"),
        )
        _fsync_directory(sealed / "bundles")
        _fsync_directory(sealed)
        _make_read_only(sealed)
        _fsync_read_only_tree(sealed)

        for project in selected_projects:
            _check_global_deadline()
            try:
                selected, selected_root = campaign.load_mirror_authority(
                    authority_path,
                    manifest,
                    project["id"],
                    expected_project_ids=selected_ids,
                )
            except campaign.CampaignError as error:
                raise SealError(
                    f"sealed authority is not verifier-compatible: {error}"
                ) from error
            if selected["id"] != project["id"] or selected_root != sealed.absolute():
                raise SealError("sealed authority verifier returned a different identity")

        if destination.exists() or destination.is_symlink():
            raise SealError(f"output already exists: {destination}")
        sealed.chmod(0o755)
        _rename_noreplace(sealed, destination)
        moved = True
        moved_identity = _directory_identity(destination)
        destination.chmod(0o555)
        _check_global_deadline()
        _fsync_directory(destination)
        final_authority = destination / "authority.json"
        for project in selected_projects:
            _check_global_deadline()
            try:
                selected, selected_root = campaign.load_mirror_authority(
                    final_authority,
                    manifest,
                    project["id"],
                    expected_project_ids=selected_ids,
                )
            except campaign.CampaignError as error:
                raise SealError(
                    f"published authority is not verifier-compatible: {error}"
                ) from error
            if selected["id"] != project["id"] or selected_root != destination:
                raise SealError("published authority verifier returned a different identity")
        _fsync_directory(parent)
        _check_global_deadline()
        _remove_owned_tree(workspace, workspace_identity)
        _check_global_deadline()
        published = True
        result_authority = final_authority
    except BaseException as error:
        failure = error
    finally:
        _GIT_DEADLINE.reset(deadline_token)
        budget_cleanup_ok = True
        try:
            budget_context.__exit__(None, None, None)
        except BaseException as error:
            budget_cleanup_ok = False
            cleanup_failures.append(f"workspace budget: {error}")
        if not published and budget_cleanup_ok:
            if moved and moved_identity is not None:
                try:
                    _remove_owned_tree(destination, moved_identity)
                except BaseException as error:
                    cleanup_failures.append(f"published destination: {error}")
            if workspace.exists() or workspace.is_symlink():
                try:
                    _remove_owned_tree(workspace, workspace_identity)
                except BaseException as error:
                    cleanup_failures.append(f"workspace: {error}")
        elif not published:
            cleanup_failures.append(
                "filesystem rollback withheld because process quiescence was not proven"
            )
    if cleanup_failures:
        detail = "; ".join(cleanup_failures)
        if failure is not None:
            raise SealError(f"{failure}; rollback failed: {detail}") from failure
        raise SealError(f"mirror cleanup failed: {detail}")
    if failure is not None:
        raise failure
    if result_authority is None:
        raise SealError("sealed mirror publication produced no authority")
    return result_authority


def _source_argument(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("source must be URL=PATH")
    upstream, raw_path = value.split("=", 1)
    if not upstream or not raw_path:
        raise argparse.ArgumentTypeError("source must be URL=PATH")
    return upstream, Path(raw_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Staging contract: set --output to the authority layout's mirrors "
            "directory; the consumer path is OUTPUT/authority.json."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=SCRIPT_DIR / "realworld_manifest.json",
    )
    parser.add_argument("--tier", default=REQUIRED_TIER)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--source",
        action="append",
        default=[],
        type=_source_argument,
        metavar="URL=PATH",
        help="explicit local source mapping; repeat for every recursive upstream",
    )
    mode.add_argument(
        "--fetch-online",
        action="store_true",
        help="explicitly permit HTTPS staging fetches",
    )
    parser.add_argument(
        "--git-timeout-seconds",
        type=int,
        default=DEFAULT_GIT_TIMEOUT_SECONDS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_map: dict[str, Path] = {}
    try:
        for upstream, path in args.source:
            if upstream in source_map:
                raise SealError(f"duplicate source mapping for {upstream}")
            source_map[upstream] = path
        authority = seal_mirror_authority(
            args.manifest,
            args.output,
            tier=args.tier,
            sources=source_map,
            fetch_online=args.fetch_online,
            git_timeout_seconds=args.git_timeout_seconds,
        )
        print(f"CODESKEPTIC_REALWORLD_MIRROR_SEALED {authority}")
        return 0
    except SealError as error:
        print(f"CODESKEPTIC_REALWORLD_MIRROR_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
