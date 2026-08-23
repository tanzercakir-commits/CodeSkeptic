#!/usr/bin/env python3
"""Seal and verify fail-closed GitHub hosted exact-head evidence.

The authority is deliberately offline.  A caller first captures complete raw
GitHub API responses and downloaded archives, then this module re-derives the
ten required gates from those immutable inputs and the exact Git commit.  It
does not push refs, dispatch workflows, or make network requests.
"""

from __future__ import annotations

import argparse
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
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence
from urllib.parse import urlsplit

try:
    import yaml
    from yaml.events import AliasEvent
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
except ImportError:  # pragma: no cover - exercised only on an incomplete host
    yaml = None
    AliasEvent = object  # type: ignore[assignment,misc]
    MappingNode = Node = ScalarNode = SequenceNode = object  # type: ignore[assignment,misc]


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import run_stability_campaign as stability  # noqa: E402


SELECTION_SCHEMA = "codeskeptic-hosted-exact-head-selection-v1"
LOG_DOWNLOAD_SCHEMA = "codeskeptic-github-attempt-log-download-v2"
ARTIFACT_DOWNLOAD_SCHEMA = "codeskeptic-github-artifact-download-v1"
GITHUB_API_VERSION = "2022-11-28"
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_WORKFLOW_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024
MAX_COLLECTION_ITEMS = 10_000
MAX_ARCHIVE_FILES = 256
MAX_ARCHIVE_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024 * 1024
MAX_INVENTORY_ENTRIES = 4096
MAX_EVIDENCE_TOTAL_BYTES = MAX_ARCHIVE_TOTAL_BYTES + 512 * 1024 * 1024
PROVIDER_FILTERED_RESULT_CAP = 1000
MAX_ZIP_ENTRIES = 1_000_000
MAX_ZIP_UNCOMPRESSED_BYTES = 64 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
GIT_EXECUTABLE = "/usr/bin/git"
MAX_SOURCE_METADATA_BYTES = 4096
MAX_SOURCE_STDERR_BYTES = 1024 * 1024
SOURCE_COMMAND_TIMEOUT_SECONDS = 30.0
SOURCE_COMMAND_GRACE_SECONDS = 1.0
PR_SET_CHILD_SUBREAPER = 36
_SOURCE_SUBREAPER_ENABLED = False
_SOURCE_SUBREAPER_PID: int | None = None

GATE_WORKFLOWS = {
    "build-and-test": ".github/workflows/ci.yml",
    "resource-budget-macos": ".github/workflows/ci.yml",
    "fuzz-smoke": ".github/workflows/ci.yml",
    "sanitizer-address": ".github/workflows/ci.yml",
    "sanitizer-undefined": ".github/workflows/ci.yml",
    "windows-native": ".github/workflows/windows.yml",
    "docs-structure": ".github/workflows/docs.yml",
    "docs-quickstart": ".github/workflows/docs.yml",
    "docker": ".github/workflows/docker.yml",
    "juliet": ".github/workflows/juliet.yml",
}

GATE_JOB_KEYS = {
    "build-and-test": "build-and-test",
    "resource-budget-macos": "resource-budget-macos",
    "fuzz-smoke": "fuzz-smoke",
    "sanitizer-address": "sanitizer-runtime",
    "sanitizer-undefined": "sanitizer-runtime",
    "windows-native": "windows-native",
    "docs-structure": "structure",
    "docs-quickstart": "quickstart",
    "docker": "build",
    "juliet": "juliet",
}

ALLOWED_JOB_IF = {
    "juliet": (
        "github.event_name != 'pull_request' || "
        "github.event.pull_request.draft == false"
    ),
}

CHECK_NAMES = {
    "build-and-test": "build-and-test",
    "resource-budget-macos": "resource-budget-macos",
    "fuzz-smoke": "fuzz-smoke",
    "sanitizer-address": "sanitizer-runtime (address)",
    "sanitizer-undefined": "sanitizer-runtime (undefined)",
    "windows-native": "windows-native",
    "docs-structure": "structure",
    "docs-quickstart": "quickstart",
    "docker": "build",
    "juliet": "juliet",
}

BASE_API_FILES = (
    "api/workflow-runs.json",
    "api/check-suites.json",
    "api/check-runs.json",
    "api/status-refs.json",
)

if list(GATE_WORKFLOWS) != stability.REQUIRED_HOSTED_GATES:
    raise RuntimeError("hosted gate/workflow policy drift")
if list(CHECK_NAMES) != stability.REQUIRED_HOSTED_GATES:
    raise RuntimeError("hosted gate/check policy drift")
if list(GATE_JOB_KEYS) != stability.REQUIRED_HOSTED_GATES:
    raise RuntimeError("hosted gate/job policy drift")


class HostedEvidenceError(RuntimeError):
    """The hosted evidence is missing, mutable, or violates fixed policy."""


class _HostedPublicationCollision(HostedEvidenceError):
    """Atomic no-replace publication observed a foreign destination."""


if yaml is not None:
    class _WorkflowString(str):
        """A YAML string retaining the provider scalar style for policy checks."""

        yaml_style: str | None

        def __new__(cls, value: str, style: str | None) -> _WorkflowString:
            instance = super().__new__(cls, value)
            instance.yaml_style = style
            return instance


    class _StrictWorkflowLoader(yaml.SafeLoader):
        """SafeLoader variant that rejects ambiguous or inherited mappings."""

        def construct_mapping(self, node: Node, deep: bool = False) -> dict[Any, Any]:
            if not isinstance(node, MappingNode):
                raise HostedEvidenceError("workflow YAML mapping is malformed")
            keys: set[Any] = set()
            for key_node, _ in node.value:
                if (
                    getattr(key_node, "tag", None) == "tag:yaml.org,2002:merge"
                    or (
                        isinstance(key_node, ScalarNode)
                        and key_node.value == "<<"
                    )
                ):
                    raise HostedEvidenceError(
                        "workflow YAML merge aliases are inadmissible"
                    )
                key = self.construct_object(key_node, deep=True)
                try:
                    duplicate = key in keys
                except TypeError as error:
                    raise HostedEvidenceError(
                        "workflow YAML mapping key is not scalar"
                    ) from error
                if duplicate:
                    raise HostedEvidenceError(
                        f"workflow YAML duplicate key is inadmissible: {key!r}"
                    )
                keys.add(key)
            return super().construct_mapping(node, deep=deep)


    def _construct_workflow_string(
        loader: _StrictWorkflowLoader, node: ScalarNode
    ) -> _WorkflowString:
        return _WorkflowString(loader.construct_scalar(node), node.style)


    _StrictWorkflowLoader.add_constructor(
        "tag:yaml.org,2002:str", _construct_workflow_string
    )


class SourceAuthority(Protocol):
    def repository_identity(self) -> str: ...
    def resolve_revision(self, revision: str) -> str: ...
    def tree_sha1(self, revision: str) -> str: ...
    def read_file(self, revision: str, path: str) -> bytes: ...


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        maximum_stdout: int,
        maximum_stderr: int,
        timeout_seconds: float,
    ) -> bytes: ...


def _source_proc_record(pid: int) -> tuple[int, int, int] | None:
    try:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        tail = payload[payload.rfind(")") + 2 :].split()
        return int(tail[1]), int(tail[2]), int(tail[19])
    except (OSError, ValueError, IndexError):
        return None


def _enable_source_subreaper() -> None:
    global _SOURCE_SUBREAPER_ENABLED, _SOURCE_SUBREAPER_PID
    current_pid = os.getpid()
    if _SOURCE_SUBREAPER_ENABLED and _SOURCE_SUBREAPER_PID == current_pid:
        return
    if os.name != "posix" or not Path("/proc").is_dir():
        raise HostedEvidenceError(
            "source authority requires Linux /proc process containment"
        )
    try:
        library = ctypes.CDLL(None, use_errno=True)
        result = library.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    except (AttributeError, OSError) as error:
        raise HostedEvidenceError(
            f"cannot enable source authority subreaper: {error}"
        ) from error
    if result != 0:
        code = ctypes.get_errno()
        raise HostedEvidenceError(
            f"cannot enable source authority subreaper: {os.strerror(code)}"
        )
    _SOURCE_SUBREAPER_ENABLED = True
    _SOURCE_SUBREAPER_PID = current_pid


def _source_child_table_empty() -> bool:
    """Reap exited children and return true only after kernel ECHILD."""

    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        except InterruptedError:
            continue
        except OSError as error:
            raise HostedEvidenceError(
                f"cannot inspect source authority child table: {error}"
            ) from error
        if pid == 0:
            return False


def _require_dedicated_source_process() -> None:
    if threading.active_count() != 1:
        raise HostedEvidenceError(
            "source authority requires a dedicated single-thread process"
        )
    _enable_source_subreaper()
    if not _source_child_table_empty():
        raise HostedEvidenceError(
            "source authority found a pre-existing child process"
        )


def _refresh_source_descendants(root_pid: int, known: dict[int, int]) -> None:
    records: dict[int, tuple[int, int]] = {}
    try:
        names = os.listdir("/proc")
    except OSError as error:
        raise HostedEvidenceError(
            f"cannot enumerate source authority descendants: {error}"
        ) from error
    for name in names:
        if not name.isascii() or not name.isdigit():
            continue
        pid = int(name)
        record = _source_proc_record(pid)
        if record is not None:
            records[pid] = (record[0], record[2])
    root = _source_proc_record(root_pid)
    if root is not None:
        known.setdefault(root_pid, root[2])
    parents = {root_pid, *known}
    changed = True
    while changed:
        changed = False
        for pid, (parent, started) in records.items():
            if pid in known:
                continue
            if parent in parents or parent == os.getpid():
                known[pid] = started
                parents.add(pid)
                changed = True


def _source_pid_matches(pid: int, started: int) -> bool:
    record = _source_proc_record(pid)
    return record is not None and record[2] == started


def _source_group_has_known_member(pgid: int, known: dict[int, int]) -> bool:
    for pid, started in known.items():
        record = _source_proc_record(pid)
        if record is not None and record[2] == started and record[1] == pgid:
            return True
    return False


def _signal_source_tree(
    process: subprocess.Popen[bytes], known: dict[int, int], signal_number: int
) -> None:
    _refresh_source_descendants(process.pid, known)
    if _source_group_has_known_member(process.pid, known):
        try:
            os.killpg(process.pid, signal_number)
        except ProcessLookupError:
            pass
    for pid, started in list(known.items()):
        if _source_pid_matches(pid, started):
            try:
                os.kill(pid, signal_number)
            except ProcessLookupError:
                pass


def _terminate_source_tree(
    process: subprocess.Popen[bytes], known: dict[int, int]
) -> None:
    for signal_number, interval in (
        (signal.SIGTERM, 0.25),
        (signal.SIGKILL, SOURCE_COMMAND_GRACE_SECONDS),
    ):
        deadline = time.monotonic() + interval
        while True:
            _signal_source_tree(process, known, signal_number)
            process.poll()
            child_table_empty = _source_child_table_empty()
            _refresh_source_descendants(process.pid, known)
            alive = any(
                _source_pid_matches(pid, started)
                for pid, started in known.items()
            )
            if (
                child_table_empty
                and not alive
                and not _source_group_has_known_member(process.pid, known)
            ):
                return
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
    raise HostedEvidenceError("source authority descendant cleanup was incomplete")


def _require_source_tree_empty(
    process: subprocess.Popen[bytes], known: dict[int, int], deadline: float
) -> None:
    grace = min(deadline, time.monotonic() + SOURCE_COMMAND_GRACE_SECONDS)
    while True:
        process.poll()
        _refresh_source_descendants(process.pid, known)
        child_table_empty = _source_child_table_empty()
        _refresh_source_descendants(process.pid, known)
        alive = any(
            _source_pid_matches(pid, started) for pid, started in known.items()
        )
        if (
            child_table_empty
            and not alive
            and not _source_group_has_known_member(process.pid, known)
        ):
            return
        if time.monotonic() >= grace:
            raise HostedEvidenceError(
                "source authority command left a descendant process"
            )
        time.sleep(0.01)


class SubprocessCommandRunner:
    """Shell-free read-only command adapter used by ``GitSourceAuthority``."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        maximum_stdout: int,
        maximum_stderr: int,
        timeout_seconds: float,
    ) -> bytes:
        if (
            isinstance(maximum_stdout, bool)
            or not isinstance(maximum_stdout, int)
            or maximum_stdout < 1
            or isinstance(maximum_stderr, bool)
            or not isinstance(maximum_stderr, int)
            or maximum_stderr < 1
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise HostedEvidenceError("source authority command limits are malformed")
        _require_dedicated_source_process()
        environment = {
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": "/tmp",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ASKPASS": "/bin/false",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "SSH_ASKPASS": "/bin/false",
        }
        process: subprocess.Popen[bytes] | None = None
        selector: selectors.BaseSelector | None = None
        known: dict[int, int] = {}
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {"stdout": maximum_stdout, "stderr": maximum_stderr}
        deadline = time.monotonic() + float(timeout_seconds)
        try:
            selector = selectors.DefaultSelector()
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                close_fds=True,
                start_new_session=True,
            )
            record = _source_proc_record(process.pid)
            if record is not None:
                known[process.pid] = record[2]
            if process.stdout is None or process.stderr is None:
                raise HostedEvidenceError("source authority pipes are unavailable")
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                _refresh_source_descendants(process.pid, known)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HostedEvidenceError("source authority command timed out")
                events = selector.select(min(remaining, 0.05))
                for key, _mask in events:
                    block = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    target = buffers[key.data]
                    if len(target) + len(block) > limits[key.data]:
                        raise HostedEvidenceError(
                            f"source authority {key.data} exceeded its size limit"
                        )
                    target.extend(block)
            while process.poll() is None:
                _refresh_source_descendants(process.pid, known)
                if time.monotonic() >= deadline:
                    raise HostedEvidenceError("source authority command timed out")
                time.sleep(0.01)
            _require_source_tree_empty(process, known, deadline)
            returncode = process.returncode
            assert returncode is not None
        except HostedEvidenceError:
            raise
        except (OSError, subprocess.SubprocessError) as error:
            raise HostedEvidenceError(
                f"cannot execute source authority: {error}"
            ) from error
        finally:
            active_error = sys.exc_info()[1]
            cleanup_errors: list[str] = []
            if process is not None:
                try:
                    if (
                        process.poll() is None
                        or not _source_child_table_empty()
                        or any(
                            _source_pid_matches(pid, started)
                            for pid, started in known.items()
                        )
                    ):
                        _terminate_source_tree(process, known)
                except HostedEvidenceError as error:
                    cleanup_errors.append(str(error))
            if selector is not None:
                try:
                    selector.close()
                except OSError as error:
                    cleanup_errors.append(f"cannot close source selector: {error}")
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        try:
                            stream.close()
                        except OSError as error:
                            cleanup_errors.append(
                                f"cannot close source command pipe: {error}"
                            )
            if cleanup_errors:
                detail = "; ".join(cleanup_errors)
                if active_error is not None:
                    raise HostedEvidenceError(
                        f"{active_error}; source cleanup failed: {detail}"
                    ) from active_error
                raise HostedEvidenceError(f"source cleanup failed: {detail}")
        if returncode != 0:
            detail = bytes(buffers["stderr"]).decode("utf-8", "replace").strip()
            raise HostedEvidenceError(
                f"source authority command failed ({returncode}): {detail}"
            )
        return bytes(buffers["stdout"])


class GitSourceAuthority:
    """Read exact commit/tree/blob authority from a local Git repository."""

    def __init__(
        self,
        repository_root: Path,
        *,
        repository: str,
        runner: CommandRunner | None = None,
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.repository = _repository(repository)
        self.runner = runner or SubprocessCommandRunner()

    def _git(self, *arguments: str) -> bytes:
        return self.runner.run(
            (
                GIT_EXECUTABLE,
                "--no-replace-objects",
                "-c", "core.hooksPath=/dev/null",
                "-c", "core.fsmonitor=false",
                "-c", "credential.helper=",
                "-c", "init.templateDir=",
                *arguments,
            ),
            cwd=self.repository_root,
            maximum_stdout=MAX_SOURCE_METADATA_BYTES,
            maximum_stderr=MAX_SOURCE_STDERR_BYTES,
            timeout_seconds=SOURCE_COMMAND_TIMEOUT_SECONDS,
        )

    def _git_blob(self, *arguments: str) -> bytes:
        return self.runner.run(
            (
                GIT_EXECUTABLE,
                "--no-replace-objects",
                "-c", "core.hooksPath=/dev/null",
                "-c", "core.fsmonitor=false",
                "-c", "credential.helper=",
                "-c", "init.templateDir=",
                *arguments,
            ),
            cwd=self.repository_root,
            maximum_stdout=MAX_WORKFLOW_BYTES,
            maximum_stderr=MAX_SOURCE_STDERR_BYTES,
            timeout_seconds=SOURCE_COMMAND_TIMEOUT_SECONDS,
        )

    def repository_identity(self) -> str:
        # A checkout's mutable remote configuration is not source authority.
        # Repository identity is an explicit input, while Git supplies only the
        # exact commit/tree/blob bytes used by the offline verifier.
        return self.repository

    def resolve_revision(self, revision: str) -> str:
        _git_sha(revision, "source revision")
        raw = self._git("rev-parse", "--verify", f"{revision}^{{commit}}")
        value = _single_ascii_line(raw, "resolved source revision")
        _git_sha(value, "resolved source revision")
        return value

    def tree_sha1(self, revision: str) -> str:
        _git_sha(revision, "source revision")
        raw = self._git("rev-parse", f"{revision}^{{tree}}")
        value = _single_ascii_line(raw, "source tree")
        _git_sha(value, "source tree")
        return value

    def read_file(self, revision: str, path: str) -> bytes:
        _git_sha(revision, "source revision")
        _relative_path(path, "workflow")
        if path not in set(GATE_WORKFLOWS.values()):
            raise HostedEvidenceError("workflow path is outside fixed hosted policy")
        object_name = f"{revision}:{path}"
        kind = _single_ascii_line(
            self._git("cat-file", "-t", object_name), "workflow object type"
        )
        if kind != "blob":
            raise HostedEvidenceError("workflow object is not a Git blob")
        size_text = _single_ascii_line(
            self._git("cat-file", "-s", object_name), "workflow blob size"
        )
        if not size_text.isascii() or not size_text.isdecimal():
            raise HostedEvidenceError("workflow blob size is malformed")
        expected_size = int(size_text)
        if expected_size < 1 or expected_size > MAX_WORKFLOW_BYTES:
            raise HostedEvidenceError("workflow blob size exceeds the safety limit")
        blob = self._git_blob("cat-file", "blob", object_name)
        if len(blob) != expected_size:
            raise HostedEvidenceError("workflow blob changed during bounded capture")
        return blob


class OfflineSnapshotInputs:
    """Filesystem adapter for previously captured API responses and archives."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, relative: str) -> Path:
        _relative_path(relative, "offline input")
        return self.root / relative


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _single_ascii_line(raw: bytes, label: str) -> str:
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise HostedEvidenceError(f"{label} is not ASCII") from error
    if not value or "\n" in value or "\r" in value:
        raise HostedEvidenceError(f"{label} is malformed")
    return value


def _git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA1.fullmatch(value) is None:
        raise HostedEvidenceError(f"{label} is not an exact Git SHA-1")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise HostedEvidenceError(f"{label} is not a SHA-256 digest")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise HostedEvidenceError(f"{label} is not a positive integer")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HostedEvidenceError(f"{label} is not a nonnegative integer")
    return value


def _repository(value: Any) -> str:
    if not isinstance(value, str) or REPOSITORY.fullmatch(value) is None:
        raise HostedEvidenceError("repository identity is malformed")
    components = value.split("/", 1)
    if value.endswith(".git"):
        raise HostedEvidenceError("repository identity must not contain .git")
    if any(component in {".", ".."} for component in components):
        raise HostedEvidenceError("repository identity has inadmissible components")
    return value


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HostedEvidenceError(f"{label} path is malformed")
    path = Path(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or path.as_posix() != value
    ):
        raise HostedEvidenceError(f"{label} path is inadmissible")
    return value


def _https_url(value: Any, label: str, *, hosts: set[str] | None = None) -> str:
    if not isinstance(value, str):
        raise HostedEvidenceError(f"{label} URL is malformed")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (hosts is not None and parsed.hostname not in hosts)
    ):
        raise HostedEvidenceError(f"{label} URL is malformed")
    return value


def _github_html_url(value: Any, repository: str, label: str) -> str:
    url = _https_url(value, label, hosts={"github.com"})
    if not url.startswith(f"https://github.com/{repository}/"):
        raise HostedEvidenceError(f"{label} URL repository drift")
    return url


def _github_api_url(value: Any, repository: str, label: str) -> str:
    url = _https_url(value, label, hosts={"api.github.com"})
    if not url.startswith(f"https://api.github.com/repos/{repository}/"):
        raise HostedEvidenceError(f"{label} URL repository drift")
    return url


def _exact_provider_url(value: Any, expected: str, label: str) -> str:
    _https_url(value, label, hosts={"github.com", "api.github.com"})
    if value != expected:
        raise HostedEvidenceError(f"{label} URL does not bind its exact authority ID")
    return value


def _exact_job_html_url(
    value: Any,
    repository: str,
    run_id: int,
    job_id: int,
    *,
    label: str = "attempt job",
) -> str:
    url = _github_html_url(value, repository, label)
    admitted = {
        f"https://github.com/{repository}/actions/runs/{run_id}/job/{job_id}",
        f"https://github.com/{repository}/runs/{run_id}/jobs/{job_id}",
    }
    if url not in admitted:
        raise HostedEvidenceError(f"{label} URL does not bind exact run/job IDs")
    return url


def _download_redirect_origin(value: Any, label: str) -> str:
    """Validate a redacted origin for a GitHub signed archive redirect."""

    origin = _https_url(value, label)
    parsed = urlsplit(origin)
    hostname = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError as error:
        raise HostedEvidenceError(f"{label} is malformed") from error
    if (
        port not in {None, 443}
        or parsed.path not in {"", "/"}
        or parsed.query
        or not (
            hostname.endswith(".actions.githubusercontent.com")
            or hostname.endswith(".blob.core.windows.net")
        )
    ):
        raise HostedEvidenceError(f"{label} is not an admissible GitHub archive origin")
    canonical = f"https://{hostname}"
    if origin.rstrip("/") != canonical:
        raise HostedEvidenceError(f"{label} is not a canonical origin")
    return canonical


def _validate_download_authority(
    value: Any,
    *,
    schema: str,
    repository: str,
    identity_fields: dict[str, int],
    request_url: str,
    archive_digest: str,
    archive_size: int,
    label: str,
) -> dict[str, Any]:
    fields = {
        "schema",
        "repository",
        *identity_fields,
        "request_url",
        "api_version",
        "redirect_http_status",
        "redirect_url_origin",
        "redirect_url_sha256",
        "download_http_status",
        "content_type",
        "archive_sha256",
        "archive_size",
    }
    authority = _exact_dict(value, fields, label)
    if authority["schema"] != schema:
        raise HostedEvidenceError(f"{label} schema drift")
    if authority["repository"] != repository:
        raise HostedEvidenceError(f"{label} repository drift")
    for field, expected in identity_fields.items():
        actual = _positive_integer(authority[field], f"{label} {field}")
        if actual != expected:
            raise HostedEvidenceError(f"{label} identity drift")
    _exact_provider_url(authority["request_url"], request_url, f"{label} request")
    if authority["api_version"] != GITHUB_API_VERSION:
        raise HostedEvidenceError(f"{label} API version drift")
    if authority["redirect_http_status"] != 302:
        raise HostedEvidenceError(f"{label} did not observe the required 302 redirect")
    _download_redirect_origin(authority["redirect_url_origin"], f"{label} redirect origin")
    _sha256(authority["redirect_url_sha256"], f"{label} redirect URL")
    if authority["download_http_status"] != 200:
        raise HostedEvidenceError(f"{label} did not observe a successful second hop")
    content_type = authority["content_type"]
    if (
        not isinstance(content_type, str)
        or content_type.split(";", 1)[0].strip().lower()
        not in {"application/zip", "application/octet-stream"}
    ):
        raise HostedEvidenceError(f"{label} content type drift")
    if (
        authority["archive_sha256"] != archive_digest
        or authority["archive_size"] != archive_size
    ):
        raise HostedEvidenceError(f"{label} archive binding drift")
    return authority


def _exact_dict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise HostedEvidenceError(f"{label} has an invalid field set")
    return value


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HostedEvidenceError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _parse_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_object_no_duplicates)
    except HostedEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HostedEvidenceError(f"{label} is not valid JSON") from error


def _metadata(stat_result: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_mode,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    )


def _open_regular(path: Path, label: str) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HostedEvidenceError(f"cannot open {label}: {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise HostedEvidenceError(f"{label} is not a regular file: {path}")
        if before.st_nlink != 1:
            raise HostedEvidenceError(f"{label} hardlink is inadmissible: {path}")
        return descriptor, before
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    descriptor, before = _open_regular(path, label)
    try:
        if before.st_size < 1 or before.st_size > maximum:
            raise HostedEvidenceError(f"{label} size is inadmissible: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise HostedEvidenceError(f"{label} changed while being read: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise HostedEvidenceError(f"{label} grew while being read: {path}")
        after = os.fstat(descriptor)
        if _metadata(before) != _metadata(after):
            raise HostedEvidenceError(f"{label} changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _hash_regular(
    path: Path,
    maximum: int,
    label: str,
    *,
    progress: Callable[[], None] | None = None,
) -> tuple[str, int]:
    descriptor, before = _open_regular(path, label)
    try:
        if progress is not None:
            progress()
        if before.st_size < 1 or before.st_size > maximum:
            raise HostedEvidenceError(f"{label} size is inadmissible: {path}")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            if progress is not None:
                progress()
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if progress is not None:
                progress()
            if not chunk:
                raise HostedEvidenceError(f"{label} changed while being hashed: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise HostedEvidenceError(f"{label} grew while being hashed: {path}")
        after = os.fstat(descriptor)
        if _metadata(before) != _metadata(after):
            raise HostedEvidenceError(f"{label} changed while being hashed: {path}")
        return digest.hexdigest(), before.st_size
    finally:
        os.close(descriptor)


def _read_json(path: Path, label: str) -> tuple[Any, bytes]:
    raw = _read_regular(path, MAX_JSON_BYTES, label)
    return _parse_json(raw, label), raw


def _write_new(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(value)
        while view:
            count = os.write(descriptor, view)
            if count < 1:
                raise HostedEvidenceError(f"short write while sealing {path}")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_regular(source: Path, target: Path, maximum: int, label: str) -> None:
    source_descriptor, before = _open_regular(source, label)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    target_descriptor = -1
    try:
        if before.st_size < 1 or before.st_size > maximum:
            raise HostedEvidenceError(f"{label} size is inadmissible: {source}")
        target_descriptor = os.open(target, flags, 0o600)
        remaining = before.st_size
        while remaining:
            chunk = os.read(source_descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise HostedEvidenceError(f"{label} changed while being copied: {source}")
            offset = 0
            while offset < len(chunk):
                count = os.write(target_descriptor, chunk[offset:])
                if count < 1:
                    raise HostedEvidenceError(f"short write while sealing {target}")
                offset += count
            remaining -= len(chunk)
        if os.read(source_descriptor, 1):
            raise HostedEvidenceError(f"{label} grew while being copied: {source}")
        after = os.fstat(source_descriptor)
        if _metadata(before) != _metadata(after):
            raise HostedEvidenceError(f"{label} changed while being copied: {source}")
        os.fsync(target_descriptor)
    except BaseException:
        if target_descriptor >= 0:
            os.close(target_descriptor)
            target_descriptor = -1
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_descriptor)
        if target_descriptor >= 0:
            os.close(target_descriptor)


def _inventory(root: Path, label: str) -> set[str]:
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise HostedEvidenceError(f"cannot inspect {label} root: {error}") from error
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise HostedEvidenceError(f"{label} root is not a real directory")
    result: set[str] = set()
    entry_count = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        entry_count += len(directory_names) + len(file_names)
        if entry_count > MAX_INVENTORY_ENTRIES:
            raise HostedEvidenceError(f"{label} inventory exceeds entry budget")
        for name in directory_names:
            candidate = current_path / name
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise HostedEvidenceError(f"{label} symlink is inadmissible: {candidate}")
            if not stat.S_ISDIR(mode):
                raise HostedEvidenceError(f"{label} special path is inadmissible: {candidate}")
        for name in file_names:
            candidate = current_path / name
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise HostedEvidenceError(f"{label} symlink is inadmissible: {candidate}")
            if not stat.S_ISREG(mode):
                raise HostedEvidenceError(f"{label} special file is inadmissible: {candidate}")
            relative = candidate.relative_to(root).as_posix()
            _relative_path(relative, label)
            if relative in result:
                raise HostedEvidenceError(f"{label} contains an aliased path")
            result.add(relative)
    return result


def _validate_archive_budget(
    root: Path, relatives: Sequence[str], label: str,
) -> tuple[int, int]:
    archives = sorted(set(relatives))
    if len(archives) != len(relatives):
        raise HostedEvidenceError(f"{label} archive paths are duplicated")
    if len(archives) > MAX_ARCHIVE_FILES:
        raise HostedEvidenceError(f"{label} archive file budget exceeded")
    total = 0
    for relative in archives:
        path = root / _relative_path(relative, f"{label} archive")
        descriptor, metadata = _open_regular(path, f"{label} archive")
        os.close(descriptor)
        if metadata.st_size < 1 or metadata.st_size > MAX_ARCHIVE_BYTES:
            raise HostedEvidenceError(f"{label} archive size is inadmissible")
        total += metadata.st_size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise HostedEvidenceError(
                f"{label} aggregate archive byte budget exceeded"
            )
    return len(archives), total


def _validate_selection(value: Any, repository: str, revision: str) -> list[dict[str, int | str]]:
    selection = _exact_dict(
        value, {"schema", "repository", "revision", "gates"}, "selection"
    )
    if selection["schema"] != SELECTION_SCHEMA:
        raise HostedEvidenceError("selection schema drift")
    if selection["repository"] != repository:
        raise HostedEvidenceError("selection repository drift")
    if selection["revision"] != revision:
        raise HostedEvidenceError("selection exact-head revision drift")
    gates = selection["gates"]
    if not isinstance(gates, list) or len(gates) != len(stability.REQUIRED_HOSTED_GATES):
        raise HostedEvidenceError("selection required gate matrix is incomplete")
    normalized: list[dict[str, int | str]] = []
    check_ids: set[int] = set()
    path_runs: dict[str, int] = {}
    for expected_gate, raw in zip(stability.REQUIRED_HOSTED_GATES, gates, strict=True):
        gate = _exact_dict(
            raw, {"gate_id", "workflow_run_id", "check_run_id"}, "selection gate"
        )
        if gate["gate_id"] != expected_gate:
            raise HostedEvidenceError("selection required gate order drift")
        run_id = _positive_integer(gate["workflow_run_id"], "selection workflow run ID")
        check_id = _positive_integer(gate["check_run_id"], "selection check-run ID")
        if check_id in check_ids:
            raise HostedEvidenceError("selection check-run IDs are duplicated")
        check_ids.add(check_id)
        workflow_path = GATE_WORKFLOWS[expected_gate]
        prior = path_runs.setdefault(workflow_path, run_id)
        if prior != run_id:
            raise HostedEvidenceError("selection workflow run binding is incoherent")
        normalized.append({
            "gate_id": expected_gate,
            "workflow_run_id": run_id,
            "check_run_id": check_id,
        })
    return normalized


def _complete_collection(
    value: Any, count_key: str, items_key: str, label: str
) -> list[Any]:
    if not isinstance(value, dict) or count_key not in value or items_key not in value:
        raise HostedEvidenceError(f"{label} API snapshot is malformed")
    count = _nonnegative_integer(value[count_key], f"{label} total count")
    if count > MAX_COLLECTION_ITEMS:
        raise HostedEvidenceError(f"{label} collection item budget exceeded")
    items = value[items_key]
    if not isinstance(items, list):
        raise HostedEvidenceError(f"{label} API collection is malformed")
    if count != len(items):
        raise HostedEvidenceError(f"{label} API snapshot is incomplete")
    return items


def _validate_artifact_attempt(raw: dict[str, Any], selected_attempt: int) -> None:
    """Bind artifacts to an attempt without timestamp inference.

    GitHub's run-level artifact collection does not expose an attempt number.
    Attempt one is unambiguous because no earlier rerun can exist.  Later
    attempts are always inadmissible: an extra locally supplied field is not
    part of the provider schema and cannot distinguish stale rerun artifacts.
    """

    if selected_attempt != 1:
        raise HostedEvidenceError(
            "artifact attempt provenance is unavailable for rerun evidence"
        )
    if "run_attempt" not in raw:
        return
    artifact_attempt = _positive_integer(
        raw.get("run_attempt"), "artifact run attempt"
    )
    if artifact_attempt != selected_attempt:
        raise HostedEvidenceError("artifact attempt provenance drift")


def _status_template(gate: str) -> str:
    leaf = "sanitizer-${{ matrix.sanitizer }}" if gate.startswith("sanitizer-") else gate
    return (
        "${{ github.sha }}:refs/status/${{ github.sha }}/"
        f"{leaf}/${{{{ job.status }}}}"
    )


def _workflow_path(value: Any, expected: str, head_branch: Any) -> str:
    if not isinstance(value, str) or not isinstance(head_branch, str) or not head_branch:
        raise HostedEvidenceError("workflow path/ref authority is malformed")
    if "@" in value:
        path, suffix = value.rsplit("@", 1)
        if suffix not in {head_branch, f"refs/heads/{head_branch}"}:
            raise HostedEvidenceError("workflow path ref does not match the run head")
    else:
        path = value
    if path != expected:
        raise HostedEvidenceError("workflow run binding path drift")
    return path


def _parse_workflow(blob: bytes) -> dict[Any, Any]:
    if yaml is None:
        raise HostedEvidenceError("PyYAML is required for workflow authority")
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HostedEvidenceError("workflow YAML is not UTF-8") from error
    try:
        for event in yaml.parse(text, Loader=_StrictWorkflowLoader):
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None):
                raise HostedEvidenceError(
                    "workflow YAML anchors and aliases are inadmissible"
                )
        value = yaml.load(text, Loader=_StrictWorkflowLoader)
    except HostedEvidenceError:
        raise
    except yaml.YAMLError as error:
        raise HostedEvidenceError(f"workflow YAML structure is malformed: {error}") from error
    if not isinstance(value, dict):
        raise HostedEvidenceError("workflow YAML document is not a mapping")
    return value


def _exact_status_run(value: Any, template: str) -> bool:
    if not isinstance(value, str) or getattr(value, "yaml_style", None) != "|":
        return False
    body = value[:-1] if value.endswith("\n") else value
    if body.endswith("\n"):
        return False
    raw_lines = body.split("\n")
    if any(line.rstrip() != line for line in raw_lines):
        return False
    lines = tuple(line.lstrip() for line in raw_lines)
    return lines in {
        (f'git push --force origin "{template}"',),
        ("git push --force origin \\", f'"{template}"'),
    }


def _scalar_occurrences(value: Any, needle: str) -> int:
    if isinstance(value, str):
        return value.count(needle)
    if isinstance(value, dict):
        return sum(
            _scalar_occurrences(key, needle) + _scalar_occurrences(child, needle)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return sum(_scalar_occurrences(child, needle) for child in value)
    return 0


def _validate_status_policy(blob: bytes, gate: str) -> None:
    """Require one exact status push in the parsed executable job structure."""

    workflow = _parse_workflow(blob)
    if "defaults" in workflow:
        raise HostedEvidenceError("workflow run-shell defaults are inadmissible")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise HostedEvidenceError("workflow jobs structure is malformed")
    job = jobs.get(GATE_JOB_KEYS[gate])
    if not isinstance(job, dict):
        raise HostedEvidenceError(f"workflow gate job binding drift: {gate}")
    if "defaults" in job or "continue-on-error" in job:
        raise HostedEvidenceError(
            f"workflow gate job execution defaults are inadmissible: {gate}"
        )
    admitted_condition = ALLOWED_JOB_IF.get(gate)
    if admitted_condition is None:
        reachable = "if" not in job
    else:
        reachable = job.get("if") == admitted_condition
    if not reachable:
        raise HostedEvidenceError(
            f"workflow gate job is not provably reachable: {gate}"
        )
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        raise HostedEvidenceError(f"workflow gate steps structure is malformed: {gate}")

    template = _status_template(gate)
    matches = 0
    expected_keys = (
        {"name", "if", "shell", "run"}
        if gate == "windows-native"
        else {"name", "if", "run"}
    )
    for step in steps:
        if not isinstance(step, dict):
            raise HostedEvidenceError(
                f"workflow gate step structure is malformed: {gate}"
            )
        if not _exact_status_run(step.get("run"), template):
            continue
        if (
            set(step) != expected_keys
            or not isinstance(step.get("name"), str)
            or not step["name"]
            or step.get("if") != "always()"
            or (gate == "windows-native" and step.get("shell") != "bash")
        ):
            raise HostedEvidenceError(
                f"workflow status step execution policy drift: {gate}"
            )
        matches += 1
    if matches != 1 or _scalar_occurrences(workflow, template) != 1:
        raise HostedEvidenceError(
            f"workflow lacks one executable unconditional github.sha status push: {gate}"
        )


def _validate_zip(
    path: Path,
    label: str,
    *,
    maximum_uncompressed: int = MAX_ZIP_UNCOMPRESSED_BYTES,
    progress: Callable[[], None] | None = None,
) -> int:
    if (
        isinstance(maximum_uncompressed, bool)
        or not isinstance(maximum_uncompressed, int)
        or maximum_uncompressed < 1
        or maximum_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES
    ):
        raise HostedEvidenceError(f"{label} aggregate ZIP expansion budget exhausted")
    descriptor, before = _open_regular(path, f"{label} ZIP")
    try:
        if progress is not None:
            progress()
        if before.st_size < 22 or before.st_size > MAX_ARCHIVE_BYTES:
            raise HostedEvidenceError(f"{label} ZIP size is inadmissible")
        if os.pread(descriptor, 4, 0) != b"PK\x03\x04":
            raise HostedEvidenceError(f"{label} ZIP framing is malformed")
        tail_size = min(before.st_size, 22 + 65535)
        tail = os.pread(descriptor, tail_size, before.st_size - tail_size)
        marker = tail.rfind(b"PK\x05\x06")
        if marker < 0 or marker + 22 > len(tail):
            raise HostedEvidenceError(f"{label} ZIP framing is malformed")
        comment_size = int.from_bytes(tail[marker + 20:marker + 22], "little")
        absolute_marker = before.st_size - tail_size + marker
        if absolute_marker + 22 + comment_size != before.st_size:
            raise HostedEvidenceError(f"{label} ZIP framing has trailing bytes")
        after = os.fstat(descriptor)
        if _metadata(before) != _metadata(after):
            raise HostedEvidenceError(f"{label} ZIP changed during framing check")
    finally:
        os.close(descriptor)
    try:
        with zipfile.ZipFile(path, "r") as archive:
            records = archive.infolist()
            if not records or len(records) > MAX_ZIP_ENTRIES:
                raise HostedEvidenceError(f"{label} ZIP inventory is inadmissible")
            if min(record.header_offset for record in records) != 0:
                raise HostedEvidenceError(
                    f"{label} ZIP framing has an unbound prefix"
                )
            names: set[str] = set()
            total = 0
            regular_count = 0
            for record in records:
                if progress is not None:
                    progress()
                name = record.filename
                _relative_path(name.rstrip("/"), f"{label} ZIP member")
                if name in names:
                    raise HostedEvidenceError(f"{label} ZIP members are duplicated")
                names.add(name)
                if record.flag_bits & 0x1:
                    raise HostedEvidenceError(f"{label} ZIP contains encrypted content")
                unix_mode = (record.external_attr >> 16) & 0xFFFF
                if unix_mode and stat.S_IFMT(unix_mode) not in {
                    0, stat.S_IFREG, stat.S_IFDIR
                }:
                    raise HostedEvidenceError(f"{label} ZIP contains a special member")
                total += record.file_size
                if total > maximum_uncompressed:
                    raise HostedEvidenceError(f"{label} ZIP expands beyond policy")
                if not record.is_dir():
                    regular_count += 1
            if regular_count < 1:
                raise HostedEvidenceError(f"{label} ZIP contains no regular file")
            for record in records:
                if record.is_dir():
                    continue
                try:
                    with archive.open(record, "r") as member:
                        while True:
                            if progress is not None:
                                progress()
                            chunk = member.read(CHUNK_BYTES)
                            if progress is not None:
                                progress()
                            if not chunk:
                                break
                except zipfile.BadZipFile as error:
                    raise HostedEvidenceError(
                        f"{label} ZIP CRC failure: {record.filename}"
                    ) from error
    except HostedEvidenceError:
        raise
    except (OSError, zipfile.BadZipFile, NotImplementedError) as error:
        raise HostedEvidenceError(f"{label} is not a valid ZIP archive") from error
    return total


def _source_identity(
    source: SourceAuthority,
    repository: str,
    revision: str,
    *,
    expected_tree: str | None = None,
) -> tuple[str, dict[str, bytes]]:
    try:
        source_repository = source.repository_identity()
        resolved = source.resolve_revision(revision)
        tree = source.tree_sha1(revision)
    except HostedEvidenceError:
        raise
    except Exception as error:
        raise HostedEvidenceError(f"source authority failed: {error}") from error
    if source_repository != repository:
        raise HostedEvidenceError("source repository identity drift")
    if resolved != revision:
        raise HostedEvidenceError("source authority did not resolve the exact revision")
    _git_sha(tree, "source tree")
    if expected_tree is not None and tree != expected_tree:
        raise HostedEvidenceError("source tree drift")
    blobs: dict[str, bytes] = {}
    for path in dict.fromkeys(GATE_WORKFLOWS.values()):
        try:
            blob = source.read_file(revision, path)
        except HostedEvidenceError:
            raise
        except Exception as error:
            raise HostedEvidenceError(f"cannot read exact workflow blob {path}: {error}") from error
        if not isinstance(blob, bytes) or not blob or len(blob) > MAX_WORKFLOW_BYTES:
            raise HostedEvidenceError(f"exact workflow blob is inadmissible: {path}")
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HostedEvidenceError(f"workflow blob is not UTF-8: {path}") from error
        if "\x00" in text:
            raise HostedEvidenceError(f"workflow blob contains NUL: {path}")
        blobs[path] = blob
    return tree, blobs


def _stage_offline_inputs(
    staging: Path,
    inputs: OfflineSnapshotInputs,
    repository: str,
    revision: str,
    workflows: dict[str, bytes],
) -> None:
    selection_value, _ = _read_json(inputs.path("selection.json"), "selection input")
    selected = _validate_selection(selection_value, repository, revision)
    run_ids = list(dict.fromkeys(int(item["workflow_run_id"]) for item in selected))
    runs_value, _ = _read_json(
        inputs.path("api/workflow-runs.json"), "workflow-run API input"
    )
    run_records = _find_by_id(
        _complete_collection(
            runs_value, "total_count", "workflow_runs", "workflow-run"
        ),
        "workflow run",
    )
    attempts: dict[int, int] = {}
    for run_id in run_ids:
        run = run_records.get(run_id)
        if run is None:
            raise HostedEvidenceError("selected workflow run is absent from API input")
        attempts[run_id] = _positive_integer(
            run.get("run_attempt"), "workflow run attempt"
        )

    expected_inputs = {"selection.json", *BASE_API_FILES}
    artifact_ids: set[int] = set()
    for run_id in run_ids:
        artifact_api = f"api/artifacts/{run_id}.json"
        expected_inputs.add(artifact_api)
        value, _ = _read_json(inputs.path(artifact_api), "artifact API input")
        artifacts = _complete_collection(value, "total_count", "artifacts", "artifact")
        attempt = attempts[run_id]
        expected_inputs.add(f"api/jobs/{run_id}-attempt-{attempt}.json")
        expected_inputs.add(f"api/log-downloads/{run_id}-attempt-{attempt}.json")
        expected_inputs.add(f"downloads/logs/{run_id}-attempt-{attempt}.zip")
        for raw in artifacts:
            if not isinstance(raw, dict):
                raise HostedEvidenceError("artifact API record is malformed")
            _validate_artifact_attempt(raw, attempt)
            artifact_id = _positive_integer(raw.get("id"), "artifact ID")
            if artifact_id in artifact_ids:
                raise HostedEvidenceError("artifact IDs are duplicated")
            artifact_ids.add(artifact_id)
            expected_inputs.add(f"api/artifact-downloads/{artifact_id}.json")
            expected_inputs.add(f"downloads/artifacts/{artifact_id}.zip")

    actual_inputs = _inventory(inputs.root, "offline input")
    if actual_inputs != expected_inputs:
        missing = sorted(expected_inputs - actual_inputs)
        extra = sorted(actual_inputs - expected_inputs)
        raise HostedEvidenceError(
            "offline input inventory mismatch (required API/log archive/artifact "
            f"archive); missing={missing!r}; extra={extra!r}"
        )
    _validate_archive_budget(
        inputs.root,
        sorted(
            relative for relative in expected_inputs
            if relative.startswith("downloads/") and relative.endswith(".zip")
        ),
        "offline input",
    )

    copy_map: dict[str, tuple[str, int, str]] = {
        "selection.json": ("raw/selection.json", MAX_JSON_BYTES, "selection input"),
        "api/workflow-runs.json": (
            "raw/api/workflow-runs.json", MAX_JSON_BYTES, "workflow-run API input"
        ),
        "api/check-suites.json": (
            "raw/api/check-suites.json", MAX_JSON_BYTES, "check-suite API input"
        ),
        "api/check-runs.json": (
            "raw/api/check-runs.json", MAX_JSON_BYTES, "check-run API input"
        ),
        "api/status-refs.json": (
            "raw/api/status-refs.json", MAX_JSON_BYTES, "status-ref API input"
        ),
    }
    for run_id in run_ids:
        attempt = attempts[run_id]
        copy_map[f"api/artifacts/{run_id}.json"] = (
            f"raw/api/artifacts/{run_id}.json", MAX_JSON_BYTES, "artifact API input"
        )
        copy_map[f"api/jobs/{run_id}-attempt-{attempt}.json"] = (
            f"raw/api/jobs/{run_id}-attempt-{attempt}.json",
            MAX_JSON_BYTES,
            "attempt-specific job API input",
        )
        copy_map[f"api/log-downloads/{run_id}-attempt-{attempt}.json"] = (
            f"raw/api/log-downloads/{run_id}-attempt-{attempt}.json",
            MAX_JSON_BYTES,
            "attempt-specific log download authority",
        )
        copy_map[f"downloads/logs/{run_id}-attempt-{attempt}.zip"] = (
            f"raw/logs/{run_id}-attempt-{attempt}.zip",
            MAX_ARCHIVE_BYTES,
            "log archive",
        )
    for artifact_id in artifact_ids:
        copy_map[f"api/artifact-downloads/{artifact_id}.json"] = (
            f"raw/api/artifact-downloads/{artifact_id}.json",
            MAX_JSON_BYTES,
            "artifact download authority",
        )
        copy_map[f"downloads/artifacts/{artifact_id}.zip"] = (
            f"raw/artifacts/{artifact_id}.zip", MAX_ARCHIVE_BYTES, "artifact archive"
        )
    for source_relative, (target_relative, maximum, label) in sorted(copy_map.items()):
        _copy_regular(
            inputs.path(source_relative), staging / target_relative, maximum, label
        )
    for workflow_path, blob in workflows.items():
        _write_new(staging / "raw" / "workflows" / Path(workflow_path).name, blob)


def _find_by_id(records: list[Any], label: str) -> dict[int, dict[str, Any]]:
    indexed: dict[int, dict[str, Any]] = {}
    for raw in records:
        if not isinstance(raw, dict):
            raise HostedEvidenceError(f"{label} API record is malformed")
        identifier = _positive_integer(raw.get("id"), f"{label} ID")
        if identifier in indexed:
            raise HostedEvidenceError(f"{label} IDs are duplicated")
        indexed[identifier] = raw
    return indexed


def derive_canonical_selection(
    runs_value: Any,
    suites_value: Any,
    checks_value: Any,
    refs_value: Any,
    repository: str,
    revision: str,
) -> dict[str, Any]:
    """Derive the sole deterministic gate selection from provider base APIs."""

    repository = _repository(repository)
    revision = _git_sha(revision, "selection revision")
    run_list = _complete_collection(
        runs_value, "total_count", "workflow_runs", "workflow-run"
    )
    if runs_value["total_count"] >= PROVIDER_FILTERED_RESULT_CAP:
        raise HostedEvidenceError(
            "workflow-run authority is ambiguous at the provider result cap"
        )
    run_records = _find_by_id(run_list, "workflow run")
    suite_list = _complete_collection(
        suites_value, "total_count", "check_suites", "check-suite"
    )
    if suites_value["total_count"] >= PROVIDER_FILTERED_RESULT_CAP:
        raise HostedEvidenceError(
            "check-suite authority is ambiguous at the check-run provider cap"
        )
    suite_records = _find_by_id(suite_list, "check suite")
    check_records = _find_by_id(
        _complete_collection(
            checks_value, "total_count", "check_runs", "check-run"
        ),
        "check run",
    )
    for suite_id, suite in suite_records.items():
        if suite.get("head_sha") != revision:
            raise HostedEvidenceError("check-suite head revision drift")
        _exact_provider_url(
            suite.get("url"),
            f"https://api.github.com/repos/{repository}/check-suites/{suite_id}",
            "check-suite API",
        )
        _exact_provider_url(
            suite.get("check_runs_url"),
            (
                f"https://api.github.com/repos/{repository}/check-suites/"
                f"{suite_id}/check-runs"
            ),
            "check-suite runs",
        )
    for run in run_records.values():
        if run.get("head_sha") != revision or run.get("status") != "completed":
            raise HostedEvidenceError("filtered workflow-run authority drift")
        suite_id = _positive_integer(
            run.get("check_suite_id"), "workflow check-suite ID"
        )
        if suite_id not in suite_records:
            raise HostedEvidenceError(
                "workflow run check suite is absent from complete suite authority"
            )
    for check in check_records.values():
        check_suite = check.get("check_suite")
        if not isinstance(check_suite, dict):
            raise HostedEvidenceError("check-run suite authority is malformed")
        suite_id = _positive_integer(
            check_suite.get("id"), "check-run suite ID"
        )
        if suite_id not in suite_records or check.get("head_sha") != revision:
            raise HostedEvidenceError("check-run suite or revision authority drift")
    if not isinstance(refs_value, list):
        raise HostedEvidenceError("status-ref API snapshot is malformed")
    refs: dict[str, dict[str, Any]] = {}
    for raw in refs_value:
        if not isinstance(raw, dict) or not isinstance(raw.get("ref"), str):
            raise HostedEvidenceError("status-ref API record is malformed")
        ref_name = raw["ref"]
        if ref_name in refs:
            raise HostedEvidenceError("status refs are duplicated")
        refs[ref_name] = raw
    for gate_id in stability.REQUIRED_HOSTED_GATES:
        ref_name = f"refs/status/{revision}/{gate_id}/success"
        ref = refs.get(ref_name)
        if ref is None:
            raise HostedEvidenceError(
                f"required success status ref is missing: {gate_id}"
            )
        target = ref.get("object")
        if (
            not isinstance(target, dict)
            or target.get("type") != "commit"
            or target.get("sha") != revision
        ):
            raise HostedEvidenceError(f"status ref target drift: {gate_id}")
        _exact_provider_url(
            target.get("url"),
            f"https://api.github.com/repos/{repository}/git/commits/{revision}",
            "status-ref target",
        )

    gates_by_path: dict[str, list[str]] = {}
    for gate_id in stability.REQUIRED_HOSTED_GATES:
        gates_by_path.setdefault(GATE_WORKFLOWS[gate_id], []).append(gate_id)
    chosen_by_gate: dict[str, tuple[int, int]] = {}
    chosen_check_ids: set[int] = set()
    for workflow_path, gate_ids in gates_by_path.items():
        candidates: list[
            tuple[int, int, dict[str, int]]
        ] = []
        for run_id, run in run_records.items():
            raw_path = run.get("path")
            if not isinstance(raw_path, str):
                continue
            path_without_ref = raw_path.rsplit("@", 1)[0]
            if path_without_ref != workflow_path:
                continue
            try:
                attempt = _positive_integer(
                    run.get("run_attempt"), "workflow run attempt"
                )
                if attempt != 1:
                    continue
                event = run.get("event")
                if (
                    not isinstance(event, str)
                    or event not in {"push", "workflow_dispatch"}
                ):
                    continue
                if (
                    run.get("head_sha") != revision
                    or run.get("status") != "completed"
                    or run.get("conclusion") != "success"
                ):
                    continue
                _workflow_path(
                    raw_path, workflow_path, run.get("head_branch")
                )
                run_repository = run.get("repository")
                if (
                    not isinstance(run_repository, dict)
                    or run_repository.get("full_name") != repository
                ):
                    continue
                _exact_provider_url(
                    run.get("url"),
                    f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
                    "workflow run API",
                )
                _exact_provider_url(
                    run.get("html_url"),
                    f"https://github.com/{repository}/actions/runs/{run_id}",
                    "workflow run",
                )
                _exact_provider_url(
                    run.get("jobs_url"),
                    f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/jobs",
                    "workflow jobs",
                )
                _exact_provider_url(
                    run.get("logs_url"),
                    f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/logs",
                    "workflow logs",
                )
                suite_id = _positive_integer(
                    run.get("check_suite_id"), "workflow check-suite ID"
                )
                suite = suite_records[suite_id]
                suite_app = suite.get("app")
                suite_repository = suite.get("repository")
                if (
                    suite.get("status") != "completed"
                    or suite.get("conclusion") != "success"
                    or not isinstance(suite_app, dict)
                    or suite_app.get("slug") != "github-actions"
                    or not isinstance(suite_repository, dict)
                    or suite_repository.get("full_name") != repository
                ):
                    continue
                _exact_provider_url(
                    run.get("check_suite_url"),
                    f"https://api.github.com/repos/{repository}/check-suites/{suite_id}",
                    "workflow check-suite",
                )
            except HostedEvidenceError:
                continue

            selected_checks: dict[str, int] = {}
            admissible = True
            for gate_id in gate_ids:
                matches: list[tuple[int, dict[str, Any]]] = []
                for check_id, check in check_records.items():
                    check_suite = check.get("check_suite")
                    if (
                        check.get("name") != CHECK_NAMES[gate_id]
                        or not isinstance(check_suite, dict)
                    ):
                        continue
                    try:
                        check_suite_id = _positive_integer(
                            check_suite.get("id"), "check-suite ID"
                        )
                    except HostedEvidenceError:
                        continue
                    if check_suite_id == suite_id:
                        matches.append((check_id, check))
                if len(matches) != 1:
                    admissible = False
                    break
                check_id, check = matches[0]
                app = check.get("app")
                if (
                    check.get("head_sha") != revision
                    or check.get("status") != "completed"
                    or check.get("conclusion") != "success"
                    or not isinstance(app, dict)
                    or app.get("slug") != "github-actions"
                ):
                    admissible = False
                    break
                selected_checks[gate_id] = check_id
            if admissible:
                event_priority = 0 if event == "push" else 1
                candidates.append((event_priority, run_id, selected_checks))
        if not candidates:
            raise HostedEvidenceError(
                f"no admissible attempt-one workflow run for {workflow_path}"
            )
        _priority, chosen_run_id, selected_checks = min(
            candidates, key=lambda candidate: (candidate[0], candidate[1])
        )
        for gate_id in gate_ids:
            check_id = selected_checks[gate_id]
            if check_id in chosen_check_ids:
                raise HostedEvidenceError(
                    "derived selection check-run IDs are duplicated"
                )
            chosen_check_ids.add(check_id)
            chosen_by_gate[gate_id] = (chosen_run_id, check_id)

    selection = {
        "schema": SELECTION_SCHEMA,
        "repository": repository,
        "revision": revision,
        "gates": [
            {
                "gate_id": gate_id,
                "workflow_run_id": chosen_by_gate[gate_id][0],
                "check_run_id": chosen_by_gate[gate_id][1],
            }
            for gate_id in stability.REQUIRED_HOSTED_GATES
        ],
    }
    _validate_selection(selection, repository, revision)
    return selection


def _snapshot_record(root: Path, relative: str, label: str) -> dict[str, Any]:
    digest, size = _hash_regular(root / relative, MAX_JSON_BYTES if relative.endswith(".json") else MAX_WORKFLOW_BYTES, label)
    return {"path": relative, "sha256": digest, "size": size}


def _derive_receipt(
    root: Path,
    repository: str,
    revision: str,
    source: SourceAuthority,
    *,
    expected_tree: str | None = None,
) -> dict[str, Any]:
    tree, source_workflows = _source_identity(
        source, repository, revision, expected_tree=expected_tree
    )
    selection, _ = _read_json(root / "raw" / "selection.json", "retained selection")
    selected = _validate_selection(selection, repository, revision)

    runs_value, _ = _read_json(
        root / "raw" / "api" / "workflow-runs.json", "workflow-run API snapshot"
    )
    run_records = _find_by_id(
        _complete_collection(
            runs_value, "total_count", "workflow_runs", "workflow-run"
        ),
        "workflow run",
    )
    suites_value, _ = _read_json(
        root / "raw" / "api" / "check-suites.json",
        "check-suite API snapshot",
    )
    checks_value, _ = _read_json(
        root / "raw" / "api" / "check-runs.json", "check-run API snapshot"
    )
    check_records = _find_by_id(
        _complete_collection(checks_value, "total_count", "check_runs", "check-run"),
        "check run",
    )
    refs_value, _ = _read_json(
        root / "raw" / "api" / "status-refs.json", "status-ref API snapshot"
    )
    if not isinstance(refs_value, list):
        raise HostedEvidenceError("status-ref API snapshot is malformed")
    refs: dict[str, dict[str, Any]] = {}
    for raw in refs_value:
        if not isinstance(raw, dict) or not isinstance(raw.get("ref"), str):
            raise HostedEvidenceError("status-ref API record is malformed")
        name = raw["ref"]
        if name in refs:
            raise HostedEvidenceError("status refs are duplicated")
        refs[name] = raw

    workflow_hashes: dict[str, str] = {}
    snapshot_paths = {
        "raw/selection.json",
        "raw/api/workflow-runs.json",
        "raw/api/check-suites.json",
        "raw/api/check-runs.json",
        "raw/api/status-refs.json",
    }
    for path, source_blob in source_workflows.items():
        retained_relative = f"raw/workflows/{Path(path).name}"
        retained_blob = _read_regular(
            root / retained_relative, MAX_WORKFLOW_BYTES, "retained workflow blob"
        )
        if retained_blob != source_blob:
            raise HostedEvidenceError(f"retained workflow blob drift: {path}")
        workflow_hashes[path] = _digest_bytes(retained_blob)
        snapshot_paths.add(retained_relative)

    normalized_runs: list[dict[str, Any]] = []
    normalized_gates: list[dict[str, Any]] = []
    accepted_run_ids: list[int] = []
    normalized_run_by_id: dict[int, dict[str, Any]] = {}
    attempt_jobs_by_run: dict[int, list[dict[str, Any]]] = {}
    check_ids: set[int] = set()
    for selected_gate in selected:
        gate_id = str(selected_gate["gate_id"])
        run_id = int(selected_gate["workflow_run_id"])
        check_id = int(selected_gate["check_run_id"])
        workflow_path = GATE_WORKFLOWS[gate_id]
        run = run_records.get(run_id)
        if run is None:
            raise HostedEvidenceError("selected workflow run is absent from API snapshot")
        attempt = _positive_integer(run.get("run_attempt"), "workflow run attempt")
        if run.get("event") not in {"push", "workflow_dispatch"}:
            raise HostedEvidenceError("workflow event is not authoritative")
        if run.get("head_sha") != revision:
            raise HostedEvidenceError("workflow run is not an exact-head run")
        if run.get("status") != "completed":
            raise HostedEvidenceError("workflow run is not completed")
        if run.get("conclusion") != "success":
            raise HostedEvidenceError("workflow run is not a success")
        _workflow_path(run.get("path"), workflow_path, run.get("head_branch"))
        run_repository = run.get("repository")
        if not isinstance(run_repository, dict) or run_repository.get("full_name") != repository:
            raise HostedEvidenceError("workflow run repository drift")
        run_url = _exact_provider_url(
            run.get("html_url"),
            f"https://github.com/{repository}/actions/runs/{run_id}",
            "workflow run",
        )
        _exact_provider_url(
            run.get("url"),
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
            "workflow run API",
        )
        _exact_provider_url(
            run.get("jobs_url"),
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/jobs",
            "workflow jobs",
        )
        _exact_provider_url(
            run.get("logs_url"),
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/logs",
            "workflow logs",
        )
        check_suite_id = _positive_integer(
            run.get("check_suite_id"), "workflow check-suite ID"
        )
        _exact_provider_url(
            run.get("check_suite_url"),
            f"https://api.github.com/repos/{repository}/check-suites/{check_suite_id}",
            "workflow check-suite",
        )
        retained_workflow = source_workflows[workflow_path]
        _validate_status_policy(retained_workflow, gate_id)
        normalized_run = {
            "workflow_path": workflow_path,
            "workflow_file_sha256": workflow_hashes[workflow_path],
            "run_id": run_id,
            "run_attempt": attempt,
            "event": run["event"],
            "head_sha": revision,
            "conclusion": "success",
            "url": run_url,
        }
        prior_run = normalized_run_by_id.setdefault(run_id, normalized_run)
        if prior_run != normalized_run:
            raise HostedEvidenceError("workflow run binding is internally inconsistent")
        if run_id not in accepted_run_ids:
            accepted_run_ids.append(run_id)
            normalized_runs.append(normalized_run)

        if run_id not in attempt_jobs_by_run:
            jobs_relative = f"raw/api/jobs/{run_id}-attempt-{attempt}.json"
            jobs_value, _ = _read_json(
                root / jobs_relative, "attempt-specific job API snapshot"
            )
            raw_jobs = _complete_collection(
                jobs_value, "total_count", "jobs", "attempt-specific job"
            )
            jobs: list[dict[str, Any]] = []
            job_ids: set[int] = set()
            for raw_job in raw_jobs:
                if not isinstance(raw_job, dict):
                    raise HostedEvidenceError("attempt-specific job API record is malformed")
                job_id = _positive_integer(raw_job.get("id"), "attempt job ID")
                if job_id in job_ids:
                    raise HostedEvidenceError("attempt job IDs are duplicated")
                job_ids.add(job_id)
                jobs.append(raw_job)
            attempt_jobs_by_run[run_id] = jobs
            snapshot_paths.add(jobs_relative)

        check = check_records.get(check_id)
        if check is None:
            raise HostedEvidenceError("selected check run is absent from API snapshot")
        if check_id in check_ids:
            raise HostedEvidenceError("selected check-run IDs are duplicated")
        check_ids.add(check_id)
        if check.get("name") != CHECK_NAMES[gate_id]:
            raise HostedEvidenceError(f"check-run name drift for {gate_id}")
        if check.get("head_sha") != revision:
            raise HostedEvidenceError("check run is not an exact-head check")
        if check.get("status") != "completed":
            raise HostedEvidenceError("check run is not completed")
        if check.get("conclusion") != "success":
            raise HostedEvidenceError("check run is not a success")
        app = check.get("app")
        if not isinstance(app, dict) or app.get("slug") != "github-actions":
            raise HostedEvidenceError("check run is not owned by GitHub Actions")
        check_suite = check.get("check_suite")
        if (
            not isinstance(check_suite, dict)
            or check_suite.get("id") != check_suite_id
        ):
            raise HostedEvidenceError("check run does not bind the workflow check suite")
        expected_check_api = (
            f"https://api.github.com/repos/{repository}/check-runs/{check_id}"
        )
        matching_jobs = [
            job for job in attempt_jobs_by_run[run_id]
            if job.get("check_run_url") == expected_check_api
        ]
        if len(matching_jobs) != 1:
            raise HostedEvidenceError(
                "attempt-specific job authority does not bind the selected check run"
            )
        job = matching_jobs[0]
        job_id = _positive_integer(job.get("id"), "attempt job ID")
        if (
            job.get("run_id") != run_id
            or job.get("head_sha") != revision
            or job.get("name") != CHECK_NAMES[gate_id]
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
        ):
            raise HostedEvidenceError("attempt-specific job authority drift")
        job_attempt = _positive_integer(
            job.get("run_attempt"), "attempt job run attempt"
        )
        if job_attempt != attempt:
            raise HostedEvidenceError("attempt job run-attempt binding drift")
        _exact_provider_url(
            job.get("run_url"),
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
            "attempt job run",
        )
        _exact_provider_url(
            job.get("url"),
            f"https://api.github.com/repos/{repository}/actions/jobs/{job_id}",
            "attempt job",
        )
        _exact_provider_url(job.get("check_run_url"), expected_check_api, "job check-run")
        job_html = _exact_job_html_url(
            job.get("html_url"), repository, run_id, job_id
        )
        details_url = _github_html_url(
            check.get("details_url"), repository, "check-run details"
        )
        if details_url != job_html:
            raise HostedEvidenceError("check run does not bind the attempt-specific job")
        check_url = _exact_job_html_url(
            check.get("html_url"),
            repository,
            run_id,
            job_id,
            label="check-run",
        )
        if check_url != job_html:
            raise HostedEvidenceError(
                "check-run URL does not bind the attempt-specific job"
            )

        ref_name = f"refs/status/{revision}/{gate_id}/success"
        ref = refs.get(ref_name)
        if ref is None:
            raise HostedEvidenceError(f"required success status ref is missing: {gate_id}")
        target = ref.get("object")
        if (
            not isinstance(target, dict)
            or target.get("type") != "commit"
            or target.get("sha") != revision
        ):
            raise HostedEvidenceError(f"status ref target drift: {gate_id}")
        _exact_provider_url(
            target.get("url"),
            f"https://api.github.com/repos/{repository}/git/commits/{revision}",
            "status-ref target",
        )
        normalized_gates.append({
            "gate_id": gate_id,
            "provider_name": "github-actions",
            "check_run_id": check_id,
            "conclusion": "success",
            "url": check_url,
            "workflow_run_id": run_id,
            "status_ref": ref_name,
            "status_ref_target": revision,
        })

    derived_selection = derive_canonical_selection(
        runs_value,
        suites_value,
        checks_value,
        refs_value,
        repository,
        revision,
    )
    if selection != derived_selection:
        raise HostedEvidenceError(
            "retained selection differs from deterministic provider selection"
        )

    normalized_logs: list[dict[str, Any]] = []
    normalized_artifacts: list[dict[str, Any]] = []
    artifact_ids: set[int] = set()
    zip_uncompressed_total = 0
    for run_id in accepted_run_ids:
        attempt = _positive_integer(
            run_records[run_id].get("run_attempt"), "workflow run attempt"
        )
        log_relative = f"raw/logs/{run_id}-attempt-{attempt}.zip"
        log_digest, log_size = _hash_regular(
            root / log_relative, MAX_ARCHIVE_BYTES, "retained log archive"
        )
        zip_uncompressed_total += _validate_zip(
            root / log_relative,
            "retained log",
            maximum_uncompressed=(
                MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES - zip_uncompressed_total
            ),
        )
        log_authority_relative = (
            f"raw/api/log-downloads/{run_id}-attempt-{attempt}.json"
        )
        log_authority_value, _ = _read_json(
            root / log_authority_relative,
            "attempt-specific log download authority",
        )
        _validate_download_authority(
            log_authority_value,
            schema=LOG_DOWNLOAD_SCHEMA,
            repository=repository,
            identity_fields={"run_id": run_id, "run_attempt": attempt},
            request_url=(
                f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/"
                f"attempts/{attempt}/logs"
            ),
            archive_digest=log_digest,
            archive_size=log_size,
            label="attempt-specific log download authority",
        )
        snapshot_paths.add(log_authority_relative)
        normalized_logs.append({
            "run_id": run_id,
            "path": log_relative,
            "sha256": log_digest,
            "size": log_size,
        })

        artifact_snapshot_relative = f"raw/api/artifacts/{run_id}.json"
        artifact_value, _ = _read_json(
            root / artifact_snapshot_relative, "artifact API snapshot"
        )
        artifacts = _complete_collection(
            artifact_value, "total_count", "artifacts", "artifact"
        )
        snapshot_paths.add(artifact_snapshot_relative)
        for raw in artifacts:
            if not isinstance(raw, dict):
                raise HostedEvidenceError("artifact API record is malformed")
            _validate_artifact_attempt(raw, attempt)
            artifact_id = _positive_integer(raw.get("id"), "artifact ID")
            if artifact_id in artifact_ids:
                raise HostedEvidenceError("artifact IDs are duplicated")
            artifact_ids.add(artifact_id)
            name = raw.get("name")
            if not isinstance(name, str) or not name or "\x00" in name:
                raise HostedEvidenceError("artifact name is malformed")
            if raw.get("expired") is not False:
                raise HostedEvidenceError("hosted artifact is expired or has unknown expiry")
            workflow_run = raw.get("workflow_run")
            if (
                not isinstance(workflow_run, dict)
                or workflow_run.get("id") != run_id
                or workflow_run.get("head_sha") != revision
            ):
                raise HostedEvidenceError("artifact workflow-run binding drift")
            provider_raw = raw.get("digest")
            if not isinstance(provider_raw, str) or not provider_raw.startswith("sha256:"):
                raise HostedEvidenceError("artifact provider digest is malformed")
            provider_digest = provider_raw.removeprefix("sha256:")
            _sha256(provider_digest, "artifact provider digest")
            artifact_url = _exact_provider_url(
                raw.get("url"),
                f"https://api.github.com/repos/{repository}/actions/artifacts/"
                f"{artifact_id}",
                "artifact",
            )
            _exact_provider_url(
                raw.get("archive_download_url"),
                f"https://api.github.com/repos/{repository}/actions/artifacts/"
                f"{artifact_id}/zip",
                "artifact download",
            )
            archive_relative = f"raw/artifacts/{artifact_id}.zip"
            archive_digest, archive_size = _hash_regular(
                root / archive_relative, MAX_ARCHIVE_BYTES, "retained artifact archive"
            )
            zip_uncompressed_total += _validate_zip(
                root / archive_relative,
                "retained artifact",
                maximum_uncompressed=(
                    MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES - zip_uncompressed_total
                ),
            )
            artifact_authority_relative = (
                f"raw/api/artifact-downloads/{artifact_id}.json"
            )
            artifact_authority_value, _ = _read_json(
                root / artifact_authority_relative,
                "artifact download authority",
            )
            _validate_download_authority(
                artifact_authority_value,
                schema=ARTIFACT_DOWNLOAD_SCHEMA,
                repository=repository,
                identity_fields={"artifact_id": artifact_id},
                request_url=(
                    f"https://api.github.com/repos/{repository}/actions/artifacts/"
                    f"{artifact_id}/zip"
                ),
                archive_digest=archive_digest,
                archive_size=archive_size,
                label="artifact download authority",
            )
            snapshot_paths.add(artifact_authority_relative)
            provider_size = _positive_integer(raw.get("size_in_bytes"), "artifact size")
            if provider_size != archive_size:
                raise HostedEvidenceError("artifact size differs from provider authority")
            if provider_digest != archive_digest:
                raise HostedEvidenceError("artifact provider digest differs from local SHA")
            normalized_artifacts.append({
                "id": artifact_id,
                "name": name,
                "provider_digest": provider_digest,
                "url": artifact_url,
                "archive_path": archive_relative,
                "archive_sha256": archive_digest,
                "size": archive_size,
                "run_id": run_id,
            })
    if not normalized_artifacts:
        raise HostedEvidenceError("hosted artifact inventory is empty")

    normalized_snapshots = [
        _snapshot_record(root, relative, "retained authority snapshot")
        for relative in sorted(snapshot_paths)
    ]
    return {
        "schema": stability.HOSTED_EXACT_HEAD_SCHEMA,
        "status": "accepted",
        "failures": [],
        "source": {
            "repository": repository,
            "revision": revision,
            "tree_sha1": tree,
        },
        "required_gates": list(stability.REQUIRED_HOSTED_GATES),
        "gates": normalized_gates,
        "runs": normalized_runs,
        "logs": normalized_logs,
        "artifacts": normalized_artifacts,
        "snapshots": normalized_snapshots,
    }


def _referenced_paths(receipt: dict[str, Any]) -> set[str]:
    result = {"receipt.json", "receipt.json.sha256", "SHA256SUMS"}
    for collection, key in (
        (receipt.get("logs"), "path"),
        (receipt.get("artifacts"), "archive_path"),
        (receipt.get("snapshots"), "path"),
    ):
        if not isinstance(collection, list):
            raise HostedEvidenceError("receipt retained-file inventory is malformed")
        for raw in collection:
            if not isinstance(raw, dict):
                raise HostedEvidenceError("receipt retained-file record is malformed")
            relative = _relative_path(raw.get(key), "retained evidence")
            if relative in result:
                raise HostedEvidenceError("receipt retained-file paths are duplicated")
            result.add(relative)
    return result


def _seal_outer(root: Path, receipt: dict[str, Any]) -> None:
    receipt_bytes = _canonical_bytes(receipt)
    _write_new(root / "receipt.json", receipt_bytes)
    receipt_digest = _digest_bytes(receipt_bytes)
    _write_new(
        root / "receipt.json.sha256",
        f"{receipt_digest}  receipt.json\n".encode("ascii"),
    )
    files = sorted(_inventory(root, "staged evidence"))
    if "SHA256SUMS" in files:
        raise HostedEvidenceError("staged SHA256SUMS already exists")
    lines: list[bytes] = []
    for relative in files:
        maximum = MAX_ARCHIVE_BYTES
        digest, _ = _hash_regular(root / relative, maximum, "staged evidence file")
        lines.append(f"{digest}  {relative}\n".encode("ascii"))
    _write_new(root / "SHA256SUMS", b"".join(lines))


def _verify_outer(root: Path) -> tuple[dict[str, Any], set[str]]:
    actual = _inventory(root, "evidence")
    if "SHA256SUMS" not in actual:
        raise HostedEvidenceError("SHA256SUMS is missing")
    archive_paths = sorted(
        relative for relative in actual
        if relative.endswith(".zip") and relative.startswith(
            ("raw/logs/", "raw/artifacts/")
        )
    )
    _validate_archive_budget(root, archive_paths, "evidence")
    evidence_bytes = 0
    for relative in sorted(actual):
        descriptor, metadata = _open_regular(
            root / relative, "evidence budget input"
        )
        os.close(descriptor)
        evidence_bytes += metadata.st_size
        if evidence_bytes > MAX_EVIDENCE_TOTAL_BYTES:
            raise HostedEvidenceError(
                "evidence aggregate byte budget exceeded"
            )
    manifest = _read_regular(
        root / "SHA256SUMS", MAX_JSON_BYTES, "SHA256SUMS"
    )
    try:
        text = manifest.decode("ascii")
    except UnicodeDecodeError as error:
        raise HostedEvidenceError("SHA256SUMS is not ASCII") from error
    if not text.endswith("\n"):
        raise HostedEvidenceError("SHA256SUMS is not newline terminated")
    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        if match is None:
            raise HostedEvidenceError("SHA256SUMS line is malformed")
        digest, relative = match.groups()
        _relative_path(relative, "SHA256SUMS")
        if relative == "SHA256SUMS" or relative in entries:
            raise HostedEvidenceError("SHA256SUMS contains a duplicate/reserved path")
        entries[relative] = digest
    if list(entries) != sorted(entries):
        raise HostedEvidenceError("SHA256SUMS entries are not sorted")
    if set(entries) | {"SHA256SUMS"} != actual:
        raise HostedEvidenceError("evidence inventory does not match SHA256SUMS")
    expected_lines: list[bytes] = []
    for relative in sorted(entries):
        maximum = (
            MAX_ARCHIVE_BYTES if relative in archive_paths else MAX_JSON_BYTES
        )
        digest, _ = _hash_regular(
            root / relative, maximum, "checksummed evidence file"
        )
        if digest != entries[relative]:
            raise HostedEvidenceError(f"SHA256SUMS checksum mismatch: {relative}")
        expected_lines.append(f"{digest}  {relative}\n".encode("ascii"))
    if manifest != b"".join(expected_lines):
        raise HostedEvidenceError("SHA256SUMS canonical bytes mismatch")

    receipt_bytes = _read_regular(root / "receipt.json", MAX_JSON_BYTES, "receipt")
    receipt = _parse_json(receipt_bytes, "receipt")
    if not isinstance(receipt, dict):
        raise HostedEvidenceError("receipt is not an object")
    if receipt_bytes != _canonical_bytes(receipt):
        raise HostedEvidenceError("receipt is not canonical JSON")
    digest = _digest_bytes(receipt_bytes)
    sidecar = _read_regular(
        root / "receipt.json.sha256", 1024, "receipt checksum sidecar"
    )
    if sidecar != f"{digest}  receipt.json\n".encode("ascii"):
        raise HostedEvidenceError("receipt checksum sidecar mismatch")
    if _referenced_paths(receipt) != actual:
        raise HostedEvidenceError("receipt retained-file inventory mismatch")
    return receipt, actual


def verify_evidence(
    root: Path,
    *,
    repository: str,
    revision: str,
    source: SourceAuthority,
) -> dict[str, Any]:
    """Verify outer checksums, GitHub authority, and exact Git source afresh."""

    repository = _repository(repository)
    revision = _git_sha(revision, "source revision")
    receipt, inventory = _verify_outer(root)
    try:
        stability.project_hosted_exact_head_receipt(
            receipt, repository=repository, revision=revision
        )
    except stability.StabilityError as error:
        raise HostedEvidenceError(f"stability projector rejected receipt: {error}") from error
    source_record = receipt.get("source")
    if not isinstance(source_record, dict):
        raise HostedEvidenceError("receipt source is malformed")
    expected_tree = source_record.get("tree_sha1")
    _git_sha(expected_tree, "receipt source tree")
    rederived = _derive_receipt(
        root,
        repository,
        revision,
        source,
        expected_tree=expected_tree,
    )
    if rederived != receipt:
        raise HostedEvidenceError("receipt does not match rederived hosted authority")
    try:
        final_receipt, final_inventory = _verify_outer(root)
    except HostedEvidenceError as error:
        raise HostedEvidenceError(
            "hosted evidence changed during verification"
        ) from error
    if final_receipt != receipt or final_inventory != inventory:
        raise HostedEvidenceError(
            "hosted evidence changed during verification"
        )
    return receipt


def _fsync_directories(root: Path) -> None:
    directories = sorted(
        (path for path in root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    directories.append(root)
    for directory in directories:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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


def _remove_tree_identity(path: Path, device: int, inode: int) -> None:
    """Atomically quarantine and remove only the exact published tree."""

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
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or pinned.st_dev != device
            or pinned.st_ino != inode
        ):
            raise HostedEvidenceError(
                f"published tree identity changed: {path}"
            )

        for _attempt in range(128):
            candidate = (
                f".codeskeptic-hosted-cleanup-{secrets.token_hex(16)}"
            )
            quarantine_name = candidate
            try:
                _rename_noreplace_at(
                    parent_descriptor,
                    path.name,
                    parent_descriptor,
                    candidate,
                )
            except _HostedPublicationCollision:
                quarantine_name = None
                continue
            rename_completed = True
            break
        if quarantine_name is None:
            raise HostedEvidenceError(
                "hosted cleanup quarantine name budget exhausted"
            )
        os.fsync(parent_descriptor)

        metadata = os.stat(
            quarantine_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        pinned = os.fstat(owned_descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
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
            raise HostedEvidenceError(
                f"published tree identity changed: {path}"
            )

        deletion_started = True
        _make_tree_removable_at(parent_descriptor, quarantine_name)
        shutil.rmtree(quarantine_name, dir_fd=parent_descriptor)
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
                    cleanup_errors.append(HostedEvidenceError(
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
                    stat.S_ISDIR(quarantined.st_mode)
                    and quarantined.st_dev == device
                    and quarantined.st_ino == inode
                )
                if not exact_quarantine:
                    cleanup_errors.append(HostedEvidenceError(
                        "quarantined hosted tree identity changed"
                    ))
                else:
                    try:
                        _make_tree_removable_at(
                            parent_descriptor, quarantine_name
                        )
                        shutil.rmtree(
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
            raise HostedEvidenceError(
                "hosted tree cleanup failed; retained quarantine: "
                f"{retained}; primary failure: {error}; "
                f"cleanup failure: {cleanup_errors[0]}"
            ) from error
        if isinstance(error, HostedEvidenceError):
            raise
        if isinstance(error, OSError):
            suffix = (
                f"; partial tree retained at {path.parent / quarantine_name}"
                if deletion_started and quarantine_name is not None
                else ""
            )
            raise HostedEvidenceError(
                f"cannot remove published tree {path}: {error}{suffix}"
            ) from error
        raise
    finally:
        if owned_descriptor is not None:
            os.close(owned_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _create_private_staging_directory(
    parent: Path, prefix: str, label: str,
) -> tuple[Path, os.stat_result]:
    """Create and identity-pin a private random staging directory."""

    for _attempt in range(128):
        candidate = parent / f"{prefix}{secrets.token_hex(16)}"
        mkdir_returned = False
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
                raise HostedEvidenceError(f"{label} authority drift")
            _fsync_directory(parent)
            return candidate, metadata
        except FileExistsError:
            continue
        except BaseException as error:
            cleanup_errors: list[Exception] = []
            if mkdir_returned or not isinstance(error, Exception):
                try:
                    created = candidate.lstat()
                except FileNotFoundError:
                    created = None
                except Exception as cleanup_error:
                    created = None
                    cleanup_errors.append(cleanup_error)
                if created is not None:
                    try:
                        if (
                            not stat.S_ISDIR(created.st_mode)
                            or created.st_uid != os.geteuid()
                            or created.st_gid != os.getegid()
                            or stat.S_IMODE(created.st_mode) != 0o700
                        ):
                            raise HostedEvidenceError(
                                f"interrupted {label} authority drift"
                            )
                        _remove_tree_identity(
                            candidate, created.st_dev, created.st_ino
                        )
                    except Exception as cleanup_error:
                        cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                detail = "; ".join(str(item) for item in cleanup_errors)
                raise HostedEvidenceError(
                    f"{label}: primary failure: {error}; "
                    f"cleanup failure: {detail}"
                ) from error
            if isinstance(error, HostedEvidenceError):
                raise
            if isinstance(error, OSError):
                raise HostedEvidenceError(f"{label}: {error}") from error
            raise
    raise HostedEvidenceError(f"{label}: random name budget exhausted")


def _rename_noreplace_at(
    source_directory: int,
    source: str,
    target_directory: int,
    target: str,
) -> None:
    if not sys.platform.startswith("linux"):
        raise HostedEvidenceError(
            "atomic no-replace evidence publication requires Linux renameat2"
        )
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise HostedEvidenceError("atomic no-replace evidence publication is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    if renameat2(
        source_directory,
        source_bytes,
        target_directory,
        target_bytes,
        1,
    ) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise _HostedPublicationCollision(
                f"output already exists: {target}"
            )
        raise HostedEvidenceError(
            f"atomic no-replace evidence publication failed: {os.strerror(code)}"
        )


def _rename_noreplace(source: Path, target: Path) -> None:
    """Atomically publish a directory without replacing any existing target."""

    _rename_noreplace_at(
        -100, os.fspath(source), -100, os.fspath(target)
    )


def seal_evidence(
    output: Path,
    *,
    repository: str,
    revision: str,
    source: SourceAuthority,
    inputs: OfflineSnapshotInputs,
) -> dict[str, Any]:
    """Create a fresh accepted bundle from complete offline GitHub inputs."""

    repository = _repository(repository)
    revision = _git_sha(revision, "source revision")
    if output.exists() or output.is_symlink():
        raise HostedEvidenceError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    tree, workflows = _source_identity(source, repository, revision)
    staging, staging_metadata = _create_private_staging_directory(
        output.parent,
        f".{output.name}.tmp-",
        "hosted evidence staging creation failed",
    )
    publication_identity: tuple[int, int] | None = None
    publication_collision = False
    verified: dict[str, Any] | None = None
    primary: BaseException | None = None
    try:
        _stage_offline_inputs(
            staging, inputs, repository, revision, workflows
        )
        receipt = _derive_receipt(
            staging, repository, revision, source, expected_tree=tree
        )
        try:
            stability.project_hosted_exact_head_receipt(
                receipt, repository=repository, revision=revision
            )
        except stability.StabilityError as error:
            raise HostedEvidenceError(
                f"stability projector rejected generated receipt: {error}"
            ) from error
        _seal_outer(staging, receipt)
        verified = verify_evidence(
            staging,
            repository=repository,
            revision=revision,
            source=source,
        )
        _fsync_directories(staging)
        publication_metadata = staging.lstat()
        if (
            publication_metadata.st_dev != staging_metadata.st_dev
            or publication_metadata.st_ino != staging_metadata.st_ino
        ):
            raise HostedEvidenceError(
                "hosted evidence staging identity changed"
            )
        publication_identity = (
            publication_metadata.st_dev,
            publication_metadata.st_ino,
        )
        _rename_noreplace(staging, output)
        _fsync_directory(output.parent)
        published_metadata = output.lstat()
        if (
            not stat.S_ISDIR(published_metadata.st_mode)
            or (published_metadata.st_dev, published_metadata.st_ino)
            != publication_identity
        ):
            raise HostedEvidenceError(
                "published hosted evidence identity changed"
            )
    except _HostedPublicationCollision as error:
        publication_collision = True
        primary = error
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    try:
        try:
            remaining_staging = staging.lstat()
        except FileNotFoundError:
            remaining_staging = None
        if remaining_staging is not None:
            _remove_tree_identity(
                staging, staging_metadata.st_dev, staging_metadata.st_ino
            )
    except Exception as cleanup_error:
        cleanup_errors.append(cleanup_error)
    if (
        (primary is not None or cleanup_errors)
        and publication_identity is not None
        and not publication_collision
    ):
        try:
            try:
                published_metadata = output.lstat()
            except FileNotFoundError:
                published_metadata = None
            if published_metadata is not None and (
                published_metadata.st_dev,
                published_metadata.st_ino,
            ) == publication_identity:
                _remove_tree_identity(
                    output, publication_identity[0], publication_identity[1]
                )
            elif published_metadata is not None:
                raise HostedEvidenceError(
                    "published hosted evidence identity changed"
                )
        except Exception as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if primary is not None and cleanup_errors:
        detail = "; ".join(str(item) for item in cleanup_errors)
        raise HostedEvidenceError(
            "hosted evidence publication failed: "
            f"primary failure: {primary}; cleanup failure: {detail}"
        ) from primary
    if primary is not None:
        if isinstance(primary, HostedEvidenceError):
            raise primary
        if not isinstance(primary, Exception):
            raise primary
        raise HostedEvidenceError(
            f"hosted evidence publication failed: {primary}"
        ) from primary
    if cleanup_errors:
        detail = "; ".join(str(item) for item in cleanup_errors)
        raise HostedEvidenceError(
            f"hosted evidence publication cleanup failed: {detail}"
        ) from cleanup_errors[0]
    assert verified is not None
    return verified


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("seal", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--repository-root", type=Path, required=True)
        subparser.add_argument("--repository", required=True)
        subparser.add_argument("--revision", required=True)
        if command == "seal":
            subparser.add_argument("--offline-input", type=Path, required=True)
            subparser.add_argument("--output", type=Path, required=True)
        else:
            subparser.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    source = GitSourceAuthority(
        arguments.repository_root, repository=arguments.repository
    )
    try:
        if arguments.command == "seal":
            receipt = seal_evidence(
                arguments.output,
                repository=arguments.repository,
                revision=arguments.revision,
                source=source,
                inputs=OfflineSnapshotInputs(arguments.offline_input),
            )
            root = arguments.output
            marker = "CODESKEPTIC_HOSTED_EXACT_HEAD_SEALED"
        else:
            receipt = verify_evidence(
                arguments.evidence,
                repository=arguments.repository,
                revision=arguments.revision,
                source=source,
            )
            root = arguments.evidence
            marker = "CODESKEPTIC_HOSTED_EXACT_HEAD_VERIFIED"
        receipt_digest, _ = _hash_regular(
            root / "receipt.json", MAX_JSON_BYTES, "receipt"
        )
        print(f"{marker} {receipt_digest} {receipt['source']['revision']}")
        return 0
    except HostedEvidenceError as error:
        print(f"CODESKEPTIC_HOSTED_EXACT_HEAD_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
