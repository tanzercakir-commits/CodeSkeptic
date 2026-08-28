#!/usr/bin/env python3
"""Run, assemble, and verify the retained Phase 10 quality-floor campaign.

The producer intentionally derives every score from retained analyzer JSON,
requested-file lists, and coverage receipts.  Human-readable Juliet output and
historical dashboard summaries are never metric inputs.

Typical use::

  run_quality_floor_campaign.py run --source ... --build-authority ... \
      --build-dir ... --juliet-dir ... --juliet-archive ... \
      --libarchive-checkout ... --output ...
  run_quality_floor_campaign.py assemble --source ... --build-authority ... \
      --build-dir ... --package ...
  run_quality_floor_campaign.py verify --source ... --build-authority ... \
      --build-dir ... --package ...

The long ``run`` action is offline: it requires an existing Juliet tree and a
clean, pinned libarchive checkout.  ``assemble`` is also exposed so completed
raw runs can be sealed without repeating the expensive analyzer executions.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import re
import secrets
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import juliet_eval  # noqa: E402
import analyzer_build_authority as build_authority  # noqa: E402
import quality_floor_receipt as quality  # noqa: E402
import run_realworld_campaign as realworld  # noqa: E402
import run_stress_matrix as stress  # noqa: E402


SCHEMA = "codeskeptic-quality-floor-campaign-v1"
BUNDLE_SCHEMA = "codeskeptic-quality-floor-bundle-evidence-v1"
JULIET_INPUT_SCHEMA = "codeskeptic-quality-floor-juliet-input-v1"
RESOURCE_INPUT_SCHEMA = "codeskeptic-quality-floor-resource-input-v1"
RESOURCE_OBSERVATION_SCHEMA = "codeskeptic-quality-floor-resource-observation-v1"
OPERATOR_SCHEMA = "codeskeptic-quality-floor-operator-v1"
MUTATION_SCHEMA = "codeskeptic-quality-floor-resource-mutations-v1"
AUTHORITY_SCHEMA = "codeskeptic-quality-floor-raw-authority-v1"
AUTHORITY_NAME = "campaign-authority.json"
CAMPAIGN_RUNTIME_V1_SCHEMA = "codeskeptic-quality-floor-runtime-v1"
CAMPAIGN_RUNTIME_SCHEMA = "codeskeptic-quality-floor-runtime-v2"
CAMPAIGN_LAUNCH_SCHEMA = "codeskeptic-quality-floor-launch-v1"
EXECUTION_AUTHORITY_SCHEMA = "codeskeptic-quality-floor-execution-authority-v1"
CAMPAIGN_LAUNCH_NAME = "campaign-launch-authority.json"
CAMPAIGN_INNER_TOKEN_ENV = "CODESKEPTIC_QUALITY_FLOOR_LAUNCH_SHA256"
CAMPAIGN_INNER_ENV_TOKEN_ENV = "CODESKEPTIC_QUALITY_FLOOR_ENV_SHA256"
FIXED_COMPILER = "/usr/bin/clang-20"
MAX_CAMPAIGN_LOG_BYTES = 64 << 20
MAX_CAMPAIGN_FAILURE_DETAIL_CHARS = 2048
AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2

MUTATION_PATH = SCRIPT_DIR / "quality_floor_resource_mutations.json"
JULIET_SCRIPT = SCRIPT_DIR / "run_juliet.sh"
THESIS_MANIFEST = ROOT / "tests" / "thesis_corpus" / "thesis_expected.txt"
THESIS_ROOT = THESIS_MANIFEST.parent
REALWORLD_MANIFEST = SCRIPT_DIR / "realworld_manifest.json"

JULIET_RULES = {
    "CWE401_Memory_Leak": "memory-leak",
    "CWE415_Double_Free": "double-free",
    "CWE416_Use_After_Free": "use-after-free",
    "CWE369_Divide_by_Zero": "div-by-zero",
    "CWE476_NULL_Pointer_Dereference": "null-deref",
    "CWE190_Integer_Overflow": "int-overflow",
}
JULIET_ARCHIVE_SHA256 = (
    "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
)
JULIET_INPUT_MANIFEST_SHA256 = (
    "4b94a809a8d0f85c421d9622c6c8b15e1663ab489027c5d332d5fdbe4d6baace"
)
JULIET_CASE_COUNTS = {
    "CWE401_Memory_Leak": 397,
    "CWE415_Double_Free": 399,
    "CWE416_Use_After_Free": 397,
    "CWE369_Divide_by_Zero": 397,
    "CWE476_NULL_Pointer_Dereference": 400,
    "CWE190_Integer_Overflow": 401,
}
JULIET_ENTRY_COUNT = 2392
RESOURCE_REVISION = "27cbc7827172698143e440801fc0ba39ccb4f1f5"
RESOURCE_TREE_OID = "7e56e62d504013b00eae01739d2fe01e45dbbe84"
RESOURCE_CLEAN_ENTRIES_SHA256 = (
    "eb4f35dbaa89f184b37a9d65c178c72dd2ac7842e94015e475db4f81c421e6ea"
)
RESOURCE_MUTATED_ENTRIES_SHA256 = (
    "a574a08ac5d167f76cdca18e9f51ca2ac7403b71ecd2ba135771c8930954b714"
)
RESOURCE_FUNCTIONS = {
    "archive_read_disk_entry_from_file",
    "_archive_write_disk_close",
    "set_fflags_platform",
}
RESOURCE_EXCLUDED_FALLBACKS = (
    "libarchive/archive_disk_acl_darwin.c",
    "libarchive/archive_disk_acl_freebsd.c",
    "libarchive/archive_disk_acl_linux.c",
    "libarchive/archive_disk_acl_sunos.c",
    "libarchive/archive_entry_copy_bhfi.c",
    "libarchive/archive_read_disk_windows.c",
    "libarchive/archive_windows.c",
    "libarchive/archive_write_disk_windows.c",
    "libarchive/filter_fork_windows.c",
)
RESOURCE_BROKEN_CASE = "mixed-clean-broken"
RESOURCE_MISSING_CASE = "missing-requested-tu"
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_OID = re.compile(r"[0-9a-f]{40}")
RFC3339_UTC = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z"
)

AUTHORITY_INPUT_PATHS = (
    "scripts/analyzer_build_authority.py",
    "scripts/run_determinism_qualification.py",
    "scripts/podman-config/containers/mounts.conf",
    "scripts/run_quality_floor_campaign.py",
    "scripts/run_juliet.sh",
    "scripts/juliet_eval.py",
    "scripts/quality_floor_receipt.py",
    "scripts/quality_floor_resource_mutations.json",
    "scripts/run_realworld_campaign.py",
    "scripts/run_stress_matrix.py",
    "scripts/realworld_manifest.json",
    "tests/thesis_corpus/thesis_expected.txt",
)
CAPABILITY_REGISTRY_RELATIVE = "src/core/RuleCapabilities.def"
BUILD_AUTHORITY_RAW_DIR = "build-authority"
CAMPAIGN_CONTAINER_LAYOUTS = ("legacy", "p10-09")
PUBLIC_ACTIONS = frozenset({"run", "assemble", "verify"})
CAMPAIGN_CHILD_GRACE_SECONDS = 2.0
CAMPAIGN_CONTAINER_CONTROL_TIMEOUT_SECONDS = 60.0
CAMPAIGN_CONTAINER_CONTROL_OUTPUT_BYTES = 1 << 20
CAMPAIGN_CONTAINER_TOKEN_LABEL = "codeskeptic.quality.token"


class CampaignError(RuntimeError):
    """Raw evidence is absent, ambiguous, stale, or internally inconsistent."""


class CampaignInterrupted(BaseException):
    """A public campaign action was interrupted after controlled cleanup."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"campaign interrupted by signal {signum}")
        self.signum = signum
        self.recovery_paths: list[Path] = []
        self.cleanup_failures: list[str] = []


@dataclass(frozen=True)
class CampaignContainerAuthority:
    cidfile: Path
    name: str
    token: str


class CampaignRecoveryRequired(CampaignError):
    """Exact container cleanup failed; retain private recovery evidence."""

    def __init__(
        self, message: str, authority: CampaignContainerAuthority
    ) -> None:
        super().__init__(message)
        self.authority = authority
        self.recovery_paths: list[Path] = []


def _campaign_children() -> dict[int, int]:
    known: dict[int, int] = {}
    realworld._refresh_descendants(os.getpid(), known)
    return known


def _campaign_children_quiescent() -> bool:
    known = _campaign_children()
    alive = any(
        realworld._pid_matches(pid, started)
        for pid, started in known.items()
    )
    return realworld._child_table_empty() and not alive


def _wait_for_campaign_children(timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _campaign_children_quiescent():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _terminate_campaign_children() -> None:
    known = _campaign_children()
    controller_group = os.getpgrp()
    for signal_number, timeout_seconds in (
        (signal.SIGTERM, 0.25),
        (signal.SIGKILL, 1.0),
    ):
        deadline = time.monotonic() + timeout_seconds
        while True:
            realworld._refresh_descendants(os.getpid(), known)
            groups: set[int] = set()
            for pid, started in list(known.items()):
                record = realworld._proc_record(pid)
                if record is None or record[2] != started:
                    continue
                if record[1] != controller_group:
                    groups.add(record[1])
            for group in groups:
                try:
                    os.killpg(group, signal_number)
                except ProcessLookupError:
                    pass
            for pid, started in list(known.items()):
                if realworld._pid_matches(pid, started):
                    try:
                        os.kill(pid, signal_number)
                    except ProcessLookupError:
                        pass
            realworld._child_table_empty()
            if _campaign_children_quiescent():
                return
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
    survivors = sorted(
        pid
        for pid, started in known.items()
        if realworld._pid_matches(pid, started)
    )
    if survivors or not realworld._child_table_empty():
        raise CampaignError("campaign descendant cleanup was incomplete")


@contextmanager
def _campaign_signal_guard(*, enabled: bool):
    if not enabled:
        yield
        return
    if (
        os.name != "posix"
        or not Path("/proc").is_dir()
        or threading.current_thread() is not threading.main_thread()
    ):
        raise CampaignError(
            "public campaign interruption containment requires a Linux main thread"
        )
    if not realworld._enable_subreaper():
        raise CampaignError("public campaign could not establish subreaper authority")
    try:
        realworld._require_empty_child_table()
    except realworld.EvidenceError as error:
        raise CampaignError(str(error)) from error
    handled = (signal.SIGTERM, signal.SIGHUP)
    previous = {number: signal.getsignal(number) for number in handled}

    def interrupt(signum: int, _frame: object) -> None:
        for number in handled:
            signal.signal(number, signal.SIG_IGN)
        raise CampaignInterrupted(signum)

    for number in handled:
        signal.signal(number, interrupt)
    try:
        yield
        if not _wait_for_campaign_children(CAMPAIGN_CHILD_GRACE_SECONDS):
            _terminate_campaign_children()
            raise CampaignError("public campaign action left a descendant alive")
    except CampaignInterrupted as error:
        try:
            _terminate_campaign_children()
        except CampaignError as cleanup_error:
            error.cleanup_failures.append(str(cleanup_error))
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def compact_json_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _bad_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def strict_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_bad_constant,
        )
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise CampaignError(f"cannot read strict JSON {path}: {error}") from error


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(payload))


def _regular(path: Path, label: str) -> Path:
    path = Path(path)
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise CampaignError(f"{label} is missing or unsafe: {path}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise CampaignError(f"{label} is missing or unsafe: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"{label} is missing or unsafe: {path}") from error


def _directory(path: Path, label: str) -> Path:
    path = Path(path)
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise CampaignError(f"{label} is missing or unsafe: {path}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise CampaignError(f"{label} is missing or unsafe: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"{label} is missing or unsafe: {path}") from error


def _relative_regular(root: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise CampaignError(f"{label} is not a canonical relative path")
    root = _directory(root, f"{label} root")
    lexical = Path(relative)
    if lexical.as_posix() != relative or any(part in ("", ".", "..") for part in lexical.parts):
        raise CampaignError(f"{label} is not canonical: {relative}")
    cursor = root
    for part in lexical.parts:
        cursor = cursor / part
        try:
            if stat.S_ISLNK(cursor.lstat().st_mode):
                raise CampaignError(f"{label} is unsafe: {relative}")
        except FileNotFoundError:
            raise CampaignError(f"{label} is missing or unsafe: {relative}") from None
        except OSError as error:
            raise CampaignError(f"{label} is missing or unsafe: {relative}") from error
    candidate = cursor.resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise CampaignError(f"{label} escapes its root: {relative}") from error
    if candidate.relative_to(root).as_posix() != relative:
        raise CampaignError(f"{label} is not canonical: {relative}")
    return _regular(candidate, label)


def _canonical_posix_absolute_path(value: Any, label: str) -> PurePosixPath:
    """Interpret retained container paths independently of the host platform."""
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("//")
    ):
        raise CampaignError(f"{label} is not a canonical container path")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.as_posix() != value
        or "." in path.parts
        or ".." in path.parts
    ):
        raise CampaignError(f"{label} is not a canonical container path")
    return path


def _normalize_retained_package_path(value: Any) -> str:
    path = _canonical_posix_absolute_path(value, "retained package artifact path")
    marker = "/raw/"
    normalized = path.as_posix()
    if marker not in normalized:
        raise CampaignError("retained package artifact path is outside raw evidence")
    return "raw/" + normalized.split(marker, 1)[1]


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    log: Path,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log.open("wb") as stream:
            completed = subprocess.run(
                list(command),
                cwd=cwd,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CampaignError(f"command failed to execute: {command[0]}: {error}") from error
    return completed.returncode


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=build_authority.determinism._git_authority_environment(cwd),
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CampaignError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def _source_identity(
    *, require_clean: bool, root: Path = ROOT
) -> dict[str, str]:
    root = _directory(root, "campaign source root")
    revision = _git(root, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise CampaignError("source HEAD is not an exact Git revision")
    if require_clean:
        dirty = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
        if dirty:
            raise CampaignError("quality-floor run requires a clean exact-head source tree")
    try:
        manifest = build_authority.determinism.source_manifest(root)
    except (build_authority.determinism.QualificationError, OSError) as error:
        raise CampaignError(f"cannot derive build-authority source manifest: {error}") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("revision") != revision
        or not isinstance(manifest.get("manifest_sha256"), str)
        or SHA256.fullmatch(manifest["manifest_sha256"]) is None
        or type(manifest.get("file_count")) is not int
        or manifest["file_count"] <= 0
    ):
        raise CampaignError("build-authority source manifest is malformed")
    return {
        "revision": revision,
        "manifest_sha256": manifest["manifest_sha256"],
    }


def _verify_retained_source_identity(
    retained: Any, *, require_clean: bool, root: Path = ROOT
) -> dict[str, str]:
    if (
        not isinstance(retained, dict)
        or set(retained) != {"revision", "manifest_sha256"}
        or not isinstance(retained["revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", retained["revision"]) is None
        or not isinstance(retained["manifest_sha256"], str)
        or SHA256.fullmatch(retained["manifest_sha256"]) is None
    ):
        raise CampaignError("retained source identity is malformed")
    root = _directory(root, "campaign source root")
    current = _source_identity(require_clean=require_clean, root=root)
    if retained["manifest_sha256"] != current["manifest_sha256"]:
        raise CampaignError("current source bytes differ from retained campaign source")
    if retained["revision"] != current["revision"]:
        completed = subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                retained["revision"],
                current["revision"],
            ],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env=build_authority.determinism._git_authority_environment(root),
        )
        if completed.returncode != 0:
            raise CampaignError(
                "retained source revision is not the current HEAD or its ancestor"
            )
    return {
        "revision": retained["revision"],
        "manifest_sha256": retained["manifest_sha256"],
    }


def _binary_identity(binary: Path) -> dict[str, str]:
    binary = _regular(binary, "analyzer binary")
    completed = subprocess.run(
        [str(binary), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    version = completed.stdout.strip()
    if completed.returncode != 0 or not version.startswith("CodeSkeptic "):
        raise CampaignError("analyzer --version tripwire failed")
    return {"version": version, "binary_sha256": sha256_file(binary)}


def _require_build_binary(binary: Path, build_dir: Path) -> tuple[Path, Path]:
    """Require the caller's analyzer to be the build authority's exact output."""
    build_dir = _directory(build_dir, "populated analyzer build directory")
    expected = _relative_regular(
        build_dir,
        build_authority.ANALYZER_RELATIVE,
        "build-authority analyzer binary",
    )
    supplied = _regular(binary, "analyzer binary")
    if Path(binary).absolute() != expected or supplied != expected:
        raise CampaignError(
            "analyzer binary must be exactly build-dir/"
            f"{build_authority.ANALYZER_RELATIVE}"
        )
    return expected, build_dir


def _build_authority_entries(authority_dir: Path) -> list[dict[str, Any]]:
    authority_dir = _directory(authority_dir, "published analyzer build authority")
    admitted = set(build_authority.AUTHORITY_FILES)
    entries: list[dict[str, Any]] = []
    actual: set[str] = set()
    for path in authority_dir.iterdir():
        if path.is_symlink() or not path.is_file():
            raise CampaignError("analyzer build authority contains an unsafe entry")
        if path.name in actual:
            raise CampaignError("analyzer build authority file set is ambiguous")
        actual.add(path.name)
        entries.append(
            {
                "path": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    if actual != admitted:
        raise CampaignError("analyzer build authority file set is not exact")
    return sorted(entries, key=lambda item: item["path"])


def _build_authority_record(
    authority_dir: Path, receipt: Any
) -> dict[str, Any]:
    entries = _build_authority_entries(authority_dir)
    if not isinstance(receipt, dict):
        raise CampaignError("analyzer build authority receipt is malformed")
    source = receipt.get("source")
    analyzer = receipt.get("analyzer")
    runtime = receipt.get("runtime")
    build_identity = receipt.get("build_identity_sha256")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "manifest_sha256", "file_count"}
        or not isinstance(source.get("revision"), str)
        or GIT_OID.fullmatch(source["revision"]) is None
        or not isinstance(source.get("manifest_sha256"), str)
        or SHA256.fullmatch(source["manifest_sha256"]) is None
        or type(source.get("file_count")) is not int
        or source["file_count"] <= 0
    ):
        raise CampaignError("analyzer build authority source is malformed")
    if (
        not isinstance(analyzer, dict)
        or set(analyzer) != {"path", "sha256", "version"}
        or analyzer.get("path") != build_authority.ANALYZER_RELATIVE
        or not isinstance(analyzer.get("sha256"), str)
        or SHA256.fullmatch(analyzer["sha256"]) is None
        or not isinstance(analyzer.get("version"), str)
        or not analyzer["version"].startswith("CodeSkeptic ")
    ):
        raise CampaignError("analyzer build authority analyzer is malformed")
    if not isinstance(runtime, dict) or not runtime:
        raise CampaignError("analyzer build authority runtime is malformed")
    if not isinstance(build_identity, str) or SHA256.fullmatch(build_identity) is None:
        raise CampaignError("analyzer build authority identity is malformed")
    record = {
        "path": BUILD_AUTHORITY_RAW_DIR,
        "file_count": len(entries),
        "bundle_sha256": compact_json_digest(entries),
        "build_identity_sha256": build_identity,
        "runtime": copy_json(runtime),
        "source": copy_json(source),
        "analyzer": copy_json(analyzer),
    }
    _campaign_container_layout(record)
    return record


def _verify_build_authority(
    authority_dir: Path,
    build_dir: Path,
    source: dict[str, str],
    *,
    source_root: Path,
    verifier: Callable[[Path, Path, Path], dict[str, Any]],
) -> tuple[dict[str, Any], Path, Path]:
    build_dir = _directory(build_dir, "populated analyzer build directory")
    binary, build_dir = _require_build_binary(
        build_dir / build_authority.ANALYZER_RELATIVE, build_dir
    )
    authority_dir = _directory(authority_dir, "published analyzer build authority")
    try:
        receipt = verifier(authority_dir, source_root, build_dir)
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(f"analyzer build authority rejected: {error}") from error
    record = _build_authority_record(authority_dir, receipt)
    source_projection = {
        "revision": record["source"]["revision"],
        "manifest_sha256": record["source"]["manifest_sha256"],
    }
    if source_projection != source:
        raise CampaignError("analyzer build authority source differs from campaign source")
    analyzer = _binary_identity(binary)
    analyzer_projection = {
        "version": record["analyzer"]["version"],
        "binary_sha256": record["analyzer"]["sha256"],
    }
    if analyzer_projection != analyzer:
        raise CampaignError("analyzer build authority analyzer differs from supplied binary")
    return record, binary, build_dir


def _verify_retained_build_authority_static(
    authority_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify the retained build bundle without Podman or a materialized build."""
    authority_dir = _directory(
        authority_dir, "retained analyzer build authority"
    )
    try:
        receipt = build_authority._verify_bundle_structure(
            authority_dir,
            None,
            final=True,
            podman=build_authority.DEFAULT_PODMAN,
        )
        record = _build_authority_record(authority_dir, receipt)
        container_layout = _campaign_container_layout(record)
        expected_operator = build_authority._expected_operator_log(
            build_authority._inner_build_identity_from_final(receipt),
            container_layout,
        )
        if (authority_dir / "operator.log").read_bytes() != expected_operator:
            raise build_authority.BuildAuthorityError(
                "operator.log differs from the re-derived inner completion record"
            )
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(
            f"retained analyzer build authority rejected: {error}"
        ) from error
    return record, receipt


def _verify_retained_source_authority(
    source_root: Path,
    build_receipt: dict[str, Any],
    *,
    require_current_source: bool = True,
) -> dict[str, str]:
    """Re-derive the retained build source at its committed revision."""
    source_root = _directory(source_root, "campaign source root")
    recorded = build_receipt["source"]
    try:
        build_authority.determinism._verify_source_authority(
            recorded,
            source_root,
            "retained quality-floor package",
            require_current_source=require_current_source,
        )
    except (build_authority.determinism.QualificationError, OSError) as error:
        raise CampaignError(
            f"retained campaign source authority rejected: {error}"
        ) from error
    return {
        "revision": recorded["revision"],
        "manifest_sha256": recorded["manifest_sha256"],
    }


def _copy_build_authority(source: Path, raw_root: Path) -> Path:
    source = _directory(source, "published analyzer build authority")
    source_entries = _build_authority_entries(source)
    target = raw_root / BUILD_AUTHORITY_RAW_DIR
    if target.exists() or target.is_symlink():
        raise CampaignError("retained analyzer build authority already exists")
    target.mkdir()
    try:
        for entry in source_entries:
            source_file = _regular(
                source / entry["path"], "published analyzer build authority file"
            )
            target_file = target / entry["path"]
            with source_file.open("rb") as reader, target_file.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
        if _build_authority_entries(target) != source_entries:
            raise CampaignError("retained analyzer build authority copy differs")
    except Exception:
        if target.exists() and target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        raise
    return target


def _script_identities(root: Path = ROOT) -> dict[str, str]:
    root = _directory(root, "campaign script authority root")
    return {
        relative: sha256_file(_regular(root / relative, f"authority input {relative}"))
        for relative in AUTHORITY_INPUT_PATHS
    }


def _source_authority_material(
    root: Path, *, revision: str | None = None
) -> dict[str, Any]:
    """Return executable quality inputs from current or recorded source bytes."""
    root = _directory(root, "campaign source authority root")
    relatives = (*AUTHORITY_INPUT_PATHS, CAPABILITY_REGISTRY_RELATIVE)
    try:
        if revision is None:
            blobs = {
                relative: _regular(
                    root / relative, f"source authority input {relative}"
                ).read_bytes()
                for relative in relatives
            }
        else:
            blobs = {
                relative: build_authority.determinism._git_blob(
                    root, revision, relative
                )
                for relative in relatives
            }
    except (build_authority.determinism.QualificationError, OSError) as error:
        raise CampaignError(
            f"cannot re-derive quality source authority material: {error}"
        ) from error
    return {
        "scripts": {
            relative: sha256_bytes(blobs[relative])
            for relative in AUTHORITY_INPUT_PATHS
        },
        "mutation_manifest": blobs[
            "scripts/quality_floor_resource_mutations.json"
        ],
        "capability_registry": blobs[CAPABILITY_REGISTRY_RELATIVE],
    }


def _validate_juliet_archive(path: Path) -> dict[str, Any]:
    archive = _regular(path, "official Juliet archive")
    digest = sha256_file(archive)
    if digest != JULIET_ARCHIVE_SHA256:
        raise CampaignError("Juliet archive is not the official pinned v1.3 archive")
    if archive.stat().st_size != 152957342:
        raise CampaignError("Juliet archive size differs from the pinned identity")
    return {
        "archive_sha256": digest,
        "archive_size": archive.stat().st_size,
        "selected_entry_count": JULIET_ENTRY_COUNT,
        "selected_manifest_sha256": JULIET_INPUT_MANIFEST_SHA256,
        "case_counts": dict(JULIET_CASE_COUNTS),
    }


def _official_corpus_identity() -> dict[str, Any]:
    return {
        "archive_sha256": JULIET_ARCHIVE_SHA256,
        "archive_size": 152957342,
        "selected_entry_count": JULIET_ENTRY_COUNT,
        "selected_manifest_sha256": JULIET_INPUT_MANIFEST_SHA256,
        "case_counts": dict(JULIET_CASE_COUNTS),
    }


def _rfc3339_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_rfc3339(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        raise CampaignError(f"raw campaign {label} is not RFC3339 UTC")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CampaignError(f"raw campaign {label} is not RFC3339 UTC") from error
    if parsed.utcoffset() != dt.timedelta(0):
        raise CampaignError(f"raw campaign {label} is not RFC3339 UTC")
    return parsed


def _raw_authority_entries(raw_root: Path) -> list[dict[str, Any]]:
    raw_root = _directory(raw_root, "raw campaign directory")
    entries: list[dict[str, Any]] = []
    for path in raw_root.rglob("*"):
        if path.is_symlink():
            raise CampaignError(f"raw evidence contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise CampaignError(f"raw evidence contains an unsafe node: {path}")
        relative = path.relative_to(raw_root).as_posix()
        if relative == AUTHORITY_NAME:
            continue
        entries.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return sorted(entries, key=lambda item: item["path"])


def _raw_artifact_summary(raw_root: Path) -> dict[str, Any]:
    entries = _raw_authority_entries(raw_root)
    if not entries:
        raise CampaignError("raw campaign has no completed operator evidence")
    return {
        "file_count": len(entries),
        "manifest_sha256": compact_json_digest(entries),
    }


def _new_raw_authority(
    source: dict[str, str],
    analyzer: dict[str, str],
    analyzer_build: dict[str, Any],
    execution_authority: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": AUTHORITY_SCHEMA,
        "run": {
            "schema": SCHEMA,
            "id": str(uuid.uuid4()),
            "state": "running",
            "started_at": _rfc3339_now(),
            "completed_at": None,
        },
        "source": source,
        "analyzer": analyzer,
        "analyzer_build_authority": analyzer_build,
        "execution_authority": execution_authority,
        "official_corpus": _official_corpus_identity(),
        "scripts": _script_identities(),
        "raw_artifacts": None,
    }


def _authority_binding(authority: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": AUTHORITY_SCHEMA,
        "run_id": authority["run"]["id"],
        "source": authority["source"],
        "analyzer": authority["analyzer"],
        "analyzer_build_authority": authority["analyzer_build_authority"],
        "execution_authority": authority["execution_authority"],
    }


def _write_initial_authority(
    raw_root: Path,
    source: dict[str, str],
    analyzer: dict[str, str],
    analyzer_build: dict[str, Any],
    execution_authority: dict[str, Any],
) -> dict[str, Any]:
    authority = _new_raw_authority(
        source, analyzer, analyzer_build, execution_authority
    )
    write_json(raw_root / AUTHORITY_NAME, authority)
    return authority


def _finalize_raw_authority(
    raw_root: Path, authority: dict[str, Any], binary: Path
) -> dict[str, Any]:
    path = _regular(raw_root / AUTHORITY_NAME, "raw campaign authority")
    retained = strict_json(path)
    if retained != authority or path.read_bytes() != canonical_json(retained):
        raise CampaignError("raw campaign start authority drifted during execution")
    if authority["scripts"] != _script_identities():
        raise CampaignError("campaign scripts changed during the raw run")
    if authority["source"] != _source_identity(require_clean=True):
        raise CampaignError("source identity changed during the raw run")
    if authority["analyzer"] != _binary_identity(binary):
        raise CampaignError("analyzer binary changed during the raw run")
    completed = copy_json(authority)
    completed["run"]["state"] = "complete"
    completed["run"]["completed_at"] = _rfc3339_now()
    completed["raw_artifacts"] = _raw_artifact_summary(raw_root)
    write_json(path, completed)
    return completed


def copy_json(value: Any) -> Any:
    """Return a JSON-only deep copy without accepting non-finite values."""
    return json.loads(canonical_json(value))


def _raw_authority_payload(
    package: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    raw_root = _directory(package / "raw", "raw campaign directory")
    path = _regular(raw_root / AUTHORITY_NAME, "raw campaign authority")
    authority = strict_json(path)
    required = {
        "schema",
        "run",
        "source",
        "analyzer",
        "analyzer_build_authority",
        "execution_authority",
        "official_corpus",
        "scripts",
        "raw_artifacts",
    }
    if not isinstance(authority, dict) or set(authority) != required:
        raise CampaignError("raw campaign authority fields are malformed")
    return raw_root, path, authority


def _campaign_analyzer_from_build(build_record: dict[str, Any]) -> dict[str, str]:
    analyzer = build_record["analyzer"]
    return {
        "version": analyzer["version"],
        "binary_sha256": analyzer["sha256"],
    }


def _validate_raw_authority_envelope(
    package: Path,
    *,
    source_root: Path,
    verified_source: dict[str, str],
    verified_analyzer: dict[str, str],
    verified_build: dict[str, Any],
    expected_scripts: dict[str, str] | None = None,
) -> dict[str, Any]:
    source_root = _directory(source_root, "campaign source root")
    raw_root, path, authority = _raw_authority_payload(package)
    if authority["schema"] != AUTHORITY_SCHEMA:
        raise CampaignError("raw campaign authority schema drift")
    run = authority["run"]
    if not isinstance(run, dict) or set(run) != {
        "schema",
        "id",
        "state",
        "started_at",
        "completed_at",
    }:
        raise CampaignError("raw campaign run identity is malformed")
    try:
        run_id = uuid.UUID(run["id"])
    except (AttributeError, TypeError, ValueError) as error:
        raise CampaignError("raw campaign run id is malformed") from error
    if (
        str(run_id) != run["id"]
        or run["schema"] != SCHEMA
        or run["state"] != "complete"
    ):
        raise CampaignError("raw campaign is not a completed canonical run")
    started = _parse_rfc3339(run["started_at"], "start")
    completed = _parse_rfc3339(run["completed_at"], "completion")
    if completed < started:
        raise CampaignError("raw campaign completion precedes its start")
    if authority["official_corpus"] != _official_corpus_identity():
        raise CampaignError("raw campaign official corpus identity drift")
    scripts = (
        _script_identities(source_root)
        if expected_scripts is None
        else expected_scripts
    )
    if authority["scripts"] != scripts:
        raise CampaignError("raw campaign script identity drift")
    if authority["source"] != verified_source:
        raise CampaignError("raw campaign source is stale or mixed")
    if authority["analyzer"] != verified_analyzer:
        raise CampaignError("raw campaign analyzer binary mismatch")
    if authority["analyzer_build_authority"] != verified_build:
        raise CampaignError("retained analyzer build authority identity mismatch")
    retained_launch = _relative_regular(
        raw_root, CAMPAIGN_LAUNCH_NAME, "retained campaign launch authority"
    )
    execution = _validate_retained_execution_authority(
        retained_launch, verified_build
    )
    if authority["execution_authority"] != execution:
        raise CampaignError("retained campaign execution authority identity mismatch")
    if authority["raw_artifacts"] != _raw_artifact_summary(raw_root):
        raise CampaignError("raw campaign artifact authority mismatch")
    if path.read_bytes() != canonical_json(authority):
        raise CampaignError("raw campaign authority is not canonical JSON")
    return authority


def _validate_raw_authority(
    package: Path,
    build_dir: Path,
    *,
    build_verifier: Callable[[Path, Path, Path], dict[str, Any]],
    require_clean_source: bool,
    exact_source_revision: bool,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    source_root = _directory(source_root, "campaign source root")
    binary, build_dir = _require_build_binary(
        Path(build_dir) / build_authority.ANALYZER_RELATIVE, build_dir
    )
    raw_root, _path, retained_authority = _raw_authority_payload(package)
    retained_source = retained_authority["source"]
    verified_analyzer = _binary_identity(binary)
    if retained_authority["analyzer"] != verified_analyzer:
        raise CampaignError("raw campaign analyzer binary mismatch")
    if exact_source_revision:
        verified_source = _source_identity(
            require_clean=require_clean_source, root=source_root
        )
        if retained_source != verified_source:
            raise CampaignError("raw campaign source is stale or mixed")
    else:
        verified_source = _verify_retained_source_identity(
            retained_source,
            require_clean=require_clean_source,
            root=source_root,
        )
    retained_build = raw_root / BUILD_AUTHORITY_RAW_DIR
    verified_build, _binary, _build_dir = _verify_build_authority(
        retained_build,
        build_dir,
        retained_source,
        source_root=source_root,
        verifier=build_verifier,
    )
    return _validate_raw_authority_envelope(
        package,
        source_root=source_root,
        verified_source=verified_source,
        verified_analyzer=verified_analyzer,
        verified_build=verified_build,
    )


def _require_operator_authority(
    payload: dict[str, Any], authority: dict[str, Any], label: str
) -> None:
    if payload.get("authority") != _authority_binding(authority):
        raise CampaignError(f"{label} is stale or belongs to a mixed campaign")


def _load_mutations(path: Path = MUTATION_PATH) -> dict[str, Any]:
    payload = strict_json(path)
    if not isinstance(payload, dict) or set(payload) != {
        "schema", "project", "mutations"
    }:
        raise CampaignError("resource mutation manifest fields are malformed")
    if payload["schema"] != MUTATION_SCHEMA:
        raise CampaignError("resource mutation manifest schema drift")
    project = payload["project"]
    if not isinstance(project, dict) or set(project) != {
        "id",
        "revision",
        "translation_units",
        "translation_unit_sha256",
        "source_files",
    }:
        raise CampaignError("resource mutation project identity is malformed")
    if (
        project["id"] != "libarchive"
        or project["revision"] != RESOURCE_REVISION
        or project["translation_units"] != 123
        or not isinstance(project["translation_unit_sha256"], str)
        or SHA256.fullmatch(project["translation_unit_sha256"]) is None
    ):
        raise CampaignError("resource mutation project pin drift")
    source_files = project["source_files"]
    if not isinstance(source_files, dict) or len(source_files) != 2:
        raise CampaignError("resource mutation source-file identity is malformed")
    for relative, identity in source_files.items():
        if (
            not isinstance(relative, str)
            or not relative.startswith("libarchive/")
            or not isinstance(identity, dict)
            or set(identity) != {"clean_sha256", "mutated_sha256"}
            or any(
                not isinstance(value, str) or SHA256.fullmatch(value) is None
                for value in identity.values()
            )
        ):
            raise CampaignError("resource mutation source-file hash is malformed")
    mutations = payload["mutations"]
    if not isinstance(mutations, list) or len(mutations) != 3:
        raise CampaignError("resource campaign requires exactly three mutations")
    seen_ids: set[str] = set()
    seen_functions: set[str] = set()
    for mutation in mutations:
        if not isinstance(mutation, dict) or set(mutation) != {
            "id",
            "path",
            "function",
            "source_revision",
            "clean_file_sha256",
            "before",
            "before_sha256",
            "replacement",
            "replacement_sha256",
            "expected_matches",
            "expected_mutated_file_sha256",
        }:
            raise CampaignError("resource mutation entry is malformed")
        mutation_id = mutation["id"]
        function = mutation["function"]
        if (
            not isinstance(mutation_id, str)
            or mutation_id in seen_ids
            or function not in RESOURCE_FUNCTIONS
            or function in seen_functions
            or mutation["path"] not in source_files
            or mutation["source_revision"] != RESOURCE_REVISION
            or mutation["clean_file_sha256"]
            != source_files[mutation["path"]]["clean_sha256"]
            or not isinstance(mutation["before"], str)
            or not isinstance(mutation["replacement"], str)
            or mutation["before"] == mutation["replacement"]
            or "close(" not in mutation["before"]
            or "close(" in mutation["replacement"]
            or mutation["expected_matches"] != 1
            or mutation["before_sha256"]
            != sha256_bytes(mutation["before"].encode("utf-8"))
            or mutation["replacement_sha256"]
            != sha256_bytes(mutation["replacement"].encode("utf-8"))
            or mutation["expected_mutated_file_sha256"]
            != source_files[mutation["path"]]["mutated_sha256"]
        ):
            raise CampaignError("resource mutation is not exact, unique, and close-only")
        seen_ids.add(mutation_id)
        seen_functions.add(function)
    if seen_functions != RESOURCE_FUNCTIONS:
        raise CampaignError("resource mutation functions differ from the fixed three")
    return payload


def _validate_libarchive_checkout(checkout: Path) -> dict[str, Any]:
    checkout = _directory(checkout, "libarchive checkout")
    revision = _git(checkout, "rev-parse", "HEAD")
    if revision != RESOURCE_REVISION:
        raise CampaignError(
            f"libarchive checkout is not pinned at {RESOURCE_REVISION}"
        )
    if _git(checkout, "status", "--porcelain=v1", "--untracked-files=all"):
        raise CampaignError("libarchive checkout is not clean")
    if (
        _git(checkout, "cat-file", "-t", "HEAD") != "commit"
        or _git(checkout, "rev-parse", "HEAD^{tree}") != RESOURCE_TREE_OID
        or _git(checkout, "cat-file", "-t", RESOURCE_TREE_OID) != "tree"
    ):
        raise CampaignError("libarchive checkout object/tree identity drift")
    config = _load_mutations()
    for relative, identity in config["project"]["source_files"].items():
        source = _relative_regular(checkout, relative, "libarchive mutation source")
        if sha256_file(source) != identity["clean_sha256"]:
            raise CampaignError(f"libarchive pinned source hash drift: {relative}")
    return config


def _resource_checkout_identity() -> dict[str, str]:
    return {
        "commit_oid": RESOURCE_REVISION,
        "commit_type": "commit",
        "tree_oid": RESOURCE_TREE_OID,
        "tree_type": "tree",
    }


def apply_resource_mutations(source: Path, config: dict[str, Any]) -> list[dict[str, str]]:
    """Apply the three hash-bound close removals to a private source copy."""
    source = _directory(source, "resource mutation copy")
    observations: list[dict[str, str]] = []
    source_files = config["project"]["source_files"]
    for relative, identity in source_files.items():
        path = _relative_regular(source, relative, "resource mutation source")
        if sha256_file(path) != identity["clean_sha256"]:
            raise CampaignError(f"resource pre-mutation hash drift: {relative}")
    for mutation in config["mutations"]:
        path = _relative_regular(source, mutation["path"], "resource mutation source")
        text = path.read_text(encoding="utf-8")
        count = text.count(mutation["before"])
        if count != mutation["expected_matches"]:
            raise CampaignError(
                f"resource mutation anchor is not exact-unique: {mutation['id']} ({count})"
            )
        path.write_text(
            text.replace(mutation["before"], mutation["replacement"], 1),
            encoding="utf-8",
            newline="",
        )
        observations.append(
            {
                "id": mutation["id"],
                "path": mutation["path"],
                "function": mutation["function"],
                "source_revision": mutation["source_revision"],
                "clean_file_sha256": mutation["clean_file_sha256"],
                "before_sha256": mutation["before_sha256"],
                "replacement_sha256": mutation["replacement_sha256"],
                "expected_matches": mutation["expected_matches"],
                "expected_mutated_file_sha256": mutation[
                    "expected_mutated_file_sha256"
                ],
            }
        )
    for relative, identity in source_files.items():
        path = _relative_regular(source, relative, "mutated resource source")
        if sha256_file(path) != identity["mutated_sha256"]:
            raise CampaignError(f"resource post-mutation hash drift: {relative}")
    return observations


def _report_semantic(
    report_path: Path,
    process_exit: int,
    requested_paths: Sequence[Path | PurePosixPath],
    relative_paths: list[str],
    *,
    whole_program: bool,
    expected_path_multiplicity: int = 1,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if process_exit not in (0, 1):
        raise CampaignError(f"analyzer process exit is unavailable: {process_exit}")
    if len(requested_paths) != len(relative_paths) or not requested_paths:
        raise CampaignError("requested translation-unit identity is malformed")
    report = strict_json(report_path)
    try:
        semantic = realworld._report_semantic(
            process_exit,
            report,
            len(requested_paths),
            realworld.translation_unit_digest(relative_paths),
            whole_program=whole_program,
        )
        realworld.translation_unit_plan(
            report,
            len(requested_paths),
            semantic["coverage"]["analyzed_tus"],
            None,
            whole_program=whole_program,
        )
        _validate_retained_translation_unit_paths(
            report,
            relative_paths,
            whole_program=whole_program,
            expected_path_multiplicity=expected_path_multiplicity,
        )
    except realworld.CampaignError as error:
        raise CampaignError(f"analyzer report is incomplete: {error}") from error
    return report, semantic


def _validate_retained_translation_unit_paths(
    report: dict[str, Any],
    relative_paths: Sequence[str],
    *,
    whole_program: bool,
    expected_path_multiplicity: int = 1,
) -> None:
    """Bind container-emitted TU paths to logical inputs without host ``Path``."""
    if not relative_paths or len(relative_paths) != len(set(relative_paths)):
        raise CampaignError("requested translation-unit paths are not unique")
    if (
        type(expected_path_multiplicity) is not int
        or not 1 <= expected_path_multiplicity <= 64
    ):
        raise CampaignError("requested translation-unit path multiplicity is malformed")
    expected = Counter(
        {path: expected_path_multiplicity for path in relative_paths}
    )
    if all(item.startswith("C/testcases") for item in relative_paths):
        normalize = _normalize_corpus_path
    elif all(item.startswith("libarchive/") for item in relative_paths):
        normalize = _normalize_libarchive_path
    elif all(item.startswith("raw/") for item in relative_paths):
        normalize = _normalize_retained_package_path
    elif all("/" not in item and "\\" not in item for item in relative_paths):
        normalize = lambda value: _canonical_posix_absolute_path(  # noqa: E731
            value, "translation-unit receipt path"
        ).name
    else:
        raise CampaignError("requested translation-unit logical paths are malformed")

    receipts = report.get("translation_units")
    if not isinstance(receipts, list) or not receipts:
        raise CampaignError("analyzer report has no translation-unit receipt plan")
    expected_phases = (
        ("summary-harvest", "analysis") if whole_program else ("analysis",)
    )
    by_phase: dict[str, list[str]] = {phase: [] for phase in expected_phases}
    for receipt in receipts:
        if not isinstance(receipt, dict) or receipt.get("phase") not in by_phase:
            raise CampaignError("translation-unit receipt phase is malformed")
        raw_path = receipt.get("path")
        _canonical_posix_absolute_path(raw_path, "translation-unit receipt path")
        try:
            logical = normalize(raw_path)
        except CampaignError as error:
            raise CampaignError(
                "translation-unit receipt path is outside the requested surface"
            ) from error
        by_phase[receipt["phase"]].append(logical)
    for phase, paths in by_phase.items():
        if Counter(paths) != expected:
            raise CampaignError(
                f"translation-unit receipt {phase} paths differ from requested inputs"
            )


def _normalize_corpus_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise CampaignError("Juliet evidence contains an empty source path")
    normalized = value.replace("\\", "/")
    marker = "/C/testcases/"
    support_marker = "/C/testcasesupport/"
    if marker in normalized:
        suffix = normalized.split(marker, 1)[1]
        return "C/testcases/" + suffix
    if support_marker in normalized:
        suffix = normalized.split(support_marker, 1)[1]
        return "C/testcasesupport/" + suffix
    if normalized.startswith("C/testcases/") or normalized.startswith(
        "C/testcasesupport/"
    ):
        return normalized
    raise CampaignError(f"Juliet evidence path is outside the suite: {value}")


def _read_path_list(
    path: Path, label: str
) -> tuple[list[PurePosixPath], list[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CampaignError(f"cannot read {label}: {error}") from error
    if not lines or any(not line.strip() or line != line.strip() for line in lines):
        raise CampaignError(f"{label} contains empty or non-canonical lines")
    normalized = [_normalize_corpus_path(line) for line in lines]
    if len(normalized) != len(set(normalized)):
        raise CampaignError(f"{label} contains duplicate requested paths")
    for line in lines:
        _canonical_posix_absolute_path(line, label)
    return [PurePosixPath(line) for line in lines], normalized


def _validate_juliet_input_manifest(
    raw_root: Path, requested: set[str]
) -> dict[str, Any]:
    path = raw_root / "juliet" / "input-manifest.json"
    payload = strict_json(path)
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "official_archive",
        "case_counts",
        "entry_count",
        "entries",
        "digest",
    }:
        raise CampaignError("Juliet input manifest fields are malformed")
    if (
        payload["schema"] != JULIET_INPUT_SCHEMA
        or payload["official_archive"]
        != {
            "sha256": JULIET_ARCHIVE_SHA256,
            "size": 152957342,
        }
        or payload["case_counts"] != JULIET_CASE_COUNTS
        or payload["entry_count"] != JULIET_ENTRY_COUNT
        or not isinstance(payload["entries"], list)
    ):
        raise CampaignError("Juliet input manifest schema is malformed")
    paths: list[str] = []
    normalized_entries: list[dict[str, str]] = []
    for entry in payload["entries"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256"}
            or not isinstance(entry["path"], str)
            or _normalize_corpus_path(entry["path"]) != entry["path"]
            or not isinstance(entry["sha256"], str)
            or SHA256.fullmatch(entry["sha256"]) is None
        ):
            raise CampaignError("Juliet input manifest entry is malformed")
        paths.append(entry["path"])
        normalized_entries.append(entry)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise CampaignError("Juliet input manifest is not sorted and unique")
    if set(paths) != requested:
        raise CampaignError("Juliet input manifest omits a requested source")
    if len(paths) != JULIET_ENTRY_COUNT:
        raise CampaignError("Juliet input manifest is not the official selected surface")
    if (
        payload["digest"] != compact_json_digest(normalized_entries)
        or payload["digest"] != JULIET_INPUT_MANIFEST_SHA256
    ):
        raise CampaignError("Juliet input manifest digest mismatch")
    return payload


def _validate_juliet_compile_db(
    path: Path,
    requested_paths: Sequence[PurePosixPath],
    requested_relatives: Sequence[str],
) -> None:
    database = strict_json(_regular(path, "retained Juliet compile database"))
    if (
        not isinstance(database, list)
        or len(database) != len(requested_paths)
        or len(requested_paths) != len(requested_relatives)
    ):
        raise CampaignError("retained Juliet compile database is not exact")
    support = [
        path
        for path, relative in zip(requested_paths, requested_relatives)
        if relative == "C/testcasesupport/io.c"
    ]
    if len(support) != 1:
        raise CampaignError("retained Juliet compile database lacks exact support")
    support_root = support[0].parent.as_posix()
    for entry, source, relative in zip(
        database, requested_paths, requested_relatives
    ):
        if not isinstance(entry, dict) or set(entry) != {
            "directory", "file", "command"
        }:
            raise CampaignError("retained Juliet compile command is malformed")
        source_value = source.as_posix()
        _canonical_posix_absolute_path(source_value, "retained Juliet compile source")
        language = "c++" if relative.endswith(".cpp") else "c"
        if (
            entry["directory"] != "/"
            or entry["file"] != source_value
            or entry["command"]
            != f"cc -x {language} -c {source_value} -I {support_root}"
        ):
            raise CampaignError("retained Juliet compile command is not source-bound")


def _diagnostic_rule(diagnostic: Any) -> str | None:
    if not isinstance(diagnostic, dict):
        raise CampaignError("analyzer report contains a malformed diagnostic")
    rule = diagnostic.get("rule_id") or diagnostic.get("rule")
    return rule if isinstance(rule, str) else None


def _juliet_rule_row(
    raw_root: Path, cwe: str, rule_id: str
) -> tuple[dict[str, Any], list[str], set[str]]:
    base = raw_root / "juliet"
    filelist = _regular(base / f"files_{cwe}.txt", f"{cwe} file list")
    analysis = _regular(base / f"analysis_{cwe}.txt", f"{cwe} analysis list")
    report_path = _regular(base / f"findings_{cwe}.json", f"{cwe} report")
    log = _regular(base / f"log_{cwe}.txt", f"{cwe} analyzer log")
    case_paths, case_relative = _read_path_list(filelist, f"{cwe} file list")
    analysis_paths, analysis_relative = _read_path_list(
        analysis, f"{cwe} analysis list"
    )
    if not set(case_relative).issubset(set(analysis_relative)):
        raise CampaignError(f"{cwe}: scored case list is not fully requested")
    support = set(analysis_relative) - set(case_relative)
    if support != {"C/testcasesupport/io.c"}:
        raise CampaignError(f"{cwe}: exact Juliet support TU is missing or ambiguous")
    _validate_juliet_compile_db(
        base / f"build_{cwe}" / "compile_commands.json",
        analysis_paths,
        analysis_relative,
    )

    raw_report = strict_json(report_path)
    process_exit = raw_report.get("exit_code") if isinstance(raw_report, dict) else None
    if type(process_exit) is not int:
        raise CampaignError(f"{cwe}: analyzer report lacks an exact process class")
    report, _ = _report_semantic(
        report_path,
        process_exit,
        analysis_paths,
        analysis_relative,
        whole_program=True,
    )
    diagnostics = report["diagnostics"]
    matched = [item for item in diagnostics if _diagnostic_rule(item) == rule_id]
    if any(
        item.get("capability_tier") != "supported"
        or item.get("blocks_verdict") is not True
        for item in matched
    ):
        raise CampaignError(
            f"{cwe}: credited diagnostics must be supported and blocking"
        )
    true_positives, false_positives, _ = juliet_eval.score(matched)
    for item in true_positives + false_positives:
        if _normalize_corpus_path(item.get("file")) not in set(case_relative):
            raise CampaignError(f"{cwe}: scored diagnostic is outside requested cases")
    tp_files = {
        _normalize_corpus_path(item.get("file")) for item in true_positives
    }
    missed = sorted(set(case_relative) - tp_files)
    buckets: dict[str, list[str]] = {}
    for relative in missed:
        bucket = juliet_eval.classify_fn(Path(relative).name)
        buckets.setdefault(bucket, []).append(relative)
    decision_counts = {
        decision: sum(len(buckets.get(bucket, ())) for bucket in members)
        for decision, members in juliet_eval.MISS_CLASSES.items()
    }
    if sum(decision_counts.values()) != len(missed):
        raise CampaignError(f"{cwe}: miss partition is incomplete")
    bundle_paths = [
        filelist.relative_to(raw_root).as_posix(),
        analysis.relative_to(raw_root).as_posix(),
        report_path.relative_to(raw_root).as_posix(),
        log.relative_to(raw_root).as_posix(),
    ]
    row = {
        "id": rule_id,
        "corpus": "juliet",
        "exact_head": True,
        "fresh": True,
        "raw_sha256": "",
        "diagnostics": {
            "true_positives": len(true_positives),
            "false_positives": len(false_positives),
        },
        "cases": {
            "files": len(case_relative),
            "misses": {
                "total": len(missed),
                "addressable": decision_counts["addressable"],
                "model_gap": decision_counts["model_gap"],
                "out_of_scope": decision_counts["out_of_scope"],
            },
        },
    }
    return row, bundle_paths, set(analysis_relative)


def _bundle_digest(root: Path, relative_paths: Iterable[str]) -> str:
    paths = sorted(set(relative_paths))
    entries = []
    for relative in paths:
        path = _relative_regular(root, relative, "raw bundle artifact")
        entries.append({"path": relative, "sha256": sha256_file(path)})
    if not entries:
        raise CampaignError("raw evidence bundle is empty")
    return compact_json_digest(entries)


def collect_juliet(
    raw_root: Path, authority: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    juliet_root = _directory(raw_root / "juliet", "Juliet raw evidence")
    operator = strict_json(juliet_root / "operator.json")
    if (
        not isinstance(operator, dict)
        or set(operator)
        != {"schema", "command", "exit_code", "file_limit", "corpus", "authority"}
        or operator["schema"] != OPERATOR_SCHEMA
        or operator["exit_code"] not in (0, 1)
        or type(operator["file_limit"]) is not int
        or operator["file_limit"] != 400
        or operator["command"]
        != [
            "bash",
            "scripts/run_juliet.sh",
            "$BINARY",
            "$RAW/juliet",
            "400",
        ]
        or operator["corpus"] != _official_corpus_identity()
    ):
        raise CampaignError("Juliet operator receipt is malformed")
    _require_operator_authority(operator, authority, "Juliet operator")
    _regular(juliet_root / "operator.log", "Juliet operator log")

    rows: list[dict[str, Any]] = []
    all_requested: set[str] = set()
    used: list[str] = ["juliet/operator.json", "juliet/operator.log"]
    for cwe, rule_id in JULIET_RULES.items():
        row, bundle, requested = _juliet_rule_row(raw_root, cwe, rule_id)
        if row["cases"]["files"] != JULIET_CASE_COUNTS[cwe]:
            raise CampaignError(f"{cwe}: sampled case count differs from official surface")
        rows.append(row)
        used.extend(bundle)
        compile_db = juliet_root / f"build_{cwe}" / "compile_commands.json"
        _regular(compile_db, f"{cwe} compile database")
        used.append(f"juliet/build_{cwe}/compile_commands.json")
        all_requested.update(requested)
    _validate_juliet_input_manifest(raw_root, all_requested)
    used.append("juliet/input-manifest.json")
    actual = {
        path.relative_to(raw_root).as_posix()
        for path in juliet_root.rglob("*")
        if path.is_file()
    }
    if actual != set(used):
        difference = sorted(actual.symmetric_difference(used))
        raise CampaignError(f"Juliet raw artifact set is incomplete or extra: {difference}")
    return rows, sorted(set(used))


def _clean_thesis_cases() -> list[str]:
    try:
        lines = THESIS_MANIFEST.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CampaignError(f"cannot read thesis manifest: {error}") from error
    names: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) != 3:
            raise CampaignError("thesis manifest row is malformed")
        name, role, floor = parts
        if role == "CLEAN":
            if floor != "0" or not name.endswith(".c"):
                raise CampaignError("clean thesis adjudication is malformed")
            names.append(name)
    if len(names) != quality.REQUIRED_CLEAN_CASES or len(names) != len(set(names)):
        raise CampaignError("thesis manifest is not exactly the adjudicated 9 CLEAN files")
    return names


def _validate_clean_compile_db(path: Path, logical_source: str) -> None:
    database = strict_json(_regular(path, "retained clean compile database"))
    if not isinstance(database, list) or len(database) != 1:
        raise CampaignError("retained clean compile database is not exact")
    entry = database[0]
    if not isinstance(entry, dict) or set(entry) != {
        "directory", "arguments", "file"
    }:
        raise CampaignError("retained clean compile command is malformed")
    source = _canonical_posix_absolute_path(
        entry["file"], "retained clean compile source"
    )
    directory = _canonical_posix_absolute_path(
        entry["directory"], "retained clean compile directory"
    )
    if (
        source.parent != directory
        or _normalize_retained_package_path(source.as_posix()) != logical_source
        or entry["arguments"]
        != [FIXED_COMPILER, "-std=gnu11", "-fsyntax-only", source.as_posix()]
    ):
        raise CampaignError("retained clean compile command is not source-bound")


def _validate_clean_report(
    report_path: Path,
    source_path: Path,
    process_exit: int,
    logical_source: str,
) -> dict[str, Any]:
    report, semantic = _report_semantic(
        report_path,
        process_exit,
        [source_path],
        [logical_source],
        whole_program=False,
    )
    coverage = semantic["coverage"]
    expected = {
        "attempted_tus": 1,
        "analyzed_tus": 1,
        "broken_tus": 0,
        "incomplete_functions": 0,
    }
    if (
        process_exit != 0
        or report.get("exit_code") != 0
        or report.get("status") != "clean"
        or report.get("complete") is not True
        or semantic["findings"] != 0
        or coverage != expected
    ):
        raise CampaignError(f"clean thesis case is not complete and zero-FP: {source_path.name}")
    return {
        "process_exit": 0,
        "report_exit": 0,
        "complete": True,
        "coverage": coverage,
        "findings": 0,
    }


def collect_clean_corpus(
    raw_root: Path, authority: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    cases: list[dict[str, Any]] = []
    used: list[str] = []
    for name in _clean_thesis_cases():
        case_id = Path(name).stem.replace("_", "-")
        relative_root = Path("thesis") / case_id
        case_root = _directory(raw_root / relative_root, f"clean case {case_id}")
        source = _regular(case_root / "source.c", f"clean source {case_id}")
        if source.read_bytes() != _regular(
            THESIS_ROOT / name, f"thesis source {name}"
        ).read_bytes():
            raise CampaignError(f"retained clean source differs from adjudicated bytes: {name}")
        compile_db = _regular(
            case_root / "compile_commands.json", f"clean compile DB {case_id}"
        )
        logical_source = f"raw/thesis/{case_id}/source.c"
        _validate_clean_compile_db(compile_db, logical_source)
        report = _regular(case_root / "report.json", f"clean report {case_id}")
        operator_path = _regular(
            case_root / "operator.json", f"clean operator {case_id}"
        )
        log = _regular(case_root / "operator.log", f"clean log {case_id}")
        operator = strict_json(operator_path)
        if (
            not isinstance(operator, dict)
            or set(operator) != {"schema", "command", "exit_code", "authority"}
            or operator["schema"] != OPERATOR_SCHEMA
            or operator["exit_code"] != 0
            or operator["command"]
            != [
                "$BINARY",
                "$SOURCE",
                "--build-path",
                "$CASE_ROOT",
                "--json",
                "$REPORT",
            ]
        ):
            raise CampaignError(f"clean operator receipt is malformed: {case_id}")
        _require_operator_authority(operator, authority, f"clean operator {case_id}")
        observation = _validate_clean_report(
            report, source, operator["exit_code"], logical_source
        )
        bundle = [
            (relative_root / item).as_posix()
            for item in (
                "source.c",
                "compile_commands.json",
                "report.json",
                "operator.json",
                "operator.log",
            )
        ]
        cases.append(
            {
                "id": case_id,
                **observation,
                "raw_sha256": "",
            }
        )
        used.extend(bundle)
    return sorted(cases, key=lambda item: item["id"]), sorted(used)


def run_clean_corpus(
    binary: Path,
    raw_root: Path,
    compiler: str,
    authority: dict[str, Any],
) -> None:
    clean_root = raw_root / "thesis"
    clean_root.mkdir(parents=True, exist_ok=False)
    for name in _clean_thesis_cases():
        case_id = Path(name).stem.replace("_", "-")
        case_root = clean_root / case_id
        case_root.mkdir()
        source = case_root / "source.c"
        shutil.copyfile(THESIS_ROOT / name, source)
        compile_db = [
            {
                "directory": str(case_root.resolve()),
                "arguments": [compiler, "-std=gnu11", "-fsyntax-only", str(source.resolve())],
                "file": str(source.resolve()),
            }
        ]
        write_json(case_root / "compile_commands.json", compile_db)
        command = [
            str(binary.resolve()),
            str(source.resolve()),
            "--build-path",
            str(case_root.resolve()),
            "--json",
            str((case_root / "report.json").resolve()),
        ]
        exit_code = _run(
            command,
            cwd=ROOT,
            log=case_root / "operator.log",
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        write_json(
            case_root / "operator.json",
            {
                "schema": OPERATOR_SCHEMA,
                "command": [
                    "$BINARY",
                    "$SOURCE",
                    "--build-path",
                    "$CASE_ROOT",
                    "--json",
                    "$REPORT",
                ],
                "exit_code": exit_code,
                "authority": _authority_binding(authority),
            },
        )


def _resource_project() -> dict[str, Any]:
    manifest = strict_json(REALWORLD_MANIFEST)
    projects = manifest.get("projects") if isinstance(manifest, dict) else None
    if not isinstance(projects, list):
        raise CampaignError("real-world manifest project list is malformed")
    matches = [
        item
        for item in projects
        if isinstance(item, dict) and item.get("id") == "libarchive"
    ]
    if len(matches) != 1:
        raise CampaignError("real-world manifest has no unique libarchive recipe")
    project = matches[0]
    if (
        project.get("revision") != RESOURCE_REVISION
        or project.get("sources", {}).get("roots") != ["libarchive"]
        or project.get("sources", {}).get("extensions") != [".c"]
        or tuple(project.get("sources", {}).get("fallback_globs", ()))
        != RESOURCE_EXCLUDED_FALLBACKS
    ):
        raise CampaignError("libarchive campaign recipe drifted from the pinned surface")
    return project


def _derive_resource_units(
    source: Path, build: Path
) -> tuple[list[Path], list[str]]:
    compile_db = _regular(build / "compile_commands.json", "libarchive compile DB")
    database = strict_json(compile_db)
    if not isinstance(database, list):
        raise CampaignError("libarchive compile database is not an array")
    source = source.resolve()
    library = (source / "libarchive").resolve()
    selected: dict[str, Path] = {}
    for entry in database:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise CampaignError("libarchive compile database entry is malformed")
        directory = Path(entry.get("directory", build))
        path = Path(entry["file"])
        if not path.is_absolute():
            path = directory / path
        resolved = path.resolve()
        if resolved.suffix != ".c" or not (resolved == library or library in resolved.parents):
            continue
        try:
            relative = resolved.relative_to(source).as_posix()
        except ValueError as error:
            raise CampaignError("libarchive compile database escapes source") from error
        if not resolved.is_file() or resolved.is_symlink():
            raise CampaignError(f"libarchive compile source is unsafe: {relative}")
        selected[relative] = resolved
    # The historical real-world recipe added nine Darwin/Windows fallbacks.
    # P10-08's strict requested-TU policy deliberately does not request files
    # without compile commands: the current Linux compile DB is the exact
    # analyzable surface, while missing/broken handling is proved separately by
    # the stress negatives.
    relative_paths = sorted(selected)
    config = _load_mutations()
    if (
        len(relative_paths) != config["project"]["translation_units"]
        or realworld.translation_unit_digest(relative_paths)
        != config["project"]["translation_unit_sha256"]
    ):
        raise CampaignError("libarchive translation-unit surface drift")
    _validate_retained_resource_compile_db(compile_db, relative_paths)
    return [selected[item] for item in relative_paths], relative_paths


def _compile_command_tokens(entry: dict[str, Any]) -> list[str]:
    arguments = entry.get("arguments")
    command = entry.get("command")
    if arguments is not None:
        if (
            not isinstance(arguments, list)
            or not arguments
            or any(not isinstance(item, str) or not item for item in arguments)
        ):
            raise CampaignError("resource compile database has an empty clang command")
        tokens = arguments
    elif isinstance(command, str) and command.strip():
        try:
            tokens = shlex.split(command)
        except ValueError as error:
            raise CampaignError("resource compile database command is malformed") from error
    else:
        raise CampaignError("resource compile database has an empty clang command")
    if not tokens or re.fullmatch(r"clang(?:\+\+)?(?:-[0-9]+)?", Path(tokens[0]).name) is None:
        raise CampaignError("resource compile database command is not clang")
    return tokens


def _validate_retained_resource_compile_db(
    path: Path, expected_relatives: Sequence[str]
) -> None:
    database = strict_json(_regular(path, "retained resource compile DB"))
    if not isinstance(database, list) or not database:
        raise CampaignError("resource compile database is empty")
    expected = list(expected_relatives)
    if expected != sorted(expected) or len(expected) != len(set(expected)):
        raise CampaignError("expected resource compile surface is malformed")
    counts: Counter[str] = Counter()
    expected_set = set(expected)
    for entry in database:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise CampaignError("resource compile database entry is malformed")
        try:
            relative = _normalize_libarchive_path(entry["file"])
        except CampaignError:
            continue
        if relative not in expected_set:
            raise CampaignError("resource compile database contains a foreign surface")
        tokens = _compile_command_tokens(entry)
        command_sources: set[str] = set()
        for token in tokens[1:]:
            try:
                command_sources.add(_normalize_libarchive_path(token))
            except CampaignError:
                continue
        if relative not in command_sources:
            raise CampaignError("resource clang command is not bound to its source")
        counts[relative] += 1
    if set(counts) != expected_set or any(counts[item] != 2 for item in expected):
        raise CampaignError("resource compile database does not cover the exact surface")


def _resource_entries(paths: list[Path], relatives: list[str]) -> list[dict[str, str]]:
    if len(paths) != len(relatives):
        raise CampaignError("resource source identity has mismatched paths")
    return [
        {"path": relative, "sha256": sha256_file(path)}
        for path, relative in zip(paths, relatives)
    ]


def _write_resource_input_manifest(
    path: Path,
    clean_paths: list[Path],
    mutated_paths: list[Path],
    relatives: list[str],
) -> None:
    clean_entries = _resource_entries(clean_paths, relatives)
    mutated_entries = _resource_entries(mutated_paths, relatives)
    write_json(
        path,
        {
            "schema": RESOURCE_INPUT_SCHEMA,
            "revision": RESOURCE_REVISION,
            "checkout": _resource_checkout_identity(),
            "mutation_manifest_sha256": sha256_file(MUTATION_PATH),
            "translation_units": {
                "count": len(relatives),
                "sha256": realworld.translation_unit_digest(relatives),
            },
            "clean_entries": clean_entries,
            "clean_digest": compact_json_digest(clean_entries),
            "mutated_entries": mutated_entries,
            "mutated_digest": compact_json_digest(mutated_entries),
        },
    )


def _configure_resource(
    source: Path, build: Path, raw: Path, compiler: str, jobs: int
) -> None:
    configure = [
        "cmake",
        "-S",
        str(source),
        "-B",
        str(build),
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_C_COMPILER={compiler}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DENABLE_TEST=OFF",
    ]
    if _run(configure, cwd=source, log=raw / "configure.log") != 0:
        raise CampaignError("libarchive configure failed")
    build_command = ["cmake", "--build", str(build), "--parallel", str(jobs)]
    if _run(build_command, cwd=source, log=raw / "build.log") != 0:
        raise CampaignError("libarchive build failed")


def _run_resource_scan(
    binary: Path,
    source: Path,
    build: Path,
    paths: list[Path],
    relative_paths: list[str],
    raw: Path,
) -> int:
    filelist = raw / "translation-units.txt"
    relative_filelist = raw / "translation-units.relative.txt"
    filelist.write_text(
        "".join(f"{path}\n" for path in paths), encoding="utf-8", newline="\n"
    )
    relative_filelist.write_text(
        "".join(f"{path}\n" for path in relative_paths),
        encoding="utf-8",
        newline="\n",
    )
    shutil.copyfile(build / "compile_commands.json", raw / "compile_commands.json")
    command = [
        str(binary.resolve()),
        "--files",
        str(filelist.resolve()),
        "--build-path",
        str(build.resolve()),
        "--json",
        str((raw / "report.json").resolve()),
        "--whole-program",
        "--report-paths",
        str((source / "libarchive").resolve()),
    ]
    return _run(
        command,
        cwd=ROOT,
        log=raw / "operator.log",
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        timeout=330 * 60,
    )


def run_resource_campaign(
    binary: Path,
    checkout: Path,
    raw_root: Path,
    compiler: str,
    jobs: int,
    authority: dict[str, Any],
) -> None:
    config = _validate_libarchive_checkout(checkout)
    _resource_project()
    resource_raw = raw_root / "resource"
    resource_raw.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(MUTATION_PATH, resource_raw / "mutations.json")
    with tempfile.TemporaryDirectory(prefix="codeskeptic-quality-resource-") as directory:
        scratch = Path(directory)
        clean_source = scratch / "clean-source"
        mutant_source = scratch / "mutant-source"
        shutil.copytree(checkout, clean_source, ignore=shutil.ignore_patterns(".git"))
        shutil.copytree(checkout, mutant_source, ignore=shutil.ignore_patterns(".git"))
        mutation_observations = apply_resource_mutations(mutant_source, config)
        observations: dict[str, Any] = {
            "schema": RESOURCE_OBSERVATION_SCHEMA,
            "authority": _authority_binding(authority),
            "mutations": mutation_observations,
            "runs": {},
        }
        clean_build = scratch / "clean-build"
        mutant_build = scratch / "mutant-build"
        clean_raw = resource_raw / "clean"
        mutant_raw = resource_raw / "mutant"
        clean_raw.mkdir()
        mutant_raw.mkdir()
        _configure_resource(clean_source, clean_build, clean_raw, compiler, jobs)
        _configure_resource(mutant_source, mutant_build, mutant_raw, compiler, jobs)
        clean_paths, relatives = _derive_resource_units(clean_source, clean_build)
        mutant_paths, mutant_relatives = _derive_resource_units(
            mutant_source, mutant_build
        )
        if mutant_relatives != relatives:
            raise CampaignError("resource mutation changed the requested TU surface")
        checkout_paths = [
            _relative_regular(checkout, relative, "pinned libarchive source")
            for relative in relatives
        ]
        checkout_entries = _resource_entries(checkout_paths, relatives)
        clean_entries = _resource_entries(clean_paths, relatives)
        if (
            clean_entries != checkout_entries
            or compact_json_digest(checkout_entries)
            != RESOURCE_CLEAN_ENTRIES_SHA256
            or compact_json_digest(_resource_entries(mutant_paths, relatives))
            != RESOURCE_MUTATED_ENTRIES_SHA256
        ):
            raise CampaignError("resource clean/mutated surface differs from canonical inputs")
        _write_resource_input_manifest(
            resource_raw / "input-manifest.json",
            clean_paths,
            mutant_paths,
            relatives,
        )
        targets = resource_raw / "targets"
        for label, source_root in (("clean", clean_source), ("mutant", mutant_source)):
            for relative in config["project"]["source_files"]:
                destination = targets / label / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_root / relative, destination)
        for label, source_root, build, paths, raw in (
            ("clean", clean_source, clean_build, clean_paths, clean_raw),
            ("mutant", mutant_source, mutant_build, mutant_paths, mutant_raw),
        ):
            exit_code = _run_resource_scan(
                binary, source_root, build, paths, relatives, raw
            )
            observations["runs"][label] = {
                "exit_code": exit_code,
                "command": [
                    "$BINARY",
                    "--files",
                    f"$RAW/{label}/translation-units.txt",
                    "--build-path",
                    f"$SCRATCH/{label}-build",
                    "--json",
                    f"$RAW/{label}/report.json",
                    "--whole-program",
                    "--report-paths",
                    f"$SCRATCH/{label}-source/libarchive",
                ],
            }
        write_json(resource_raw / "operator.json", observations)


def _resource_input(
    raw_root: Path, *, mutation_manifest: bytes | None = None
) -> tuple[dict[str, Any], list[str]]:
    resource_root = _directory(raw_root / "resource", "resource raw evidence")
    retained_config = _regular(
        resource_root / "mutations.json", "retained resource mutation manifest"
    )
    expected_mutations = (
        MUTATION_PATH.read_bytes()
        if mutation_manifest is None
        else mutation_manifest
    )
    if retained_config.read_bytes() != expected_mutations:
        raise CampaignError(
            "retained resource mutations differ from verified source authority"
        )
    config = _load_mutations(retained_config)
    payload = strict_json(resource_root / "input-manifest.json")
    required = {
        "schema",
        "revision",
        "checkout",
        "mutation_manifest_sha256",
        "translation_units",
        "clean_entries",
        "clean_digest",
        "mutated_entries",
        "mutated_digest",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise CampaignError("resource input manifest fields are malformed")
    project = config["project"]
    if (
        payload["schema"] != RESOURCE_INPUT_SCHEMA
        or payload["revision"] != project["revision"]
        or payload["checkout"] != _resource_checkout_identity()
        or payload["mutation_manifest_sha256"] != sha256_file(retained_config)
        or payload["translation_units"]
        != {
            "count": project["translation_units"],
            "sha256": project["translation_unit_sha256"],
        }
    ):
        raise CampaignError("resource input provenance drift")

    normalized: dict[str, list[dict[str, str]]] = {}
    for label in ("clean", "mutated"):
        entries = payload[f"{label}_entries"]
        if not isinstance(entries, list) or len(entries) != project["translation_units"]:
            raise CampaignError(f"resource {label} input entries are incomplete")
        paths: list[str] = []
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "sha256"}
                or not isinstance(entry["path"], str)
                or not entry["path"].startswith("libarchive/")
                or PurePosixPath(entry["path"]).is_absolute()
                or not isinstance(entry["sha256"], str)
                or SHA256.fullmatch(entry["sha256"]) is None
            ):
                raise CampaignError(f"resource {label} input entry is malformed")
            paths.append(entry["path"])
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise CampaignError(f"resource {label} input entries are not sorted/unique")
        if realworld.translation_unit_digest(paths) != project["translation_unit_sha256"]:
            raise CampaignError(f"resource {label} TU identity drift")
        if payload[f"{label}_digest"] != compact_json_digest(entries):
            raise CampaignError(f"resource {label} input digest mismatch")
        normalized[label] = entries
    if payload["clean_digest"] != RESOURCE_CLEAN_ENTRIES_SHA256:
        raise CampaignError("resource clean input differs from canonical checkout")
    if payload["mutated_digest"] != RESOURCE_MUTATED_ENTRIES_SHA256:
        raise CampaignError("resource mutated input differs from exact seeds")
    if [item["path"] for item in normalized["clean"]] != [
        item["path"] for item in normalized["mutated"]
    ]:
        raise CampaignError("resource clean and mutant surfaces differ")
    clean_by_path = {item["path"]: item["sha256"] for item in normalized["clean"]}
    mutant_by_path = {
        item["path"]: item["sha256"] for item in normalized["mutated"]
    }
    changed = {path for path in clean_by_path if clean_by_path[path] != mutant_by_path[path]}
    if changed != set(project["source_files"]):
        raise CampaignError("resource mutation changed files outside the fixed two")
    used = ["resource/mutations.json", "resource/input-manifest.json"]
    for relative, identity in project["source_files"].items():
        if (
            clean_by_path.get(relative) != identity["clean_sha256"]
            or mutant_by_path.get(relative) != identity["mutated_sha256"]
        ):
            raise CampaignError(f"resource target identity drift: {relative}")
        for label, expected in (
            ("clean", identity["clean_sha256"]),
            ("mutant", identity["mutated_sha256"]),
        ):
            retained = _relative_regular(
                resource_root / "targets", f"{label}/{relative}", "resource target copy"
            )
            if sha256_file(retained) != expected:
                raise CampaignError(f"retained resource target drift: {label}/{relative}")
            used.append(f"resource/targets/{label}/{relative}")
    return payload, used


def _normalize_libarchive_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise CampaignError("resource evidence contains an empty source path")
    normalized = value.replace("\\", "/")
    marker = "/libarchive/"
    if marker in normalized:
        return "libarchive/" + normalized.split(marker, 1)[1]
    if normalized.startswith("libarchive/"):
        return normalized
    raise CampaignError(f"resource evidence path is outside libarchive: {value}")


def _read_resource_filelist(
    path: Path,
) -> tuple[list[PurePosixPath], list[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CampaignError(f"cannot read resource TU list: {error}") from error
    if not lines or any(not line or line != line.strip() for line in lines):
        raise CampaignError("resource TU list has an empty/non-canonical line")
    relatives = [_normalize_libarchive_path(item) for item in lines]
    if relatives != sorted(relatives) or len(relatives) != len(set(relatives)):
        raise CampaignError("resource TU list is not sorted and unique")
    for line in lines:
        _canonical_posix_absolute_path(line, "resource requested TU path")
    return [PurePosixPath(item) for item in lines], relatives


def _diagnostic_projection(diagnostic: Any) -> tuple[Any, ...]:
    if not isinstance(diagnostic, dict):
        raise CampaignError("resource report diagnostic is malformed")
    return (
        _normalize_libarchive_path(diagnostic.get("file")),
        _diagnostic_rule(diagnostic),
        diagnostic.get("severity"),
        diagnostic.get("function"),
        diagnostic.get("message"),
    )


def collect_resource(
    raw_root: Path,
    authority: dict[str, Any],
    *,
    mutation_manifest: bytes | None = None,
) -> tuple[dict[str, Any], list[str]]:
    payload, used = _resource_input(
        raw_root, mutation_manifest=mutation_manifest
    )
    resource_root = raw_root / "resource"
    operator_path = _regular(resource_root / "operator.json", "resource operator")
    operator = strict_json(operator_path)
    if not isinstance(operator, dict) or set(operator) != {
        "schema", "authority", "mutations", "runs"
    }:
        raise CampaignError("resource operator fields are malformed")
    if operator["schema"] != RESOURCE_OBSERVATION_SCHEMA:
        raise CampaignError("resource operator schema drift")
    _require_operator_authority(operator, authority, "resource operator")
    config = _load_mutations(resource_root / "mutations.json")
    expected_mutations = [
        {
            "id": item["id"],
            "path": item["path"],
            "function": item["function"],
            "source_revision": item["source_revision"],
            "clean_file_sha256": item["clean_file_sha256"],
            "before_sha256": item["before_sha256"],
            "replacement_sha256": item["replacement_sha256"],
            "expected_matches": item["expected_matches"],
            "expected_mutated_file_sha256": item[
                "expected_mutated_file_sha256"
            ],
        }
        for item in config["mutations"]
    ]
    if operator["mutations"] != expected_mutations:
        raise CampaignError("resource operator mutation observations drift")
    runs = operator["runs"]
    if not isinstance(runs, dict) or set(runs) != {"clean", "mutant"}:
        raise CampaignError("resource operator run set is malformed")

    reports: dict[str, dict[str, Any]] = {}
    expected_relatives = [item["path"] for item in payload["clean_entries"]]
    for label in ("clean", "mutant"):
        run = runs[label]
        if (
            not isinstance(run, dict)
            or set(run) != {"exit_code", "command"}
            or run["exit_code"] not in (0, 1)
            or run["command"]
            != [
                "$BINARY",
                "--files",
                f"$RAW/{label}/translation-units.txt",
                "--build-path",
                f"$SCRATCH/{label}-build",
                "--json",
                f"$RAW/{label}/report.json",
                "--whole-program",
                "--report-paths",
                f"$SCRATCH/{label}-source/libarchive",
            ]
        ):
            raise CampaignError(f"resource {label} operator run is malformed")
        run_root = _directory(resource_root / label, f"resource {label} evidence")
        filelist = _regular(
            run_root / "translation-units.txt", f"resource {label} TU list"
        )
        relative_filelist = _regular(
            run_root / "translation-units.relative.txt",
            f"resource {label} relative TU list",
        )
        paths, relatives = _read_resource_filelist(filelist)
        retained_relatives = relative_filelist.read_text(encoding="utf-8").splitlines()
        if relatives != expected_relatives or retained_relatives != expected_relatives:
            raise CampaignError(f"resource {label} requested TU identity drift")
        _validate_retained_resource_compile_db(
            run_root / "compile_commands.json", expected_relatives
        )
        report_path = _regular(run_root / "report.json", f"resource {label} report")
        report, semantic = _report_semantic(
            report_path,
            run["exit_code"],
            paths,
            relatives,
            whole_program=True,
            expected_path_multiplicity=2,
        )
        if semantic["coverage"] != {
            "attempted_tus": 123,
            "analyzed_tus": 246,
            "broken_tus": 0,
            "incomplete_functions": 0,
        }:
            raise CampaignError(f"resource {label} coverage differs from exact surface")
        reports[label] = report
        for name in (
            "configure.log",
            "build.log",
            "translation-units.txt",
            "translation-units.relative.txt",
            "compile_commands.json",
            "report.json",
            "operator.log",
        ):
            _regular(run_root / name, f"resource {label} artifact {name}")
            used.append(f"resource/{label}/{name}")
    used.append("resource/operator.json")

    clean_resource = [
        item
        for item in reports["clean"]["diagnostics"]
        if _diagnostic_rule(item) == "resource-leak"
    ]
    mutant_resource = [
        item
        for item in reports["mutant"]["diagnostics"]
        if _diagnostic_rule(item) == "resource-leak"
    ]
    if clean_resource:
        raise CampaignError("clean pinned libarchive produced a resource-leak FP")
    if len(mutant_resource) != 3:
        raise CampaignError("resource mutant did not produce exactly three findings")
    functions = Counter(item.get("function") for item in mutant_resource)
    if functions != Counter({name: 1 for name in RESOURCE_FUNCTIONS}):
        raise CampaignError("resource mutant findings do not map one-to-one to seeds")
    mutation_paths = set(config["project"]["source_files"])
    for item in mutant_resource:
        if (
            _normalize_libarchive_path(item.get("file")) not in mutation_paths
            or item.get("blocks_verdict") is not True
            or item.get("capability_tier") != "supported"
        ):
            raise CampaignError("resource mutant finding is not an exact blocking seed")
    clean_other = Counter(
        _diagnostic_projection(item)
        for item in reports["clean"]["diagnostics"]
        if _diagnostic_rule(item) != "resource-leak"
    )
    mutant_other = Counter(
        _diagnostic_projection(item)
        for item in reports["mutant"]["diagnostics"]
        if _diagnostic_rule(item) != "resource-leak"
    )
    if clean_other != mutant_other:
        raise CampaignError("resource mutations changed unrelated diagnostics")

    exact_resource_files = sorted(
        path.relative_to(raw_root).as_posix()
        for path in resource_root.rglob("*")
        if path.is_file()
    )
    if set(exact_resource_files) != set(used):
        unexpected = sorted(set(exact_resource_files).symmetric_difference(used))
        raise CampaignError(f"resource raw artifact set is incomplete or extra: {unexpected}")
    return {
        "id": "resource-leak",
        "corpus": "resource-leak-mutation",
        "exact_head": True,
        "fresh": True,
        "raw_sha256": "",
        "diagnostics": {"true_positives": 3, "false_positives": 0},
        "cases": {
            "files": 3,
            "misses": {
                "total": 0,
                "addressable": 0,
                "model_gap": 0,
                "out_of_scope": 0,
            },
        },
    }, exact_resource_files


def collect_requested_tu_negatives(
    raw_root: Path, binary: Path | None, authority: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    # ``binary`` is retained in the internal API for compatibility with the
    # live collector, but receipt verification uses the already authenticated
    # build-authority identity and never executes the analyzer.
    del binary
    stress_root = _directory(raw_root / "stress", "stress raw evidence")
    operator_path = _regular(stress_root / "operator.json", "stress operator")
    operator = strict_json(operator_path)
    if (
        not isinstance(operator, dict)
        or set(operator) != {"schema", "authority", "receipt_sha256"}
        or operator["schema"] != OPERATOR_SCHEMA
        or not isinstance(operator["receipt_sha256"], str)
        or SHA256.fullmatch(operator["receipt_sha256"]) is None
    ):
        raise CampaignError("stress operator receipt is malformed")
    _require_operator_authority(operator, authority, "stress operator")
    receipt_path = _regular(stress_root / "receipt.json", "stress receipt")
    if sha256_file(receipt_path) != operator["receipt_sha256"]:
        raise CampaignError("stress operator is not bound to its receipt")
    try:
        receipt = stress.verify_receipt_with_identity(
            receipt_path,
            {
                "sha256": authority["analyzer"]["binary_sha256"],
                "version": authority["analyzer"]["version"],
            },
            expected_source_revision=authority["source"]["revision"],
        )
    except stress.MatrixError as error:
        raise CampaignError(f"stress receipt is not independently valid: {error}") from error
    if receipt["source"]["base_commit"] != authority["source"]["revision"]:
        raise CampaignError(
            "stress receipt source revision differs from campaign authority"
        )
    by_id = {item.get("id"): item for item in receipt["cases"] if isinstance(item, dict)}
    admitted = {"stress/operator.json", "stress/receipt.json"}
    for case in receipt["cases"]:
        case_id = case["id"]
        for run in case["runs"]:
            repetition = run["repetition"]
            expected_log = f"logs/{case_id}-{repetition}.log"
            expected_report = f"reports/{case_id}-{repetition}.json"
            if run["log"] != expected_log or run["report"] != expected_report:
                raise CampaignError(
                    "stress receipt uses non-canonical evidence paths"
                )
            admitted.update(
                {f"stress/{expected_log}", f"stress/{expected_report}"}
            )
    selections = (
        ("broken", RESOURCE_BROKEN_CASE, "broken-requested-tu"),
        ("missing", RESOURCE_MISSING_CASE, "missing-requested-tu"),
    )
    results: list[dict[str, Any]] = []
    for kind, stress_id, case_id in selections:
        case = by_id.get(stress_id)
        if not isinstance(case, dict) or not isinstance(case.get("runs"), list):
            raise CampaignError(f"stress receipt lacks requested-TU negative: {stress_id}")
        projections = [run.get("projection") for run in case["runs"]]
        if not projections or any(item != projections[0] for item in projections):
            raise CampaignError(f"requested-TU negative is not repeat-stable: {stress_id}")
        projection = projections[0]
        if (
            not isinstance(projection, dict)
            or projection.get("process_exit") != 2
            or projection.get("report_exit") != 2
            or projection.get("complete") is not False
            or projection.get("status") not in {"failed", "incomplete"}
        ):
            raise CampaignError(f"requested-TU negative did not fail closed: {stress_id}")
        coverage = projection.get("coverage")
        if not isinstance(coverage, dict):
            raise CampaignError(f"requested-TU negative lacks coverage: {stress_id}")
        if kind == "missing" and not (
            coverage.get("attempted_tus") == 2
            and coverage.get("analyzed_tus") == 1
            and coverage.get("broken_tus") == 0
            and coverage.get("incomplete_functions") == 0
        ):
            raise CampaignError("missing requested-TU negative coverage drift")
        if kind == "broken" and not (
            coverage.get("attempted_tus") == 2
            and coverage.get("analyzed_tus") == 1
            and coverage.get("broken_tus") == 1
            and coverage.get("incomplete_functions") == 0
        ):
            raise CampaignError("broken requested-TU negative coverage drift")
        bundle = ["stress/receipt.json"]
        for run in case["runs"]:
            bundle.extend([f"stress/{run['log']}", f"stress/{run['report']}"])
        results.append(
            {
                "id": case_id,
                "kind": kind,
                "process_exit": 2,
                "report_exit": 2,
                "complete": False,
                "verdict": None,
                "coverage": coverage,
                "raw_sha256": "",
            }
        )
    all_stress_files = {
        path.relative_to(raw_root).as_posix()
        for path in stress_root.rglob("*")
        if path.is_file()
    }
    if all_stress_files != admitted:
        difference = sorted(all_stress_files.symmetric_difference(admitted))
        raise CampaignError(
            f"stress raw artifact set is incomplete or extra: {difference}"
        )
    return results, sorted(admitted)


def run_requested_tu_negatives(
    binary: Path, raw_root: Path, authority: dict[str, Any]
) -> None:
    output = raw_root / "stress"
    try:
        stress.run_matrix(binary, output=output)
    except stress.MatrixError as error:
        raise CampaignError(f"stress matrix rejected: {error}") from error
    receipt = _regular(output / "receipt.json", "stress receipt")
    write_json(
        output / "operator.json",
        {
            "schema": OPERATOR_SCHEMA,
            "authority": _authority_binding(authority),
            "receipt_sha256": sha256_file(receipt),
        },
    )


def _raw_files(raw_root: Path) -> list[Path]:
    raw_root = _directory(raw_root, "raw campaign directory")
    files: list[Path] = []
    for path in raw_root.rglob("*"):
        if path.is_symlink():
            raise CampaignError(f"raw evidence contains a symlink: {path}")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise CampaignError(f"raw evidence contains an unsafe node: {path}")
    if not files:
        raise CampaignError("raw campaign directory is empty")
    return sorted(files, key=lambda item: item.relative_to(raw_root).as_posix())


def _collect_observations(
    package: Path,
    binary: Path | None,
    authority: dict[str, Any],
    *,
    source_material: dict[str, Any] | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, list[str]],
]:
    raw_root = _directory(package / "raw", "raw campaign directory")
    juliet_rows, juliet_used = collect_juliet(raw_root, authority)
    resource_row, resource_used = collect_resource(
        raw_root,
        authority,
        mutation_manifest=(
            source_material["mutation_manifest"]
            if source_material is not None
            else None
        ),
    )
    clean_cases, clean_used = collect_clean_corpus(raw_root, authority)
    negatives, stress_used = collect_requested_tu_negatives(
        raw_root, binary, authority
    )
    by_rule = {item["id"]: item for item in [*juliet_rows, resource_row]}
    if set(by_rule) != set(quality.EXPECTED_RULES):
        raise CampaignError("raw campaign does not cover the exact seven default rules")
    rules = [by_rule[rule_id] for rule_id in quality.EXPECTED_RULES]
    used = {
        "authority": [AUTHORITY_NAME, CAMPAIGN_LAUNCH_NAME],
        "build_authority": [
            f"{BUILD_AUTHORITY_RAW_DIR}/{name}"
            for name in sorted(build_authority.AUTHORITY_FILES)
        ],
        "juliet": juliet_used,
        "resource": resource_used,
        "clean_corpus": clean_used,
        "requested_tu_negatives": stress_used,
    }
    all_used = set().union(*(set(items) for items in used.values()))
    actual = {
        path.relative_to(raw_root).as_posix() for path in _raw_files(raw_root)
    }
    if all_used != actual:
        difference = sorted(all_used.symmetric_difference(actual))
        raise CampaignError(f"raw evidence contains unconsumed or missing files: {difference}")
    return rules, clean_cases, negatives, used


def _bundle_payload(
    package: Path,
    evidence_kind: str,
    evidence_id: str,
    observation: dict[str, Any],
    raw_paths: Iterable[str],
) -> dict[str, Any]:
    artifacts = []
    for raw_relative in sorted(set(raw_paths)):
        relative = f"raw/{raw_relative}"
        path = _relative_regular(package, relative, "bundle raw artifact")
        artifacts.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    if not artifacts:
        raise CampaignError(f"bundle evidence is empty: {evidence_kind}/{evidence_id}")
    normalized_observation = dict(observation)
    normalized_observation.pop("raw_sha256", None)
    campaign_authority = strict_json(package / "raw" / AUTHORITY_NAME)
    return {
        "schema": BUNDLE_SCHEMA,
        "evidence_kind": evidence_kind,
        "evidence_id": evidence_id,
        "authority": _authority_binding(campaign_authority),
        "observation": normalized_observation,
        "artifacts": artifacts,
    }


def _bundle_specs(
    package: Path,
    rules: list[dict[str, Any]],
    clean_cases: list[dict[str, Any]],
    negatives: list[dict[str, Any]],
    used: dict[str, list[str]],
) -> list[tuple[Path, dict[str, Any], dict[str, Any]]]:
    inverse_cwe = {rule: cwe for cwe, rule in JULIET_RULES.items()}
    specs: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
    for row in rules:
        rule_id = row["id"]
        if rule_id == "resource-leak":
            raw_paths = used["resource"]
        else:
            cwe = inverse_cwe[rule_id]
            raw_paths = [
                "juliet/operator.json",
                "juliet/operator.log",
                "juliet/input-manifest.json",
                f"juliet/files_{cwe}.txt",
                f"juliet/analysis_{cwe}.txt",
                f"juliet/findings_{cwe}.json",
                f"juliet/log_{cwe}.txt",
                f"juliet/build_{cwe}/compile_commands.json",
            ]
        raw_paths = [
            *used["authority"],
            *used["build_authority"],
            *raw_paths,
        ]
        path = package / "bundles" / "rules" / f"{rule_id}.json"
        specs.append(
            (path, row, _bundle_payload(package, "rule", rule_id, row, raw_paths))
        )
    for case in clean_cases:
        case_id = case["id"]
        prefix = f"thesis/{case_id}/"
        raw_paths = [item for item in used["clean_corpus"] if item.startswith(prefix)]
        raw_paths = [
            *used["authority"],
            *used["build_authority"],
            *raw_paths,
        ]
        path = package / "bundles" / "clean" / f"{case_id}.json"
        specs.append(
            (
                path,
                case,
                _bundle_payload(package, "clean-case", case_id, case, raw_paths),
            )
        )
    stress_receipt = strict_json(package / "raw" / "stress" / "receipt.json")
    stress_by_id = {
        item.get("id"): item
        for item in stress_receipt.get("cases", [])
        if isinstance(item, dict)
    }
    stress_ids = {
        "broken": RESOURCE_BROKEN_CASE,
        "missing": RESOURCE_MISSING_CASE,
    }
    for case in negatives:
        stress_case = stress_by_id.get(stress_ids[case["kind"]])
        if not isinstance(stress_case, dict):
            raise CampaignError("requested-TU bundle source is absent")
        raw_paths = ["stress/receipt.json"]
        for run in stress_case["runs"]:
            raw_paths.extend([f"stress/{run['log']}", f"stress/{run['report']}"])
        raw_paths = [
            *used["authority"],
            *used["build_authority"],
            "stress/operator.json",
            *raw_paths,
        ]
        path = package / "bundles" / "requested-tu" / f"{case['kind']}.json"
        specs.append(
            (
                path,
                case,
                _bundle_payload(
                    package, "requested-tu", case["kind"], case, raw_paths
                ),
            )
        )
    if len(specs) != 18:
        raise CampaignError("quality floor must produce exactly 18 evidence bundles")
    return specs


def materialize_bundles(
    package: Path,
    rules: list[dict[str, Any]],
    clean_cases: list[dict[str, Any]],
    negatives: list[dict[str, Any]],
    used: dict[str, list[str]],
    *,
    write: bool,
) -> None:
    specs = _bundle_specs(package, rules, clean_cases, negatives, used)
    expected_paths = {path.resolve() for path, _row, _payload in specs}
    if write:
        if (package / "bundles").exists():
            raise CampaignError("bundle evidence directory already exists")
        for path, _row, payload in specs:
            write_json(path, payload)
    else:
        bundle_root = _directory(package / "bundles", "bundle evidence directory")
        actual_paths = {
            path.resolve() for path in bundle_root.rglob("*") if path.is_file()
        }
        if actual_paths != expected_paths:
            raise CampaignError("bundle evidence file set differs from the exact 18")
        for path, _row, payload in specs:
            retained = strict_json(path)
            if retained != payload or path.read_bytes() != canonical_json(retained):
                raise CampaignError(f"bundle evidence differs from raw: {path.name}")
    hashes: set[str] = set()
    for path, row, _payload in specs:
        digest = sha256_file(_regular(path, "bundle evidence"))
        if digest in hashes:
            raise CampaignError("bundle evidence files do not have unique hashes")
        hashes.add(digest)
        row["raw_sha256"] = digest


def _manifest_files(package: Path) -> list[Path]:
    files = []
    for dirname in ("raw", "bundles"):
        root = _directory(package / dirname, f"{dirname} evidence directory")
        for path in root.rglob("*"):
            if path.is_symlink():
                raise CampaignError(f"retained artifact is a symlink: {path}")
            if path.is_file():
                files.append(path)
            elif not path.is_dir():
                raise CampaignError(f"retained artifact is unsafe: {path}")
    return sorted(files, key=lambda path: path.relative_to(package).as_posix())


def _raw_manifest_bytes(package: Path) -> bytes:
    return "".join(
        f"{sha256_file(path)}  {path.relative_to(package).as_posix()}\n"
        for path in _manifest_files(package)
    ).encode("utf-8")


def write_raw_manifest(package: Path) -> tuple[Path, int]:
    path = package / quality.RAW_MANIFEST_NAME
    if path.exists() or path.is_symlink():
        raise CampaignError(f"{quality.RAW_MANIFEST_NAME} already exists")
    data = _raw_manifest_bytes(package)
    path.write_bytes(data)
    return path, len(data.splitlines())


def verify_raw_manifest(package: Path) -> tuple[Path, int]:
    path = _regular(
        package / quality.RAW_MANIFEST_NAME, "raw SHA-256 manifest"
    )
    expected = _raw_manifest_bytes(package)
    if path.read_bytes() != expected:
        raise CampaignError("RAW_SHA256SUMS does not cover exact raw and bundle files")
    return path, len(expected.splitlines())


def derive_quality_input(
    package: Path,
    binary: Path | None,
    *,
    require_clean_source: bool,
    authority: dict[str, Any],
    source_identity: dict[str, str] | None = None,
    source_material: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    if source_identity is not None and source_identity != authority["source"]:
        raise CampaignError("quality input source differs from raw campaign authority")
    rules, clean_cases, negatives, used = _collect_observations(
        package, binary, authority, source_material=source_material
    )
    materialize_bundles(
        package, rules, clean_cases, negatives, used, write=False
    )
    raw_manifest, file_count = verify_raw_manifest(package)
    capabilities = quality.capability_registry_identity(
        source_material["capability_registry"]
        if source_material is not None
        else None
    )
    manifest = {
        "schema": quality.INPUT_SCHEMA,
        "identity": {
            "source": source_identity
            if source_identity is not None
            else authority["source"],
            "analyzer": authority["analyzer"],
            "capabilities": {
                "registry_sha256": capabilities["sha256"],
                "supported_quality_gated_default_rules": capabilities["rules"],
            },
            "retained_artifacts": {
                "manifest_path": quality.RAW_MANIFEST_NAME,
                "manifest_sha256": sha256_file(raw_manifest),
                "file_count": file_count,
            },
        },
        "rules": rules,
        "clean_corpus": {"cases": clean_cases},
        "requested_tu_negatives": {"cases": negatives},
    }
    return manifest, used


def assemble_package(
    package: Path,
    build_dir: Path,
    *,
    build_verifier: Callable[[Path, Path, Path], dict[str, Any]],
    require_clean_source: bool = True,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    package = _directory(package, "campaign package")
    build_dir = _directory(build_dir, "populated analyzer build directory")
    if _paths_overlap(package, build_dir):
        raise CampaignError("campaign package overlaps analyzer build directory")
    for name in (
        "bundles",
        quality.RAW_MANIFEST_NAME,
        "quality-floor-input.json",
        "receipt.json",
        "receipt.json.sha256",
    ):
        if (package / name).exists() or (package / name).is_symlink():
            raise CampaignError(f"campaign seal path already exists: {name}")
    authority = _validate_raw_authority(
        package,
        build_dir,
        build_verifier=build_verifier,
        require_clean_source=require_clean_source,
        exact_source_revision=True,
        source_root=source_root,
    )
    binary = _relative_regular(
        build_dir,
        build_authority.ANALYZER_RELATIVE,
        "build-authority analyzer binary",
    )
    rules, clean_cases, negatives, used = _collect_observations(
        package, binary, authority
    )
    materialize_bundles(
        package, rules, clean_cases, negatives, used, write=True
    )
    write_raw_manifest(package)
    quality_input, components = derive_quality_input(
        package,
        binary,
        require_clean_source=require_clean_source,
        authority=authority,
    )
    input_path = package / "quality-floor-input.json"
    write_json(input_path, quality_input)
    del components
    receipt = quality.generate_receipt(input_path, package / "receipt.json")
    _validate_sealed_package_shape(package)
    return receipt


def _validate_sealed_package_shape(package: Path) -> None:
    package = _directory(package, "sealed campaign package")
    expected_top = {
        "raw",
        "bundles",
        quality.RAW_MANIFEST_NAME,
        "quality-floor-input.json",
        "receipt.json",
        "receipt.json.sha256",
    }
    if {item.name for item in package.iterdir()} != expected_top:
        raise CampaignError("campaign package top-level shape is not exact")
    _directory(package / "raw", "sealed campaign raw evidence")
    _directory(package / "bundles", "sealed campaign bundle evidence")
    for name, label in (
        (quality.RAW_MANIFEST_NAME, "raw SHA-256 manifest"),
        ("quality-floor-input.json", "quality-floor input"),
        ("receipt.json", "quality-floor receipt"),
        ("receipt.json.sha256", "quality-floor receipt sidecar"),
    ):
        _regular(package / name, label)
    for path in package.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CampaignError(
                f"sealed campaign package contains an unsafe node: {path}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise CampaignError(
                f"sealed campaign package contains a symlink: {path}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise CampaignError(
                f"sealed campaign package contains an unsafe node: {path}"
            )
        if metadata.st_nlink != 1:
            raise CampaignError(
                f"sealed campaign package contains an externally aliased hard link: {path}"
            )


def _verify_retained_semantic_chain(
    package: Path,
    binary: Path | None,
    authority: dict[str, Any],
    source_identity: dict[str, str],
    *,
    require_accepted: bool,
    source_material: dict[str, Any] | None = None,
) -> dict[str, Any]:
    verify_raw_manifest(package)
    input_path = _regular(package / "quality-floor-input.json", "quality-floor input")
    retained_input = strict_json(input_path)
    retained_source = (
        retained_input.get("identity", {}).get("source")
        if isinstance(retained_input, dict)
        else None
    )
    if retained_source != authority["source"] or retained_source != source_identity:
        raise CampaignError("retained input source differs from raw campaign authority")
    expected_input, _components = derive_quality_input(
        package,
        binary,
        require_clean_source=False,
        authority=authority,
        source_identity=source_identity,
        source_material=source_material,
    )
    if retained_input != expected_input or input_path.read_bytes() != canonical_json(
        retained_input
    ):
        raise CampaignError("quality-floor input differs from raw-derived metrics")
    try:
        return quality.verify_receipt(
            package / "receipt.json",
            input_path,
            require_accepted=require_accepted,
            capability_registry=(
                source_material["capability_registry"]
                if source_material is not None
                else None
            ),
        )
    except quality.QualityFloorError as error:
        raise CampaignError(f"quality-floor receipt rejected: {error}") from error


def verify_package(
    package: Path,
    build_dir: Path,
    *,
    build_verifier: Callable[[Path, Path, Path], dict[str, Any]],
    require_accepted: bool = True,
    require_clean_source: bool = True,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    package = _directory(package, "campaign package")
    build_dir = _directory(build_dir, "populated analyzer build directory")
    if _paths_overlap(package, build_dir):
        raise CampaignError("campaign package overlaps analyzer build directory")
    _validate_sealed_package_shape(package)
    authority = _validate_raw_authority(
        package,
        build_dir,
        build_verifier=build_verifier,
        require_clean_source=require_clean_source,
        exact_source_revision=False,
        source_root=source_root,
    )
    binary = _relative_regular(
        build_dir,
        build_authority.ANALYZER_RELATIVE,
        "build-authority analyzer binary",
    )
    verified_source = _verify_retained_source_identity(
        authority["source"],
        require_clean=require_clean_source,
        root=source_root,
    )
    return _verify_retained_semantic_chain(
        package,
        binary,
        authority,
        verified_source,
        require_accepted=require_accepted,
    )


def verify_retained_package(
    package: Path,
    *,
    require_accepted: bool = True,
    source_root: Path = ROOT,
    require_current_source: bool = True,
) -> dict[str, Any]:
    """Offline semantic verification using only committed retained evidence."""
    package = _directory(package, "campaign package")
    source_root = _directory(source_root, "campaign source root")
    if source_root != _directory(ROOT, "executing campaign source root"):
        raise CampaignError(
            "offline verification source must contain the executing campaign runner"
        )
    _validate_sealed_package_shape(package)
    raw_root = _directory(package / "raw", "raw campaign directory")
    build_record, build_receipt = _verify_retained_build_authority_static(
        raw_root / BUILD_AUTHORITY_RAW_DIR
    )
    verified_source = _verify_retained_source_authority(
        source_root,
        build_receipt,
        require_current_source=require_current_source,
    )
    source_material = _source_authority_material(
        source_root,
        revision=(
            None
            if require_current_source
            else build_receipt["source"]["revision"]
        ),
    )
    authority = _validate_raw_authority_envelope(
        package,
        source_root=source_root,
        verified_source=verified_source,
        verified_analyzer=_campaign_analyzer_from_build(build_record),
        verified_build=build_record,
        expected_scripts=source_material["scripts"],
    )
    return _verify_retained_semantic_chain(
        package,
        None,
        authority,
        verified_source,
        require_accepted=require_accepted,
        source_material=source_material,
    )


def _write_juliet_input_manifest(
    juliet_dir: Path, raw_root: Path, archive_identity: dict[str, Any]
) -> None:
    requested: dict[str, str] = {}
    juliet_raw = raw_root / "juliet"
    for cwe in JULIET_RULES:
        analysis = _regular(
            juliet_raw / f"analysis_{cwe}.txt", f"{cwe} analysis list"
        )
        paths, relatives = _read_path_list(analysis, f"{cwe} analysis list")
        for path, relative in zip(paths, relatives):
            resolved = _regular(path, f"Juliet input {relative}")
            try:
                resolved.relative_to(juliet_dir.resolve())
            except ValueError as error:
                raise CampaignError(
                    f"Juliet requested source escapes supplied tree: {relative}"
                ) from error
            digest = sha256_file(resolved)
            prior = requested.get(relative)
            if prior is not None and prior != digest:
                raise CampaignError(f"Juliet input path has conflicting bytes: {relative}")
            requested[relative] = digest
    entries = [
        {"path": path, "sha256": requested[path]} for path in sorted(requested)
    ]
    if len(entries) != JULIET_ENTRY_COUNT:
        raise CampaignError("Juliet selected source/support entry count drift")
    digest = compact_json_digest(entries)
    if digest != JULIET_INPUT_MANIFEST_SHA256:
        raise CampaignError("Juliet selected source/support bytes are not official v1.3")
    write_json(
        juliet_raw / "input-manifest.json",
        {
            "schema": JULIET_INPUT_SCHEMA,
            "official_archive": {
                "sha256": archive_identity["archive_sha256"],
                "size": archive_identity["archive_size"],
            },
            "case_counts": dict(JULIET_CASE_COUNTS),
            "entry_count": len(entries),
            "entries": entries,
            "digest": digest,
        },
    )


def run_juliet(
    binary: Path,
    juliet_dir: Path,
    juliet_archive: Path,
    raw_root: Path,
    authority: dict[str, Any],
) -> None:
    juliet_dir = _directory(juliet_dir, "pre-downloaded Juliet directory")
    archive_identity = _validate_juliet_archive(juliet_archive)
    juliet_raw = raw_root / "juliet"
    juliet_raw.mkdir(parents=True, exist_ok=False)
    command = [
        "bash",
        str(JULIET_SCRIPT),
        str(binary.resolve()),
        str(juliet_raw.resolve()),
        "400",
    ]
    env = {
        **os.environ,
        "JULIET_DIR": str(juliet_dir),
        "LC_ALL": "C",
        "LANG": "C",
    }
    exit_code = _run(
        command, cwd=ROOT, log=juliet_raw / "operator.log", env=env
    )
    if exit_code not in (0, 1):
        raise CampaignError(f"Juliet operator was unavailable (exit {exit_code})")
    _write_juliet_input_manifest(juliet_dir, raw_root, archive_identity)
    write_json(
        juliet_raw / "operator.json",
        {
            "schema": OPERATOR_SCHEMA,
            "command": [
                "bash",
                "scripts/run_juliet.sh",
                "$BINARY",
                "$RAW/juliet",
                "400",
            ],
            "exit_code": exit_code,
            "file_limit": 400,
            "corpus": archive_identity,
            "authority": _authority_binding(authority),
        },
    )


def _tree_identity(root: Path, label: str) -> dict[str, Any]:
    root = _directory(root, label)
    entries: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CampaignError(f"{label} contains an unsafe node: {path}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise CampaignError(f"{label} contains a symlink: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise CampaignError(f"{label} contains an unsafe node: {path}")
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": metadata.st_size,
                "nlink": metadata.st_nlink,
                "sha256": sha256_file(path),
            }
        )
    entries.sort(key=lambda item: item["path"])
    if not entries:
        raise CampaignError(f"{label} is empty")
    return {
        "file_count": len(entries),
        "manifest_sha256": compact_json_digest(entries),
    }


def _verify_outer_script_authority(source: Path) -> dict[str, str]:
    source = _directory(source, "standalone campaign source")
    executing = _script_identities(ROOT)
    retained = _script_identities(source)
    if retained != executing:
        raise CampaignError(
            "executing campaign scripts differ from the standalone source"
        )
    return retained


def _verify_external_build_authority(
    authority_dir: Path,
    source: Path,
    build_dir: Path,
) -> tuple[dict[str, Any], Path, Path, Path]:
    source = _directory(source, "standalone campaign source")
    build_dir = _directory(build_dir, "populated analyzer build directory")
    binary = _relative_regular(
        build_dir,
        build_authority.ANALYZER_RELATIVE,
        "build-authority analyzer binary",
    )
    authority_dir = _directory(authority_dir, "published analyzer build authority")
    try:
        receipt = build_authority.verify_authority(
            authority_dir, source, build_dir
        )
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(f"analyzer build authority rejected: {error}") from error
    record = _build_authority_record(authority_dir, receipt)
    source_projection = {
        "revision": record["source"]["revision"],
        "manifest_sha256": record["source"]["manifest_sha256"],
    }
    if source_projection != _source_identity(require_clean=True, root=source):
        raise CampaignError("build authority source differs from standalone source")
    if (
        record["analyzer"]["sha256"] != sha256_file(binary)
        or record["analyzer"]["version"] != build_authority.ANALYZER_VERSION
    ):
        raise CampaignError("build authority analyzer differs from build output")
    return record, source, build_dir, binary


def _campaign_jobs(action: str, jobs: Any) -> int | None:
    if action == "run":
        if type(jobs) is not int or not 1 <= jobs <= 64:
            raise CampaignError("campaign jobs must be between 1 and 64")
        return jobs
    if action not in {"assemble", "verify"} or jobs is not None:
        raise CampaignError("campaign action/jobs contract is malformed")
    return None


def _campaign_container_paths(container_layout: str) -> dict[str, str]:
    if container_layout == "legacy":
        return {
            "source": "/source",
            "build": "/build",
            "build_authority": "/build-authority",
        }
    if container_layout == "p10-09":
        return {
            "source": "/authority/source",
            "build": "/authority/build",
            "build_authority": "/authority/build-authority",
        }
    raise CampaignError("campaign container layout is unsupported")


def _campaign_container_layout(build_record: Any) -> str:
    if not isinstance(build_record, dict):
        raise CampaignError("analyzer build container layout evidence is malformed")
    try:
        container_layout = build_authority._container_layout_from_runtime(
            build_record.get("runtime")
        )
    except (build_authority.BuildAuthorityError, KeyError, TypeError) as error:
        raise CampaignError(
            f"analyzer build container layout is not exact: {error}"
        ) from error
    if container_layout not in CAMPAIGN_CONTAINER_LAYOUTS:
        raise CampaignError("analyzer build container layout is unsupported")
    _campaign_container_paths(container_layout)
    return container_layout


def _normalized_campaign_argv_v1(
    action: str,
    jobs: int | None,
    *,
    require_accepted: bool = True,
    container_layout: str = "legacy",
) -> list[str]:
    """Re-derive the frozen runtime-v1 contract for retained evidence only."""

    if container_layout != "legacy":
        raise CampaignError(
            "retained campaign runtime v1 container layout is unsupported"
        )
    jobs = _campaign_jobs(action, jobs)
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
        "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--workdir",
        "/source",
        "-e",
        f"{CAMPAIGN_INNER_TOKEN_ENV}=$LAUNCH_SHA256",
        "-e",
        f"{CAMPAIGN_INNER_ENV_TOKEN_ENV}=$ENV_SHA256",
        "-e",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "-e",
        "HOME=/scratch/home",
        "-e",
        "LANG=C",
        "-e",
        "LC_ALL=C",
        "-e",
        "TZ=UTC",
        "-e",
        "TMPDIR=/scratch",
        "-e",
        "XDG_CACHE_HOME=/scratch/xdg-cache",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "GIT_OPTIONAL_LOCKS=0",
        "-e",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "-e",
        "GIT_CONFIG_NOSYSTEM=1",
        "-e",
        "GIT_NO_REPLACE_OBJECTS=1",
        "-e",
        "GIT_CONFIG_COUNT=5",
        "-e",
        "GIT_CONFIG_KEY_0=safe.directory",
        "-e",
        "GIT_CONFIG_VALUE_0=/source",
        "-e",
        "GIT_CONFIG_KEY_1=safe.directory",
        "-e",
        "GIT_CONFIG_VALUE_1=/libarchive",
        "-e",
        "GIT_CONFIG_KEY_2=core.hooksPath",
        "-e",
        "GIT_CONFIG_VALUE_2=/dev/null",
        "-e",
        "GIT_CONFIG_KEY_3=core.fsmonitor",
        "-e",
        "GIT_CONFIG_VALUE_3=false",
        "-e",
        "GIT_CONFIG_KEY_4=core.commitGraph",
        "-e",
        "GIT_CONFIG_VALUE_4=false",
        "-v",
        "$SOURCE:/source:ro",
        "-v",
        "$BUILD:/build:ro",
        "-v",
        "$BUILD_AUTHORITY:/build-authority:ro",
    ]
    if action == "run":
        common.extend(
            [
                "-v",
                "$JULIET:/juliet:ro",
                "-v",
                "$JULIET_ARCHIVE:/juliet.zip:ro",
                "-v",
                "$LIBARCHIVE:/libarchive:ro",
                "-v",
                "$STAGE:/stage:rw",
                "-v",
                "$SCRATCH:/scratch:rw",
            ]
        )
        inner = [
            "_inner-run",
            "--source", "/source",
            "--build-authority", "/build-authority",
            "--build-dir", "/build",
            "--juliet-dir", "/juliet",
            "--juliet-archive", "/juliet.zip",
            "--libarchive-checkout", "/libarchive",
            "--output", "/stage/package",
            "--launch-authority", f"/stage/{CAMPAIGN_LAUNCH_NAME}",
            "--jobs", str(jobs),
        ]
    elif action == "assemble":
        common.extend(
            [
                "-v", "$STAGE:/stage:rw",
                "-v", "$SCRATCH:/scratch:rw",
            ]
        )
        inner = [
            "_inner-assemble",
            "--source", "/source",
            "--build-authority", "/build-authority",
            "--build-dir", "/build",
            "--package", "/stage/package",
            "--launch-authority", f"/stage/{CAMPAIGN_LAUNCH_NAME}",
        ]
    else:
        common.extend(
            [
                "-v", "$PACKAGE:/package:ro",
                "-v", "$LAUNCH_DIR:/launch:ro",
                "-v", "$SCRATCH:/scratch:rw",
            ]
        )
        inner = [
            "_inner-verify",
            "--source", "/source",
            "--build-authority", "/build-authority",
            "--build-dir", "/build",
            "--package", "/package",
            "--launch-authority", f"/launch/{CAMPAIGN_LAUNCH_NAME}",
        ]
        if not require_accepted:
            inner.append("--allow-rejected")
    return [
        *common,
        build_authority.PINNED_IMAGE,
        "/usr/bin/python3",
        "/source/scripts/run_quality_floor_campaign.py",
        *inner,
    ]


def _normalized_campaign_argv(
    action: str,
    jobs: int | None,
    *,
    require_accepted: bool = True,
    container_layout: str = "legacy",
) -> list[str]:
    jobs = _campaign_jobs(action, jobs)
    paths = _campaign_container_paths(container_layout)
    common = [
        "$PODMAN",
        "--cgroup-manager=cgroupfs",
        "--conmon=/usr/bin/conmon",
        "--events-backend=none",
        "--hooks-dir=/usr/share/empty",
        "--runtime=/usr/bin/crun",
        "run",
        "--cidfile", "$CONTAINER_CIDFILE",
        "--name", "$CONTAINER_NAME",
        "--label", f"{CAMPAIGN_CONTAINER_TOKEN_LABEL}=$CONTAINER_TOKEN",
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
        "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--workdir",
        paths["source"],
        "-e",
        f"{CAMPAIGN_INNER_TOKEN_ENV}=$LAUNCH_SHA256",
        "-e",
        f"{CAMPAIGN_INNER_ENV_TOKEN_ENV}=$ENV_SHA256",
        "-e",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "-e",
        "HOME=/scratch/home",
        "-e",
        "LANG=C",
        "-e",
        "LC_ALL=C",
        "-e",
        "TZ=UTC",
        "-e",
        "TMPDIR=/scratch",
        "-e",
        "XDG_CACHE_HOME=/scratch/xdg-cache",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "GIT_OPTIONAL_LOCKS=0",
        "-e",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "-e",
        "GIT_CONFIG_NOSYSTEM=1",
        "-e",
        "GIT_NO_REPLACE_OBJECTS=1",
        "-e",
        "GIT_CONFIG_COUNT=5",
        "-e",
        "GIT_CONFIG_KEY_0=safe.directory",
        "-e",
        f"GIT_CONFIG_VALUE_0={paths['source']}",
        "-e",
        "GIT_CONFIG_KEY_1=safe.directory",
        "-e",
        "GIT_CONFIG_VALUE_1=/libarchive",
        "-e",
        "GIT_CONFIG_KEY_2=core.hooksPath",
        "-e",
        "GIT_CONFIG_VALUE_2=/dev/null",
        "-e",
        "GIT_CONFIG_KEY_3=core.fsmonitor",
        "-e",
        "GIT_CONFIG_VALUE_3=false",
        "-e",
        "GIT_CONFIG_KEY_4=core.commitGraph",
        "-e",
        "GIT_CONFIG_VALUE_4=false",
        "-v",
        f"$SOURCE:{paths['source']}:ro",
        "-v",
        f"$BUILD:{paths['build']}:ro",
        "-v",
        f"$BUILD_AUTHORITY:{paths['build_authority']}:ro",
    ]
    if action == "run":
        common.extend(
            [
                "-v",
                "$JULIET:/juliet:ro",
                "-v",
                "$JULIET_ARCHIVE:/juliet.zip:ro",
                "-v",
                "$LIBARCHIVE:/libarchive:ro",
                "-v",
                "$STAGE:/stage:rw",
                "-v",
                "$SCRATCH:/scratch:rw",
            ]
        )
        inner = [
            "_inner-run",
            "--source", paths["source"],
            "--build-authority", paths["build_authority"],
            "--build-dir", paths["build"],
            "--juliet-dir", "/juliet",
            "--juliet-archive", "/juliet.zip",
            "--libarchive-checkout", "/libarchive",
            "--output", "/stage/package",
            "--launch-authority", f"/stage/{CAMPAIGN_LAUNCH_NAME}",
            "--jobs", str(jobs),
        ]
    elif action == "assemble":
        common.extend(
            [
                "-v", "$STAGE:/stage:rw",
                "-v", "$SCRATCH:/scratch:rw",
            ]
        )
        inner = [
            "_inner-assemble",
            "--source", paths["source"],
            "--build-authority", paths["build_authority"],
            "--build-dir", paths["build"],
            "--package", "/stage/package",
            "--launch-authority", f"/stage/{CAMPAIGN_LAUNCH_NAME}",
        ]
    else:
        common.extend(
            [
                "-v", "$PACKAGE:/package:ro",
                "-v", "$LAUNCH_DIR:/launch:ro",
                "-v", "$SCRATCH:/scratch:rw",
            ]
        )
        inner = [
            "_inner-verify",
            "--source", paths["source"],
            "--build-authority", paths["build_authority"],
            "--build-dir", paths["build"],
            "--package", "/package",
            "--launch-authority", f"/launch/{CAMPAIGN_LAUNCH_NAME}",
        ]
        if not require_accepted:
            inner.append("--allow-rejected")
    return [
        *common,
        build_authority.PINNED_IMAGE,
        "/usr/bin/python3",
        f"{paths['source']}/scripts/run_quality_floor_campaign.py",
        *inner,
    ]


def _campaign_runtime(
    action: str,
    jobs: int | None,
    build_record: dict[str, Any],
    *,
    require_accepted: bool = True,
) -> dict[str, Any]:
    container_layout = _campaign_container_layout(build_record)
    try:
        host_runtime = build_authority._runtime_authority(
            container_layout=container_layout
        )
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(f"cannot establish campaign runtime: {error}") from error
    retained_runtime = build_record.get("runtime")
    if host_runtime != retained_runtime:
        raise CampaignError("campaign runtime differs from build authority runtime")
    normalized = _normalized_campaign_argv(
        action,
        jobs,
        require_accepted=require_accepted,
        container_layout=container_layout,
    )
    return {
        "schema": CAMPAIGN_RUNTIME_SCHEMA,
        "image": copy_json(host_runtime["image"]),
        "podman": copy_json(host_runtime["podman"]),
        "normalized_argv": normalized,
        "normalized_argv_sha256": compact_json_digest(normalized),
    }


def _validate_campaign_runtime(
    runtime: Any,
    action: str,
    jobs: int | None,
    *,
    require_accepted: bool,
    build_record: dict[str, Any],
    allow_retained_v1: bool = False,
) -> dict[str, Any]:
    required = {
        "schema", "image", "podman", "normalized_argv",
        "normalized_argv_sha256",
    }
    if not isinstance(runtime, dict) or set(runtime) != required:
        raise CampaignError("campaign runtime fields are malformed")
    retained = build_record.get("runtime")
    if (
        not isinstance(retained, dict)
        or runtime["image"] != retained.get("image")
        or runtime["podman"] != retained.get("podman")
    ):
        raise CampaignError("campaign runtime is not build-runtime bound")
    container_layout = _campaign_container_layout(build_record)
    if runtime["schema"] == CAMPAIGN_RUNTIME_SCHEMA:
        normalized = _normalized_campaign_argv(
            action,
            jobs,
            require_accepted=require_accepted,
            container_layout=container_layout,
        )
    elif runtime["schema"] == CAMPAIGN_RUNTIME_V1_SCHEMA and allow_retained_v1:
        normalized = _normalized_campaign_argv_v1(
            action,
            jobs,
            require_accepted=require_accepted,
            container_layout=container_layout,
        )
    else:
        raise CampaignError("campaign runtime schema drift")
    if (
        runtime["normalized_argv"] != normalized
        or runtime["normalized_argv_sha256"] != compact_json_digest(normalized)
    ):
        raise CampaignError("campaign normalized container argv drift")
    return runtime


def _campaign_mounts(
    action: str, *, container_layout: str = "legacy"
) -> dict[str, str]:
    paths = _campaign_container_paths(container_layout)
    common = {
        "source": paths["source"],
        "build": paths["build"],
        "build_authority": paths["build_authority"],
        "scratch": "/scratch",
    }
    if action == "run":
        return {
            **common,
            "juliet": "/juliet",
            "juliet_archive": "/juliet.zip",
            "libarchive": "/libarchive",
            "output": "/stage/package",
            "launch": f"/stage/{CAMPAIGN_LAUNCH_NAME}",
        }
    if action == "assemble":
        return {
            **common,
            "package": "/stage/package",
            "launch": f"/stage/{CAMPAIGN_LAUNCH_NAME}",
        }
    if action == "verify":
        return {
            **common,
            "package": "/package",
            "launch": f"/launch/{CAMPAIGN_LAUNCH_NAME}",
        }
    raise CampaignError("campaign action is unsupported")


def _validate_campaign_mounts(
    value: Any, action: str, *, container_layout: str = "legacy"
) -> dict[str, str]:
    expected = _campaign_mounts(action, container_layout=container_layout)
    if value != expected:
        raise CampaignError("campaign launch mount authority drift")
    for name, path in value.items():
        _canonical_posix_absolute_path(path, f"campaign {name} mount")
    return value


def _campaign_input_identity(
    action: str,
    *,
    source: Path,
    build_record: dict[str, Any],
    juliet_dir: Path | None = None,
    juliet_archive: Path | None = None,
    libarchive_checkout: Path | None = None,
    package: Path | None = None,
) -> dict[str, Any]:
    container_layout = _campaign_container_layout(build_record)
    source_projection = {
        "revision": build_record["source"]["revision"],
        "manifest_sha256": build_record["source"]["manifest_sha256"],
    }
    if source_projection != _source_identity(require_clean=True, root=source):
        raise CampaignError("campaign input source differs from build authority")
    result: dict[str, Any] = {
        "source": copy_json(build_record["source"]),
        "build_authority": copy_json(build_record),
        "mounts": _campaign_mounts(
            action, container_layout=container_layout
        ),
    }
    if action == "run":
        if juliet_dir is None or juliet_archive is None or libarchive_checkout is None:
            raise CampaignError("run campaign inputs are incomplete")
        juliet_dir = _directory(juliet_dir, "pre-downloaded Juliet directory")
        juliet_archive = _regular(juliet_archive, "official Juliet archive")
        libarchive_checkout = _directory(
            libarchive_checkout, "libarchive checkout"
        )
        _validate_libarchive_checkout(libarchive_checkout)
        result.update(
            {
                "juliet": _tree_identity(juliet_dir, "Juliet input tree"),
                "juliet_archive": _validate_juliet_archive(juliet_archive),
                "libarchive": {
                    "checkout": _resource_checkout_identity(),
                    "tree": _tree_identity(
                        libarchive_checkout, "libarchive input tree"
                    ),
                },
            }
        )
    elif action == "assemble":
        if package is None:
            raise CampaignError("assemble campaign input is missing")
        package = _directory(package, "raw campaign package")
        if {item.name for item in package.iterdir()} != {"raw"}:
            raise CampaignError("assemble input must contain only completed raw evidence")
        result["package_raw"] = _tree_identity(
            package / "raw", "raw campaign input"
        )
    elif action == "verify":
        if package is None:
            raise CampaignError("verify campaign input is missing")
        result["package"] = _tree_identity(
            _directory(package, "sealed campaign package"),
            "sealed campaign package",
        )
    else:
        raise CampaignError("campaign input action is unsupported")
    return result


def _launch_payload(
    action: str,
    jobs: int | None,
    build_record: dict[str, Any],
    runtime: dict[str, Any],
    inputs: dict[str, Any],
    *,
    require_accepted: bool = True,
) -> dict[str, Any]:
    _campaign_jobs(action, jobs)
    _validate_campaign_runtime(
        runtime,
        action,
        jobs,
        require_accepted=require_accepted,
        build_record=build_record,
    )
    _validate_campaign_input_authority(inputs, action, build_record)
    return {
        "schema": CAMPAIGN_LAUNCH_SCHEMA,
        "action": action,
        "jobs": jobs,
        "require_accepted": require_accepted,
        "build_identity_sha256": build_record["build_identity_sha256"],
        "runtime": copy_json(runtime),
        "inputs": copy_json(inputs),
    }


def _execution_authority(
    launch: dict[str, Any], launch_sha256: str
) -> dict[str, Any]:
    runtime = launch["runtime"]
    return {
        "schema": EXECUTION_AUTHORITY_SCHEMA,
        "action": launch["action"],
        "jobs": launch["jobs"],
        "image": copy_json(runtime["image"]),
        "podman": copy_json(runtime["podman"]),
        "normalized_argv": copy_json(runtime["normalized_argv"]),
        "normalized_argv_sha256": runtime["normalized_argv_sha256"],
        "build_identity_sha256": launch["build_identity_sha256"],
        "launch_sha256": launch_sha256,
    }


def _validate_tree_identity_record(value: Any, label: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"file_count", "manifest_sha256"}
        or type(value["file_count"]) is not int
        or value["file_count"] <= 0
        or not isinstance(value["manifest_sha256"], str)
        or SHA256.fullmatch(value["manifest_sha256"]) is None
    ):
        raise CampaignError(f"{label} tree identity is malformed")
    return value


def _validate_campaign_input_authority(
    value: Any, action: str, build_record: dict[str, Any]
) -> dict[str, Any]:
    common = {"source", "build_authority", "mounts"}
    extra = {
        "run": {"juliet", "juliet_archive", "libarchive"},
        "assemble": {"package_raw"},
        "verify": {"package"},
    }.get(action)
    if extra is None or not isinstance(value, dict) or set(value) != common | extra:
        raise CampaignError("campaign launch input authority fields are malformed")
    if (
        value["source"] != build_record["source"]
        or value["build_authority"] != build_record
    ):
        raise CampaignError("campaign launch source or build authority drift")
    _validate_campaign_mounts(
        value["mounts"],
        action,
        container_layout=_campaign_container_layout(build_record),
    )
    if action == "run":
        _validate_tree_identity_record(value["juliet"], "Juliet input")
        if value["juliet_archive"] != _official_corpus_identity():
            raise CampaignError("campaign launch Juliet archive identity drift")
        libarchive = value["libarchive"]
        if (
            not isinstance(libarchive, dict)
            or set(libarchive) != {"checkout", "tree"}
            or libarchive["checkout"] != _resource_checkout_identity()
        ):
            raise CampaignError("campaign launch libarchive identity drift")
        _validate_tree_identity_record(libarchive["tree"], "libarchive input")
    else:
        _validate_tree_identity_record(
            value["package_raw" if action == "assemble" else "package"],
            "campaign package input",
        )
    return value


def _validate_launch_payload(
    payload: Any,
    raw: bytes,
    *,
    expected_action: str,
    build_record: dict[str, Any],
    require_token: bool,
    allow_retained_runtime_v1: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    fields = {
        "schema", "action", "jobs", "require_accepted",
        "build_identity_sha256", "runtime", "inputs",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise CampaignError("campaign launch authority fields are malformed")
    if payload["schema"] != CAMPAIGN_LAUNCH_SCHEMA:
        raise CampaignError("campaign launch authority schema drift")
    if payload["action"] != expected_action:
        raise CampaignError("campaign launch action drift")
    if type(payload["require_accepted"]) is not bool:
        raise CampaignError("campaign launch acceptance mode is malformed")
    jobs = _campaign_jobs(payload["action"], payload["jobs"])
    if payload["build_identity_sha256"] != build_record["build_identity_sha256"]:
        raise CampaignError("campaign launch build identity mismatch")
    _validate_campaign_runtime(
        payload["runtime"],
        payload["action"],
        jobs,
        require_accepted=payload["require_accepted"],
        build_record=build_record,
        allow_retained_v1=allow_retained_runtime_v1,
    )
    _validate_campaign_input_authority(
        payload["inputs"], payload["action"], build_record
    )
    digest = sha256_bytes(raw)
    if require_token and os.environ.get(CAMPAIGN_INNER_TOKEN_ENV) != digest:
        raise CampaignError("campaign inner launch token is missing or stale")
    return payload, _execution_authority(payload, digest)


def _read_launch_authority(
    path: Path,
    *,
    expected_action: str,
    build_record: dict[str, Any],
    require_token: bool,
    allow_retained_runtime_v1: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    path = _regular(path, "campaign launch authority")
    raw = path.read_bytes()
    payload = strict_json(path)
    if raw != canonical_json(payload):
        raise CampaignError("campaign launch authority is not canonical JSON")
    return _validate_launch_payload(
        payload,
        raw,
        expected_action=expected_action,
        build_record=build_record,
        require_token=require_token,
        allow_retained_runtime_v1=allow_retained_runtime_v1,
    )


def _validate_retained_execution_authority(
    launch_path: Path, build_record: dict[str, Any]
) -> dict[str, Any]:
    _payload, execution = _read_launch_authority(
        launch_path,
        expected_action="run",
        build_record=build_record,
        require_token=False,
        allow_retained_runtime_v1=True,
    )
    return execution


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _prepare_output(
    output: Path, *, protected_inputs: Sequence[tuple[Path, str]]
) -> Path:
    lexical = Path(output)
    if lexical.exists() or lexical.is_symlink():
        try:
            mode = lexical.lstat().st_mode
        except OSError as error:
            raise CampaignError("campaign output is unsafe") from error
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise CampaignError("campaign output must be absent or an empty directory")
        if any(lexical.iterdir()):
            raise CampaignError("campaign output must be absent or an empty directory")
        resolved = lexical.resolve(strict=True)
    else:
        parent = _directory(lexical.parent, "campaign output parent")
        resolved = (parent / lexical.name).resolve(strict=False)
    for protected, label in protected_inputs:
        if _paths_overlap(resolved, protected):
            raise CampaignError(f"campaign output overlaps {label}")
    if not lexical.exists():
        lexical.mkdir()
        resolved = lexical.resolve(strict=True)
    return resolved


def _mount_path(path: Path, label: str) -> str:
    value = str(Path(path).absolute())
    if any(character in value for character in ("\x00", "\n", "\r", ":", "$")):
        raise CampaignError(f"{label} path is unsafe for a Podman bind mount")
    return value


def _expand_campaign_argv(
    normalized: Sequence[str], bindings: dict[str, str]
) -> list[str]:
    expanded: list[str] = []
    ordered_bindings = sorted(
        bindings.items(), key=lambda item: len(item[0]), reverse=True
    )
    for token in normalized:
        value = token
        for marker, replacement in ordered_bindings:
            value = value.replace(marker, replacement)
        if "$" in value:
            raise CampaignError(f"unbound campaign argv marker: {value}")
        expanded.append(value)
    return expanded


def _campaign_container_command(
    action: str,
    jobs: int | None,
    launch_sha256: str,
    *,
    container_authority: CampaignContainerAuthority,
    source: Path,
    build_dir: Path,
    build_authority_dir: Path,
    scratch: Path,
    stage: Path | None = None,
    package: Path | None = None,
    launch_dir: Path | None = None,
    juliet_dir: Path | None = None,
    juliet_archive: Path | None = None,
    libarchive_checkout: Path | None = None,
    require_accepted: bool = True,
    build_record: dict[str, Any] | None = None,
) -> list[str]:
    if SHA256.fullmatch(launch_sha256) is None:
        raise CampaignError("campaign launch SHA-256 is malformed")
    if (
        container_authority.name
        != _campaign_container_name(container_authority.token, action)
        or container_authority.cidfile.exists()
        or container_authority.cidfile.is_symlink()
    ):
        raise CampaignError("campaign container execution authority is stale")
    container_layout = (
        "legacy"
        if build_record is None
        else _campaign_container_layout(build_record)
    )
    normalized = _normalized_campaign_argv(
        action,
        jobs,
        require_accepted=require_accepted,
        container_layout=container_layout,
    )
    bindings = {
        "$PODMAN": str(build_authority.DEFAULT_PODMAN),
        "$CONTAINER_CIDFILE": _mount_path(
            container_authority.cidfile, "container ID file"
        ),
        "$CONTAINER_NAME": container_authority.name,
        "$CONTAINER_TOKEN": container_authority.token,
        "$LAUNCH_SHA256": launch_sha256,
        "$SOURCE": _mount_path(source, "source"),
        "$BUILD": _mount_path(build_dir, "build"),
        "$BUILD_AUTHORITY": _mount_path(
            build_authority_dir, "build authority"
        ),
        "$SCRATCH": _mount_path(scratch, "scratch"),
        "$ENV_SHA256": compact_json_digest(
            _inner_environment(container_layout)
        ),
    }
    if action in {"run", "assemble"}:
        if stage is None:
            raise CampaignError("campaign stage is missing")
        bindings["$STAGE"] = _mount_path(stage, "campaign stage")
    if action == "run":
        if juliet_dir is None or juliet_archive is None or libarchive_checkout is None:
            raise CampaignError("run campaign mount is missing")
        bindings.update(
            {
                "$JULIET": _mount_path(juliet_dir, "Juliet directory"),
                "$JULIET_ARCHIVE": _mount_path(
                    juliet_archive, "Juliet archive"
                ),
                "$LIBARCHIVE": _mount_path(
                    libarchive_checkout, "libarchive checkout"
                ),
            }
        )
    elif action == "verify":
        if package is None or launch_dir is None:
            raise CampaignError("verify campaign mount is missing")
        bindings["$PACKAGE"] = _mount_path(package, "campaign package")
        bindings["$LAUNCH_DIR"] = _mount_path(
            launch_dir, "campaign launch directory"
        )
    return _expand_campaign_argv(normalized, bindings)


def _campaign_container_name(token: str, action: str) -> str:
    if SHA256.fullmatch(token) is None or action not in PUBLIC_ACTIONS:
        raise CampaignError("campaign container identity is malformed")
    return f"codeskeptic-quality-{token[:16]}-{action}"


def _new_campaign_container_authority(
    log: Path,
    action: str,
    *,
    invocation_token: str | None = None,
) -> CampaignContainerAuthority:
    token = (
        secrets.token_hex(32)
        if invocation_token is None
        else invocation_token
    )
    name = _campaign_container_name(token, action)
    cidfile = log.with_suffix(log.suffix + ".cid")
    if cidfile.exists() or cidfile.is_symlink():
        raise CampaignError("campaign container ID file must be absent")
    return CampaignContainerAuthority(cidfile=cidfile, name=name, token=token)


def _validate_campaign_container_invocation(
    command: Sequence[str],
    authority: CampaignContainerAuthority,
    *,
    action: str,
    log: Path,
) -> list[str]:
    command = list(command)
    if (
        authority.name != _campaign_container_name(authority.token, action)
        or authority.cidfile != log.with_suffix(log.suffix + ".cid")
    ):
        raise CampaignError("campaign container execution authority drift")
    if not command or command[0] != os.fspath(build_authority.DEFAULT_PODMAN):
        raise CampaignError("campaign command does not use the pinned Podman path")
    try:
        run_index = command.index("run")
    except ValueError as error:
        raise CampaignError("campaign command omits podman run") from error
    expected = [
        "--cidfile", os.fspath(authority.cidfile),
        "--name", authority.name,
        "--label", f"{CAMPAIGN_CONTAINER_TOKEN_LABEL}={authority.token}",
        "--rm",
    ]
    if (
        command[run_index + 1:run_index + 1 + len(expected)] != expected
        or any(
            command.count(option) != 1
            for option in ("--cidfile", "--name", "--label")
        )
    ):
        raise CampaignError("campaign container execution authority drift")
    return command


def _run_campaign_container_process(
    command: Sequence[str], stream: Any, environment: dict[str, str]
) -> int:
    if not realworld._enable_subreaper():
        raise CampaignError("campaign container could not establish subreaper authority")
    try:
        realworld._require_empty_child_table()
    except realworld.EvidenceError as error:
        raise CampaignError(str(error)) from error
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
        returncode = process.wait()
    except BaseException as error:
        try:
            _terminate_campaign_children()
        except CampaignError as cleanup_error:
            if isinstance(error, CampaignInterrupted):
                error.cleanup_failures.append(str(cleanup_error))
                raise error
            raise CampaignError(
                f"campaign container execution failed: {error}; "
                f"cleanup failed: {cleanup_error}"
            ) from error
        raise
    if not _wait_for_campaign_children(CAMPAIGN_CHILD_GRACE_SECONDS):
        cleanup_error: CampaignError | None = None
        try:
            _terminate_campaign_children()
        except CampaignError as error:
            cleanup_error = error
        detail = "campaign container left a detached descendant alive"
        if cleanup_error is not None:
            detail += f"; cleanup failed: {cleanup_error}"
        raise CampaignError(detail)
    return returncode


def _run_bounded_campaign_control(
    command: Sequence[str], environment: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    command = list(command)
    if not command:
        raise CampaignError("campaign Podman control command is empty")
    if not realworld._enable_subreaper():
        raise CampaignError("campaign control could not establish subreaper authority")
    try:
        realworld._require_empty_child_table()
    except realworld.EvidenceError as error:
        raise CampaignError(str(error)) from error

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
            bufsize=0,
        )
        if process.stdout is None:
            raise CampaignError("campaign Podman control pipe is unavailable")
        selector.register(process.stdout, selectors.EVENT_READ)
        failure: str | None = None
        while selector.get_map():
            remaining = (
                CAMPAIGN_CONTAINER_CONTROL_TIMEOUT_SECONDS
                - (time.monotonic() - started)
            )
            if remaining <= 0:
                failure = "campaign Podman control timed out"
                break
            events = selector.select(min(0.05, remaining))
            for key, _mask in events:
                admitted = CAMPAIGN_CONTAINER_CONTROL_OUTPUT_BYTES - len(output)
                block = os.read(key.fd, min(65536, admitted + 1))
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(block) > admitted:
                    failure = "campaign Podman control output is oversized"
                    break
                output.extend(block)
            if failure is not None:
                break

        if failure is None:
            remaining = (
                CAMPAIGN_CONTAINER_CONTROL_TIMEOUT_SECONDS
                - (time.monotonic() - started)
            )
            try:
                returncode = process.wait(timeout=max(0.0, remaining))
            except subprocess.TimeoutExpired:
                failure = "campaign Podman control timed out"
        else:
            returncode = None
        if failure is None and not _wait_for_campaign_children(
            CAMPAIGN_CHILD_GRACE_SECONDS
        ):
            failure = "campaign Podman control left a detached descendant alive"
        if failure is not None:
            try:
                _terminate_campaign_children()
            except CampaignError as cleanup_error:
                raise CampaignError(
                    f"{failure}; cleanup failed: {cleanup_error}"
                ) from cleanup_error
            raise CampaignError(failure)
        if returncode is None:
            raise CampaignError("campaign Podman control produced no result")
        return subprocess.CompletedProcess(
            command, returncode, bytes(output), b""
        )
    except BaseException as error:
        try:
            _terminate_campaign_children()
        except CampaignError as cleanup_error:
            if isinstance(error, CampaignInterrupted):
                error.cleanup_failures.append(str(cleanup_error))
                raise error
            raise CampaignError(
                f"campaign Podman control failed: {error}; "
                f"cleanup failed: {cleanup_error}"
            ) from error
        if isinstance(error, (CampaignInterrupted, CampaignError)):
            raise
        raise CampaignError(
            f"campaign Podman control failed: {error}"
        ) from error
    finally:
        selector.close()
        if process is not None:
            if process.returncode is None:
                try:
                    process.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    pass
            if process.stdout is not None:
                process.stdout.close()


def _campaign_podman_control(
    podman: str, arguments: Sequence[str]
) -> subprocess.CompletedProcess[bytes]:
    try:
        environment = build_authority._podman_environment()
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(
            f"cannot establish cleanup Podman environment: {error}"
        ) from error
    return _run_bounded_campaign_control(
        [podman, "--events-backend=none", *arguments], environment
    )


def _inspect_campaign_container(
    podman: str, reference: str
) -> dict[str, Any] | None:
    completed = _campaign_podman_control(
        podman,
        ["container", "inspect", "--format", "{{json .}}", reference],
    )
    if completed.returncode != 0:
        exists = _campaign_podman_control(
            podman, ["container", "exists", reference]
        )
        if exists.returncode == 1:
            return None
        detail = completed.stdout[-4000:].decode("utf-8", errors="replace")
        raise CampaignError(f"cannot inspect campaign container: {detail}")
    try:
        value = json.loads(
            completed.stdout.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_bad_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise CampaignError(
            f"campaign container inspection is malformed: {error}"
        ) from error
    if not isinstance(value, dict):
        raise CampaignError("campaign container inspection is malformed")
    return value


def _campaign_container_identity(
    value: dict[str, Any], *, name: str, token: str
) -> str:
    container_id = value.get("Id")
    inspected_name = value.get("Name")
    config = value.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(container_id, str)
        or SHA256.fullmatch(container_id) is None
        or not isinstance(inspected_name, str)
        or inspected_name.removeprefix("/") != name
        or not isinstance(labels, dict)
        or labels.get(CAMPAIGN_CONTAINER_TOKEN_LABEL) != token
    ):
        raise CampaignError("campaign container ownership drift")
    return container_id


def _campaign_cidfile(
    cidfile: Path,
) -> tuple[str | None, os.stat_result | None]:
    if not cidfile.exists() and not cidfile.is_symlink():
        return None, None
    try:
        metadata = cidfile.lstat()
        raw = build_authority._read_regular(cidfile, 128)
        value = raw.decode("ascii")
    except Exception as error:
        raise CampaignError(
            f"campaign container ID file is malformed: {error}"
        ) from error
    if SHA256.fullmatch(value) is None:
        raise CampaignError("campaign container ID file is malformed")
    return value, metadata


def _campaign_cid_quarantine_identity(
    metadata: os.stat_result,
) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        build_authority._stat_time_ns(metadata, "st_mtime"),
    )


def _unlink_campaign_cidfile(
    cidfile: Path,
    metadata: os.stat_result | None,
    expected_cid: str | None,
) -> None:
    if metadata is None:
        return
    if expected_cid is None:
        raise CampaignError("campaign container ID file authority is incomplete")
    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    parent_flags |= getattr(os, "O_DIRECTORY", 0)
    parent_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    descriptor: int | None = None
    quarantine_name: str | None = None
    try:
        parent_descriptor = os.open(cidfile.parent, parent_flags)
        descriptor = os.open(
            cidfile.name, file_flags, dir_fd=parent_descriptor
        )
        pinned_before = os.fstat(descriptor)
        raw = os.read(descriptor, 129)
        pinned_after = os.fstat(descriptor)
        if (
            build_authority._stat_fingerprint(pinned_before)
            != build_authority._stat_fingerprint(metadata)
            or build_authority._stat_fingerprint(pinned_after)
            != build_authority._stat_fingerprint(metadata)
            or raw != expected_cid.encode("ascii")
        ):
            raise CampaignError("campaign container ID file identity drift")

        for _attempt in range(128):
            candidate = (
                ".codeskeptic-quality-cid-cleanup-"
                + secrets.token_hex(16)
            )
            quarantine_name = candidate
            try:
                _rename_noreplace_at(
                    parent_descriptor,
                    cidfile.name,
                    parent_descriptor,
                    candidate,
                )
            except FileExistsError:
                quarantine_name = None
                continue
            break
        if quarantine_name is None:
            raise CampaignError("campaign CID cleanup quarantine budget exhausted")
        os.fsync(parent_descriptor)

        quarantined = os.stat(
            quarantine_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        pinned = os.fstat(descriptor)
        if (
            _campaign_cid_quarantine_identity(quarantined)
            != _campaign_cid_quarantine_identity(metadata)
            or _campaign_cid_quarantine_identity(pinned)
            != _campaign_cid_quarantine_identity(metadata)
        ):
            raise CampaignError("campaign container ID quarantine identity drift")
        try:
            os.stat(
                cidfile.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise CampaignError(
                "campaign container ID file was replaced during cleanup"
            )
        os.unlink(quarantine_name, dir_fd=parent_descriptor)
        quarantine_name = None
        os.fsync(parent_descriptor)
        try:
            os.stat(
                cidfile.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise CampaignError(
                "campaign container ID file was replaced during cleanup"
            )
    except BaseException as error:
        recovery_error: BaseException | None = None
        if parent_descriptor is not None and quarantine_name is not None:
            try:
                os.stat(
                    quarantine_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                quarantine_name = None
            except BaseException as restore_error:
                recovery_error = restore_error
            if quarantine_name is not None and recovery_error is None:
                try:
                    os.stat(
                        cidfile.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    try:
                        _rename_noreplace_at(
                            parent_descriptor,
                            quarantine_name,
                            parent_descriptor,
                            cidfile.name,
                        )
                        quarantine_name = None
                        os.fsync(parent_descriptor)
                    except BaseException as restore_error:
                        recovery_error = restore_error
                except BaseException as restore_error:
                    recovery_error = restore_error
                else:
                    recovery_error = CampaignError(
                        "campaign CID cleanup found a foreign replacement"
                    )
        retained = (
            os.fspath(cidfile.parent / quarantine_name)
            if quarantine_name is not None
            else "none"
        )
        if isinstance(error, CampaignInterrupted):
            if recovery_error is not None:
                error.cleanup_failures.append(
                    "CID cleanup recovery failed; retained quarantine: "
                    f"{retained}; {recovery_error}"
                )
            raise error
        if recovery_error is not None:
            raise CampaignError(
                "campaign CID cleanup failed; retained quarantine: "
                f"{retained}; primary failure: {error}; "
                f"recovery failure: {recovery_error}"
            ) from error
        if isinstance(error, CampaignError):
            raise
        if not isinstance(error, OSError):
            raise
        raise CampaignError(
            f"cannot remove campaign container ID file: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _rename_noreplace_at(
    source_directory: int,
    source: str,
    destination_directory: int,
    destination: str,
) -> None:
    if os.name != "posix":
        raise OSError(
            errno.ENOSYS,
            "atomic no-replace cleanup is unavailable",
            destination,
        )
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(
            errno.ENOSYS,
            "atomic no-replace cleanup is unavailable",
            destination,
        )
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        source_directory,
        os.fsencode(source),
        destination_directory,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    ) == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(
            error_number, os.strerror(error_number), destination
        )
    raise OSError(error_number, os.strerror(error_number), destination)


def _cleanup_campaign_container_exact(
    *, cidfile: Path, podman: str, name: str, token: str
) -> None:
    expected_cid, metadata = _campaign_cidfile(cidfile)
    reference = expected_cid if expected_cid is not None else name
    inspected = _inspect_campaign_container(podman, reference)
    if inspected is not None:
        container_id = _campaign_container_identity(
            inspected, name=name, token=token
        )
        if expected_cid is not None and container_id != expected_cid:
            raise CampaignError("campaign container ID file identity drift")
        completed = _campaign_podman_control(
            podman, ["rm", "--force", "--ignore", container_id]
        )
        if completed.returncode != 0:
            detail = completed.stdout[-4000:].decode(
                "utf-8", errors="replace"
            )
            raise CampaignError(f"cannot clean campaign container: {detail}")
        if _inspect_campaign_container(podman, container_id) is not None:
            raise CampaignError("campaign container survived cleanup")
    replacement = _inspect_campaign_container(podman, name)
    if replacement is not None:
        _campaign_container_identity(replacement, name=name, token=token)
        raise CampaignError("campaign container name survived or was replaced")
    _unlink_campaign_cidfile(cidfile, metadata, expected_cid)


def _cleanup_campaign_container(
    *, cidfile: Path, podman: str, name: str, token: str
) -> None:
    """Clean an exact owned object and normalize every ordinary failure."""

    try:
        _cleanup_campaign_container_exact(
            cidfile=cidfile,
            podman=podman,
            name=name,
            token=token,
        )
    except (CampaignInterrupted, CampaignError):
        raise
    except Exception as error:
        raise CampaignError(
            f"campaign container cleanup failed: {error}"
        ) from error


def _campaign_completion_marker(log: Path, action: str) -> str:
    if not log.is_file() or not 0 < log.stat().st_size <= MAX_CAMPAIGN_LOG_BYTES:
        raise CampaignError("campaign container completion log is empty or oversized")
    try:
        marker = log.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise CampaignError(
            f"campaign container completion log is unreadable: {error}"
        ) from error
    pattern = rf"CODESKEPTIC_QUALITY_FLOOR_INNER_{action.upper()} ([0-9a-f]{{64}})"
    if re.fullmatch(pattern, marker) is None:
        raise CampaignError("campaign container completion marker is malformed")
    return marker.rsplit(" ", 1)[1]


def _campaign_cleanup_failure_detail(
    error: CampaignError, authority: CampaignContainerAuthority
) -> str:
    return (
        f"{error}; recovery authority: cidfile={authority.cidfile}, "
        f"name={authority.name}, token={authority.token}"
    )


def _execute_campaign_container(
    command: Sequence[str],
    log: Path,
    action: str,
    container_authority: CampaignContainerAuthority,
) -> str:
    command = _validate_campaign_container_invocation(
        command, container_authority, action=action, log=log
    )
    try:
        environment = build_authority._podman_environment()
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(
            f"cannot establish closed Podman environment: {error}"
        ) from error
    primary: BaseException | None = None
    returncode: int | None = None
    launch_attempted = False
    try:
        with log.open("xb") as stream:
            if (
                container_authority.cidfile.exists()
                or container_authority.cidfile.is_symlink()
            ):
                raise CampaignError(
                    "campaign container ID file appeared before launch"
                )
            launch_attempted = True
            returncode = _run_campaign_container_process(
                command, stream, environment
            )
    except OSError as error:
        primary = CampaignError(
            f"cannot launch pinned campaign container: {error}"
        )
        primary.__cause__ = error
    except BaseException as error:
        primary = error

    marker: str | None = None
    if primary is None:
        try:
            if returncode is None:
                raise CampaignError(
                    "campaign container execution produced no result"
                )
            if returncode != 0:
                detail = _campaign_failure_detail(log)
                raise CampaignError(
                    f"pinned campaign container failed with exit {returncode}; "
                    f"last diagnostic: {detail}"
                )
            marker = _campaign_completion_marker(log, action)
        except BaseException as error:
            primary = error

    cleanup_error: CampaignError | None = None
    cleanup_interruption: CampaignInterrupted | None = None
    if launch_attempted:
        try:
            _cleanup_campaign_container(
                cidfile=container_authority.cidfile,
                podman=command[0],
                name=container_authority.name,
                token=container_authority.token,
            )
        except CampaignInterrupted as error:
            cleanup_interruption = error
            try:
                _cleanup_campaign_container(
                    cidfile=container_authority.cidfile,
                    podman=command[0],
                    name=container_authority.name,
                    token=container_authority.token,
                )
            except CampaignError as retry_error:
                error.cleanup_failures.append(
                    _campaign_cleanup_failure_detail(
                        retry_error, container_authority
                    )
                )
            except CampaignInterrupted as retry_interruption:
                error.cleanup_failures.append(
                    "cleanup retry was interrupted by signal "
                    f"{retry_interruption.signum}"
                )
        except CampaignError as error:
            cleanup_error = error

    if cleanup_interruption is not None:
        if primary is not None:
            cleanup_interruption.cleanup_failures.append(
                f"pre-interruption execution failure: {primary}"
            )
        raise cleanup_interruption
    if primary is not None:
        if isinstance(primary, CampaignInterrupted):
            if cleanup_error is not None:
                primary.cleanup_failures.append(
                    _campaign_cleanup_failure_detail(
                        cleanup_error, container_authority
                    )
                )
            raise primary
        if cleanup_error is not None:
            raise CampaignRecoveryRequired(
                f"campaign container execution failed: {primary}; "
                "cleanup failed: "
                + _campaign_cleanup_failure_detail(
                    cleanup_error, container_authority
                ),
                container_authority,
            ) from primary
        raise primary
    if cleanup_error is not None:
        raise CampaignRecoveryRequired(
            "campaign container cleanup failed: "
            + _campaign_cleanup_failure_detail(
                cleanup_error, container_authority
            ),
            container_authority,
        ) from cleanup_error
    if marker is None:
        raise CampaignError("campaign container completion marker is unavailable")
    return marker


def _campaign_failure_detail(log: Path) -> str:
    try:
        size = log.stat().st_size
    except OSError:
        return "unavailable"
    if not 0 < size <= MAX_CAMPAIGN_LOG_BYTES:
        return "empty or oversized"
    try:
        lines = [
            line.strip()
            for line in log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError):
        return "unreadable"
    if not lines:
        return "empty"
    detail = lines[-1]
    if len(detail) > MAX_CAMPAIGN_FAILURE_DETAIL_CHARS:
        detail = "[truncated]" + detail[-MAX_CAMPAIGN_FAILURE_DETAIL_CHARS:]
    return json.dumps(detail, ensure_ascii=True)


def _write_launch_authority(path: Path, payload: dict[str, Any]) -> str:
    raw = canonical_json(payload)
    try:
        with path.open("xb") as stream:
            stream.write(raw)
    except OSError as error:
        raise CampaignError(f"cannot write campaign launch authority: {error}") from error
    return sha256_bytes(raw)


def _copy_tree_exact(source: Path, target: Path, label: str) -> None:
    source = _directory(source, label)
    if target.exists() or target.is_symlink():
        raise CampaignError(f"{label} copy target already exists")
    target.mkdir(parents=True)
    before = _tree_identity(source, label)
    try:
        for path in source.rglob("*"):
            relative = path.relative_to(source)
            destination = target / relative
            if path.is_symlink():
                raise CampaignError(f"{label} contains a symlink: {path}")
            if path.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                with path.open("rb") as reader, destination.open("xb") as writer:
                    shutil.copyfileobj(reader, writer)
            else:
                raise CampaignError(f"{label} contains an unsafe node: {path}")
        if _tree_identity(target, f"retained {label}") != before:
            raise CampaignError(f"{label} copy differs from its source")
    except Exception:
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        raise


def _validate_output_target(
    output: Path, protected: Sequence[tuple[Path, str]]
) -> Path:
    lexical = Path(output)
    if lexical.exists() or lexical.is_symlink():
        raise CampaignError("campaign output must be absent for atomic promotion")
    parent = _directory(lexical.parent, "campaign output parent")
    resolved = (parent / lexical.name).resolve(strict=False)
    for candidate, label in protected:
        if _paths_overlap(resolved, candidate):
            raise CampaignError(f"campaign output overlaps {label}")
    return resolved


def _reject_package_overlap(
    package: Path, snapshot: dict[str, Any], *, label: str
) -> Path:
    package = _directory(package, label)
    for protected, protected_label in (
        (ROOT.resolve(), "executing source root"),
        (snapshot["source"], "standalone source"),
        (snapshot["build_dir"], "analyzer build directory"),
        (snapshot["build_authority_dir"], "build authority"),
    ):
        if _paths_overlap(package, protected):
            raise CampaignError(f"{label} overlaps {protected_label}")
    return package


def _rename_exchange(left: Path, right: Path) -> None:
    """Atomically exchange two existing filesystem entries on Linux."""
    if os.name != "posix":
        raise CampaignError("atomic campaign replacement requires POSIX renameat2")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise CampaignError("atomic campaign replacement requires renameat2")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        AT_FDCWD,
        os.fsencode(left),
        AT_FDCWD,
        os.fsencode(right),
        RENAME_EXCHANGE,
    ) != 0:
        error_number = ctypes.get_errno()
        raise CampaignError(
            "cannot atomically exchange campaign packages: "
            f"{os.strerror(error_number)}"
        )


def _promote_new_package(
    staged: Path, output: Path, expected_staged: dict[str, Any]
) -> None:
    _validate_tree_identity_record(
        expected_staged, "independently verified staged campaign"
    )
    _validate_sealed_package_shape(staged)
    staged = _directory(staged, "verified staged campaign package")
    if _tree_identity(
        staged, "staged campaign at atomic promotion"
    ) != expected_staged:
        raise CampaignError(
            "staged campaign changed after independent verification"
        )
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise CampaignError("campaign output became unavailable for promotion")
    try:
        staged.rename(output)
    except OSError as error:
        raise CampaignError(f"cannot promote verified campaign package: {error}") from error


def _replace_package(
    staged: Path,
    package: Path,
    expected_raw: dict[str, Any],
    expected_staged: dict[str, Any],
) -> None:
    _validate_tree_identity_record(
        expected_staged, "independently verified staged campaign"
    )
    _validate_sealed_package_shape(staged)
    staged = _directory(staged, "verified staged campaign package")
    if _tree_identity(
        staged, "staged campaign at atomic replacement"
    ) != expected_staged:
        raise CampaignError(
            "staged campaign changed after independent verification"
        )
    package = _directory(package, "raw campaign package")
    _validate_tree_identity_record(expected_raw, "expected raw campaign")
    _rename_exchange(staged, package)
    try:
        staged = _directory(staged, "atomically exchanged original campaign")
        retained_original = _tree_identity(
            staged / "raw", "atomically exchanged raw campaign"
        )
    except Exception as error:
        _rename_exchange(staged, package)
        raise CampaignError(
            "atomic campaign replacement could not recheck the original package"
        ) from error
    if retained_original != expected_raw:
        _rename_exchange(staged, package)
        raise CampaignError("raw campaign changed at atomic replacement")


def _cleanup_workspace(workspace: Path) -> None:
    if workspace.is_dir() and not workspace.is_symlink():
        try:
            shutil.rmtree(workspace)
        except OSError:
            # Promotion, when it occurred, was already atomic.  A private residue
            # must not turn a complete published package into a reported failure.
            pass


def _finish_campaign_workspace(workspace: Path) -> None:
    active = sys.exc_info()[1]
    if isinstance(active, (CampaignInterrupted, CampaignRecoveryRequired)):
        if workspace.is_dir() and not workspace.is_symlink():
            active.recovery_paths.append(workspace)
        return
    _cleanup_workspace(workspace)


def _inner_environment(
    container_layout: str = "legacy",
) -> dict[str, str]:
    paths = _campaign_container_paths(container_layout)
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/scratch/home",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "TMPDIR": "/scratch",
        "XDG_CACHE_HOME": "/scratch/xdg-cache",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_COUNT": "5",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": paths["source"],
        "GIT_CONFIG_KEY_1": "safe.directory",
        "GIT_CONFIG_VALUE_1": "/libarchive",
        "GIT_CONFIG_KEY_2": "core.hooksPath",
        "GIT_CONFIG_VALUE_2": "/dev/null",
        "GIT_CONFIG_KEY_3": "core.fsmonitor",
        "GIT_CONFIG_VALUE_3": "false",
        "GIT_CONFIG_KEY_4": "core.commitGraph",
        "GIT_CONFIG_VALUE_4": "false",
    }


def _validate_inner_environment(container_layout: str = "legacy") -> None:
    expected_environment = _inner_environment(container_layout)
    if os.environ.get(CAMPAIGN_INNER_ENV_TOKEN_ENV) != compact_json_digest(
        expected_environment
    ):
        raise CampaignError("campaign inner environment token is missing or stale")
    for key, expected in expected_environment.items():
        if os.environ.get(key) != expected:
            raise CampaignError(f"campaign inner environment drift: {key}")
    if (
        not isinstance(os.environ.get("HOSTNAME"), str)
        or re.fullmatch(r"[0-9a-f]{12}", os.environ["HOSTNAME"]) is None
        or os.environ.get("container") != "podman"
        or SHA256.fullmatch(os.environ.get(CAMPAIGN_INNER_TOKEN_ENV, "")) is None
    ):
        raise CampaignError("campaign inner runtime environment identity drift")
    admitted = {
        *expected_environment,
        CAMPAIGN_INNER_TOKEN_ENV,
        CAMPAIGN_INNER_ENV_TOKEN_ENV,
        "HOSTNAME",
        "container",
    }
    unexpected = sorted(set(os.environ) - admitted)
    missing = sorted(admitted - set(os.environ))
    if unexpected or missing:
        raise CampaignError(
            "campaign inner environment field set drift: "
            f"missing={missing}, unexpected={unexpected}"
        )


def _validate_inner_paths(
    action: str,
    *,
    source: Path,
    build_dir: Path,
    build_authority_dir: Path,
    package: Path | None,
    launch_authority: Path,
    juliet_dir: Path | None = None,
    juliet_archive: Path | None = None,
    libarchive_checkout: Path | None = None,
) -> str:
    actual = {
        "source": str(source),
        "build": str(build_dir),
        "build_authority": str(build_authority_dir),
        "launch": str(launch_authority),
    }
    if package is not None:
        actual["package" if action != "run" else "output"] = str(package)
    if action == "run":
        actual.update(
            {
                "juliet": str(juliet_dir),
                "juliet_archive": str(juliet_archive),
                "libarchive": str(libarchive_checkout),
            }
        )
    script = str(Path(__file__).resolve())
    matches: list[str] = []
    for container_layout in CAMPAIGN_CONTAINER_LAYOUTS:
        paths = _campaign_container_paths(container_layout)
        expected = _campaign_mounts(
            action, container_layout=container_layout
        )
        if (
            all(expected.get(key) == value for key, value in actual.items())
            and str(ROOT) == paths["source"]
            and script
            == f"{paths['source']}/scripts/run_quality_floor_campaign.py"
        ):
            matches.append(container_layout)
    if len(matches) != 1:
        mismatch_sets = [
            (
                container_layout,
                [
                    key
                    for key, value in actual.items()
                    if _campaign_mounts(
                        action, container_layout=container_layout
                    ).get(key)
                    != value
                ],
            )
            for container_layout in CAMPAIGN_CONTAINER_LAYOUTS
        ]
        minimum = min(len(items) for _layout, items in mismatch_sets)
        nearest = [
            items for _layout, items in mismatch_sets if len(items) == minimum
        ]
        if len(nearest) == 1 and nearest[0]:
            raise CampaignError(
                "campaign inner container layout mount path drift: "
                f"{nearest[0][0]}"
            )
        raise CampaignError(
            "campaign inner container layout or mount path drift"
        )
    _validate_inner_environment(matches[0])
    return matches[0]


def _run_campaign_core(
    published_build_authority: Path,
    build_dir: Path,
    juliet_dir: Path,
    juliet_archive: Path,
    libarchive_checkout: Path,
    output: Path,
    *,
    jobs: int,
    build_verifier: Callable[[Path, Path, Path], dict[str, Any]],
    execution_authority: dict[str, Any],
    launch_authority: Path,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    source_root = _directory(source_root, "campaign source root")
    source = _source_identity(require_clean=True, root=source_root)
    analyzer_build, binary, build_dir = _verify_build_authority(
        published_build_authority,
        build_dir,
        source,
        source_root=source_root,
        verifier=build_verifier,
    )
    analyzer = _binary_identity(binary)
    published_build_authority = _directory(
        published_build_authority, "published analyzer build authority"
    )
    libarchive_checkout = _directory(libarchive_checkout, "libarchive checkout")
    _validate_libarchive_checkout(libarchive_checkout)
    juliet_dir = _directory(juliet_dir, "pre-downloaded Juliet directory")
    juliet_archive = _regular(juliet_archive, "official Juliet archive")
    _validate_juliet_archive(juliet_archive)
    _campaign_jobs("run", jobs)
    output = _prepare_output(
        output,
        protected_inputs=(
            (source_root, "source root"),
            (juliet_dir, "Juliet directory"),
            (juliet_archive, "Juliet archive"),
            (libarchive_checkout, "libarchive checkout"),
            (published_build_authority, "published analyzer build authority"),
            (build_dir, "analyzer build directory"),
            (binary, "analyzer binary"),
        ),
    )
    raw_root = output / "raw"
    raw_root.mkdir()
    retained_launch = raw_root / CAMPAIGN_LAUNCH_NAME
    launch_source = _regular(launch_authority, "campaign launch authority")
    retained_launch.write_bytes(launch_source.read_bytes())
    if sha256_file(retained_launch) != execution_authority["launch_sha256"]:
        raise CampaignError("retained campaign launch authority copy differs")
    retained_build_authority = _copy_build_authority(
        published_build_authority, raw_root
    )
    if _build_authority_record(
        retained_build_authority,
        {
            "source": analyzer_build["source"],
            "analyzer": analyzer_build["analyzer"],
            "runtime": analyzer_build["runtime"],
            "build_identity_sha256": analyzer_build["build_identity_sha256"],
        },
    ) != analyzer_build:
        raise CampaignError("retained analyzer build authority copy identity differs")
    authority = _write_initial_authority(
        raw_root,
        source,
        analyzer,
        analyzer_build,
        execution_authority,
    )
    run_juliet(binary, juliet_dir, juliet_archive, raw_root, authority)
    run_clean_corpus(binary, raw_root, FIXED_COMPILER, authority)
    run_requested_tu_negatives(binary, raw_root, authority)
    run_resource_campaign(
        binary, libarchive_checkout, raw_root, FIXED_COMPILER, jobs, authority
    )
    _finalize_raw_authority(raw_root, authority, binary)
    return assemble_package(
        output,
        build_dir,
        build_verifier=build_verifier,
        require_clean_source=True,
        source_root=source_root,
    )


def _outer_snapshot(
    action: str,
    *,
    source: Path,
    build_authority_dir: Path,
    build_dir: Path,
    jobs: int | None,
    require_accepted: bool = True,
    juliet_dir: Path | None = None,
    juliet_archive: Path | None = None,
    libarchive_checkout: Path | None = None,
    package: Path | None = None,
) -> dict[str, Any]:
    scripts = _verify_outer_script_authority(source)
    build_record, source, build_dir, binary = _verify_external_build_authority(
        build_authority_dir, source, build_dir
    )
    container_layout = _campaign_container_layout(build_record)
    runtime = _campaign_runtime(
        action,
        jobs,
        build_record,
        require_accepted=require_accepted,
    )
    inputs = _campaign_input_identity(
        action,
        source=source,
        build_record=build_record,
        juliet_dir=juliet_dir,
        juliet_archive=juliet_archive,
        libarchive_checkout=libarchive_checkout,
        package=package,
    )
    launch = _launch_payload(
        action,
        jobs,
        build_record,
        runtime,
        inputs,
        require_accepted=require_accepted,
    )
    return {
        "scripts": scripts,
        "build_record": build_record,
        "container_layout": container_layout,
        "source": source,
        "build_dir": build_dir,
        "binary": binary,
        "build_authority_dir": _directory(
            build_authority_dir, "published analyzer build authority"
        ),
        "runtime": runtime,
        "inputs": inputs,
        "launch": launch,
    }


def _lightweight_outer_recheck(
    snapshot: dict[str, Any],
    *,
    action: str,
    require_accepted: bool,
    juliet_dir: Path | None = None,
    juliet_archive: Path | None = None,
    libarchive_checkout: Path | None = None,
    package: Path | None = None,
) -> None:
    container_layout = _campaign_container_layout(snapshot["build_record"])
    if container_layout != snapshot.get("container_layout"):
        raise CampaignError(
            "campaign container layout changed during container execution"
        )
    if _verify_outer_script_authority(snapshot["source"]) != snapshot["scripts"]:
        raise CampaignError("campaign scripts changed during container execution")
    try:
        host_runtime = build_authority._runtime_authority(
            container_layout=container_layout
        )
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(f"cannot recheck campaign runtime: {error}") from error
    if (
        host_runtime["image"] != snapshot["runtime"]["image"]
        or host_runtime["podman"] != snapshot["runtime"]["podman"]
    ):
        raise CampaignError("campaign runtime changed during container execution")
    inputs = _campaign_input_identity(
        action,
        source=snapshot["source"],
        build_record=snapshot["build_record"],
        juliet_dir=juliet_dir,
        juliet_archive=juliet_archive,
        libarchive_checkout=libarchive_checkout,
        package=package,
    )
    if inputs != snapshot["inputs"]:
        raise CampaignError("campaign inputs changed during container execution")
    _validate_campaign_runtime(
        snapshot["runtime"],
        action,
        snapshot["launch"]["jobs"],
        require_accepted=require_accepted,
        build_record=snapshot["build_record"],
    )


def _final_outer_recheck(
    initial: dict[str, Any],
    action: str,
    *,
    jobs: int | None,
    require_accepted: bool,
    juliet_dir: Path | None = None,
    juliet_archive: Path | None = None,
    libarchive_checkout: Path | None = None,
    package: Path | None = None,
) -> None:
    final = _outer_snapshot(
        action,
        source=initial["source"],
        build_authority_dir=initial["build_authority_dir"],
        build_dir=initial["build_dir"],
        jobs=jobs,
        require_accepted=require_accepted,
        juliet_dir=juliet_dir,
        juliet_archive=juliet_archive,
        libarchive_checkout=libarchive_checkout,
        package=package,
    )
    for field in (
        "scripts",
        "build_record",
        "container_layout",
        "runtime",
        "inputs",
        "launch",
    ):
        if final[field] != initial[field]:
            raise CampaignError(f"campaign outer authority changed: {field}")


def _inner_launch_context(
    action: str,
    launch_authority: Path,
    source: Path,
    build_authority_dir: Path,
    build_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]:
    launch_authority = _regular(launch_authority, "campaign launch authority")
    raw = launch_authority.read_bytes()
    payload = strict_json(launch_authority)
    if raw != canonical_json(payload):
        raise CampaignError("campaign launch authority is not canonical JSON")
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != CAMPAIGN_LAUNCH_SCHEMA
        or payload.get("action") != action
        or not isinstance(payload.get("runtime"), dict)
        or payload["runtime"].get("schema") != CAMPAIGN_RUNTIME_SCHEMA
        or os.environ.get(CAMPAIGN_INNER_TOKEN_ENV) != sha256_bytes(raw)
    ):
        raise CampaignError("campaign inner launch authority is missing or stale")
    try:
        receipt = build_authority.verify_authority_in_current_runtime(
            build_authority_dir, source, build_dir
        )
    except (build_authority.BuildAuthorityError, OSError) as error:
        raise CampaignError(
            f"in-runtime analyzer build authority rejected: {error}"
        ) from error
    build_record = _build_authority_record(build_authority_dir, receipt)
    payload, execution = _validate_launch_payload(
        payload,
        raw,
        expected_action=action,
        build_record=build_record,
        require_token=True,
    )
    source_projection = {
        "revision": build_record["source"]["revision"],
        "manifest_sha256": build_record["source"]["manifest_sha256"],
    }
    if source_projection != _source_identity(require_clean=True, root=source):
        raise CampaignError("inner source differs from analyzer build authority")
    binary = _relative_regular(
        build_dir,
        build_authority.ANALYZER_RELATIVE,
        "build-authority analyzer binary",
    )
    analyzer = _binary_identity(binary)
    if analyzer != {
        "version": build_record["analyzer"]["version"],
        "binary_sha256": build_record["analyzer"]["sha256"],
    }:
        raise CampaignError("inner analyzer differs from build authority")
    return payload, execution, build_record, binary


def _require_package_build_binding(
    package: Path, build_record: dict[str, Any]
) -> None:
    authority = strict_json(package / "raw" / AUTHORITY_NAME)
    if (
        not isinstance(authority, dict)
        or authority.get("analyzer_build_authority") != build_record
    ):
        raise CampaignError("campaign package belongs to a different analyzer build")


def _inner_run(
    source: Path,
    build_authority_dir: Path,
    build_dir: Path,
    juliet_dir: Path,
    juliet_archive: Path,
    libarchive_checkout: Path,
    output: Path,
    launch_authority: Path,
    jobs: int,
) -> dict[str, Any]:
    container_layout = _validate_inner_paths(
        "run",
        source=source,
        build_dir=build_dir,
        build_authority_dir=build_authority_dir,
        package=output,
        launch_authority=launch_authority,
        juliet_dir=juliet_dir,
        juliet_archive=juliet_archive,
        libarchive_checkout=libarchive_checkout,
    )
    payload, execution, build_record, _binary = _inner_launch_context(
        "run", launch_authority, source, build_authority_dir, build_dir
    )
    if _campaign_container_layout(build_record) != container_layout:
        raise CampaignError(
            "inner run container layout differs from analyzer build authority"
        )
    before = _campaign_input_identity(
        "run",
        source=source,
        build_record=build_record,
        juliet_dir=juliet_dir,
        juliet_archive=juliet_archive,
        libarchive_checkout=libarchive_checkout,
    )
    if before != payload["inputs"] or payload["jobs"] != jobs:
        raise CampaignError("inner run inputs or jobs differ from launch authority")
    receipt = _run_campaign_core(
        build_authority_dir,
        build_dir,
        juliet_dir,
        juliet_archive,
        libarchive_checkout,
        output,
        jobs=jobs,
        build_verifier=build_authority.verify_authority_in_current_runtime,
        execution_authority=execution,
        launch_authority=launch_authority,
        source_root=source,
    )
    after = _campaign_input_identity(
        "run",
        source=source,
        build_record=build_record,
        juliet_dir=juliet_dir,
        juliet_archive=juliet_archive,
        libarchive_checkout=libarchive_checkout,
    )
    if after != before:
        raise CampaignError("inner run inputs changed during execution")
    return receipt


def _inner_assemble(
    source: Path,
    build_authority_dir: Path,
    build_dir: Path,
    package: Path,
    launch_authority: Path,
) -> dict[str, Any]:
    container_layout = _validate_inner_paths(
        "assemble",
        source=source,
        build_dir=build_dir,
        build_authority_dir=build_authority_dir,
        package=package,
        launch_authority=launch_authority,
    )
    payload, _execution, build_record, _binary = _inner_launch_context(
        "assemble", launch_authority, source, build_authority_dir, build_dir
    )
    if _campaign_container_layout(build_record) != container_layout:
        raise CampaignError(
            "inner assemble container layout differs from analyzer build authority"
        )
    before = _campaign_input_identity(
        "assemble",
        source=source,
        build_record=build_record,
        package=package,
    )
    if before != payload["inputs"]:
        raise CampaignError("inner assemble input differs from launch authority")
    _require_package_build_binding(package, build_record)
    receipt = assemble_package(
        package,
        build_dir,
        build_verifier=build_authority.verify_authority_in_current_runtime,
        source_root=source,
    )
    if _tree_identity(package / "raw", "assembled raw campaign") != before[
        "package_raw"
    ]:
        raise CampaignError("inner assemble changed retained raw evidence")
    return receipt


def _inner_verify(
    source: Path,
    build_authority_dir: Path,
    build_dir: Path,
    package: Path,
    launch_authority: Path,
    *,
    require_accepted: bool,
) -> dict[str, Any]:
    container_layout = _validate_inner_paths(
        "verify",
        source=source,
        build_dir=build_dir,
        build_authority_dir=build_authority_dir,
        package=package,
        launch_authority=launch_authority,
    )
    payload, _execution, build_record, _binary = _inner_launch_context(
        "verify", launch_authority, source, build_authority_dir, build_dir
    )
    if _campaign_container_layout(build_record) != container_layout:
        raise CampaignError(
            "inner verify container layout differs from analyzer build authority"
        )
    if payload["require_accepted"] != require_accepted:
        raise CampaignError("inner verify acceptance mode differs from launch")
    before = _campaign_input_identity(
        "verify",
        source=source,
        build_record=build_record,
        package=package,
    )
    if before != payload["inputs"]:
        raise CampaignError("inner verify input differs from launch authority")
    _require_package_build_binding(package, build_record)
    receipt = verify_package(
        package,
        build_dir,
        build_verifier=build_authority.verify_authority_in_current_runtime,
        require_accepted=require_accepted,
        source_root=source,
    )
    if _campaign_input_identity(
        "verify", source=source, build_record=build_record, package=package
    ) != before:
        raise CampaignError("inner verify changed its read-only package")
    return receipt


def _launch_independent_verify(
    workspace: Path,
    package: Path,
    snapshot: dict[str, Any],
    *,
    require_accepted: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_sealed_package_shape(package)
    launch_dir = workspace / "verify-launch"
    scratch = workspace / "verify-scratch"
    launch_dir.mkdir()
    scratch.mkdir()
    runtime = _campaign_runtime(
        "verify",
        None,
        snapshot["build_record"],
        require_accepted=require_accepted,
    )
    inputs = _campaign_input_identity(
        "verify",
        source=snapshot["source"],
        build_record=snapshot["build_record"],
        package=package,
    )
    launch = _launch_payload(
        "verify",
        None,
        snapshot["build_record"],
        runtime,
        inputs,
        require_accepted=require_accepted,
    )
    launch_path = launch_dir / CAMPAIGN_LAUNCH_NAME
    launch_sha = _write_launch_authority(launch_path, launch)
    log = workspace / "verify-container.log"
    container_authority = _new_campaign_container_authority(log, "verify")
    command = _campaign_container_command(
        "verify",
        None,
        launch_sha,
        container_authority=container_authority,
        source=snapshot["source"],
        build_dir=snapshot["build_dir"],
        build_authority_dir=snapshot["build_authority_dir"],
        scratch=scratch,
        package=package,
        launch_dir=launch_dir,
        require_accepted=require_accepted,
        build_record=snapshot["build_record"],
    )
    marker = _execute_campaign_container(
        command, log, "verify", container_authority
    )
    _validate_sealed_package_shape(package)
    receipt_path = _regular(package / "receipt.json", "campaign receipt")
    if marker != sha256_file(receipt_path):
        raise CampaignError("inner verify marker differs from campaign receipt")
    if _campaign_input_identity(
        "verify",
        source=snapshot["source"],
        build_record=snapshot["build_record"],
        package=package,
    ) != inputs:
        raise CampaignError("package changed during independent verification")
    receipt = strict_json(receipt_path)
    return receipt, copy_json(inputs["package"])


def run_campaign(
    source: Path,
    published_build_authority: Path,
    build_dir: Path,
    juliet_dir: Path,
    juliet_archive: Path,
    libarchive_checkout: Path,
    output: Path,
    *,
    jobs: int,
) -> dict[str, Any]:
    snapshot = _outer_snapshot(
        "run",
        source=source,
        build_authority_dir=published_build_authority,
        build_dir=build_dir,
        jobs=jobs,
        juliet_dir=juliet_dir,
        juliet_archive=juliet_archive,
        libarchive_checkout=libarchive_checkout,
    )
    output = _validate_output_target(
        output,
        (
            (ROOT.resolve(), "executing source root"),
            (snapshot["source"], "standalone source"),
            (snapshot["build_dir"], "analyzer build directory"),
            (snapshot["build_authority_dir"], "build authority"),
            (_directory(juliet_dir, "Juliet directory"), "Juliet directory"),
            (_regular(juliet_archive, "Juliet archive"), "Juliet archive"),
            (
                _directory(libarchive_checkout, "libarchive checkout"),
                "libarchive checkout",
            ),
        ),
    )
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.campaign-", dir=output.parent)
    )
    try:
        stage = staging / "stage"
        scratch = staging / "run-scratch"
        stage.mkdir()
        scratch.mkdir()
        launch_path = stage / CAMPAIGN_LAUNCH_NAME
        launch_sha = _write_launch_authority(launch_path, snapshot["launch"])
        log = staging / "run-container.log"
        container_authority = _new_campaign_container_authority(log, "run")
        command = _campaign_container_command(
            "run",
            jobs,
            launch_sha,
            container_authority=container_authority,
            source=snapshot["source"],
            build_dir=snapshot["build_dir"],
            build_authority_dir=snapshot["build_authority_dir"],
            scratch=scratch,
            stage=stage,
            juliet_dir=juliet_dir,
            juliet_archive=juliet_archive,
            libarchive_checkout=libarchive_checkout,
            build_record=snapshot["build_record"],
        )
        marker = _execute_campaign_container(
            command, log, "run", container_authority
        )
        staged_package = _directory(
            stage / "package", "staged campaign package"
        )
        _validate_sealed_package_shape(staged_package)
        if marker != sha256_file(
            _regular(staged_package / "receipt.json", "campaign receipt")
        ):
            raise CampaignError("inner run marker differs from campaign receipt")
        _lightweight_outer_recheck(
            snapshot,
            action="run",
            require_accepted=True,
            juliet_dir=juliet_dir,
            juliet_archive=juliet_archive,
            libarchive_checkout=libarchive_checkout,
        )
        verified, verified_package_identity = _launch_independent_verify(
            staging, staged_package, snapshot, require_accepted=True
        )
        _final_outer_recheck(
            snapshot,
            "run",
            jobs=jobs,
            require_accepted=True,
            juliet_dir=juliet_dir,
            juliet_archive=juliet_archive,
            libarchive_checkout=libarchive_checkout,
        )
        _validate_sealed_package_shape(staged_package)
        if _tree_identity(
            staged_package, "independently verified campaign package"
        ) != verified_package_identity:
            raise CampaignError("campaign package changed before atomic promotion")
        _promote_new_package(
            staged_package, output, verified_package_identity
        )
        return verified
    finally:
        _finish_campaign_workspace(staging)


def assemble_campaign(
    source: Path,
    published_build_authority: Path,
    build_dir: Path,
    package: Path,
) -> dict[str, Any]:
    snapshot = _outer_snapshot(
        "assemble",
        source=source,
        build_authority_dir=published_build_authority,
        build_dir=build_dir,
        jobs=None,
        package=package,
    )
    package = _reject_package_overlap(
        package, snapshot, label="raw campaign package"
    )
    staging = Path(
        tempfile.mkdtemp(prefix=f".{package.name}.assemble-", dir=package.parent)
    )
    try:
        stage = staging / "stage"
        scratch = staging / "assemble-scratch"
        stage.mkdir()
        scratch.mkdir()
        staged_package = stage / "package"
        staged_package.mkdir()
        _copy_tree_exact(
            package / "raw", staged_package / "raw", "raw campaign input"
        )
        launch_path = stage / CAMPAIGN_LAUNCH_NAME
        launch_sha = _write_launch_authority(launch_path, snapshot["launch"])
        log = staging / "assemble-container.log"
        container_authority = _new_campaign_container_authority(
            log, "assemble"
        )
        command = _campaign_container_command(
            "assemble",
            None,
            launch_sha,
            container_authority=container_authority,
            source=snapshot["source"],
            build_dir=snapshot["build_dir"],
            build_authority_dir=snapshot["build_authority_dir"],
            scratch=scratch,
            stage=stage,
            build_record=snapshot["build_record"],
        )
        marker = _execute_campaign_container(
            command, log, "assemble", container_authority
        )
        _validate_sealed_package_shape(staged_package)
        if marker != sha256_file(
            _regular(staged_package / "receipt.json", "campaign receipt")
        ):
            raise CampaignError("inner assemble marker differs from campaign receipt")
        _lightweight_outer_recheck(
            snapshot,
            action="assemble",
            require_accepted=True,
            package=package,
        )
        verified, verified_package_identity = _launch_independent_verify(
            staging, staged_package, snapshot, require_accepted=True
        )
        _final_outer_recheck(
            snapshot,
            "assemble",
            jobs=None,
            require_accepted=True,
            package=package,
        )
        _validate_sealed_package_shape(staged_package)
        if _tree_identity(
            staged_package, "independently verified campaign package"
        ) != verified_package_identity:
            raise CampaignError("campaign package changed before atomic replacement")
        _replace_package(
            staged_package,
            package,
            snapshot["inputs"]["package_raw"],
            verified_package_identity,
        )
        return verified
    finally:
        _finish_campaign_workspace(staging)


def verify_campaign(
    source: Path,
    published_build_authority: Path,
    build_dir: Path,
    package: Path,
    *,
    require_accepted: bool,
) -> dict[str, Any]:
    snapshot = _outer_snapshot(
        "verify",
        source=source,
        build_authority_dir=published_build_authority,
        build_dir=build_dir,
        jobs=None,
        require_accepted=require_accepted,
        package=package,
    )
    package = _reject_package_overlap(
        package, snapshot, label="sealed campaign package"
    )
    staging = Path(
        tempfile.mkdtemp(prefix=f".{package.name}.verify-", dir=package.parent)
    )
    try:
        receipt, verified_package_identity = _launch_independent_verify(
            staging, package, snapshot, require_accepted=require_accepted
        )
        _final_outer_recheck(
            snapshot,
            "verify",
            jobs=None,
            require_accepted=require_accepted,
            package=package,
        )
        _validate_sealed_package_shape(package)
        if _tree_identity(
            package, "independently verified campaign package"
        ) != verified_package_identity:
            raise CampaignError("campaign package changed after public verification")
        return receipt
    finally:
        _finish_campaign_workspace(staging)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(
        dest="action", required=True, metavar="{run,assemble,verify}"
    )

    run_parser = subparsers.add_parser("run", help="run and seal the offline campaign")
    run_parser.add_argument("--source", type=Path, required=True)
    run_parser.add_argument("--build-authority", type=Path, required=True)
    run_parser.add_argument("--build-dir", type=Path, required=True)
    run_parser.add_argument("--juliet-dir", type=Path, required=True)
    run_parser.add_argument("--juliet-archive", type=Path, required=True)
    run_parser.add_argument("--libarchive-checkout", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument(
        "--jobs", type=int, default=max(1, min(8, os.cpu_count() or 1))
    )

    assemble_parser = subparsers.add_parser(
        "assemble", help="seal an already completed raw campaign"
    )
    assemble_parser.add_argument("--source", type=Path, required=True)
    assemble_parser.add_argument("--build-authority", type=Path, required=True)
    assemble_parser.add_argument("--build-dir", type=Path, required=True)
    assemble_parser.add_argument("--package", type=Path, required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="rederive and verify a retained campaign"
    )
    verify_parser.add_argument("--source", type=Path, required=True)
    verify_parser.add_argument("--build-authority", type=Path, required=True)
    verify_parser.add_argument("--build-dir", type=Path, required=True)
    verify_parser.add_argument("--package", type=Path, required=True)
    verify_parser.add_argument(
        "--allow-rejected", action="store_true", help="verify a quality rejection"
    )

    inner_run = subparsers.add_parser("_inner-run")
    inner_run.add_argument("--source", type=Path, required=True)
    inner_run.add_argument("--build-authority", type=Path, required=True)
    inner_run.add_argument("--build-dir", type=Path, required=True)
    inner_run.add_argument("--juliet-dir", type=Path, required=True)
    inner_run.add_argument("--juliet-archive", type=Path, required=True)
    inner_run.add_argument("--libarchive-checkout", type=Path, required=True)
    inner_run.add_argument("--output", type=Path, required=True)
    inner_run.add_argument("--launch-authority", type=Path, required=True)
    inner_run.add_argument("--jobs", type=int, required=True)

    inner_assemble = subparsers.add_parser("_inner-assemble")
    inner_assemble.add_argument("--source", type=Path, required=True)
    inner_assemble.add_argument("--build-authority", type=Path, required=True)
    inner_assemble.add_argument("--build-dir", type=Path, required=True)
    inner_assemble.add_argument("--package", type=Path, required=True)
    inner_assemble.add_argument("--launch-authority", type=Path, required=True)

    inner_verify = subparsers.add_parser("_inner-verify")
    inner_verify.add_argument("--source", type=Path, required=True)
    inner_verify.add_argument("--build-authority", type=Path, required=True)
    inner_verify.add_argument("--build-dir", type=Path, required=True)
    inner_verify.add_argument("--package", type=Path, required=True)
    inner_verify.add_argument("--launch-authority", type=Path, required=True)
    inner_verify.add_argument("--allow-rejected", action="store_true")
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    if args.action == "run":
        receipt = run_campaign(
            args.source,
            args.build_authority,
            args.build_dir,
            args.juliet_dir,
            args.juliet_archive,
            args.libarchive_checkout,
            args.output,
            jobs=args.jobs,
        )
    elif args.action == "assemble":
        receipt = assemble_campaign(
            args.source,
            args.build_authority,
            args.build_dir,
            args.package,
        )
    elif args.action == "verify":
        receipt = verify_campaign(
            args.source,
            args.build_authority,
            args.build_dir,
            args.package,
            require_accepted=not args.allow_rejected,
        )
    elif args.action == "_inner-run":
        _inner_run(
            args.source,
            args.build_authority,
            args.build_dir,
            args.juliet_dir,
            args.juliet_archive,
            args.libarchive_checkout,
            args.output,
            args.launch_authority,
            args.jobs,
        )
        print(
            "CODESKEPTIC_QUALITY_FLOOR_INNER_RUN "
            + sha256_file(args.output / "receipt.json")
        )
        return 0
    elif args.action == "_inner-assemble":
        _inner_assemble(
            args.source,
            args.build_authority,
            args.build_dir,
            args.package,
            args.launch_authority,
        )
        print(
            "CODESKEPTIC_QUALITY_FLOOR_INNER_ASSEMBLE "
            + sha256_file(args.package / "receipt.json")
        )
        return 0
    else:
        _inner_verify(
            args.source,
            args.build_authority,
            args.build_dir,
            args.package,
            args.launch_authority,
            require_accepted=not args.allow_rejected,
        )
        print(
            "CODESKEPTIC_QUALITY_FLOOR_INNER_VERIFY "
            + sha256_file(args.package / "receipt.json")
        )
        return 0
    if receipt["status"] != "accepted":
        print(
            "QUALITY_FLOOR_CAMPAIGN_REJECTED " + "; ".join(receipt["failures"]),
            file=sys.stderr,
        )
        return 2
    print("QUALITY_FLOOR_CAMPAIGN_ACCEPTED")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        with _campaign_signal_guard(enabled=args.action in PUBLIC_ACTIONS):
            return _dispatch(args)
    except CampaignInterrupted as error:
        details = [
            f"QUALITY_FLOOR_CAMPAIGN_INTERRUPTED signal={error.signum}"
        ]
        if error.recovery_paths:
            details.append(
                "recovery=" + ",".join(map(str, error.recovery_paths))
            )
        if error.cleanup_failures:
            details.append(
                "cleanup_failed=" + "; ".join(error.cleanup_failures)
            )
        print(" ".join(details), file=sys.stderr)
        return 128 + error.signum
    except (CampaignError, quality.QualityFloorError, OSError) as error:
        detail = f"QUALITY_FLOOR_CAMPAIGN_UNAVAILABLE {error}"
        if (
            isinstance(error, CampaignRecoveryRequired)
            and error.recovery_paths
        ):
            detail += " recovery=" + ",".join(
                map(str, error.recovery_paths)
            )
        print(detail, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
