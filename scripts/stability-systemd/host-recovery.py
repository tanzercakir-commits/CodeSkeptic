#!/usr/bin/env python3
"""Durably own and recover the final P10-09 host mutation envelope.

The marker is published before a session may create persistent runtime state,
arm the cgroup authority, or start a rootful Podman container.  Recovery is
deliberately narrower than general host cleanup: it removes only identities
derived from an exact, installed-bundle-bound marker and refuses everything
else.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


SCHEMA = "codeskeptic-p10-09-host-recovery-intent-v1"
PODMAN_INSPECTION_SCHEMA = "codeskeptic-p10-09-podman-inspection-intent-v1"
STATUS = "armed"
INSTALLATION_SCHEMA = "codeskeptic-stability-installation-v1"
INSTALLATION_AUTHORITY_SCHEMA = "codeskeptic-stability-installation-authority-v1"
BUNDLE_RECEIPT_SCHEMA = "codeskeptic-stability-staging-bundle-v1"
GUIDED_HANDOFF_SCHEMA = "codeskeptic-guided-handoff-v1"
GUIDED_DECISION_SCHEMA = "codeskeptic-guided-decision-v1"
GRAPHICAL_RESTORATION_SCHEMA = "codeskeptic-graphical-restoration-v1"
CAMPAIGN_REQUEST_SCHEMA = "codeskeptic-campaign-request-v1"
PROBE_REQUEST_SCHEMA = "codeskeptic-probe-only-v1"
CGROUP_SCHEMA = "codeskeptic-p10-09-cgroup-authority-intent-v1"

UUID_TEXT = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
UUID = re.compile(UUID_TEXT)
CAMPAIGN_SESSION = re.compile(
    rf"[0-9]{{8}}T[0-9]{{6}}Z-({UUID_TEXT})-({UUID_TEXT})"
)
PROBE_SESSION = re.compile(rf"probe-({UUID_TEXT})")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")

INSTALLATION_RECEIPT = Path(
    "/opt/codeskeptic-p10-09/installation/receipt.json"
)
INSTALLATION_RECEIPT_SHA = INSTALLATION_RECEIPT.with_name("receipt.json.sha256")
INSTALLATION_ROOT = INSTALLATION_RECEIPT.parent
BUNDLE_RECEIPT = INSTALLATION_ROOT / "bundle" / "receipt.json"
BUNDLE_RECEIPT_SHA = BUNDLE_RECEIPT.with_name("receipt.json.sha256")
AUTHORITY_ROOT = Path("/opt/codeskeptic-p10-09/authority")
OPERATOR_ROOT = Path("/opt/codeskeptic-p10-09/operator")
CONTAINERS_CONF = OPERATOR_ROOT / "containers.conf"
CONFIG_PATH = Path("/etc/codeskeptic-p10-09/runtime.json")
UNIT_PATH = Path("/etc/systemd/system/codeskeptic-stability.service")
STATE_ROOT = Path("/var/lib/codeskeptic-p10-09")
GUIDED_LIFECYCLE_LOCK = STATE_ROOT / "guided.lock"
GUIDED_ENTRYPOINT = Path(
    "/opt/codeskeptic-p10-09/operator/guided-stability.sh"
)
INSTALLATION_AUTHORITY = STATE_ROOT / "installation-authority.json"
MARKER = STATE_ROOT / "host-recovery-intent.json"
MARKER_TEMP = STATE_ROOT / ".host-recovery-intent.tmp"
PODMAN_INSPECTION_MARKER = STATE_ROOT / "podman-inspection-intent.json"
PODMAN_INSPECTION_MARKER_TEMP = STATE_ROOT / ".podman-inspection-intent.tmp"
SESSION_ROOT = STATE_ROOT / "sessions"
LAUNCH_ROOTS = STATE_ROOT / "launches"
CONTAINER_RUNTIME_ROOT = STATE_ROOT / "runtime"
RUNTIME_IDENTITY_ROOT = STATE_ROOT / "runtime-identities"
PODMAN_ROOT = STATE_ROOT / "podman-root"
PODMAN_ENVIRONMENT_ROOT = STATE_ROOT / "podman-environment"
RUNTIME_ROOT = Path("/run/codeskeptic-p10-09")
PODMAN_RUNROOT = RUNTIME_ROOT / "podman-runroot"
CGROUP_AUTHORITY = Path(
    "/opt/codeskeptic-p10-09/operator/cgroup-authority.py"
)
CGROUP_MARKER = STATE_ROOT / "cgroup-authority-intent.json"
CGROUP_MARKER_TEMP = STATE_ROOT / ".cgroup-authority-intent.tmp"
GRAPHICAL_RESTORATION = STATE_ROOT / "graphical-restoration-state.json"
GRAPHICAL_RESTORATION_TEMP = STATE_ROOT / ".graphical-restoration-state.json.tmp"
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

PODMAN = Path("/usr/bin/podman")
ENV = Path("/usr/bin/env")
PYTHON = Path("/usr/bin/python3")
CONMON = Path("/usr/bin/conmon")
CRUN = Path("/usr/bin/crun")
STAGING_AUTHORITY = OPERATOR_ROOT / "stage_stability_campaign.py"
PINNED_EVIDENCE_IMAGE_ID = (
    "sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5"
)
PINNED_EVIDENCE_IMAGE_DIGEST = (
    "sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
)
PINNED_EVIDENCE_IMAGE = (
    "localhost/codeskeptic-p10-07-evidence@"
    + PINNED_EVIDENCE_IMAGE_DIGEST
)
PINNED_PODMAN_VERSION = "5.8.4"

CONFIG_SHA_PATH = Path(f"{CONFIG_PATH}.sha256")
CONTROLLER_CGROUP_RELATIVE = (
    "/system.slice/codeskeptic-stability.service/controller"
)
PAYLOAD_CGROUP_RELATIVE = (
    "/system.slice/codeskeptic-stability.service/codeskeptic-p10-09"
)
MEASUREMENT_CGROUP = Path(f"/sys/fs/cgroup{PAYLOAD_CGROUP_RELATIVE}/measurement")
MEASUREMENT_CPU_LIST = "0,1,2,3"
CONTAINER_WORKDIR = "/authority/source"
CONTAINER_ENVIRONMENT = {
    "HOME": "/runtime/home",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TMPDIR": "/runtime/tmp",
    "TZ": "UTC",
    "XDG_CACHE_HOME": "/runtime/xdg-cache",
    "container": "podman",
}
SANITIZER_CTEST_TMPFS = {
    (
        "/authority/source/build/p10-09-sanitizers/"
        "address-tests/Testing/Temporary"
    ): "rw,nosuid,nodev,size=16m,mode=1777,rprivate,tmpcopyup",
    (
        "/authority/source/build/p10-09-sanitizers/"
        "undefined-tests/Testing/Temporary"
    ): "rw,nosuid,nodev,size=16m,mode=1777,rprivate,tmpcopyup",
}
IMAGE_CONFIG_LABELS = {
    "io.buildah.version": "1.43.0",
    "org.opencontainers.image.version": "24.04",
}
RUNTIME_CONTROLLER_COMMAND = (
    "/usr/bin/taskset",
    "--cpu-list",
    "4-11",
    "/usr/bin/python3",
    "-B",
    "/operator/container-entry.py",
    "run",
)
RUNTIME_VERIFIER_COMMAND = (
    "/usr/bin/taskset",
    "--cpu-list",
    "4-11",
    "/usr/bin/python3",
    "-B",
    "/operator/container-entry.py",
    "verify",
)
# The preflight source is deliberately not duplicated here.  Its exact bytes
# are bound by this digest while the remaining argv elements are checked
# individually below.
PREFLIGHT_PYTHON_SHA256 = (
    "b139a1af1797d51c06955598534bd87ba7e70f86868ce5f07e19cd4baac60426"
)

OWNER_LABEL = "io.codeskeptic.p10-09.host-recovery"
SESSION_LABEL = "io.codeskeptic.p10-09.session"
BUNDLE_LABEL = "io.codeskeptic.p10-09.bundle-revision"
KIND_LABEL = "io.codeskeptic.p10-09.container-kind"

ROOT_UID = 0
ROOT_GID = 0
MAX_MARKER_BYTES = 16 * 1024
MAX_INSTALLATION_BYTES = 64 * 1024
MAX_PODMAN_OUTPUT_BYTES = 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 1024 * 1024

CommandRunner = Callable[..., subprocess.CompletedProcess[bytes]]
COMMAND_RUNNER: CommandRunner = subprocess.run


class RecoveryError(RuntimeError):
    """A controlled fail-closed whole-host recovery error."""


def compact_canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def pretty_canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def require_root_caller() -> None:
    if os.geteuid() != ROOT_UID:
        raise RecoveryError("host recovery must run as root")


def require_exact_directory(
    path: Path, label: str, *, mode: int | None = None
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RecoveryError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise RecoveryError(f"{label} is not an exact directory")
    if metadata.st_uid != ROOT_UID or metadata.st_gid != ROOT_GID:
        raise RecoveryError(f"{label} ownership drift")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise RecoveryError(f"{label} mode drift")
    return metadata


def require_state_root() -> None:
    require_exact_directory(STATE_ROOT, "state root", mode=0o700)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_guided_lifecycle_lock_descriptor(descriptor: int) -> None:
    require_state_root()
    try:
        opened = os.fstat(descriptor)
        path_metadata = GUIDED_LIFECYCLE_LOCK.lstat()
    except OSError as error:
        raise RecoveryError(f"guided lifecycle lock is unavailable: {error}") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(path_metadata.st_mode)
        or GUIDED_LIFECYCLE_LOCK.is_symlink()
        or opened.st_dev != path_metadata.st_dev
        or opened.st_ino != path_metadata.st_ino
        or opened.st_uid != ROOT_UID
        or opened.st_gid != ROOT_GID
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or opened.st_size != 0
    ):
        raise RecoveryError("guided lifecycle lock authority drift")


def acquire_guided_lifecycle_lock() -> int:
    """Open without following or truncating, then take the global guided lock."""

    require_root_caller()
    require_state_root()
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(
            GUIDED_LIFECYCLE_LOCK,
            flags | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        created = True
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        fsync_directory(STATE_ROOT)
    except FileExistsError:
        descriptor = os.open(GUIDED_LIFECYCLE_LOCK, flags)
    try:
        _validate_guided_lifecycle_lock_descriptor(descriptor)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RecoveryError("another guided invocation is already active") from error
    except BaseException:
        os.close(descriptor)
        raise
    if created:
        fsync_directory(STATE_ROOT)
    return descriptor


def validate_guided_lifecycle_lock(descriptor: int) -> str:
    require_root_caller()
    if descriptor < 3:
        raise RecoveryError("guided lifecycle lock descriptor is malformed")
    _validate_guided_lifecycle_lock_descriptor(descriptor)
    try:
        # An inherited duplicate refers to the same open-file description, so
        # this succeeds without releasing or replacing the parent's lock.
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise RecoveryError("guided lifecycle lock is not inherited") from error
    return "locked"


def exec_guided_under_lifecycle_lock(mode: str) -> None:
    if mode not in {"campaign", "probe-only"}:
        raise RecoveryError("guided lifecycle mode is malformed")
    descriptor = acquire_guided_lifecycle_lock()
    os.set_inheritable(descriptor, True)
    os.execv(
        GUIDED_ENTRYPOINT,
        [
            os.fspath(GUIDED_ENTRYPOINT),
            "--root-locked",
            mode,
            str(descriptor),
        ],
    )


def read_exact_file(
    path: Path,
    label: str,
    maximum: int,
    *,
    allowed_links: set[int] = frozenset({1}),
    exact_mode: int = 0o400,
    allow_empty: bool = False,
) -> tuple[os.stat_result, bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RecoveryError(f"{label} is unavailable: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != ROOT_UID
            or metadata.st_gid != ROOT_GID
            or stat.S_IMODE(metadata.st_mode) != exact_mode
            or metadata.st_nlink not in allowed_links
            or (metadata.st_size < 1 and not allow_empty)
            or metadata.st_size > maximum
        ):
            raise RecoveryError(f"{label} metadata drift")
        chunks = bytearray()
        while len(chunks) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        extra = os.read(descriptor, 1)
    finally:
        os.close(descriptor)
    raw = bytes(chunks)
    if (
        len(raw) != metadata.st_size
        or extra
        or after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
    ):
        raise RecoveryError(f"{label} changed while reading")
    return metadata, raw


def _load_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise RecoveryError(f"{label} claims drift")
    return value


def installation_identity(*, verify_filesystem: bool = True) -> dict[str, str]:
    _, authority_raw = read_exact_file(
        INSTALLATION_AUTHORITY,
        "installation out-of-band authority",
        4096,
    )
    authority = _load_json(
        authority_raw, "installation out-of-band authority"
    )
    if (
        set(authority)
        != {"bundle_receipt_sha256", "bundle_revision", "schema"}
        or pretty_canonical(authority) != authority_raw
        or authority.get("schema") != INSTALLATION_AUTHORITY_SCHEMA
        or not isinstance(authority.get("bundle_revision"), str)
        or GIT_SHA1.fullmatch(authority["bundle_revision"]) is None
        or not isinstance(authority.get("bundle_receipt_sha256"), str)
        or SHA256.fullmatch(authority["bundle_receipt_sha256"]) is None
    ):
        raise RecoveryError("installation out-of-band authority claims drift")
    _, raw = read_exact_file(
        INSTALLATION_RECEIPT,
        "installation receipt",
        MAX_INSTALLATION_BYTES,
    )
    value = _load_json(raw, "installation receipt")
    expected_fields = {
        "authority_root",
        "bundle_inventory_sha256",
        "bundle_receipt_sha256",
        "bundle_revision",
        "config_path",
        "image",
        "installed_inventory_sha256",
        "operator_root",
        "schema",
        "unit_path",
    }
    if set(value) != expected_fields or pretty_canonical(value) != raw:
        raise RecoveryError("installation receipt claims drift")
    if value["schema"] != INSTALLATION_SCHEMA:
        raise RecoveryError("installation receipt schema drift")
    expected_paths = {
        "authority_root": os.fspath(AUTHORITY_ROOT),
        "operator_root": os.fspath(OPERATOR_ROOT),
        "config_path": os.fspath(CONFIG_PATH),
        "unit_path": os.fspath(UNIT_PATH),
    }
    if any(value.get(field) != expected for field, expected in expected_paths.items()):
        raise RecoveryError("installation fixed path authority drift")
    revision = value["bundle_revision"]
    receipt_sha = value["bundle_receipt_sha256"]
    inventory_sha = value["bundle_inventory_sha256"]
    installed_sha = value["installed_inventory_sha256"]
    image = value["image"]
    if not isinstance(revision, str) or GIT_SHA1.fullmatch(revision) is None:
        raise RecoveryError("installation bundle revision is malformed")
    if (
        revision != authority["bundle_revision"]
        or receipt_sha != authority["bundle_receipt_sha256"]
    ):
        raise RecoveryError("installation differs from out-of-band authority")
    for label, candidate in (
        ("bundle receipt", receipt_sha),
        ("bundle inventory", inventory_sha),
        ("installed inventory", installed_sha),
    ):
        if not isinstance(candidate, str) or SHA256.fullmatch(candidate) is None:
            raise RecoveryError(f"installation {label} digest is malformed")
    if inventory_sha != installed_sha:
        raise RecoveryError("installed inventory differs from the sealed bundle")
    if (
        not isinstance(image, dict)
        or set(image) != {"archive_sha256", "digest", "id", "reference"}
        or image.get("id") != PINNED_EVIDENCE_IMAGE_ID
        or image.get("digest") != PINNED_EVIDENCE_IMAGE_DIGEST
        or not isinstance(image.get("archive_sha256"), str)
        or SHA256.fullmatch(image["archive_sha256"]) is None
        or image.get("reference") != PINNED_EVIDENCE_IMAGE
    ):
        raise RecoveryError("installation image identity drift")
    _, sidecar = read_exact_file(
        INSTALLATION_RECEIPT_SHA,
        "installation receipt checksum",
        1024,
    )
    expected_sidecar = (
        f"{hashlib.sha256(raw).hexdigest()}  receipt.json\n".encode("ascii")
    )
    if sidecar != expected_sidecar:
        raise RecoveryError("installation receipt checksum drift")
    if verify_filesystem:
        verify_installed_filesystem_authority(revision, receipt_sha)
    _, bundle_raw = read_exact_file(
        BUNDLE_RECEIPT,
        "installed bundle receipt",
        MAX_INSTALLATION_BYTES,
    )
    bundle = _load_json(bundle_raw, "installed bundle receipt")
    expected_bundle_fields = {
        "image_archive_sha256",
        "image_digest",
        "image_id",
        "image_reference",
        "inventory_sha256",
        "revision",
        "runtime_config_sha256",
        "schema",
        "source_manifest_sha256",
        "source_tree_sha1",
    }
    if set(bundle) != expected_bundle_fields or pretty_canonical(bundle) != bundle_raw:
        raise RecoveryError("installed bundle receipt claims drift")
    if (
        bundle.get("schema") != BUNDLE_RECEIPT_SCHEMA
        or bundle.get("revision") != revision
        or bundle.get("inventory_sha256") != inventory_sha
        or bundle.get("image_archive_sha256") != image["archive_sha256"]
        or bundle.get("image_reference") != PINNED_EVIDENCE_IMAGE
        or bundle.get("image_digest") != PINNED_EVIDENCE_IMAGE_DIGEST
        or bundle.get("image_id") != PINNED_EVIDENCE_IMAGE_ID
        or hashlib.sha256(bundle_raw).hexdigest() != receipt_sha
    ):
        raise RecoveryError("installed bundle receipt identity drift")
    for label, candidate in (
        ("source tree", bundle.get("source_tree_sha1")),
        ("source manifest", bundle.get("source_manifest_sha256")),
        ("runtime config", bundle.get("runtime_config_sha256")),
    ):
        pattern = GIT_SHA1 if label == "source tree" else SHA256
        if not isinstance(candidate, str) or pattern.fullmatch(candidate) is None:
            raise RecoveryError(f"installed bundle {label} identity is malformed")
    _, bundle_sidecar = read_exact_file(
        BUNDLE_RECEIPT_SHA,
        "installed bundle receipt checksum",
        1024,
    )
    expected_bundle_sidecar = (
        f"{receipt_sha}  receipt.json\n".encode("ascii")
    )
    if bundle_sidecar != expected_bundle_sidecar:
        raise RecoveryError("installed bundle receipt checksum drift")
    return {
        "bundle_inventory_sha256": inventory_sha,
        "bundle_receipt_sha256": receipt_sha,
        "bundle_revision": revision,
        "installed_inventory_sha256": installed_sha,
        "image_archive_sha256": image["archive_sha256"],
        "image_digest": PINNED_EVIDENCE_IMAGE_DIGEST,
        "image_id": image["id"],
        "image_reference": PINNED_EVIDENCE_IMAGE,
        "installation_authority_sha256": hashlib.sha256(
            authority_raw
        ).hexdigest(),
        "installation_receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_config_sha256": bundle["runtime_config_sha256"],
        "source_manifest_sha256": bundle["source_manifest_sha256"],
        "source_tree_sha1": bundle["source_tree_sha1"],
    }


def verify_installed_filesystem_authority(
    revision: str, bundle_receipt_sha256: str
) -> None:
    try:
        completed = subprocess.run(
            [
                os.fspath(PYTHON),
                "-B",
                os.fspath(STAGING_AUTHORITY),
                "verify-install-filesystem",
                "--receipt",
                os.fspath(INSTALLATION_RECEIPT),
                "--expected-revision",
                revision,
                "--expected-bundle-receipt-sha256",
                bundle_receipt_sha256,
            ],
            capture_output=True,
            text=False,
            check=False,
            timeout=300,
            env={
                "HOME": "/",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RecoveryError(
            f"installed filesystem authority verification failed: {error}"
        ) from error
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > 4096 or len(stderr) > 64 * 1024:
        raise RecoveryError("installed filesystem authority output is oversized")
    expected_stdout = (
        "CODESKEPTIC_INSTALLATION_FILESYSTEM_VERIFIED "
        f"{INSTALLATION_RECEIPT}\n"
    ).encode("ascii")
    if completed.returncode != 0 or stdout != expected_stdout or stderr:
        detail = stderr.decode("utf-8", errors="replace").strip()[-2000:]
        raise RecoveryError(
            "installed filesystem authority verification failed"
            + (f": {detail}" if detail else "")
        )


def current_boot_id() -> str:
    try:
        raw = BOOT_ID_PATH.read_bytes()
    except OSError as error:
        raise RecoveryError(f"boot identity is unavailable: {error}") from error
    try:
        value = raw.decode("ascii", errors="strict").removesuffix("\n")
    except UnicodeDecodeError as error:
        raise RecoveryError(f"boot identity is malformed: {error}") from error
    if raw != f"{value}\n".encode("ascii") or UUID.fullmatch(value) is None:
        raise RecoveryError("boot identity is malformed")
    return value


def session_identity(mode: str, session: str) -> tuple[str, str]:
    if mode == "campaign":
        matched = CAMPAIGN_SESSION.fullmatch(session)
        if matched is None:
            raise RecoveryError("campaign session identity is malformed")
        return matched.group(1), matched.group(2)
    if mode == "probe-only":
        matched = PROBE_SESSION.fullmatch(session)
        if matched is None:
            raise RecoveryError("probe session identity is malformed")
        return "", matched.group(1)
    raise RecoveryError("host recovery mode is malformed")


def _container_names(mode: str, nonce: str) -> dict[str, str]:
    names = {"preflight": f"codeskeptic-p10-09-preflight-{nonce}"}
    if mode == "campaign":
        names.update(
            {
                "campaign": f"codeskeptic-p10-09-{nonce}",
                "verifier": f"codeskeptic-p10-09-verifier-{nonce}",
            }
        )
    return names


def expected_marker(
    mode: str,
    session: str,
    *,
    boot_id: str | None = None,
    verify_filesystem: bool = True,
) -> dict[str, object]:
    embedded_boot, nonce = session_identity(mode, session)
    selected_boot = current_boot_id() if boot_id is None else boot_id
    if UUID.fullmatch(selected_boot) is None:
        raise RecoveryError("host recovery boot identity is malformed")
    if mode == "campaign" and embedded_boot != selected_boot:
        raise RecoveryError("campaign session boot identity drift")
    return {
        "boot_id": selected_boot,
        "containers": _container_names(mode, nonce),
        "installation": installation_identity(
            verify_filesystem=verify_filesystem
        ),
        "mode": mode,
        "schema": SCHEMA,
        "session": session,
        "session_nonce": nonce,
        "status": STATUS,
    }


def _validate_marker_value(
    value: dict[str, Any], raw: bytes, *, verify_filesystem: bool = True
) -> dict[str, object]:
    expected_fields = {
        "boot_id",
        "containers",
        "installation",
        "mode",
        "schema",
        "session",
        "session_nonce",
        "status",
    }
    if set(value) != expected_fields:
        raise RecoveryError("host recovery marker claims drift")
    mode = value.get("mode")
    session = value.get("session")
    boot_id = value.get("boot_id")
    if not isinstance(mode, str) or not isinstance(session, str):
        raise RecoveryError("host recovery marker claims drift")
    if not isinstance(boot_id, str) or UUID.fullmatch(boot_id) is None:
        raise RecoveryError("host recovery marker boot identity drift")
    embedded_boot, nonce = session_identity(mode, session)
    if mode == "campaign" and embedded_boot != boot_id:
        raise RecoveryError("host recovery marker session boot drift")
    expected = {
        "boot_id": boot_id,
        "containers": _container_names(mode, nonce),
        "installation": installation_identity(
            verify_filesystem=verify_filesystem
        ),
        "mode": mode,
        "schema": SCHEMA,
        "session": session,
        "session_nonce": nonce,
        "status": STATUS,
    }
    if value != expected or raw != compact_canonical(expected):
        raise RecoveryError("host recovery marker claims drift")
    return expected


def _read_marker_candidate(
    path: Path,
    *,
    allowed_links: set[int],
    verify_filesystem: bool = True,
) -> tuple[os.stat_result, bytes, dict[str, object]]:
    metadata, raw = read_exact_file(
        path,
        "host recovery marker",
        MAX_MARKER_BYTES,
        allowed_links=allowed_links,
    )
    return metadata, raw, _validate_marker_value(
        _load_json(raw, "host recovery marker"),
        raw,
        verify_filesystem=verify_filesystem,
    )


def _discover_marker(
    *, repair: bool, verify_filesystem: bool = True
) -> dict[str, object] | None:
    marker_present = MARKER.exists() or MARKER.is_symlink()
    temporary_present = MARKER_TEMP.exists() or MARKER_TEMP.is_symlink()
    if not marker_present and not temporary_present:
        return None
    if not marker_present:
        try:
            temporary, _, value = _read_marker_candidate(
                MARKER_TEMP,
                allowed_links={1},
                verify_filesystem=verify_filesystem,
            )
        except RecoveryError:
            # The caller cannot mutate session state until the hardlinked main
            # marker exists and arm() returns.  Therefore an exact-metadata,
            # unlinked partial temporary is a pre-publication cutpoint, not an
            # authority for deleting anything else.
            read_exact_file(
                MARKER_TEMP,
                "unpublished host recovery marker temporary",
                MAX_MARKER_BYTES,
                allowed_links={1},
                allow_empty=True,
            )
            if not repair:
                raise
            MARKER_TEMP.unlink()
            fsync_directory(STATE_ROOT)
            return None
        if repair:
            os.link(MARKER_TEMP, MARKER, follow_symlinks=False)
            fsync_directory(STATE_ROOT)
            MARKER_TEMP.unlink()
            fsync_directory(STATE_ROOT)
            reread, _, reread_value = _read_marker_candidate(
                MARKER,
                allowed_links={1},
                verify_filesystem=verify_filesystem,
            )
            if (
                reread.st_dev != temporary.st_dev
                or reread.st_ino != temporary.st_ino
                or reread_value != value
            ):
                raise RecoveryError("host recovery marker repair identity drift")
        return value
    metadata, raw, value = _read_marker_candidate(
        MARKER,
        allowed_links={1, 2},
        verify_filesystem=verify_filesystem,
    )
    if metadata.st_nlink == 1:
        if temporary_present:
            raise RecoveryError("unexpected host recovery marker temporary")
        return value
    if not temporary_present:
        raise RecoveryError("host recovery marker has an unexplained hardlink")
    temporary, temporary_raw, temporary_value = _read_marker_candidate(
        MARKER_TEMP,
        allowed_links={2},
        verify_filesystem=verify_filesystem,
    )
    if (
        temporary.st_dev != metadata.st_dev
        or temporary.st_ino != metadata.st_ino
        or temporary_raw != raw
        or temporary_value != value
    ):
        raise RecoveryError("host recovery marker link identity drift")
    if repair:
        MARKER_TEMP.unlink()
        fsync_directory(STATE_ROOT)
        _read_marker_candidate(
            MARKER,
            allowed_links={1},
            verify_filesystem=verify_filesystem,
        )
    return value


_HOST_MARKER_SAMPLE_BOOT = "11111111-1111-1111-1111-111111111111"
_HOST_MARKER_SAMPLE_NONCE = "22222222-2222-2222-2222-222222222222"
_HOST_MARKER_SAMPLE_TIMESTAMP = "00000000T000000Z"
_UUID_SHAPE = "hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh"
_TIMESTAMP_SHAPE = "ddddddddTddddddZ"


def _host_marker_prefix_pattern(
    mode: str,
) -> tuple[bytes | tuple[str, str], ...]:
    if mode == "campaign":
        session = (
            f"{_HOST_MARKER_SAMPLE_TIMESTAMP}-{_HOST_MARKER_SAMPLE_BOOT}-"
            f"{_HOST_MARKER_SAMPLE_NONCE}"
        )
    elif mode == "probe-only":
        session = f"probe-{_HOST_MARKER_SAMPLE_NONCE}"
    else:
        raise RecoveryError("host recovery marker prefix mode is malformed")
    complete = compact_canonical(
        expected_marker(
            mode,
            session,
            boot_id=_HOST_MARKER_SAMPLE_BOOT,
            verify_filesystem=False,
        )
    )
    tokens = {
        _HOST_MARKER_SAMPLE_TIMESTAMP.encode("ascii"): (
            "timestamp",
            _TIMESTAMP_SHAPE,
        ),
        _HOST_MARKER_SAMPLE_BOOT.encode("ascii"): ("boot_id", _UUID_SHAPE),
        _HOST_MARKER_SAMPLE_NONCE.encode("ascii"): (
            "session_nonce",
            _UUID_SHAPE,
        ),
    }
    parts: list[bytes | tuple[str, str]] = []
    offset = 0
    while offset < len(complete):
        matches = [
            (position, token, specification)
            for token, specification in tokens.items()
            if (position := complete.find(token, offset)) >= 0
        ]
        if not matches:
            parts.append(complete[offset:])
            break
        position, token, specification = min(matches, key=lambda item: item[0])
        if position > offset:
            parts.append(complete[offset:position])
        parts.append(specification)
        offset = position + len(token)
    return tuple(parts)


def _matches_shape_prefix(value: bytes, shape: str) -> bool:
    if len(value) > len(shape):
        return False
    for byte, expected in zip(value, shape):
        if expected == "d":
            if not ord("0") <= byte <= ord("9"):
                return False
        elif expected == "h":
            if not (
                ord("0") <= byte <= ord("9")
                or ord("a") <= byte <= ord("f")
            ):
                return False
        elif byte != ord(expected):
            return False
    return True


def _matches_host_marker_pattern_prefix(
    raw: bytes, pattern: tuple[bytes | tuple[str, str], ...]
) -> bool:
    position = 0
    captured: dict[str, bytes] = {}
    for part in pattern:
        if position == len(raw):
            return True
        if isinstance(part, bytes):
            available = min(len(part), len(raw) - position)
            if raw[position : position + available] != part[:available]:
                return False
            position += available
            if available < len(part):
                return position == len(raw)
            continue
        name, shape = part
        expected = captured.get(name)
        available = min(len(shape), len(raw) - position)
        observed = raw[position : position + available]
        if expected is None:
            if not _matches_shape_prefix(observed, shape):
                return False
            if available == len(shape):
                captured[name] = observed
        elif observed != expected[:available]:
            return False
        position += available
        if available < len(shape):
            return position == len(raw)
    return False


def is_strict_unpublished_host_marker_prefix(raw: bytes) -> bool:
    return any(
        _matches_host_marker_pattern_prefix(raw, _host_marker_prefix_pattern(mode))
        for mode in ("campaign", "probe-only")
    )


def _read_unpublished_host_marker_prefix() -> tuple[os.stat_result, bytes]:
    return read_exact_file(
        MARKER_TEMP,
        "unpublished host recovery marker temporary",
        MAX_MARKER_BYTES,
        allowed_links={1},
        allow_empty=True,
    )


def _discard_unpublished_host_marker_prefix(
    expected_metadata: os.stat_result, expected_raw: bytes
) -> None:
    metadata, raw = _read_unpublished_host_marker_prefix()
    if (
        metadata.st_dev != expected_metadata.st_dev
        or metadata.st_ino != expected_metadata.st_ino
        or raw != expected_raw
        or not is_strict_unpublished_host_marker_prefix(raw)
    ):
        raise RecoveryError(
            "unpublished host recovery marker changed before discard"
        )
    MARKER_TEMP.unlink()
    fsync_directory(STATE_ROOT)


def read_marker(
    session: str | None = None, *, verify_filesystem: bool = True
) -> dict[str, object]:
    require_root_caller()
    require_state_root()
    value = _discover_marker(
        repair=True, verify_filesystem=verify_filesystem
    )
    if value is None:
        raise RecoveryError("host recovery marker is unavailable")
    if session is not None and value["session"] != session:
        raise RecoveryError("host recovery marker session drift")
    return value


def _create_marker(value: dict[str, object]) -> None:
    raw = compact_canonical(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(MARKER_TEMP, flags, 0o400)
    try:
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise RecoveryError("short host recovery marker write")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            MARKER_TEMP.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    os.link(MARKER_TEMP, MARKER, follow_symlinks=False)
    fsync_directory(STATE_ROOT)
    MARKER_TEMP.unlink()
    fsync_directory(STATE_ROOT)


def expected_podman_inspection_marker(
    *, boot_id: str | None = None
) -> dict[str, object]:
    selected_boot = current_boot_id() if boot_id is None else boot_id
    if UUID.fullmatch(selected_boot) is None:
        raise RecoveryError("Podman inspection boot identity is malformed")
    return {
        "boot_id": selected_boot,
        "installation": installation_identity(),
        "schema": PODMAN_INSPECTION_SCHEMA,
        "status": STATUS,
    }


def _validate_podman_inspection_marker(
    raw: bytes,
) -> dict[str, object]:
    value = _load_json(raw, "Podman inspection marker")
    if set(value) != {"boot_id", "installation", "schema", "status"}:
        raise RecoveryError("Podman inspection marker claims drift")
    boot_id = value.get("boot_id")
    if not isinstance(boot_id, str) or UUID.fullmatch(boot_id) is None:
        raise RecoveryError("Podman inspection marker boot identity drift")
    expected = expected_podman_inspection_marker(boot_id=boot_id)
    if value != expected or raw != compact_canonical(expected):
        raise RecoveryError("Podman inspection marker claims drift")
    return expected


def _read_podman_inspection_candidate(
    path: Path, *, allowed_links: set[int]
) -> tuple[os.stat_result, bytes, dict[str, object]]:
    metadata, raw = read_exact_file(
        path,
        "Podman inspection marker",
        MAX_MARKER_BYTES,
        allowed_links=allowed_links,
    )
    return metadata, raw, _validate_podman_inspection_marker(raw)


def _discover_podman_inspection_marker(
    *, repair: bool
) -> dict[str, object] | None:
    main_present = _is_present(PODMAN_INSPECTION_MARKER)
    temporary_present = _is_present(PODMAN_INSPECTION_MARKER_TEMP)
    if not main_present and not temporary_present:
        return None
    if not main_present:
        try:
            temporary, _, value = _read_podman_inspection_candidate(
                PODMAN_INSPECTION_MARKER_TEMP, allowed_links={1}
            )
        except RecoveryError:
            read_exact_file(
                PODMAN_INSPECTION_MARKER_TEMP,
                "unpublished Podman inspection marker temporary",
                MAX_MARKER_BYTES,
                allowed_links={1},
                allow_empty=True,
            )
            if not repair:
                raise
            PODMAN_INSPECTION_MARKER_TEMP.unlink()
            fsync_directory(STATE_ROOT)
            return None
        if repair:
            os.link(
                PODMAN_INSPECTION_MARKER_TEMP,
                PODMAN_INSPECTION_MARKER,
                follow_symlinks=False,
            )
            fsync_directory(STATE_ROOT)
            PODMAN_INSPECTION_MARKER_TEMP.unlink()
            fsync_directory(STATE_ROOT)
            reread, _, reread_value = _read_podman_inspection_candidate(
                PODMAN_INSPECTION_MARKER, allowed_links={1}
            )
            if (
                reread.st_dev != temporary.st_dev
                or reread.st_ino != temporary.st_ino
                or reread_value != value
            ):
                raise RecoveryError("Podman inspection marker repair drift")
        return value
    metadata, raw, value = _read_podman_inspection_candidate(
        PODMAN_INSPECTION_MARKER, allowed_links={1, 2}
    )
    if metadata.st_nlink == 1:
        if temporary_present:
            raise RecoveryError("unexpected Podman inspection marker temporary")
        return value
    if not temporary_present:
        raise RecoveryError("Podman inspection marker has unexplained hardlink")
    temporary, temporary_raw, temporary_value = _read_podman_inspection_candidate(
        PODMAN_INSPECTION_MARKER_TEMP, allowed_links={2}
    )
    if (
        temporary.st_dev != metadata.st_dev
        or temporary.st_ino != metadata.st_ino
        or temporary_raw != raw
        or temporary_value != value
    ):
        raise RecoveryError("Podman inspection marker link identity drift")
    if repair:
        PODMAN_INSPECTION_MARKER_TEMP.unlink()
        fsync_directory(STATE_ROOT)
    return value


def _create_podman_inspection_marker(value: dict[str, object]) -> None:
    raw = compact_canonical(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(PODMAN_INSPECTION_MARKER_TEMP, flags, 0o400)
    try:
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise RecoveryError("short Podman inspection marker write")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            PODMAN_INSPECTION_MARKER_TEMP.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    os.link(
        PODMAN_INSPECTION_MARKER_TEMP,
        PODMAN_INSPECTION_MARKER,
        follow_symlinks=False,
    )
    fsync_directory(STATE_ROOT)
    PODMAN_INSPECTION_MARKER_TEMP.unlink()
    fsync_directory(STATE_ROOT)


def _is_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _require_empty_optional_directory(path: Path, label: str) -> None:
    if not _is_present(path):
        return
    require_exact_directory(path, label, mode=0o700)
    try:
        next(path.iterdir())
    except StopIteration:
        return
    except OSError as error:
        raise RecoveryError(f"cannot inspect {label}: {error}") from error
    raise RecoveryError(f"{label} contains state without authority")


def _runtime_root_has_unbound_state(
    *, allow_podman_runroot_state: bool = False
) -> None:
    require_exact_directory(RUNTIME_ROOT, "runtime root", mode=0o700)
    request_paths = {
        "campaign": RUNTIME_ROOT / "campaign.request",
        "probe-only": RUNTIME_ROOT / "probe-only.request",
    }
    present_requests = [
        (mode, path) for mode, path in request_paths.items() if _is_present(path)
    ]
    if len(present_requests) > 1:
        raise RecoveryError("multiple unbound launch requests exist")
    for mode, path in present_requests:
        _, raw = read_exact_file(
            path, "unbound launch request", 1024, exact_mode=0o600
        )
        value = _load_json(raw, "unbound launch request")
        if compact_canonical(value) != raw:
            raise RecoveryError("unbound launch request is not canonical")
        nonce = value.get("nonce")
        if not isinstance(nonce, str) or UUID.fullmatch(nonce) is None:
            raise RecoveryError("unbound launch request nonce is malformed")
        if mode == "campaign":
            valid = (
                set(value)
                == {"mode", "nonce", "schema", "target_uid", "target_user"}
                and value.get("mode") == "campaign"
                and value.get("schema") == CAMPAIGN_REQUEST_SCHEMA
                and isinstance(value.get("target_user"), str)
                and re.fullmatch(
                    r"[a-z_][a-z0-9_-]{0,31}", value["target_user"]
                )
                is not None
                and not isinstance(value.get("target_uid"), bool)
                and isinstance(value.get("target_uid"), int)
                and value["target_uid"] > 0
            )
        else:
            valid = (
                set(value) == {"mode", "nonce", "schema"}
                and value.get("mode") == "probe-only"
                and value.get("schema") == PROBE_REQUEST_SCHEMA
            )
        if not valid:
            raise RecoveryError("unbound launch request claims drift")
    lock_path = RUNTIME_ROOT / "stability.lock"
    if _is_present(lock_path):
        _, raw = read_exact_file(
            lock_path,
            "stability lock",
            1,
            exact_mode=0o600,
            allow_empty=True,
        )
        if raw:
            raise RecoveryError("stability lock contains unexpected data")
    allowed = {
        "campaign.request",
        "probe-only.request",
        "stability.lock",
    }
    for child in RUNTIME_ROOT.iterdir():
        if child.name in allowed:
            continue
        if child == PODMAN_RUNROOT:
            if allow_podman_runroot_state:
                require_exact_directory(child, "Podman runroot", mode=0o700)
            else:
                _require_empty_optional_directory(child, "Podman runroot")
            continue
        raise RecoveryError(
            f"runtime artifact exists without authority: {child.name}"
        )


def _repair_unpublished_request_temporaries() -> None:
    for request_name in ("campaign.request", "probe-only.request"):
        path = RUNTIME_ROOT / request_name
        temporary = RUNTIME_ROOT / f".{request_name}.tmp"
        if not _is_present(temporary):
            continue
        temporary_metadata, temporary_raw = read_exact_file(
            temporary,
            "unpublished launch request temporary",
            1024,
            allowed_links={1, 2},
            exact_mode=0o600,
            allow_empty=True,
        )
        if _is_present(path):
            path_metadata, path_raw = read_exact_file(
                path,
                "published launch request",
                1024,
                allowed_links={2},
                exact_mode=0o600,
            )
            if (
                temporary_metadata.st_nlink != 2
                or temporary_metadata.st_dev != path_metadata.st_dev
                or temporary_metadata.st_ino != path_metadata.st_ino
                or temporary_raw != path_raw
            ):
                raise RecoveryError("launch request publication link identity drift")
        elif temporary_metadata.st_nlink != 1:
            raise RecoveryError("launch request temporary has an unexplained hardlink")
        temporary.unlink()
        fsync_directory(RUNTIME_ROOT)


def discard_unbound_launch_requests() -> str:
    require_root_caller()
    require_state_root()
    if (
        _is_present(MARKER)
        or _is_present(MARKER_TEMP)
        or _is_present(PODMAN_INSPECTION_MARKER)
        or _is_present(PODMAN_INSPECTION_MARKER_TEMP)
    ):
        raise RecoveryError("cannot discard a request under active host authority")
    _repair_unpublished_request_temporaries()
    _validate_unbound_filesystem_clean()
    removed = 0
    for name in ("campaign.request", "probe-only.request"):
        path = RUNTIME_ROOT / name
        if _is_present(path):
            _unlink_exact(path)
            removed += 1
    return f"discarded-{removed}"


def _ensure_podman_runroot() -> None:
    require_exact_directory(RUNTIME_ROOT, "runtime root", mode=0o700)
    if not _is_present(PODMAN_RUNROOT):
        PODMAN_RUNROOT.mkdir(mode=0o700)
        fsync_directory(RUNTIME_ROOT)
    require_exact_directory(PODMAN_RUNROOT, "Podman runroot", mode=0o700)


def _podman_argv(arguments: Sequence[str]) -> list[str]:
    environment = (
        f"CONTAINERS_CONF={CONTAINERS_CONF}",
        f"HOME={PODMAN_ENVIRONMENT_ROOT}/home",
        "LANG=C",
        "LC_ALL=C",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ=UTC",
        f"XDG_DATA_HOME={PODMAN_ENVIRONMENT_ROOT}/data",
        f"XDG_CACHE_HOME={PODMAN_ENVIRONMENT_ROOT}/cache",
        f"XDG_CONFIG_HOME={PODMAN_ENVIRONMENT_ROOT}/config",
        f"XDG_RUNTIME_DIR={PODMAN_ENVIRONMENT_ROOT}/runtime",
        f"TMPDIR={PODMAN_ENVIRONMENT_ROOT}/tmp",
    )
    return [
        os.fspath(ENV),
        "--ignore-environment",
        "--",
        *environment,
        os.fspath(PODMAN),
        "--root",
        os.fspath(PODMAN_ROOT),
        "--runroot",
        os.fspath(PODMAN_RUNROOT),
        "--storage-driver=overlay",
        "--cgroup-manager=cgroupfs",
        f"--conmon={CONMON}",
        "--events-backend=none",
        f"--hooks-dir={OPERATOR_ROOT}",
        f"--runtime={CRUN}",
        *arguments,
    ]


def run_podman(arguments: Sequence[str]) -> bytes:
    completed = COMMAND_RUNNER(
        _podman_argv(arguments),
        capture_output=True,
        text=False,
        check=False,
    )
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise RecoveryError("Podman command returned a non-byte stream")
    if len(stdout) > MAX_PODMAN_OUTPUT_BYTES or len(stderr) > MAX_PODMAN_OUTPUT_BYTES:
        raise RecoveryError("Podman command output exceeds its fixed bound")
    if completed.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise RecoveryError(
            f"Podman recovery command failed ({completed.returncode}): {detail}"
        )
    return stdout


def _verify_podman_version() -> None:
    version = run_podman(("version", "--format", "{{.Client.Version}}"))
    try:
        version_text = version.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise RecoveryError("Podman version is malformed") from error
    if version_text != PINNED_PODMAN_VERSION:
        raise RecoveryError("Podman version drift")


def _podman_ids() -> list[str]:
    if not _is_present(PODMAN_ROOT):
        return []
    require_exact_directory(PODMAN_ROOT, "Podman root", mode=0o700)
    require_exact_directory(
        PODMAN_ENVIRONMENT_ROOT, "Podman environment root", mode=0o700
    )
    for name in ("home", "data", "cache", "config", "runtime", "tmp"):
        require_exact_directory(
            PODMAN_ENVIRONMENT_ROOT / name,
            f"Podman environment {name}",
            mode=0o700,
        )
    # Version drift must be rejected before creating a missing runroot,
    # inspecting containers, recovering cgroups, unlinking CIDs, or removing
    # any owned runtime object.
    _verify_podman_version()
    _ensure_podman_runroot()
    raw = run_podman(
        ("container", "list", "--all", "--no-trunc", "--format", "{{.ID}}")
    )
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise RecoveryError(f"Podman inventory is malformed: {error}") from error
    identifiers = text.splitlines()
    if any(CONTAINER_ID.fullmatch(item) is None for item in identifiers):
        raise RecoveryError("Podman inventory contains a malformed identity")
    if len(identifiers) != len(set(identifiers)):
        raise RecoveryError("Podman inventory contains duplicate identities")
    return identifiers


def _verify_pinned_image_store() -> None:
    if not _is_present(PODMAN_ROOT):
        return
    _verify_podman_version()
    identity = run_podman(
        (
            "image",
            "inspect",
            "--format",
            "{{.Id}}|{{.Digest}}",
            PINNED_EVIDENCE_IMAGE,
        )
    )
    try:
        identity_text = identity.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise RecoveryError("Podman image identity is malformed") from error
    if identity_text.count("|") != 1:
        raise RecoveryError("Podman image identity is malformed")
    image_id, digest = identity_text.split("|", 1)
    if not image_id.startswith("sha256:"):
        image_id = f"sha256:{image_id}"
    if (
        image_id != PINNED_EVIDENCE_IMAGE_ID
        or digest != PINNED_EVIDENCE_IMAGE_DIGEST
    ):
        raise RecoveryError("Podman pinned image identity drift")
    inventory = run_podman(
        ("image", "list", "--all", "--no-trunc", "--format", "{{.ID}}")
    )
    try:
        image_ids = {
            line if line.startswith("sha256:") else f"sha256:{line}"
            for line in inventory.decode("ascii", errors="strict").splitlines()
            if line
        }
    except UnicodeDecodeError as error:
        raise RecoveryError("Podman image inventory is malformed") from error
    if image_ids != {PINNED_EVIDENCE_IMAGE_ID}:
        raise RecoveryError("Podman image inventory is not exact")


def container_name(marker: dict[str, object], kind: str) -> str:
    containers = marker.get("containers")
    if not isinstance(containers, dict) or kind not in containers:
        raise RecoveryError("container kind is not owned by this session")
    name = containers[kind]
    if not isinstance(name, str):
        raise RecoveryError("container name identity drift")
    return name


def expected_container_labels(
    marker: dict[str, object], kind: str
) -> dict[str, str]:
    container_name(marker, kind)
    installation = marker.get("installation")
    session = marker.get("session")
    if not isinstance(installation, dict) or not isinstance(session, str):
        raise RecoveryError("host recovery marker identity is incomplete")
    revision = installation.get("bundle_revision")
    if not isinstance(revision, str):
        raise RecoveryError("host recovery bundle identity is incomplete")
    return {
        OWNER_LABEL: SCHEMA,
        SESSION_LABEL: session,
        BUNDLE_LABEL: revision,
        KIND_LABEL: kind,
    }


def _container_paths(marker: dict[str, object]) -> tuple[Path, Path, Path]:
    session = marker.get("session")
    mode = marker.get("mode")
    if not isinstance(session, str):
        raise RecoveryError("container session identity is incomplete")
    if mode == "campaign":
        return (
            LAUNCH_ROOTS / session,
            SESSION_ROOT / session / "campaign",
            CONTAINER_RUNTIME_ROOT / session,
        )
    if mode == "probe-only":
        probe_root = RUNTIME_ROOT / session
        return (
            probe_root / "launch",
            probe_root / "evidence",
            probe_root / "runtime",
        )
    raise RecoveryError("container mode identity is incomplete")


def expected_container_mounts(
    marker: dict[str, object], kind: str
) -> dict[str, tuple[str, bool]]:
    container_name(marker, kind)
    launch, evidence, runtime = _container_paths(marker)
    mutable = kind != "verifier"
    expected = {
        "/authority": (os.fspath(AUTHORITY_ROOT), False),
        "/operator": (os.fspath(OPERATOR_ROOT), False),
        "/config/runtime.json": (os.fspath(CONFIG_PATH), False),
        "/config/runtime.json.sha256": (os.fspath(CONFIG_SHA_PATH), False),
        "/evidence": (os.fspath(evidence), mutable),
        "/launch": (os.fspath(launch), False),
        "/runtime": (os.fspath(runtime), mutable),
        "/sys/fs/cgroup": ("/sys/fs/cgroup", False),
    }
    if mutable:
        measurement_procs = MEASUREMENT_CGROUP / "cgroup.procs"
        expected[os.fspath(measurement_procs)] = (
            os.fspath(measurement_procs),
            True,
        )
    return expected


def expected_container_binds(
    marker: dict[str, object], kind: str
) -> list[str]:
    container_name(marker, kind)
    launch, evidence, runtime = _container_paths(marker)
    mutable = kind != "verifier"
    ordered = [
        (AUTHORITY_ROOT, Path("/authority"), False),
        (OPERATOR_ROOT, Path("/operator"), False),
        (CONFIG_PATH, Path("/config/runtime.json"), False),
        (CONFIG_SHA_PATH, Path("/config/runtime.json.sha256"), False),
        (launch, Path("/launch"), False),
        (evidence, Path("/evidence"), mutable),
        (runtime, Path("/runtime"), mutable),
        (Path("/sys/fs/cgroup"), Path("/sys/fs/cgroup"), False),
    ]
    if mutable:
        measurement_procs = MEASUREMENT_CGROUP / "cgroup.procs"
        ordered.append((measurement_procs, measurement_procs, True))
    return [
        f"{source}:{destination}:{'rw' if writable else 'ro'},"
        "rprivate,nosuid,nodev,rbind"
        for source, destination, writable in ordered
    ]


def expected_container_cidfile(marker: dict[str, object], kind: str) -> Path:
    session = marker.get("session")
    if not isinstance(session, str):
        raise RecoveryError("container session identity is incomplete")
    suffixes = {
        "campaign": ".cid",
        "preflight": ".preflight.cid",
        "verifier": ".verifier.cid",
    }
    if kind not in suffixes:
        raise RecoveryError("container kind is not owned by this session")
    container_name(marker, kind)
    return RUNTIME_ROOT / f"{session}{suffixes[kind]}"


def _validate_container_command(
    config: dict[str, object], kind: str
) -> tuple[str, ...]:
    command = config.get("Cmd")
    if not isinstance(command, list) or any(
        not isinstance(item, str) for item in command
    ):
        raise RecoveryError("owned container command is malformed")
    observed = tuple(command)
    if kind == "campaign":
        expected = RUNTIME_CONTROLLER_COMMAND
        if observed != expected:
            raise RecoveryError("owned campaign command identity drift")
    elif kind == "verifier":
        expected = RUNTIME_VERIFIER_COMMAND
        if observed != expected:
            raise RecoveryError("owned verifier command identity drift")
    elif kind == "preflight":
        if (
            len(observed) != 11
            or observed[:3] != ("/usr/bin/taskset", "--cpu-list", "4-11")
            or observed[3:6] != ("/usr/bin/python3", "-B", "-c")
            or hashlib.sha256(observed[6].encode("utf-8")).hexdigest()
            != PREFLIGHT_PYTHON_SHA256
            or observed[7]
            != CONTROLLER_CGROUP_RELATIVE
            or observed[8] != os.fspath(MEASUREMENT_CGROUP)
            or observed[9] != f"{PAYLOAD_CGROUP_RELATIVE}/measurement"
            or observed[10] != MEASUREMENT_CPU_LIST
        ):
            raise RecoveryError("owned preflight command identity drift")
    else:
        raise RecoveryError("container kind is not owned by this session")
    return observed


def _validate_container_environment(config: dict[str, object]) -> None:
    environment = config.get("Env")
    if not isinstance(environment, list) or any(
        not isinstance(item, str) or "=" not in item for item in environment
    ):
        raise RecoveryError("owned container environment is malformed")
    claims: dict[str, str] = {}
    for item in environment:
        name, value = item.split("=", 1)
        if not name or name in claims:
            raise RecoveryError("owned container environment is ambiguous")
        claims[name] = value
    if claims != CONTAINER_ENVIRONMENT:
        raise RecoveryError("owned container environment identity drift")


def _validate_container_mounts(
    marker: dict[str, object], kind: str, mounts: object
) -> None:
    expected = expected_container_mounts(marker, kind)
    if not isinstance(mounts, list) or len(mounts) != len(expected):
        raise RecoveryError("owned container mount inventory drift")
    observed: dict[str, tuple[str, bool]] = {}
    for mount in mounts:
        if not isinstance(mount, dict):
            raise RecoveryError("owned container mount claims are malformed")
        destination = mount.get("Destination")
        source = mount.get("Source")
        writable = mount.get("RW")
        if (
            mount.get("Type") != "bind"
            or not isinstance(destination, str)
            or not isinstance(source, str)
            or not isinstance(writable, bool)
            or destination in observed
            or mount.get("Propagation") != "rprivate"
            or not isinstance(mount.get("Options"), list)
            or any(
                not isinstance(option, str) for option in mount["Options"]
            )
            or len(mount["Options"]) != 3
            or set(mount["Options"]) != {"nodev", "nosuid", "rbind"}
        ):
            raise RecoveryError("owned container mount claims are malformed")
        observed[destination] = (source, writable)
    if observed != expected:
        raise RecoveryError("owned container mount authority drift")


def _validate_container_ulimit(host_config: dict[str, object]) -> None:
    limits = host_config.get("Ulimits")
    if not isinstance(limits, list) or len(limits) != 1:
        raise RecoveryError("owned container ulimit inventory drift")
    limit = limits[0]
    if (
        not isinstance(limit, dict)
        or limit.get("Name") not in {"nofile", "RLIMIT_NOFILE"}
        or limit.get("Soft") != 4096
        or limit.get("Hard") != 4096
    ):
        raise RecoveryError("owned container open-file limit drift")


def _validate_container_execution_contract(
    marker: dict[str, object], kind: str, value: dict[str, object]
) -> None:
    config = value.get("Config")
    host_config = value.get("HostConfig")
    if not isinstance(config, dict) or not isinstance(host_config, dict):
        raise RecoveryError("owned container execution claims are malformed")
    command = _validate_container_command(config, kind)
    if value.get("Path") != command[0] or value.get("Args") != list(command[1:]):
        raise RecoveryError("owned container process identity drift")
    if (
        config.get("Entrypoint") not in ("", None)
        or config.get("Image") != PINNED_EVIDENCE_IMAGE
        or config.get("User") != "0:0"
        or config.get("WorkingDir") != CONTAINER_WORKDIR
    ):
        raise RecoveryError("owned container execution identity drift")
    _validate_container_environment(config)
    _validate_container_mounts(marker, kind, value.get("Mounts"))
    expected_host = {
        "AutoRemove": False,
        "Cgroup": "",
        "CgroupManager": "cgroupfs",
        "CgroupMode": "host",
        "CgroupParent": "",
        "Cgroups": "disabled",
        "CpusetCpus": "",
        "ContainerIDFile": os.fspath(expected_container_cidfile(marker, kind)),
        "IpcMode": "private",
        "NetworkMode": "none",
        "PidMode": "private",
        "Privileged": False,
        "PublishAllPorts": False,
        "ReadonlyRootfs": True,
        "UTSMode": "private",
        "UsernsMode": "",
    }
    if any(host_config.get(name) != claim for name, claim in expected_host.items()):
        raise RecoveryError("owned container isolation contract drift")
    if host_config.get("Tmpfs") != SANITIZER_CTEST_TMPFS:
        raise RecoveryError("owned container tmpfs contract drift")
    if host_config.get("Binds") != expected_container_binds(marker, kind):
        raise RecoveryError("owned container ordered bind contract drift")
    security = host_config.get("SecurityOpt")
    if (
        not isinstance(security, list)
        or any(not isinstance(item, str) for item in security)
        or set(security) != {"label=disable", "no-new-privileges"}
        or len(security) != 2
    ):
        raise RecoveryError("owned container security options drift")
    if (
        host_config.get("CapAdd") != []
        or host_config.get("CapDrop") != []
        or host_config.get("Devices") != []
        or host_config.get("PortBindings") != {}
        or host_config.get("RestartPolicy")
        != {"MaximumRetryCount": 0, "Name": "no"}
    ):
        raise RecoveryError("owned container host privilege contract drift")
    network = value.get("NetworkSettings")
    if not isinstance(network, dict) or network.get("Ports") != {}:
        raise RecoveryError("owned container network contract drift")
    if (
        value.get("Driver") != "overlay"
        or value.get("OCIRuntime") != os.fspath(CRUN)
        or value.get("Pod") != ""
        or value.get("IsInfra") is not False
        or value.get("IsService") is not False
        or value.get("ProcessLabel") != ""
    ):
        raise RecoveryError("owned container runtime contract drift")
    _validate_container_ulimit(host_config)


def _container_lifecycle(value: dict[str, object]) -> str:
    state = value.get("State")
    if not isinstance(state, dict):
        raise RecoveryError("owned container lifecycle claims are malformed")
    status = state.get("Status")
    pid = state.get("Pid")
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or state.get("Paused") is not False
        or state.get("Restarting") is not False
        or state.get("Dead") is not False
    ):
        raise RecoveryError("owned container lifecycle state drift")
    if status == "running" and state.get("Running") is True and pid > 0:
        return "running"
    conmon_pid = state.get("ConmonPid")
    if (
        status == "initialized"
        and state.get("Running") is False
        and pid > 0
        and not isinstance(conmon_pid, bool)
        and isinstance(conmon_pid, int)
        and conmon_pid > 0
    ):
        return "initialized"
    if (
        status == "stopping"
        and state.get("Running") is False
        and pid > 0
        and not isinstance(conmon_pid, bool)
        and isinstance(conmon_pid, int)
        and conmon_pid > 0
        and state.get("StoppedByUser") is True
    ):
        return "stopping"
    if (
        status == "removing"
        and state.get("Running") is False
        and pid == 0
    ):
        # Podman persists this state only after process, namespace, cgroup,
        # mount, and exec-session cleanup.  The caller additionally requires
        # our fsync'd CID-first cutpoint before resuming the idempotent rm.
        return "removing"
    # Podman 5.8.4 exposes the durable non-running libpod states through
    # inspect as created, stopped, and exited.
    if (
        status in {"created", "stopped", "exited"}
        and state.get("Running") is False
        and pid == 0
    ):
        return "stopped"
    raise RecoveryError("owned container lifecycle state drift")


def _owned_container_inventory(
    marker: dict[str, object],
    lifecycles: dict[str, str] | None = None,
) -> list[tuple[str, str]]:
    identifiers = _podman_ids()
    owned: list[tuple[str, str]] = []
    expected_names = {
        container_name(marker, kind): kind
        for kind in marker["containers"]  # type: ignore[union-attr]
    }
    seen_kinds: set[str] = set()
    for identifier in identifiers:
        raw = run_podman(("container", "inspect", identifier))
        try:
            document = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RecoveryError(
                f"Podman inspection is malformed for {identifier}: {error}"
            ) from error
        if not isinstance(document, list) or len(document) != 1:
            raise RecoveryError("Podman inspection cardinality drift")
        value = document[0]
        if not isinstance(value, dict):
            raise RecoveryError("Podman inspection claims drift")
        name = value.get("Name")
        kind = expected_names.get(name) if isinstance(name, str) else None
        config = value.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        image_id = value.get("Image")
        if isinstance(image_id, str) and SHA256.fullmatch(image_id) is not None:
            image_id = f"sha256:{image_id}"
        expected_labels = (
            expected_container_labels(marker, kind) if kind is not None else None
        )
        expected_config_labels = (
            {**IMAGE_CONFIG_LABELS, **expected_labels}
            if expected_labels is not None else None
        )
        if (
            value.get("Id") != identifier
            or kind is None
            or kind in seen_kinds
            or image_id != PINNED_EVIDENCE_IMAGE_ID
            or value.get("ImageDigest") != PINNED_EVIDENCE_IMAGE_DIGEST
            or value.get("ImageName") != PINNED_EVIDENCE_IMAGE
            or labels != expected_config_labels
        ):
            raise RecoveryError(
                f"foreign container exists in the dedicated store: {identifier}"
            )
        _validate_container_execution_contract(marker, kind, value)
        lifecycle = _container_lifecycle(value)
        if lifecycles is not None:
            lifecycles[identifier] = lifecycle
        seen_kinds.add(kind)
        owned.append((identifier, kind))
    return owned


def remove_owned_container(session: str, kind: str) -> str:
    """Remove at most one fully validated container, CID first."""

    require_root_caller()
    require_state_root()
    marker = read_marker(session)
    container_name(marker, kind)
    _identity, _runtime_files = _validate_owned_state(marker)
    validate_cgroup_session_binding(marker)
    inventory = _owned_container_inventory(marker)
    _validate_complete_cid_bindings(marker, inventory)
    if any(observed_kind != kind for _identifier, observed_kind in inventory):
        raise RecoveryError("normal cleanup overlaps another owned container kind")
    matches = [
        identifier
        for identifier, observed_kind in inventory
        if observed_kind == kind
    ]
    if len(matches) > 1:
        raise RecoveryError("owned container kind is ambiguous")
    cidfile = expected_container_cidfile(marker, kind)
    if inventory or _is_present(cidfile):
        # Even an empty/partial CID unlink is a mutation. Require the durable
        # cgroup marker, active ancestry, complete payload child inventory,
        # and exact Podman IDs first.
        verify_active_cgroup_authority(marker, inventory)
    if _is_present(cidfile):
        _unlink_exact(cidfile)
    if not matches:
        return "absent"
    identifier = matches[0]
    run_podman(("rm", "--force", "--ignore", "--", identifier))
    remaining = _owned_container_inventory(marker)
    _validate_complete_cid_bindings(marker, remaining)
    if any(observed_kind == kind for _item, observed_kind in remaining):
        raise RecoveryError("owned container survived exact removal")
    return identifier


def _validate_unbound_filesystem_clean(
    *, allow_podman_runroot_state: bool = False
) -> None:
    _require_empty_optional_directory(
        CONTAINER_RUNTIME_ROOT, "container runtime root"
    )
    _require_empty_optional_directory(
        RUNTIME_IDENTITY_ROOT, "runtime identity root"
    )
    _runtime_root_has_unbound_state(
        allow_podman_runroot_state=allow_podman_runroot_state
    )


def _validate_clean_without_marker() -> None:
    _validate_unbound_filesystem_clean()
    identifiers = _podman_ids()
    if identifiers:
        raise RecoveryError("Podman containers exist without authority")


def _validate_terminal_filesystem_clean() -> None:
    _validate_unbound_filesystem_clean()
    for request in (
        RUNTIME_ROOT / "campaign.request",
        RUNTIME_ROOT / "probe-only.request",
    ):
        if _is_present(request):
            raise RecoveryError("a new launch request appeared during recovery")


def _validate_prearm_filesystem(marker: dict[str, object]) -> None:
    _require_empty_optional_directory(
        CONTAINER_RUNTIME_ROOT, "container runtime root"
    )
    _require_empty_optional_directory(
        RUNTIME_IDENTITY_ROOT, "runtime identity root"
    )
    require_exact_directory(RUNTIME_ROOT, "runtime root", mode=0o700)
    _require_empty_optional_directory(PODMAN_RUNROOT, "Podman runroot")
    # The runner may already have atomically consumed the guided request in
    # order to derive its nonce.  Validate that exact request against the
    # would-be marker without permitting any session-owned state mutation.
    _validate_runtime_artifacts(marker)


def arm(mode: str, session: str) -> str:
    require_root_caller()
    require_state_root()
    if (
        _is_present(MARKER)
        or _is_present(MARKER_TEMP)
        or _is_present(PODMAN_INSPECTION_MARKER)
        or _is_present(PODMAN_INSPECTION_MARKER_TEMP)
    ):
        raise RecoveryError("host recovery marker already exists")
    value = expected_marker(mode, session)
    # Podman inspection itself may create runroot locks.  Publish first so all
    # such mutations are already covered by the durable recovery authority.
    _validate_prearm_filesystem(value)
    _create_marker(value)
    read_marker(session, verify_filesystem=False)
    if _owned_container_inventory(value):
        raise RecoveryError("Podman containers predate this recovery intent")
    return "armed"


def expected_runtime_identity(marker: dict[str, object]) -> dict[str, str]:
    session = marker["session"]
    nonce = marker["session_nonce"]
    boot_id = marker["boot_id"]
    if not all(isinstance(item, str) for item in (session, nonce, boot_id)):
        raise RecoveryError("runtime identity source claims drift")
    return {
        "boot_id": boot_id,
        "runtime": os.fspath(CONTAINER_RUNTIME_ROOT / session),
        "session": session,
        "session_nonce": nonce,
    }


def expected_handoff(marker: dict[str, object]) -> dict[str, str]:
    mode = marker["mode"]
    nonce = marker["session_nonce"]
    session = marker["session"]
    if not all(isinstance(item, str) for item in (mode, nonce, session)):
        raise RecoveryError("guided handoff source claims drift")
    return {
        "mode": mode,
        "nonce": nonce,
        "schema": GUIDED_HANDOFF_SCHEMA,
        "session": session,
    }


def expected_guided_decision(
    marker: dict[str, object], action: str
) -> dict[str, str]:
    if action not in {"accept", "cancel"}:
        raise RecoveryError("guided decision action is malformed")
    mode = marker["mode"]
    nonce = marker["session_nonce"]
    session = marker["session"]
    if not all(isinstance(item, str) for item in (mode, nonce, session)):
        raise RecoveryError("guided decision source claims drift")
    return {
        "action": action,
        "mode": mode,
        "nonce": nonce,
        "schema": GUIDED_DECISION_SCHEMA,
        "session": session,
    }


def expected_graphical_restoration(
    marker: dict[str, object],
) -> dict[str, str]:
    mode = marker["mode"]
    nonce = marker["session_nonce"]
    session = marker["session"]
    if mode != "campaign" or not all(
        isinstance(item, str) for item in (nonce, session)
    ):
        raise RecoveryError("graphical restoration source claims drift")
    return {
        "nonce": nonce,
        "phase": "restore-required",
        "schema": GRAPHICAL_RESTORATION_SCHEMA,
        "session": session,
    }


def expected_cgroup_marker(marker: dict[str, object]) -> dict[str, object]:
    installation = marker.get("installation")
    session = marker.get("session")
    if not isinstance(installation, dict) or not isinstance(session, str):
        raise RecoveryError("cgroup binding source claims drift")
    revision = installation.get("bundle_revision")
    if not isinstance(revision, str):
        raise RecoveryError("cgroup bundle binding is incomplete")
    return {
        "exclusive_cpus": "0-3",
        "measurement_cgroup": (
            "/sys/fs/cgroup/system.slice/codeskeptic-stability.service/"
            "codeskeptic-p10-09/measurement"
        ),
        "original_root_isolated_cpus": "",
        "original_service_exclusive_cpus": "",
        "original_system_slice_exclusive_cpus": "",
        "payload_cgroup": (
            "/sys/fs/cgroup/system.slice/codeskeptic-stability.service/"
            "codeskeptic-p10-09"
        ),
        "schema": CGROUP_SCHEMA,
        "service_cgroup": (
            "/sys/fs/cgroup/system.slice/codeskeptic-stability.service"
        ),
        "session": session,
        "source_revision": revision,
        "status": "armed",
        "system_slice_cgroup": "/sys/fs/cgroup/system.slice",
    }


def _read_cgroup_candidate(
    path: Path, *, allowed_links: set[int], marker: dict[str, object]
) -> tuple[os.stat_result, bytes]:
    metadata, raw = read_exact_file(
        path,
        "cgroup authority marker",
        MAX_MARKER_BYTES,
        allowed_links=allowed_links,
    )
    value = _load_json(raw, "cgroup authority marker")
    if value.get("session") != marker.get("session"):
        raise RecoveryError("cgroup authority session differs from host recovery")
    expected = expected_cgroup_marker(marker)
    if value != expected or raw != compact_canonical(expected):
        raise RecoveryError("cgroup authority marker claims drift")
    return metadata, raw


def validate_cgroup_session_binding(marker: dict[str, object]) -> None:
    main_present = _is_present(CGROUP_MARKER)
    temporary_present = _is_present(CGROUP_MARKER_TEMP)
    if not main_present and not temporary_present:
        return
    if not main_present:
        _, raw = read_exact_file(
            CGROUP_MARKER_TEMP,
            "unpublished cgroup authority marker temporary",
            MAX_MARKER_BYTES,
            allowed_links={1},
            allow_empty=True,
        )
        if not compact_canonical(expected_cgroup_marker(marker)).startswith(raw):
            raise RecoveryError("cgroup authority marker temporary claims drift")
        return
    metadata, raw = _read_cgroup_candidate(
        CGROUP_MARKER, allowed_links={1, 2}, marker=marker
    )
    if metadata.st_nlink == 1:
        if temporary_present:
            raise RecoveryError("unexpected cgroup authority marker temporary")
        return
    if not temporary_present:
        raise RecoveryError("cgroup authority marker has an unexplained hardlink")
    temporary, temporary_raw = _read_cgroup_candidate(
        CGROUP_MARKER_TEMP, allowed_links={2}, marker=marker
    )
    if (
        temporary.st_dev != metadata.st_dev
        or temporary.st_ino != metadata.st_ino
        or temporary_raw != raw
    ):
        raise RecoveryError("cgroup authority marker link identity drift")


def verify_active_cgroup_authority(
    marker: dict[str, object],
    owned_containers: Sequence[tuple[str, str]],
) -> None:
    """Reject runtime cgroup creation and bind the exact Podman inventory."""

    if not _is_present(CGROUP_MARKER):
        raise RecoveryError("owned container exists without cgroup authority")
    if _is_present(CGROUP_MARKER_TEMP):
        raise RecoveryError("owned container overlaps cgroup publication")
    validate_cgroup_session_binding(marker)
    session = marker.get("session")
    if not isinstance(session, str):
        raise RecoveryError("cgroup verification session is malformed")
    command = [
        os.fspath(CGROUP_AUTHORITY),
        "verify-active",
        "--session",
        session,
    ]
    for identifier, _kind in owned_containers:
        if CONTAINER_ID.fullmatch(identifier) is None:
            raise RecoveryError("cgroup container identity is malformed")
        command.extend(("--container-id", identifier))
    completed = subprocess.run(
        command,
        capture_output=True,
        text=False,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or b"").decode(
            "utf-8", errors="replace"
        ).strip()
        raise RecoveryError(
            "active cgroup authority verification failed "
            f"({completed.returncode}): {detail}"
        )


def verify_recovery_cgroup_authority(
    marker: dict[str, object],
    owned_containers: Sequence[tuple[str, str]],
) -> None:
    """Read-only validation for a stopped container or reboot cutpoint."""

    if not _is_present(CGROUP_MARKER):
        raise RecoveryError("owned container exists without cgroup authority")
    if _is_present(CGROUP_MARKER_TEMP):
        raise RecoveryError("owned container overlaps cgroup publication")
    validate_cgroup_session_binding(marker)
    session = marker.get("session")
    if not isinstance(session, str):
        raise RecoveryError("cgroup verification session is malformed")
    command = [
        os.fspath(CGROUP_AUTHORITY),
        "verify-recovery",
        "--session",
        session,
    ]
    for identifier, _kind in owned_containers:
        if CONTAINER_ID.fullmatch(identifier) is None:
            raise RecoveryError("cgroup container identity is malformed")
        command.extend(("--container-id", identifier))
    completed = subprocess.run(
        command,
        capture_output=True,
        text=False,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or b"").decode(
            "utf-8", errors="replace"
        ).strip()
        raise RecoveryError(
            "recovery cgroup authority verification failed "
            f"({completed.returncode}): {detail}"
        )


def _validate_exact_optional_file(
    path: Path, label: str, expected: bytes, *, modes: set[int] = frozenset({0o400})
) -> bool:
    if not _is_present(path):
        return False
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in modes:
        raise RecoveryError(f"{label} mode drift")
    _, raw = read_exact_file(
        path,
        label,
        max(len(expected), 1),
        exact_mode=mode,
    )
    if raw != expected:
        raise RecoveryError(f"{label} claims drift")
    return True


def _validate_unpublished_prefix(
    path: Path,
    label: str,
    expected_candidates: Sequence[bytes],
    *,
    exact_mode: int = 0o400,
) -> bool:
    if not _is_present(path):
        return False
    maximum = max(len(candidate) for candidate in expected_candidates)
    _, raw = read_exact_file(
        path,
        label,
        maximum,
        exact_mode=exact_mode,
        allow_empty=True,
    )
    if not any(candidate.startswith(raw) for candidate in expected_candidates):
        raise RecoveryError(f"{label} claims drift")
    return True


def _validate_atomic_publication(
    final_paths: Sequence[Path],
    temporary: Path,
    label: str,
    expected_candidates: Sequence[bytes],
) -> list[Path]:
    present_finals = [path for path in final_paths if _is_present(path)]
    temporary_present = _is_present(temporary)
    if len(present_finals) > 1:
        raise RecoveryError(f"multiple {label} authorities exist")
    if not present_finals:
        if not temporary_present:
            return []
        _validate_unpublished_prefix(
            temporary, f"unpublished {label} temporary", expected_candidates
        )
        return [temporary]
    final = present_finals[0]
    metadata = final.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != 0o400:
        raise RecoveryError(f"{label} mode drift")
    final_metadata, raw = read_exact_file(
        final,
        label,
        max(len(candidate) for candidate in expected_candidates),
        allowed_links={1, 2},
        exact_mode=0o400,
    )
    if raw not in expected_candidates:
        raise RecoveryError(f"{label} claims drift")
    if final_metadata.st_nlink == 1:
        if temporary_present:
            raise RecoveryError(f"unexpected {label} publication temporary")
        return [final]
    if not temporary_present:
        raise RecoveryError(f"{label} has an unexplained hardlink")
    temporary_metadata, temporary_raw = read_exact_file(
        temporary,
        f"{label} publication temporary",
        len(raw),
        allowed_links={2},
        exact_mode=0o400,
    )
    if (
        temporary_metadata.st_dev != final_metadata.st_dev
        or temporary_metadata.st_ino != final_metadata.st_ino
        or temporary_raw != raw
    ):
        raise RecoveryError(f"{label} publication identity drift")
    return [final, temporary]


def _validate_runtime_identity(marker: dict[str, object]) -> Path | None:
    session = marker["session"]
    assert isinstance(session, str)
    path = RUNTIME_IDENTITY_ROOT / f"{session}.json"
    if not _is_present(path):
        return None
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in {0o400, 0o600}:
        raise RecoveryError("runtime identity mode drift")
    expected = compact_canonical(expected_runtime_identity(marker))
    _, raw = read_exact_file(
        path,
        "runtime identity",
        len(expected),
        exact_mode=mode,
        allow_empty=True,
    )
    # The legacy writer creates this deterministic target and writes forwards.
    # A strict prefix is its only legitimate SIGKILL publication cutpoint.
    if not expected.startswith(raw):
        raise RecoveryError("runtime identity claims drift")
    return path


def _validate_graphical_restoration_artifacts(
    marker: dict[str, object],
) -> Path | None:
    main_present = _is_present(GRAPHICAL_RESTORATION)
    temporary_present = _is_present(GRAPHICAL_RESTORATION_TEMP)
    if not main_present and not temporary_present:
        return None
    if marker.get("mode") != "campaign":
        raise RecoveryError("graphical restoration state exists for probe authority")
    expected = compact_canonical(expected_graphical_restoration(marker))
    if not main_present:
        temporary, raw = read_exact_file(
            GRAPHICAL_RESTORATION_TEMP,
            "unpublished graphical restoration temporary",
            len(expected),
            allowed_links={1},
            exact_mode=0o400,
            allow_empty=True,
        )
        del temporary
        if not expected.startswith(raw):
            raise RecoveryError("graphical restoration temporary claims drift")
        return GRAPHICAL_RESTORATION_TEMP
    main, raw = read_exact_file(
        GRAPHICAL_RESTORATION,
        "graphical restoration state",
        len(expected),
        allowed_links={1, 2},
        exact_mode=0o400,
    )
    if raw != expected:
        raise RecoveryError("graphical restoration state claims drift")
    if main.st_nlink == 1:
        if temporary_present:
            raise RecoveryError("unexpected graphical restoration temporary")
        return None
    if not temporary_present:
        raise RecoveryError("graphical restoration state has unexplained hardlink")
    temporary, temporary_raw = read_exact_file(
        GRAPHICAL_RESTORATION_TEMP,
        "graphical restoration publication temporary",
        len(expected),
        allowed_links={2},
        exact_mode=0o400,
    )
    if (
        temporary.st_dev != main.st_dev
        or temporary.st_ino != main.st_ino
        or temporary_raw != raw
    ):
        raise RecoveryError("graphical restoration publication identity drift")
    return GRAPHICAL_RESTORATION_TEMP


def _validate_runtime_artifacts(marker: dict[str, object]) -> list[Path]:
    session = marker["session"]
    mode = marker["mode"]
    nonce = marker["session_nonce"]
    assert isinstance(session, str) and isinstance(mode, str) and isinstance(nonce, str)
    removable: list[Path] = []
    removable.extend(
        _validate_atomic_publication(
            [RUNTIME_ROOT / "session-name"],
            RUNTIME_ROOT / ".session-name.tmp",
            "session name",
            (f"{session}\n".encode("ascii"),),
        )
    )
    removable.extend(
        _validate_atomic_publication(
            [RUNTIME_ROOT / "guided-handoff.json"],
            RUNTIME_ROOT / ".guided-handoff.json.tmp",
            "guided handoff",
            (compact_canonical(expected_handoff(marker)),),
        )
    )
    decision_paths: list[Path] = []
    public_decision = RUNTIME_ROOT / "guided-decision.json"
    if _is_present(public_decision):
        decision_paths.append(public_decision)
    consumed_decision = re.compile(r"[.]guided-decision[.]consumed[.][1-9][0-9]*")
    decision_paths.extend(
        child
        for child in RUNTIME_ROOT.iterdir()
        if consumed_decision.fullmatch(child.name) is not None
    )
    removable.extend(
        _validate_atomic_publication(
            decision_paths,
            RUNTIME_ROOT / ".guided-decision.json.tmp",
            "guided decision",
            tuple(
                compact_canonical(expected_guided_decision(marker, action))
                for action in ("accept", "cancel")
            ),
        )
    )
    cid_kinds = {".preflight.cid": "preflight"}
    if mode == "campaign":
        cid_kinds.update({".cid": "campaign", ".verifier.cid": "verifier"})
    for suffix in cid_kinds:
        path = RUNTIME_ROOT / f"{session}{suffix}"
        if not _is_present(path):
            continue
        metadata = path.lstat()
        mode_bits = stat.S_IMODE(metadata.st_mode)
        if mode_bits not in {0o400, 0o600}:
            raise RecoveryError(f"container ID file mode drift: {path.name}")
        _, raw = read_exact_file(
            path,
            "container ID file",
            65,
            exact_mode=mode_bits,
            allow_empty=True,
        )
        try:
            text = raw.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise RecoveryError("container ID file claims drift") from error
        complete = text.endswith("\n")
        candidate = text.removesuffix("\n") if complete else text
        if (
            len(candidate) > 64
            or re.fullmatch(r"[0-9a-f]*", candidate) is None
            or (complete and len(candidate) != 64)
        ):
            raise RecoveryError("container ID file claims drift")
        removable.append(path)
    stderr_path = RUNTIME_ROOT / f"{session}.verifier.stderr"
    if _is_present(stderr_path):
        metadata = stderr_path.lstat()
        mode_bits = stat.S_IMODE(metadata.st_mode)
        if mode_bits not in {0o400, 0o600}:
            raise RecoveryError("verifier stderr mode drift")
        read_exact_file(
            stderr_path,
            "verifier stderr",
            MAX_RUNTIME_FILE_BYTES,
            exact_mode=mode_bits,
            allow_empty=True,
        )
        removable.append(stderr_path)
    request_name = "campaign.request" if mode == "campaign" else "probe-only.request"
    request_path = RUNTIME_ROOT / request_name
    if _is_present(request_path):
        _, raw = read_exact_file(
            request_path, "launch request", 1024, exact_mode=0o600
        )
        request = _load_json(raw, "launch request")
        if compact_canonical(request) != raw or request.get("nonce") != nonce:
            raise RecoveryError("launch request claims drift")
        if mode == "campaign":
            required = {"mode", "nonce", "schema", "target_uid", "target_user"}
            valid = (
                set(request) == required
                and request.get("mode") == "campaign"
                and request.get("schema") == CAMPAIGN_REQUEST_SCHEMA
                and isinstance(request.get("target_user"), str)
                and re.fullmatch(
                    r"[a-z_][a-z0-9_-]{0,31}", request["target_user"]
                )
                is not None
                and not isinstance(request.get("target_uid"), bool)
                and isinstance(request.get("target_uid"), int)
                and request["target_uid"] > 0
            )
        else:
            valid = (
                set(request) == {"mode", "nonce", "schema"}
                and request.get("mode") == "probe-only"
                and request.get("schema") == PROBE_REQUEST_SCHEMA
            )
        if not valid:
            raise RecoveryError("launch request claims drift")
        removable.append(request_path)
    consumed_pattern = (
        re.compile(r"[.]campaign[.]consumed[.][1-9][0-9]*")
        if mode == "campaign"
        else re.compile(r"[.]probe-only[.]consumed[.][1-9][0-9]*")
    )
    consumed = [
        child
        for child in RUNTIME_ROOT.iterdir()
        if consumed_pattern.fullmatch(child.name) is not None
    ]
    if len(consumed) > 1:
        raise RecoveryError("multiple consumed launch requests exist")
    if consumed and _is_present(request_path):
        raise RecoveryError("public and consumed launch requests overlap")
    if consumed:
        _, raw = read_exact_file(
            consumed[0], "consumed launch request", 1024, exact_mode=0o600
        )
        request = _load_json(raw, "consumed launch request")
        if compact_canonical(request) != raw or request.get("nonce") != nonce:
            raise RecoveryError("consumed launch request claims drift")
        if mode == "campaign":
            valid_consumed = (
                set(request)
                == {"mode", "nonce", "schema", "target_uid", "target_user"}
                and request.get("mode") == "campaign"
                and request.get("schema") == CAMPAIGN_REQUEST_SCHEMA
                and isinstance(request.get("target_user"), str)
                and re.fullmatch(
                    r"[a-z_][a-z0-9_-]{0,31}", request["target_user"]
                )
                is not None
                and not isinstance(request.get("target_uid"), bool)
                and isinstance(request.get("target_uid"), int)
                and request["target_uid"] > 0
            )
        else:
            valid_consumed = (
                set(request) == {"mode", "nonce", "schema"}
                and request.get("mode") == "probe-only"
                and request.get("schema") == PROBE_REQUEST_SCHEMA
            )
        if not valid_consumed:
            raise RecoveryError("consumed launch request claims drift")
        removable.append(consumed[0])
    allowed = {
        RUNTIME_ROOT / "stability.lock",
        PODMAN_RUNROOT,
        *removable,
    }
    if mode == "probe-only":
        allowed.add(RUNTIME_ROOT / session)
    for child in RUNTIME_ROOT.iterdir():
        if child not in allowed:
            raise RecoveryError(
                f"runtime artifact exists without authority: {child.name}"
            )
    return removable


def _validate_complete_cid_bindings(
    marker: dict[str, object], owned_containers: Sequence[tuple[str, str]]
) -> None:
    session = marker["session"]
    mode = marker["mode"]
    assert isinstance(session, str) and isinstance(mode, str)
    suffix_kinds = {".preflight.cid": "preflight"}
    if mode == "campaign":
        suffix_kinds.update({".cid": "campaign", ".verifier.cid": "verifier"})
    owned_by_kind = {kind: identifier for identifier, kind in owned_containers}
    owned_by_id = {identifier: kind for identifier, kind in owned_containers}
    for suffix, kind in suffix_kinds.items():
        path = RUNTIME_ROOT / f"{session}{suffix}"
        if not _is_present(path):
            continue
        metadata = path.lstat()
        mode_bits = stat.S_IMODE(metadata.st_mode)
        _, raw = read_exact_file(
            path,
            "container ID file",
            65,
            exact_mode=mode_bits,
            allow_empty=True,
        )
        if not raw.endswith(b"\n"):
            candidate = raw.decode("ascii", errors="strict")
            if candidate:
                expected_identifier = owned_by_kind.get(kind)
                if (
                    expected_identifier is not None
                    and not expected_identifier.startswith(candidate)
                ) or any(
                    observed_kind != kind and identifier.startswith(candidate)
                    for identifier, observed_kind in owned_containers
                ):
                    raise RecoveryError(
                        "partial container ID differs from owned container"
                    )
            continue
        identifier = raw[:-1].decode("ascii", errors="strict")
        if (
            owned_by_kind.get(kind) != identifier
            or owned_by_id.get(identifier) != kind
        ):
            raise RecoveryError("container ID file differs from owned container")


def _unlink_owned_cidfiles(marker: dict[str, object]) -> None:
    kinds = ["preflight"]
    if marker.get("mode") == "campaign":
        kinds.extend(("campaign", "verifier"))
    for kind in kinds:
        path = expected_container_cidfile(marker, kind)
        if _is_present(path):
            _unlink_exact(path)


def _mount_targets() -> tuple[Path, ...]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8", errors="strict"
        ).splitlines()
    except OSError as error:
        raise RecoveryError(f"cannot inspect mount topology: {error}") from error
    targets: list[Path] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            raise RecoveryError("mount topology record is malformed")
        value = fields[4]
        for escaped, raw in (
            ("\\040", " "),
            ("\\011", "\t"),
            ("\\012", "\n"),
            ("\\134", "\\"),
        ):
            value = value.replace(escaped, raw)
        targets.append(Path(value))
    return tuple(targets)


def _require_unmounted_tree(path: Path) -> None:
    absolute = path.absolute()
    for target in _mount_targets():
        if target == absolute or absolute in target.parents:
            raise RecoveryError(f"owned runtime tree contains mountpoint {target}")


def _remove_directory_contents_fd(descriptor: int, expected_device: int) -> None:
    for name in os.listdir(descriptor):
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if metadata.st_dev != expected_device:
            raise RecoveryError("owned runtime tree crosses a filesystem boundary")
        if stat.S_ISDIR(metadata.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            flags |= getattr(os, "O_NOFOLLOW", 0)
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                    raise RecoveryError("owned runtime directory identity changed")
                _remove_directory_contents_fd(child, expected_device)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


def _remove_owned_tree(path: Path, parent: Path, label: str) -> None:
    if not _is_present(path):
        return
    require_exact_directory(parent, f"{label} parent", mode=0o700)
    if path.parent != parent or path.name in {"", ".", ".."}:
        raise RecoveryError(f"{label} path escaped its fixed parent")
    parent_metadata = parent.lstat()
    metadata = require_exact_directory(path, label, mode=0o700)
    if metadata.st_dev != parent_metadata.st_dev:
        raise RecoveryError(f"{label} is a separate filesystem")
    _require_unmounted_tree(path)
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    parent_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(parent, parent_flags)
    try:
        opened_parent = os.fstat(parent_fd)
        if (
            opened_parent.st_dev != parent_metadata.st_dev
            or opened_parent.st_ino != parent_metadata.st_ino
        ):
            raise RecoveryError(f"{label} parent identity changed while opening")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                raise RecoveryError(f"{label} identity changed while opening")
            _remove_directory_contents_fd(descriptor, metadata.st_dev)
        finally:
            os.close(descriptor)
        os.rmdir(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _clear_owned_directory(path: Path, label: str) -> None:
    if not _is_present(path):
        return
    metadata = require_exact_directory(path, label, mode=0o700)
    _require_unmounted_tree(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise RecoveryError(f"{label} identity changed while opening")
        _remove_directory_contents_fd(descriptor, metadata.st_dev)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_fixed_child_inventory(
    root: Path, allowed_names: set[str], label: str
) -> None:
    if not _is_present(root):
        return
    require_exact_directory(root, label, mode=0o700)
    for child in root.iterdir():
        if child.name not in allowed_names:
            raise RecoveryError(
                f"{label} contains state without authority: {child.name}"
            )


def _validate_owned_state(marker: dict[str, object]) -> tuple[Path | None, list[Path]]:
    session = marker["session"]
    assert isinstance(session, str)
    _validate_fixed_child_inventory(
        CONTAINER_RUNTIME_ROOT, {session}, "container runtime root"
    )
    _validate_fixed_child_inventory(
        RUNTIME_IDENTITY_ROOT,
        {f"{session}.json"},
        "runtime identity root",
    )
    runtime_path = CONTAINER_RUNTIME_ROOT / session
    if _is_present(runtime_path):
        require_exact_directory(
            CONTAINER_RUNTIME_ROOT, "container runtime root", mode=0o700
        )
        require_exact_directory(runtime_path, "session runtime", mode=0o700)
    identity = _validate_runtime_identity(marker)
    runtime_files = _validate_runtime_artifacts(marker)
    graphical_temporary = _validate_graphical_restoration_artifacts(marker)
    if graphical_temporary is not None:
        runtime_files.append(graphical_temporary)
    return identity, runtime_files


def recover_cgroup_authority(
    owned_containers: Sequence[tuple[str, str]] = (),
) -> None:
    command = [os.fspath(CGROUP_AUTHORITY), "recover"]
    for identifier, _kind in owned_containers:
        if CONTAINER_ID.fullmatch(identifier) is None:
            raise RecoveryError("cgroup recovery container identity is malformed")
        command.extend(("--container-id", identifier))
    completed = subprocess.run(
        command,
        capture_output=True,
        text=False,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or b"").decode(
            "utf-8", errors="replace"
        ).strip()
        raise RecoveryError(
            f"cgroup authority recovery failed ({completed.returncode}): {detail}"
        )


def check_clean_cgroup_authority() -> None:
    completed = subprocess.run(
        [os.fspath(CGROUP_AUTHORITY), "check-clean"],
        capture_output=True,
        text=False,
        check=False,
    )
    expected_stdout = (
        b"CODESKEPTIC_P10_09_CGROUP_AUTHORITY_OK "
        b"action=check-clean result=clean\n"
    )
    if completed.returncode != 0 or completed.stdout != expected_stdout or completed.stderr:
        detail = (completed.stderr or b"").decode(
            "utf-8", errors="replace"
        ).strip()
        raise RecoveryError(
            "cgroup clean-state verification failed "
            f"({completed.returncode})" + (f": {detail}" if detail else "")
        )


def _unlink_exact(path: Path) -> None:
    path.unlink()
    fsync_directory(path.parent)


def _remove_marker() -> None:
    if _is_present(MARKER_TEMP):
        raise RecoveryError("host recovery marker temporary survived repair")
    _unlink_exact(MARKER)


def _validate_bound_recovery_state(
    marker: dict[str, object],
    *,
    allow_unpublished_cgroup: bool = False,
) -> tuple[Path | None, list[Path], list[tuple[str, str]], bool]:
    if _is_present(PODMAN_INSPECTION_MARKER) or _is_present(
        PODMAN_INSPECTION_MARKER_TEMP
    ):
        raise RecoveryError("Podman inspection authority overlaps a host session")
    identity, runtime_files = _validate_owned_state(marker)
    lifecycles: dict[str, str] = {}
    owned_containers = _owned_container_inventory(marker, lifecycles)
    _validate_complete_cid_bindings(marker, owned_containers)
    if len(owned_containers) > 1:
        raise RecoveryError("multiple owned containers overlap one host session")
    validate_cgroup_session_binding(marker)
    # First bind a live container to the exact active cgroup state.  Remove it
    # before cgroup recovery so a root container cannot race recovery writes.
    # The second, container-free recovery call re-reads the entire crash-cut
    # tuple before the cgroup authority's first control write or rmdir.
    if owned_containers:
        identifier, kind = owned_containers[0]
        if lifecycles.get(identifier) == "running":
            verify_active_cgroup_authority(marker, owned_containers)
        elif lifecycles.get(identifier) == "initialized":
            verify_active_cgroup_authority(marker, owned_containers)
        elif lifecycles.get(identifier) == "stopping":
            if _is_present(expected_container_cidfile(marker, kind)):
                raise RecoveryError(
                    "stopping container precedes the durable CID-first cutpoint"
                )
            verify_active_cgroup_authority(marker, owned_containers)
        elif lifecycles.get(identifier) == "stopped":
            verify_recovery_cgroup_authority(marker, owned_containers)
        elif lifecycles.get(identifier) == "removing":
            if _is_present(expected_container_cidfile(marker, kind)):
                raise RecoveryError(
                    "removing container precedes the durable CID-first cutpoint"
                )
            verify_recovery_cgroup_authority(marker, owned_containers)
        else:
            raise RecoveryError("owned container lifecycle binding drift")
    elif _is_present(CGROUP_MARKER):
        if _is_present(CGROUP_MARKER_TEMP):
            raise RecoveryError(
                "cgroup authority publication overlaps host marker repair"
            )
        verify_recovery_cgroup_authority(marker, [])
    elif _is_present(CGROUP_MARKER_TEMP):
        if not allow_unpublished_cgroup:
            raise RecoveryError(
                "unpublished cgroup authority overlaps host marker repair"
            )
        return identity, runtime_files, owned_containers, True
    else:
        check_clean_cgroup_authority()
    return identity, runtime_files, owned_containers, False


def _recover_bound(marker: dict[str, object]) -> str:
    # Marker publication repair is itself a filesystem mutation.  First bind
    # the unrepaired inode to every runtime, Podman, lifecycle, and cgroup
    # claim; repair; then repeat the complete read-only gate.
    host_marker_published = _is_present(MARKER)
    _identity, _runtime_files, _owned_containers, unpublished_cgroup = (
        _validate_bound_recovery_state(
            marker,
            allow_unpublished_cgroup=host_marker_published,
        )
    )
    if unpublished_cgroup:
        published = _discover_marker(repair=False)
        if not _is_present(MARKER) or published != marker:
            raise RecoveryError(
                "host authority changed before cgroup publication recovery"
            )
        # cgroup-authority independently proves the clean startup tuple and
        # accepts only its own canonical strict-prefix publication cutpoint.
        recover_cgroup_authority()
        _validate_bound_recovery_state(marker)
    repaired = _discover_marker(repair=True)
    if repaired != marker:
        raise RecoveryError("host recovery marker changed during repair")
    identity, runtime_files, owned_containers, _unpublished_cgroup = (
        _validate_bound_recovery_state(repaired)
    )
    marker = repaired
    # CID-first makes every interruption unambiguous: a surviving container
    # can be rediscovered from its exact store projection, while a complete
    # CID can never outlive the container it names.
    _unlink_owned_cidfiles(marker)
    for identifier, _kind in owned_containers:
        run_podman(("rm", "--force", "--ignore", "--", identifier))
    if _podman_ids():
        raise RecoveryError("Podman containers survived bounded recovery")
    _verify_pinned_image_store()
    recover_cgroup_authority()
    session = marker["session"]
    mode = marker["mode"]
    assert isinstance(session, str) and isinstance(mode, str)
    runtime_path = CONTAINER_RUNTIME_ROOT / session
    if _is_present(runtime_path):
        _remove_owned_tree(runtime_path, CONTAINER_RUNTIME_ROOT, "session runtime")
    if identity is not None:
        _validate_runtime_identity(marker)
        _unlink_exact(identity)
    # The normal runner may already have removed these durable objects.  Fsync
    # both fixed parents even when their children are absent so a power loss
    # cannot make the marker deletion durable while resurrecting a prior
    # runtime tree or identity entry.
    for durable_parent, label in (
        (CONTAINER_RUNTIME_ROOT, "container runtime root"),
        (RUNTIME_IDENTITY_ROOT, "runtime identity root"),
    ):
        if _is_present(durable_parent):
            require_exact_directory(durable_parent, label, mode=0o700)
            fsync_directory(durable_parent)
    if mode == "probe-only":
        probe_path = RUNTIME_ROOT / session
        if _is_present(probe_path):
            _remove_owned_tree(probe_path, RUNTIME_ROOT, "probe runtime")
    for path in runtime_files:
        if _is_present(path):
            _unlink_exact(path)
    _clear_owned_directory(PODMAN_RUNROOT, "Podman runroot")
    # Marker-last is a hard gate: unrelated runtime/identity state can never
    # be hidden by a seemingly successful terminal cleanup.
    _validate_terminal_filesystem_clean()
    _remove_marker()
    return "recovered"


def _recover_without_host_marker() -> str:
    _repair_unpublished_request_temporaries()
    inspection = _discover_podman_inspection_marker(repair=True)
    if inspection is None:
        _validate_unbound_filesystem_clean()
        _create_podman_inspection_marker(expected_podman_inspection_marker())
        inspection = _discover_podman_inspection_marker(repair=True)
        if inspection is None:
            raise RecoveryError("Podman inspection authority publication failed")
    else:
        _validate_unbound_filesystem_clean(allow_podman_runroot_state=True)
    identifiers = _podman_ids()
    if identifiers:
        raise RecoveryError("Podman containers exist without host authority")
    _verify_pinned_image_store()
    recover_cgroup_authority()
    _clear_owned_directory(PODMAN_RUNROOT, "Podman runroot")
    _validate_unbound_filesystem_clean()
    _unlink_exact(PODMAN_INSPECTION_MARKER)
    return "already-clean"


def recover() -> str:
    require_root_caller()
    require_state_root()
    try:
        marker = _discover_marker(repair=False)
    except RecoveryError:
        if _is_present(MARKER) or not _is_present(MARKER_TEMP):
            raise
        metadata, raw = _read_unpublished_host_marker_prefix()
        if not is_strict_unpublished_host_marker_prefix(raw):
            raise
        if _is_present(PODMAN_INSPECTION_MARKER) or _is_present(
            PODMAN_INSPECTION_MARKER_TEMP
        ):
            raise RecoveryError(
                "unpublished host marker overlaps Podman inspection authority"
            )
        _validate_unbound_filesystem_clean()
        check_clean_cgroup_authority()
        _discard_unpublished_host_marker_prefix(metadata, raw)
        return _recover_without_host_marker()
    if marker is None:
        return _recover_without_host_marker()
    return _recover_bound(marker)


def cleanup(session: str) -> str:
    marker = read_marker(session)
    return _recover_bound(marker)


def snapshot(session: str) -> Path:
    marker = read_marker(session)
    if marker["mode"] != "campaign":
        raise RecoveryError("probe recovery intents are not accepted evidence")
    destination = SESSION_ROOT / session / "host" / "host-recovery-intent.json"
    require_exact_directory(destination.parent, "host evidence root", mode=0o700)
    raw = compact_canonical(marker)
    if _is_present(destination):
        _, existing = read_exact_file(
            destination, "host recovery evidence", MAX_MARKER_BYTES
        )
        if existing != raw:
            raise RecoveryError("host recovery evidence identity drift")
        return destination
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o400)
    try:
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise RecoveryError("short host recovery evidence write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(destination.parent)
    return destination


def marker_sha256(session: str) -> str:
    marker = read_marker(session)
    return hashlib.sha256(compact_canonical(marker)).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    arm_parser = subparsers.add_parser("arm")
    arm_parser.add_argument("--mode", choices=("campaign", "probe-only"), required=True)
    arm_parser.add_argument("--session", required=True)
    verify_parser = subparsers.add_parser("verify-active")
    verify_parser.add_argument("--session", required=True)
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--session", required=True)
    subparsers.add_parser("recover")
    subparsers.add_parser("discard-unbound-launch-requests")
    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--session", required=True)
    labels_parser = subparsers.add_parser("labels")
    labels_parser.add_argument("--session", required=True)
    labels_parser.add_argument(
        "--kind", choices=("preflight", "campaign", "verifier"), required=True
    )
    remove_parser = subparsers.add_parser("remove-owned-container")
    remove_parser.add_argument("--session", required=True)
    remove_parser.add_argument(
        "--kind", choices=("preflight", "campaign", "verifier"), required=True
    )
    guided_lock_parser = subparsers.add_parser("lock-guided")
    guided_lock_parser.add_argument(
        "--mode", choices=("campaign", "probe-only"), required=True
    )
    validate_lock_parser = subparsers.add_parser("validate-guided-lock")
    validate_lock_parser.add_argument("--fd", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "arm":
            outcome = arm(arguments.mode, arguments.session)
        elif arguments.command == "verify-active":
            read_marker(arguments.session)
            outcome = "active"
        elif arguments.command == "cleanup":
            outcome = cleanup(arguments.session)
        elif arguments.command == "recover":
            outcome = recover()
        elif arguments.command == "discard-unbound-launch-requests":
            outcome = discard_unbound_launch_requests()
        elif arguments.command == "snapshot":
            outcome = os.fspath(snapshot(arguments.session))
        elif arguments.command == "labels":
            marker = read_marker(
                arguments.session, verify_filesystem=False
            )
            labels = expected_container_labels(marker, arguments.kind)
            outcome = "\n".join(f"{key}={labels[key]}" for key in sorted(labels))
        elif arguments.command == "remove-owned-container":
            outcome = remove_owned_container(arguments.session, arguments.kind)
        elif arguments.command == "lock-guided":
            exec_guided_under_lifecycle_lock(arguments.mode)
            raise AssertionError("guided lifecycle exec unexpectedly returned")
        elif arguments.command == "validate-guided-lock":
            outcome = validate_guided_lifecycle_lock(arguments.fd)
        else:  # pragma: no cover - argparse owns command exhaustiveness.
            parser.error("unknown command")
        print(outcome)
        return 0
    except (OSError, RecoveryError) as error:
        print(f"HOST_RECOVERY_FAIL {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
