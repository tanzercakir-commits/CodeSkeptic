#!/usr/bin/env python3
"""Import one sealed calibration as an immutable review projection.

This consumer deliberately never writes into the source repository.  A trusted
operator bundle and its out-of-band SHA256SUMS identity are required so the
producer and controller seals can be replayed before any projection is
published.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import NoReturn


SCHEMA = "codeskeptic-determinism-calibration-import-v1"
SESSION_SCHEMA = "codeskeptic-p10-09-candidate-controller-session-v3"
PRODUCER_SCHEMA = "codeskeptic-p10-09-candidate-session-v3"
CALIBRATION_SCHEMA = "codeskeptic-determinism-calibration-v7"
REJECTION_SCHEMA = "codeskeptic-determinism-rejected-v7"
BASELINE_SCHEMA = "codeskeptic-determinism-baseline-v7"
SESSION_NAME = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{7}")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MANIFEST_LINE = re.compile(rb"([0-9a-f]{64})  ([^\r\n]+)\n")
EVIDENCE_PREFIX = PurePosixPath(
    "docs/evidence/phase10/determinism/calibrations"
)
OPERATOR_SCRIPTS = (
    "controller-seal.py",
    "session-seal.py",
    "verify-candidate.py",
)
CONTROLLER_TOP = frozenset({
    "producer",
    "independent-verifier.log",
    "independent-verifier-exit-code.txt",
    "independent-verifier-container.json",
    "controller-cleanup.json",
    "receipt.json",
    "receipt.json.sha256",
    "SHA256SUMS",
})
PRODUCER_TOP = frozenset({
    "calibration",
    "qualification-rejection",
    "determinism-baseline.candidate.json",
    "qualification-exit-code.txt",
    "qualification.log",
    "calibration-verify.log",
    "rejection-verify.log",
    "candidate-verify.log",
    "build-authority-verify.log",
    "build-authority-preflight.log",
    "cgroup-authority-intent.json",
    "cgroup-authority-intent.json.sha256",
    "cgroup-smoke.json",
    "cgroup-smoke.json.sha256",
    "systemd-probe-run.json",
    "systemd-probe-run.json.sha256",
    "systemd-probe-post-stop.json",
    "systemd-probe-post-stop.json.sha256",
    "receipt.json",
    "receipt.json.sha256",
    "SHA256SUMS",
})
CONTROLLER_RECEIPT_FIELDS = frozenset({
    "schema", "status", "source_revision", "producer_receipt_sha256",
    "producer_manifest_sha256", "independent_verifier_log_sha256",
    "independent_verifier_container_sha256", "controller_cleanup_sha256",
    "cgroup_authority_intent_sha256", "cgroup_smoke_sha256",
    "systemd_probe_run_sha256", "systemd_probe_post_stop_sha256",
    "verification",
})
PRODUCER_RECEIPT_FIELDS = frozenset({
    "schema", "status", "source_revision", "calibration_evidence_path",
    "inner_qualification_exit_code", "candidate_baseline_sha256",
    "calibration_receipt_sha256", "rejection_receipt_sha256",
    "cgroup_authority_intent_sha256", "cgroup_smoke_sha256",
    "systemd_probe_run_sha256", "systemd_probe_post_stop_sha256",
    "verification",
})
RECEIPT_FIELDS = frozenset({
    "schema", "status", "base_revision", "base_tree_oid",
    "calibration_evidence_path",
    "candidate_baseline_sha256", "previous_baseline_sha256",
    "calibration_receipt_sha256", "calibration_manifest_sha256",
    "source_session", "trusted_operator", "verification",
})


class CalibrationImportError(RuntimeError):
    """A controlled fail-closed import failure."""


def fail(message: str) -> NoReturn:
    raise CalibrationImportError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def qualification_canonical(value: object) -> bytes:
    """Canonical form emitted by run_determinism_qualification.py."""

    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"cannot hash non-regular file: {path}")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def real_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        metadata = absolute.lstat()
    except FileNotFoundError as error:
        raise CalibrationImportError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} is not a real directory")
    if absolute.resolve(strict=True) != absolute:
        fail(f"{label} traverses a symbolic link")
    return absolute


def relative_path(value: object, label: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        fail(f"{label} is malformed")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{label} is malformed")
    return path


def tree_inventory(root: Path, label: str) -> tuple[list[str], list[str]]:
    directories: list[str] = []
    files: list[str] = []

    def walk_error(error: OSError) -> NoReturn:
        raise error

    for directory, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=walk_error
    ):
        current = Path(directory)
        if not stat.S_ISDIR(current.lstat().st_mode):
            fail(f"{label} traversal reached a non-directory")
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            path = current / name
            relative = path.relative_to(root).as_posix()
            if not stat.S_ISDIR(path.lstat().st_mode):
                fail(f"{label} contains a non-directory tree entry: {relative}")
            directories.append(relative)
        for name in file_names:
            path = current / name
            relative = path.relative_to(root).as_posix()
            if not stat.S_ISREG(path.lstat().st_mode):
                fail(f"{label} contains a non-regular file: {relative}")
            files.append(relative)
    return sorted(directories), sorted(files)


def verify_frozen_tree(
    root: Path, label: str, *, executable_suffixes: frozenset[str] = frozenset()
) -> tuple[list[str], list[str]]:
    directories, files = tree_inventory(root, label)
    root_metadata = root.lstat()
    owner = (root_metadata.st_uid, root_metadata.st_gid)
    if stat.S_IMODE(root_metadata.st_mode) != 0o555:
        fail(f"{label} root mode drift")
    for relative in directories:
        metadata = (root / relative).lstat()
        if (metadata.st_uid, metadata.st_gid) != owner:
            fail(f"{label} owner drift: {relative}")
        if stat.S_IMODE(metadata.st_mode) != 0o555:
            fail(f"{label} directory mode drift: {relative}")
    for relative in files:
        metadata = (root / relative).lstat()
        if (metadata.st_uid, metadata.st_gid) != owner:
            fail(f"{label} owner drift: {relative}")
        expected = 0o555 if Path(relative).suffix in executable_suffixes else 0o444
        if stat.S_IMODE(metadata.st_mode) != expected:
            fail(f"{label} file mode drift: {relative}")
    return directories, files


def read_canonical(
    path: Path, label: str, *, qualification: bool = False
) -> tuple[dict[str, object], bytes]:
    if not stat.S_ISREG(path.lstat().st_mode):
        fail(f"{label} is not a regular file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CalibrationImportError(f"{label} is malformed") from error
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    expected = qualification_canonical(value) if qualification else canonical(value)
    if raw != expected:
        fail(f"{label} is not canonical")
    return value, raw


def read_canonical_bytes(
    raw: bytes, label: str, *, qualification: bool = False
) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CalibrationImportError(f"{label} is malformed") from error
    expected = qualification_canonical(value) if qualification else canonical(value)
    if not isinstance(value, dict) or raw != expected:
        fail(f"{label} is not canonical")
    return value


def verify_sidecar(root: Path, label: str) -> None:
    raw = (root / "receipt.json").read_bytes()
    expected = f"{sha256_bytes(raw)}  receipt.json\n".encode("ascii")
    if (root / "receipt.json.sha256").read_bytes() != expected:
        fail(f"{label} receipt sidecar drift")


def verify_manifest(
    root: Path, label: str, *, qualification_receipt: bool = False
) -> tuple[list[str], str]:
    _, files = tree_inventory(root, label)
    if "SHA256SUMS" not in files:
        fail(f"{label} SHA256SUMS is missing")
    raw = (root / "SHA256SUMS").read_bytes()
    position = 0
    recorded: list[str] = []
    while position < len(raw):
        match = MANIFEST_LINE.match(raw, position)
        if match is None:
            fail(f"{label} SHA256SUMS is malformed")
        try:
            relative = match.group(2).decode("utf-8")
        except UnicodeDecodeError as error:
            raise CalibrationImportError(f"{label} manifest path is not UTF-8") from error
        parsed = relative_path(relative, f"{label} manifest path")
        if parsed.as_posix() == "SHA256SUMS":
            fail(f"{label} manifest contains itself")
        if match.group(1).decode("ascii") != digest(root / parsed.as_posix()):
            fail(f"{label} checksum drift: {relative}")
        recorded.append(relative)
        position = match.end()
    expected = sorted(relative for relative in files if relative != "SHA256SUMS")
    if qualification_receipt:
        receipt_files = ["receipt.json", "receipt.json.sha256"]
        if not set(receipt_files) <= set(expected):
            fail(f"{label} receipt inventory is incomplete")
        expected = receipt_files + [
            relative for relative in expected if relative not in receipt_files
        ]
    if recorded != expected or len(recorded) != len(set(recorded)):
        fail(f"{label} manifest inventory drift")
    expected_raw = b"".join(
        f"{digest(root / relative)}  {relative}\n".encode("utf-8")
        for relative in expected
    )
    if raw != expected_raw:
        fail(f"{label} SHA256SUMS canonical drift")
    return expected, sha256_bytes(raw)


def verify_operator(bundle: Path, expected_manifest_sha: str) -> dict[str, str]:
    if HEX64.fullmatch(expected_manifest_sha) is None:
        fail("operator manifest identity is malformed")
    _, files = verify_frozen_tree(
        bundle, "operator bundle", executable_suffixes=frozenset({".py", ".sh"})
    )
    if digest(bundle / "SHA256SUMS") != expected_manifest_sha:
        fail("operator manifest identity drift")
    recorded, _ = verify_manifest(bundle, "operator bundle")
    if set(files) != set(recorded) | {"SHA256SUMS"}:
        fail("operator inventory drift")
    missing = set(OPERATOR_SCRIPTS) - set(recorded)
    if missing:
        fail(f"operator verifier inventory is incomplete: {sorted(missing)}")
    return {name: digest(bundle / name) for name in OPERATOR_SCRIPTS}


def run_checked(
    command: list[str], marker: str, label: str,
    environment: dict[str, str],
) -> None:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env=environment,
    )
    output = completed.stdout.splitlines()
    if completed.returncode != 0 or not output or marker.encode("ascii") not in output[-1]:
        raise CalibrationImportError(
            f"{label} failed ({completed.returncode}): {completed.stdout[-2000:]!r}"
        )


def isolated_git_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    config = root / "config"
    home.mkdir(mode=0o700)
    config.mkdir(mode=0o700)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.fspath(home),
        "XDG_CONFIG_HOME": os.fspath(config),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "file",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }


def isolated_git(
    arguments: list[str], environment: dict[str, str], label: str,
    *, expected: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["/usr/bin/git", "--no-optional-locks", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )
    if completed.returncode not in expected:
        raise CalibrationImportError(
            f"{label} failed ({completed.returncode}): "
            f"{completed.stderr[-1000:]!r}"
        )
    return completed


def verify_checkout_inventory(
    checkout: Path, environment: dict[str, str]
) -> None:
    status = isolated_git(
        [
            "-C", os.fspath(checkout), "status", "--porcelain=v1",
            "--ignored=matching", "--untracked-files=all",
        ],
        environment,
        "exact-base source status",
    ).stdout
    if status:
        fail(f"exact-base source is not clean: {status[-1000:]!r}")
    staged = isolated_git(
        ["-C", os.fspath(checkout), "ls-files", "--stage", "-z"],
        environment,
        "exact-base source index read",
    ).stdout
    tracked: dict[str, bool] = {}
    for entry in staged.split(b"\x00"):
        if not entry:
            continue
        try:
            identity, raw_path = entry.split(b"\t", 1)
            mode, _object_id, stage = identity.split(b" ")
            relative = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise CalibrationImportError(
                "exact-base source index is malformed"
            ) from error
        if mode not in {b"100644", b"100755"} or stage != b"0":
            fail(f"exact-base source has a non-regular entry: {relative}")
        normalized = relative_path(
            relative, "exact-base source path"
        ).as_posix()
        if normalized in tracked:
            fail("exact-base source index contains a duplicate path")
        tracked[normalized] = mode == b"100755"

    observed: set[str] = set()
    for directory, directory_names, file_names in os.walk(
        checkout, topdown=True, followlinks=False
    ):
        current = Path(directory)
        if current == checkout and ".git" in directory_names:
            directory_names.remove(".git")
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            path = current / name
            relative = path.relative_to(checkout).as_posix()
            if not stat.S_ISDIR(path.lstat().st_mode):
                fail(f"exact-base source contains a non-directory: {relative}")
        for name in file_names:
            path = current / name
            relative = path.relative_to(checkout).as_posix()
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                fail(
                    f"exact-base source contains a non-regular file: {relative}"
                )
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                fail(
                    "exact-base source file is group/other writable: "
                    f"{relative}"
                )
            expected_executable = tracked.get(relative)
            if expected_executable is None:
                fail(f"exact-base source contains an untracked file: {relative}")
            if bool(stat.S_IMODE(metadata.st_mode) & 0o111) != expected_executable:
                fail(f"exact-base source executable mode drift: {relative}")
            observed.add(relative)
    if observed != set(tracked):
        fail("exact-base source working-tree inventory drift")


@contextlib.contextmanager
def exact_base_source(
    source_repo: Path, base_revision: str, scratch_parent: Path
):
    with tempfile.TemporaryDirectory(
        prefix="calibration-exact-base-", dir=scratch_parent
    ) as temporary:
        root = Path(temporary)
        environment = isolated_git_environment(root)
        checkout = root / "source"
        isolated_git(
            [
                "-c", "protocol.file.allow=always", "clone", "--quiet",
                "--no-local", "--no-checkout", "--", os.fspath(source_repo),
                os.fspath(checkout),
            ],
            environment,
            "exact-base source clone",
        )
        isolated_git(
            [
                "-C", os.fspath(checkout), "-c", "core.hooksPath=/dev/null",
                "checkout", "--quiet", "--detach", base_revision,
            ],
            environment,
            "base revision exact-source checkout",
        )
        isolated_git(
            ["-C", os.fspath(checkout), "remote", "remove", "origin"],
            environment,
            "exact-base source origin removal",
        )
        revision = isolated_git(
            ["-C", os.fspath(checkout), "rev-parse", "HEAD^{commit}"],
            environment,
            "exact-base source revision read",
        ).stdout.decode("ascii").strip()
        if revision != base_revision:
            fail("base revision identity drift")
        tree_oid = isolated_git(
            ["-C", os.fspath(checkout), "rev-parse", "HEAD^{tree}"],
            environment,
            "exact-base source tree read",
        ).stdout.decode("ascii").strip()
        if HEX40.fullmatch(tree_oid) is None:
            fail("exact-base source tree identity is malformed")
        if isolated_git(
            ["-C", os.fspath(checkout), "remote"],
            environment,
            "exact-base source remote inventory",
        ).stdout:
            fail("exact-base source retained a remote")
        verify_checkout_inventory(checkout, environment)
        yield checkout, tree_oid, environment


def top_names(root: Path) -> frozenset[str]:
    return frozenset(path.name for path in root.iterdir())


def verify_session_layout(session: Path) -> None:
    verify_frozen_tree(session, "controller session")
    if top_names(session) != CONTROLLER_TOP:
        fail("controller session inventory drift")
    producer = session / "producer"
    if top_names(producer) != PRODUCER_TOP:
        fail("producer inventory drift")
    verify_manifest(session, "controller session")
    verify_manifest(producer, "producer session")
    for name in ("calibration", "qualification-rejection"):
        verify_manifest(
            producer / name, name, qualification_receipt=True
        )
        verify_sidecar(producer / name, name)
    verify_sidecar(producer, "producer session")
    verify_sidecar(session, "controller session")


def validated_evidence_path(value: object) -> str:
    path = relative_path(value, "calibration evidence path")
    try:
        path.relative_to(EVIDENCE_PREFIX)
    except ValueError as error:
        raise CalibrationImportError(
            "calibration evidence path is outside retained authority"
        ) from error
    if path == EVIDENCE_PREFIX:
        fail("calibration evidence path omits its identity")
    return path.as_posix()


def verify_relationships(
    session: Path, base_revision: str, previous_raw: bytes
) -> tuple[dict[str, object], str]:
    producer = session / "producer"
    controller, _ = read_canonical(session / "receipt.json", "controller receipt")
    if set(controller) != CONTROLLER_RECEIPT_FIELDS:
        fail("controller receipt field set drift")
    if (
        controller.get("schema") != SESSION_SCHEMA
        or controller.get("status") != "accepted"
    ):
        fail("controller receipt classification drift")
    if controller.get("source_revision") != base_revision:
        fail("controller source revision drift")
    if controller.get("producer_receipt_sha256") != digest(producer / "receipt.json"):
        fail("controller producer receipt identity drift")
    if controller.get("producer_manifest_sha256") != digest(producer / "SHA256SUMS"):
        fail("controller producer manifest identity drift")

    producer_receipt, _ = read_canonical(
        producer / "receipt.json", "producer receipt"
    )
    if set(producer_receipt) != PRODUCER_RECEIPT_FIELDS:
        fail("producer receipt field set drift")
    if (
        producer_receipt.get("schema") != PRODUCER_SCHEMA
        or producer_receipt.get("status") != "accepted-candidate"
    ):
        fail("producer receipt classification drift")
    if producer_receipt.get("source_revision") != base_revision:
        fail("producer source revision drift")
    evidence_path = validated_evidence_path(
        producer_receipt.get("calibration_evidence_path")
    )
    candidate_path = producer / "determinism-baseline.candidate.json"
    calibration_path = producer / "calibration/receipt.json"
    rejection_path = producer / "qualification-rejection/receipt.json"
    for field, path, label in (
        ("candidate_baseline_sha256", candidate_path, "candidate baseline"),
        ("calibration_receipt_sha256", calibration_path, "calibration receipt"),
        ("rejection_receipt_sha256", rejection_path, "rejection receipt"),
    ):
        if producer_receipt.get(field) != digest(path):
            fail(f"producer {label} identity drift")

    candidate, _ = read_canonical(
        candidate_path, "candidate baseline", qualification=True
    )
    calibration, _ = read_canonical(
        calibration_path, "calibration receipt", qualification=True
    )
    rejection, _ = read_canonical(
        rejection_path, "qualification rejection receipt", qualification=True
    )
    previous = read_canonical_bytes(
        previous_raw, "base revision baseline", qualification=True
    )
    if candidate.get("schema") != BASELINE_SCHEMA:
        fail("candidate baseline classification drift")
    profiles = candidate.get("profiles")
    old_profiles = previous.get("profiles")
    if not isinstance(profiles, dict) or not isinstance(old_profiles, dict):
        fail("candidate or predecessor profile set is malformed")
    if (
        calibration.get("schema") != CALIBRATION_SCHEMA
        or calibration.get("status") != "calibration"
    ):
        fail("calibration receipt classification drift")
    source = calibration.get("source")
    if not isinstance(source, dict) or source.get("revision") != base_revision:
        fail("calibration source revision drift")
    host = calibration.get("host")
    class_id = host.get("class_id") if isinstance(host, dict) else None
    if not isinstance(class_id, str) or set(profiles) != {class_id}:
        fail("candidate/calibration profile relationship drift")
    old_profile = old_profiles.get(class_id)
    profile = profiles.get(class_id)
    if not isinstance(old_profile, dict) or not isinstance(profile, dict):
        fail("candidate predecessor profile relationship drift")
    provenance = profile.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("source_revision") != base_revision:
        fail("candidate source revision drift")
    calibration_link = provenance.get("calibration")
    if not isinstance(calibration_link, dict):
        fail("candidate calibration relationship is malformed")
    if calibration_link.get("evidence_path") != evidence_path:
        fail("candidate calibration evidence path drift")
    if calibration_link.get("receipt_sha256") != digest(calibration_path):
        fail("candidate calibration receipt link drift")
    promotion = provenance.get("promotion")
    if not isinstance(promotion, dict):
        fail("candidate promotion relationship is malformed")
    if promotion.get("previous_baseline_sha256") != sha256_bytes(previous_raw):
        fail("candidate predecessor baseline identity drift")
    if promotion.get("previous_profile_sha256") != sha256_bytes(
        qualification_canonical(old_profile)
    ):
        fail("candidate predecessor profile identity drift")
    decision = rejection.get("decision")
    observations = rejection.get("observations")
    failures = rejection.get("failures")
    if isinstance(decision, dict):
        failures = decision.get("failures", failures)
    if (
        rejection.get("schema") != REJECTION_SCHEMA
        or rejection.get("status") != "rejected"
        or not isinstance(decision, dict)
        or decision.get("classification") != "complete-gate-rejection"
        or not isinstance(observations, dict)
        or observations.get("complete") is not True
        or not isinstance(failures, list)
        or len(failures) != 1
        or not isinstance(failures[0], dict)
        or failures[0].get("type") != "profile-unavailable"
    ):
        fail("qualification rejection relationship drift")
    return candidate, evidence_path


def verify_external_authority(
    session: Path,
    bundle: Path,
    source_repo: Path,
    previous_raw: bytes,
    evidence_path: str,
    scratch_parent: Path,
) -> None:
    python = "/usr/bin/python3"
    with tempfile.TemporaryDirectory(
        prefix="calibration-candidate-", dir=scratch_parent
    ) as temporary:
        temporary_root = Path(temporary)
        environment_root = temporary_root / "environment"
        environment_root.mkdir(mode=0o700)
        environment = isolated_git_environment(environment_root)
        run_checked(
            [python, "-E", "-s", "-B", os.fspath(bundle / "session-seal.py"),
             "verify", "--root", os.fspath(session / "producer")],
            "CODESKEPTIC_P10_09_CANDIDATE_SESSION_OK action=verify",
            "producer session verifier",
            environment,
        )
        run_checked(
            [python, "-E", "-s", "-B", os.fspath(bundle / "controller-seal.py"),
             "verify", "--root", os.fspath(session)],
            "CODESKEPTIC_P10_09_CONTROLLER_SESSION_OK action=verify",
            "controller session verifier",
            environment,
        )
        previous = temporary_root / "previous-baseline.json"
        previous.write_bytes(previous_raw)
        scratch = temporary_root / "scratch"
        scratch.mkdir()
        run_checked(
            [
                python, "-E", "-s", "-B",
                os.fspath(bundle / "verify-candidate.py"),
                "--source", os.fspath(source_repo),
                "--previous", os.fspath(previous),
                "--candidate", os.fspath(
                    session / "producer/determinism-baseline.candidate.json"
                ),
                "--calibration", os.fspath(session / "producer/calibration"),
                "--rejection", os.fspath(
                    session / "producer/qualification-rejection"
                ),
                "--evidence-path", evidence_path,
                "--scratch-parent", os.fspath(scratch),
            ],
            "CODESKEPTIC_P10_09_CANDIDATE_VERIFIED",
            "candidate authority verifier",
            environment,
        )


def projection_receipt(
    session: Path,
    bundle_manifest_sha: str,
    operator_scripts: dict[str, str],
    base_revision: str,
    base_tree_oid: str,
    previous_raw: bytes,
    evidence_path: str,
) -> dict[str, object]:
    producer = session / "producer"
    return {
        "schema": SCHEMA,
        "status": "ready-for-reviewed-promotion",
        "base_revision": base_revision,
        "base_tree_oid": base_tree_oid,
        "calibration_evidence_path": evidence_path,
        "candidate_baseline_sha256": digest(
            producer / "determinism-baseline.candidate.json"
        ),
        "previous_baseline_sha256": sha256_bytes(previous_raw),
        "calibration_receipt_sha256": digest(producer / "calibration/receipt.json"),
        "calibration_manifest_sha256": digest(producer / "calibration/SHA256SUMS"),
        "source_session": {
            "name": session.name,
            "controller_receipt_sha256": digest(session / "receipt.json"),
            "controller_manifest_sha256": digest(session / "SHA256SUMS"),
            "producer_receipt_sha256": digest(producer / "receipt.json"),
            "producer_manifest_sha256": digest(producer / "SHA256SUMS"),
        },
        "trusted_operator": {
            "manifest_sha256": bundle_manifest_sha,
            "verifier_scripts": dict(sorted(operator_scripts.items())),
        },
        "verification": {
            "producer_seal": "pass",
            "controller_seal": "pass",
            "candidate_authority": "pass",
            "base_revision": "pass",
            "projection_inventory": "pass",
        },
    }


def write_file(path: Path, value: bytes, mode: int = 0o444) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def expected_projection_inventory(
    session: Path, evidence_path: str
) -> tuple[set[str], set[str]]:
    calibration = session / "producer/calibration"
    calibration_dirs, calibration_files = tree_inventory(calibration, "calibration")
    evidence = PurePosixPath(evidence_path)
    parent_dirs: set[str] = {"scripts"}
    current = PurePosixPath()
    for part in evidence.parts:
        current /= part
        parent_dirs.add(current.as_posix())
    directories = parent_dirs | {
        (evidence / relative).as_posix() for relative in calibration_dirs
    }
    files = {
        "SHA256SUMS", "receipt.json", "receipt.json.sha256",
        "scripts/determinism_baseline.json",
        *((evidence / relative).as_posix() for relative in calibration_files),
    }
    return directories, files


def verify_projection(
    projection: Path,
    session: Path,
    bundle_manifest_sha: str,
    operator_scripts: dict[str, str],
    base_revision: str,
    base_tree_oid: str,
    previous_raw: bytes,
    evidence_path: str,
) -> None:
    directories, files = verify_frozen_tree(projection, "projection")
    expected_directories, expected_files = expected_projection_inventory(
        session, evidence_path
    )
    if set(directories) != expected_directories or set(files) != expected_files:
        fail("projection inventory drift")
    verify_manifest(projection, "projection")
    verify_sidecar(projection, "projection")
    evidence = projection / evidence_path
    verify_manifest(
        evidence, "projected calibration", qualification_receipt=True
    )
    verify_sidecar(evidence, "projected calibration")
    receipt, _ = read_canonical(projection / "receipt.json", "projection receipt")
    if set(receipt) != RECEIPT_FIELDS:
        fail("projection receipt field set drift")
    expected = projection_receipt(
        session, bundle_manifest_sha, operator_scripts, base_revision,
        base_tree_oid, previous_raw, evidence_path,
    )
    if receipt != expected:
        fail("projection receipt claims or identity drift")
    candidate_source = session / "producer/determinism-baseline.candidate.json"
    candidate_output = projection / "scripts/determinism_baseline.json"
    if candidate_output.read_bytes() != candidate_source.read_bytes():
        fail("projection candidate baseline drift")
    source_calibration = session / "producer/calibration"
    _, calibration_files = tree_inventory(source_calibration, "calibration")
    for relative in calibration_files:
        if (evidence / relative).read_bytes() != (source_calibration / relative).read_bytes():
            fail(f"projection calibration drift: {relative}")


def fsync_tree(root: Path) -> None:
    directories, files = tree_inventory(root, "projection staging")
    for relative in files:
        descriptor = os.open(root / relative, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for relative in sorted(directories, key=lambda item: item.count("/"), reverse=True):
        descriptor = os.open(root / relative, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rename_noreplace(source: Path, destination: Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        fail("atomic create-new publish is unavailable on this platform")
    function.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    at_fdcwd = -100
    result = function(
        at_fdcwd, os.fsencode(source), at_fdcwd, os.fsencode(destination), 1
    )
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            fail("projection output already exists")
        raise OSError(error, os.strerror(error), os.fspath(destination))


def freeze_projection(root: Path) -> None:
    directories, files = tree_inventory(root, "projection staging")
    for relative in files:
        os.chmod(root / relative, 0o444, follow_symlinks=False)
    for relative in sorted(directories, key=lambda item: item.count("/"), reverse=True):
        os.chmod(root / relative, 0o555)
    os.chmod(root, 0o555)


def remove_private_staging(root: Path) -> None:
    """Make only our unpublished private tree removable, then remove it."""

    for directory, directory_names, _ in os.walk(
        root, topdown=False, followlinks=False
    ):
        current = Path(directory)
        for name in directory_names:
            path = current / name
            if stat.S_ISDIR(path.lstat().st_mode):
                os.chmod(path, 0o700)
        os.chmod(current, 0o700)
    shutil.rmtree(root)


def materialize_projection(
    output: Path,
    session: Path,
    bundle_manifest_sha: str,
    operator_scripts: dict[str, str],
    base_revision: str,
    base_tree_oid: str,
    previous_raw: bytes,
    evidence_path: str,
) -> None:
    parent = real_directory(output.parent, "projection parent")
    if output.exists() or output.is_symlink():
        fail("projection output already exists")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=parent))
    try:
        (temporary / "scripts").mkdir(mode=0o755)
        destination = temporary / evidence_path
        destination.parent.mkdir(parents=True, mode=0o755)
        shutil.copytree(
            session / "producer/calibration", destination,
            symlinks=True, copy_function=shutil.copyfile,
        )
        write_file(
            temporary / "scripts/determinism_baseline.json",
            (session / "producer/determinism-baseline.candidate.json").read_bytes(),
        )
        receipt = canonical(projection_receipt(
            session, bundle_manifest_sha, operator_scripts, base_revision,
            base_tree_oid, previous_raw, evidence_path,
        ))
        write_file(temporary / "receipt.json", receipt)
        write_file(
            temporary / "receipt.json.sha256",
            f"{sha256_bytes(receipt)}  receipt.json\n".encode("ascii"),
        )
        _, files = tree_inventory(temporary, "projection staging")
        manifest = b"".join(
            f"{digest(temporary / relative)}  {relative}\n".encode("utf-8")
            for relative in files if relative != "SHA256SUMS"
        )
        write_file(temporary / "SHA256SUMS", manifest)
        freeze_projection(temporary)
        verify_projection(
            temporary, session, bundle_manifest_sha, operator_scripts,
            base_revision, base_tree_oid, previous_raw, evidence_path,
        )
        fsync_tree(temporary)
        rename_noreplace(temporary, output)
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary.exists():
            remove_private_staging(temporary)


def ensure_separate_output(
    output: Path, session: Path, bundle: Path, source_repo: Path
) -> None:
    absolute = Path(os.path.abspath(output))
    for root, label in (
        (session, "session"), (bundle, "operator bundle"),
        (source_repo, "source repository"),
    ):
        try:
            absolute.relative_to(root)
        except ValueError:
            continue
        fail(f"projection must be outside the {label}")


def execute(arguments: argparse.Namespace) -> None:
    session = real_directory(arguments.session, "controller session")
    if SESSION_NAME.fullmatch(session.name) is None:
        fail("controller session identity is malformed")
    bundle = real_directory(arguments.operator_bundle, "operator bundle")
    source_repo = real_directory(arguments.source_repo, "source repository")
    if HEX40.fullmatch(arguments.base_revision) is None:
        fail("base revision is malformed")
    output = Path(os.path.abspath(arguments.projection))
    ensure_separate_output(output, session, bundle, source_repo)
    if arguments.action == "import" and (output.exists() or output.is_symlink()):
        fail("projection output already exists")
    if arguments.action == "verify":
        projection = real_directory(output, "projection")
    else:
        projection = None

    operator_scripts = verify_operator(
        bundle, arguments.operator_manifest_sha256
    )
    verify_session_layout(session)
    scratch_parent = real_directory(output.parent, "projection parent")
    with exact_base_source(
        source_repo, arguments.base_revision, scratch_parent
    ) as (trusted_source, base_tree_oid, git_environment):
        previous_raw = (
            trusted_source / "scripts/determinism_baseline.json"
        ).read_bytes()
        read_canonical_bytes(
            previous_raw, "base revision baseline", qualification=True
        )
        _, evidence_path = verify_relationships(
            session, arguments.base_revision, previous_raw
        )
        verify_external_authority(
            session, bundle, trusted_source, previous_raw, evidence_path,
            scratch_parent,
        )
        if verify_operator(
            bundle, arguments.operator_manifest_sha256
        ) != operator_scripts:
            fail("operator verifier identity changed during replay")
        verify_session_layout(session)
        verify_checkout_inventory(trusted_source, git_environment)
        replay_tree = isolated_git(
            ["-C", os.fspath(trusted_source), "rev-parse", "HEAD^{tree}"],
            git_environment,
            "post-replay exact-base source tree read",
        ).stdout.decode("ascii").strip()
        if replay_tree != base_tree_oid:
            fail("exact-base source tree changed during replay")
    if arguments.action == "import":
        materialize_projection(
            output, session, arguments.operator_manifest_sha256,
            operator_scripts, arguments.base_revision, base_tree_oid,
            previous_raw, evidence_path,
        )
    else:
        assert projection is not None
        verify_projection(
            projection, session, arguments.operator_manifest_sha256,
            operator_scripts, arguments.base_revision, base_tree_oid,
            previous_raw, evidence_path,
        )
    print(
        "CODESKEPTIC_DETERMINISM_CALIBRATION_IMPORT_OK "
        f"action={arguments.action} revision={arguments.base_revision}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("import", "verify"))
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--operator-bundle", type=Path, required=True)
    parser.add_argument("--operator-manifest-sha256", required=True)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--base-revision", required=True)
    parser.add_argument("--projection", type=Path, required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    execute(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        CalibrationImportError, OSError, KeyError, TypeError, ValueError,
        UnicodeDecodeError,
    ) as error:
        print(
            f"CODESKEPTIC_DETERMINISM_CALIBRATION_IMPORT_FAIL {error}",
            file=sys.stderr,
        )
        raise SystemExit(2)
