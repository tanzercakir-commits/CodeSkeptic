#!/usr/bin/env python3
"""Fail-closed one-time installer for the fixed P10-09 launch boundary."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import dataclasses
import errno
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterator


SOURCE_ROOT = Path(__file__).resolve().parent
INSTALL_ROOT = Path("/opt/codeskeptic-p10-09-launch")
UNIT_ROOT = Path("/etc/systemd/system")
ACTIVATION_ROOT = UNIT_ROOT / "sockets.target.wants"
GUIDED_PATH = Path(
    "/opt/codeskeptic-p10-09/operator/guided-stability.sh"
)
CORE_AUTHORITY_PATH = Path(
    "/var/lib/codeskeptic-p10-09/installation-authority.json"
)
CORE_PRODUCER_PATH = Path(
    "/opt/codeskeptic-p10-09/operator/stage_stability_campaign.py"
)
CORE_RECEIPT_PATH = Path(
    "/opt/codeskeptic-p10-09/installation/receipt.json"
)
INSTALL_LOCK_PATH = Path("/run/codeskeptic-p10-09-launch.install.lock")
RUNTIME_ROOT = Path("/run/codeskeptic-p10-09-launch")

SCHEMA = "codeskeptic-stability-launch-installation-v1"
RECEIPT_NAME = "receipt.json"
SIDECAR_NAME = "receipt.json.sha256"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 15 * 60
SYSTEMD_TIMEOUT_SECONDS = 30
GROUP_TOKEN = b"@OPERATOR_GROUP@"
USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
GROUP_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")

BROKER_NAME = "launch-broker.py"
CLIENT_NAME = "launch-client.py"
CAMPAIGN_SOCKET_NAME = "codeskeptic-p10-09-campaign.socket"
CAMPAIGN_SOCKET_SOURCE = CAMPAIGN_SOCKET_NAME + ".in"
CAMPAIGN_SERVICE_NAME = "codeskeptic-p10-09-campaign@.service"
PROBE_SOCKET_NAME = "codeskeptic-p10-09-probe.socket"
PROBE_SOCKET_SOURCE = PROBE_SOCKET_NAME + ".in"
PROBE_SERVICE_NAME = "codeskeptic-p10-09-probe@.service"
TIMEOUT_DROPIN_NAME = "10-timeout-abort.conf"
TIMEOUT_DROPIN_SOURCE = "timeout-stop-terminate.conf"

PACKAGE_MODES = {
    "README.md": 0o444,
    BROKER_NAME: 0o555,
    CLIENT_NAME: 0o555,
    CAMPAIGN_SOCKET_NAME: 0o444,
    CAMPAIGN_SERVICE_NAME: 0o444,
    PROBE_SOCKET_NAME: 0o444,
    PROBE_SERVICE_NAME: 0o444,
    TIMEOUT_DROPIN_SOURCE: 0o444,
}
UNIT_NAMES = (
    CAMPAIGN_SOCKET_NAME,
    CAMPAIGN_SERVICE_NAME,
    PROBE_SOCKET_NAME,
    PROBE_SERVICE_NAME,
)
SOCKET_NAMES = (CAMPAIGN_SOCKET_NAME, PROBE_SOCKET_NAME)
SERVICE_NAMES = (CAMPAIGN_SERVICE_NAME, PROBE_SERVICE_NAME)
SOURCE_NAMES = {
    "README.md": "README.md",
    BROKER_NAME: BROKER_NAME,
    CLIENT_NAME: CLIENT_NAME,
    CAMPAIGN_SOCKET_NAME: CAMPAIGN_SOCKET_SOURCE,
    CAMPAIGN_SERVICE_NAME: CAMPAIGN_SERVICE_NAME,
    PROBE_SOCKET_NAME: PROBE_SOCKET_SOURCE,
    PROBE_SERVICE_NAME: PROBE_SERVICE_NAME,
    TIMEOUT_DROPIN_SOURCE: TIMEOUT_DROPIN_SOURCE,
}


class InstallError(RuntimeError):
    """The fixed launch installation cannot be safely created or reused."""


@dataclasses.dataclass(frozen=True)
class OperatorIdentity:
    uid: int
    user: str
    gid: int
    group: str


@dataclasses.dataclass(frozen=True)
class Layout:
    install_root: Path = INSTALL_ROOT
    unit_root: Path = UNIT_ROOT
    activation_root: Path = ACTIVATION_ROOT
    guided_path: Path = GUIDED_PATH
    core_authority_path: Path = CORE_AUTHORITY_PATH
    core_producer_path: Path = CORE_PRODUCER_PATH
    core_receipt_path: Path = CORE_RECEIPT_PATH
    install_lock_path: Path = INSTALL_LOCK_PATH
    runtime_root: Path = RUNTIME_ROOT


@dataclasses.dataclass(frozen=True)
class CreatedNode:
    path: Path
    device: int
    inode: int
    kind: str
    link_target: str | None = None
    children: tuple[str, ...] | None = None


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]


def _canonical_document(value: object) -> bytes:
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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve_operator_identity(uid: int, user: str) -> OperatorIdentity:
    if (
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or not 0 < uid < 2**31
        or not isinstance(user, str)
        or USER_NAME.fullmatch(user) is None
    ):
        raise InstallError("operator identity is malformed")
    try:
        by_uid = pwd.getpwuid(uid)
        by_user = pwd.getpwnam(user)
        group = grp.getgrgid(by_uid.pw_gid)
    except KeyError as error:
        raise InstallError("operator account is unavailable") from error
    if (
        by_uid.pw_name != user
        or by_user.pw_uid != uid
        or by_user.pw_gid != by_uid.pw_gid
        or GROUP_NAME.fullmatch(group.gr_name) is None
    ):
        raise InstallError("operator account identity drift")
    return OperatorIdentity(
        uid=uid,
        user=user,
        gid=by_uid.pw_gid,
        group=group.gr_name,
    )


def render_socket_unit(data: bytes, group: str) -> bytes:
    if not isinstance(group, str) or GROUP_NAME.fullmatch(group) is None:
        raise InstallError("operator group is malformed")
    if data.count(GROUP_TOKEN) != 1:
        raise InstallError("socket template group token drift")
    try:
        rendered = data.replace(GROUP_TOKEN, group.encode("ascii"))
        rendered.decode("ascii", errors="strict")
    except (UnicodeDecodeError, UnicodeEncodeError) as error:
        raise InstallError("socket template is not canonical ASCII") from error
    return rendered


def _read_source(path: Path, identity: OperatorIdentity) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise InstallError(f"cannot inspect launch source {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != identity.uid
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size > MAX_SOURCE_BYTES
    ):
        raise InstallError(f"launch source authority drift: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InstallError(f"cannot open launch source {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(before, opened):
            raise InstallError(f"launch source changed while opening: {path}")
        data = b""
        while len(data) <= MAX_SOURCE_BYTES:
            block = os.read(descriptor, min(65536, MAX_SOURCE_BYTES + 1 - len(data)))
            if not block:
                break
            data += block
        after = os.fstat(descriptor)
        if (
            len(data) != opened.st_size
            or not os.path.samestat(opened, after)
            or after.st_size != opened.st_size
        ):
            raise InstallError(f"launch source changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def _validate_socket_unit(data: bytes, name: str, identity: OperatorIdentity) -> None:
    modes = {
        CAMPAIGN_SOCKET_NAME: "campaign",
        PROBE_SOCKET_NAME: "probe",
    }
    try:
        mode = modes[name]
        expected = (
            "[Unit]\n"
            f"Description=CodeSkeptic P10-09 fixed {mode} launch socket\n"
            "Documentation=file:/opt/codeskeptic-p10-09-launch/README.md\n"
            "Before=shutdown.target rescue.target emergency.target\n"
            "Conflicts=shutdown.target rescue.target emergency.target\n"
            "IgnoreOnIsolate=yes\n"
            "StartLimitIntervalSec=0\n"
            "\n"
            "[Socket]\n"
            f"ListenStream=/run/codeskeptic-p10-09-launch/{mode}.sock\n"
            "DirectoryMode=0755\n"
            "SocketUser=root\n"
            f"SocketGroup={identity.group}\n"
            "SocketMode=0660\n"
            "Accept=yes\n"
            "AcceptFileDescriptors=no\n"
            "Backlog=1\n"
            "MaxConnections=1\n"
            "MaxConnectionsPerSource=1\n"
            "RemoveOnStop=yes\n"
            "TriggerLimitIntervalSec=0\n"
            "PollLimitIntervalSec=2s\n"
            "PollLimitBurst=4\n"
            "\n"
            "[Install]\n"
            "WantedBy=sockets.target\n"
        ).encode("ascii")
    except (KeyError, UnicodeEncodeError) as error:
        raise InstallError(f"socket unit identity drift: {name}") from error
    if data != expected:
        raise InstallError(f"socket unit contract drift: {name}")


def _validate_service_unit(data: bytes, name: str) -> None:
    modes = {
        CAMPAIGN_SERVICE_NAME: "campaign",
        PROBE_SERVICE_NAME: "probe",
    }
    try:
        mode = modes[name]
    except KeyError as error:
        raise InstallError(f"service unit identity drift: {name}") from error
    expected = (
        "[Unit]\n"
        f"Description=CodeSkeptic P10-09 fixed {mode} launch broker\n"
        "Documentation=file:/opt/codeskeptic-p10-09-launch/README.md\n"
        "After=local-fs.target\n"
        "Before=shutdown.target rescue.target emergency.target\n"
        "Conflicts=shutdown.target rescue.target emergency.target\n"
        "IgnoreOnIsolate=yes\n"
        "RefuseManualStart=yes\n"
        "CollectMode=inactive-or-failed\n"
        "\n"
        "[Service]\n"
        "Type=exec\n"
        "User=root\n"
        "Group=root\n"
        "UMask=0077\n"
        "ExecStart=/usr/bin/python3 -I -B "
        f"/opt/codeskeptic-p10-09-launch/launch-broker.py {mode}\n"
        "StandardInput=socket\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "TimeoutStartSec=15min\n"
        "RuntimeMaxSec=16min\n"
        "Restart=no\n"
        "KillMode=control-group\n"
        "RuntimeDirectory=codeskeptic-p10-09\n"
        "RuntimeDirectoryMode=0700\n"
        "RuntimeDirectoryPreserve=yes\n"
        "NoNewPrivileges=yes\n"
        "ProtectSystem=strict\n"
        "ProtectHome=yes\n"
        "ProtectHostname=yes\n"
        "ProtectClock=yes\n"
        "ProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectControlGroups=no\n"
        "PrivateTmp=yes\n"
        "PrivateNetwork=yes\n"
        "PrivateDevices=no\n"
        "LockPersonality=yes\n"
        "RestrictRealtime=yes\n"
        "RestrictSUIDSGID=yes\n"
        "SystemCallArchitectures=native\n"
        "ReadOnlyPaths=/opt/codeskeptic-p10-09 "
        "/opt/codeskeptic-p10-09-launch -/etc/codeskeptic-p10-09\n"
        "ReadWritePaths=-/var/lib/codeskeptic-p10-09 "
        "/run/codeskeptic-p10-09 /sys/fs/cgroup\n"
    ).encode("ascii")
    if data != expected:
        raise InstallError(f"service unit contract drift: {name}")


def prepare_payload(
    source_root: Path, identity: OperatorIdentity
) -> dict[str, bytes]:
    payload: dict[str, bytes] = {}
    for destination, source_name in SOURCE_NAMES.items():
        data = _read_source(source_root / source_name, identity)
        if source_name.endswith(".socket.in"):
            data = render_socket_unit(data, identity.group)
        payload[destination] = data
    for name in SOCKET_NAMES:
        _validate_socket_unit(payload[name], name, identity)
    for name in SERVICE_NAMES:
        _validate_service_unit(payload[name], name)
    if payload[TIMEOUT_DROPIN_SOURCE] != (
        b"[Service]\nTimeoutStopFailureMode=terminate\n"
    ):
        raise InstallError("timeout drop-in contract drift")
    return payload


def _read_root_regular(path: Path, mode: int, maximum: int = MAX_SOURCE_BYTES) -> bytes:
    return _read_regular_owned(path, mode, 0, 0, maximum=maximum)


def _guided_hash(path: Path) -> str:
    return _sha256(_read_root_regular(path, 0o555))


def _write_new(
    path: Path,
    data: bytes,
    mode: int,
    owner_uid: int,
    owner_gid: int,
    *,
    created_nodes: list[CreatedNode] | None = None,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise InstallError(f"cannot create fixed file {path}: {error}") from error
    node: CreatedNode | None = None
    registered = False
    try:
        opened = os.fstat(descriptor)
        node = CreatedNode(path, opened.st_dev, opened.st_ino, "file")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise InstallError(f"created fixed file identity drift: {path}")
        os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        try:
            os.close(descriptor)
        finally:
            descriptor = -1
        if created_nodes is not None:
            created_nodes.append(node)
            registered = True
        _fsync_directory(path.parent)
    except BaseException as primary:
        cleanup_failures: list[str] = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_failures.append(f"close: {error}")
        if not registered:
            if node is None:
                cleanup_failures.append(
                    "remove: created file identity is unavailable"
                )
            else:
                try:
                    metadata = path.lstat()
                    if (
                        metadata.st_dev != node.device
                        or metadata.st_ino != node.inode
                        or not stat.S_ISREG(metadata.st_mode)
                    ):
                        raise InstallError("created file identity changed")
                    path.unlink()
                    _fsync_directory(path.parent)
                except FileNotFoundError:
                    pass
                except (OSError, InstallError) as error:
                    cleanup_failures.append(f"remove: {error}")
        if cleanup_failures:
            raise InstallError(
                f"fixed file creation failed: {primary}; cleanup failed: "
                + "; ".join(cleanup_failures)
            ) from primary
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise InstallError("renameat2 is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    ) != 0:
        error = ctypes.get_errno()
        raise InstallError(
            f"cannot publish launch installation: {os.strerror(error)}"
        )


def _receipt(
    layout: Layout,
    identity: OperatorIdentity,
    payload: dict[str, bytes],
    guided_sha256: str,
    core_authority_sha256: str,
) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "install_root": str(layout.install_root),
        "operator": {
            "uid": identity.uid,
            "user": identity.user,
            "gid": identity.gid,
            "group": identity.group,
        },
        "guided": {
            "path": str(layout.guided_path),
            "sha256": guided_sha256,
        },
        "core_authority": {
            "path": str(layout.core_authority_path),
            "sha256": core_authority_sha256,
        },
        "files": {name: _sha256(payload[name]) for name in sorted(payload)},
        "unit_paths": {
            name: str(layout.unit_root / name) for name in UNIT_NAMES
        },
        "dropin_paths": {
            name: str(
                layout.unit_root / f"{name}.d" / TIMEOUT_DROPIN_NAME
            )
            for name in SERVICE_NAMES
        },
        "activation_links": {
            name: str(layout.activation_root / name) for name in SOCKET_NAMES
        },
    }


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    timeout = (
        COMMAND_TIMEOUT_SECONDS
        if len(argv) >= 4
        and argv[0:2] == ["/usr/bin/python3", "-B"]
        and argv[3] == "verify-install-filesystem"
        else SYSTEMD_TIMEOUT_SECONDS
    )
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InstallError(f"fixed command could not complete: {argv[0]}: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[:512]
        raise InstallError(f"fixed command failed: {argv[0]}: {detail}")
    return completed


def _run_systemctl(runner: CommandRunner, *arguments: str) -> None:
    completed = runner(["/usr/bin/systemctl", *arguments])
    if completed.returncode != 0:
        raise InstallError(f"systemctl command failed: {arguments[0]}")


def _systemctl_properties(
    runner: CommandRunner, name: str, fields: tuple[str, ...]
) -> dict[str, str]:
    completed = runner(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            *(f"--property={field}" for field in fields),
            name,
        ]
    )
    if completed.returncode != 0:
        raise InstallError("systemd unit identity query failed")
    output = completed.stdout
    if not isinstance(output, bytes) or len(output) > 16 * 1024:
        raise InstallError("systemd unit identity output is malformed")
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
        pairs = [line.split("=", 1) for line in lines]
    except UnicodeDecodeError as error:
        raise InstallError("systemd unit identity output is malformed") from error
    if (
        len(lines) != len(fields)
        or any(len(pair) != 2 for pair in pairs)
        or len({pair[0] for pair in pairs}) != len(fields)
        or {pair[0] for pair in pairs} != set(fields)
    ):
        raise InstallError("systemd unit identity output is malformed")
    return {key: value for key, value in pairs}


def _verify_loaded_unit_authority(
    runner: CommandRunner,
    layout: Layout,
    identity: OperatorIdentity,
    *,
    require_inactive: bool = False,
) -> dict[str, tuple[str, str]]:
    states: dict[str, tuple[str, str]] = {}
    socket_fields = (
        "LoadState",
        "ActiveState",
        "SubState",
        "FragmentPath",
        "DropInPaths",
        "UnitFileState",
        "Listen",
        "SocketUser",
        "SocketGroup",
        "SocketMode",
        "DirectoryMode",
        "Accept",
        "AcceptFileDescriptors",
        "Backlog",
        "MaxConnections",
        "MaxConnectionsPerSource",
        "RemoveOnStop",
        "IgnoreOnIsolate",
    )
    for name in SOCKET_NAMES:
        mode = "campaign" if name == CAMPAIGN_SOCKET_NAME else "probe"
        properties = _systemctl_properties(runner, name, socket_fields)
        expected = {
            "LoadState": "loaded",
            "ActiveState": properties["ActiveState"],
            "SubState": properties["SubState"],
            "FragmentPath": str(layout.unit_root / name),
            "DropInPaths": "",
            "UnitFileState": "enabled",
            "Listen": (
                f"/run/codeskeptic-p10-09-launch/{mode}.sock "
                "(Stream)"
            ),
            "SocketUser": "root",
            "SocketGroup": identity.group,
            "SocketMode": "0660",
            "DirectoryMode": "0755",
            "Accept": "yes",
            "AcceptFileDescriptors": "no",
            "Backlog": "1",
            "MaxConnections": "1",
            "MaxConnectionsPerSource": "1",
            "RemoveOnStop": "yes",
            "IgnoreOnIsolate": "yes",
        }
        allowed_state = (
            {("inactive", "dead")}
            if require_inactive
            else {("inactive", "dead"), ("active", "listening")}
        )
        if (
            (properties["ActiveState"], properties["SubState"])
            not in allowed_state
            or properties != expected
        ):
            raise InstallError(f"systemd loaded socket authority drift: {name}")
        states[name] = (
            properties["ActiveState"],
            properties["SubState"],
        )

    service_fields = (
        "LoadState",
        "FragmentPath",
        "DropInPaths",
        "UnitFileState",
        "ExecStart",
        "ExecStartPre",
        "ExecCondition",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
        "User",
        "Group",
        "StandardInput",
        "StandardOutput",
        "StandardError",
        "RefuseManualStart",
        "IgnoreOnIsolate",
        "RuntimeDirectory",
        "RuntimeDirectoryMode",
        "RuntimeDirectoryPreserve",
        "RuntimeMaxUSec",
        "TimeoutStopFailureMode",
    )
    for name in SERVICE_NAMES:
        mode = "campaign" if name == CAMPAIGN_SERVICE_NAME else "probe"
        audit_name = name.replace("@.service", "@codeskeptic-authority.service")
        properties = _systemctl_properties(runner, audit_name, service_fields)
        expected_start = (
            "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B "
            f"/opt/codeskeptic-p10-09-launch/launch-broker.py {mode} ; "
        )
        if (
            properties["LoadState"] != "loaded"
            or properties["FragmentPath"] != str(layout.unit_root / name)
            or properties["DropInPaths"]
            != str(layout.unit_root / f"{name}.d" / TIMEOUT_DROPIN_NAME)
            or properties["UnitFileState"] != "static"
            or not properties["ExecStart"].startswith(expected_start)
            or properties["ExecStart"].count("{") != 1
            or properties["ExecStart"].count("}") != 1
            or any(
                properties[field]
                for field in (
                    "ExecStartPre",
                    "ExecCondition",
                    "ExecStartPost",
                    "ExecReload",
                    "ExecStop",
                    "ExecStopPost",
                )
            )
            or properties["User"] != "root"
            or properties["Group"] != "root"
            or properties["StandardInput"] != "socket"
            or properties["StandardOutput"] != "journal"
            or properties["StandardError"] != "journal"
            or properties["RefuseManualStart"] != "yes"
            or properties["IgnoreOnIsolate"] != "yes"
            or properties["RuntimeDirectory"] != "codeskeptic-p10-09"
            or properties["RuntimeDirectoryMode"] != "0700"
            or properties["RuntimeDirectoryPreserve"] != "yes"
            or properties["RuntimeMaxUSec"] != "16min"
            or properties["TimeoutStopFailureMode"] != "terminate"
        ):
            raise InstallError(f"systemd loaded service authority drift: {name}")
    return states


def _verify_live_sockets(
    runner: CommandRunner,
    layout: Layout,
    identity: OperatorIdentity,
    *,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> None:
    fields = (
        "LoadState",
        "ActiveState",
        "SubState",
        "FragmentPath",
        "DropInPaths",
        "UnitFileState",
    )
    for name in SOCKET_NAMES:
        properties = _systemctl_properties(runner, name, fields)
        expected = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "listening",
            "FragmentPath": str(layout.unit_root / name),
            "DropInPaths": "",
            "UnitFileState": "enabled",
        }
        if properties != expected:
            raise InstallError(f"systemd did not activate the exact socket: {name}")

    try:
        runtime = layout.runtime_root.lstat()
    except OSError as error:
        raise InstallError(
            f"cannot inspect live launch socket directory: {error}"
        ) from error
    if (
        not stat.S_ISDIR(runtime.st_mode)
        or runtime.st_uid != owner_uid
        or runtime.st_gid != owner_gid
        or stat.S_IMODE(runtime.st_mode) != 0o755
    ):
        raise InstallError("live launch socket directory authority drift")
    for mode in ("campaign", "probe"):
        path = layout.runtime_root / f"{mode}.sock"
        try:
            metadata = path.lstat()
        except OSError as error:
            raise InstallError(
                f"cannot inspect live launch socket node: {error}"
            ) from error
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != owner_uid
            or metadata.st_gid != identity.gid
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise InstallError(f"live launch socket node authority drift: {path}")


def _stop_and_verify_quiescent(runner: CommandRunner, layout: Layout) -> None:
    _run_systemctl(runner, "stop", *SOCKET_NAMES)
    for name in SOCKET_NAMES:
        properties = _systemctl_properties(
            runner, name, ("ActiveState", "SubState")
        )
        if properties != {"ActiveState": "inactive", "SubState": "dead"}:
            raise InstallError(f"launch socket did not quiesce: {name}")
    _verify_no_active_instances(runner)
    for mode in ("campaign", "probe"):
        path = layout.runtime_root / f"{mode}.sock"
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise InstallError(
                f"cannot inspect stopped launch socket: {error}"
            ) from error
        raise InstallError(f"stopped launch socket path remains: {path}")


def _verify_no_active_instances(runner: CommandRunner) -> None:
    completed = runner(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--all",
            "--no-legend",
            "--plain",
            "--state=active,activating,deactivating,reloading",
            "codeskeptic-p10-09-campaign@*.service",
            "codeskeptic-p10-09-probe@*.service",
        ]
    )
    if (
        completed.returncode != 0
        or not isinstance(completed.stdout, bytes)
        or len(completed.stdout) > 16 * 1024
        or completed.stdout.strip()
    ):
        raise InstallError("launch broker instances are not quiescent")


def _verify_no_live_socket_authority(
    runner: CommandRunner, layout: Layout
) -> None:
    fields = ("LoadState", "ActiveState", "SubState", "FragmentPath")
    expected = {
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "SubState": "dead",
        "FragmentPath": "",
    }
    for name in SOCKET_NAMES:
        if _systemctl_properties(runner, name, fields) != expected:
            raise InstallError(f"pre-existing launch socket authority: {name}")
    for mode in ("campaign", "probe"):
        path = layout.runtime_root / f"{mode}.sock"
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise InstallError(
                f"cannot inspect pre-existing launch socket: {error}"
            ) from error
        raise InstallError(f"pre-existing launch socket path: {path}")


def _rollback(nodes: list[CreatedNode]) -> list[str]:
    failures: list[str] = []
    for node in reversed(nodes):
        try:
            metadata = node.path.lstat()
            if metadata.st_dev != node.device or metadata.st_ino != node.inode:
                raise InstallError("created identity changed")
            if node.kind == "symlink":
                if not stat.S_ISLNK(metadata.st_mode) or os.readlink(node.path) != node.link_target:
                    raise InstallError("created symlink changed")
                node.path.unlink()
                _fsync_directory(node.path.parent)
            elif node.kind == "file":
                if not stat.S_ISREG(metadata.st_mode):
                    raise InstallError("created file changed")
                node.path.unlink()
                _fsync_directory(node.path.parent)
            elif node.kind == "directory":
                if not stat.S_ISDIR(metadata.st_mode):
                    raise InstallError("created directory changed")
                node.path.rmdir()
                _fsync_directory(node.path.parent)
            elif node.kind == "directory-open":
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or node.children is None
                    or tuple(
                        sorted(path.name for path in node.path.iterdir())
                    )
                    != node.children
                ):
                    raise InstallError("created directory inventory changed")
                os.chmod(node.path, 0o700)
                _fsync_directory(node.path)
            else:
                raise InstallError("unknown created-node kind")
        except FileNotFoundError:
            continue
        except (OSError, InstallError) as error:
            failures.append(f"{node.path}: {error}")
            if node.kind == "directory-open":
                break
    return failures


def _node_path_status(node: CreatedNode) -> str:
    try:
        metadata = node.path.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unknown"
    if metadata.st_dev != node.device or metadata.st_ino != node.inode:
        return "drift"
    if node.kind == "directory":
        return "match" if stat.S_ISDIR(metadata.st_mode) else "drift"
    if node.kind == "symlink":
        try:
            target = os.readlink(node.path)
        except OSError:
            return "unknown"
        return (
            "match"
            if stat.S_ISLNK(metadata.st_mode) and target == node.link_target
            else "drift"
        )
    return "drift"


def _remove_tail_registration(
    created_nodes: list[CreatedNode], node: CreatedNode
) -> None:
    if not created_nodes or created_nodes[-1] is not node:
        raise InstallError("created-node registration order drift")
    created_nodes.pop()


def _create_directory_recorded(
    path: Path,
    mode: int,
    owner_uid: int,
    owner_gid: int,
    created_nodes: list[CreatedNode],
) -> None:
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{path.name}.install-",
            dir=path.parent,
        )
    )
    temporary_node: CreatedNode | None = None
    published_node: CreatedNode | None = None
    registered = False
    try:
        metadata = temporary.lstat()
        temporary_node = CreatedNode(
            temporary,
            metadata.st_dev,
            metadata.st_ino,
            "directory",
        )
        if not stat.S_ISDIR(metadata.st_mode):
            raise InstallError("temporary directory identity drift")
        os.chown(temporary, owner_uid, owner_gid)
        os.chmod(temporary, mode)
        _fsync_directory(temporary)
        verified = temporary.lstat()
        if (
            verified.st_dev != temporary_node.device
            or verified.st_ino != temporary_node.inode
            or not stat.S_ISDIR(verified.st_mode)
            or verified.st_uid != owner_uid
            or verified.st_gid != owner_gid
            or stat.S_IMODE(verified.st_mode) != mode
        ):
            raise InstallError("prepared directory authority drift")
        published_node = CreatedNode(
            path,
            verified.st_dev,
            verified.st_ino,
            "directory",
        )
        created_nodes.append(published_node)
        registered = True
        _rename_noreplace(temporary, path)
        _fsync_directory(path.parent)
        return
    except BaseException as primary:
        published_status = (
            "absent"
            if published_node is None
            else _node_path_status(published_node)
        )
        temporary_status = (
            "unknown"
            if temporary_node is None
            else _node_path_status(temporary_node)
        )
        if published_status == "match" or (
            published_status == "unknown" and temporary_status != "match"
        ):
            raise
        cleanup_failures: list[str] = []
        if registered and published_node is not None:
            try:
                _remove_tail_registration(created_nodes, published_node)
            except InstallError as error:
                cleanup_failures.append(f"registration: {error}")
        if temporary_node is None:
            cleanup_failures.append("temporary directory identity is unavailable")
        elif temporary_status == "match":
            cleanup_failures.extend(_rollback([temporary_node]))
        elif temporary_status != "absent":
            cleanup_failures.append("temporary directory identity drift")
        if cleanup_failures:
            raise InstallError(
                f"directory creation failed: {primary}; cleanup failed: "
                + "; ".join(cleanup_failures)
            ) from primary
        raise


def _create_symlink_recorded(
    path: Path,
    target: str,
    owner_uid: int,
    owner_gid: int,
    created_nodes: list[CreatedNode],
) -> None:
    temporary = path.parent / (
        f".{path.name}.install-{secrets.token_hex(16)}"
    )
    temporary_node: CreatedNode | None = None
    published_node: CreatedNode | None = None
    registered = False
    try:
        os.symlink(target, temporary)
        metadata = temporary.lstat()
        temporary_node = CreatedNode(
            temporary,
            metadata.st_dev,
            metadata.st_ino,
            "symlink",
            target,
        )
        if (
            not stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or os.readlink(temporary) != target
        ):
            raise InstallError("temporary symlink identity drift")
        os.lchown(temporary, owner_uid, owner_gid)
        verified = temporary.lstat()
        if (
            verified.st_dev != temporary_node.device
            or verified.st_ino != temporary_node.inode
            or not stat.S_ISLNK(verified.st_mode)
            or verified.st_nlink != 1
            or verified.st_uid != owner_uid
            or verified.st_gid != owner_gid
            or os.readlink(temporary) != target
        ):
            raise InstallError("prepared symlink authority drift")
        published_node = CreatedNode(
            path,
            verified.st_dev,
            verified.st_ino,
            "symlink",
            target,
        )
        created_nodes.append(published_node)
        registered = True
        _rename_noreplace(temporary, path)
        _fsync_directory(path.parent)
        return
    except BaseException as primary:
        published_status = (
            "absent"
            if published_node is None
            else _node_path_status(published_node)
        )
        temporary_status = (
            "unknown"
            if temporary_node is None
            else _node_path_status(temporary_node)
        )
        if published_status == "match" or (
            published_status == "unknown" and temporary_status != "match"
        ):
            raise
        cleanup_failures: list[str] = []
        if registered and published_node is not None:
            try:
                _remove_tail_registration(created_nodes, published_node)
            except InstallError as error:
                cleanup_failures.append(f"registration: {error}")
        if temporary_node is None:
            try:
                temporary.lstat()
            except FileNotFoundError:
                pass
            except OSError as error:
                cleanup_failures.append(
                    f"temporary symlink inspection: {error}"
                )
            else:
                cleanup_failures.append("temporary symlink identity is unavailable")
        elif temporary_status == "match":
            cleanup_failures.extend(_rollback([temporary_node]))
        elif temporary_status != "absent":
            cleanup_failures.append("temporary symlink identity drift")
        if cleanup_failures:
            raise InstallError(
                f"symlink creation failed: {primary}; cleanup failed: "
                + "; ".join(cleanup_failures)
            ) from primary
        raise


def _cleanup_temporary_package(
    node: CreatedNode | None,
    allowed_children: set[str],
) -> list[str]:
    if node is None:
        return ["temporary package identity is unavailable"]
    status = _node_path_status(node)
    if status == "absent":
        return []
    if status != "match":
        return [f"{node.path}: temporary package identity drift"]
    try:
        names = sorted(path.name for path in node.path.iterdir())
        if not set(names).issubset(allowed_children):
            raise InstallError("temporary package inventory drift")
        children: list[CreatedNode] = []
        for name in names:
            path = node.path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise InstallError("temporary package child identity drift")
            children.append(
                CreatedNode(path, metadata.st_dev, metadata.st_ino, "file")
            )
        os.chmod(node.path, 0o700)
        failures = _rollback([node, *children])
        return failures
    except (OSError, InstallError) as error:
        return [f"{node.path}: {error}"]


def _verify_receipt_shape(
    receipt: object,
    layout: Layout,
    identity: OperatorIdentity,
    payload: dict[str, bytes],
    guided_sha256: str,
    core_authority_sha256: str,
) -> None:
    if receipt != _receipt(
        layout,
        identity,
        payload,
        guided_sha256,
        core_authority_sha256,
    ):
        raise InstallError("installed launch receipt differs from authority")


def verify_installation(
    layout: Layout,
    identity: OperatorIdentity,
    payload: dict[str, bytes],
    guided_sha256: str,
    core_authority_sha256: str,
    *,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> None:
    _verify_authority_ancestry(layout, owner_uid, owner_gid)
    try:
        root_metadata = layout.install_root.lstat()
        names = sorted(path.name for path in layout.install_root.iterdir())
    except OSError as error:
        raise InstallError(f"cannot inspect installed launch root: {error}") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != owner_uid
        or root_metadata.st_gid != owner_gid
        or stat.S_IMODE(root_metadata.st_mode) != 0o555
        or names != sorted((*PACKAGE_MODES, RECEIPT_NAME, SIDECAR_NAME))
    ):
        raise InstallError("installed launch root inventory drift")
    for name, mode in PACKAGE_MODES.items():
        data = _read_regular_owned(
            layout.install_root / name, mode, owner_uid, owner_gid
        )
        if data != payload[name]:
            raise InstallError(f"installed launch file drift: {name}")
    receipt_data = _read_regular_owned(
        layout.install_root / RECEIPT_NAME, 0o400, owner_uid, owner_gid
    )
    sidecar_data = _read_regular_owned(
        layout.install_root / SIDECAR_NAME, 0o400, owner_uid, owner_gid
    )
    expected_sidecar = (
        f"{_sha256(receipt_data)}  {RECEIPT_NAME}\n"
    ).encode("ascii")
    if sidecar_data != expected_sidecar:
        raise InstallError("installed launch receipt sidecar drift")
    try:
        receipt = json.loads(receipt_data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallError("installed launch receipt is malformed") from error
    if receipt_data != _canonical_document(receipt):
        raise InstallError("installed launch receipt is not canonical")
    _verify_receipt_shape(
        receipt,
        layout,
        identity,
        payload,
        guided_sha256,
        core_authority_sha256,
    )
    for name in UNIT_NAMES:
        data = _read_regular_owned(
            layout.unit_root / name, 0o444, owner_uid, owner_gid
        )
        if data != payload[name]:
            raise InstallError(f"live launch unit drift: {name}")
    for name in SERVICE_NAMES:
        directory = layout.unit_root / f"{name}.d"
        try:
            metadata = directory.lstat()
            children = sorted(path.name for path in directory.iterdir())
        except OSError as error:
            raise InstallError(
                f"cannot inspect launch drop-in directory: {error}"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or children != [TIMEOUT_DROPIN_NAME]
        ):
            raise InstallError(f"launch drop-in inventory drift: {name}")
        data = _read_regular_owned(
            directory / TIMEOUT_DROPIN_NAME,
            0o444,
            owner_uid,
            owner_gid,
        )
        if data != payload[TIMEOUT_DROPIN_SOURCE]:
            raise InstallError(f"live launch drop-in drift: {name}")
    try:
        activation_metadata = layout.activation_root.lstat()
    except OSError as error:
        raise InstallError(f"cannot inspect activation root: {error}") from error
    if (
        not stat.S_ISDIR(activation_metadata.st_mode)
        or activation_metadata.st_uid != owner_uid
        or activation_metadata.st_gid != owner_gid
        or stat.S_IMODE(activation_metadata.st_mode) != 0o755
    ):
        raise InstallError("activation root authority drift")
    for name in SOCKET_NAMES:
        path = layout.activation_root / name
        try:
            metadata = path.lstat()
            target = os.readlink(path)
        except OSError as error:
            raise InstallError(
                f"cannot inspect launch activation: {error}"
            ) from error
        if (
            not stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or target != f"../{name}"
        ):
            raise InstallError(f"launch activation drift: {name}")


def _read_regular_owned(
    path: Path,
    mode: int,
    owner_uid: int,
    owner_gid: int,
    *,
    maximum: int = MAX_SOURCE_BYTES,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise InstallError(f"cannot inspect installed file {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != owner_uid
        or before.st_gid != owner_gid
        or stat.S_IMODE(before.st_mode) != mode
        or before.st_size > maximum
    ):
        raise InstallError(f"installed file metadata drift: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InstallError(f"cannot open installed file {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(before, opened):
            raise InstallError(f"installed file changed while opening: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) != opened.st_size
            or not os.path.samestat(opened, after)
            or after.st_size != opened.st_size
        ):
            raise InstallError(f"installed file changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def _verify_fixed_parent(
    path: Path, owner_uid: int, owner_gid: int, mode: int
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise InstallError(f"cannot inspect fixed parent {path}: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise InstallError(f"fixed parent authority drift: {path}")


def _verify_authority_ancestry(
    layout: Layout, owner_uid: int, owner_gid: int
) -> None:
    """Bind every replace-capable directory below the trusted OS anchors."""

    directories = (
        (layout.install_root.parent, 0o755),
        (layout.guided_path.parent.parent.parent, 0o755),
        (layout.guided_path.parent.parent, 0o555),
        (layout.guided_path.parent, 0o555),
        (layout.core_authority_path.parent.parent.parent, 0o755),
        (layout.core_authority_path.parent.parent, 0o755),
        (layout.core_authority_path.parent, 0o700),
        (layout.unit_root.parent.parent, 0o755),
        (layout.unit_root.parent, 0o755),
        (layout.unit_root, 0o755),
    )
    for path, mode in directories:
        _verify_fixed_parent(path, owner_uid, owner_gid, mode)


@contextlib.contextmanager
def _exclusive_install_lock(
    layout: Layout, owner_uid: int, owner_gid: int
) -> Iterator[None]:
    _verify_fixed_parent(
        layout.install_lock_path.parent, owner_uid, owner_gid, 0o755
    )
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(
            layout.install_lock_path,
            flags | os.O_CREAT | os.O_EXCL,
            0o000,
        )
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(layout.install_lock_path, flags)
        except OSError as error:
            raise InstallError(f"cannot open install lock: {error}") from error
    except OSError as error:
        raise InstallError(f"cannot create install lock: {error}") from error
    created_node: CreatedNode | None = None
    locked = False
    primary: BaseException | None = None
    try:
        deadline = time.monotonic() + (2.0 if created else 0.0)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN):
                    raise InstallError(
                        f"cannot lock launch installation: {error}"
                    ) from error
                if not created or time.monotonic() >= deadline:
                    raise InstallError(
                        "another launch installation is active"
                    ) from error
                time.sleep(0.01)

        try:
            opened = os.fstat(descriptor)
            if created:
                created_node = CreatedNode(
                    layout.install_lock_path,
                    opened.st_dev,
                    opened.st_ino,
                    "file",
                )
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    raise InstallError("created install lock identity drift")
                os.fchown(descriptor, owner_uid, owner_gid)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                _fsync_directory(layout.install_lock_path.parent)
            metadata = os.fstat(descriptor)
            path_metadata = layout.install_lock_path.lstat()
        except OSError as error:
            raise InstallError(f"cannot validate install lock: {error}") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not os.path.samestat(metadata, path_metadata)
        ):
            raise InstallError("install lock authority drift")
    except BaseException as error:
        primary = error

    if primary is not None:
        cleanup_failures: list[str] = []
        if created:
            if created_node is None:
                cleanup_failures.append(
                    "remove: created lock identity is unavailable"
                )
            else:
                try:
                    path_metadata = layout.install_lock_path.lstat()
                    if (
                        path_metadata.st_dev != created_node.device
                        or path_metadata.st_ino != created_node.inode
                        or not stat.S_ISREG(path_metadata.st_mode)
                    ):
                        raise InstallError("created install lock identity changed")
                    layout.install_lock_path.unlink()
                    _fsync_directory(layout.install_lock_path.parent)
                except FileNotFoundError:
                    pass
                except (OSError, InstallError) as error:
                    cleanup_failures.append(f"remove: {error}")
        if locked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError as error:
                cleanup_failures.append(f"unlock: {error}")
        try:
            os.close(descriptor)
        except OSError as error:
            cleanup_failures.append(f"close: {error}")
        if cleanup_failures:
            raise InstallError(
                f"install lock setup failed: {primary}; cleanup failed: "
                + "; ".join(cleanup_failures)
            ) from primary
        raise primary

    try:
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _verify_core_installation(
    layout: Layout,
    runner: CommandRunner,
    owner_uid: int,
    owner_gid: int,
) -> str:
    authority_data = _read_regular_owned(
        layout.core_authority_path,
        0o400,
        owner_uid,
        owner_gid,
        maximum=4096,
    )
    try:
        authority = json.loads(authority_data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallError("core installation authority is malformed") from error
    expected_fields = {"schema", "bundle_revision", "bundle_receipt_sha256"}
    if (
        authority_data != _canonical_document(authority)
        or not isinstance(authority, dict)
        or set(authority) != expected_fields
        or authority.get("schema")
        != "codeskeptic-stability-installation-authority-v1"
        or not isinstance(authority.get("bundle_revision"), str)
        or GIT_SHA1.fullmatch(authority["bundle_revision"]) is None
        or not isinstance(authority.get("bundle_receipt_sha256"), str)
        or SHA256.fullmatch(authority["bundle_receipt_sha256"]) is None
    ):
        raise InstallError("core installation authority drift")
    _read_regular_owned(
        layout.core_producer_path, 0o555, owner_uid, owner_gid
    )
    _read_regular_owned(
        layout.core_receipt_path,
        0o400,
        owner_uid,
        owner_gid,
        maximum=64 * 1024,
    )
    completed = runner([
        "/usr/bin/python3",
        "-B",
        str(layout.core_producer_path),
        "verify-install-filesystem",
        "--receipt",
        str(layout.core_receipt_path),
        "--expected-revision",
        authority["bundle_revision"],
        "--expected-bundle-receipt-sha256",
        authority["bundle_receipt_sha256"],
    ])
    if completed.returncode != 0:
        raise InstallError("core installation filesystem verification failed")
    return _sha256(authority_data)


def _install_launch_boundary_locked(
    identity: OperatorIdentity,
    *,
    source_root: Path = SOURCE_ROOT,
    layout: Layout = Layout(),
    runner: CommandRunner = _default_runner,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> str:
    _verify_authority_ancestry(layout, owner_uid, owner_gid)
    payload = prepare_payload(source_root, identity)
    if owner_uid == 0 and owner_gid == 0:
        guided_sha256 = _guided_hash(layout.guided_path)
    else:
        guided_sha256 = _sha256(
            _read_regular_owned(
                layout.guided_path, 0o555, owner_uid, owner_gid
            )
        )
    core_authority_sha256 = _verify_core_installation(
        layout, runner, owner_uid, owner_gid
    )

    if layout.install_root.exists() or layout.install_root.is_symlink():
        try:
            verify_installation(
                layout,
                identity,
                payload,
                guided_sha256,
                core_authority_sha256,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        except (InstallError, OSError) as error:
            raise InstallError(
                "existing launch authority is not exactly reusable; "
                "an interrupted or partial one-time installation requires "
                f"a separately reviewed administrator recovery: {error}"
            ) from error
        _run_systemctl(runner, "daemon-reload")
        states = _verify_loaded_unit_authority(runner, layout, identity)
        unique_states = set(states.values())
        if len(unique_states) != 1:
            raise InstallError("reused launch socket state is mixed")
        state = unique_states.pop()
        if state == ("active", "listening"):
            _verify_live_sockets(
                runner,
                layout,
                identity,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            return "reused"
        if state != ("inactive", "dead"):
            raise InstallError("reused launch socket state drift")
        _verify_no_active_instances(runner)
        try:
            _run_systemctl(runner, "start", *SOCKET_NAMES)
            _verify_live_sockets(
                runner,
                layout,
                identity,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        except BaseException as primary:
            try:
                _stop_and_verify_quiescent(runner, layout)
            except BaseException as cleanup:
                raise InstallError(
                    f"reused installation activation failed: {primary}; "
                    f"quiescence failed: {cleanup}"
                ) from primary
            if isinstance(primary, InstallError):
                raise primary
            raise InstallError(
                f"reused installation activation failed: {primary}"
            ) from primary
        return "reused"

    for name in UNIT_NAMES:
        path = layout.unit_root / name
        if path.exists() or path.is_symlink():
            raise InstallError(f"live unit target is occupied: {path}")
    for name in SERVICE_NAMES:
        path = layout.unit_root / f"{name}.d"
        if path.exists() or path.is_symlink():
            raise InstallError(f"live drop-in target is occupied: {path}")
    for name in SOCKET_NAMES:
        path = layout.activation_root / name
        if path.exists() or path.is_symlink():
            raise InstallError(f"activation target is occupied: {path}")
    _verify_no_active_instances(runner)
    _run_systemctl(runner, "daemon-reload")
    _verify_no_live_socket_authority(runner, layout)
    created: list[CreatedNode] = []
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{layout.install_root.name}.install-",
            dir=layout.install_root.parent,
        )
    )
    temporary_node: CreatedNode | None = None
    published = False
    sockets_may_be_active = False
    primary: BaseException | None = None
    temporary_cleanup_failure: BaseException | None = None
    try:
        temporary_metadata = temporary.lstat()
        temporary_node = CreatedNode(
            temporary,
            temporary_metadata.st_dev,
            temporary_metadata.st_ino,
            "directory",
        )
        if not stat.S_ISDIR(temporary_metadata.st_mode):
            raise InstallError("temporary package identity drift")
        os.chown(temporary, owner_uid, owner_gid)
        os.chmod(temporary, 0o700)
        for name, mode in PACKAGE_MODES.items():
            _write_new(
                temporary / name, payload[name], mode, owner_uid, owner_gid
            )
        receipt_data = _canonical_document(
            _receipt(
                layout,
                identity,
                payload,
                guided_sha256,
                core_authority_sha256,
            )
        )
        sidecar_data = (
            f"{_sha256(receipt_data)}  {RECEIPT_NAME}\n"
        ).encode("ascii")
        _write_new(
            temporary / SIDECAR_NAME,
            sidecar_data,
            0o400,
            owner_uid,
            owner_gid,
        )
        _write_new(
            temporary / RECEIPT_NAME,
            receipt_data,
            0o400,
            owner_uid,
            owner_gid,
        )
        os.chmod(temporary, 0o555)
        _fsync_directory(temporary)
        package_children = tuple(
            sorted((*PACKAGE_MODES, RECEIPT_NAME, SIDECAR_NAME))
        )
        prepared_root = temporary.lstat()
        if (
            temporary_node is None
            or prepared_root.st_dev != temporary_node.device
            or prepared_root.st_ino != temporary_node.inode
            or not stat.S_ISDIR(prepared_root.st_mode)
            or prepared_root.st_uid != owner_uid
            or prepared_root.st_gid != owner_gid
            or stat.S_IMODE(prepared_root.st_mode) != 0o555
            or tuple(sorted(path.name for path in temporary.iterdir()))
            != package_children
        ):
            raise InstallError("prepared launch package authority drift")
        publication_nodes = [
            CreatedNode(
                layout.install_root,
                prepared_root.st_dev,
                prepared_root.st_ino,
                "directory",
            )
        ]
        expected_modes = {
            **PACKAGE_MODES,
            RECEIPT_NAME: 0o400,
            SIDECAR_NAME: 0o400,
        }
        for name in package_children:
            metadata = (temporary / name).lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != owner_uid
                or metadata.st_gid != owner_gid
                or stat.S_IMODE(metadata.st_mode) != expected_modes[name]
            ):
                raise InstallError("prepared launch package file drift")
            publication_nodes.append(
                CreatedNode(
                    layout.install_root / name,
                    metadata.st_dev,
                    metadata.st_ino,
                    "file",
                )
            )
        publication_nodes.append(
            CreatedNode(
                layout.install_root,
                prepared_root.st_dev,
                prepared_root.st_ino,
                "directory-open",
                children=package_children,
            )
        )
        publication_start = len(created)
        try:
            created.extend(publication_nodes)
            _rename_noreplace(temporary, layout.install_root)
        except BaseException:
            root_status = _node_path_status(publication_nodes[0])
            if root_status not in ("match", "unknown"):
                del created[publication_start:]
            raise
        published = True
        _fsync_directory(layout.install_root.parent)

        for name in UNIT_NAMES:
            path = layout.unit_root / name
            _write_new(
                path,
                payload[name],
                0o444,
                owner_uid,
                owner_gid,
                created_nodes=created,
            )
        for name in SERVICE_NAMES:
            directory = layout.unit_root / f"{name}.d"
            _create_directory_recorded(
                directory,
                0o755,
                owner_uid,
                owner_gid,
                created,
            )
            path = directory / TIMEOUT_DROPIN_NAME
            _write_new(
                path,
                payload[TIMEOUT_DROPIN_SOURCE],
                0o444,
                owner_uid,
                owner_gid,
                created_nodes=created,
            )
            _fsync_directory(directory)
        _fsync_directory(layout.unit_root)

        if not layout.activation_root.exists():
            _create_directory_recorded(
                layout.activation_root,
                0o755,
                owner_uid,
                owner_gid,
                created,
            )
        activation_metadata = layout.activation_root.lstat()
        if (
            not stat.S_ISDIR(activation_metadata.st_mode)
            or activation_metadata.st_uid != owner_uid
            or activation_metadata.st_gid != owner_gid
            or stat.S_IMODE(activation_metadata.st_mode) != 0o755
        ):
            raise InstallError("activation root authority drift")
        for name in SOCKET_NAMES:
            path = layout.activation_root / name
            target = f"../{name}"
            _create_symlink_recorded(
                path,
                target,
                owner_uid,
                owner_gid,
                created,
            )
        _fsync_directory(layout.activation_root)
        _fsync_directory(layout.unit_root)

        sockets_may_be_active = True
        _run_systemctl(runner, "daemon-reload")
        _verify_loaded_unit_authority(
            runner, layout, identity, require_inactive=True
        )
        _run_systemctl(runner, "start", *SOCKET_NAMES)
        _verify_live_sockets(
            runner,
            layout,
            identity,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        verify_installation(
            layout,
            identity,
            payload,
            guided_sha256,
            core_authority_sha256,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        return "created"
    except BaseException as error:
        primary = error
    finally:
        if not published:
            temporary_failures = _cleanup_temporary_package(
                temporary_node,
                set((*PACKAGE_MODES, RECEIPT_NAME, SIDECAR_NAME)),
            )
            if temporary_failures:
                temporary_cleanup_failure = InstallError(
                    "; ".join(temporary_failures)
                )
    if primary is None:
        raise InstallError("installation failed without a primary error")
    cleanup_failures: list[str] = []
    if temporary_cleanup_failure is not None:
        cleanup_failures.append(
            f"temporary staging cleanup: {temporary_cleanup_failure}"
        )
    sockets_stopped = not sockets_may_be_active
    if sockets_may_be_active:
        try:
            _stop_and_verify_quiescent(runner, layout)
            sockets_stopped = True
        except BaseException as error:
            cleanup_failures.append(f"socket stop: {error}")
    if sockets_stopped:
        cleanup_failures.extend(_rollback(created))
    else:
        cleanup_failures.append(
            "on-disk rollback refused while launch sockets may be active"
        )
    try:
        _run_systemctl(runner, "daemon-reload")
    except BaseException as error:
        cleanup_failures.append(f"daemon reload: {error}")
    if cleanup_failures:
        raise InstallError(
            f"installation failed: {primary}; rollback incomplete: "
            + "; ".join(cleanup_failures)
        ) from primary
    if isinstance(primary, InstallError):
        raise primary
    raise InstallError(f"launch installation failed: {primary}") from primary


def install_launch_boundary(
    identity: OperatorIdentity,
    *,
    source_root: Path = SOURCE_ROOT,
    layout: Layout = Layout(),
    runner: CommandRunner = _default_runner,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> str:
    with _exclusive_install_lock(layout, owner_uid, owner_gid):
        return _install_launch_boundary_locked(
            identity,
            source_root=source_root,
            layout=layout,
            runner=runner,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )


def _operator_from_sudo_environment() -> OperatorIdentity:
    user = os.environ.get("SUDO_USER", "")
    uid_text = os.environ.get("SUDO_UID", "")
    if not uid_text.isascii() or not uid_text.isdecimal():
        raise InstallError("run the installer once through sudo as the operator")
    return resolve_operator_identity(int(uid_text), user)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install or verify the fixed P10-09 launch boundary"
    )
    parser.add_argument("command", choices=("install", "verify"))
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise InstallError("launch installation requires one root authorization")
        identity = _operator_from_sudo_environment()
        layout = Layout()
        if arguments.command == "verify":
            with _exclusive_install_lock(layout, 0, 0):
                payload = prepare_payload(SOURCE_ROOT, identity)
                guided_sha256 = _guided_hash(GUIDED_PATH)
                core_authority_sha256 = _verify_core_installation(
                    layout, _default_runner, 0, 0
                )
                verify_installation(
                    layout,
                    identity,
                    payload,
                    guided_sha256,
                    core_authority_sha256,
                )
                _verify_loaded_unit_authority(
                    _default_runner, layout, identity
                )
                _verify_live_sockets(_default_runner, layout, identity)
            print("CODESKEPTIC_LAUNCH_INSTALLATION_VERIFIED")
            return 0
        result = install_launch_boundary(identity)
        print(f"CODESKEPTIC_LAUNCH_INSTALLATION_{result.upper()}")
        return 0
    except (InstallError, OSError, subprocess.SubprocessError) as error:
        print(f"CODESKEPTIC_LAUNCH_INSTALLATION_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
