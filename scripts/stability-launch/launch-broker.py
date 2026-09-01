#!/usr/bin/env python3
"""Root side of the fixed, payload-free P10-09 launch boundary."""

from __future__ import annotations

import dataclasses
import grp
import hashlib
import json
import os
import pwd
import re
import select
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import Callable


INSTALL_ROOT = Path("/opt/codeskeptic-p10-09-launch")
RECEIPT_PATH = INSTALL_ROOT / "receipt.json"
RECEIPT_SIDECAR_PATH = INSTALL_ROOT / "receipt.json.sha256"
GUIDED_PATH = Path(
    "/opt/codeskeptic-p10-09/operator/guided-stability.sh"
)
CORE_AUTHORITY_PATH = Path(
    "/var/lib/codeskeptic-p10-09/installation-authority.json"
)
UNIT_ROOT = Path("/etc/systemd/system")
ACTIVATION_ROOT = UNIT_ROOT / "sockets.target.wants"
RUNTIME_ROOT = Path("/run/codeskeptic-p10-09-launch")

SCHEMA = "codeskeptic-stability-launch-installation-v1"
RESULT_SCHEMA = "CODESKEPTIC_LAUNCH_RESULT_V1"
MAX_RECEIPT_BYTES = 16 * 1024
MAX_SIDECAR_BYTES = 1024
MAX_RESULT_BYTES = 128
PAYLOAD_TIMEOUT_SECONDS = 2.0
GUIDED_TIMEOUT_SECONDS = 15 * 60
SYSTEMD_QUERY_TIMEOUT_SECONDS = 10
SYSTEMCTL = "/usr/bin/systemctl"

PACKAGE_MODES = {
    "README.md": 0o444,
    "launch-broker.py": 0o555,
    "launch-client.py": 0o555,
    "codeskeptic-p10-09-campaign.socket": 0o444,
    "codeskeptic-p10-09-campaign@.service": 0o444,
    "codeskeptic-p10-09-probe.socket": 0o444,
    "codeskeptic-p10-09-probe@.service": 0o444,
    "timeout-stop-terminate.conf": 0o444,
}
UNIT_NAMES = (
    "codeskeptic-p10-09-campaign.socket",
    "codeskeptic-p10-09-campaign@.service",
    "codeskeptic-p10-09-probe.socket",
    "codeskeptic-p10-09-probe@.service",
)
SOCKET_NAMES = (
    "codeskeptic-p10-09-campaign.socket",
    "codeskeptic-p10-09-probe.socket",
)
SERVICE_NAMES = (
    "codeskeptic-p10-09-campaign@.service",
    "codeskeptic-p10-09-probe@.service",
)
TIMEOUT_DROPIN_NAME = "10-timeout-abort.conf"
TIMEOUT_DROPIN_SOURCE = "timeout-stop-terminate.conf"
SOCKET_PATHS = {
    "campaign": RUNTIME_ROOT / "campaign.sock",
    "probe": RUNTIME_ROOT / "probe.sock",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
GROUP_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class BrokerError(RuntimeError):
    """Installed authority or a launch attempt violated the fixed contract."""


def _require_peer_half_close(
    connection: socket.socket, timeout: float
) -> None:
    """Require Linux's explicit peer-write-half-close indication."""

    if not hasattr(select, "POLLRDHUP"):
        raise BrokerError("kernel peer half-close signaling is unavailable")
    poller = select.poll()
    descriptor = connection.fileno()
    poller.register(
        descriptor,
        select.POLLRDHUP | select.POLLERR | select.POLLHUP | select.POLLNVAL,
    )
    milliseconds = max(1, int(timeout * 1000 + 0.999))
    events = poller.poll(milliseconds)
    if len(events) != 1 or events[0][0] != descriptor:
        raise BrokerError("launch client did not half-close its request")
    event = events[0][1]
    if event & (select.POLLERR | select.POLLNVAL) or not event & select.POLLRDHUP:
        raise BrokerError("launch client did not half-close its request")


@dataclasses.dataclass(frozen=True)
class OperatorIdentity:
    uid: int
    user: str
    gid: int
    group: str


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    pid: int
    uid: int
    gid: int


@dataclasses.dataclass(frozen=True)
class GuidedInvocation:
    argv: tuple[str, ...]
    environment: dict[str, str]


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


def _read_fixed_file(
    path: Path,
    *,
    maximum: int,
    owner_uid: int,
    owner_gid: int,
    mode: int,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise BrokerError(f"cannot inspect fixed file {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != owner_uid
        or before.st_gid != owner_gid
        or stat.S_IMODE(before.st_mode) != mode
        or before.st_size > maximum
    ):
        raise BrokerError(f"fixed file metadata drift: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BrokerError(f"cannot open fixed file {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(before, opened):
            raise BrokerError(f"fixed file changed while opening: {path}")
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
            raise BrokerError(f"fixed file changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def _fixed_hash(
    path: Path,
    *,
    mode: int,
    owner_uid: int = 0,
    owner_gid: int = 0,
    maximum: int = 8 * 1024 * 1024,
) -> str:
    return hashlib.sha256(
        _read_fixed_file(
            path,
            maximum=maximum,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=mode,
        )
    ).hexdigest()


def _verify_fixed_parent(
    path: Path, *, owner_uid: int, owner_gid: int, mode: int = 0o755
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BrokerError(f"cannot inspect fixed parent {path}: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise BrokerError(f"fixed parent authority drift: {path}")


def _verify_authority_ancestry(
    *,
    install_root: Path,
    unit_root: Path,
    guided_path: Path,
    core_authority_path: Path,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Bind every replace-capable directory below the trusted OS anchors."""

    directories = (
        (install_root.parent, 0o755),
        (guided_path.parent.parent.parent, 0o755),
        (guided_path.parent.parent, 0o555),
        (guided_path.parent, 0o555),
        (core_authority_path.parent.parent.parent, 0o755),
        (core_authority_path.parent.parent, 0o755),
        (core_authority_path.parent, 0o700),
        (unit_root.parent.parent, 0o755),
        (unit_root.parent, 0o755),
        (unit_root, 0o755),
    )
    for path, mode in directories:
        _verify_fixed_parent(
            path,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=mode,
        )


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise BrokerError(f"{label} fields drift")
    return value


def _operator_identity(value: object) -> OperatorIdentity:
    operator = _exact_dict(
        value, {"uid", "user", "gid", "group"}, "operator identity"
    )
    uid = operator["uid"]
    user = operator["user"]
    gid = operator["gid"]
    group = operator["group"]
    if (
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or not 0 < uid < 2**31
        or isinstance(gid, bool)
        or not isinstance(gid, int)
        or not 0 < gid < 2**31
        or not isinstance(user, str)
        or USER_NAME.fullmatch(user) is None
        or not isinstance(group, str)
        or GROUP_NAME.fullmatch(group) is None
    ):
        raise BrokerError("operator identity is malformed")
    try:
        by_uid = pwd.getpwuid(uid)
        by_user = pwd.getpwnam(user)
        by_gid = grp.getgrgid(gid)
        by_group = grp.getgrnam(group)
    except KeyError as error:
        raise BrokerError("operator account is unavailable") from error
    if (
        by_uid.pw_name != user
        or by_uid.pw_gid != gid
        or by_user.pw_uid != uid
        or by_user.pw_gid != gid
        or by_gid.gr_name != group
        or by_group.gr_gid != gid
    ):
        raise BrokerError("operator account identity drift")
    return OperatorIdentity(uid=uid, user=user, gid=gid, group=group)


def read_launch_authority(
    *,
    install_root: Path = INSTALL_ROOT,
    unit_root: Path = UNIT_ROOT,
    activation_root: Path = ACTIVATION_ROOT,
    guided_path: Path = GUIDED_PATH,
    core_authority_path: Path = CORE_AUTHORITY_PATH,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> OperatorIdentity:
    """Rederive the separate launcher receipt and every live root-owned byte."""

    _verify_authority_ancestry(
        install_root=install_root,
        unit_root=unit_root,
        guided_path=guided_path,
        core_authority_path=core_authority_path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )

    try:
        root_metadata = install_root.lstat()
        root_names = sorted(path.name for path in install_root.iterdir())
    except OSError as error:
        raise BrokerError(f"cannot inspect launch installation: {error}") from error
    expected_names = sorted((*PACKAGE_MODES, "receipt.json", "receipt.json.sha256"))
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != owner_uid
        or root_metadata.st_gid != owner_gid
        or stat.S_IMODE(root_metadata.st_mode) != 0o555
        or root_names != expected_names
    ):
        raise BrokerError("launch installation inventory drift")

    receipt_data = _read_fixed_file(
        install_root / "receipt.json",
        maximum=MAX_RECEIPT_BYTES,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o400,
    )
    sidecar_data = _read_fixed_file(
        install_root / "receipt.json.sha256",
        maximum=MAX_SIDECAR_BYTES,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o400,
    )
    expected_sidecar = (
        f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n"
    ).encode("ascii")
    if sidecar_data != expected_sidecar:
        raise BrokerError("launch receipt sidecar drift")
    try:
        value = json.loads(receipt_data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrokerError("launch receipt is malformed") from error
    if receipt_data != _canonical_document(value):
        raise BrokerError("launch receipt is not canonical")
    receipt = _exact_dict(
        value,
        {
            "schema",
            "install_root",
            "operator",
            "guided",
            "core_authority",
            "files",
            "unit_paths",
            "dropin_paths",
            "activation_links",
        },
        "launch receipt",
    )
    if receipt["schema"] != SCHEMA or receipt["install_root"] != str(install_root):
        raise BrokerError("launch receipt identity drift")
    identity = _operator_identity(receipt["operator"])

    core_authority = _exact_dict(
        receipt["core_authority"], {"path", "sha256"}, "core authority"
    )
    if (
        core_authority["path"] != str(core_authority_path)
        or not isinstance(core_authority["sha256"], str)
        or SHA256.fullmatch(core_authority["sha256"]) is None
        or _fixed_hash(
            core_authority_path,
            mode=0o400,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            maximum=4096,
        )
        != core_authority["sha256"]
    ):
        raise BrokerError("installed core authority drift")

    files = _exact_dict(receipt["files"], set(PACKAGE_MODES), "launch files")
    for name, mode in PACKAGE_MODES.items():
        expected = files[name]
        if (
            not isinstance(expected, str)
            or SHA256.fullmatch(expected) is None
            or _fixed_hash(
                install_root / name,
                mode=mode,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            != expected
        ):
            raise BrokerError(f"installed launch file identity drift: {name}")

    expected_unit_paths = {name: str(unit_root / name) for name in UNIT_NAMES}
    if receipt["unit_paths"] != expected_unit_paths:
        raise BrokerError("launch unit path authority drift")
    for name in UNIT_NAMES:
        if _fixed_hash(
            unit_root / name,
            mode=0o444,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        ) != files[name]:
            raise BrokerError(f"live launch unit identity drift: {name}")

    expected_dropin_paths = {
        name: str(unit_root / f"{name}.d" / TIMEOUT_DROPIN_NAME)
        for name in SERVICE_NAMES
    }
    if receipt["dropin_paths"] != expected_dropin_paths:
        raise BrokerError("launch drop-in path authority drift")
    for name in SERVICE_NAMES:
        directory = unit_root / f"{name}.d"
        try:
            metadata = directory.lstat()
            children = sorted(path.name for path in directory.iterdir())
        except OSError as error:
            raise BrokerError(
                f"cannot inspect launch drop-in directory: {error}"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or children != [TIMEOUT_DROPIN_NAME]
            or _fixed_hash(
                directory / TIMEOUT_DROPIN_NAME,
                mode=0o444,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            != files[TIMEOUT_DROPIN_SOURCE]
        ):
            raise BrokerError(f"launch drop-in identity drift: {name}")

    expected_links = {
        name: str(activation_root / name) for name in SOCKET_NAMES
    }
    if receipt["activation_links"] != expected_links:
        raise BrokerError("launch activation authority drift")
    try:
        activation_metadata = activation_root.lstat()
    except OSError as error:
        raise BrokerError(f"cannot inspect activation root: {error}") from error
    if (
        not stat.S_ISDIR(activation_metadata.st_mode)
        or activation_metadata.st_uid != owner_uid
        or activation_metadata.st_gid != owner_gid
        or stat.S_IMODE(activation_metadata.st_mode) != 0o755
    ):
        raise BrokerError("launch activation root authority drift")
    for name in SOCKET_NAMES:
        path = activation_root / name
        try:
            metadata = path.lstat()
            target = os.readlink(path)
        except OSError as error:
            raise BrokerError(f"cannot inspect launch activation: {error}") from error
        if (
            not stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or target != f"../{name}"
        ):
            raise BrokerError(f"launch activation identity drift: {name}")

    guided = _exact_dict(receipt["guided"], {"path", "sha256"}, "guided authority")
    if (
        guided["path"] != str(guided_path)
        or not isinstance(guided["sha256"], str)
        or SHA256.fullmatch(guided["sha256"]) is None
        or _fixed_hash(
            guided_path,
            mode=0o555,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        != guided["sha256"]
    ):
        raise BrokerError("installed guided authority drift")
    return identity


def _close_ancillary_fds(ancillary: list[tuple[int, int, bytes]]) -> None:
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        width = struct.calcsize("i")
        for offset in range(0, len(data) - (len(data) % width), width):
            descriptor = struct.unpack_from("i", data, offset)[0]
            try:
                os.close(descriptor)
            except OSError:
                pass


def authorize_connection(
    connection: socket.socket,
    *,
    expected_path: Path | None,
    authorized_uid: int,
    payload_timeout: float = PAYLOAD_TIMEOUT_SECONDS,
) -> PeerIdentity:
    """Authorize only SO_PEERCRED and an empty half-closed request."""

    if connection.family != socket.AF_UNIX:
        raise BrokerError("launch connection is not AF_UNIX")
    if (
        connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        != socket.SOCK_STREAM
    ):
        raise BrokerError("launch connection is not SOCK_STREAM")
    if expected_path is not None and connection.getsockname() != str(expected_path):
        raise BrokerError("launch connection local path drift")
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrokerError("kernel peer credentials are unavailable")
    size = struct.calcsize("3i")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid == 0 or uid != authorized_uid or gid < 0:
        raise BrokerError("launch peer is not the installed operator")

    previous_timeout = connection.gettimeout()
    flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    try:
        _require_peer_half_close(connection, payload_timeout)
        connection.settimeout(payload_timeout)
        payload, ancillary, message_flags, _address = connection.recvmsg(
            1, socket.CMSG_SPACE(struct.calcsize("i")), flags
        )
    except TimeoutError as error:
        raise BrokerError("launch client did not half-close its request") from error
    finally:
        connection.settimeout(previous_timeout)
    _close_ancillary_fds(ancillary)
    forbidden_flags = getattr(socket, "MSG_TRUNC", 0) | getattr(
        socket, "MSG_CTRUNC", 0
    )
    if payload != b"" or ancillary or message_flags & forbidden_flags:
        raise BrokerError("launch client payload or ancillary data is forbidden")
    return PeerIdentity(pid=pid, uid=uid, gid=gid)


def guided_invocation(mode: str, identity: OperatorIdentity) -> GuidedInvocation:
    if mode == "campaign":
        argv = (str(GUIDED_PATH), "--root")
    elif mode == "probe":
        argv = (str(GUIDED_PATH), "--root", "--probe-only")
    else:
        raise BrokerError("launch mode is not fixed")
    environment = {
        "HOME": "/root",
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": "root",
        "PATH": "/usr/sbin:/usr/bin",
        "SUDO_GID": str(identity.gid),
        "SUDO_UID": str(identity.uid),
        "SUDO_USER": identity.user,
        "USER": "root",
    }
    return GuidedInvocation(argv=argv, environment=environment)


def _fixed_command(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            timeout=SYSTEMD_QUERY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BrokerError(f"fixed systemd query failed: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[:512]
        raise BrokerError(f"fixed systemd query rejected: {detail}")
    return completed


def _systemctl_properties(
    runner: CommandRunner, name: str, fields: tuple[str, ...]
) -> dict[str, str]:
    completed = runner(
        [
            SYSTEMCTL,
            "show",
            "--no-pager",
            *(f"--property={field}" for field in fields),
            name,
        ]
    )
    output = completed.stdout
    if (
        completed.returncode != 0
        or not isinstance(output, bytes)
        or len(output) > 16 * 1024
    ):
        raise BrokerError("effective systemd authority output is malformed")
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
        pairs = [line.split("=", 1) for line in lines]
    except UnicodeDecodeError as error:
        raise BrokerError("effective systemd authority output is malformed") from error
    if (
        len(lines) != len(fields)
        or any(len(pair) != 2 for pair in pairs)
        or len({pair[0] for pair in pairs}) != len(fields)
        or {pair[0] for pair in pairs} != set(fields)
    ):
        raise BrokerError("effective systemd authority output is malformed")
    return {key: value for key, value in pairs}


def verify_effective_systemd_authority(
    mode: str,
    identity: OperatorIdentity,
    *,
    pid: int | None = None,
    runner: CommandRunner = _fixed_command,
    unit_root: Path = UNIT_ROOT,
) -> None:
    if mode not in SOCKET_PATHS:
        raise BrokerError("effective systemd mode is not fixed")
    process_id = os.getpid() if pid is None else pid
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise BrokerError("effective systemd process identity is malformed")
    completed = runner([SYSTEMCTL, "whoami", str(process_id)])
    output = completed.stdout
    if completed.returncode != 0 or not isinstance(output, bytes) or len(output) > 512:
        raise BrokerError("effective systemd instance identity is malformed")
    try:
        decoded = output.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise BrokerError("effective systemd instance identity is malformed") from error
    if not decoded.endswith("\n") or decoded.count("\n") != 1:
        raise BrokerError("effective systemd instance identity is malformed")
    instance = decoded[:-1]
    prefix = f"codeskeptic-p10-09-{mode}@"
    if (
        not instance.startswith(prefix)
        or not instance.endswith(".service")
        or instance == f"{prefix}.service"
        or any(character.isspace() or character == "/" for character in instance)
    ):
        raise BrokerError("effective systemd instance identity drift")

    service_name = f"codeskeptic-p10-09-{mode}@.service"
    service_fields = (
        "Id",
        "LoadState",
        "FragmentPath",
        "DropInPaths",
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
    service = _systemctl_properties(runner, instance, service_fields)
    expected_start = (
        "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B "
        f"/opt/codeskeptic-p10-09-launch/launch-broker.py {mode} ; "
    )
    if (
        service["Id"] != instance
        or service["LoadState"] != "loaded"
        or service["FragmentPath"] != str(unit_root / service_name)
        or service["DropInPaths"]
        != str(unit_root / f"{service_name}.d" / "10-timeout-abort.conf")
        or not service["ExecStart"].startswith(expected_start)
        or service["ExecStart"].count("{") != 1
        or service["ExecStart"].count("}") != 1
        or any(
            service[field]
            for field in (
                "ExecStartPre",
                "ExecCondition",
                "ExecStartPost",
                "ExecReload",
                "ExecStop",
                "ExecStopPost",
            )
        )
        or service["User"] != "root"
        or service["Group"] != "root"
        or service["StandardInput"] != "socket"
        or service["StandardOutput"] != "journal"
        or service["StandardError"] != "journal"
        or service["RefuseManualStart"] != "yes"
        or service["IgnoreOnIsolate"] != "yes"
        or service["RuntimeDirectory"] != "codeskeptic-p10-09"
        or service["RuntimeDirectoryMode"] != "0700"
        or service["RuntimeDirectoryPreserve"] != "yes"
        or service["RuntimeMaxUSec"] != "16min"
        or service["TimeoutStopFailureMode"] != "terminate"
    ):
        raise BrokerError("effective systemd service authority drift")

    socket_name = f"codeskeptic-p10-09-{mode}.socket"
    socket_fields = (
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "FragmentPath",
        "DropInPaths",
        "Listen",
        "SocketUser",
        "SocketGroup",
        "SocketMode",
        "Accept",
        "AcceptFileDescriptors",
        "IgnoreOnIsolate",
    )
    socket_authority = _systemctl_properties(
        runner, socket_name, socket_fields
    )
    expected_socket = {
        "Id": socket_name,
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "listening",
        "FragmentPath": str(unit_root / socket_name),
        "DropInPaths": "",
        "Listen": (
            f"/run/codeskeptic-p10-09-launch/{mode}.sock "
            "(Stream)"
        ),
        "SocketUser": "root",
        "SocketGroup": identity.group,
        "SocketMode": "0660",
        "Accept": "yes",
        "AcceptFileDescriptors": "no",
        "IgnoreOnIsolate": "yes",
    }
    if socket_authority != expected_socket:
        raise BrokerError("effective systemd socket authority drift")


def _send_result(connection: socket.socket, mode: str, result: int) -> None:
    if mode not in SOCKET_PATHS or not 0 <= result <= 255:
        result = 2
    payload = f"{RESULT_SCHEMA} {mode} {result}".encode("ascii")
    if len(payload) > MAX_RESULT_BYTES:
        return
    try:
        connection.sendall(payload)
    except OSError:
        pass


def run_broker(mode: str, connection: socket.socket) -> int:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise BrokerError("launch broker must run as root")
    identity = read_launch_authority()
    authorize_connection(
        connection,
        expected_path=SOCKET_PATHS.get(mode),
        authorized_uid=identity.uid,
    )
    verify_effective_systemd_authority(mode, identity)
    invocation = guided_invocation(mode, identity)
    try:
        completed = subprocess.run(
            invocation.argv,
            check=False,
            stdin=subprocess.DEVNULL,
            env=invocation.environment,
            close_fds=True,
            timeout=GUIDED_TIMEOUT_SECONDS,
        )
        result = completed.returncode
    except subprocess.TimeoutExpired:
        result = 124
    if not 0 <= result <= 255:
        result = 1
    _send_result(connection, mode, result)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in (["campaign"], ["probe"]):
        print(
            "CODESKEPTIC_LAUNCH_BROKER_FAIL fixed mode required",
            file=sys.stderr,
        )
        return 2
    mode = arguments[0]
    connection: socket.socket | None = None
    try:
        connection = socket.socket(fileno=os.dup(0))
        return run_broker(mode, connection)
    except (BrokerError, OSError, subprocess.SubprocessError) as error:
        detail = str(error).replace("\n", " ")[:512]
        print(f"CODESKEPTIC_LAUNCH_BROKER_FAIL {detail}", file=sys.stderr)
        if connection is not None:
            _send_result(connection, mode, 2)
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
