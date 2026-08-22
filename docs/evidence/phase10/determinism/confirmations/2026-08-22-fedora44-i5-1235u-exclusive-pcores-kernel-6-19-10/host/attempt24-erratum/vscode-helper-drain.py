#!/usr/bin/python3
"""Fail closed unless VS Code and its CodeSkeptic helpers are absent.

Attempt 11 invokes only the signal-free ``--require-absent`` entry point.  The
older drain primitives remain here solely for regression comparison; the
command-line entry point cannot reach them.
"""

from __future__ import annotations

import hashlib
import os
import re
import select
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


TARGET_UID = 1000
CODE_EXE = "/usr/share/code/code"
CRASHPAD_EXE = "/usr/share/code/chrome_crashpad_handler"
DCONF_EXE = "/usr/bin/dconf"
CODEX_EXE = (
    "/home/tanzer/.vscode/extensions/openai.chatgpt-26.818.21641-linux-x64/"
    "bin/linux-x86_64/codex"
)
CODE_MODE_EXE = (
    "/home/tanzer/.vscode/extensions/openai.chatgpt-26.818.21641-linux-x64/"
    "bin/linux-x86_64/codex-code-mode-host"
)
CODEX_CMDLINE = (
    CODEX_EXE.encode("ascii")
    + b"\0-c\0features.code_mode_host=true\0app-server\0"
    + b"--analytics-default-enabled\0"
)
CODE_MODE_CMDLINE = CODE_MODE_EXE.encode("ascii") + b"\0"
KONSOLE_CRASHPAD_CMDLINE_SHA256 = (
    "aec39e4b32234ed137b454edd21476c5ce8e453aea14639f97919cfff4f54f25"
)
DESKTOP_CRASHPAD_CMDLINE_SHA256 = (
    "aa4552cfe45c751723d1c8cccb7e0a1e9d50e0453b465d10ec78d18ad651d6d7"
)
DCONF_CMDLINE_SHA256 = (
    "f6040b6bfe5c50fa9b3c6d4eb4e563bb3bdfaf25afd0d21f53683d191a3e6f95"
)
USER_MANAGER_CMDLINE = b"/usr/lib/systemd/systemd\0--user\0"
USER_MANAGER_CGROUP = (
    b"0::/user.slice/user-1000.slice/user@1000.service/init.scope\n"
)
KONSOLE_CRASHPAD_CGROUP_RE = re.compile(
    rb"0::/user\.slice/user-1000\.slice/user@1000\.service/app\.slice/"
    rb"app-org\.kde\.konsole-[1-9][0-9]*\.scope/tab\([1-9][0-9]*\)\.scope\n"
)
DESKTOP_CRASHPAD_CGROUP_RE = re.compile(
    rb"0::/user\.slice/user-1000\.slice/user@1000\.service/app\.slice/"
    rb"app-code@[0-9a-f]{32}\.service\n"
)
DCONF_CGROUP_RE = re.compile(
    rb"0::/user\.slice/user-1000\.slice/user@1000\.service/app\.slice/"
    rb"app-code-[1-9][0-9]*\.scope\n"
)
APP_CODE_CGROUP_RE = re.compile(
    rb"0::/user\.slice/user-1000\.slice/user@1000\.service/app\.slice/"
    rb"(app-code-(?:[1-9][0-9]*)\.scope|"
    rb"app-code@[0-9a-f]{32}\.service)\n"
)
APP_CODE_SCOPE_RE = re.compile(r"app-code-[1-9][0-9]*\.scope")
APP_CODE_SERVICE_RE = re.compile(r"app-code@[0-9a-f]{32}\.service")
HELPER_SESSION_CGROUP_RE = re.compile(
    rb"0::/user\.slice/user-1000\.slice/session-[1-9][0-9]*\.scope\n"
)
SYSTEMCTL_ENV = {
    "HOME": "/home/tanzer",
    "USER": "tanzer",
    "LOGNAME": "tanzer",
    "PATH": "/usr/sbin:/usr/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "XDG_RUNTIME_DIR": "/run/user/1000",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
}
COMMON_UNIT_PROPERTIES = (
    "Id",
    "Description",
    "LoadState",
    "ActiveState",
    "SubState",
    "FreezerState",
    "FragmentPath",
    "SourcePath",
    "UnitFileState",
    "RefuseManualStart",
    "RefuseManualStop",
    "Transient",
    "Result",
    "ControlGroup",
    "KillMode",
    "SendSIGKILL",
)


class DrainError(RuntimeError):
    pass


class ProcessGone(DrainError):
    pass


@dataclass(frozen=True)
class Snapshot:
    pid: int
    comm: str
    state: str
    ppid: int
    starttime: int
    uids: tuple[int, int, int, int]
    exe: str | None
    cmdline: bytes
    cgroup: bytes


@dataclass
class Handle:
    snapshot: Snapshot
    pidfd: int


def _read_bounded(path: Path, maximum: int) -> bytes:
    try:
        with path.open("rb", buffering=0) as stream:
            data = stream.read(maximum + 1)
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessGone(str(path)) from None
    except OSError as exc:
        raise DrainError(f"cannot read {path}: {exc}") from exc
    if len(data) > maximum:
        raise DrainError(f"oversized process field: {path}")
    return data


def require_helper_session_cgroup(proc_root: Path = Path("/proc")) -> None:
    cgroup = _read_bounded(proc_root / str(os.getpid()) / "cgroup", 4096)
    if HELPER_SESSION_CGROUP_RE.fullmatch(cgroup) is None:
        raise DrainError("VS Code helper is not in a physical TTY session cgroup")


def _readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessGone(str(path)) from None
    except OSError as exc:
        raise DrainError(f"cannot read process executable {path}: {exc}") from exc


def _parse_stat(data: bytes) -> tuple[str, int, int]:
    try:
        marker = data.rindex(b") ")
        fields = data[marker + 2 :].split()
        if len(fields) < 20:
            raise ValueError("too few fields")
        state = fields[0].decode("ascii")
        ppid = int(fields[1], 10)
        starttime = int(fields[19], 10)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DrainError("malformed /proc stat identity") from exc
    if len(state) != 1 or state not in "RSDTtXZPI" or ppid < 0 or starttime <= 0:
        raise DrainError("invalid /proc stat identity")
    return state, ppid, starttime


def _parse_uids(data: bytes) -> tuple[int, int, int, int]:
    rows = [line for line in data.splitlines() if line.startswith(b"Uid:")]
    if len(rows) != 1:
        raise DrainError("missing or duplicate process Uid field")
    fields = rows[0].split()
    if len(fields) != 5:
        raise DrainError("malformed process Uid field")
    try:
        result = tuple(int(value, 10) for value in fields[1:])
    except ValueError as exc:
        raise DrainError("malformed process Uid value") from exc
    if len(result) != 4:
        raise DrainError("malformed process Uid cardinality")
    return result  # type: ignore[return-value]


def read_snapshot(pid: int, proc_root: Path = Path("/proc")) -> Snapshot:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise DrainError("invalid PID")
    root = proc_root / str(pid)
    comm_raw = _read_bounded(root / "comm", 256)
    if not comm_raw.endswith(b"\n") or comm_raw.count(b"\n") != 1:
        raise DrainError("malformed process comm")
    try:
        comm = comm_raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise DrainError("non-ASCII process comm") from exc
    state, ppid, starttime = _parse_stat(_read_bounded(root / "stat", 65536))
    uids = _parse_uids(_read_bounded(root / "status", 65536))
    cmdline = _read_bounded(root / "cmdline", 65536)
    cgroup = _read_bounded(root / "cgroup", 4096)
    exe = None if comm == "systemd" else _readlink(root / "exe")
    return Snapshot(pid, comm, state, ppid, starttime, uids, exe, cmdline, cgroup)


def _pid_directories(proc_root: Path) -> list[int]:
    try:
        names = os.listdir(proc_root)
    except OSError as exc:
        raise DrainError(f"cannot enumerate {proc_root}: {exc}") from exc
    return sorted(int(name) for name in names if name.isascii() and name.isdigit())


def collect_named(names: set[str], proc_root: Path = Path("/proc")) -> list[Snapshot]:
    result: list[Snapshot] = []
    for pid in _pid_directories(proc_root):
        try:
            comm = _read_bounded(proc_root / str(pid) / "comm", 256)
        except ProcessGone:
            continue
        expected = None
        for name in names:
            if comm == name.encode("ascii") + b"\n":
                expected = name
                break
        if expected is None:
            continue
        try:
            snapshot = read_snapshot(pid, proc_root)
        except ProcessGone:
            continue
        if snapshot.comm != expected:
            raise DrainError(f"process comm changed while reading PID {pid}")
        if snapshot.uids == (TARGET_UID,) * 4:
            result.append(snapshot)
    return result


def validate_user_manager(snapshot: Snapshot) -> None:
    if not (
        snapshot.comm == "systemd"
        and snapshot.state not in {"X", "Z"}
        and snapshot.ppid == 1
        and snapshot.uids == (TARGET_UID,) * 4
        and snapshot.cmdline == USER_MANAGER_CMDLINE
        and snapshot.cgroup == USER_MANAGER_CGROUP
    ):
        raise DrainError(f"unexpected tanzer user-manager identity: {snapshot.pid}")


def find_user_manager(proc_root: Path = Path("/proc")) -> Snapshot:
    matches = []
    for snapshot in collect_named({"systemd"}, proc_root):
        try:
            validate_user_manager(snapshot)
        except DrainError:
            continue
        matches.append(snapshot)
    if len(matches) != 1:
        raise DrainError(f"expected exactly one tanzer user manager, observed {len(matches)}")
    second = read_snapshot(matches[0].pid, proc_root)
    if second != matches[0]:
        raise DrainError("tanzer user-manager identity changed while reading")
    return second


def validate_code(snapshot: Snapshot) -> None:
    executable_prefix = CODE_EXE.encode("ascii")
    if not (
        snapshot.comm == "code"
        and snapshot.state not in {"X", "Z"}
        and snapshot.uids == (TARGET_UID,) * 4
        and snapshot.exe == CODE_EXE
        and snapshot.cmdline.startswith(executable_prefix)
        and len(snapshot.cmdline) > len(executable_prefix)
        and snapshot.cmdline[len(executable_prefix)] in {0, 32}
        and APP_CODE_CGROUP_RE.fullmatch(snapshot.cgroup)
    ):
        raise DrainError(f"unexpected VS Code process identity: {snapshot.pid}")


def code_unit_name(snapshot: Snapshot) -> str:
    match = APP_CODE_CGROUP_RE.fullmatch(snapshot.cgroup)
    if match is None:
        raise DrainError(f"unexpected VS Code cgroup identity: {snapshot.pid}")
    try:
        unit = match.group(1).decode("ascii")
    except UnicodeDecodeError as exc:
        raise DrainError(f"non-ASCII VS Code unit identity: {snapshot.pid}") from exc
    return unit


def _parse_systemctl_properties(output: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            raise DrainError("malformed VS Code systemd property output")
        key, value = line.split("=", 1)
        if not key or key in properties:
            raise DrainError("duplicate or empty VS Code systemd property")
        properties[key] = value
    return properties


def validate_code_unit_properties(
    unit: str,
    properties: Mapping[str, str],
    *,
    freezer_state: str = "running",
) -> None:
    is_scope = APP_CODE_SCOPE_RE.fullmatch(unit) is not None
    is_service = APP_CODE_SERVICE_RE.fullmatch(unit) is not None
    if is_scope == is_service:
        raise DrainError(f"invalid VS Code unit name: {unit}")
    expected_keys = set(COMMON_UNIT_PROPERTIES)
    if is_service:
        expected_keys.update({"Type", "MainPID", "ControlPID", "Restart"})
    if set(properties) != expected_keys:
        raise DrainError(f"VS Code unit property inventory differs: {unit}")
    expected_description = unit if is_scope else "Visual Studio Code - Text Editor"
    expected_source = "" if is_scope else "/usr/share/applications/code.desktop"
    expected = {
        "Id": unit,
        "Description": expected_description,
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "FreezerState": freezer_state,
        "FragmentPath": f"/run/user/1000/systemd/transient/{unit}",
        "SourcePath": expected_source,
        "UnitFileState": "transient",
        "RefuseManualStart": "no",
        "RefuseManualStop": "no",
        "Transient": "yes",
        "ControlGroup": (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit
        ),
        "KillMode": "control-group",
        "SendSIGKILL": "yes",
    }
    if is_service:
        expected["Restart"] = "no"
    for key, value in expected.items():
        if properties.get(key) != value:
            raise DrainError(f"VS Code unit {key} differs: {unit}")
    result = properties.get("Result")
    if is_scope and result != "success":
        raise DrainError(f"VS Code unit Result differs: {unit}")
    if is_service:
        main_pid = properties.get("MainPID", "")
        if (
            properties.get("Type") != "simple"
            or properties.get("ControlPID") != "0"
            or not main_pid.isascii()
            or not main_pid.isdigit()
        ):
            raise DrainError(f"VS Code service process identity differs: {unit}")
        if result != "success" and not (result == "exit-code" and main_pid == "0"):
            raise DrainError(f"VS Code unit Result differs: {unit}")


def validate_stopped_code_unit_properties(
    unit: str, properties: Mapping[str, str]
) -> None:
    is_scope = APP_CODE_SCOPE_RE.fullmatch(unit) is not None
    is_service = APP_CODE_SERVICE_RE.fullmatch(unit) is not None
    if is_scope == is_service:
        raise DrainError(f"invalid VS Code unit name: {unit}")
    expected_keys = set(COMMON_UNIT_PROPERTIES) - {"Description"}
    if is_service:
        expected_keys.update({"Type", "MainPID", "ControlPID", "Restart"})
    if set(properties) != expected_keys:
        raise DrainError(f"stopped VS Code unit property inventory differs: {unit}")
    common = {
        "Id": unit,
        "ActiveState": "inactive",
        "SubState": "dead",
        "FreezerState": "running",
        "RefuseManualStart": "no",
        "RefuseManualStop": "no",
        "KillMode": "control-group",
        "SendSIGKILL": "yes",
    }
    for key, value in common.items():
        if properties.get(key) != value:
            raise DrainError(f"stopped VS Code unit {key} differs: {unit}")
    load_state = properties.get("LoadState")
    if load_state == "not-found":
        expected = {
            "FragmentPath": "",
            "SourcePath": "",
            "UnitFileState": "",
            "Transient": "no",
            "ControlGroup": "",
            "Result": "success",
        }
        if is_service:
            expected.update(
                {"Type": "", "MainPID": "0", "ControlPID": "0", "Restart": "no"}
            )
    elif load_state == "loaded":
        expected = {
            "FragmentPath": f"/run/user/1000/systemd/transient/{unit}",
            "SourcePath": "" if is_scope else "/usr/share/applications/code.desktop",
            "UnitFileState": "transient",
            "Transient": "yes",
            "ControlGroup": (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit
            ),
        }
        if properties.get("Result") not in {"success", "signal"}:
            raise DrainError(f"stopped VS Code unit Result differs: {unit}")
        if is_service:
            expected.update(
                {
                    "Type": "simple",
                    "MainPID": "0",
                    "ControlPID": "0",
                    "Restart": "no",
                }
            )
    else:
        raise DrainError(f"stopped VS Code unit LoadState differs: {unit}")
    for key, value in expected.items():
        if properties.get(key) != value:
            raise DrainError(f"stopped VS Code unit {key} differs: {unit}")


def _systemctl(arguments: list[str], timeout: float = 5.0) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "--user", "--no-pager", *arguments],
            check=False,
            text=True,
            capture_output=True,
            env=SYSTEMCTL_ENV,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DrainError(f"cannot query VS Code systemd authority: {exc}") from exc
    if result.returncode != 0 or result.stderr:
        raise DrainError(
            "VS Code systemd authority failed "
            f"exit={result.returncode} stderr={result.stderr[-1000:]!r}"
        )
    return result.stdout


def _query_code_unit(unit: str) -> dict[str, str]:
    property_names = list(COMMON_UNIT_PROPERTIES)
    if APP_CODE_SERVICE_RE.fullmatch(unit):
        property_names.extend(("Type", "MainPID", "ControlPID", "Restart"))
    arguments = ["show", unit]
    for name in property_names:
        arguments.extend(("-p", name))
    properties = _parse_systemctl_properties(_systemctl(arguments))
    validate_code_unit_properties(unit, properties)
    return properties


def _query_frozen_code_unit(unit: str) -> dict[str, str]:
    property_names = list(COMMON_UNIT_PROPERTIES)
    if APP_CODE_SERVICE_RE.fullmatch(unit):
        property_names.extend(("Type", "MainPID", "ControlPID", "Restart"))
    arguments = ["show", unit]
    for name in property_names:
        arguments.extend(("-p", name))
    properties = _parse_systemctl_properties(_systemctl(arguments))
    validate_code_unit_properties(unit, properties, freezer_state="frozen")
    return properties


def _query_stopped_code_unit(unit: str) -> dict[str, str]:
    property_names = [name for name in COMMON_UNIT_PROPERTIES if name != "Description"]
    if APP_CODE_SERVICE_RE.fullmatch(unit):
        property_names.extend(("Type", "MainPID", "ControlPID", "Restart"))
    arguments = ["show", unit]
    for name in property_names:
        arguments.extend(("-p", name))
    properties = _parse_systemctl_properties(_systemctl(arguments))
    validate_stopped_code_unit_properties(unit, properties)
    return properties


def _list_code_units() -> dict[str, tuple[str, str, str]]:
    output = _systemctl(
        [
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--type=service",
            "--type=scope",
        ]
    )
    units: dict[str, tuple[str, str, str]] = {}
    for line in output.splitlines():
        fields = line.split(None, 4)
        if len(fields) != 5:
            raise DrainError("malformed VS Code systemd unit inventory")
        unit, load_state, active_state, sub_state, _description = fields
        if not unit.startswith("app-code"):
            continue
        if not (
            APP_CODE_SCOPE_RE.fullmatch(unit)
            or APP_CODE_SERVICE_RE.fullmatch(unit)
        ):
            raise DrainError(f"invalid VS Code unit in systemd inventory: {unit}")
        if unit in units:
            raise DrainError(f"duplicate VS Code unit in systemd inventory: {unit}")
        units[unit] = (load_state, active_state, sub_state)
    return dict(sorted(units.items()))


def _validate_code_unit_member(snapshot: Snapshot, user_manager_pid: int) -> None:
    code_unit_name(snapshot)
    if snapshot.comm == "code":
        validate_code(snapshot)
        return
    cmdline_sha = hashlib.sha256(snapshot.cmdline).hexdigest()
    if snapshot.comm == "chrome_crashpad" and (
        snapshot.state not in {"X", "Z"}
        and snapshot.ppid > 0
        and snapshot.uids == (TARGET_UID,) * 4
        and snapshot.exe == CRASHPAD_EXE
        and cmdline_sha == DESKTOP_CRASHPAD_CMDLINE_SHA256
        and APP_CODE_SERVICE_RE.fullmatch(code_unit_name(snapshot))
    ):
        return
    if snapshot.comm == "dconf" and (
        snapshot.state not in {"X", "Z"}
        and snapshot.ppid > 0
        and snapshot.uids == (TARGET_UID,) * 4
        and snapshot.exe == DCONF_EXE
        and cmdline_sha == DCONF_CMDLINE_SHA256
        and APP_CODE_SCOPE_RE.fullmatch(code_unit_name(snapshot))
    ):
        return
    if snapshot.comm == "codex" and (
        snapshot.state not in {"X", "Z"}
        and snapshot.ppid > 0
        and snapshot.uids == (TARGET_UID,) * 4
        and snapshot.exe == CODEX_EXE
        and snapshot.cmdline == CODEX_CMDLINE
    ):
        return
    if snapshot.comm == "codex-code-mode" and (
        snapshot.state not in {"X", "Z"}
        and snapshot.ppid > 0
        and snapshot.uids == (TARGET_UID,) * 4
        and snapshot.exe == CODE_MODE_EXE
        and snapshot.cmdline == CODE_MODE_CMDLINE
    ):
        return
    raise DrainError(f"unexpected process in VS Code unit: {snapshot.pid}")


def collect_code_unit_members(
    user_manager_pid: int,
    proc_root: Path = Path("/proc"),
    *,
    allowed_dead: set[tuple[int, int]] | frozenset[tuple[int, int]] = frozenset(),
) -> dict[str, list[Snapshot]]:
    units: dict[str, list[Snapshot]] = {}
    for pid in _pid_directories(proc_root):
        root = proc_root / str(pid)
        try:
            cgroup = _read_bounded(root / "cgroup", 4096)
        except ProcessGone:
            continue
        if APP_CODE_CGROUP_RE.fullmatch(cgroup) is None:
            continue
        try:
            uids = _parse_uids(_read_bounded(root / "status", 65536))
        except ProcessGone:
            continue
        if uids != (TARGET_UID,) * 4:
            raise DrainError(f"non-user process in VS Code unit: {pid}")
        try:
            snapshot = read_snapshot(pid, proc_root)
        except ProcessGone:
            continue
        if snapshot.cgroup != cgroup:
            raise DrainError(f"VS Code cgroup identity changed while reading: {pid}")
        unit = code_unit_name(snapshot)
        if snapshot.state in {"X", "Z"}:
            if (snapshot.pid, snapshot.starttime) not in allowed_dead:
                raise DrainError(f"unexpected dead process in VS Code unit: {pid}")
        else:
            _validate_code_unit_member(snapshot, user_manager_pid)
        units.setdefault(unit, []).append(snapshot)
    for members in units.values():
        members.sort(key=lambda item: (item.pid, item.starttime))
    return dict(sorted(units.items()))


def _open_code_unit_handles(
    units: Mapping[str, list[Snapshot]],
    user_manager_pid: int,
    proc_root: Path,
) -> list[Handle]:
    handles: list[Handle] = []
    try:
        for unit in sorted(units):
            for snapshot in units[unit]:
                if snapshot.state in {"X", "Z"}:
                    raise DrainError(
                        f"dead process cannot become VS Code pidfd authority: {snapshot.pid}"
                    )
                try:
                    pidfd = os.pidfd_open(snapshot.pid, 0)
                except OSError as exc:
                    raise DrainError(
                        f"cannot open exact VS Code pidfd: {snapshot.pid}: {exc}"
                    ) from exc
                try:
                    current = read_snapshot(snapshot.pid, proc_root)
                    _validate_code_unit_member(current, user_manager_pid)
                    if current != snapshot or code_unit_name(current) != unit:
                        raise DrainError(
                            "VS Code identity changed while opening pidfd: "
                            f"{snapshot.pid}"
                        )
                except BaseException:
                    os.close(pidfd)
                    raise
                handles.append(Handle(snapshot, pidfd))
    except BaseException:
        _close_handles(handles)
        raise
    return handles


def _close_handles(handles: list[Handle]) -> None:
    first_error: OSError | None = None
    for handle in handles:
        try:
            os.close(handle.pidfd)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise DrainError(f"cannot close VS Code pidfd: {first_error}") from first_error


def _terminate_frozen_code_handles(
    handles: list[Handle],
    user_manager_pid: int,
    proc_root: Path,
) -> None:
    for handle in handles:
        current = read_snapshot(handle.snapshot.pid, proc_root)
        _validate_code_unit_member(current, user_manager_pid)
        if current != handle.snapshot:
            raise DrainError(
                f"VS Code identity changed before pidfd SIGKILL: {handle.snapshot.pid}"
            )
    try:
        for handle in handles:
            signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
    except OSError as exc:
        raise DrainError(f"cannot terminate exact frozen VS Code process: {exc}") from exc
    remaining = _wait_pidfds(handles, 10.0)
    if remaining:
        raise DrainError(
            "frozen VS Code processes did not exit after pidfd SIGKILL: "
            + ",".join(str(handle.snapshot.pid) for handle in remaining)
        )


def _query_code_unit_lifecycle(unit: str) -> dict[str, str]:
    if not (
        APP_CODE_SCOPE_RE.fullmatch(unit) or APP_CODE_SERVICE_RE.fullmatch(unit)
    ):
        raise DrainError(f"invalid VS Code lifecycle unit name: {unit}")
    names = ("Id", "LoadState", "ActiveState", "SubState", "FreezerState")
    arguments = ["show", unit]
    for name in names:
        arguments.extend(("-p", name))
    properties = _parse_systemctl_properties(_systemctl(arguments))
    if set(properties) != set(names) or properties.get("Id") != unit:
        raise DrainError(f"VS Code lifecycle identity differs: {unit}")
    return properties


def _require_absent_code_unit_lifecycle(
    unit: str, properties: Mapping[str, str], context: str
) -> None:
    expected = {
        "Id": unit,
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "SubState": "dead",
        "FreezerState": "running",
    }
    if properties != expected:
        raise DrainError(f"absent VS Code lifecycle state differs {context}: {unit}")


def _require_thawed_or_stopped_code_unit_lifecycle(
    unit: str, properties: Mapping[str, str], context: str
) -> None:
    if properties["LoadState"] == "not-found":
        _require_absent_code_unit_lifecycle(unit, properties, context)
        return
    if (
        properties["LoadState"] == "loaded"
        and properties["ActiveState"] == "active"
        and properties["SubState"] == "running"
        and properties["FreezerState"] == "running"
    ):
        _query_code_unit(unit)
        return
    if (
        properties["LoadState"] == "loaded"
        and properties["ActiveState"] == "inactive"
        and properties["SubState"] == "dead"
        and properties["FreezerState"] == "running"
    ):
        _query_stopped_code_unit(unit)
        return
    raise DrainError(f"VS Code lifecycle state differs {context}: {unit}")


def _recover_thawed_or_stopped_code_unit_lifecycle(
    unit: str, properties: Mapping[str, str], context: str
) -> None:
    if (
        properties["LoadState"] == "loaded"
        and properties["ActiveState"] == "failed"
        and properties["SubState"] == "failed"
        and properties["FreezerState"] == "running"
    ):
        _systemctl(["reset-failed", "--", unit])
        properties = _query_code_unit_lifecycle(unit)
    _require_thawed_or_stopped_code_unit_lifecycle(unit, properties, context)


def _thaw_code_unit(unit: str) -> None:
    properties = _query_code_unit_lifecycle(unit)
    load_state = properties["LoadState"]
    if load_state == "not-found":
        _require_absent_code_unit_lifecycle(unit, properties, "before thaw")
        return
    if load_state != "loaded":
        raise DrainError(f"VS Code lifecycle state differs before thaw: {unit}")
    if properties["FreezerState"] == "running":
        _recover_thawed_or_stopped_code_unit_lifecycle(
            unit, properties, "before thaw"
        )
        return
    if properties["FreezerState"] != "frozen":
        raise DrainError(f"VS Code lifecycle state differs before thaw: {unit}")
    try:
        _systemctl(["thaw", unit])
    except DrainError as thaw_error:
        after_error = _query_code_unit_lifecycle(unit)
        try:
            _recover_thawed_or_stopped_code_unit_lifecycle(
                unit, after_error, "after thaw error"
            )
            return
        except DrainError as recovery_error:
            raise DrainError(
                f"VS Code lifecycle recovery failed after thaw error: {unit}: "
                f"{recovery_error}"
            ) from thaw_error
    after = _query_code_unit_lifecycle(unit)
    _recover_thawed_or_stopped_code_unit_lifecycle(unit, after, "after thaw")


def stop_vscode_units(proc_root: Path = Path("/proc")) -> None:
    manager = find_user_manager(proc_root)
    units = collect_code_unit_members(manager.pid, proc_root)
    system_units = _list_code_units()
    if set(system_units) != set(units):
        raise DrainError("VS Code systemd/process inventory differs")
    if any(state != ("loaded", "active", "running") for state in system_units.values()):
        raise DrainError("VS Code systemd unit state differs before stop")
    if not system_units:
        print("CODESKEPTIC_HEADLESS_VSCODE_UNITS_ABSENT", flush=True)
        return
    for unit in units:
        _query_code_unit(unit)
    names = sorted(units)
    handles = _open_code_unit_handles(units, manager.pid, proc_root)
    freeze_cleanup_needed = False
    try:
        freeze_cleanup_needed = True
        _systemctl(["freeze", "--", *names])
        second = collect_code_unit_members(manager.pid, proc_root)
        initial_identities = {
            unit: tuple((item.pid, item.starttime) for item in members)
            for unit, members in units.items()
        }
        frozen_identities = {
            unit: tuple((item.pid, item.starttime) for item in members)
            for unit, members in second.items()
        }
        if frozen_identities != initial_identities:
            raise DrainError("VS Code unit inventory changed before stop")
        frozen_system_units = _list_code_units()
        if set(frozen_system_units) != set(units):
            raise DrainError("VS Code systemd inventory changed before stop")
        if any(
            load != "loaded" or active != "active"
            for load, active, _sub in frozen_system_units.values()
        ):
            raise DrainError("VS Code systemd state changed before stop")
        for unit in second:
            _query_frozen_code_unit(unit)
        _terminate_frozen_code_handles(handles, manager.pid, proc_root)
        for unit in names:
            _thaw_code_unit(unit)
        freeze_cleanup_needed = False
    except BaseException as original_error:
        cleanup_errors: list[str] = []
        if freeze_cleanup_needed:
            for unit in names:
                try:
                    _thaw_code_unit(unit)
                except DrainError as thaw_error:
                    cleanup_errors.append(f"{unit}: {thaw_error}")
        try:
            _close_handles(handles)
        except DrainError as close_error:
            cleanup_errors.append(str(close_error))
        if cleanup_errors:
            raise DrainError(
                "VS Code unit validation failed and cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from original_error
        raise
    _close_handles(handles)
    original_identities = {
        (snapshot.pid, snapshot.starttime)
        for members in second.values()
        for snapshot in members
    }
    print(
        "CODESKEPTIC_HEADLESS_VSCODE_UNITS_VALIDATED "
        + " ".join(names),
        flush=True,
    )
    deadline = time.monotonic() + 30.0
    while True:
        remaining = collect_code_unit_members(
            manager.pid, proc_root, allowed_dead=original_identities
        )
        remaining_live_identities = {
            (snapshot.pid, snapshot.starttime)
            for members in remaining.values()
            for snapshot in members
            if snapshot.state not in {"X", "Z"}
        }
        if not remaining_live_identities.issubset(original_identities):
            raise DrainError("new VS Code process appeared during stop")
        unexpected = set(remaining) - set(names)
        if unexpected:
            raise DrainError(
                "new VS Code units appeared during stop: "
                + ",".join(sorted(unexpected))
            )
        if not remaining:
            stopped_system_units = _list_code_units()
            unexpected_stopped = set(stopped_system_units) - set(names)
            if unexpected_stopped:
                raise DrainError(
                    "new VS Code units remained after stop: "
                    + ",".join(sorted(unexpected_stopped))
                )
            try:
                for unit in names:
                    _query_stopped_code_unit(unit)
            except DrainError as stopped_error:
                if time.monotonic() >= deadline:
                    raise DrainError(
                        "VS Code units did not reach stopped state: "
                        f"{stopped_error}"
                    ) from stopped_error
                time.sleep(0.25)
                continue
            print(
                "CODESKEPTIC_HEADLESS_VSCODE_UNITS_STOPPED "
                + " ".join(names),
                flush=True,
            )
            return
        if time.monotonic() >= deadline:
            raise DrainError(
                "VS Code units did not stop: " + ",".join(sorted(remaining))
            )
        time.sleep(0.25)


def require_extension_helpers_absent(proc_root: Path = Path("/proc")) -> None:
    helpers = collect_named({"codex", "codex-code-mode"}, proc_root)
    if helpers:
        raise DrainError(
            "VS Code extension helpers survived unit stop: "
            + ",".join(str(snapshot.pid) for snapshot in helpers)
        )
    print("CODESKEPTIC_HEADLESS_VSCODE_EXTENSION_HELPERS_ABSENT", flush=True)


def _require_one_vscode_absence_snapshot(
    proc_root: Path = Path("/proc"),
) -> None:
    manager = find_user_manager(proc_root)
    members = collect_code_unit_members(manager.pid, proc_root)
    if members:
        raise DrainError(
            "VS Code processes remain: "
            + ",".join(
                str(snapshot.pid)
                for snapshots in members.values()
                for snapshot in snapshots
            )
        )
    units = _list_code_units()
    if units:
        raise DrainError("VS Code units remain: " + ",".join(units))
    named = collect_named(
        {"code", "codex", "codex-code-mode", "chrome_crashpad"},
        proc_root,
    )
    blockers = [
        snapshot
        for snapshot in named
        if snapshot.comm in {"code", "codex", "codex-code-mode"}
        or (
            snapshot.comm == "chrome_crashpad"
            and snapshot.exe == CRASHPAD_EXE
        )
    ]
    if blockers:
        raise DrainError(
            "VS Code processes remain: "
            + ",".join(str(snapshot.pid) for snapshot in blockers)
        )


def require_vscode_absent(proc_root: Path = Path("/proc")) -> None:
    for attempt in range(2):
        _require_one_vscode_absence_snapshot(proc_root)
        if attempt == 0:
            time.sleep(0.25)
    print("CODESKEPTIC_HEADLESS_VSCODE_ABSENT", flush=True)


def drain_vscode(proc_root: Path = Path("/proc")) -> None:
    stop_vscode_units(proc_root)
    wait_for_code_exit(proc_root)
    require_extension_helpers_absent(proc_root)
    drain_helpers(proc_root)


def wait_for_code_exit(proc_root: Path = Path("/proc"), timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        processes = collect_named({"code"}, proc_root)
        for snapshot in processes:
            validate_code(snapshot)
        if not processes:
            print("CODESKEPTIC_HEADLESS_VSCODE_PROCESSES_ABSENT", flush=True)
            return
        if time.monotonic() >= deadline:
            pids = ",".join(str(item.pid) for item in processes)
            raise DrainError(f"VS Code processes did not exit after graphical shutdown: {pids}")
        time.sleep(0.25)


def validate_helper(snapshot: Snapshot, user_manager_pid: int) -> str:
    if snapshot.state in {"X", "Z"} or snapshot.ppid != user_manager_pid:
        raise DrainError(f"helper is not a live user-manager orphan: {snapshot.pid}")
    if snapshot.uids != (TARGET_UID,) * 4:
        raise DrainError(f"helper UID identity mismatch: {snapshot.pid}")
    cmdline_sha = hashlib.sha256(snapshot.cmdline).hexdigest()
    if snapshot.comm == "chrome_crashpad":
        konsole_helper = (
            cmdline_sha == KONSOLE_CRASHPAD_CMDLINE_SHA256
            and KONSOLE_CRASHPAD_CGROUP_RE.fullmatch(snapshot.cgroup)
        )
        desktop_helper = (
            cmdline_sha == DESKTOP_CRASHPAD_CMDLINE_SHA256
            and DESKTOP_CRASHPAD_CGROUP_RE.fullmatch(snapshot.cgroup)
        )
        if not (
            snapshot.exe == CRASHPAD_EXE
            and (konsole_helper or desktop_helper)
        ):
            raise DrainError(f"unexpected VS Code crashpad helper identity: {snapshot.pid}")
        return "crashpad"
    if snapshot.comm == "dconf":
        if not (
            snapshot.exe == DCONF_EXE
            and cmdline_sha == DCONF_CMDLINE_SHA256
            and DCONF_CGROUP_RE.fullmatch(snapshot.cgroup)
        ):
            raise DrainError(f"unexpected VS Code dconf watcher identity: {snapshot.pid}")
        return "dconf"
    raise DrainError(f"unexpected helper comm: {snapshot.pid}")


def open_validated_helpers(
    user_manager_pid: int, proc_root: Path = Path("/proc")
) -> list[Handle]:
    handles: list[Handle] = []
    try:
        for first in collect_named({"chrome_crashpad", "dconf"}, proc_root):
            validate_helper(first, user_manager_pid)
            try:
                pidfd = os.pidfd_open(first.pid, 0)
            except ProcessLookupError:
                raise ProcessGone(str(first.pid)) from None
            except OSError as exc:
                raise DrainError(f"cannot open pidfd for helper {first.pid}: {exc}") from exc
            try:
                second = read_snapshot(first.pid, proc_root)
                validate_helper(second, user_manager_pid)
                if second != first:
                    raise DrainError(f"helper identity changed while reading: {first.pid}")
            except BaseException:
                os.close(pidfd)
                raise
            handles.append(Handle(second, pidfd))
        return handles
    except BaseException:
        for handle in handles:
            os.close(handle.pidfd)
        raise


def _wait_pidfds(handles: list[Handle], timeout: float) -> list[Handle]:
    if not handles:
        return []
    poller = select.poll()
    by_fd = {handle.pidfd: handle for handle in handles}
    for fd in by_fd:
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    deadline = time.monotonic() + timeout
    remaining = dict(by_fd)
    while remaining:
        milliseconds = max(0, int((deadline - time.monotonic()) * 1000))
        if milliseconds == 0:
            break
        for fd, _events in poller.poll(min(milliseconds, 250)):
            remaining.pop(fd, None)
    return [remaining[fd] for fd in sorted(remaining)]


def drain_helpers(proc_root: Path = Path("/proc")) -> None:
    manager = find_user_manager(proc_root)
    handles = open_validated_helpers(manager.pid, proc_root)
    if not handles:
        print("CODESKEPTIC_HEADLESS_VSCODE_HELPERS_ABSENT", flush=True)
        return
    counts = {"crashpad": 0, "dconf": 0}
    for handle in handles:
        counts[validate_helper(handle.snapshot, manager.pid)] += 1
    print(
        "CODESKEPTIC_HEADLESS_VSCODE_HELPERS_VALIDATED "
        f"crashpad={counts['crashpad']} dconf={counts['dconf']}",
        flush=True,
    )
    try:
        for handle in handles:
            signal.pidfd_send_signal(handle.pidfd, signal.SIGTERM)
        remaining = _wait_pidfds(handles, 5.0)
        for handle in remaining:
            current = read_snapshot(handle.snapshot.pid, proc_root)
            validate_helper(current, manager.pid)
            if current != handle.snapshot:
                raise DrainError(
                    f"helper identity changed before SIGKILL: {handle.snapshot.pid}"
                )
            signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
        if _wait_pidfds(remaining, 10.0):
            pids = ",".join(str(item.snapshot.pid) for item in remaining)
            raise DrainError(f"VS Code helpers did not exit after SIGKILL: {pids}")
    except OSError as exc:
        raise DrainError(f"cannot signal exact VS Code helper: {exc}") from exc
    finally:
        for handle in handles:
            os.close(handle.pidfd)
    original = {(item.snapshot.pid, item.snapshot.starttime) for item in handles}
    reap_deadline = time.monotonic() + 5.0
    while True:
        survivors = collect_named({"chrome_crashpad", "dconf"}, proc_root)
        if not survivors:
            break
        waiting_for_reap = True
        for snapshot in survivors:
            if snapshot.state in {"X", "Z"} and (snapshot.pid, snapshot.starttime) in original:
                continue
            waiting_for_reap = False
            validate_helper(snapshot, manager.pid)
        if not waiting_for_reap:
            pids = ",".join(str(item.pid) for item in survivors)
            raise DrainError(f"new VS Code helpers appeared during drain: {pids}")
        if time.monotonic() >= reap_deadline:
            pids = ",".join(str(item.pid) for item in survivors)
            raise DrainError(f"terminated VS Code helpers were not reaped: {pids}")
        time.sleep(0.10)
    print(
        "CODESKEPTIC_HEADLESS_VSCODE_HELPERS_DRAINED "
        f"crashpad={counts['crashpad']} dconf={counts['dconf']}",
        flush=True,
    )


def main(argv: list[str]) -> int:
    if argv != ["--require-absent"]:
        print("vscode helper requires --require-absent", file=sys.stderr)
        return 2
    try:
        require_helper_session_cgroup()
        require_vscode_absent()
    except DrainError as exc:
        print(f"CODESKEPTIC_HEADLESS_VSCODE_HELPER_FAIL {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
