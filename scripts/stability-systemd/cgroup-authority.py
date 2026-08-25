#!/usr/bin/env python3
"""Own and recover the exact final P10-09 cgroup authority."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from pathlib import Path


SCHEMA = "codeskeptic-p10-09-cgroup-authority-intent-v1"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
CAMPAIGN_SESSION = re.compile(rf"[0-9]{{8}}T[0-9]{{6}}Z-{UUID}-{UUID}")
PROBE_SESSION = re.compile(rf"probe-{UUID}")
INSTALLATION_RECEIPT = Path(
    "/opt/codeskeptic-p10-09/installation/receipt.json"
)
STATE_ROOT = Path("/var/lib/codeskeptic-p10-09")
MARKER = STATE_ROOT / "cgroup-authority-intent.json"
MARKER_TEMP = STATE_ROOT / ".cgroup-authority-intent.tmp"
CGROUP_ROOT = Path("/sys/fs/cgroup")
SYSTEM_SLICE = CGROUP_ROOT / "system.slice"
SERVICE = SYSTEM_SLICE / "codeskeptic-stability.service"
CONTROLLER = SERVICE / "controller"
PAYLOAD = SERVICE / "codeskeptic-p10-09"
MEASUREMENT = PAYLOAD / "measurement"
EXCLUSIVE_CPUS = "0-3"
CONTROLLER_CPUS = "4-11"
CAMPAIGN_CPUS = "0-11"
REQUIRED_CONTROLLERS = frozenset({"cpuset", "cpu", "memory", "pids"})
CPU_POSSIBLE = Path("/sys/devices/system/cpu/possible")
CPU_ONLINE = Path("/sys/devices/system/cpu/online")
ROOT_UID = 0
ROOT_GID = 0
UUID_SHAPE = "hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh"
CAMPAIGN_SESSION_SHAPE = f"ddddddddTddddddZ-{UUID_SHAPE}-{UUID_SHAPE}"
PROBE_SESSION_SHAPE = f"probe-{UUID_SHAPE}"


class AuthorityError(RuntimeError):
    """A controlled fail-closed cgroup authority error."""


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def installation_canonical(value: object) -> bytes:
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


def valid_session(session: str) -> str:
    if not isinstance(session, str) or (
        CAMPAIGN_SESSION.fullmatch(session) is None
        and PROBE_SESSION.fullmatch(session) is None
    ):
        raise AuthorityError("cgroup authority session identity is malformed")
    return session


def valid_container_ids(values: tuple[str, ...]) -> frozenset[str]:
    if (
        any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in values)
        or len(set(values)) != len(values)
    ):
        raise AuthorityError("container identity inventory is malformed")
    return frozenset(values)


def read_exact_owned_file(path: Path, label: str, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != ROOT_UID
        or metadata.st_gid != ROOT_GID
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_nlink != 1
        or metadata.st_size < 1
        or metadata.st_size > maximum
    ):
        raise AuthorityError(f"{label} metadata drift")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            raise AuthorityError(f"{label} changed while opening")
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = bytes(chunks)
    if (
        len(raw) != metadata.st_size
        or len(raw) > maximum
        or after.st_size != metadata.st_size
    ):
        raise AuthorityError(f"{label} changed while reading")
    return raw


def installed_source_revision() -> str:
    raw = read_exact_owned_file(
        INSTALLATION_RECEIPT, "installation receipt", 65536
    )
    try:
        value = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorityError(f"installation receipt is malformed: {error}") from error
    if not isinstance(value, dict) or installation_canonical(value) != raw:
        raise AuthorityError("installation receipt is not canonical")
    revision = value.get("bundle_revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise AuthorityError("installation source revision is malformed")
    return revision


def expected_marker(session: str) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "status": "armed",
        "source_revision": installed_source_revision(),
        "session": valid_session(session),
        "exclusive_cpus": EXCLUSIVE_CPUS,
        "system_slice_cgroup": os.fspath(SYSTEM_SLICE),
        "service_cgroup": os.fspath(SERVICE),
        "payload_cgroup": os.fspath(PAYLOAD),
        "measurement_cgroup": os.fspath(MEASUREMENT),
        "original_root_isolated_cpus": "",
        "original_system_slice_exclusive_cpus": "",
        "original_service_exclusive_cpus": "",
    }


def require_exact_directory(path: Path, label: str) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise AuthorityError(f"{label} is not an exact directory")
    if path.resolve(strict=True) != path:
        raise AuthorityError(f"{label} identity drift")


def cgroup_value(path: Path, label: str) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise AuthorityError(f"{label} is not a regular cgroup file")
    return path.read_text(encoding="ascii").strip()


def write_control(path: Path, value: str) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise AuthorityError(f"refusing non-regular cgroup control: {path}")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        raw = f"{value}\n".encode("ascii")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise AuthorityError(f"short cgroup control write: {path}")
            offset += written
    finally:
        os.close(descriptor)


def require_member_with_empty_exclusive(path: Path, label: str) -> None:
    require_exact_directory(path, label)
    if cgroup_value(path / "cpuset.cpus.partition", label) != "member":
        raise AuthorityError(f"{label} is not a member cpuset")
    if cgroup_value(path / "cpuset.cpus.exclusive", label):
        raise AuthorityError(f"{label} configured exclusive CPUs are not empty")
    if cgroup_value(path / "cpuset.cpus.exclusive.effective", label):
        raise AuthorityError(f"{label} effective exclusive CPUs are not empty")


def require_owned_exclusive(path: Path, label: str) -> None:
    require_exact_directory(path, label)
    if cgroup_value(path / "cpuset.cpus.partition", label) != "member":
        raise AuthorityError(f"{label} is not a member cpuset")
    if cgroup_value(path / "cpuset.cpus.exclusive", label) != EXCLUSIVE_CPUS:
        raise AuthorityError(f"{label} configured exclusive CPU authority drift")
    if cgroup_value(path / "cpuset.cpus.exclusive.effective", label) != EXCLUSIVE_CPUS:
        raise AuthorityError(f"{label} effective exclusive CPU authority drift")


def require_state_root() -> None:
    require_exact_directory(STATE_ROOT, "state root")
    metadata = STATE_ROOT.lstat()
    if metadata.st_uid != ROOT_UID or metadata.st_gid != ROOT_GID:
        raise AuthorityError("state root ownership drift")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise AuthorityError("state root mode drift")


def fsync_state_root() -> None:
    directory = os.open(
        STATE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_owned_marker_file(
    path: Path, session: str, *, allowed_links: set[int]
) -> tuple[os.stat_result, bytes]:
    metadata, raw, discovered_session = read_marker_candidate_file(
        path, allowed_links=allowed_links
    )
    if discovered_session != valid_session(session):
        raise AuthorityError("cgroup authority marker session drift")
    return metadata, raw


def read_marker_candidate_file(
    path: Path, *, allowed_links: set[int]
) -> tuple[os.stat_result, bytes, str]:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != ROOT_UID
            or metadata.st_gid != ROOT_GID
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink not in allowed_links
            or metadata.st_size < 1
            or metadata.st_size > 4096
        ):
            raise AuthorityError("cgroup authority marker metadata drift")
        chunks = bytearray()
        while len(chunks) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        raw = bytes(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != metadata.st_size
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or os.read(descriptor, 1)
        ):
            raise AuthorityError("cgroup authority marker changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorityError(
            f"cgroup authority marker is malformed: {error}"
        ) from error
    if not isinstance(value, dict):
        raise AuthorityError("cgroup authority marker claims drift")
    session = valid_session(value.get("session"))
    if raw != canonical(expected_marker(session)):
        raise AuthorityError("cgroup authority marker claims drift")
    return metadata, raw, session


def read_unpublished_prefix_file() -> tuple[os.stat_result, bytes]:
    descriptor = os.open(
        MARKER_TEMP,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != ROOT_UID
            or metadata.st_gid != ROOT_GID
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size > 4096
        ):
            raise AuthorityError(
                "cgroup authority unpublished marker metadata drift"
            )
        chunks = bytearray()
        while len(chunks) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        raw = bytes(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != metadata.st_size
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or os.read(descriptor, 1)
        ):
            raise AuthorityError(
                "cgroup authority unpublished marker changed while reading"
            )
    finally:
        os.close(descriptor)
    return metadata, raw


def matches_session_shape_prefix(value: bytes, shape: str) -> bool:
    if len(value) > len(shape):
        return False
    for byte, expected in zip(value, shape):
        if expected == "d":
            if byte < ord("0") or byte > ord("9"):
                return False
        elif expected == "h":
            if not (ord("0") <= byte <= ord("9") or ord("a") <= byte <= ord("f")):
                return False
        elif byte != ord(expected):
            return False
    return True


def is_strict_unpublished_marker_prefix(raw: bytes) -> bool:
    sample_session = (
        "00000000T000000Z-"
        "00000000-0000-0000-0000-000000000000-"
        "00000000-0000-0000-0000-000000000000"
    )
    complete = canonical(expected_marker(sample_session))
    token = sample_session.encode("ascii")
    start = complete.index(token)
    before_session = complete[:start]
    after_session = complete[start + len(token) :]

    if len(raw) <= len(before_session):
        return before_session.startswith(raw)
    if not raw.startswith(before_session):
        return False
    remainder = raw[len(before_session) :]
    for shape in (CAMPAIGN_SESSION_SHAPE, PROBE_SESSION_SHAPE):
        session_length = len(shape)
        if len(remainder) <= session_length:
            if matches_session_shape_prefix(remainder, shape):
                return True
            continue
        session = remainder[:session_length]
        suffix = remainder[session_length:]
        if (
            matches_session_shape_prefix(session, shape)
            and len(suffix) < len(after_session)
            and after_session.startswith(suffix)
        ):
            return True
    return False


def discard_partial_unpublished_marker(
    expected_metadata: os.stat_result, expected_raw: bytes
) -> None:
    metadata, raw = read_unpublished_prefix_file()
    if (
        metadata.st_dev != expected_metadata.st_dev
        or metadata.st_ino != expected_metadata.st_ino
        or raw != expected_raw
        or not is_strict_unpublished_marker_prefix(raw)
    ):
        raise AuthorityError(
            "cgroup authority unpublished marker changed before discard"
        )
    MARKER_TEMP.unlink()
    fsync_state_root()


def discover_marker_session() -> str | None:
    marker_present = MARKER.exists() or MARKER.is_symlink()
    temporary_present = MARKER_TEMP.exists() or MARKER_TEMP.is_symlink()
    if not marker_present:
        if not temporary_present:
            return None
        _, _, session = read_marker_candidate_file(
            MARKER_TEMP, allowed_links={1}
        )
        return session
    metadata, raw, session = read_marker_candidate_file(
        MARKER, allowed_links={1, 2}
    )
    if metadata.st_nlink == 1:
        if temporary_present:
            raise AuthorityError("unexpected cgroup authority marker temporary")
        return session
    temporary, temporary_raw, temporary_session = read_marker_candidate_file(
        MARKER_TEMP, allowed_links={2}
    )
    if (
        temporary.st_dev != metadata.st_dev
        or temporary.st_ino != metadata.st_ino
        or temporary_raw != raw
        or temporary_session != session
    ):
        raise AuthorityError("cgroup authority marker link identity drift")
    return session


def publish_marker(session: str) -> None:
    require_state_root()
    if MARKER.exists() or MARKER.is_symlink():
        raise AuthorityError("cgroup authority marker already exists")
    if MARKER_TEMP.exists() or MARKER_TEMP.is_symlink():
        raise AuthorityError("cgroup authority marker temporary already exists")
    raw = canonical(expected_marker(session))
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
                raise AuthorityError("short cgroup authority marker write")
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
    fsync_state_root()
    MARKER_TEMP.unlink()
    fsync_state_root()


def read_marker(session: str, *, repair_link: bool = False) -> bytes:
    metadata, raw = read_owned_marker_file(MARKER, session, allowed_links={1, 2})
    if metadata.st_nlink == 1:
        if MARKER_TEMP.exists() or MARKER_TEMP.is_symlink():
            raise AuthorityError("unexpected cgroup authority marker temporary")
        return raw
    temporary, temporary_raw = read_owned_marker_file(
        MARKER_TEMP, session, allowed_links={2}
    )
    if (
        temporary.st_dev != metadata.st_dev
        or temporary.st_ino != metadata.st_ino
        or temporary_raw != raw
    ):
        raise AuthorityError("cgroup authority marker link identity drift")
    if repair_link:
        MARKER_TEMP.unlink()
        fsync_state_root()
        return read_marker(session)
    return raw


def discard_unpublished_marker(session: str) -> bool:
    if not MARKER_TEMP.exists() and not MARKER_TEMP.is_symlink():
        return False
    read_owned_marker_file(MARKER_TEMP, session, allowed_links={1})
    MARKER_TEMP.unlink()
    fsync_state_root()
    return True


def require_initial_state() -> None:
    require_exact_directory(CGROUP_ROOT, "cgroup root")
    if cgroup_value(CGROUP_ROOT / "cpuset.cpus.isolated", "root isolated CPUs"):
        raise AuthorityError("root isolated CPUs are not initially empty")
    if cgroup_value(CPU_POSSIBLE, "possible CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("possible CPU topology drift")
    if cgroup_value(CPU_ONLINE, "online CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("online CPU topology drift")
    require_member_with_empty_exclusive(SYSTEM_SLICE, "system.slice")
    require_member_with_empty_exclusive(SERVICE, "service")
    if cgroup_value(SYSTEM_SLICE / "cpuset.cpus.effective", "system.slice CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("initial system.slice effective CPUs drift")
    if cgroup_value(SERVICE / "cpuset.cpus.effective", "service CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("initial service effective CPUs drift")
    require_exact_directory(CONTROLLER, "controller")
    if cgroup_value(CONTROLLER / "cpuset.cpus.effective", "controller CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("initial controller effective CPUs drift")
    subtree = set(
        cgroup_value(SERVICE / "cgroup.subtree_control", "service controllers").split()
    )
    if subtree != REQUIRED_CONTROLLERS:
        raise AuthorityError("service subtree controller authority drift")
    for path, label in ((PAYLOAD, "payload"), (MEASUREMENT, "measurement")):
        if path.exists() or path.is_symlink():
            raise AuthorityError(f"{label} cgroup already exists")


def arm(session: str) -> None:
    valid_session(session)
    require_initial_state()
    publish_marker(session)
    write_control(SYSTEM_SLICE / "cpuset.cpus.exclusive", EXCLUSIVE_CPUS)
    require_owned_exclusive(SYSTEM_SLICE, "system.slice")
    write_control(SERVICE / "cpuset.cpus.exclusive", EXCLUSIVE_CPUS)
    require_owned_exclusive(SERVICE, "service")
    read_marker(session)


def expected_active_ancestry() -> tuple[tuple[Path, str, str], ...]:
    return (
        (SYSTEM_SLICE, "member", CONTROLLER_CPUS),
        (SERVICE, "member", CONTROLLER_CPUS),
        (PAYLOAD, "member", CONTROLLER_CPUS),
        (MEASUREMENT, "isolated", EXCLUSIVE_CPUS),
    )


def verify_active(
    session: str, owned_container_ids: tuple[str, ...] = ()
) -> None:
    valid_container_ids(owned_container_ids)
    read_marker(session)
    for path, partition, effective_cpus in expected_active_ancestry():
        label = path.name
        require_exact_directory(path, label)
        if cgroup_value(path / "cpuset.cpus.exclusive", label) != EXCLUSIVE_CPUS:
            raise AuthorityError(f"configured exclusive CPU ancestry drift: {label}")
        if cgroup_value(path / "cpuset.cpus.exclusive.effective", label) != EXCLUSIVE_CPUS:
            raise AuthorityError(f"effective exclusive CPU ancestry drift: {label}")
        if cgroup_value(path / "cpuset.cpus.partition", label) != partition:
            raise AuthorityError(f"partition ancestry drift: {label}")
        if cgroup_value(path / "cpuset.cpus.effective", label) != effective_cpus:
            raise AuthorityError(f"effective CPU ancestry drift: {label}")
    require_exact_directory(CONTROLLER, "controller")
    if cgroup_value(CONTROLLER / "cpuset.cpus.effective", "controller CPUs") != CONTROLLER_CPUS:
        raise AuthorityError("controller effective CPUs drift")
    if cgroup_value(CGROUP_ROOT / "cpuset.cpus.isolated", "root isolated CPUs") != EXCLUSIVE_CPUS:
        raise AuthorityError("root isolated CPU inventory drift")
    if cgroup_value(CPU_POSSIBLE, "possible CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("possible CPU topology drift")
    if cgroup_value(CPU_ONLINE, "online CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("online CPU topology drift")
    # Ancestry values alone do not establish ownership of every mutable
    # descendant. Container cleanup uses this action as its final
    # pre-mutation gate, so reject any foreign payload child here too.
    validate_payload_tree(owned_container_ids)


def cgroup_events(path: Path, label: str) -> dict[str, str]:
    events: dict[str, str] = {}
    for line in cgroup_value(path / "cgroup.events", label).splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in events:
            raise AuthorityError(f"{label} cgroup events are malformed")
        events[fields[0]] = fields[1]
    if events.get("populated") not in {"0", "1"}:
        raise AuthorityError(f"{label} populated state is malformed")
    return events


def kill_and_wait(path: Path, label: str) -> None:
    if cgroup_events(path, label)["populated"] == "1":
        write_control(path / "cgroup.kill", "1")
        for _ in range(500):
            if cgroup_events(path, label)["populated"] == "0":
                break
            time.sleep(0.01)
        else:
            raise AuthorityError(f"{label} cgroup did not become recursively empty")
    if cgroup_events(path, label)["populated"] != "0":
        raise AuthorityError(f"{label} cgroup remains populated")


def child_directories(path: Path) -> list[Path]:
    children: list[Path] = []
    for child in path.iterdir():
        metadata = child.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise AuthorityError(f"cgroup subtree contains a symlink: {child}")
        if stat.S_ISDIR(metadata.st_mode):
            children.append(child)
    return sorted(children, key=lambda item: item.name)


def validate_owned_tree(
    path: Path, label: str, *, measurement_root: bool = False
) -> None:
    require_exact_directory(path, label)
    partition = cgroup_value(path / "cpuset.cpus.partition", label)
    configured = cgroup_value(path / "cpuset.cpus.exclusive", label)
    if measurement_root:
        if partition != "member" and partition != "isolated" and not partition.startswith(
            "isolated invalid ("
        ):
            raise AuthorityError("measurement partition ownership drift")
        if configured not in {"", EXCLUSIVE_CPUS}:
            raise AuthorityError("refusing foreign measurement exclusive CPUs")
    else:
        if partition != "member":
            raise AuthorityError(f"{label} is not a member cgroup")
        if configured:
            raise AuthorityError(f"refusing foreign {label} exclusive CPUs")
    children = child_directories(path)
    if measurement_root and children:
        raise AuthorityError("measurement cgroup contains foreign descendants")
    for child in children:
        validate_owned_tree(child, f"{label}/{child.name}")


def validate_payload_tree(
    owned_container_ids: tuple[str, ...] = (),
) -> list[Path]:
    valid_container_ids(owned_container_ids)
    require_exact_directory(PAYLOAD, "payload")
    if cgroup_value(PAYLOAD / "cpuset.cpus.partition", "payload") != "member":
        raise AuthorityError("payload is not a member cgroup")
    configured = cgroup_value(PAYLOAD / "cpuset.cpus.exclusive", "payload")
    if configured not in {"", EXCLUSIVE_CPUS}:
        raise AuthorityError("refusing foreign payload exclusive CPUs")
    subtree = set(
        cgroup_value(PAYLOAD / "cgroup.subtree_control", "payload").split()
    )
    if not subtree <= REQUIRED_CONTROLLERS:
        raise AuthorityError("payload subtree controller inventory drift")
    children = child_directories(PAYLOAD)
    for child in children:
        if child == MEASUREMENT:
            validate_owned_tree(child, "measurement", measurement_root=True)
        else:
            raise AuthorityError(
                f"payload contains an unexpected runtime cgroup: {child.name}"
            )
    return children


def remove_owned_tree(
    path: Path, label: str, *, measurement_root: bool = False
) -> None:
    require_exact_directory(path, label)
    kill_and_wait(path, label)
    children = child_directories(path)
    if measurement_root and children:
        raise AuthorityError("measurement cgroup contains foreign descendants")
    for child in children:
        remove_owned_tree(child, f"{label}/{child.name}")
    partition = cgroup_value(path / "cpuset.cpus.partition", label)
    if measurement_root:
        if partition == "member":
            pass
        elif partition == "isolated" or partition.startswith("isolated invalid ("):
            write_control(path / "cpuset.cpus.partition", "member")
        else:
            raise AuthorityError("measurement partition ownership drift")
    elif partition != "member":
        raise AuthorityError(f"{label} is not a member cgroup")
    if cgroup_value(path / "cpuset.cpus.partition", label) != "member":
        raise AuthorityError(f"{label} partition did not return to member")
    path.rmdir()


def cleanup_payload(owned_container_ids: tuple[str, ...] = ()) -> None:
    if not PAYLOAD.exists() and not PAYLOAD.is_symlink():
        return
    validate_payload_tree(owned_container_ids)
    kill_and_wait(PAYLOAD, "payload")
    for child in child_directories(PAYLOAD):
        if child == MEASUREMENT:
            remove_owned_tree(child, "measurement", measurement_root=True)
        else:
            raise AuthorityError(
                f"payload contains an unexpected runtime cgroup: {child.name}"
            )
    if child_directories(PAYLOAD):
        raise AuthorityError("payload retained child cgroups")
    subtree = set(
        cgroup_value(PAYLOAD / "cgroup.subtree_control", "payload").split()
    )
    if not subtree <= REQUIRED_CONTROLLERS:
        raise AuthorityError("payload subtree controller inventory drift")
    if subtree:
        write_control(
            PAYLOAD / "cgroup.subtree_control",
            " ".join(f"-{controller}" for controller in sorted(subtree)),
        )
    if cgroup_value(PAYLOAD / "cgroup.subtree_control", "payload"):
        raise AuthorityError("payload subtree controllers were not disabled")
    kill_and_wait(PAYLOAD, "payload")
    PAYLOAD.rmdir()


def restore_ancestor(path: Path, label: str, *, allow_absent: bool = False) -> bool:
    if not path.exists() and not path.is_symlink():
        if allow_absent:
            return False
        raise AuthorityError(f"{label} cgroup is absent")
    require_exact_directory(path, label)
    if cgroup_value(path / "cpuset.cpus.partition", label) != "member":
        raise AuthorityError(f"{label} partition ownership drift")
    configured = cgroup_value(path / "cpuset.cpus.exclusive", label)
    if configured not in {"", EXCLUSIVE_CPUS}:
        raise AuthorityError(f"refusing to clear foreign {label} exclusive CPUs")
    if configured == EXCLUSIVE_CPUS:
        write_control(path / "cpuset.cpus.exclusive", "")
    if cgroup_value(path / "cpuset.cpus.exclusive", label):
        raise AuthorityError(f"{label} configured exclusive CPUs were not restored")
    if cgroup_value(path / "cpuset.cpus.exclusive.effective", label):
        raise AuthorityError(f"{label} effective exclusive CPUs were not restored")
    if cgroup_value(path / "cpuset.cpus.effective", label) != CAMPAIGN_CPUS:
        raise AuthorityError(f"{label} effective CPUs were not restored")
    return True


def require_restored_ancestor(
    path: Path, label: str, *, allow_absent: bool = False
) -> None:
    if not path.exists() and not path.is_symlink():
        if allow_absent:
            return
        raise AuthorityError(f"{label} cgroup is absent")
    require_exact_directory(path, label)
    if cgroup_value(path / "cpuset.cpus.partition", label) != "member":
        raise AuthorityError(f"{label} partition is not restored")
    if cgroup_value(path / "cpuset.cpus.exclusive", label):
        raise AuthorityError(f"{label} configured exclusive CPUs are not restored")
    if cgroup_value(path / "cpuset.cpus.exclusive.effective", label):
        raise AuthorityError(f"{label} effective exclusive CPUs are not restored")
    if cgroup_value(path / "cpuset.cpus.effective", label) != CAMPAIGN_CPUS:
        raise AuthorityError(f"{label} effective CPUs are not restored")


def already_clean() -> None:
    if PAYLOAD.exists() or PAYLOAD.is_symlink() or MEASUREMENT.exists() or MEASUREMENT.is_symlink():
        raise AuthorityError("cgroup authority marker is absent but payload remains")
    require_restored_ancestor(SERVICE, "service", allow_absent=True)
    require_restored_ancestor(SYSTEM_SLICE, "system.slice")
    if cgroup_value(CGROUP_ROOT / "cpuset.cpus.isolated", "root isolated CPUs"):
        raise AuthorityError("cgroup authority marker is absent but isolated CPUs remain")
    if cgroup_value(CPU_POSSIBLE, "possible CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("possible CPU topology drift")
    if cgroup_value(CPU_ONLINE, "online CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("online CPU topology drift")


def remove_marker(session: str) -> None:
    read_marker(session, repair_link=True)
    MARKER.unlink()
    fsync_state_root()


def cleanup(
    session: str, owned_container_ids: tuple[str, ...] = ()
) -> str:
    valid_container_ids(owned_container_ids)
    valid_session(session)
    if not MARKER.exists() and not MARKER.is_symlink():
        already_clean()
        if discard_unpublished_marker(session):
            return "discarded-unarmed-intent"
        return "already-clean"
    read_marker(session, repair_link=True)
    root_isolated = cgroup_value(
        CGROUP_ROOT / "cpuset.cpus.isolated", "root isolated CPUs"
    )
    if root_isolated not in {"", EXCLUSIVE_CPUS}:
        raise AuthorityError("refusing foreign root isolated CPUs")
    system_configured = cgroup_value(
        SYSTEM_SLICE / "cpuset.cpus.exclusive", "system.slice"
    )
    if system_configured not in {"", EXCLUSIVE_CPUS}:
        raise AuthorityError("refusing foreign system.slice exclusive CPUs")
    if SERVICE.exists() and not SERVICE.is_symlink():
        service_configured = cgroup_value(
            SERVICE / "cpuset.cpus.exclusive", "service"
        )
        if service_configured not in {"", EXCLUSIVE_CPUS}:
            raise AuthorityError("refusing foreign service exclusive CPUs")
    cleanup_payload(owned_container_ids)
    restore_ancestor(SERVICE, "service", allow_absent=True)
    restore_ancestor(SYSTEM_SLICE, "system.slice")
    if cgroup_value(CGROUP_ROOT / "cpuset.cpus.isolated", "root isolated CPUs"):
        raise AuthorityError("root isolated CPUs were not restored")
    if cgroup_value(CPU_POSSIBLE, "possible CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("possible CPU topology drift")
    if cgroup_value(CPU_ONLINE, "online CPUs") != CAMPAIGN_CPUS:
        raise AuthorityError("online CPU topology drift")
    remove_marker(session)
    return "restored"


def check_clean() -> None:
    if MARKER.exists() or MARKER.is_symlink():
        raise AuthorityError("cgroup authority marker remains")
    if MARKER_TEMP.exists() or MARKER_TEMP.is_symlink():
        raise AuthorityError("cgroup authority marker temporary remains")
    already_clean()


def recover(owned_container_ids: tuple[str, ...] = ()) -> str:
    valid_container_ids(owned_container_ids)
    marker_present = MARKER.exists() or MARKER.is_symlink()
    temporary_present = MARKER_TEMP.exists() or MARKER_TEMP.is_symlink()
    if not marker_present and temporary_present:
        require_state_root()
        metadata, raw = read_unpublished_prefix_file()
        if is_strict_unpublished_marker_prefix(raw):
            already_clean()
            discard_partial_unpublished_marker(metadata, raw)
            return "discarded-partial-unarmed-intent"
    session = discover_marker_session()
    if session is None:
        check_clean()
        return "already-clean"
    return cleanup(session, owned_container_ids)


def main() -> int:
    if os.geteuid() != 0:
        raise AuthorityError("cgroup authority helper must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("arm", "verify-active", "cleanup", "recover", "check-clean"),
    )
    parser.add_argument("--session")
    parser.add_argument("--container-id", action="append", default=[])
    args = parser.parse_args()
    if args.action in {"recover", "check-clean"}:
        if args.session is not None:
            raise AuthorityError(f"{args.action} does not accept a session")
        if args.action == "check-clean" and args.container_id:
            raise AuthorityError(
                "check-clean does not accept a container identity"
            )
        if args.action == "recover":
            result = recover(tuple(args.container_id))
        else:
            check_clean()
            result = "clean"
    else:
        if args.session is None:
            raise AuthorityError(f"{args.action} requires --session")
        if args.action == "arm":
            if args.container_id:
                raise AuthorityError("arm does not accept a container identity")
            arm(args.session)
            result = "armed"
        elif args.action == "verify-active":
            verify_active(args.session, tuple(args.container_id))
            result = "active"
        else:
            result = cleanup(args.session, tuple(args.container_id))
    print(
        "CODESKEPTIC_P10_09_CGROUP_AUTHORITY_OK "
        f"action={args.action} result={result}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError, TypeError, ValueError) as error:
        print(
            f"CODESKEPTIC_P10_09_CGROUP_AUTHORITY_FAIL {error}",
            file=sys.stderr,
        )
        raise SystemExit(2)
