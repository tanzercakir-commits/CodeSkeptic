#!/usr/bin/env python3
"""Payload-free client for the two fixed P10-09 launch endpoints."""

from __future__ import annotations

import os
import pwd
import re
import select
import socket
import stat
import struct
import sys
from pathlib import Path
from typing import BinaryIO


RUNTIME_ROOT = Path("/run/codeskeptic-p10-09-launch")
SOCKET_PATHS = {
    "campaign": RUNTIME_ROOT / "campaign.sock",
    "probe": RUNTIME_ROOT / "probe.sock",
}
RESULT = re.compile(
    rb"CODESKEPTIC_LAUNCH_RESULT_V1 (campaign|probe) ([0-9]{1,3})"
)
MAX_RESULT_BYTES = 128


class ClientError(RuntimeError):
    """The fixed root launch endpoint or its result is unavailable."""


def _require_peer_half_close(connection: socket.socket, timeout: float) -> None:
    """Require Linux's explicit peer-write-half-close indication."""

    if not hasattr(select, "POLLRDHUP"):
        raise ClientError("kernel peer half-close signaling is unavailable")
    poller = select.poll()
    descriptor = connection.fileno()
    poller.register(
        descriptor,
        select.POLLRDHUP | select.POLLERR | select.POLLHUP | select.POLLNVAL,
    )
    milliseconds = max(1, int(timeout * 1000 + 0.999))
    events = poller.poll(milliseconds)
    if len(events) != 1 or events[0][0] != descriptor:
        raise ClientError("launch endpoint did not close its result")
    event = events[0][1]
    if event & (select.POLLERR | select.POLLNVAL) or not event & select.POLLRDHUP:
        raise ClientError("launch endpoint did not close its result")


def _verify_socket_path(
    path: Path,
    *,
    expected_parent_uid: int,
    expected_parent_gid: int,
    expected_socket_uid: int,
    expected_socket_gid: int,
    expected_mode: int,
) -> None:
    try:
        parent = path.parent.lstat()
        metadata = path.lstat()
    except OSError as error:
        raise ClientError(f"cannot inspect fixed launch socket: {error}") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != expected_parent_uid
        or parent.st_gid != expected_parent_gid
        or stat.S_IMODE(parent.st_mode) != 0o755
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_socket_uid
        or metadata.st_gid != expected_socket_gid
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise ClientError("fixed launch socket authority drift")


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


def run_client(
    mode: str,
    *,
    socket_path: Path | None = None,
    expected_parent_uid: int = 0,
    expected_parent_gid: int = 0,
    expected_socket_uid: int = 0,
    expected_socket_gid: int | None = None,
    expected_mode: int = 0o660,
    expected_server_uid: int = 0,
    output: BinaryIO | None = None,
    timeout: float = 17 * 60,
) -> int:
    if mode not in SOCKET_PATHS:
        raise ClientError("launch mode is not fixed")
    if expected_socket_gid is None:
        expected_socket_gid = pwd.getpwuid(os.getuid()).pw_gid
    path = SOCKET_PATHS[mode] if socket_path is None else socket_path
    _verify_socket_path(
        path,
        expected_parent_uid=expected_parent_uid,
        expected_parent_gid=expected_parent_gid,
        expected_socket_uid=expected_socket_uid,
        expected_socket_gid=expected_socket_gid,
        expected_mode=expected_mode,
    )
    destination = sys.stdout.buffer if output is None else output

    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect(os.fspath(path))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ClientError("kernel peer credentials are unavailable")
        size = struct.calcsize("3i")
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, size
        )
        _pid, server_uid, _gid = struct.unpack("3i", raw)
        if server_uid != expected_server_uid:
            raise ClientError("launch server is not root-owned")
        destination.write(
            f"CodeSkeptic {mode} accepted; result awaited.\n".encode("ascii")
        )
        destination.flush()
        connection.shutdown(socket.SHUT_WR)
        _require_peer_half_close(connection, timeout)
        flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
        forbidden_flags = getattr(socket, "MSG_TRUNC", 0) | getattr(
            socket, "MSG_CTRUNC", 0
        )
        blocks: list[bytes] = []
        total = 0
        while True:
            payload, ancillary, message_flags, _address = connection.recvmsg(
                MAX_RESULT_BYTES + 1 - total,
                socket.CMSG_SPACE(struct.calcsize("i")),
                flags,
            )
            _close_ancillary_fds(ancillary)
            if ancillary or message_flags & forbidden_flags:
                raise ClientError("launch result framing drift")
            if not payload:
                break
            blocks.append(payload)
            total += len(payload)
            if total > MAX_RESULT_BYTES:
                raise ClientError("launch result framing drift")
    except OSError as error:
        raise ClientError(f"fixed launch connection failed: {error}") from error
    finally:
        connection.close()
    payload = b"".join(blocks)
    match = RESULT.fullmatch(payload)
    if match is None or match.group(1).decode("ascii") != mode:
        raise ClientError("launch result is missing or unbound")
    result = int(match.group(2))
    if not 0 <= result <= 255:
        raise ClientError("launch result is malformed")
    destination.write(f"CodeSkeptic {mode} exit {result}.\n".encode("ascii"))
    destination.flush()
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == []:
        mode = "campaign"
    elif arguments == ["--probe-only"]:
        mode = "probe"
    else:
        print(
            "CODESKEPTIC_LAUNCH_CLIENT_FAIL run exactly launch-client.py "
            "[--probe-only]",
            file=sys.stderr,
        )
        return 2
    try:
        return run_client(mode)
    except ClientError as error:
        print(f"CODESKEPTIC_LAUNCH_CLIENT_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
