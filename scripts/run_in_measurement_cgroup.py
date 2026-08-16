#!/usr/bin/env python3
"""Move one measurement command into a prevalidated cgroup, then exec it."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


def fail(message: str) -> "NoReturn":
    print(f"MEASUREMENT_CGROUP_FAIL {message}", file=sys.stderr)
    raise SystemExit(125)


def parse_cpus(value: str) -> list[int]:
    if re.fullmatch(r"[0-9]{1,5}(?:,[0-9]{1,5})*", value) is None:
        fail("CPU list is malformed")
    cpus = [int(item) for item in value.split(",")]
    if not cpus or cpus != sorted(set(cpus)) or cpus[-1] > 65535:
        fail("CPU list is malformed")
    return cpus


def enter_measurement_cgroup(
    cgroup_path: Path, cpus: list[int],
    authority_root: Path = Path("/sys/fs/cgroup"),
) -> Path:
    try:
        authority = authority_root.resolve(strict=True)
        cgroup = cgroup_path.resolve(strict=True)
        cgroup.relative_to(authority)
    except (FileNotFoundError, OSError, ValueError):
        fail("measurement cgroup is unavailable")
    if cgroup == authority or not cgroup.is_dir():
        fail("measurement cgroup is not a dedicated child")
    flags = os.O_WRONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(cgroup / "cgroup.procs", flags)
        try:
            payload = f"{os.getpid()}\n".encode("ascii")
            if os.write(descriptor, payload) != len(payload):
                fail("measurement cgroup move was incomplete")
        finally:
            os.close(descriptor)
    except OSError:
        fail("cannot enter measurement cgroup")
    try:
        effective = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        fail("cannot verify measurement CPU affinity")
    if effective != cpus:
        fail("measurement CPU affinity differs from exclusive cgroup")
    return cgroup


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cgroup", type=Path, required=True)
    parser.add_argument("--cpus", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command or any("\x00" in item for item in command):
        fail("command is missing or malformed")
    cpus = parse_cpus(args.cpus)
    enter_measurement_cgroup(args.cgroup, cpus)
    try:
        os.execv(command[0], command)
    except OSError:
        fail("cannot execute measurement command")


if __name__ == "__main__":
    raise SystemExit(main())
