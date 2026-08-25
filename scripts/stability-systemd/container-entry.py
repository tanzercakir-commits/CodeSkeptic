#!/usr/bin/env python3
"""Fail-closed entrypoint for the real P10-09 controller and verifier."""

from __future__ import annotations

import os
import resource
import sys
from pathlib import Path
from typing import NoReturn, Sequence


EXPECTED_CGROUP = "/system.slice/codeskeptic-stability.service/controller"
EXPECTED_AFFINITY = frozenset(range(4, 12))
EXPECTED_NOFILE = (4096, 4096)
COMMANDS = {
    "run": (
        "/usr/bin/python3",
        "-B",
        "/authority/source/scripts/run_stability_campaign.py",
        "run",
        "--config",
        "/config/runtime.json",
        "--output",
        "/evidence",
    ),
    "verify": (
        "/usr/bin/python3",
        "-B",
        "/authority/source/scripts/run_stability_campaign.py",
        "verify",
        "--config",
        "/config/runtime.json",
        "--evidence",
        "/evidence",
    ),
}


class EntryError(RuntimeError):
    """A controlled container process-contract rejection."""


def validate_process_contract() -> None:
    if os.geteuid() != 0:
        raise EntryError("container entry is not root")
    if os.getpid() != 1:
        raise EntryError("container entry is not PID 1")
    record = Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
    if record != f"0::{EXPECTED_CGROUP}":
        raise EntryError("container entry cgroup identity drift")
    if os.sched_getaffinity(0) != EXPECTED_AFFINITY:
        raise EntryError("container entry CPU affinity drift")
    if resource.getrlimit(resource.RLIMIT_NOFILE) != EXPECTED_NOFILE:
        raise EntryError("container entry open-file limit drift")


def main(argv: Sequence[str] | None = None) -> NoReturn:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or arguments[0] not in COMMANDS:
        raise EntryError("container role is missing or malformed")
    validate_process_contract()
    command = COMMANDS[arguments[0]]
    try:
        os.execv(command[0], command)
    except OSError as error:
        raise EntryError(f"cannot execute the {arguments[0]} role: {error}") from error
    raise AssertionError("os.execv returned unexpectedly")


if __name__ == "__main__":
    try:
        main()
    except (EntryError, OSError, TypeError, ValueError) as error:
        print(
            f"CODESKEPTIC_STABILITY_CONTAINER_ENTRY_FAIL {error}",
            file=sys.stderr,
        )
        raise SystemExit(2)
