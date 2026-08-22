#!/usr/bin/env python3
"""Fail closed unless a qualification container inherited the controller cgroup."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: container-entry.py COMMAND [ARG ...]")
    expected = os.environ.pop("CODESKEPTIC_EXPECTED_CONTROLLER_CGROUP", None)
    measurement_raw = os.environ.pop("CODESKEPTIC_MEASUREMENT_CGROUP", None)
    if expected is None or measurement_raw is None:
        raise RuntimeError("container cgroup authority environment is missing")
    lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    if lines != [expected]:
        raise RuntimeError("container escaped the controller cgroup")
    measurement = Path(measurement_raw).resolve(strict=True)
    authority = Path("/sys/fs/cgroup").resolve(strict=True)
    measurement.relative_to(authority)
    flags = os.O_WRONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(measurement / "cgroup.procs", flags)
    os.close(descriptor)
    events = dict(
        line.split(" ", 1)
        for line in (measurement / "cgroup.events")
        .read_text(encoding="ascii")
        .splitlines()
    )
    if events.get("populated") != "0" or events.get("frozen") != "0":
        raise RuntimeError("measurement cgroup is populated or frozen at entry")
    os.execvp(sys.argv[1], sys.argv[1:])
    raise AssertionError("exec returned")


if __name__ == "__main__":
    raise SystemExit(main())
