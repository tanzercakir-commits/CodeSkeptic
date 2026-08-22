#!/usr/bin/env python3
"""Exercise the committed V7 runner against a real exclusive cgroup."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: smoke.py REPO CGROUP")
    repo = Path(sys.argv[1]).resolve(strict=True)
    cgroup = Path(sys.argv[2]).resolve(strict=True)
    sys.path.insert(0, str(repo / "scripts"))
    import run_determinism_qualification as qualification

    host = qualification.host_identity(
        "fedora-local-exclusive-smoke", "required", cgroup
    )
    affinity = host["cpu_affinity"]
    controller = host["controller_cpu_affinity"]
    if set(affinity) & set(controller):
        raise RuntimeError("controller overlaps measurement CPUs")

    before = qualification._capture_environment(
        affinity,
        measurement_cgroup=cgroup,
        expected_controller_affinity=controller,
    )
    child_program = (
        "import hashlib,json,os,time; "
        "start=time.monotonic(); value=b'codeskeptic'; "
        "\nwhile time.monotonic()-start < 0.5: value=hashlib.sha256(value).digest(); "
        "\nprint(json.dumps({'affinity':sorted(os.sched_getaffinity(0)),"
        "'cgroup':open('/proc/self/cgroup',encoding='ascii').read().strip()}))"
    )
    command = [
        sys.executable,
        str(repo / "scripts" / "run_in_measurement_cgroup.py"),
        "--cgroup",
        str(cgroup),
        "--cpus",
        ",".join(str(cpu) for cpu in affinity),
        "--",
        sys.executable,
        "-c",
        child_program,
    ]
    started = time.monotonic_ns()
    completed = subprocess.run(
        command,
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    wall_ms = max(1, (time.monotonic_ns() - started + 999_999) // 1_000_000)
    if completed.returncode != 0:
        raise RuntimeError(
            f"wrapper failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    child = json.loads(completed.stdout)
    if child.get("affinity") != affinity:
        raise RuntimeError("child affinity differs from measurement cgroup")
    authority_root = Path("/sys/fs/cgroup").resolve(strict=True)
    expected_membership = "0::/" + cgroup.relative_to(authority_root).as_posix()
    membership_lines = str(child.get("cgroup", "")).splitlines()
    if membership_lines != [expected_membership]:
        raise RuntimeError("child cgroup membership differs from requested group")

    after = qualification._capture_environment(
        affinity,
        measurement_cgroup=cgroup,
        expected_controller_affinity=controller,
    )
    decision = qualification._evaluate_runtime_environment(
        before,
        after,
        wall_ms,
        affinity,
        host["host_logical_cpus"],
        qualification.ENVIRONMENT_POLICY,
        True,
    )
    owned = decision["metrics"]["cgroup_owned_cpu_ms"]
    if owned <= 0:
        raise RuntimeError("real cgroup CPU accounting did not advance")
    if not decision["valid"]:
        raise RuntimeError(
            "real cgroup environment decision failed: "
            + "; ".join(decision["violations"])
        )
    print(json.dumps({
        "affinity": affinity,
        "controller": controller,
        "cgroup": cgroup.name,
        "cgroup_owned_cpu_ms": owned,
        "decision_valid": decision["valid"],
        "violations": decision["violations"],
        "wall_ms": wall_ms,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
