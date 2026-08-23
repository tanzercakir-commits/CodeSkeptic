#!/usr/bin/env python3
"""Contracts for Phase 10 determinism and performance qualification."""

from __future__ import annotations

import copy
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_determinism_qualification as qualification  # noqa: E402
import run_in_measurement_cgroup as measurement_wrapper  # noqa: E402


KINDS = ("unit", "real-repository", "release-candidate")
SAMPLE_BYTES = b"int sample;\n"
THESIS_MANIFEST_BYTES = b"sample.cpp CLEAN 0\n"


def temporary_root(value: str) -> Path:
    """Return the real directory behind a platform temporary-path alias."""

    return Path(value).resolve(strict=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def manifest() -> dict:
    inputs = {
        "unit": {
            "mode": "thesis-corpus",
            "manifest": "tests/thesis_corpus/thesis_expected.txt",
        },
        "real-repository": {
            "mode": "repository",
            "path": "src",
            "policy": "no-absolute-paths",
        },
        "release-candidate": {
            "mode": "release-candidate",
            "project": "llama-cpp",
            "realworld_manifest": "scripts/realworld_manifest.json",
            "translation_units": ["src/sample.cpp"],
        },
    }
    return {
        "schema": qualification.MANIFEST_SCHEMA,
        "repetitions": 10,
        "performance_regression_limit_percent": 10,
        "environment_policy": {
            "batch_max_overhead_ms": 60000,
            "idle_seconds": 30,
            "idle_max_overshoot_ms": 2000,
            "idle_host_external_cpu_limit_basis_points": 50,
            "idle_affinity_external_cpu_limit_basis_points": 200,
            "idle_cpu_pressure_some_limit_basis_points": 200,
            "idle_memory_pressure_full_limit_basis_points": 0,
            "idle_io_pressure_full_limit_basis_points": 0,
            "runtime_affinity_external_cpu_limit_basis_points": 200,
            "thermal_throttle_limit_ms": 0,
        },
        "workloads": [
            {
                "id": kind,
                "kind": kind,
                "input": inputs[kind],
                "analyzer_args": [],
                "wall_timeout_seconds": 1800,
                "tu_timeout_seconds": 300,
                "tu_memory_mib": 4096,
                "measurement_iterations": 10 if kind == "unit" else 1,
                "minimum_batch_cpu_ms": 5000 if kind == "unit" else 0,
            }
            for kind in KINDS
        ],
    }


def metric(value: int) -> dict:
    return {
        "count": 10,
        "min": value,
        "median": value,
        "p90": value,
        "max": value,
    }


def workload_source_root(kind: str, repo_root: Path = ROOT) -> Path:
    return (
        repo_root.parent / f".{repo_root.name}-release-fixture"
        if kind == "release-candidate" else repo_root
    )


def fixture_build_toolchain() -> dict:
    return {
        "cmake_cache_schema": qualification.CMAKE_CACHE_IDENTITY_SCHEMA,
        "cmake_cache_canonical_sha256": "d" * 64,
        "cmake": "/fixture/cmake",
        "ninja": "/fixture/ninja",
        "c_compiler": "/fixture/clang-20",
        "cxx_compiler": "/fixture/clang++-20",
        "generator": "Ninja",
    }


def input_receipt(kind: str, repo_root: Path = ROOT) -> dict:
    source_root = workload_source_root(kind, repo_root)
    marker = "$RELEASE_SOURCE" if kind == "release-candidate" else "$REPO"
    if kind == "unit":
        build_root = repo_root.parent / f".{repo_root.name}-unit-build"
        relative = "tests/thesis_corpus/sample.cpp"
    elif kind == "real-repository":
        build_root = repo_root.parent / f".{repo_root.name}-build"
        relative = "src/sample.cpp"
    else:
        build_root = repo_root.parent / f".{repo_root.name}-release-build"
        relative = "src/sample.cpp"
    roots = qualification._normalization_roots(
        repo_root, kind, source_root, build_root
    )
    source = source_root / relative
    execution = {
        "working_directory": str(source_root),
        "canonical_path": str(source),
        "output": "",
        "command_line": ["clang++", "-c", str(source)],
    }
    normalized = {
        field: qualification._replace_root(execution[field], roots)
        for field in ("working_directory", "canonical_path", "output")
    }
    normalized["command_line"] = [
        qualification._replace_root(token, roots)
        for token in execution["command_line"]
    ]
    command = {
        "path": f"{marker}/{relative}",
        "compile_command_sha256": qualification._translation_unit_command_sha256(
            execution
        ),
        "command_ordinal": 0,
        "phase": "analysis",
        "execution": execution,
        "normalized_execution": normalized,
    }
    files = [{"path": relative, "sha256": sha256(SAMPLE_BYTES)}]
    extra = {
        "selected_compile_commands_sha256": (
            qualification._selected_commands_sha256([command])
        ),
    }
    if kind == "unit":
        extra["corpus_manifest_sha256"] = sha256(THESIS_MANIFEST_BYTES)
    elif kind == "real-repository":
        extra.update({
            "policy": "no-absolute-paths",
            "repository_source_manifest_sha256": qualification.digest_json(files),
            "build_toolchain": fixture_build_toolchain(),
        })
    else:
        extra.update(qualification._release_manifest_identity(
            repo_root, manifest()["workloads"][2]
        ))
        extra["build_toolchain"] = fixture_build_toolchain()
    value = {
        "kind": kind,
        "identity_sha256": "",
        "translation_unit_sha256": qualification.digest_json([relative]),
        "translation_unit_plan_sha256": qualification.digest_json(
            [qualification._normalized_command(command)]
        ),
        "translation_units": 1,
        "source_marker": marker,
        "roots": [
            {"marker": root_marker, "path": str(path)}
            for path, root_marker in sorted(roots, key=lambda item: item[1])
        ],
        "files": files,
        "commands": [command],
        "extra": extra,
    }
    value["identity_sha256"] = qualification.digest_json(
        qualification._input_identity_material(value)
    )
    qualification._validate_input_receipt(value, kind)
    return value


def analyzer_report(
    kind: str, repo_root: Path = ROOT, input_value: dict | None = None
) -> dict:
    input_value = input_value or input_receipt(kind, repo_root)
    command = input_value["commands"][0]
    return {
        "tool": "CodeSkeptic",
        "status": "clean",
        "complete": True,
        "exit_code": 0,
        "coverage": {
            "attempted_tus": 1,
            "analyzed_tus": 1,
            "broken_tus": 0,
            "incomplete_functions": 0,
        },
        "evidence": {field: False for field in qualification.EVIDENCE_FIELDS},
        "finding_counts": {"total": 0, "blocking": 0, "report_only": 0},
        "translation_units": [{
            "path": command["execution"]["canonical_path"],
            "compile_command_sha256": command["compile_command_sha256"],
            "command_ordinal": 0,
            "phase": "analysis",
            "status": "completed",
            "duration_ms": 1,
            "peak_memory_kib": 100,
            "timeout_seconds": 300,
            "memory_mib": 4096,
            "origin": "executed",
            "checkpoint_key_sha256": "",
            "payload_sha256": "",
        }],
        "total": 0,
        "diagnostics": [],
    }


def semantic_sha(kind: str, repo_root: Path = ROOT) -> str:
    input_value = input_receipt(kind, repo_root)
    report = analyzer_report(kind, repo_root, input_value)
    release = workload_source_root(kind, repo_root) if kind == "release-candidate" else None
    return qualification.digest_json(
        qualification.semantic_projection(
            report, repo_root, release, input_value, (300, 4096)
        )
    )


def time_log(value: int) -> bytes:
    seconds = value / 2000
    return (
        f"\tUser time (seconds): {seconds:.3f}\n"
        f"\tSystem time (seconds): {seconds:.3f}\n"
        f"\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:00.{value:03d}\n"
        f"\tMaximum resident set size (kbytes): {value}\n"
        "\tExit status: 0\n"
    ).encode()


def environment_snapshot(
    *, host_cpus: int = 4, affinity: list[int] | None = None,
    host_busy_ticks: int = 1000, affinity_busy_ticks: int = 1000,
    owned_usage_us: int = 1_000_000,
) -> dict:
    affinity = [0, 1] if affinity is None else affinity
    controller = [
        cpu for cpu in range(host_cpus) if cpu not in set(affinity)
    ][:max(1, len(affinity))]
    pressure = {
        name: {"some_total_us": 100, "full_total_us": 10}
        for name in ("cpu", "memory", "io")
    }
    return {
        "cpu": {
            "clock_ticks_per_second": 100,
            "host_logical_cpus": host_cpus,
            "host_busy_ticks": host_busy_ticks,
            "affinity_busy_ticks": affinity_busy_ticks,
        },
        "global_pressure": copy.deepcopy(pressure),
        "system_uclamp": {
            "minimum_limit": 1024,
            "maximum_limit": 1024,
        },
        "measurement_cgroup": {
            "mode": qualification.MEASUREMENT_ENVIRONMENT_EXCLUSIVE,
            "controller_cpu_affinity": controller,
            "effective_cpu_affinity": list(affinity),
            "exclusive_cpu_affinity": list(affinity),
            "partition": "isolated",
            "uclamp_min": 1024,
            "uclamp_max": 1024,
            "ancestor_uclamp_max": [],
            "populated": 0,
            "frozen": 0,
            "cpu_usage_us": owned_usage_us,
            "nr_throttled": 0,
            "throttled_us": 0,
            "memory_oom": 0,
            "memory_oom_kill": 0,
            "memory_oom_group_kill": 0,
            "pressure": copy.deepcopy(pressure),
        },
        "cpufreq": [
            {
                "cpu": cpu, "driver": "intel_pstate",
                "governor": "powersave", "minimum_khz": 400000,
                "maximum_khz": 4400000, "current_khz": 4000000,
            }
            for cpu in affinity
        ],
        "thermal": [
            {
                "cpu": cpu, "core_count": 1, "core_total_ms": 2,
                "package_count": 3, "package_total_ms": 4,
            }
            for cpu in affinity
        ],
    }


def environment_evidence(
    value: int, *, scope: str = "inner-record-only", required: bool = False,
) -> tuple[dict, bytes]:
    ticks = value // 10
    before = environment_snapshot()
    after = copy.deepcopy(before)
    after["cpu"]["host_busy_ticks"] += ticks
    after["cpu"]["affinity_busy_ticks"] += ticks
    after["measurement_cgroup"]["cpu_usage_us"] += value * 1000
    decision = qualification._evaluate_runtime_environment(
        before, after, value, [0, 1], 4,
        qualification.ENVIRONMENT_POLICY, required,
    )
    payload = {
        "schema": qualification.ENVIRONMENT_SCHEMA,
        "scope": scope,
        "wall_ms": value,
        "before": before,
        "after": after,
        "decision": decision,
    }
    if scope == "performance-batch":
        payload["gated_wall_ms"] = value
    return decision, qualification.canonical_json(payload)


def idle_preflight_evidence(*, required: bool = True) -> tuple[dict, bytes]:
    before = environment_snapshot()
    after = copy.deepcopy(before)
    decision = qualification._evaluate_idle_environment(
        before, after, 30_000, [0, 1], 4,
        qualification.ENVIRONMENT_POLICY, required,
    )
    payload = {
        "schema": qualification.ENVIRONMENT_SCHEMA,
        "scope": "idle-preflight",
        "wall_ms": 30_000,
        "before": before,
        "after": after,
        "decision": decision,
    }
    return decision, qualification.canonical_json(payload)


def hardware_identity() -> dict:
    return {
        "architecture": "x86_64",
        "cpu_model": "test cpu",
        "logical_cpus": 2,
        "host_logical_cpus": 4,
        "cpu_affinity_source": qualification.AFFINITY_SOURCE_CGROUP,
        "cpu_affinity": [0, 1],
        "cpu_uclamp_source": qualification.UCLAMP_SOURCE_CGROUP,
        "cpu_uclamp_min": 1024,
        "cpu_uclamp_max": 1024,
        "cpu_uclamp_ancestor_max": [],
        "system_uclamp_min_limit": 1024,
        "system_uclamp_max_limit": 1024,
        "controller_cpu_affinity": [2, 3],
        "measurement_environment": (
            qualification.MEASUREMENT_ENVIRONMENT_EXCLUSIVE
        ),
        "measurement_cgroup_populated": 0,
        "measurement_cgroup_frozen": 0,
        "memory_bytes": 8 * 1024 * 1024 * 1024,
    }


def measurement_cgroup_fixture(
    authority: Path, *, effective: str = "0-1",
    exclusive: str = "0-1", partition: str = "isolated",
    members: str = "", uclamp_min: str = "100.00",
    uclamp_max: str = "100.00",
) -> Path:
    group = authority / "codeskeptic.measurement"
    group.mkdir(parents=True)
    values = {
        "cpuset.cpus.effective": effective,
        "cpuset.cpus.exclusive.effective": exclusive,
        "cpuset.cpus.partition": partition,
        "cgroup.procs": members,
        "cgroup.events": "populated 0\nfrozen 0\n",
        "cpu.uclamp.min": uclamp_min,
        "cpu.uclamp.max": uclamp_max,
        "cpu.stat": (
            "usage_usec 1000000\n"
            "nr_throttled 0\n"
            "throttled_usec 0\n"
        ),
        "memory.events": "oom 0\noom_kill 0\noom_group_kill 0\n",
    }
    pressure = (
        "some avg10=0.00 avg60=0.00 avg300=0.00 total=100\n"
        "full avg10=0.00 avg60=0.00 avg300=0.00 total=10\n"
    )
    for resource in ("cpu", "memory", "io"):
        values[f"{resource}.pressure"] = pressure
    for name, value in values.items():
        (group / name).write_text(value, encoding="ascii")
    return group


def artifact_bytes(payload: dict) -> dict[str, bytes]:
    result: dict[str, bytes] = {
        qualification._idle_preflight_artifact_path(): idle_preflight_evidence()[1]
    }
    for workload in payload["workloads"]:
        kind = workload["kind"]
        input_value = payload["inputs"][kind]
        repo_root = qualification._root_for_marker(input_value, "$REPO")
        for run in workload["runs"]:
            for inner in run["inner_runs"]:
                paths = inner["artifacts"]
                result[paths[0]] = qualification.canonical_json(
                    analyzer_report(kind, repo_root, input_value)
                )
                result[paths[1]] = b""
                result[paths[2]] = b""
                result[paths[3]] = time_log(inner["metrics"]["wall_ms"])
                result[paths[4]] = environment_evidence(
                    inner["metrics"]["wall_ms"]
                )[1]
            result[run["environment_artifact"]] = environment_evidence(
                run["metrics"]["wall_ms"],
                scope="performance-batch", required=True,
            )[1]
    return result


def toolchain_identity() -> dict:
    return {
        name: {"sha256": f"{index:064x}", "version": f"{name} 1.0"}
        for index, name in enumerate(qualification.TOOLCHAIN_NAMES, 1)
    }


def initialize_source_repo(path: Path) -> dict:
    path.mkdir(parents=True)
    for relative in (
        ".github/workflows", "src", "fuzz", "scripts", "tests", "docs",
        "profiles",
    ):
        (path / relative).mkdir(parents=True)
    for relative, content in (
        ("CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n"),
        (".gitattributes", "* text eol=lf\n"),
        ("Dockerfile", "FROM scratch\n"),
        ("action.yml", "name: fixture\n"),
        (".github/workflows/fixture.yml", "name: fixture\n"),
        ("fuzz/fixture.cpp", "int fuzz_fixture;\n"),
        ("tests/CMakeLists.txt", "# fixture tests\n"),
        ("docs/fixture.md", "fixture\n"),
        ("docs/TODO.md", "# Queue\n\nbase\n"),
        ("profiles/fixture.txt", "fixture\n"),
    ):
        (path / relative).write_text(content, encoding="utf-8")
    (path / "src" / "sample.cpp").write_bytes(SAMPLE_BYTES)
    thesis_root = path / "tests" / "thesis_corpus"
    thesis_root.mkdir(parents=True)
    (thesis_root / "sample.cpp").write_bytes(SAMPLE_BYTES)
    (thesis_root / "thesis_expected.txt").write_bytes(THESIS_MANIFEST_BYTES)
    shutil.copyfile(
        ROOT / "scripts" / "run_realworld_campaign.py",
        path / "scripts" / "run_realworld_campaign.py",
    )
    shutil.copyfile(
        ROOT / "scripts" / "realworld_manifest.json",
        path / "scripts" / "realworld_manifest.json",
    )
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path,
                   check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"],
                   cwd=path, check=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "source"], cwd=path, check=True,
                   stdout=subprocess.DEVNULL)
    return qualification.source_manifest(path)


def git_commit(repo: Path, message: str) -> str:
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", message], cwd=repo, check=True,
        stdout=subprocess.DEVNULL,
    )
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()


def write_determinism_infrastructure(repo: Path, raw_manifest: dict) -> None:
    files = {
        "CMakeLists.txt": "# fixture project\n",
        ".github/workflows/determinism.yml": "name: fixture determinism\n",
        "scripts/determinism_workloads.json": qualification.canonical_json(
            raw_manifest
        ),
        "scripts/run_determinism_qualification.py": "# fixture runner\n",
        "scripts/run_in_measurement_cgroup.py": "# fixture cgroup entry\n",
        "tests/DeterminismQualificationTest.py": "# fixture contract\n",
        "tests/DeterminismWorkflowTest.py": "# fixture workflow contract\n",
    }
    for relative, content in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    (repo / "tests" / "CMakeLists.txt").write_text(
        "# fixture tests\n# determinism contracts\n", encoding="utf-8"
    )
    (repo / "docs" / "TODO.md").write_text(
        "# Queue\n\nphase-determinism-performance-qualification\n",
        encoding="utf-8",
    )


def process_is_running(pid: int) -> bool:
    status = Path(f"/proc/{pid}/status")
    try:
        state = next(
            line for line in status.read_text(encoding="utf-8").splitlines()
            if line.startswith("State:")
        )
    except StopIteration:
        return False
    except FileNotFoundError:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        try:
            observed = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(pid)],
                check=False,
                capture_output=True,
                text=True,
                timeout=0.5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return True
        state = observed.stdout.strip()
        if observed.returncode != 0 or not state:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            return True
        return not state.startswith("Z")
    return " Z " not in f" {state} " and "(zombie)" not in state


def write_llama_release_links(source: Path, build: Path) -> None:
    source.mkdir(parents=True, exist_ok=True)
    (build / "bin").mkdir(parents=True, exist_ok=True)
    for terminal in (
        "libggml-base.so.0.19.0",
        "libggml-cpu.so.0.19.0",
        "libggml.so.0.19.0",
        "libllama.so.0.0.1",
    ):
        (build / "bin" / terminal).write_bytes(b"library\n")
    for qualified, target in qualification.LLAMA_STAGING_BUILD_SYMLINKS.items():
        prefix, relative = qualified.split("/", 1)
        if prefix != "build":
            raise AssertionError("fixture symlink contract is malformed")
        (build / relative).symlink_to(target)


def baseline(
    manifest_sha: str,
    value: int = 100,
    repo_root: Path = ROOT,
    source_revision: str = "baseline-revision",
) -> dict:
    inputs = {kind: input_receipt(kind, repo_root) for kind in KINDS}
    semantics = {kind: semantic_sha(kind, repo_root) for kind in KINDS}
    return {
        "schema": qualification.BASELINE_SCHEMA,
        "manifest_sha256": manifest_sha,
        "performance_regression_limit_percent": 10,
        "semantic_reference": {
            kind: {
                "semantic_sha256": semantics[kind],
                "input_identity_sha256": inputs[kind]["identity_sha256"],
                "translation_unit_sha256": inputs[kind]["translation_unit_sha256"],
                "translation_unit_plan_sha256": inputs[kind]["translation_unit_plan_sha256"],
            }
            for kind in KINDS
        },
        "profiles": {
            "test-linux-x86_64": {
                "os": "Linux 6.19.10-300.fc44.x86_64",
                "provenance": {
                    "source_revision": source_revision,
                    "toolchain": toolchain_identity(),
                    "calibration": {
                        "evidence_path": (
                            "docs/evidence/phase10/determinism/calibrations/"
                            "test-linux-x86_64"
                        ),
                        "receipt_sha256": "8" * 64,
                    },
                    "promotion": {
                        "reason": "Initial protected performance baseline",
                        "previous_baseline_sha256": None,
                        "previous_profile_sha256": None,
                    },
                },
                "hardware": hardware_identity(),
                "workloads": {
                    kind: {
                        "semantic_sha256": semantics[kind],
                        "input_identity_sha256": inputs[kind]["identity_sha256"],
                        "translation_unit_sha256": inputs[kind]["translation_unit_sha256"],
                        "translation_unit_plan_sha256": inputs[kind]["translation_unit_plan_sha256"],
                        "statistics": {
                            "wall_ms": metric(5000 if kind == "unit" else value),
                            "cpu_ms": metric(5000 if kind == "unit" else value),
                            "peak_rss_kib": metric(500 if kind == "unit" else value),
                        },
                    }
                    for kind in KINDS
                },
            }
        },
    }


def calibration_receipt(
    manifest_sha: str,
    value: int = 100,
    repo_root: Path = ROOT,
    source_revision: str = "baseline-revision",
    source: dict | None = None,
) -> dict:
    accepted = receipt(manifest_sha, value, repo_root, source_revision, source)
    return {
        "schema": qualification.CALIBRATION_SCHEMA,
        "status": "calibration",
        "source": {
            **accepted["source"],
            "revision": source_revision,
        },
        "configuration": {
            "manifest_sha256": manifest_sha,
            "repetitions": 10,
            "performance_regression_limit_percent": 10,
            "environment_policy": qualification.ENVIRONMENT_POLICY,
        },
        "host": accepted["host"],
        "toolchain": accepted["toolchain"],
        "inputs": accepted["inputs"],
        "workloads": accepted["workloads"],
        "started_at": accepted["started_at"],
        "finished_at": accepted["finished_at"],
        "duration_ms": accepted["duration_ms"],
        "artifacts": accepted["artifacts"],
    }


def rejected_receipt(
    manifest_sha: str,
    message: str = "controlled rejection",
    repo_root: Path = ROOT,
    source_revision: str = "head-revision",
    source: dict | None = None,
) -> dict:
    accepted = receipt(
        manifest_sha, repo_root=repo_root,
        source_revision=source_revision, source=source,
    )
    failure = qualification._failure_record("qualification-error", message)
    return {
        "schema": qualification.REJECTED_SCHEMA,
        "status": "rejected",
        "source": accepted["source"],
        "configuration": accepted["configuration"],
        "host": accepted["host"],
        "toolchain": accepted["toolchain"],
        "inputs": {},
        "baseline": {"sha256": None, "profile": None},
        "decision": {
            "classification": "incomplete",
            "failures": [failure],
            "performance_regressions": [],
        },
        "observations": {"complete": False, "workloads": []},
        "started_at": accepted["started_at"],
        "finished_at": accepted["finished_at"],
        "duration_ms": accepted["duration_ms"],
        "artifacts": [],
    }


def receipt(
    manifest_sha: str,
    value: int = 100,
    repo_root: Path = ROOT,
    source_revision: str = "head-revision",
    source: dict | None = None,
) -> dict:
    inputs = {kind: input_receipt(kind, repo_root) for kind in KINDS}
    workloads = []
    _, preflight_raw = idle_preflight_evidence()
    artifacts = [{
        "path": qualification._idle_preflight_artifact_path(),
        "sha256": sha256(preflight_raw),
        "size": len(preflight_raw),
    }]
    for kind in KINDS:
        runs = []
        semantic = semantic_sha(kind, repo_root)
        iterations = 10 if kind == "unit" else 1
        inner_value = 500 if kind == "unit" else value
        for repetition in range(1, 11):
            inner_runs = []
            for iteration in range(1, iterations + 1):
                paths = qualification._iteration_artifact_paths(
                    kind, repetition, iteration
                )
                environment, environment_raw = environment_evidence(inner_value)
                data_by_path = {
                    paths[0]: qualification.canonical_json(
                        analyzer_report(kind, repo_root, inputs[kind])
                    ),
                    paths[1]: b"",
                    paths[2]: b"",
                    paths[3]: time_log(inner_value),
                    paths[4]: environment_raw,
                }
                artifacts.extend(
                    {"path": path, "sha256": sha256(data), "size": len(data)}
                    for path, data in data_by_path.items()
                )
                inner_runs.append({
                    "iteration": iteration,
                    "semantic_sha256": semantic,
                    "exit_code": 0,
                    "metrics": {
                        "wall_ms": inner_value,
                        "cpu_ms": inner_value,
                        "peak_rss_kib": inner_value,
                    },
                    "environment": environment,
                    "artifacts": paths,
                })
            run_metrics = {
                "wall_ms": inner_value * iterations,
                "cpu_ms": inner_value * iterations,
                "peak_rss_kib": inner_value,
            }
            batch_environment, batch_raw = environment_evidence(
                run_metrics["wall_ms"],
                scope="performance-batch", required=True,
            )
            batch_path = qualification._batch_environment_artifact_path(
                kind, repetition
            )
            artifacts.append({
                "path": batch_path,
                "sha256": sha256(batch_raw),
                "size": len(batch_raw),
            })
            runs.append(
                {
                    "repetition": repetition,
                    "semantic_sha256": semantic,
                    "exit_code": 0,
                    "metrics": run_metrics,
                    "measurement_iterations": iterations,
                    "batch_valid": True,
                    "environment_valid": batch_environment["valid"],
                    "environment": batch_environment,
                    "environment_artifact": batch_path,
                    "inner_runs": inner_runs,
                    "artifacts": qualification._run_artifact_paths(
                        kind, repetition, iterations
                    ),
                }
            )
        outer_wall_cpu = inner_value * iterations
        workloads.append(
            {
                "id": kind,
                "kind": kind,
                "semantic_sha256": semantic,
                "runs": runs,
                "statistics": {
                    "wall_ms": metric(outer_wall_cpu),
                    "cpu_ms": metric(outer_wall_cpu),
                    "peak_rss_kib": metric(inner_value),
                },
            }
        )
    return {
        "schema": qualification.RECEIPT_SCHEMA,
        "status": "accepted",
        "source": source or {
            "revision": source_revision,
            "manifest_sha256": "2" * 64,
            "file_count": 1,
        },
        "configuration": {
            "manifest_sha256": manifest_sha,
            "repetitions": 10,
            "performance_regression_limit_percent": 10,
            "performance_policy": "required",
            "environment_policy": qualification.ENVIRONMENT_POLICY,
        },
        "host": {
            "class_id": "test-linux-x86_64",
            "os": "Linux 6.19.10-300.fc44.x86_64",
            **hardware_identity(),
        },
        "toolchain": toolchain_identity(),
        "inputs": {
            kind: inputs[kind]
            for kind in KINDS
        },
        "workloads": workloads,
        "baseline": {
            "profile": "test-linux-x86_64",
            "sha256": "7" * 64,
            "semantic_gate": "pass",
            "performance_gate": "pass",
            "regressions": [],
        },
        "started_at": "2026-08-15T00:00:00+00:00",
        "finished_at": "2026-08-15T00:01:00+00:00",
        "duration_ms": 60_000,
        "failures": [],
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
    }


class DeterminismQualificationTest(unittest.TestCase):
    def test_exclusive_batch_environment_uses_distinct_v7_schemas(self) -> None:
        self.assertEqual(
            qualification.MANIFEST_SCHEMA,
            "codeskeptic-determinism-workloads-v3",
        )
        self.assertEqual(
            qualification.BASELINE_SCHEMA,
            "codeskeptic-determinism-baseline-v7",
        )
        self.assertEqual(
            qualification.RECEIPT_SCHEMA,
            "codeskeptic-determinism-qualification-v7",
        )
        self.assertEqual(
            qualification.REJECTED_SCHEMA,
            "codeskeptic-determinism-rejected-v7",
        )
        self.assertEqual(
            qualification.CALIBRATION_SCHEMA,
            "codeskeptic-determinism-calibration-v7",
        )
        self.assertEqual(
            qualification.ENVIRONMENT_SCHEMA,
            "codeskeptic-determinism-environment-v3",
        )
        sample = receipt(qualification.digest_json(manifest()))
        self.assertEqual(len(sample["artifacts"]), 631)
        self.assertEqual(len(artifact_bytes(sample)), 631)
        self.assertEqual(
            [len(item["runs"]) for item in sample["workloads"]],
            [10, 10, 10],
        )
        self.assertEqual(
            [len(item["runs"][0]["inner_runs"])
             for item in sample["workloads"]],
            [10, 1, 1],
        )
        forged_policy = copy.deepcopy(sample)
        forged_policy["configuration"]["environment_policy"][
            "idle_io_pressure_full_limit_basis_points"
        ] = False
        with self.assertRaisesRegex(
            qualification.QualificationError, "configuration differs"
        ):
            qualification.validate_receipt_payload(
                forged_policy, manifest(),
                baseline(qualification.digest_json(manifest())),
            )

    def test_v7_baseline_profile_binds_exact_kernel_os_identity(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        current = receipt(manifest_sha)
        pinned = baseline(manifest_sha)

        self.assertTrue(qualification._profile_matches(
            pinned["profiles"]["test-linux-x86_64"],
            current["host"], current["toolchain"],
        ))
        current["host"]["os"] = "Linux 7.1.8-200.fc44.x86_64"
        self.assertFalse(qualification._profile_matches(
            pinned["profiles"]["test-linux-x86_64"],
            current["host"], current["toolchain"],
        ))
        with self.assertRaisesRegex(
            qualification.QualificationError, "baseline OS.*inventory drift"
        ):
            qualification.validate_receipt_payload(
                current, raw_manifest, pinned
            )

        missing_os = copy.deepcopy(pinned)
        missing_os["profiles"]["test-linux-x86_64"].pop("os")
        with self.assertRaises(qualification.QualificationError):
            qualification.validate_baseline(missing_os, manifest_sha)
        malformed_os = copy.deepcopy(pinned)
        malformed_os["profiles"]["test-linux-x86_64"]["os"] = 7
        with self.assertRaisesRegex(
            qualification.QualificationError, "baseline OS identity"
        ):
            qualification.validate_baseline(malformed_os, manifest_sha)

        legacy = copy.deepcopy(pinned)
        legacy["schema"] = "codeskeptic-determinism-baseline-v6"
        with self.assertRaisesRegex(
            qualification.QualificationError, "unsupported.*baseline schema"
        ):
            qualification.validate_baseline(legacy, manifest_sha)

        malformed_receipt = receipt(manifest_sha)
        malformed_receipt["host"]["os"] = "\n"
        with self.assertRaisesRegex(
            qualification.QualificationError, "receipt host OS identity"
        ):
            qualification.validate_receipt_payload(
                malformed_receipt, raw_manifest, pinned
            )
        malformed_calibration = calibration_receipt(manifest_sha)
        malformed_calibration["host"]["os"] = "\x00Linux"
        with self.assertRaisesRegex(
            qualification.QualificationError, "calibration host OS identity"
        ):
            qualification._validate_calibration_payload(
                malformed_calibration, raw_manifest
            )
        malformed_rejected = rejected_receipt(manifest_sha)
        malformed_rejected["host"]["os"] = []
        with self.assertRaisesRegex(
            qualification.QualificationError, "rejected host OS identity"
        ):
            qualification._validate_rejected_payload(
                malformed_rejected, raw_manifest, None
            )

        legacy_receipt = receipt(manifest_sha)
        legacy_receipt["schema"] = "codeskeptic-determinism-qualification-v6"
        with self.assertRaisesRegex(
            qualification.QualificationError, "receipt is not accepted"
        ):
            qualification.validate_receipt_payload(
                legacy_receipt, raw_manifest, pinned
            )
        legacy_calibration = calibration_receipt(manifest_sha)
        legacy_calibration["schema"] = "codeskeptic-determinism-calibration-v6"
        with self.assertRaisesRegex(
            qualification.QualificationError, "classification drift"
        ):
            qualification._validate_calibration_payload(
                legacy_calibration, raw_manifest
            )
        legacy_rejected = rejected_receipt(manifest_sha)
        legacy_rejected["schema"] = "codeskeptic-determinism-rejected-v6"
        with self.assertRaisesRegex(
            qualification.QualificationError, "classification drift"
        ):
            qualification._validate_rejected_payload(
                legacy_rejected, raw_manifest, None
            )

    def test_v7_profile_tolerates_boot_page_accounting_not_capacity_drift(
        self,
    ) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        current = receipt(manifest_sha)
        pinned = baseline(manifest_sha)
        profile = pinned["profiles"]["test-linux-x86_64"]

        current["host"]["memory_bytes"] -= 8192
        self.assertTrue(qualification._profile_matches(
            profile, current["host"], current["toolchain"],
        ))
        qualification.validate_receipt_payload(current, raw_manifest, pinned)

        current["host"]["memory_bytes"] = (
            profile["hardware"]["memory_bytes"]
            + qualification.MEMORY_PROFILE_TOLERANCE_BYTES
        )
        self.assertTrue(qualification._profile_matches(
            profile, current["host"], current["toolchain"],
        ))
        qualification.validate_receipt_payload(current, raw_manifest, pinned)

        current["host"]["memory_bytes"] = (
            profile["hardware"]["memory_bytes"]
            + qualification.MEMORY_PROFILE_TOLERANCE_BYTES
            + 4096
        )
        self.assertFalse(qualification._profile_matches(
            profile, current["host"], current["toolchain"],
        ))
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "baseline OS, hardware, or toolchain inventory drift",
        ):
            qualification.validate_receipt_payload(
                current, raw_manifest, pinned
            )

        current["host"]["memory_bytes"] = profile["hardware"]["memory_bytes"]
        current["host"]["cpu_model"] += " drift"
        self.assertFalse(qualification._profile_matches(
            profile, current["host"], current["toolchain"],
        ))

    def test_v7_verifier_preserves_narrow_legacy_exact_memory_rejection(
        self,
    ) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        current = receipt(manifest_sha)
        pinned = baseline(manifest_sha)
        current["host"]["memory_bytes"] -= 8192
        failure = qualification._failure_record(
            "profile-unavailable",
            "baseline performance profile is unavailable for "
            "test-linux-x86_64",
        )
        rejected = {
            "schema": qualification.REJECTED_SCHEMA,
            "status": "rejected",
            "source": current["source"],
            "configuration": current["configuration"],
            "host": current["host"],
            "toolchain": current["toolchain"],
            "inputs": current["inputs"],
            "baseline": {
                "sha256": current["baseline"]["sha256"],
                "profile": current["host"]["class_id"],
            },
            "decision": {
                "classification": "complete-gate-rejection",
                "failures": [failure],
                "performance_regressions": [],
            },
            "observations": {
                "complete": True,
                "workloads": current["workloads"],
            },
            "started_at": current["started_at"],
            "finished_at": current["finished_at"],
            "duration_ms": current["duration_ms"],
            "artifacts": current["artifacts"],
        }

        qualification._validate_rejected_payload(
            rejected, raw_manifest, pinned
        )
        self.assertFalse(
            qualification._legacy_exact_memory_rejection_matches(
                [failure], [], None, current["host"], current["toolchain"],
                "required",
            )
        )

        forged = copy.deepcopy(rejected)
        forged["host"]["memory_bytes"] = pinned["profiles"][
            "test-linux-x86_64"
        ]["hardware"]["memory_bytes"]
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "rejected decision differs from recomputed gate failures",
        ):
            qualification._validate_rejected_payload(
                forged, raw_manifest, pinned
            )

    def test_required_baseline_preflight_precedes_release_preparation(
        self,
    ) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        pinned = baseline(manifest_sha)
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            repo = root / "repo"
            build = root / "build"
            repo.mkdir()
            build.mkdir()
            binaries = {}
            for name in (
                "codeskeptic", "clang", "time", "cmake", "ninja",
                "c-compiler", "cxx-compiler",
            ):
                path = root / name
                path.write_bytes(b"fixture\n")
                binaries[name] = path
            args = mock.Mock(
                repo_root=repo,
                build_path=build,
                binary=binaries["codeskeptic"],
                clang=binaries["clang"],
                time_binary=binaries["time"],
                cmake=binaries["cmake"],
                ninja=binaries["ninja"],
                c_compiler=binaries["c-compiler"],
                cxx_compiler=binaries["cxx-compiler"],
                output=root / "evidence",
                manifest=root / "manifest.json",
                baseline=root / "baseline.json",
                repetitions=10,
                revision="head-revision",
                measurement_cgroup=None,
                hardware_class="test-linux-x86_64",
                performance_policy="required",
                prepare_release_candidate=True,
                release_workspace=root / "release-workspace",
                release_source=None,
                release_build=None,
                jobs=2,
                establish_baseline=False,
                candidate_baseline_output=None,
                baseline_authority_root=repo,
            )
            events = []

            def regular_kind(path: Path) -> str:
                return "directory" if path in {repo, build} else "regular"

            def load_pinned_baseline(*unused: object) -> dict:
                events.append("baseline")
                return pinned

            drifted_hardware = hardware_identity()
            drifted_hardware["memory_bytes"] += (
                qualification.MEMORY_PROFILE_TOLERANCE_BYTES + 4096
            )

            with (
                mock.patch.object(
                    qualification, "_regular_kind", side_effect=regular_kind,
                ),
                mock.patch.object(
                    qualification, "load_manifest", return_value=raw_manifest,
                ),
                mock.patch.object(
                    qualification, "source_manifest", return_value={
                        "revision": "head-revision",
                        "manifest_sha256": "2" * 64,
                        "file_count": 1,
                    },
                ),
                mock.patch.object(
                    qualification, "_git_output", return_value="",
                ),
                mock.patch.object(
                    qualification, "host_identity", return_value={
                        "class_id": "test-linux-x86_64",
                        "os": "Linux 6.19.10-300.fc44.x86_64",
                        **drifted_hardware,
                    },
                ),
                mock.patch.object(
                    qualification, "toolchain_identity",
                    return_value=toolchain_identity(),
                ),
                mock.patch.object(
                    qualification, "load_baseline",
                    side_effect=load_pinned_baseline,
                ),
                mock.patch.object(
                    qualification, "verify_baseline_authority",
                    side_effect=lambda *unused: events.append("authority"),
                ),
                mock.patch.object(
                    qualification, "prepare_release_candidate",
                    side_effect=lambda *unused: events.append("release"),
                ),
                mock.patch.object(qualification, "_persist_rejection"),
            ):
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "baseline OS, hardware, or toolchain inventory drift",
                ):
                    qualification.run_qualification(args)

            self.assertEqual(events, ["baseline", "authority"])

    def test_baseline_preflight_preserves_promotion_and_establishment(
        self,
    ) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        pinned = baseline(manifest_sha)
        host = receipt(manifest_sha)["host"]
        host["memory_bytes"] += (
            qualification.MEMORY_PROFILE_TOLERANCE_BYTES + 4096
        )
        toolchain = toolchain_identity()

        promotion_args = mock.Mock(
            establish_baseline=False,
            performance_policy="required",
            candidate_baseline_output=Path("candidate.json"),
            baseline_authority_root=Path("authority"),
        )
        with (
            mock.patch.object(
                qualification, "load_baseline", return_value=pinned,
            ) as load,
            mock.patch.object(
                qualification, "verify_baseline_authority",
            ) as verify,
        ):
            self.assertIs(
                qualification._preflight_qualification_baseline(
                    promotion_args, Path("baseline.json"), manifest_sha,
                    host, toolchain,
                ),
                pinned,
            )
        load.assert_called_once()
        verify.assert_called_once()

        establishment_args = mock.Mock(establish_baseline=True)
        with mock.patch.object(
            qualification, "load_baseline",
            side_effect=AssertionError("establishment loaded a baseline"),
        ) as load:
            self.assertIsNone(
                qualification._preflight_qualification_baseline(
                    establishment_args, Path("baseline.json"), manifest_sha,
                    host, toolchain,
                )
            )
        load.assert_not_called()

    def test_required_measurement_environment_rejects_v5_and_requires_cgroup(self) -> None:
        self.assertEqual(
            qualification._measurement_environment_mode("required", None),
            "unavailable",
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "measurement cgroup"
        ):
            qualification._require_measurement_environment(
                "required", None, [0, 2]
            )

    def test_v5_wire_formats_are_rejected_after_v6_authority_migration(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        old_manifest = copy.deepcopy(raw_manifest)
        old_manifest["schema"] = "codeskeptic-determinism-workloads-v2"
        with self.assertRaisesRegex(
            qualification.QualificationError, "manifest schema"
        ):
            qualification.validate_manifest(old_manifest)

        old_baseline = baseline(manifest_sha)
        old_baseline["schema"] = "codeskeptic-determinism-baseline-v5"
        with self.assertRaisesRegex(
            qualification.QualificationError, "baseline schema"
        ):
            qualification.validate_baseline(old_baseline, manifest_sha)

        old_receipt = receipt(manifest_sha)
        old_receipt["schema"] = "codeskeptic-determinism-qualification-v5"
        with self.assertRaisesRegex(
            qualification.QualificationError, "not accepted"
        ):
            qualification.validate_receipt_payload(
                old_receipt, raw_manifest, baseline(manifest_sha)
            )

        old_rejected = rejected_receipt(manifest_sha)
        old_rejected["schema"] = "codeskeptic-determinism-rejected-v5"
        with self.assertRaisesRegex(
            qualification.QualificationError, "classification drift"
        ):
            qualification._validate_rejected_payload(old_rejected, raw_manifest)

        old_calibration = calibration_receipt(manifest_sha)
        old_calibration["schema"] = "codeskeptic-determinism-calibration-v5"
        with self.assertRaisesRegex(
            qualification.QualificationError, "classification drift"
        ):
            qualification._validate_calibration_payload(
                old_calibration, raw_manifest
            )

    def test_record_only_runs_cannot_establish_performance_authority(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                qualification.main([
                    "--binary", "/fixture/codeskeptic",
                    "--repo-root", "/fixture/repo",
                    "--build-path", "/fixture/build",
                    "--revision", "fixture-revision",
                    "--output", "/fixture/output",
                    "--hardware-class", "fixture-linux-x86_64",
                    "--repetitions", "10",
                    "--establish-baseline",
                    "--calibration-output", "/fixture/calibration",
                    "--calibration-evidence-path",
                    "docs/evidence/phase10/determinism/calibrations/fixture",
                    "--promotion-reason", "fixture",
                    "--performance-policy", "record-only",
                ])
        self.assertEqual(error.exception.code, 2)

    def test_measurement_cgroup_identity_is_exclusive_empty_and_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            authority = root / "cgroup"
            authority.mkdir()
            group = measurement_cgroup_fixture(authority)
            identity = qualification._measurement_cgroup_identity(
                group, [2, 3], authority
            )
            self.assertEqual(identity["cpus"], [0, 1])
            self.assertEqual(identity["uclamp_min"], 1024)
            self.assertEqual(identity["uclamp_max"], 1024)

            canonical_authority = root / "kernel-canonical-cgroup"
            canonical_authority.mkdir()
            kernel_canonical = measurement_cgroup_fixture(
                canonical_authority, uclamp_min="max", uclamp_max="max",
            )
            canonical_identity = qualification._measurement_cgroup_identity(
                kernel_canonical, [2, 3], canonical_authority
            )
            self.assertEqual(canonical_identity["uclamp_min"], 1024)
            self.assertEqual(canonical_identity["uclamp_max"], 1024)

            cases = (
                ("cpuset.cpus.exclusive.effective", "0\n", "exclusive CPU"),
                ("cpuset.cpus.partition", "member\n", "partition"),
                ("cgroup.procs", "123\n", "not empty"),
                (
                    "cgroup.events", "populated 1\nfrozen 0\n",
                    "descendant is populated",
                ),
                ("cpu.uclamp.min", "0.00\n", "clamp"),
            )
            for relative, value, message in cases:
                path = group / relative
                original = path.read_bytes()
                path.write_text(value, encoding="ascii")
                with self.subTest(relative=relative):
                    with self.assertRaisesRegex(
                        qualification.QualificationError, message
                    ):
                        qualification._measurement_cgroup_identity(
                            group, [2, 3], authority
                        )
                path.write_bytes(original)

            with self.assertRaisesRegex(
                qualification.QualificationError, "overlaps isolated"
            ):
                qualification._measurement_cgroup_identity(
                    group, [1, 2], authority
                )

            delegated = authority / "delegated"
            delegated.mkdir()
            (delegated / "cpu.uclamp.max").write_text(
                "max\n", encoding="ascii"
            )
            nested = measurement_cgroup_fixture(delegated)
            nested_identity = qualification._measurement_cgroup_identity(
                nested, [2, 3], authority
            )
            self.assertEqual(
                nested_identity["ancestor_uclamp_max"], [1024]
            )
            (delegated / "cpu.uclamp.max").write_text(
                "50.00\n", encoding="ascii"
            )
            with self.assertRaisesRegex(
                qualification.QualificationError, "ancestor.*pinned|ancestor.*caps"
            ):
                qualification._measurement_cgroup_identity(
                    nested, [2, 3], authority
                )

            outside_authority = root / "outside"
            outside_authority.mkdir()
            outside = measurement_cgroup_fixture(outside_authority)
            with self.assertRaisesRegex(
                qualification.QualificationError, "unavailable"
            ):
                qualification._measurement_cgroup_identity(
                    outside, [2, 3], authority
                )

    def test_cgroup_counters_are_recomputed_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            qualification.os, "sched_getaffinity", return_value={2, 3},
            create=True,
        ):
            authority = temporary_root(directory) / "cgroup"
            authority.mkdir()
            group = measurement_cgroup_fixture(authority)
            before_group = qualification._measurement_cgroup_snapshot(
                group, [0, 1], authority
            )
            (group / "cpu.stat").write_text(
                "usage_usec 2000000\nnr_throttled 1\nthrottled_usec 10\n",
                encoding="ascii",
            )
            (group / "memory.events").write_text(
                "oom 1\noom_kill 0\noom_group_kill 0\n",
                encoding="ascii",
            )
            after_group = qualification._measurement_cgroup_snapshot(
                group, [0, 1], authority
            )
            before = environment_snapshot()
            after = copy.deepcopy(before)
            before["measurement_cgroup"] = before_group
            after["measurement_cgroup"] = after_group
            after["cpu"]["host_busy_ticks"] += 100
            after["cpu"]["affinity_busy_ticks"] += 100
            decision = qualification._evaluate_runtime_environment(
                before, after, 1000, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, True,
            )
            self.assertTrue(any("throttling" in item
                                for item in decision["violations"]))
            self.assertTrue(any("OOM" in item
                                for item in decision["violations"]))

            reset = copy.deepcopy(after)
            reset["measurement_cgroup"]["cpu_usage_us"] = 1
            with self.assertRaisesRegex(
                qualification.QualificationError, "counter reset"
            ):
                qualification._evaluate_runtime_environment(
                    before, reset, 1000, [0, 1], 4,
                    qualification.ENVIRONMENT_POLICY, True,
                )

    def test_measurement_wrapper_enters_only_the_bounded_cgroup(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()):
            root = temporary_root(directory)
            authority = root / "cgroup"
            authority.mkdir()
            group = authority / "measurement"
            group.mkdir()
            membership = group / "cgroup.procs"
            membership.write_text("", encoding="ascii")
            with (
                mock.patch.object(
                    measurement_wrapper.os, "getpid", return_value=4321
                ),
                mock.patch.object(
                    measurement_wrapper.os, "sched_getaffinity",
                    return_value={0, 1}, create=True,
                ),
            ):
                observed = measurement_wrapper.enter_measurement_cgroup(
                    group, [0, 1], authority
                )
            self.assertEqual(observed, group.resolve())
            self.assertEqual(membership.read_text(encoding="ascii"), "4321\n")

            outside = root / "outside"
            outside.mkdir()
            (outside / "cgroup.procs").write_text("", encoding="ascii")
            with self.assertRaises(SystemExit) as error:
                measurement_wrapper.enter_measurement_cgroup(
                    outside, [0, 1], authority
                )
            self.assertEqual(error.exception.code, 125)

            sentinel = root / "sentinel"
            sentinel.write_text("preserve\n", encoding="ascii")
            membership.unlink()
            membership.symlink_to(sentinel)
            with self.assertRaises(SystemExit) as error:
                measurement_wrapper.enter_measurement_cgroup(
                    group, [0, 1], authority
                )
            self.assertEqual(error.exception.code, 125)
            self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve\n")

            for malformed in ("", "1,0", "0,0", "0-2", "x"):
                with self.subTest(cpus=malformed):
                    with self.assertRaises(SystemExit) as error:
                        measurement_wrapper.parse_cpus(malformed)
                    self.assertEqual(error.exception.code, 125)

    def test_idle_preflight_rejection_is_checksummed_and_recomputed(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        accepted = receipt(manifest_sha)
        before = environment_snapshot()
        after = copy.deepcopy(before)
        after["global_pressure"]["io"]["full_total_us"] += 1
        decision = qualification._evaluate_idle_environment(
            before, after, 30_000, [0, 1], 4,
            qualification.ENVIRONMENT_POLICY, True,
        )
        self.assertFalse(decision["valid"])
        raw = qualification.canonical_json({
            "schema": qualification.ENVIRONMENT_SCHEMA,
            "scope": "idle-preflight",
            "wall_ms": 30_000,
            "before": before,
            "after": after,
            "decision": decision,
        })
        path = qualification._idle_preflight_artifact_path()
        artifacts = {path: raw}
        rejected = qualification._rejected_payload(
            accepted["source"], manifest_sha, "required",
            accepted["host"], accepted["toolchain"], accepted["inputs"],
            dt.datetime.now(dt.timezone.utc), time.monotonic_ns(),
            qualification.QualificationPreflightError(decision["violations"]),
            artifacts, None, None,
        )
        self.assertEqual(
            rejected["decision"]["classification"],
            "idle-preflight-rejection",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            evidence = root / "rejected"
            qualification.write_receipt(evidence, rejected, artifacts)
            verified = qualification.verify_receipt(
                evidence, manifest_path, root / "missing-baseline.json", None
            )
            self.assertEqual(
                verified["decision"]["classification"],
                "idle-preflight-rejection",
            )

            accepted_invalid = root / "accepted-invalid"
            (accepted_invalid / "raw").mkdir(parents=True)
            (accepted_invalid / path).write_bytes(raw)
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "accepted evidence carries an invalid idle preflight",
            ):
                qualification._verify_idle_preflight_claim(
                    accepted, accepted_invalid, raw_manifest
                )

            valid_root = root / "rejected-valid"
            (valid_root / "raw").mkdir(parents=True)
            valid_raw = idle_preflight_evidence()[1]
            (valid_root / path).write_bytes(valid_raw)
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "rejection carries a valid raw preflight",
            ):
                qualification._verify_idle_preflight_claim(
                    rejected, valid_root, raw_manifest
                )

            wrong_failure = copy.deepcopy(rejected)
            wrong_failure["decision"]["failures"][0]["message"] += " forged"
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "rejection differs from raw violations",
            ):
                qualification._verify_idle_preflight_claim(
                    wrong_failure, accepted_invalid, raw_manifest
                )

            missing_raw = copy.deepcopy(rejected)
            missing_raw["artifacts"] = []
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "artifact inventory is not canonical",
            ):
                qualification._validate_rejected_payload(
                    missing_raw, raw_manifest
                )

            short_decision = qualification._evaluate_idle_environment(
                before, copy.deepcopy(before), 1, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, True,
            )
            self.assertFalse(short_decision["valid"])
            self.assertTrue(any("duration" in item
                                for item in short_decision["violations"]))

            incomplete = rejected_receipt(
                qualification.digest_json(raw_manifest)
            )
            incomplete["artifacts"] = [{
                "path": path,
                "sha256": sha256(valid_raw),
                "size": len(valid_raw),
            }]
            incomplete_root = root / "incomplete-valid"
            qualification.write_receipt(
                incomplete_root, incomplete, {path: valid_raw}
            )
            qualification.verify_receipt(
                incomplete_root, manifest_path,
                root / "missing-baseline.json", None,
            )

            invalid_late_payload = json.loads(valid_raw.decode("utf-8"))
            invalid_late_payload["wall_ms"] = 1
            invalid_late_payload["decision"] = (
                qualification._evaluate_idle_environment(
                    invalid_late_payload["before"],
                    invalid_late_payload["after"], 1, [0, 1], 4,
                    qualification.ENVIRONMENT_POLICY, True,
                )
            )
            invalid_late_raw = qualification.canonical_json(
                invalid_late_payload
            )
            forged_incomplete = copy.deepcopy(incomplete)
            forged_incomplete["artifacts"] = [{
                "path": path,
                "sha256": sha256(invalid_late_raw),
                "size": len(invalid_late_raw),
            }]
            forged_incomplete_root = root / "incomplete-invalid"
            qualification.write_receipt(
                forged_incomplete_root, forged_incomplete,
                {path: invalid_late_raw},
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "accepted evidence carries an invalid idle preflight",
            ):
                qualification.verify_receipt(
                    forged_incomplete_root, manifest_path,
                    root / "missing-baseline.json", None,
                )

            tampered_raw = json.loads(raw.decode("utf-8"))
            tampered_raw["decision"]["valid"] = True
            forged_bytes = qualification.canonical_json(tampered_raw)
            forged_artifacts = {path: forged_bytes}
            forged = copy.deepcopy(rejected)
            forged["artifacts"] = [{
                "path": path,
                "sha256": sha256(forged_bytes),
                "size": len(forged_bytes),
            }]
            forged_root = root / "forged"
            qualification.write_receipt(
                forged_root, forged, forged_artifacts
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "idle preflight decision differs",
            ):
                qualification.verify_receipt(
                    forged_root, manifest_path,
                    root / "missing-baseline.json", None,
                )

            float_decision = json.loads(raw.decode("utf-8"))
            float_decision["decision"]["metrics"][
                "cgroup_nr_throttled_delta"
            ] = 0.0
            float_root = root / "float-decision"
            (float_root / "raw").mkdir(parents=True)
            (float_root / path).write_bytes(
                qualification.canonical_json(float_decision)
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "decision differs from raw artifact",
            ):
                qualification._verify_idle_preflight_claim(
                    rejected, float_root, raw_manifest
                )

    def test_global_runtime_pressure_is_record_only_but_idle_is_hard_gate(self) -> None:
        before = environment_snapshot()
        after = copy.deepcopy(before)
        after["cpu"]["host_busy_ticks"] += 100
        after["cpu"]["affinity_busy_ticks"] += 100
        after["measurement_cgroup"]["cpu_usage_us"] += 1_000_000
        after["global_pressure"]["cpu"]["some_total_us"] += 300_000
        after["global_pressure"]["memory"]["full_total_us"] += 1
        after["global_pressure"]["io"]["full_total_us"] += 1
        runtime = qualification._evaluate_runtime_environment(
            before, after, 1000, [0, 1], 4,
            qualification.ENVIRONMENT_POLICY, True,
        )
        self.assertTrue(runtime["valid"])
        self.assertEqual(runtime["violations"], [])
        idle = qualification._evaluate_idle_environment(
            before, after, 1000, [0, 1], 4,
            qualification.ENVIRONMENT_POLICY, True,
        )
        self.assertFalse(idle["valid"])
        self.assertTrue(any("global CPU pressure" in item
                            for item in idle["violations"]))
        self.assertTrue(any("memory full pressure" in item
                            for item in idle["violations"]))
        self.assertTrue(any("IO full pressure" in item
                            for item in idle["violations"]))

        extra = copy.deepcopy(before)
        extra["ignored"] = 0
        with self.assertRaisesRegex(
            qualification.QualificationError, "environment before fields"
        ):
            qualification._evaluate_runtime_environment(
                extra, after, 1000, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, True,
            )

        unavailable = copy.deepcopy(before)
        unavailable["measurement_cgroup"] = (
            qualification._measurement_cgroup_snapshot(None, [0, 1])
        )
        malformed_unavailable = copy.deepcopy(unavailable)
        malformed_unavailable["measurement_cgroup"]["nr_throttled"] = 0
        with self.assertRaisesRegex(
            qualification.QualificationError, "unavailable measurement"
        ):
            qualification._evaluate_runtime_environment(
                unavailable, malformed_unavailable, 1000, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, False,
            )

        numeric_identity_cases = (
            ("effective_cpu_affinity", [0.0, 1.0]),
            ("exclusive_cpu_affinity", [0.0, 1.0]),
            ("uclamp_min", 1024.0),
            ("uclamp_max", 1024.0),
            ("ancestor_uclamp_max", [1024.0]),
        )
        for field, value in numeric_identity_cases:
            forged_before = environment_snapshot()
            forged_after = copy.deepcopy(forged_before)
            forged_before["measurement_cgroup"][field] = value
            forged_after["measurement_cgroup"][field] = copy.deepcopy(value)
            with self.subTest(field=field), self.assertRaises(
                qualification.QualificationError
            ):
                qualification._evaluate_runtime_environment(
                    forged_before, forged_after, 1000, [0, 1], 4,
                    qualification.ENVIRONMENT_POLICY, True,
                )

        thermal_before = environment_snapshot()
        thermal_after = copy.deepcopy(thermal_before)
        thermal_before["thermal"][0]["cpu"] = 0.0
        thermal_after["thermal"][0]["cpu"] = 0.0
        with self.assertRaises(qualification.QualificationError):
            qualification._evaluate_runtime_environment(
                thermal_before, thermal_after, 1000, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, True,
            )

        malformed_controller = environment_snapshot()
        malformed_controller["measurement_cgroup"][
            "controller_cpu_affinity"
        ] = [2, "3"]
        with self.assertRaises(qualification.QualificationError):
            qualification._evaluate_runtime_environment(
                malformed_controller, copy.deepcopy(malformed_controller),
                1000, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, True,
            )

        for field in ("minimum_limit", "maximum_limit"):
            forged_system = environment_snapshot()
            forged_system["system_uclamp"][field] = 1024.0
            with self.subTest(system_field=field), self.assertRaises(
                qualification.QualificationError
            ):
                qualification._evaluate_runtime_environment(
                    forged_system, copy.deepcopy(forged_system),
                    1000, [0, 1], 4,
                    qualification.ENVIRONMENT_POLICY, True,
                )
        capped_system = environment_snapshot()
        capped_system["system_uclamp"]["minimum_limit"] = 512
        capped_system["system_uclamp"]["maximum_limit"] = 512
        with self.assertRaisesRegex(
            qualification.QualificationError, "system CPU.*not pinned"
        ):
            qualification._evaluate_runtime_environment(
                capped_system, copy.deepcopy(capped_system),
                1000, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, True,
            )
        drifting_system = environment_snapshot()
        drifted_system = copy.deepcopy(drifting_system)
        drifted_system["system_uclamp"]["minimum_limit"] = 512
        drifted_system["system_uclamp"]["maximum_limit"] = 512
        with self.assertRaisesRegex(
            qualification.QualificationError, "system CPU.*drift"
        ):
            qualification._evaluate_runtime_environment(
                drifting_system, drifted_system, 1000, [0, 1], 4,
                qualification.ENVIRONMENT_POLICY, True,
            )

    def test_batch_wall_gate_is_bound_to_inner_gnu_time_evidence(self) -> None:
        raw_manifest = manifest()
        payload = receipt(qualification.digest_json(raw_manifest))
        retained = artifact_bytes(payload)
        batch_path = qualification._batch_environment_artifact_path("unit", 1)
        original = json.loads(retained[batch_path].decode("utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            for relative, data in retained.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            forged = copy.deepcopy(original)
            forged["gated_wall_ms"] += 60_000
            (root / batch_path).write_bytes(
                qualification.canonical_json(forged)
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "batch wall evidence differs from raw artifacts",
            ):
                qualification._verify_workload_raw_claims(
                    payload, root, raw_manifest
                )

            forged = copy.deepcopy(original)
            forged["wall_ms"] = (
                forged["gated_wall_ms"] +
                qualification.ENVIRONMENT_POLICY["batch_max_overhead_ms"] + 1
            )
            (root / batch_path).write_bytes(
                qualification.canonical_json(forged)
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "batch wall evidence differs from the measured inner window",
            ):
                qualification._verify_workload_raw_claims(
                    payload, root, raw_manifest
                )

    def test_runtime_global_activity_is_record_only_but_affinity_is_hard_gate(self) -> None:
        before = environment_snapshot(
            host_cpus=12, affinity=[0, 2], host_busy_ticks=1000,
            affinity_busy_ticks=1000, owned_usage_us=1_000_000,
        )
        after = copy.deepcopy(before)
        after["cpu"]["host_busy_ticks"] += 600
        after["cpu"]["affinity_busy_ticks"] += 100
        after["measurement_cgroup"]["cpu_usage_us"] += 900_000
        decision = qualification._evaluate_runtime_environment(
            before, after, wall_ms=1000, affinity=[0, 2],
            logical_cpus=12, policy=qualification.ENVIRONMENT_POLICY,
            required=True,
        )
        self.assertGreater(
            decision["metrics"]["host_external_cpu_basis_points"], 50
        )
        self.assertFalse(any("host external" in value
                             for value in decision["violations"]))
        self.assertTrue(any("affinity external" in value
                            for value in decision["violations"]))

    def test_manifest_requires_exact_three_workloads_ten_runs_and_ten_percent(self) -> None:
        valid = qualification.validate_manifest(manifest())
        self.assertEqual([item["kind"] for item in valid["workloads"]], list(KINDS))

        for mutation, message in (
            (("repetitions", 9), "repetitions"),
            (("performance_regression_limit_percent", 11), "regression"),
        ):
            changed = manifest()
            changed[mutation[0]] = mutation[1]
            with self.assertRaisesRegex(qualification.QualificationError, message):
                qualification.validate_manifest(changed)

        changed = manifest()
        changed["workloads"].pop()
        with self.assertRaisesRegex(qualification.QualificationError, "workload kinds"):
            qualification.validate_manifest(changed)

        changed = manifest()
        changed["workloads"][0]["analyzer_args"] = ["--files", "attacker.txt"]
        with self.assertRaisesRegex(qualification.QualificationError, "input authority"):
            qualification.validate_manifest(changed)

        changed = manifest()
        changed["workloads"][0]["measurement_iterations"] = 1
        with self.assertRaisesRegex(qualification.QualificationError, "measurement batch"):
            qualification.validate_manifest(changed)

        changed = manifest()
        changed["environment_policy"][
            "idle_host_external_cpu_limit_basis_points"
        ] = 100
        with self.assertRaisesRegex(qualification.QualificationError, "environment policy"):
            qualification.validate_manifest(changed)

        for field in (
            "idle_memory_pressure_full_limit_basis_points",
            "idle_io_pressure_full_limit_basis_points",
            "thermal_throttle_limit_ms",
        ):
            changed = manifest()
            changed["environment_policy"][field] = False
            with self.subTest(field=field), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.validate_manifest(changed)

    def test_performance_regressions_are_complete_ordered_records(self) -> None:
        current = {
            "wall_ms": metric(100),
            "cpu_ms": metric(100),
            "peak_rss_kib": metric(100),
        }
        current["cpu_ms"]["p90"] = 111
        current["cpu_ms"]["max"] = 112
        current["peak_rss_kib"]["max"] = 113
        failures = qualification.performance_regressions(
            "unit", current,
            {
                "wall_ms": metric(100),
                "cpu_ms": metric(100),
                "peak_rss_kib": metric(100),
            },
            10,
        )
        self.assertEqual(
            [(item["metric"], item["statistic"]) for item in failures],
            [("cpu_ms", "p90"), ("cpu_ms", "max"),
             ("peak_rss_kib", "max")],
        )
        self.assertTrue(all(item["type"] == "performance-regression"
                            for item in failures))
        self.assertEqual(failures[0]["current"], 111)
        self.assertEqual(failures[0]["baseline"], 100)
        self.assertEqual(failures[0]["limit_percent"], 10)

    def test_environment_snapshot_delta_is_bounded_and_fail_closed(self) -> None:
        proc_stat = (
            "cpu  200 0 100 700 0 0 0 0 0 0\n"
            "cpu0 100 0 50 350 0 0 0 0 0 0\n"
            "cpu2 100 0 50 350 0 0 0 0 0 0\n"
        ).encode()
        parsed = qualification._parse_proc_stat(proc_stat, [0, 2], 100)
        self.assertEqual(parsed["host_busy_ticks"], 300)
        self.assertEqual(parsed["affinity_busy_ticks"], 300)
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU accounting"
        ):
            qualification._parse_proc_stat(
                proc_stat + b"cpu0 100 0 50 350 0 0 0 0 0 0\n",
                [0, 2], 100,
            )
        pressure = qualification._parse_pressure(
            b"some avg10=0.00 avg60=0.00 avg300=0.00 total=12\n"
            b"full avg10=0.00 avg60=0.00 avg300=0.00 total=3\n",
            "cpu",
        )
        self.assertEqual(pressure, {"some_total_us": 12, "full_total_us": 3})
        with self.assertRaisesRegex(qualification.QualificationError, "pressure"):
            qualification._parse_pressure(
                b"some avg10=0 avg60=0 avg300=0 total=1\n", "cpu"
            )

        before = environment_snapshot(
            host_cpus=4, affinity=[0], host_busy_ticks=100,
            affinity_busy_ticks=40, owned_usage_us=1_000_000,
        )
        after = copy.deepcopy(before)
        after["cpu"]["host_busy_ticks"] += 101
        after["cpu"]["affinity_busy_ticks"] += 100
        after["measurement_cgroup"]["cpu_usage_us"] += 900_000
        after["thermal"][0]["package_total_ms"] += 1
        decision = qualification._evaluate_idle_environment(
            before, after, wall_ms=1000, affinity=[0], logical_cpus=4,
            policy=qualification.ENVIRONMENT_POLICY,
            required=True,
        )
        self.assertFalse(decision["valid"])
        self.assertEqual(decision["metrics"]["host_external_cpu_ms"], 110)
        self.assertEqual(decision["metrics"]["thermal_throttle_ms"], 1)
        self.assertTrue(any("host external CPU" in item
                            for item in decision["violations"]))
        self.assertTrue(any("thermal throttle" in item
                            for item in decision["violations"]))
        count_only_after = copy.deepcopy(before)
        count_only_after["cpu"]["host_busy_ticks"] += 90
        count_only_after["cpu"]["affinity_busy_ticks"] += 90
        count_only_after["measurement_cgroup"]["cpu_usage_us"] += 900_000
        count_only_after["thermal"][0]["core_count"] += 1
        count_only = qualification._evaluate_idle_environment(
            before, count_only_after, wall_ms=1000, affinity=[0], logical_cpus=4,
            policy=qualification.ENVIRONMENT_POLICY, required=True,
        )
        self.assertFalse(count_only["valid"])
        self.assertEqual(count_only["metrics"]["thermal_throttle_count"], 1)
        unavailable = copy.deepcopy(before)
        unavailable["cpufreq"] = []
        unavailable["thermal"] = []
        required_unavailable = qualification._evaluate_idle_environment(
            unavailable, copy.deepcopy(unavailable), wall_ms=1000,
            affinity=[0], logical_cpus=4,
            policy=qualification.ENVIRONMENT_POLICY, required=True,
        )
        self.assertFalse(required_unavailable["valid"])
        record_only_unavailable = qualification._evaluate_idle_environment(
            unavailable, copy.deepcopy(unavailable), wall_ms=30_000,
            affinity=[0], logical_cpus=4,
            policy=qualification.ENVIRONMENT_POLICY, required=False,
        )
        self.assertTrue(record_only_unavailable["valid"])
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU topology"
        ):
            qualification._evaluate_idle_environment(
                before, after, wall_ms=1000, affinity=[0], logical_cpus=8,
                policy=qualification.ENVIRONMENT_POLICY, required=True,
            )
        malformed_frequency = copy.deepcopy(after)
        malformed_frequency["cpufreq"][0]["current_khz"] = []
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU frequency"
        ):
            qualification._evaluate_idle_environment(
                before, malformed_frequency, wall_ms=1000,
                affinity=[0], logical_cpus=4,
                policy=qualification.ENVIRONMENT_POLICY, required=True,
            )
        duplicate_frequency_before = copy.deepcopy(before)
        duplicate_frequency_after = copy.deepcopy(after)
        duplicate_frequency_before["cpufreq"] *= 2
        duplicate_frequency_after["cpufreq"] *= 2
        with self.assertRaisesRegex(
            qualification.QualificationError, "frequency identity"
        ):
            qualification._evaluate_idle_environment(
                duplicate_frequency_before, duplicate_frequency_after,
                wall_ms=1000, affinity=[0], logical_cpus=4,
                policy=qualification.ENVIRONMENT_POLICY, required=True,
            )

    def test_environment_capture_is_exact_and_rejects_authority_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            proc_root = root / "proc"
            cpu_root = root / "cpu"
            (proc_root / "pressure").mkdir(parents=True)
            kernel_sysctl = proc_root / "sys" / "kernel"
            kernel_sysctl.mkdir(parents=True)
            (kernel_sysctl / "sched_util_clamp_min").write_text(
                "1024\n", encoding="ascii"
            )
            (kernel_sysctl / "sched_util_clamp_max").write_text(
                "1024\n", encoding="ascii"
            )
            proc_root.joinpath("stat").write_text(
                "cpu 200 0 100 700 0 0 0 0 0 0\n"
                "cpu0 200 0 100 700 0 0 0 0 0 0\n",
                encoding="ascii",
            )
            for resource_name in ("cpu", "memory", "io"):
                proc_root.joinpath("pressure", resource_name).write_text(
                    "some avg10=0.00 avg60=0.00 avg300=0.00 total=12\n"
                    "full avg10=0.00 avg60=0.00 avg300=0.00 total=3\n",
                    encoding="ascii",
                )
            frequency = cpu_root / "cpu0" / "cpufreq"
            thermal = cpu_root / "cpu0" / "thermal_throttle"
            frequency.mkdir(parents=True)
            thermal.mkdir(parents=True)
            for name, value in (
                ("scaling_driver", "intel_pstate"),
                ("scaling_governor", "powersave"),
                ("scaling_min_freq", "400000"),
                ("scaling_max_freq", "4400000"),
                ("scaling_cur_freq", "4000000"),
            ):
                frequency.joinpath(name).write_text(value + "\n", encoding="ascii")
            for name, value in (
                ("core_throttle_count", "1"),
                ("core_throttle_total_time_ms", "2"),
                ("package_throttle_count", "3"),
                ("package_throttle_total_time_ms", "4"),
            ):
                thermal.joinpath(name).write_text(value + "\n", encoding="ascii")

            captured = qualification._capture_environment(
                [0], proc_root, cpu_root
            )
            self.assertEqual(captured["cpu"]["host_logical_cpus"], 1)
            self.assertEqual(captured["cpufreq"][0]["maximum_khz"], 4400000)
            self.assertEqual(captured["thermal"][0]["package_total_ms"], 4)

            cgroup_authority = root / "cgroup"
            cgroup = measurement_cgroup_fixture(
                cgroup_authority, effective="0", exclusive="0"
            )
            with mock.patch.object(
                qualification.os, "sched_getaffinity", return_value={1},
                create=True,
            ):
                captured_group = qualification._capture_environment(
                    [0], proc_root, cpu_root, cgroup, cgroup_authority, [1]
                )
            self.assertEqual(
                captured_group["measurement_cgroup"]["mode"],
                "exclusive-cgroup-v2",
            )
            self.assertEqual(
                captured_group["measurement_cgroup"]["cpu_usage_us"],
                1_000_000,
            )
            self.assertEqual(
                captured_group["system_uclamp"],
                {"minimum_limit": 1024, "maximum_limit": 1024},
            )
            self.assertEqual(
                captured_group["measurement_cgroup"][
                    "controller_cpu_affinity"
                ],
                [1],
            )

            system_maximum = kernel_sysctl / "sched_util_clamp_max"
            system_maximum.unlink()
            with mock.patch.object(
                qualification.os, "sched_getaffinity", return_value={1},
                create=True,
            ), self.assertRaisesRegex(
                qualification.QualificationError, "system CPU.*unavailable"
            ):
                qualification._capture_environment(
                    [0], proc_root, cpu_root, cgroup,
                    cgroup_authority, [1],
                )
            system_maximum.write_text("1024\n", encoding="ascii")

            outside = root / "outside-frequency"
            outside.mkdir()
            shutil.rmtree(frequency)
            frequency.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(
                qualification.QualificationError, "escapes its authority root"
            ):
                qualification._capture_environment([0], proc_root, cpu_root)

    def test_statistics_are_integer_nearest_rank_and_complete(self) -> None:
        values = [9, 1, 7, 3, 2, 10, 6, 8, 4, 5]
        self.assertEqual(
            qualification.metric_statistics(values),
            {"count": 10, "min": 1, "median": 6, "p90": 9, "max": 10},
        )

    def test_run_once_executes_and_binds_every_pinned_inner_measurement(self) -> None:
        raw_manifest = manifest()
        definition = raw_manifest["workloads"][0]
        input_value = input_receipt("unit")
        prepared = {
            "definition": definition,
            "input": input_value,
            "args": [],
            "release_source": None,
        }
        environment_payload = json.loads(environment_evidence(500)[1])
        environment_payload["before"]["cpu"]["host_logical_cpus"] = 8
        environment_payload["after"]["cpu"]["host_logical_cpus"] = 8
        batch_payload = json.loads(environment_evidence(
            5000, scope="performance-batch", required=True
        )[1])
        batch_payload["before"]["cpu"]["host_logical_cpus"] = 8
        batch_payload["after"]["cpu"]["host_logical_cpus"] = 8

        def run_process(
            command: list[str], _environment: dict[str, str], _timeout: int,
            _stdout_path: Path, _stderr_path: Path,
            _required_outputs: list[Path],
        ) -> subprocess.CompletedProcess:
            time_path = Path(command[command.index("-o") + 1])
            report_path = Path(command[-1])
            time_path.write_bytes(time_log(500))
            report_path.write_bytes(
                qualification.canonical_json(analyzer_report("unit"))
            )
            return subprocess.CompletedProcess(
                command, 0, stdout=b"", stderr=b""
            )

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            qualification.os, "sched_getaffinity", return_value={2, 3},
            create=True,
        ), mock.patch.object(
            qualification, "_capture_environment",
            side_effect=(
                [copy.deepcopy(batch_payload["before"])] + [
                    copy.deepcopy(environment_payload[side])
                    for _iteration in range(10)
                    for side in ("before", "after")
                ] + [copy.deepcopy(batch_payload["after"])]
            ),
        ) as capture, mock.patch.object(
            qualification, "_run_bounded_process", side_effect=run_process
        ) as bounded, mock.patch.object(
            qualification.time, "monotonic_ns",
            side_effect=(0, 5_000_000_000),
        ):
            run, artifacts = qualification.run_once(
                Path("/fixture/codeskeptic"), Path("/usr/bin/time"),
                prepared, 1, ROOT, temporary_root(directory), "required",
                {
                    "cpu_affinity": [0, 1],
                    "logical_cpus": 2,
                    "host_logical_cpus": 8,
                    "controller_cpu_affinity": [2, 3],
                },
                Path("/sys/fs/cgroup/codeskeptic-measurement"),
            )
        self.assertEqual(bounded.call_count, 10)
        self.assertEqual(capture.call_count, 22)
        self.assertEqual(run["measurement_iterations"], 10)
        self.assertEqual(len(run["inner_runs"]), 10)
        self.assertEqual(run["metrics"]["cpu_ms"], 5000)
        self.assertTrue(run["batch_valid"])
        self.assertTrue(run["environment_valid"])
        self.assertEqual(len(artifacts), 51)

    def test_batch_accounting_failure_retains_and_recomputes_exact_raw(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        definition = raw_manifest["workloads"][0]
        input_value = input_receipt("unit")
        prepared = {
            "definition": definition,
            "input": input_value,
            "args": [],
            "release_source": None,
        }
        inner = json.loads(environment_evidence(500)[1])
        inner["before"]["cpu"]["host_logical_cpus"] = 8
        inner["after"]["cpu"]["host_logical_cpus"] = 8
        batch_before = environment_snapshot(
            host_cpus=8, affinity=[0, 1], host_busy_ticks=1000,
            affinity_busy_ticks=1000, owned_usage_us=1_000_000,
        )
        batch_after = copy.deepcopy(batch_before)
        batch_after["cpu"]["host_busy_ticks"] += 518
        batch_after["cpu"]["affinity_busy_ticks"] += 518
        batch_after["measurement_cgroup"]["cpu_usage_us"] += 5_239_000

        def run_process(
            command: list[str], _environment: dict[str, str], _timeout: int,
            stdout_path: Path, stderr_path: Path,
            _required_outputs: list[Path],
        ) -> subprocess.CompletedProcess:
            Path(command[command.index("-o") + 1]).write_bytes(time_log(500))
            Path(command[-1]).write_bytes(
                qualification.canonical_json(analyzer_report("unit"))
            )
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
            return subprocess.CompletedProcess(
                command, 0, stdout=b"", stderr=b""
            )

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            qualification.os, "sched_getaffinity", return_value={2, 3},
            create=True,
        ), mock.patch.object(
            qualification, "_capture_environment",
            side_effect=(
                [copy.deepcopy(batch_before)] + [
                    copy.deepcopy(inner[side])
                    for _iteration in range(10)
                    for side in ("before", "after")
                ] + [copy.deepcopy(batch_after)]
            ),
        ), mock.patch.object(
            qualification, "_run_bounded_process", side_effect=run_process
        ), mock.patch.object(
            qualification.time, "monotonic_ns",
            side_effect=(0, 5_000_000_000),
        ):
            scratch = temporary_root(directory)
            with self.assertRaises(
                qualification.QualificationBatchEnvironmentError
            ) as raised:
                qualification.run_once(
                    Path("/fixture/codeskeptic"), Path("/usr/bin/time"),
                    prepared, 1, ROOT, scratch, "required",
                    {
                        "cpu_affinity": [0, 1],
                        "logical_cpus": 2,
                        "host_logical_cpus": 8,
                        "controller_cpu_affinity": [2, 3],
                    },
                    Path("/sys/fs/cgroup/codeskeptic-measurement"),
                )
            error = raised.exception
            self.assertEqual(str(error), "measurement cgroup CPU accounting drift")
            retained = qualification._collect_failed_run_artifacts(
                scratch, "unit", 1, 10
            )

        batch_path = qualification._batch_environment_artifact_path("unit", 1)
        self.assertIn(batch_path, retained)
        batch = json.loads(retained[batch_path].decode("utf-8"))
        self.assertEqual(batch["scope"], "performance-batch-rejected")
        self.assertEqual(
            batch["failure"]["message"],
            "measurement cgroup CPU accounting drift",
        )
        self.assertEqual(batch["gated_wall_ms"], 5000)

        host = receipt(manifest_sha)["host"]
        host["host_logical_cpus"] = 8
        idle_before = environment_snapshot(host_cpus=8)
        idle_after = copy.deepcopy(idle_before)
        idle_decision = qualification._evaluate_idle_environment(
            idle_before, idle_after, 30_000, [0, 1], 8,
            qualification.ENVIRONMENT_POLICY, True,
        )
        idle_raw = qualification.canonical_json({
            "schema": qualification.ENVIRONMENT_SCHEMA,
            "scope": "idle-preflight",
            "wall_ms": 30_000,
            "before": idle_before,
            "after": idle_after,
            "decision": idle_decision,
        })
        retained[qualification._idle_preflight_artifact_path()] = idle_raw
        rejected = qualification._rejected_payload(
            {
                "revision": "head-revision",
                "manifest_sha256": "2" * 64,
                "file_count": 1,
            },
            manifest_sha, "required", host, toolchain_identity(),
            {"unit": input_value}, dt.datetime.now(dt.timezone.utc),
            time.monotonic_ns(), error, retained, None, None,
        )
        self.assertEqual(
            rejected["decision"]["failures"][0]["type"],
            "batch-environment-error",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            evidence = root / "rejected"
            qualification.write_receipt(evidence, rejected, retained)
            qualification.verify_receipt(
                evidence, manifest_path, root / "missing-baseline.json", None
            )

            forged_artifacts = dict(retained)
            forged = copy.deepcopy(batch)
            forged["after"]["measurement_cgroup"]["cpu_usage_us"] -= 100_000
            forged_artifacts[batch_path] = qualification.canonical_json(forged)
            forged_receipt = copy.deepcopy(rejected)
            descriptor = next(
                item for item in forged_receipt["artifacts"]
                if item["path"] == batch_path
            )
            descriptor["sha256"] = sha256(forged_artifacts[batch_path])
            descriptor["size"] = len(forged_artifacts[batch_path])
            forged_evidence = root / "forged"
            qualification.write_receipt(
                forged_evidence, forged_receipt, forged_artifacts
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "batch environment failure was not reproduced",
            ):
                qualification.verify_receipt(
                    forged_evidence, manifest_path,
                    root / "missing-baseline.json", None,
                )

            relabeled_artifacts = dict(retained)
            relabeled_batch = copy.deepcopy(batch)
            relabeled_batch["failure"]["type"] = "qualification-error"
            relabeled_batch["scope"] = "performance-batch"
            relabeled_artifacts[batch_path] = qualification.canonical_json(
                relabeled_batch
            )
            relabeled_receipt = copy.deepcopy(rejected)
            relabeled_receipt["decision"]["failures"][0][
                "type"
            ] = "qualification-error"
            descriptor = next(
                item for item in relabeled_receipt["artifacts"]
                if item["path"] == batch_path
            )
            descriptor["sha256"] = sha256(relabeled_artifacts[batch_path])
            descriptor["size"] = len(relabeled_artifacts[batch_path])
            relabeled_evidence = root / "relabeled"
            qualification.write_receipt(
                relabeled_evidence, relabeled_receipt, relabeled_artifacts
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "batch",
            ):
                qualification.verify_receipt(
                    relabeled_evidence, manifest_path,
                    root / "missing-baseline.json", None,
                )

    def test_batch_wall_failure_is_also_retained_before_rejection(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        definition = raw_manifest["workloads"][0]
        input_value = input_receipt("unit")
        prepared = {
            "definition": definition,
            "input": input_value,
            "args": [],
            "release_source": None,
        }
        inner = json.loads(environment_evidence(500)[1])
        inner["before"]["cpu"]["host_logical_cpus"] = 8
        inner["after"]["cpu"]["host_logical_cpus"] = 8
        batch = json.loads(environment_evidence(
            5000, scope="performance-batch", required=True
        )[1])
        batch["before"]["cpu"]["host_logical_cpus"] = 8
        batch["after"]["cpu"]["host_logical_cpus"] = 8

        def run_process(
            command: list[str], _environment: dict[str, str], _timeout: int,
            stdout_path: Path, stderr_path: Path,
            _required_outputs: list[Path],
        ) -> subprocess.CompletedProcess:
            Path(command[command.index("-o") + 1]).write_bytes(time_log(500))
            Path(command[-1]).write_bytes(
                qualification.canonical_json(analyzer_report("unit"))
            )
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
            return subprocess.CompletedProcess(
                command, 0, stdout=b"", stderr=b""
            )

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            qualification.os, "sched_getaffinity", return_value={2, 3},
            create=True,
        ), mock.patch.object(
            qualification, "_capture_environment",
            side_effect=(
                [copy.deepcopy(batch["before"])] + [
                    copy.deepcopy(inner[side])
                    for _iteration in range(10)
                    for side in ("before", "after")
                ] + [copy.deepcopy(batch["after"])]
            ),
        ), mock.patch.object(
            qualification, "_run_bounded_process", side_effect=run_process
        ), mock.patch.object(
            qualification.time, "monotonic_ns",
            side_effect=(0, 65_001_000_000),
        ):
            scratch = temporary_root(directory)
            with self.assertRaisesRegex(
                qualification.QualificationBatchEnvironmentError,
                "batch wall evidence differs",
            ) as raised:
                qualification.run_once(
                    Path("/fixture/codeskeptic"), Path("/usr/bin/time"),
                    prepared, 1, ROOT, scratch, "required",
                    {
                        "cpu_affinity": [0, 1],
                        "logical_cpus": 2,
                        "host_logical_cpus": 8,
                        "controller_cpu_affinity": [2, 3],
                    },
                    Path("/sys/fs/cgroup/codeskeptic-measurement"),
                )
            retained = qualification._collect_failed_run_artifacts(
                scratch, "unit", 1, 10
            )
            error = raised.exception
        failed_batch = json.loads(retained[
            qualification._batch_environment_artifact_path("unit", 1)
        ].decode("utf-8"))
        self.assertEqual(failed_batch["scope"], "performance-batch-rejected")
        self.assertEqual(
            failed_batch["failure"]["message"],
            "batch wall evidence differs from the measured inner window",
        )

        host = receipt(manifest_sha)["host"]
        host["host_logical_cpus"] = 8
        idle_before = environment_snapshot(host_cpus=8)
        idle_after = copy.deepcopy(idle_before)
        idle_decision = qualification._evaluate_idle_environment(
            idle_before, idle_after, 30_000, [0, 1], 8,
            qualification.ENVIRONMENT_POLICY, True,
        )
        retained[qualification._idle_preflight_artifact_path()] = (
            qualification.canonical_json({
                "schema": qualification.ENVIRONMENT_SCHEMA,
                "scope": "idle-preflight",
                "wall_ms": 30_000,
                "before": idle_before,
                "after": idle_after,
                "decision": idle_decision,
            })
        )
        rejected = qualification._rejected_payload(
            {
                "revision": "head-revision",
                "manifest_sha256": "2" * 64,
                "file_count": 1,
            },
            manifest_sha, "required", host, toolchain_identity(),
            {"unit": input_value}, dt.datetime.now(dt.timezone.utc),
            time.monotonic_ns(), error, retained, None, None,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            evidence = root / "wall-rejected"
            qualification.write_receipt(evidence, rejected, retained)
            qualification.verify_receipt(
                evidence, manifest_path, root / "missing-baseline.json", None
            )

    def test_rejected_batch_wall_values_require_strict_integers(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        accepted = receipt(manifest_sha, value=1)
        all_artifacts = artifact_bytes(accepted)
        kind = "release-candidate"
        repetition = 1
        batch_path = qualification._batch_environment_artifact_path(
            kind, repetition
        )
        required = {
            qualification._idle_preflight_artifact_path(),
            batch_path,
            *qualification._iteration_artifact_paths(kind, repetition, 1),
        }
        message = "batch gated wall time is outside the admitted range"
        error = qualification.QualificationBatchEnvironmentError(
            message, kind, repetition
        )

        for malformed in (True, 1.0):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory:
                retained = {
                    path: data for path, data in all_artifacts.items()
                    if path in required
                }
                batch = json.loads(retained[batch_path].decode("utf-8"))
                batch["scope"] = "performance-batch-rejected"
                batch.pop("decision")
                batch["gated_wall_ms"] = malformed
                batch["failure"] = qualification._failure_record(
                    "batch-environment-error", message,
                    workload=kind, repetition=repetition,
                )
                retained[batch_path] = qualification.canonical_json(batch)
                rejected = qualification._rejected_payload(
                    accepted["source"], manifest_sha, "required",
                    accepted["host"], accepted["toolchain"],
                    {kind: accepted["inputs"][kind]},
                    dt.datetime.now(dt.timezone.utc), time.monotonic_ns(),
                    error, retained, None, None,
                )
                root = temporary_root(directory)
                manifest_path = root / "manifest.json"
                manifest_path.write_bytes(
                    qualification.canonical_json(raw_manifest)
                )
                evidence = root / "rejected"
                qualification.write_receipt(evidence, rejected, retained)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "batch gated wall time",
                ):
                    qualification.verify_receipt(
                        evidence, manifest_path,
                        root / "missing-baseline.json", None,
                    )

    def test_accepted_and_calibration_wire_integers_reject_bool_and_float(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        pinned = baseline(manifest_sha)

        mutations = (
            (lambda value: value["workloads"][0]["runs"][0].__setitem__(
                "repetition", True
            ), "repetition"),
            (lambda value: value["workloads"][0]["runs"][0]["inner_runs"][0].__setitem__(
                "iteration", 1.0
            ), "iteration"),
            (lambda value: value["workloads"][1]["runs"][0].__setitem__(
                "measurement_iterations", True
            ), "measurement"),
            (lambda value: value["workloads"][0]["runs"][0].__setitem__(
                "exit_code", False
            ), "verdict"),
            (lambda value: value["workloads"][0]["runs"][0]["inner_runs"][0].__setitem__(
                "exit_code", 0.0
            ), "exit"),
        )
        for mutate, label in mutations:
            with self.subTest(label=label):
                forged = receipt(manifest_sha)
                mutate(forged)
                with self.assertRaises(qualification.QualificationError):
                    qualification.validate_receipt_payload(
                        forged, raw_manifest, pinned
                    )

        calibration = calibration_receipt(manifest_sha)
        calibration["workloads"][1]["runs"][0][
            "measurement_iterations"
        ] = True
        with self.assertRaises(qualification.QualificationError):
            qualification._validate_calibration_payload(
                calibration, raw_manifest
            )

        accepted = receipt(manifest_sha, value=1)
        original_artifacts = artifact_bytes(accepted)
        for artifact_path, field in (
            (
                qualification._iteration_artifact_paths(
                    "real-repository", 1, 1
                )[4],
                "wall_ms",
            ),
            (
                qualification._batch_environment_artifact_path(
                    "real-repository", 1
                ),
                "gated_wall_ms",
            ),
        ):
            with self.subTest(raw_field=field), tempfile.TemporaryDirectory() as directory:
                artifacts = dict(original_artifacts)
                raw = json.loads(artifacts[artifact_path].decode("utf-8"))
                raw[field] = True
                artifacts[artifact_path] = qualification.canonical_json(raw)
                forged = copy.deepcopy(accepted)
                descriptor = next(
                    item for item in forged["artifacts"]
                    if item["path"] == artifact_path
                )
                descriptor["sha256"] = sha256(artifacts[artifact_path])
                descriptor["size"] = len(artifacts[artifact_path])
                root = temporary_root(directory)
                manifest_path = root / "manifest.json"
                baseline_path = root / "baseline.json"
                manifest_path.write_bytes(
                    qualification.canonical_json(raw_manifest)
                )
                baseline_path.write_bytes(
                    qualification.canonical_json(pinned)
                )
                forged["baseline"]["sha256"] = qualification.sha256_file(
                    baseline_path
                )
                evidence = root / "accepted"
                qualification.write_receipt(evidence, forged, artifacts)
                with self.assertRaises(qualification.QualificationError):
                    qualification.verify_receipt(
                        evidence, manifest_path, baseline_path, None
                    )

    def test_pinned_ten_fields_are_strict_integers_in_every_v7_schema(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        pinned = baseline(manifest_sha)

        cases = (
            (
                "manifest repetitions", lambda: manifest(),
                lambda value, malformed: value.__setitem__(
                    "repetitions", malformed
                ),
                lambda value: qualification.validate_manifest(value),
            ),
            (
                "manifest limit", lambda: manifest(),
                lambda value, malformed: value.__setitem__(
                    "performance_regression_limit_percent", malformed
                ),
                lambda value: qualification.validate_manifest(value),
            ),
            (
                "baseline limit", lambda: baseline(manifest_sha),
                lambda value, malformed: value.__setitem__(
                    "performance_regression_limit_percent", malformed
                ),
                lambda value: qualification.validate_baseline(
                    value, manifest_sha
                ),
            ),
            (
                "accepted repetitions", lambda: receipt(manifest_sha),
                lambda value, malformed: value["configuration"].__setitem__(
                    "repetitions", malformed
                ),
                lambda value: qualification.validate_receipt_payload(
                    value, raw_manifest, pinned
                ),
            ),
            (
                "accepted limit", lambda: receipt(manifest_sha),
                lambda value, malformed: value["configuration"].__setitem__(
                    "performance_regression_limit_percent", malformed
                ),
                lambda value: qualification.validate_receipt_payload(
                    value, raw_manifest, pinned
                ),
            ),
            (
                "calibration repetitions",
                lambda: calibration_receipt(manifest_sha),
                lambda value, malformed: value["configuration"].__setitem__(
                    "repetitions", malformed
                ),
                lambda value: qualification._validate_calibration_payload(
                    value, raw_manifest
                ),
            ),
            (
                "calibration limit",
                lambda: calibration_receipt(manifest_sha),
                lambda value, malformed: value["configuration"].__setitem__(
                    "performance_regression_limit_percent", malformed
                ),
                lambda value: qualification._validate_calibration_payload(
                    value, raw_manifest
                ),
            ),
            (
                "rejected repetitions", lambda: rejected_receipt(manifest_sha),
                lambda value, malformed: value["configuration"].__setitem__(
                    "repetitions", malformed
                ),
                lambda value: qualification._validate_rejected_payload(
                    value, raw_manifest, None
                ),
            ),
            (
                "rejected limit", lambda: rejected_receipt(manifest_sha),
                lambda value, malformed: value["configuration"].__setitem__(
                    "performance_regression_limit_percent", malformed
                ),
                lambda value: qualification._validate_rejected_payload(
                    value, raw_manifest, None
                ),
            ),
        )
        for label, factory, mutate, validate in cases:
            for malformed in (True, 10.0):
                with self.subTest(label=label, malformed=malformed):
                    value = factory()
                    mutate(value, malformed)
                    with self.assertRaises(qualification.QualificationError):
                        validate(value)

    def test_semantic_projection_excludes_runtime_telemetry_but_not_findings(self) -> None:
        report = {
            "tool": "CodeSkeptic",
            "status": "findings",
            "complete": True,
            "exit_code": 1,
            "coverage": {
                "attempted_tus": 1,
                "analyzed_tus": 1,
                "broken_tus": 0,
                "incomplete_functions": 0,
            },
            "finding_counts": {"total": 1, "blocking": 1, "report_only": 0},
            "total": 1,
            "diagnostics": [{
                "severity": "error",
                "fingerprint": "csf1-0000000000000001",
                "rule_id": "null-deref",
                "capability_tier": "supported",
                "blocks_verdict": True,
                "file": str(ROOT / "src" / "sample.cpp"),
                "line": 1,
                "column": 2,
                "function": "f",
                "message": "null dereference",
                "notes": [],
            }],
            "translation_units": [{
                "path": str(ROOT / "src" / "sample.cpp"),
                "compile_command_sha256": "1" * 64,
                "command_ordinal": 0,
                "phase": "analysis",
                "status": "completed",
                "duration_ms": 1,
                "peak_memory_kib": 10,
                "timeout_seconds": 300,
                "memory_mib": 4096,
                "origin": "executed",
                "checkpoint_key_sha256": "",
                "payload_sha256": "",
            }],
            "evidence": {
                field: False for field in qualification.EVIDENCE_FIELDS
            },
        }
        first = qualification.digest_json(
            qualification.semantic_projection(report, ROOT, None)
        )
        changed_telemetry = copy.deepcopy(report)
        changed_telemetry["translation_units"][0]["duration_ms"] = 999
        changed_telemetry["translation_units"][0]["peak_memory_kib"] = 99999
        changed_telemetry["translation_units"][0]["compile_command_sha256"] = "2" * 64
        self.assertEqual(
            first,
            qualification.digest_json(
                qualification.semantic_projection(changed_telemetry, ROOT, None)
            ),
        )
        changed_finding = copy.deepcopy(report)
        changed_finding["diagnostics"][0]["fingerprint"] = "csf1-0000000000000002"
        self.assertNotEqual(
            first,
            qualification.digest_json(
                qualification.semantic_projection(changed_finding, ROOT, None)
            ),
        )

        partial = copy.deepcopy(report)
        partial["coverage"]["attempted_tus"] = 2
        with self.assertRaisesRegex(qualification.QualificationError, "coverage"):
            qualification.semantic_projection(partial, ROOT, None)

        non_boolean = copy.deepcopy(report)
        non_boolean["evidence"]["tool_failed"] = 1
        with self.assertRaisesRegex(qualification.QualificationError, "evidence"):
            qualification.semantic_projection(non_boolean, ROOT, None)

        outside = copy.deepcopy(report)
        outside["translation_units"][0]["path"] = "/outside/not-requested.cpp"
        with self.assertRaisesRegex(qualification.QualificationError, "admitted root"):
            qualification.semantic_projection(outside, ROOT, None)

    def test_gnu_time_parser_requires_cpu_and_peak_rss(self) -> None:
        raw = (
            "\tUser time (seconds): 1.25\n"
            "\tSystem time (seconds): 0.50\n"
            "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:02.25\n"
            "\tMaximum resident set size (kbytes): 12345\n"
            "\tExit status: 0\n"
        ).encode()
        self.assertEqual(
            qualification._parse_time_log(raw),
            (2250, 1750, 12345, 0),
        )
        with self.assertRaisesRegex(qualification.QualificationError, "missing wall"):
            qualification._parse_time_log(b"User time (seconds): 1.0\n")

    def test_repository_manifest_pins_a_real_release_candidate_slice(self) -> None:
        actual = qualification.load_manifest(
            ROOT / "scripts" / "determinism_workloads.json"
        )
        release = actual["workloads"][2]["input"]
        realworld = json.loads(
            (ROOT / release["realworld_manifest"]).read_text(encoding="utf-8")
        )
        project = next(
            item for item in realworld["projects"] if item["id"] == release["project"]
        )
        self.assertIn(project["id"], realworld["campaigns"]["release-candidate"]["projects"])
        self.assertRegex(project["revision"], r"^[0-9a-f]{40}$")
        self.assertEqual(len(release["translation_units"]), 12)
        self.assertEqual(
            sum(path.startswith("src/") for path in release["translation_units"]), 6
        )
        self.assertEqual(
            sum(path.startswith("ggml/src/") for path in release["translation_units"]), 6
        )
        self.assertEqual(release["mode"], "release-candidate")
        self.assertEqual(
            actual["workloads"][2]["analyzer_args"],
            [
                "--report-paths",
                "{release_source}/src,{release_source}/ggml/src",
            ],
        )
        self.assertIsNone(project.get("environment"))
        self.assertIsInstance(qualification._release_environment(project), dict)
        release_roots = input_receipt("release-candidate")["roots"]
        self.assertEqual(
            [item["marker"] for item in release_roots],
            ["$RELEASE_BUILD", "$RELEASE_SOURCE", "$REPO"],
        )

    def test_one_semantic_drift_or_missing_repetition_fails_closed(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        current = receipt(manifest_sha)
        base = baseline(manifest_sha)

        drift = copy.deepcopy(current)
        drift["workloads"][1]["runs"][8]["semantic_sha256"] = "f" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "semantic drift"):
            qualification.validate_receipt_payload(drift, raw_manifest, base)

        omitted = copy.deepcopy(current)
        omitted["workloads"][0]["runs"].pop()
        with self.assertRaisesRegex(qualification.QualificationError, "ten repetitions"):
            qualification.validate_receipt_payload(omitted, raw_manifest, base)

    def test_wall_cpu_and_peak_memory_each_enforce_ten_percent(self) -> None:
        for metric_name, statistic in (
            ("wall_ms", "median"),
            ("wall_ms", "p90"),
            ("wall_ms", "max"),
            ("cpu_ms", "median"),
            ("cpu_ms", "p90"),
            ("cpu_ms", "max"),
            ("peak_rss_kib", "max"),
        ):
            current = {name: metric(100) for name in qualification.METRICS}
            pinned = {name: metric(100) for name in qualification.METRICS}
            current[metric_name][statistic] = 111
            failures = qualification.performance_regressions(
                "unit", current, pinned, 10
            )
            self.assertTrue(
                any(
                    failure["metric"] == metric_name
                    and failure["statistic"] == statistic
                    and "10 percent" in failure["message"]
                    for failure in failures
                )
            )

    def test_hardware_class_and_baseline_semantics_are_fail_closed(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        current = receipt(manifest_sha)
        base = baseline(manifest_sha)

        current["host"]["class_id"] = "unknown-host"
        with self.assertRaisesRegex(qualification.QualificationError, "baseline profile"):
            qualification.validate_receipt_payload(current, raw_manifest, base)

        current["configuration"]["performance_policy"] = "record-only"
        current["baseline"]["profile"] = None
        current["baseline"]["performance_gate"] = "not-gated"
        qualification.validate_receipt_payload(current, raw_manifest, base)

        current = receipt(manifest_sha)
        base["profiles"]["test-linux-x86_64"]["workloads"]["unit"][
            "semantic_sha256"
        ] = "a" * 64
        base["semantic_reference"]["unit"]["semantic_sha256"] = "a" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "baseline semantic"):
            qualification.validate_receipt_payload(current, raw_manifest, base)

        current = receipt(manifest_sha)
        base = baseline(manifest_sha)
        current["inputs"]["unit"]["identity_sha256"] = "f" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "input identity"):
            qualification.validate_receipt_payload(current, raw_manifest, base)

        current = receipt(manifest_sha)
        base = baseline(manifest_sha)
        current["toolchain"]["c_compiler"] = {
            "sha256": "f" * 64,
            "version": "different compiler",
        }
        with self.assertRaisesRegex(
            qualification.QualificationError, "hardware|toolchain|profile"
        ):
            qualification.validate_receipt_payload(current, raw_manifest, base)

        current = receipt(manifest_sha)
        base = baseline(manifest_sha)
        current["host"]["cpu_affinity"] = [0, 2]
        current["host"]["controller_cpu_affinity"] = [1, 3]
        with self.assertRaisesRegex(
            qualification.QualificationError, "hardware|toolchain|profile"
        ):
            qualification.validate_receipt_payload(current, raw_manifest, base)

        current = receipt(manifest_sha)
        current["host"]["cpu_affinity"] = [0, 0]
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU affinity"
        ):
            qualification.validate_receipt_payload(current, raw_manifest, base)

    def test_host_identity_binds_the_effective_cpu_affinity(self) -> None:
        with (
            mock.patch.object(
                qualification.os, "sched_getaffinity", return_value={2, 3},
                create=True,
            ),
            mock.patch.object(
                qualification, "_require_measurement_environment",
                return_value={
                    "path": Path("/sys/fs/cgroup/measurement"),
                    "cpus": [0, 1],
                    "uclamp_min": 1024,
                    "uclamp_max": 1024,
                    "ancestor_uclamp_max": [],
                    "populated": 0,
                    "frozen": 0,
                },
            ),
            mock.patch.object(
                qualification, "_system_uclamp_limits",
                return_value=(1024, 1024),
            ),
            mock.patch.object(qualification.os, "cpu_count", return_value=4),
        ):
            required = qualification.host_identity(
                "test-linux-x86_64", "required",
                Path("/sys/fs/cgroup/measurement"),
            )
        self.assertEqual(required["cpu_affinity"], [0, 1])
        self.assertEqual(required["controller_cpu_affinity"], [2, 3])
        self.assertEqual(required["cpu_affinity_source"], "cgroup-v2-exclusive")
        self.assertEqual(required["cpu_uclamp_source"], "cgroup-v2")
        self.assertEqual(
            required["measurement_environment"], "exclusive-cgroup-v2"
        )

        with (
            mock.patch.object(
                qualification.os, "sched_getaffinity", return_value={7, 3},
                create=True,
            ),
            mock.patch.object(
                qualification, "_cpu_uclamp_identity",
                return_value=("proc-self-sched", 1024, 1024),
            ),
            mock.patch.object(
                qualification, "_system_uclamp_limits",
                return_value=(1024, 1024),
            ),
            mock.patch.object(qualification.os, "cpu_count", return_value=8),
        ):
            identity = qualification.host_identity("test-linux-x86_64")

        self.assertEqual(identity["cpu_affinity"], [3, 7])
        self.assertEqual(identity["cpu_affinity_source"], "sched_getaffinity")
        self.assertEqual(identity["logical_cpus"], 2)
        self.assertEqual(identity["host_logical_cpus"], 8)
        self.assertEqual(identity["cpu_uclamp_source"], "proc-self-sched")
        self.assertEqual(identity["cpu_uclamp_min"], 1024)
        self.assertEqual(identity["cpu_uclamp_max"], 1024)

        with (
            mock.patch.object(
                qualification.os, "sched_getaffinity",
                side_effect=AttributeError, create=True,
            ),
            mock.patch.object(qualification.os, "cpu_count", return_value=3),
        ):
            fallback = qualification.host_identity("test-linux-x86_64")
        self.assertEqual(fallback["cpu_affinity"], [])
        self.assertEqual(fallback["cpu_affinity_source"], "unavailable")
        self.assertEqual(fallback["logical_cpus"], 3)
        self.assertEqual(fallback["host_logical_cpus"], 3)

        with mock.patch.object(
            qualification.os, "sched_getaffinity",
            side_effect=OSError("denied"), create=True,
        ):
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "cannot read effective CPU affinity",
            ):
                qualification.host_identity("test-linux-x86_64")

        with mock.patch.object(
            qualification.os, "sched_getaffinity", return_value=set(),
            create=True,
        ):
            with self.assertRaisesRegex(
                qualification.QualificationError, "affinity is empty"
            ):
                qualification.host_identity(
                    "test-linux-x86_64", performance_policy="required"
                )

    def test_malformed_affinity_is_rejected_without_raw_type_errors(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        for malformed in (
            [0, "1"], [{}], [1, 0], [0, 0], [], [-1, 0], [0, 65536],
        ):
            current = receipt(manifest_sha)
            current["host"]["cpu_affinity"] = malformed
            current["host"]["logical_cpus"] = len(malformed) or 1
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(
                    qualification.QualificationError, "CPU affinity"
                ):
                    qualification.validate_receipt_payload(
                        current, raw_manifest, baseline(manifest_sha)
                    )

        current = receipt(manifest_sha)
        current["host"]["cpu_affinity"] = [0]
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU affinity"
        ):
            qualification.validate_receipt_payload(
                current, raw_manifest, baseline(manifest_sha)
            )

        for malformed_source in ([], {}, 7, None, "invented"):
            current = receipt(manifest_sha)
            current["host"]["cpu_affinity_source"] = malformed_source
            with self.subTest(malformed_source=malformed_source):
                with self.assertRaisesRegex(
                    qualification.QualificationError, "source is malformed"
                ):
                    qualification.validate_receipt_payload(
                        current, raw_manifest, baseline(manifest_sha)
                    )

        current = receipt(manifest_sha)
        current["host"].update({
            "cpu_affinity_source": "unavailable",
            "cpu_affinity": [],
            "cpu_uclamp_source": "proc-self-sched",
            "controller_cpu_affinity": [],
            "measurement_environment": "unavailable",
            "measurement_cgroup_populated": None,
            "measurement_cgroup_frozen": None,
        })
        with self.assertRaisesRegex(
            qualification.QualificationError, "measurement.*(?:cgroup|boundary)"
        ):
            qualification.validate_receipt_payload(
                current, raw_manifest, baseline(manifest_sha)
            )

        current = receipt(manifest_sha)
        current["configuration"]["performance_policy"] = "record-only"
        current["host"].update({
            "cpu_affinity_source": "unavailable",
            "cpu_affinity": [],
            "cpu_uclamp_source": "proc-self-sched",
            "controller_cpu_affinity": [],
            "measurement_environment": "unavailable",
            "measurement_cgroup_populated": None,
            "measurement_cgroup_frozen": None,
        })
        current["baseline"]["profile"] = None
        current["baseline"]["performance_gate"] = "not-gated"
        qualification.validate_receipt_payload(
            current, raw_manifest, baseline(manifest_sha)
        )

        malformed_baseline = baseline(manifest_sha)
        malformed_baseline["profiles"]["test-linux-x86_64"]["hardware"].update({
            "cpu_affinity_source": "unavailable",
            "cpu_affinity": [],
            "cpu_uclamp_source": "proc-self-sched",
            "controller_cpu_affinity": [],
            "measurement_environment": "unavailable",
            "measurement_cgroup_populated": None,
            "measurement_cgroup_frozen": None,
        })
        with self.assertRaisesRegex(
            qualification.QualificationError, "measurement cgroup"
        ):
            qualification.validate_baseline(malformed_baseline, manifest_sha)

        malformed_calibration = calibration_receipt(manifest_sha)
        malformed_calibration["host"].update({
            "cpu_affinity_source": "unavailable",
            "cpu_affinity": [],
            "cpu_uclamp_source": "proc-self-sched",
            "controller_cpu_affinity": [],
            "measurement_environment": "unavailable",
            "measurement_cgroup_populated": None,
            "measurement_cgroup_frozen": None,
        })
        with self.assertRaisesRegex(
            qualification.QualificationError, "measurement cgroup"
        ):
            qualification._validate_calibration_payload(
                malformed_calibration, raw_manifest
            )

        rejected = rejected_receipt(manifest_sha)
        rejected["host"]["cpu_affinity"] = [0, "1"]
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU affinity"
        ):
            qualification._validate_rejected_payload(rejected, raw_manifest)

        rejected["host"].update({
            "cpu_affinity_source": "unavailable",
            "cpu_affinity": [],
            "cpu_uclamp_source": "unavailable",
            "cpu_uclamp_min": None,
            "cpu_uclamp_max": None,
            "controller_cpu_affinity": [],
            "measurement_environment": "unavailable",
            "measurement_cgroup_populated": None,
            "measurement_cgroup_frozen": None,
        })
        qualification._validate_rejected_payload(rejected, raw_manifest)

    def test_uclamp_identity_and_required_performance_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sched = temporary_root(directory) / "sched"
            sched.write_text(
                "effective uclamp.min : 1024\n"
                "effective uclamp.max : 1024\n",
                encoding="ascii",
            )
            self.assertEqual(
                qualification._cpu_uclamp_identity(sched),
                ("proc-self-sched", 1024, 1024),
            )
            self.assertEqual(
                qualification._cpu_uclamp_identity(temporary_root(directory) / "missing"),
                ("unavailable", None, None),
            )
            sched.write_text("effective uclamp.min : 1024\n", encoding="ascii")
            with self.assertRaisesRegex(
                qualification.QualificationError, "malformed"
            ):
                qualification._cpu_uclamp_identity(sched)
            for malformed in (
                "effective uclamp.min : nope\n"
                "effective uclamp.max : nope\n",
                "effective uclamp.min : 00000\n"
                "effective uclamp.max : 1024\n",
                "effective uclamp.min : 0\n"
                "effective uclamp.max : 999999999999999999999999\n",
                "effective uclamp.min : 1024\n"
                "effective uclamp.min : 1024\n"
                "effective uclamp.max : 1024\n",
            ):
                sched.write_text(malformed, encoding="ascii")
                with self.subTest(sched=malformed):
                    with self.assertRaisesRegex(
                        qualification.QualificationError, "malformed"
                    ):
                        qualification._cpu_uclamp_identity(sched)

            sched.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaisesRegex(
                qualification.QualificationError, "oversized"
            ):
                qualification._cpu_uclamp_identity(sched)

        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        for malformed in (
            ([], 1024, 1024),
            ("invented", 1024, 1024),
            ("proc-self-sched", "1024", 1024),
            ("proc-self-sched", 1024, 1025),
            ("proc-self-sched", 1024, 512),
            ("unavailable", 0, 1024),
        ):
            current = receipt(manifest_sha)
            (current["host"]["cpu_uclamp_source"],
             current["host"]["cpu_uclamp_min"],
             current["host"]["cpu_uclamp_max"]) = malformed
            with self.subTest(malformed=malformed):
                with self.assertRaises(qualification.QualificationError):
                    qualification.validate_receipt_payload(
                        current, raw_manifest, baseline(manifest_sha)
                    )

        current = receipt(manifest_sha)
        current["host"].update({
            "cpu_uclamp_source": "cgroup-v2",
            "cpu_uclamp_min": 0,
            "cpu_uclamp_max": 1024,
        })
        with self.assertRaisesRegex(
            qualification.QualificationError, "not stable"
        ):
            qualification.validate_receipt_payload(
                current, raw_manifest, baseline(manifest_sha)
            )

        current["configuration"]["performance_policy"] = "record-only"
        current["baseline"]["profile"] = None
        current["baseline"]["performance_gate"] = "not-gated"
        qualification.validate_receipt_payload(
            current, raw_manifest, baseline(manifest_sha)
        )

    def test_pinned_baseline_records_full_toolchain_identity(self) -> None:
        raw_manifest = manifest()
        base = baseline(qualification.digest_json(raw_manifest))
        provenance = base["profiles"]["test-linux-x86_64"]["provenance"]
        self.assertEqual(
            set(provenance["toolchain"]),
            {
                "analyzer", "clang", "gnu_time", "cmake", "ninja",
                "c_compiler", "cxx_compiler", "python",
            },
        )
        for tool in provenance["toolchain"].values():
            self.assertRegex(tool["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(tool["version"])

    def test_build_cache_identity_is_workspace_independent_and_config_sensitive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            tools = root / "tools"
            tools.mkdir()
            cmake = tools / "cmake"
            ninja = tools / "ninja"
            c_compiler = tools / "clang-20"
            cxx_compiler = tools / "clang++-20"
            git = tools / "git"
            for tool in (cmake, ninja, c_compiler, cxx_compiler, git):
                tool.write_bytes(b"fixture\n")
            aliases = root / "aliases"
            aliases.mkdir()
            alias_tools = tuple(aliases / tool.name for tool in (
                cmake, ninja, c_compiler, cxx_compiler
            ))
            for alias, tool in zip(alias_tools, (
                cmake, ninja, c_compiler, cxx_compiler
            )):
                alias.symlink_to(tool)

            def write_cache(
                name: str, option: str, reverse: bool,
                recorded_tools: tuple[Path, Path, Path, Path] | None = None,
                option_type: str = "BOOL", unknown_option: str = "alpha",
                git_version: str = "2.43.0",
            ) -> tuple[Path, Path]:
                workspace = root / name
                source = workspace / "source"
                build = source / "build"
                source.mkdir(parents=True)
                build.mkdir()
                recorded_cmake, recorded_ninja, recorded_c, recorded_cxx = (
                    recorded_tools or (cmake, ninja, c_compiler, cxx_compiler)
                )
                entries = [
                    f"CMAKE_COMMAND:INTERNAL={recorded_cmake}",
                    f"CMAKE_MAKE_PROGRAM:FILEPATH={recorded_ninja}",
                    f"CMAKE_C_COMPILER:FILEPATH={recorded_c}",
                    f"CMAKE_CXX_COMPILER:FILEPATH={recorded_cxx}",
                    "CMAKE_GENERATOR:INTERNAL=Ninja",
                    f"GIT_EXE:FILEPATH={git}",
                    f"GIT_EXECUTABLE:FILEPATH={git}",
                    f"FIND_PACKAGE_MESSAGE_DETAILS_Git:INTERNAL="
                    f"[{git}][v{git_version}()]",
                    f"CMAKE_HOME_DIRECTORY:INTERNAL={source}",
                    f"CMAKE_CACHEFILE_DIR:INTERNAL={build}",
                    f"CodeSkeptic_SOURCE_DIR:STATIC={source}",
                    f"CodeSkeptic_BINARY_DIR:STATIC={build}",
                    f"CODESKEPTIC_BUILD_TESTS:{option_type}={option}",
                    f"UNKNOWN_FUTURE_OPTION:STRING={unknown_option}",
                ]
                if reverse:
                    entries.reverse()
                (build / "CMakeCache.txt").write_text(
                    "// generated cache\n" + "\n".join(entries) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                return source, build

            first_source, first_build = write_cache("first", "OFF", False)
            first = qualification._build_toolchain_identity(
                first_build, first_source,
                cmake, ninja, c_compiler, cxx_compiler,
            )
            lexical_source = first_source / ".." / "source"
            lexical_build = lexical_source / "build"
            cache_path = first_build / "CMakeCache.txt"
            cache_lines = cache_path.read_text(encoding="utf-8").splitlines()
            lexical_values = {
                "CMAKE_HOME_DIRECTORY:": lexical_source,
                "CMAKE_CACHEFILE_DIR:": lexical_build,
                "CodeSkeptic_SOURCE_DIR:": lexical_source,
                "CodeSkeptic_BINARY_DIR:": lexical_build,
            }

            def lexicalize_cache_line(line: str) -> str:
                for prefix, value in lexical_values.items():
                    if line.startswith(prefix):
                        return f"{line.split('=', 1)[0]}={value}"
                return line

            cache_path.write_text(
                "\n".join(lexicalize_cache_line(line) for line in cache_lines) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            lexical = qualification._build_toolchain_identity(
                lexical_build, lexical_source,
                cmake, ninja, c_compiler, cxx_compiler,
            )
            relocated_source, relocated_build = write_cache(
                "relocated", "OFF", True, alias_tools
            )
            relocated = qualification._build_toolchain_identity(
                relocated_build, relocated_source,
                cmake, ninja, c_compiler, cxx_compiler,
            )
            changed_source, changed_build = write_cache("changed", "ON", False)
            changed = qualification._build_toolchain_identity(
                changed_build, changed_source,
                cmake, ninja, c_compiler, cxx_compiler,
            )
            typed_source, typed_build = write_cache(
                "typed", "OFF", False, option_type="STRING"
            )
            typed = qualification._build_toolchain_identity(
                typed_build, typed_source,
                cmake, ninja, c_compiler, cxx_compiler,
            )
            unknown_source, unknown_build = write_cache(
                "unknown", "OFF", False, unknown_option="beta"
            )
            unknown = qualification._build_toolchain_identity(
                unknown_build, unknown_source,
                cmake, ninja, c_compiler, cxx_compiler,
            )
            git_drift_source, git_drift_build = write_cache(
                "git-drift", "OFF", False, git_version="2.54.0"
            )
            git_drift = qualification._build_toolchain_identity(
                git_drift_build, git_drift_source,
                cmake, ninja, c_compiler, cxx_compiler,
            )

            self.assertEqual(
                first["cmake_cache_canonical_sha256"],
                relocated["cmake_cache_canonical_sha256"],
            )
            self.assertEqual(
                first["cmake_cache_canonical_sha256"],
                lexical["cmake_cache_canonical_sha256"],
            )
            self.assertNotEqual(
                first["cmake_cache_canonical_sha256"],
                changed["cmake_cache_canonical_sha256"],
            )
            self.assertNotEqual(
                first["cmake_cache_canonical_sha256"],
                typed["cmake_cache_canonical_sha256"],
            )
            self.assertNotEqual(
                first["cmake_cache_canonical_sha256"],
                unknown["cmake_cache_canonical_sha256"],
            )
            self.assertEqual(
                first["cmake_cache_canonical_sha256"],
                git_drift["cmake_cache_canonical_sha256"],
            )
            self.assertEqual(
                first["cmake_cache_schema"],
                "codeskeptic-cmake-cache-v2",
            )
            legacy_identity = dict(first)
            legacy_identity["cmake_cache_schema"] = "codeskeptic-cmake-cache-v1"
            with self.assertRaisesRegex(
                qualification.QualificationError, "CMake cache schema drift"
            ):
                qualification._validate_build_toolchain_identity(
                    legacy_identity, "legacy build toolchain", None
                )

            mismatched_git_source, mismatched_git = write_cache(
                "mismatched-git", "OFF", False
            )
            mismatched_git_cache = mismatched_git / "CMakeCache.txt"
            mismatched_git_cache.write_text(
                mismatched_git_cache.read_text(encoding="utf-8").replace(
                    f"GIT_EXE:FILEPATH={git}",
                    f"GIT_EXE:FILEPATH={cmake}",
                ),
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "Git discovery identity drift",
            ):
                qualification._build_toolchain_identity(
                    mismatched_git, mismatched_git_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            missing_git_source, missing_git = write_cache(
                "missing-git", "OFF", False
            )
            missing_git_cache = missing_git / "CMakeCache.txt"
            missing_git_cache.write_text(
                "\n".join(
                    line for line in missing_git_cache.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if not line.startswith("GIT_EXE:")
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "Git discovery identity drift",
            ):
                qualification._build_toolchain_identity(
                    missing_git, missing_git_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            malformed_git_source, malformed_git = write_cache(
                "malformed-git", "OFF", False
            )
            malformed_git_cache = malformed_git / "CMakeCache.txt"
            malformed_git_cache.write_text(
                malformed_git_cache.read_text(encoding="utf-8").replace(
                    f"[{git}][v2.43.0()]",
                    "[/unexpected/git][v2.43.0()]",
                ),
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "Git discovery details are malformed",
            ):
                qualification._build_toolchain_identity(
                    malformed_git, malformed_git_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            malformed_version_source, malformed_version = write_cache(
                "malformed-version", "OFF", False
            )
            malformed_version_cache = malformed_version / "CMakeCache.txt"
            malformed_version_cache.write_text(
                malformed_version_cache.read_text(encoding="utf-8").replace(
                    "[v2.43.0()]", "[vnot-a-version()]"
                ),
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "Git discovery details are malformed",
            ):
                qualification._build_toolchain_identity(
                    malformed_version, malformed_version_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            duplicate_source, duplicate = write_cache("duplicate", "OFF", False)
            with (duplicate / "CMakeCache.txt").open(
                "a", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write("CMAKE_GENERATOR:INTERNAL=Ninja\n")
            with self.assertRaisesRegex(
                qualification.QualificationError, "duplicates CMAKE_GENERATOR"
            ):
                qualification._build_toolchain_identity(
                    duplicate, duplicate_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            malformed_source, malformed = write_cache("malformed", "OFF", False)
            with (malformed / "CMakeCache.txt").open(
                "a", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write("MALFORMED_CACHE_RECORD\n")
            with self.assertRaisesRegex(
                qualification.QualificationError, "has no value"
            ):
                qualification._build_toolchain_identity(
                    malformed, malformed_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            nul_source, nul = write_cache("nul", "OFF", False)
            with (nul / "CMakeCache.txt").open(
                "a", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write("NUL_VALUE:STRING=bad\x00value\n")
            with self.assertRaisesRegex(
                qualification.QualificationError, "is malformed"
            ):
                qualification._build_toolchain_identity(
                    nul, nul_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            other_source = root / "other-source"
            other_source.mkdir()
            with self.assertRaisesRegex(
                qualification.QualificationError, "source root identity drift"
            ):
                qualification._build_toolchain_identity(
                    first_build, other_source,
                    cmake, ninja, c_compiler, cxx_compiler,
                )

            boundary_roots = [(Path("/work"), "$SOURCE")]
            self.assertEqual(
                qualification._canonical_cmake_cache_value(
                    "/work/include", boundary_roots
                ),
                [{"root": "$SOURCE"}, {"literal": "/include"}],
            )
            self.assertEqual(
                qualification._canonical_cmake_cache_value(
                    "/work-evil/include", boundary_roots
                ),
                [{"literal": "/work-evil/include"}],
            )
            self.assertEqual(
                qualification._canonical_cmake_cache_value(
                    "https://example.test/work/include", boundary_roots
                ),
                [{"literal": "https://example.test/work/include"}],
            )

    def test_release_preparation_rejects_reusable_workspace_state(self) -> None:
        release_workload = manifest()["workloads"][2]
        with tempfile.TemporaryDirectory() as directory:
            workspace = temporary_root(directory) / "release"
            source = workspace / "llama-cpp"
            build = workspace / "llama-cpp-build"
            source.mkdir(parents=True)
            build.mkdir()
            (build / "compile_commands.json").write_text(
                "[]\n", encoding="utf-8", newline="\n"
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "release workspace must be empty",
            ):
                qualification.prepare_release_candidate(
                    ROOT, release_workload, workspace, 1,
                    Path("/usr/bin/cmake"), Path("/usr/bin/ninja"),
                    Path("/usr/bin/clang-20"), Path("/usr/bin/clang++-20"),
                )

    def test_release_preparation_accepts_only_an_exact_empty_target_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "release" / "source"
            build = root / "release" / "build"
            source.mkdir(parents=True)
            build.mkdir()
            self.assertEqual(
                qualification._release_candidate_paths(
                    None, "llama-cpp",
                    release_source=source,
                    release_build=build,
                ),
                (source.resolve(), build.resolve()),
            )
            with self.assertRaisesRegex(
                qualification.QualificationError, "both"
            ):
                qualification._release_candidate_paths(
                    None, "llama-cpp", release_source=source
                )
            (build / "stale").write_text("collision\n", encoding="utf-8")
            with self.assertRaisesRegex(
                qualification.QualificationError, "empty"
            ):
                qualification._release_candidate_paths(
                    None, "llama-cpp",
                    release_source=source,
                    release_build=build,
                )

            with self.assertRaisesRegex(
                qualification.QualificationError, "mutually exclusive"
            ):
                qualification._release_candidate_paths(
                    root / "workspace", "llama-cpp",
                    release_source=source,
                    release_build=build,
                )

            nested = source / "nested-build"
            nested.mkdir()
            with self.assertRaisesRegex(
                qualification.QualificationError, "overlap"
            ):
                qualification._release_candidate_paths(
                    None, "llama-cpp",
                    release_source=source,
                    release_build=nested,
                )

            alias = root / "source-alias"
            alias.symlink_to(source, target_is_directory=True)
            with self.assertRaisesRegex(
                qualification.QualificationError, "not a real directory"
            ):
                qualification._release_candidate_paths(
                    None, "llama-cpp",
                    release_source=alias,
                    release_build=build,
                )

            parent_alias = root / "release-alias"
            parent_alias.symlink_to(source.parent, target_is_directory=True)
            with self.assertRaisesRegex(
                qualification.QualificationError, "not a real directory"
            ):
                qualification._release_candidate_paths(
                    None, "llama-cpp",
                    release_source=parent_alias / "source",
                    release_build=build,
                )

    def test_release_checkout_ignores_ambient_templates_and_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            upstream = root / "upstream"
            upstream.mkdir()
            subprocess.run(
                ["git", "init", "--quiet", "-b", "main"],
                cwd=upstream, check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Fixture"],
                cwd=upstream, check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=upstream, check=True,
            )
            (upstream / "sample.txt").write_text(
                "pinned bytes\n", encoding="utf-8"
            )
            subprocess.run(["git", "add", "."], cwd=upstream, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "fixture"],
                cwd=upstream, check=True,
            )
            revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=upstream, text=True,
            ).strip()

            marker = root / "post-checkout-ran"
            template = root / "malicious-template"
            template_hook = template / "hooks" / "post-checkout"
            template_hook.parent.mkdir(parents=True)
            template_hook.write_text(
                "#!/bin/sh\n" f"touch '{marker}'\n", encoding="utf-8"
            )
            template_hook.chmod(0o755)
            global_hooks = root / "global-hooks"
            global_hooks.mkdir()
            global_hook = global_hooks / "post-checkout"
            global_hook.write_text(
                "#!/bin/sh\n" f"touch '{marker}'\n", encoding="utf-8"
            )
            global_hook.chmod(0o755)
            home = root / "home"
            home.mkdir()
            global_config = home / ".gitconfig"
            global_config.write_text(
                "[init]\n"
                f"\ttemplateDir = {template}\n"
                "[core]\n"
                f"\thooksPath = {global_hooks}\n",
                encoding="utf-8",
            )
            source = root / "release-source"
            source.mkdir()
            injected = {
                "GIT_CONFIG_GLOBAL": os.fspath(global_config),
                "GIT_CONFIG_PARAMETERS": (
                    f"'core.hooksPath'='{global_hooks}'"
                ),
                "GIT_DIR": os.fspath(upstream / ".git"),
                "GIT_TEMPLATE_DIR": os.fspath(template),
                "HOME": os.fspath(home),
                "PATH": "/usr/bin:/bin",
            }
            with mock.patch.dict(os.environ, injected, clear=True):
                closed = qualification._release_git_environment(
                    source, upstream.as_uri()
                )
                qualification._prepare_release_checkout(
                    source, upstream.as_uri(), revision
                )

            self.assertFalse(marker.exists())
            self.assertFalse((source / ".git" / "hooks" / "post-checkout").exists())
            self.assertEqual(
                (source / "sample.txt").read_text(encoding="utf-8"),
                "pinned bytes\n",
            )
            self.assertNotIn("GIT_CONFIG_PARAMETERS", closed)
            self.assertNotIn("GIT_DIR", closed)
            self.assertNotIn("GIT_TEMPLATE_DIR", closed)
            self.assertEqual(closed["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(closed["GIT_CONFIG_SYSTEM"], os.devnull)
            self.assertEqual(closed["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(closed["GIT_PROTOCOL_FROM_USER"], "0")
            self.assertEqual(closed["GIT_ALLOW_PROTOCOL"], "file")

            completed = subprocess.CompletedProcess([], 0, b"")
            mocked_source = root / "mocked-release-source"
            with mock.patch.object(
                qualification.subprocess, "run", return_value=completed
            ) as invoked:
                qualification._prepare_release_checkout(
                    mocked_source, upstream.as_uri(), revision
                )
            expected_environment = qualification._release_git_environment(
                mocked_source, upstream.as_uri()
            )
            self.assertEqual(len(invoked.call_args_list), 4)
            for invocation in invoked.call_args_list:
                self.assertEqual(invocation.kwargs["env"], expected_environment)
                self.assertIs(invocation.kwargs["stdin"], subprocess.DEVNULL)
            commands = [call.args[0] for call in invoked.call_args_list]
            self.assertIn("--template=", commands[0])
            self.assertIn("remote", commands[1])
            self.assertIn("fetch", commands[2])
            self.assertIn("checkout", commands[3])

    def test_explicit_target_pin_detects_target_and_parent_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            release = root / "release"
            source = release / "source"
            build = release / "build"
            source.mkdir(parents=True)
            build.mkdir()
            with qualification._PinnedReleaseTargets(
                source, build, require_empty=True
            ) as target_pin:
                original = release / "original-build"
                build.rename(original)
                build.symlink_to(original.name, target_is_directory=True)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "build identity drift",
                ):
                    target_pin.verify("before mutation")

        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            release = root / "release"
            source = release / "source"
            build = release / "build"
            source.mkdir(parents=True)
            build.mkdir()
            with qualification._PinnedReleaseTargets(
                source, build, require_empty=True
            ) as target_pin:
                original = root / "original-release"
                release.rename(original)
                source.mkdir(parents=True)
                build.mkdir()
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "parent identity drift",
                ):
                    target_pin.verify("before mutation")

    def test_explicit_release_projection_removes_only_exact_llama_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "source"
            build = root / "build"
            write_llama_release_links(source, build)

            qualification._project_explicit_release_candidate(
                "llama-cpp", source, build
            )

            for qualified in qualification.LLAMA_STAGING_BUILD_SYMLINKS:
                _, relative = qualified.split("/", 1)
                self.assertFalse((build / relative).exists())
                self.assertFalse((build / relative).is_symlink())
            for terminal in (
                "libggml-base.so.0.19.0",
                "libggml-cpu.so.0.19.0",
                "libggml.so.0.19.0",
                "libllama.so.0.0.1",
            ):
                self.assertTrue((build / "bin" / terminal).is_file())

            unexpected = source / "unexpected"
            unexpected.symlink_to("missing")
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "symlink inventory drift",
            ):
                qualification._project_explicit_release_candidate(
                    "llama-cpp", source, build
                )

    def test_explicit_release_projection_rolls_back_or_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "source"
            build = root / "build"
            write_llama_release_links(source, build)
            real_unlink = os.unlink
            calls = 0

            def fail_second_unlink(
                path: str, *, dir_fd: int | None = None,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected unlink failure")
                real_unlink(path, dir_fd=dir_fd)

            with mock.patch.object(
                qualification.os, "unlink", side_effect=fail_second_unlink
            ), self.assertRaisesRegex(
                qualification.QualificationError,
                "cannot project explicit release candidate",
            ):
                qualification._project_explicit_release_candidate(
                    "llama-cpp", source, build
                )
            for qualified, target in (
                qualification.LLAMA_STAGING_BUILD_SYMLINKS.items()
            ):
                _, relative = qualified.split("/", 1)
                self.assertTrue((build / relative).is_symlink())
                self.assertEqual(os.readlink(build / relative), target)

        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "source"
            build = root / "build"
            write_llama_release_links(source, build)
            real_unlink = os.unlink
            calls = 0

            def fail_second_unlink_again(
                path: str, *, dir_fd: int | None = None,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected unlink failure")
                real_unlink(path, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    qualification.os, "unlink",
                    side_effect=fail_second_unlink_again,
                ),
                mock.patch.object(
                    qualification.os, "symlink",
                    side_effect=OSError("injected rollback failure"),
                ),
                self.assertRaisesRegex(
                    qualification.QualificationError, "rollback failed"
                ),
            ):
                qualification._project_explicit_release_candidate(
                    "llama-cpp", source, build
                )

    def test_explicit_release_projection_detects_build_subdirectory_race(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "source"
            build = root / "build"
            write_llama_release_links(source, build)
            real_unlink = os.unlink
            raced = False

            def replace_bin_after_first_unlink(
                path: str, *, dir_fd: int | None = None,
            ) -> None:
                nonlocal raced
                real_unlink(path, dir_fd=dir_fd)
                if not raced:
                    raced = True
                    (build / "bin").rename(build / "original-bin")
                    (build / "bin").mkdir()

            with (
                mock.patch.object(
                    qualification.os, "unlink",
                    side_effect=replace_bin_after_first_unlink,
                ),
                self.assertRaisesRegex(
                    qualification.QualificationError,
                    "build/bin identity drift",
                ),
            ):
                qualification._project_explicit_release_candidate(
                    "llama-cpp", source, build
                )
            for qualified, target in (
                qualification.LLAMA_STAGING_BUILD_SYMLINKS.items()
            ):
                _, relative = qualified.split("/", 1)
                name = Path(relative).name
                self.assertTrue((build / "original-bin" / name).is_symlink())
                self.assertEqual(
                    os.readlink(build / "original-bin" / name), target
                )

    def test_prepare_projects_explicit_targets_but_not_legacy_workspace(self) -> None:
        release_workload = manifest()["workloads"][2]

        def exercise(
            root: Path, *, explicit: bool,
        ) -> tuple[Path, Path, mock.Mock]:
            if explicit:
                source = root / "release" / "source"
                build = root / "release" / "build"
                source.mkdir(parents=True)
                build.mkdir()
                workspace = None
                explicit_arguments = {
                    "release_source": source,
                    "release_build": build,
                }
            else:
                workspace = root / "workspace"
                workspace.mkdir()
                source = workspace / "llama-cpp"
                build = workspace / "llama-cpp-build"
                explicit_arguments = {}

            def fake_checkout(
                checkout_source: Path,
                unused_repository: str,
                unused_revision: str,
                unused_pin: object = None,
            ) -> None:
                checkout_source.mkdir(parents=True, exist_ok=True)

            prepared = False

            def fake_build(
                command: list[str], **unused: object,
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal prepared
                if not prepared:
                    write_llama_release_links(source, build)
                    (build / "compile_commands.json").write_text(
                        "[]\n", encoding="utf-8"
                    )
                    prepared = True
                return subprocess.CompletedProcess(command, 0, b"ok\n")

            with (
                mock.patch.object(
                    qualification, "_prepare_release_checkout",
                    side_effect=fake_checkout,
                ),
                mock.patch.object(
                    qualification.subprocess, "run", side_effect=fake_build,
                ),
                mock.patch.object(
                    qualification, "_build_toolchain_identity", return_value={},
                ),
                mock.patch.object(
                    qualification, "_git_output", return_value="",
                ),
                mock.patch.object(
                    qualification, "_project_explicit_release_candidate",
                    wraps=qualification._project_explicit_release_candidate,
                ) as projected,
            ):
                observed_source, observed_build, _ = (
                    qualification.prepare_release_candidate(
                        ROOT, release_workload, workspace, 1,
                        Path("/usr/bin/cmake"), Path("/usr/bin/ninja"),
                        Path("/usr/bin/clang-20"),
                        Path("/usr/bin/clang++-20"),
                        **explicit_arguments,
                    )
                )
            self.assertEqual(observed_source, source)
            self.assertEqual(observed_build, build)
            return source, build, projected

        with tempfile.TemporaryDirectory() as directory:
            source, build, projected = exercise(
                temporary_root(directory), explicit=True
            )
            projected.assert_called_once()
            for qualified in qualification.LLAMA_STAGING_BUILD_SYMLINKS:
                _, relative = qualified.split("/", 1)
                self.assertFalse((build / relative).is_symlink())
            self.assertTrue(source.is_dir())

        with tempfile.TemporaryDirectory() as directory:
            source, build, projected = exercise(
                temporary_root(directory), explicit=False
            )
            projected.assert_not_called()
            for qualified in qualification.LLAMA_STAGING_BUILD_SYMLINKS:
                _, relative = qualified.split("/", 1)
                self.assertTrue((build / relative).is_symlink())
            self.assertTrue(source.is_dir())

    def test_prepare_rejects_explicit_target_replacement_before_projection(self) -> None:
        release_workload = manifest()["workloads"][2]
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source = root / "release" / "source"
            build = root / "release" / "build"
            source.mkdir(parents=True)
            build.mkdir()

            def fake_checkout(
                unused_source: Path,
                unused_repository: str,
                unused_revision: str,
                unused_pin: object = None,
            ) -> None:
                return None

            prepared = False

            def fake_build(
                command: list[str], **unused: object,
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal prepared
                if not prepared:
                    write_llama_release_links(source, build)
                    (build / "compile_commands.json").write_text(
                        "[]\n", encoding="utf-8"
                    )
                    prepared = True
                return subprocess.CompletedProcess(command, 0, b"ok\n")

            def replace_build(*unused: object) -> dict:
                build.rename(root / "original-build")
                build.mkdir()
                return {}

            with (
                mock.patch.object(
                    qualification, "_prepare_release_checkout",
                    side_effect=fake_checkout,
                ),
                mock.patch.object(
                    qualification.subprocess, "run", side_effect=fake_build,
                ),
                mock.patch.object(
                    qualification, "_build_toolchain_identity",
                    side_effect=replace_build,
                ),
                mock.patch.object(
                    qualification, "_git_output", return_value="",
                ),
                mock.patch.object(
                    qualification, "_project_explicit_release_candidate",
                ) as projected,
                self.assertRaisesRegex(
                    qualification.QualificationError, "build identity drift"
                ),
            ):
                qualification.prepare_release_candidate(
                    ROOT, release_workload, None, 1,
                    Path("/usr/bin/cmake"), Path("/usr/bin/ninja"),
                    Path("/usr/bin/clang-20"), Path("/usr/bin/clang++-20"),
                    release_source=source, release_build=build,
                )
            projected.assert_not_called()

    def test_run_forwards_explicit_release_preparation_targets(self) -> None:
        raw_manifest = manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            repo = root / "repo"
            build = root / "build"
            source = root / "release" / "source"
            release_build = root / "release" / "build"
            for path in (repo, build, source, release_build):
                path.mkdir(parents=True, exist_ok=True)
            binaries: dict[str, Path] = {}
            for name in (
                "codeskeptic", "clang", "time", "cmake", "ninja",
                "cc", "cxx",
            ):
                binaries[name] = root / name
                binaries[name].write_bytes(b"fixture\n")
            args = mock.Mock(
                repo_root=repo,
                build_path=build,
                binary=binaries["codeskeptic"],
                clang=binaries["clang"],
                time_binary=binaries["time"],
                cmake=binaries["cmake"],
                ninja=binaries["ninja"],
                c_compiler=binaries["cc"],
                cxx_compiler=binaries["cxx"],
                output=root / "evidence",
                manifest=root / "manifest.json",
                baseline=root / "baseline.json",
                repetitions=10,
                revision="head-revision",
                measurement_cgroup=None,
                hardware_class="test-linux-x86_64",
                performance_policy="required",
                prepare_release_candidate=True,
                release_workspace=None,
                release_source=source,
                release_build=release_build,
                jobs=2,
                establish_baseline=False,
                candidate_baseline_output=None,
                baseline_authority_root=repo,
            )
            prepared = mock.Mock(
                side_effect=qualification.QualificationError(
                    "explicit preparation reached"
                )
            )
            with (
                mock.patch.object(
                    qualification, "load_manifest", return_value=raw_manifest,
                ),
                mock.patch.object(
                    qualification, "source_manifest", return_value={
                        "revision": "head-revision",
                        "manifest_sha256": "1" * 64,
                        "file_count": 1,
                    },
                ),
                mock.patch.object(qualification, "_git_output", return_value=""),
                mock.patch.object(qualification, "host_identity", return_value={}),
                mock.patch.object(
                    qualification, "toolchain_identity", return_value={},
                ),
                mock.patch.object(
                    qualification, "_preflight_qualification_baseline",
                ),
                mock.patch.object(
                    qualification, "prepare_release_candidate", prepared,
                ),
                mock.patch.object(qualification, "_persist_rejection"),
                self.assertRaisesRegex(
                    qualification.QualificationError,
                    "explicit preparation reached",
                ),
            ):
                qualification.run_qualification(args)
            self.assertEqual(prepared.call_args.kwargs, {
                "release_source": source,
                "release_build": release_build,
            })

    def test_pinned_baseline_is_bound_to_raw_calibration_and_promotion(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        with tempfile.TemporaryDirectory() as directory:
            authority = temporary_root(directory) / "authority"
            initialize_source_repo(authority)
            write_determinism_infrastructure(authority, raw_manifest)
            source_revision = git_commit(authority, "determinism infrastructure")
            source = qualification.source_manifest_at_revision(
                authority, source_revision
            )
            calibration = calibration_receipt(
                manifest_sha, repo_root=authority,
                source_revision=source_revision, source=source,
            )
            calibration_artifacts = artifact_bytes(calibration)
            manifest_path = authority / "scripts" / "determinism_workloads.json"
            evidence_path = (
                authority / "docs" / "evidence" / "phase10" /
                "determinism" / "calibrations" / "test-linux-x86_64"
            )
            qualification.write_receipt(
                evidence_path, calibration, calibration_artifacts
            )

            base = baseline(
                manifest_sha, repo_root=authority,
                source_revision=source_revision,
            )
            provenance = base["profiles"]["test-linux-x86_64"]["provenance"]
            provenance["calibration"]["receipt_sha256"] = qualification.sha256_file(
                evidence_path / "receipt.json"
            )
            qualification.validate_baseline(base, manifest_sha)
            qualification.verify_baseline_authority(
                base, authority, manifest_path
            )

            profile = base["profiles"]["test-linux-x86_64"]
            profile["os"] = "Linux 7.1.8-200.fc44.x86_64"
            qualification.validate_baseline(base, manifest_sha)
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "calibration provenance drift",
            ):
                qualification.verify_baseline_authority(
                    base, authority, manifest_path
                )
            profile["os"] = calibration["host"]["os"]

            provenance["promotion"]["reason"] = ""
            with self.assertRaisesRegex(
                qualification.QualificationError, "promotion reason"
            ):
                qualification.validate_baseline(base, manifest_sha)
            provenance["promotion"]["reason"] = "Initial protected performance baseline"

            (evidence_path / "raw" / "unit" / "run-01" / "time.txt").write_bytes(
                time_log(101)
            )
            with self.assertRaisesRegex(
                qualification.QualificationError, "checksum|raw|manifest|file set"
            ):
                qualification.verify_baseline_authority(
                    base, authority, manifest_path
                )

    def test_path_manifest_canonicalizes_its_root_and_reports_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = temporary_root(directory)
            root = temporary / "root"
            root.mkdir()
            inside = root / "inside.cpp"
            inside.write_bytes(SAMPLE_BYTES)
            alias = temporary / "root-alias"
            alias.symlink_to(root, target_is_directory=True)
            outside = temporary / "outside.cpp"
            outside.write_bytes(SAMPLE_BYTES)
            self.assertEqual(
                qualification._path_manifest([inside], alias),
                [{"path": "inside.cpp", "sha256": sha256(SAMPLE_BYTES)}],
            )
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "input path escapes its source root",
            ):
                qualification._path_manifest([outside], root)

    def test_manifest_and_git_tree_reject_input_identity_drift(self) -> None:
        raw_manifest = manifest()
        with tempfile.TemporaryDirectory() as directory:
            repo = temporary_root(directory) / "repo"
            initialize_source_repo(repo)
            write_determinism_infrastructure(repo, raw_manifest)
            source_revision = git_commit(repo, "determinism infrastructure")
            inputs = {kind: input_receipt(kind, repo) for kind in KINDS}

            changed_manifest = copy.deepcopy(raw_manifest)
            changed_manifest["workloads"][2]["input"][
                "translation_units"
            ] = ["src/not-requested.cpp"]
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "release-candidate receipt differs",
            ):
                qualification._validate_manifest_inputs(
                    inputs, changed_manifest, repo, toolchain_identity(),
                    source_revision,
                )

            changed_inputs = copy.deepcopy(inputs)
            changed_inputs["unit"]["files"][0]["sha256"] = "f" * 64
            changed_inputs["unit"]["identity_sha256"] = qualification.digest_json(
                qualification._input_identity_material(changed_inputs["unit"])
            )
            with self.assertRaisesRegex(
                qualification.QualificationError, "input file identity drift"
            ):
                qualification._validate_manifest_inputs(
                    changed_inputs, raw_manifest, repo, toolchain_identity(),
                    source_revision,
                )

    def test_candidate_baseline_records_predecessor_identities(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        current = baseline(manifest_sha)
        accepted = receipt(manifest_sha)
        previous_baseline_sha = qualification.digest_json(current)
        previous_profile_sha = qualification.digest_json(
            current["profiles"]["test-linux-x86_64"]
        )
        promoted = qualification.build_baseline(
            manifest_sha,
            accepted["host"],
            "promoted-revision",
            accepted["toolchain"],
            accepted["workloads"],
            accepted["inputs"],
            (
                "docs/evidence/phase10/determinism/calibrations/"
                "promoted-test-linux-x86_64"
            ),
            "9" * 64,
            "Reviewed CPU and RSS baseline promotion",
            previous_baseline_sha,
            previous_profile_sha,
        )
        qualification.validate_baseline(promoted, manifest_sha)
        provenance = promoted["profiles"]["test-linux-x86_64"]["provenance"]
        self.assertEqual(
            provenance["promotion"]["previous_baseline_sha256"],
            previous_baseline_sha,
        )
        self.assertEqual(
            provenance["promotion"]["previous_profile_sha256"],
            previous_profile_sha,
        )

    def test_initial_baseline_bootstrap_allows_only_retained_authority_files(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        with tempfile.TemporaryDirectory() as directory:
            repo = temporary_root(directory) / "repo"
            initialize_source_repo(repo)
            base_revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
            write_determinism_infrastructure(repo, raw_manifest)
            infrastructure_revision = git_commit(
                repo, "determinism infrastructure"
            )
            source = qualification.source_manifest_at_revision(
                repo, infrastructure_revision
            )
            calibration = calibration_receipt(
                manifest_sha, repo_root=repo,
                source_revision=infrastructure_revision, source=source,
            )
            calibration_artifacts = artifact_bytes(calibration)
            manifest_path = repo / "scripts" / "determinism_workloads.json"
            changelog = repo / "docs" / "devlog" / "changelog.md"
            changelog.parent.mkdir(parents=True)
            changelog.write_text("# Changelog\n", encoding="utf-8")

            evidence = (
                repo / "docs" / "evidence" / "phase10" / "determinism" /
                "calibrations" / "test-linux-x86_64"
            )
            qualification.write_receipt(
                evidence, calibration, calibration_artifacts
            )
            pinned = baseline(
                manifest_sha, repo_root=repo,
                source_revision=infrastructure_revision,
            )
            pinned["profiles"]["test-linux-x86_64"]["provenance"][
                "calibration"
            ]["receipt_sha256"] = qualification.sha256_file(
                evidence / "receipt.json"
            )
            baseline_path = repo / "scripts" / "determinism_baseline.json"
            baseline_path.write_bytes(qualification.canonical_json(pinned))
            stress_receipt = (
                repo / "docs" / "evidence" / "phase10" / "stress" /
                "bootstrap" / "receipt.json"
            )
            stress_receipt.parent.mkdir(parents=True)
            stress_receipt.write_text("retained stress evidence\n", encoding="utf-8")
            changelog.write_text("# Changelog\n\nBaseline promoted.\n", encoding="utf-8")
            git_commit(repo, "promote baseline")
            qualification.verify_bootstrap_promotion(
                repo, base_revision, baseline_path, manifest_path
            )

            cmake = repo / "CMakeLists.txt"
            cmake.write_text("# post-authority repair\n", encoding="utf-8")
            git_commit(repo, "forbidden post-authority infrastructure repair")
            with self.assertRaisesRegex(
                qualification.QualificationError, "authority change set exceeds"
            ):
                qualification.verify_bootstrap_promotion(
                    repo, base_revision, baseline_path, manifest_path
                )

    def test_receipt_source_revision_survives_ignored_authority_commit(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        with tempfile.TemporaryDirectory() as directory:
            repo = temporary_root(directory) / "repo"
            source = initialize_source_repo(repo)
            source_revision = source["revision"]
            payload = calibration_receipt(
                manifest_sha, repo_root=repo,
                source_revision=source_revision, source=source,
            )
            evidence = temporary_root(directory) / "calibration"
            qualification.write_receipt(
                evidence, payload, artifact_bytes(payload)
            )
            manifest_path = temporary_root(directory) / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))

            ignored = (
                repo / "docs" / "evidence" / "phase10" / "stress" /
                "later" / "receipt.json"
            )
            ignored.parent.mkdir(parents=True)
            ignored.write_text("later authority\n", encoding="utf-8")
            git_commit(repo, "retain ignored authority")

            qualification.verify_receipt(
                evidence, manifest_path, temporary_root(directory) / "unused.json", repo
            )

            (repo / "src" / "sample.cpp").write_text(
                "int changed;\n", encoding="utf-8"
            )
            git_commit(repo, "change admitted source")
            with self.assertRaisesRegex(
                qualification.QualificationError, "source bytes differ"
            ):
                qualification.verify_receipt(
                    evidence, manifest_path,
                    temporary_root(directory) / "unused.json", repo,
                )

    def test_baseline_update_requires_exact_predecessor_and_authority_only_diff(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        with tempfile.TemporaryDirectory() as directory:
            repo = temporary_root(directory) / "repo"
            initialize_source_repo(repo)
            write_determinism_infrastructure(repo, raw_manifest)
            source_revision = git_commit(repo, "determinism infrastructure")
            manifest_path = repo / "scripts" / "determinism_workloads.json"
            first_source = qualification.source_manifest_at_revision(
                repo, source_revision
            )
            first_calibration = calibration_receipt(
                manifest_sha, repo_root=repo,
                source_revision=source_revision, source=first_source,
            )
            first_evidence = (
                repo / "docs" / "evidence" / "phase10" / "determinism" /
                "calibrations" / "first"
            )
            qualification.write_receipt(
                first_evidence, first_calibration,
                artifact_bytes(first_calibration),
            )
            first = baseline(
                manifest_sha, repo_root=repo,
                source_revision=source_revision,
            )
            first_provenance = first["profiles"]["test-linux-x86_64"]["provenance"]
            first_provenance["calibration"] = {
                "evidence_path": (
                    "docs/evidence/phase10/determinism/calibrations/first"
                ),
                "receipt_sha256": qualification.sha256_file(
                    first_evidence / "receipt.json"
                ),
            }
            baseline_path = repo / "scripts" / "determinism_baseline.json"
            baseline_path.write_bytes(qualification.canonical_json(first))
            changelog = repo / "docs" / "devlog" / "changelog.md"
            changelog.parent.mkdir(parents=True, exist_ok=True)
            changelog.write_text("# Changelog\n\nFirst baseline.\n", encoding="utf-8")
            base_revision = git_commit(repo, "first baseline")

            second_source = qualification.source_manifest_at_revision(
                repo, base_revision
            )
            second_calibration = calibration_receipt(
                manifest_sha, repo_root=repo,
                source_revision=base_revision, source=second_source,
            )
            second_evidence = (
                repo / "docs" / "evidence" / "phase10" / "determinism" /
                "calibrations" / "second"
            )
            qualification.write_receipt(
                second_evidence, second_calibration,
                artifact_bytes(second_calibration),
            )
            second = qualification.build_baseline(
                manifest_sha,
                second_calibration["host"],
                base_revision,
                second_calibration["toolchain"],
                second_calibration["workloads"],
                second_calibration["inputs"],
                "docs/evidence/phase10/determinism/calibrations/second",
                qualification.sha256_file(second_evidence / "receipt.json"),
                "Reviewed replacement performance profile",
                qualification.sha256_file(baseline_path),
                qualification.digest_json(first["profiles"]["test-linux-x86_64"]),
            )
            baseline_path.write_bytes(qualification.canonical_json(second))
            changelog.write_text(
                "# Changelog\n\nFirst baseline.\n\nSecond baseline.\n",
                encoding="utf-8",
            )
            git_commit(repo, "promote profile")
            qualification.verify_baseline_promotion(
                repo, base_revision, baseline_path, manifest_path
            )

            second["profiles"]["test-linux-x86_64"]["provenance"]["promotion"][
                "previous_baseline_sha256"
            ] = "f" * 64
            baseline_path.write_bytes(qualification.canonical_json(second))
            git_commit(repo, "forge lineage")
            with self.assertRaisesRegex(
                qualification.QualificationError, "promotion lineage drift"
            ):
                qualification.verify_baseline_promotion(
                    repo, base_revision, baseline_path, manifest_path
                )

    def test_rejected_bundle_verifies_without_a_baseline_and_cli_is_status_aware(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        rejected = rejected_receipt(
            manifest_sha, "unit repetition 1 timed out"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            source_repo = root / "source"
            rejected["source"] = initialize_source_repo(source_repo)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            evidence = root / "rejected"
            qualification.write_receipt(evidence, rejected, {})
            verified = qualification.verify_receipt(
                evidence, manifest_path, root / "missing-baseline.json", None
            )
            self.assertEqual(verified["status"], "rejected")
            self.assertEqual(
                qualification.main([
                    "--verify-receipt", str(evidence),
                    "--manifest", str(manifest_path),
                    "--baseline", str(root / "missing-baseline.json"),
                    "--repo-root", str(source_repo),
                ]),
                0,
            )
            noncanonical = copy.deepcopy(rejected)
            noncanonical["artifacts"] = [{
                "path": "attacker.log", "sha256": "0" * 64, "size": 0,
            }]
            with self.assertRaisesRegex(
                qualification.QualificationError, "not canonical"
            ):
                qualification._validate_rejected_payload(
                    noncanonical, raw_manifest, None
                )

    def test_complete_rejection_binds_all_regressions_and_raw_observations(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        accepted = receipt(manifest_sha)
        performance_baseline = baseline(manifest_sha)
        profile = performance_baseline["profiles"]["test-linux-x86_64"]
        profile["workloads"]["unit"]["statistics"]["wall_ms"] = metric(7000)
        profile["workloads"]["unit"]["statistics"]["cpu_ms"] = metric(5700)
        profile["workloads"]["unit"]["statistics"]["peak_rss_kib"] = metric(700)
        release_stats = profile["workloads"]["release-candidate"]["statistics"]
        release_stats["peak_rss_kib"] = metric(200)

        unit = accepted["workloads"][0]
        for run in unit["runs"][-2:]:
            for inner in run["inner_runs"]:
                inner["metrics"] = {
                    "wall_ms": 630, "cpu_ms": 630, "peak_rss_kib": 630,
                }
                inner["environment"] = environment_evidence(630)[0]
            run["metrics"] = {
                "wall_ms": 6300, "cpu_ms": 6300, "peak_rss_kib": 630,
            }
            batch = environment_evidence(
                6300, scope="performance-batch", required=True
            )[0]
            run["environment"] = batch
            run["environment_valid"] = batch["valid"]
        unit["statistics"] = {
            metric_name: qualification.metric_statistics(
                [run["metrics"][metric_name] for run in unit["runs"]]
            )
            for metric_name in qualification.METRICS
        }
        release = accepted["workloads"][2]
        release_run = release["runs"][-1]
        release_inner = release_run["inner_runs"][0]
        release_inner["metrics"] = {
            "wall_ms": 200, "cpu_ms": 200, "peak_rss_kib": 200,
        }
        release_inner["environment"] = environment_evidence(200)[0]
        release_run["metrics"] = dict(release_inner["metrics"])
        release_batch = environment_evidence(
            200, scope="performance-batch", required=True
        )[0]
        release_run["environment"] = release_batch
        release_run["environment_valid"] = release_batch["valid"]
        release["statistics"] = {
            metric_name: qualification.metric_statistics(
                [run["metrics"][metric_name] for run in release["runs"]]
            )
            for metric_name in qualification.METRICS
        }
        raw_artifacts = artifact_bytes(accepted)
        accepted["artifacts"] = sorted(
            (
                {"path": path, "sha256": sha256(data), "size": len(data)}
                for path, data in raw_artifacts.items()
            ),
            key=lambda item: item["path"],
        )
        failures = qualification._baseline_gate_failures(
            performance_baseline, accepted["host"], accepted["toolchain"],
            accepted["inputs"], accepted["workloads"], "required",
        )
        self.assertEqual(
            [(item["workload"], item["metric"], item["statistic"])
             for item in failures],
            [
                ("unit", "cpu_ms", "p90"),
                ("unit", "cpu_ms", "max"),
                ("release-candidate", "wall_ms", "max"),
                ("release-candidate", "cpu_ms", "max"),
            ],
        )

        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            manifest_path = root / "manifest.json"
            baseline_path = root / "baseline.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            baseline_path.write_bytes(
                qualification.canonical_json(performance_baseline)
            )
            rejected = {
                "schema": qualification.REJECTED_SCHEMA,
                "status": "rejected",
                "source": accepted["source"],
                "configuration": accepted["configuration"],
                "host": accepted["host"],
                "toolchain": accepted["toolchain"],
                "inputs": accepted["inputs"],
                "baseline": {
                    "sha256": qualification.sha256_file(baseline_path),
                    "profile": "test-linux-x86_64",
                },
                "decision": {
                    "classification": "complete-gate-rejection",
                    "failures": failures,
                    "performance_regressions": failures,
                },
                "observations": {
                    "complete": True,
                    "workloads": accepted["workloads"],
                },
                "started_at": accepted["started_at"],
                "finished_at": accepted["finished_at"],
                "duration_ms": accepted["duration_ms"],
                "artifacts": accepted["artifacts"],
            }
            evidence = root / "rejected"
            qualification.write_receipt(evidence, rejected, raw_artifacts)
            verified = qualification.verify_receipt(
                evidence, manifest_path, baseline_path, None
            )
            self.assertEqual(
                verified["decision"]["performance_regressions"], failures
            )

            tampered_artifacts = dict(raw_artifacts)
            environment_path = qualification._iteration_artifact_paths(
                "unit", 1, 1
            )[4]
            environment = json.loads(
                tampered_artifacts[environment_path].decode("utf-8")
            )
            environment["decision"]["valid"] = False
            tampered_artifacts[environment_path] = qualification.canonical_json(
                environment
            )
            tampered = copy.deepcopy(rejected)
            tampered["artifacts"] = sorted(
                (
                    {
                        "path": path,
                        "sha256": sha256(data),
                        "size": len(data),
                    }
                    for path, data in tampered_artifacts.items()
                ),
                key=lambda item: item["path"],
            )
            forged = root / "forged-rejected"
            qualification.write_receipt(forged, tampered, tampered_artifacts)
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "environment decision differs from raw artifact",
            ):
                qualification.verify_receipt(
                    forged, manifest_path, baseline_path, None
                )

    def test_complete_measurement_rejection_does_not_require_a_baseline(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        measured = receipt(manifest_sha)
        unit = measured["workloads"][0]
        for run in unit["runs"]:
            for inner in run["inner_runs"]:
                inner["metrics"] = {
                    "wall_ms": 400, "cpu_ms": 400,
                    "peak_rss_kib": 400,
                }
                inner["environment"] = environment_evidence(400)[0]
            run["metrics"] = {
                "wall_ms": 4000, "cpu_ms": 4000,
                "peak_rss_kib": 400,
            }
            run["batch_valid"] = False
            batch = environment_evidence(
                4000, scope="performance-batch", required=True
            )[0]
            run["environment"] = batch
            run["environment_valid"] = batch["valid"]
        unit["statistics"] = {
            metric_name: qualification.metric_statistics(
                [run["metrics"][metric_name] for run in unit["runs"]]
            )
            for metric_name in qualification.METRICS
        }
        failures = qualification._measurement_failures(
            raw_manifest, measured["workloads"]
        )
        artifacts = artifact_bytes(measured)
        error = qualification.QualificationDecisionError(
            failures, measured["workloads"]
        )
        rejected = qualification._rejected_payload(
            measured["source"], manifest_sha, "required",
            measured["host"], measured["toolchain"], measured["inputs"],
            dt.datetime.now(dt.timezone.utc), time.monotonic_ns(), error,
            artifacts, None, None,
        )
        self.assertEqual(
            rejected["decision"]["classification"],
            "complete-measurement-rejection",
        )
        qualification._validate_rejected_payload(
            rejected, raw_manifest, None
        )
        existing_baseline = baseline(manifest_sha)
        existing_baseline["profiles"]["test-linux-x86_64"]["workloads"][
            "release-candidate"
        ]["statistics"]["cpu_ms"] = metric(80)
        rejected_with_baseline = qualification._rejected_payload(
            measured["source"], manifest_sha, "required",
            measured["host"], measured["toolchain"], measured["inputs"],
            dt.datetime.now(dt.timezone.utc), time.monotonic_ns(), error,
            artifacts, "7" * 64, "test-linux-x86_64",
        )
        self.assertEqual(
            rejected_with_baseline["decision"]["failures"], failures
        )
        qualification._validate_rejected_payload(
            rejected_with_baseline, raw_manifest, existing_baseline
        )
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            evidence = root / "rejected"
            qualification.write_receipt(evidence, rejected, artifacts)
            verified = qualification.verify_receipt(
                evidence, manifest_path, root / "missing-baseline.json", None
            )
            self.assertTrue(verified["observations"]["complete"])

    def test_rejected_evidence_is_persisted_once_and_never_overwritten(self) -> None:
        raw_manifest = manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            output = root / "rejected"
            source_repo = root / "source"
            source = initialize_source_repo(source_repo)
            accepted = receipt(qualification.digest_json(raw_manifest))
            started_at = dt.datetime.now(dt.timezone.utc)
            qualification._persist_rejection(
                output,
                source,
                raw_manifest,
                manifest_path,
                root / "missing-baseline.json",
                source_repo,
                "required",
                accepted["host"],
                accepted["toolchain"],
                {},
                started_at,
                time.monotonic_ns(),
                {},
                qualification.QualificationError("preparation failed"),
            )
            verified = qualification.verify_receipt(
                output, manifest_path, root / "missing-baseline.json", source_repo
            )
            self.assertEqual(
                verified["decision"]["failures"][0]["message"],
                "preparation failed",
            )
            with self.assertRaisesRegex(
                qualification.QualificationError, "refuses to overwrite"
            ):
                qualification._persist_rejection(
                    output,
                    source,
                    raw_manifest,
                    manifest_path,
                    root / "missing-baseline.json",
                    source_repo,
                    "required",
                    accepted["host"],
                    accepted["toolchain"],
                    {},
                    started_at,
                    time.monotonic_ns(),
                    {},
                    qualification.QualificationError("second failure"),
                )

    def test_verify_recomputes_claims_from_raw_artifacts(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        payload = receipt(manifest_sha)
        base = baseline(manifest_sha)

        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory) / "evidence"
            artifact_bytes = {
                item["path"]: json.dumps({"forged": True}).encode()
                for item in payload["artifacts"]
            }
            for item in payload["artifacts"]:
                data = artifact_bytes[item["path"]]
                item["sha256"] = sha256(data)
                item["size"] = len(data)
            baseline_path = temporary_root(directory) / "baseline.json"
            manifest_path = temporary_root(directory) / "manifest.json"
            baseline_path.write_bytes(qualification.canonical_json(base))
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            payload["baseline"]["sha256"] = qualification.sha256_file(baseline_path)
            qualification.write_receipt(root, payload, artifact_bytes)
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "raw artifact|report|artifact|GNU time|canonical",
            ):
                qualification.verify_receipt(
                    root, manifest_path, baseline_path, None
                )

    def test_bounded_process_kills_timeout_process_group_and_log_flood(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX process-group contract")
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            heartbeat = root / "heartbeat.log"
            grandchild_program = (
                "import signal,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "f=open(sys.argv[1],'ab',buffering=0); "
                "exec('while True:\\n f.write(b\"x\")\\n time.sleep(0.02)')"
            )
            child_program = (
                "import os,signal,subprocess,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"heartbeat={str(heartbeat)!r}; "
                f"child=subprocess.Popen([sys.executable,'-c',{grandchild_program!r},"
                f"{str(heartbeat)!r}]); "
                "exec('for _ in range(100):\\n"
                " if os.path.exists(heartbeat): break\\n"
                " time.sleep(0.005)'); "
                "assert os.path.exists(heartbeat); "
                "print(child.pid, flush=True); time.sleep(30)"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(qualification.QualificationError, "timed out"):
                qualification._run_bounded_process(
                    [sys.executable, "-c", child_program], os.environ.copy(),
                    1.0, stdout, stderr, [heartbeat], 1024,
                )
            self.assertLess(time.monotonic() - started, 2.5)
            child_pid = int(stdout.read_text(encoding="utf-8").strip())
            for _ in range(40):
                if not process_is_running(child_pid):
                    break
                time.sleep(0.025)
            self.assertFalse(process_is_running(child_pid))
            self.assertTrue(heartbeat.is_file())
            heartbeat_size = heartbeat.stat().st_size
            self.assertGreater(heartbeat_size, 0)
            time.sleep(0.1)
            self.assertEqual(heartbeat.stat().st_size, heartbeat_size)

            orphan_program = (
                "import subprocess,sys; "
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
                "print(child.pid, flush=True)"
            )
            with self.assertRaisesRegex(
                qualification.QualificationError, "live descendants"
            ):
                qualification._run_bounded_process(
                    [sys.executable, "-c", orphan_program],
                    os.environ.copy(), 5, stdout, stderr, [], 1024,
                )
            orphan_pid = int(stdout.read_text(encoding="utf-8").strip())
            for _ in range(40):
                if not process_is_running(orphan_pid):
                    break
                time.sleep(0.025)
            self.assertFalse(process_is_running(orphan_pid))

            with self.assertRaisesRegex(qualification.QualificationError, "size limit"):
                qualification._run_bounded_process(
                    [sys.executable, "-c", "print('x' * 10000)"],
                    os.environ.copy(), 5, stdout, stderr, [], 128,
                )

    def test_process_group_reaps_finished_leader_before_forced_signal(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX process-group contract")

        events: list[str] = []
        group_alive = True

        class FinishedLeader:
            pid = 424242
            returncode: int | None = None

            def poll(self) -> int:
                events.append("poll")
                self.returncode = -signal.SIGTERM
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                if self.returncode is None:
                    raise subprocess.TimeoutExpired(["fixture"], timeout)
                return self.returncode

            def kill(self) -> None:
                raise AssertionError("finished leader must not be killed")

        leader = FinishedLeader()

        def group_exists(_process_group: int) -> bool:
            events.append("probe")
            return group_alive

        def signal_group(_process_group: int, sig: int) -> None:
            nonlocal group_alive
            events.append(signal.Signals(sig).name)
            if sig == signal.SIGKILL:
                self.assertIsNotNone(
                    leader.returncode, "leader must be reaped before SIGKILL"
                )
                group_alive = False

        with (
            mock.patch.object(qualification, "_process_group_exists", group_exists),
            mock.patch.object(qualification.os, "killpg", signal_group),
            mock.patch.object(
                qualification.time, "monotonic", side_effect=(0.0, 1.0, 2.0)
            ),
        ):
            qualification._terminate_process_group(leader)
        self.assertIn("SIGKILL", events)
        self.assertLess(events.index("poll"), events.index("SIGKILL"))

    def test_process_group_cleanup_permission_error_is_fail_closed(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX process-group contract")

        class UnsignalableLeader:
            pid = 424243
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                if self.returncode is None:
                    raise subprocess.TimeoutExpired(["fixture"], timeout)
                return self.returncode

            def kill(self) -> None:
                self.returncode = -signal.SIGKILL

        with (
            mock.patch.object(
                qualification, "_process_group_exists", return_value=True
            ),
            mock.patch.object(
                qualification.os,
                "killpg",
                side_effect=PermissionError(1, "Operation not permitted"),
            ),
            mock.patch.object(
                qualification.time,
                "monotonic",
                side_effect=(0.0, 1.0, 2.0, 3.0),
            ),
        ):
            with self.assertRaisesRegex(
                qualification.QualificationError,
                "cleanup failed.*Operation not permitted",
            ):
                qualification._terminate_process_group(
                    UnsignalableLeader(), "qualification process timed out"
                )

    def test_process_group_must_be_gone_after_forced_signal(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX process-group contract")

        class ReapedLeader:
            pid = 424244
            returncode = -signal.SIGTERM

            def poll(self) -> int:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return self.returncode

            def kill(self) -> None:
                raise AssertionError("reaped leader must not be killed")

        with (
            mock.patch.object(
                qualification, "_process_group_exists", return_value=True
            ),
            mock.patch.object(qualification.os, "killpg"),
            mock.patch.object(
                qualification.time,
                "monotonic",
                side_effect=(0.0, 1.0, 2.0, 3.0),
            ),
        ):
            with self.assertRaisesRegex(
                qualification.QualificationError, "cleanup failed"
            ):
                qualification._terminate_process_group(
                    ReapedLeader(), "qualification process timed out"
                )

    def test_aggregate_artifact_memory_is_bounded(self) -> None:
        original = qualification.MAX_BUNDLE_BYTES
        try:
            qualification.MAX_BUNDLE_BYTES = 4
            retained = {"first": b"12"}
            qualification._add_artifacts_bounded(retained, {"second": b"34"})
            self.assertEqual(retained, {"first": b"12", "second": b"34"})
            with self.assertRaisesRegex(
                qualification.QualificationError, "aggregate size limit"
            ):
                qualification._add_artifacts_bounded(
                    retained, {"third": b"5"}
                )
        finally:
            qualification.MAX_BUNDLE_BYTES = original

    def test_checksums_exact_file_set_and_non_regular_paths_are_enforced(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        payload = receipt(manifest_sha)
        base = baseline(manifest_sha)

        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory) / "evidence"
            artifact_data = artifact_bytes(payload)
            baseline_path = temporary_root(directory) / "baseline.json"
            manifest_path = temporary_root(directory) / "manifest.json"
            baseline_path.write_bytes(qualification.canonical_json(base))
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))
            payload["baseline"]["sha256"] = qualification.sha256_file(baseline_path)
            qualification.write_receipt(root, payload, artifact_data)
            qualification.verify_receipt(root, manifest_path, baseline_path, None)

            extra = root / "unexpected.txt"
            extra.write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(qualification.QualificationError, "file set"):
                qualification.verify_receipt(root, manifest_path, baseline_path, None)
            extra.unlink()

            report = root / payload["artifacts"][0]["path"]
            outside = temporary_root(directory) / "outside"
            report.unlink()
            try:
                os.symlink(outside, report)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(qualification.QualificationError, "regular file"):
                qualification.verify_receipt(root, manifest_path, baseline_path, None)


if __name__ == "__main__":
    unittest.main()
