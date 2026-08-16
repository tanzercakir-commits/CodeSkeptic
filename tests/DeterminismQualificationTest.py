#!/usr/bin/env python3
"""Contracts for Phase 10 determinism and performance qualification."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
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


KINDS = ("unit", "real-repository", "release-candidate")
SAMPLE_BYTES = b"int sample;\n"
THESIS_MANIFEST_BYTES = b"sample.cpp CLEAN 0\n"


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
            "affinity_external_cpu_limit_basis_points": 200,
            "host_external_cpu_limit_basis_points": 50,
            "cpu_pressure_some_limit_basis_points": 200,
            "memory_pressure_full_limit_basis_points": 0,
            "io_pressure_full_limit_basis_points": 0,
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


def environment_evidence(value: int) -> tuple[dict, bytes]:
    ticks = value // 10
    before = {
        "cpu": {
            "clock_ticks_per_second": 100,
            "host_logical_cpus": 2,
            "host_busy_ticks": 1000,
            "affinity_busy_ticks": 1000,
        },
        "pressure": {
            name: {"some_total_us": 100, "full_total_us": 10}
            for name in ("cpu", "memory", "io")
        },
        "cpufreq": [
            {
                "cpu": cpu, "driver": "intel_pstate",
                "governor": "powersave", "minimum_khz": 400000,
                "maximum_khz": 4400000, "current_khz": 4000000,
            }
            for cpu in (0, 1)
        ],
        "thermal": [
            {
                "cpu": cpu, "core_count": 1, "core_total_ms": 2,
                "package_count": 3, "package_total_ms": 4,
            }
            for cpu in (0, 1)
        ],
    }
    after = copy.deepcopy(before)
    after["cpu"]["host_busy_ticks"] += ticks
    after["cpu"]["affinity_busy_ticks"] += ticks
    decision = qualification._evaluate_environment(
        before, after, value, value, [0, 1],
        2,
        qualification.ENVIRONMENT_POLICY, True,
    )
    payload = {
        "schema": "codeskeptic-determinism-environment-v1",
        "before": before,
        "after": after,
        "decision": decision,
    }
    return decision, qualification.canonical_json(payload)


def artifact_bytes(payload: dict) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
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
                "hardware": {
                    "architecture": "x86_64",
                    "cpu_model": "test cpu",
                    "logical_cpus": 2,
                    "host_logical_cpus": 2,
                    "cpu_affinity_source": "sched_getaffinity",
                    "cpu_affinity": [0, 1],
                    "cpu_uclamp_source": "proc-self-sched",
                    "cpu_uclamp_min": 1024,
                    "cpu_uclamp_max": 1024,
                    "memory_bytes": 8 * 1024 * 1024 * 1024,
                },
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
    artifacts = []
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
            runs.append(
                {
                    "repetition": repetition,
                    "semantic_sha256": semantic,
                    "exit_code": 0,
                    "metrics": run_metrics,
                    "measurement_iterations": iterations,
                    "batch_valid": True,
                    "environment_valid": True,
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
            "os": "Linux",
            "architecture": "x86_64",
            "cpu_model": "test cpu",
            "logical_cpus": 2,
            "host_logical_cpus": 2,
            "cpu_affinity_source": "sched_getaffinity",
            "cpu_affinity": [0, 1],
            "cpu_uclamp_source": "proc-self-sched",
            "cpu_uclamp_min": 1024,
            "cpu_uclamp_max": 1024,
            "memory_bytes": 8 * 1024 * 1024 * 1024,
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
    def test_batched_environment_evidence_uses_a_distinct_v5_schema(self) -> None:
        self.assertEqual(
            qualification.MANIFEST_SCHEMA,
            "codeskeptic-determinism-workloads-v2",
        )
        self.assertEqual(
            qualification.BASELINE_SCHEMA,
            "codeskeptic-determinism-baseline-v5",
        )
        self.assertEqual(
            qualification.RECEIPT_SCHEMA,
            "codeskeptic-determinism-qualification-v5",
        )
        self.assertEqual(
            qualification.REJECTED_SCHEMA,
            "codeskeptic-determinism-rejected-v5",
        )
        self.assertEqual(
            qualification.CALIBRATION_SCHEMA,
            "codeskeptic-determinism-calibration-v5",
        )

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
        changed["environment_policy"]["host_external_cpu_limit_basis_points"] = 100
        with self.assertRaisesRegex(qualification.QualificationError, "environment policy"):
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

        before = {
            "cpu": {
                "clock_ticks_per_second": 100,
                "host_logical_cpus": 4,
                "host_busy_ticks": 100,
                "affinity_busy_ticks": 40,
            },
            "pressure": {
                "cpu": {"some_total_us": 10, "full_total_us": 0},
                "memory": {"some_total_us": 10, "full_total_us": 0},
                "io": {"some_total_us": 10, "full_total_us": 0},
            },
            "cpufreq": [{
                "cpu": 0, "driver": "intel_pstate", "governor": "powersave",
                "minimum_khz": 400000, "maximum_khz": 4400000,
                "current_khz": 4000000,
            }],
            "thermal": [{
                "cpu": 0, "core_count": 1, "core_total_ms": 2,
                "package_count": 3, "package_total_ms": 4,
            }],
        }
        after = copy.deepcopy(before)
        after["cpu"]["host_busy_ticks"] += 101
        after["cpu"]["affinity_busy_ticks"] += 100
        after["thermal"][0]["package_total_ms"] += 1
        decision = qualification._evaluate_environment(
            before, after, child_cpu_ms=900, wall_ms=1000,
            affinity=[0], logical_cpus=4,
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
        count_only_after["thermal"][0]["core_count"] += 1
        count_only = qualification._evaluate_environment(
            before, count_only_after, child_cpu_ms=900, wall_ms=1000,
            affinity=[0], logical_cpus=4,
            policy=qualification.ENVIRONMENT_POLICY, required=True,
        )
        self.assertFalse(count_only["valid"])
        self.assertEqual(count_only["metrics"]["thermal_throttle_count"], 1)
        unavailable = copy.deepcopy(before)
        unavailable["cpufreq"] = []
        unavailable["thermal"] = []
        required_unavailable = qualification._evaluate_environment(
            unavailable, copy.deepcopy(unavailable), child_cpu_ms=0,
            wall_ms=1000, affinity=[0], logical_cpus=4,
            policy=qualification.ENVIRONMENT_POLICY, required=True,
        )
        self.assertFalse(required_unavailable["valid"])
        record_only_unavailable = qualification._evaluate_environment(
            unavailable, copy.deepcopy(unavailable), child_cpu_ms=0,
            wall_ms=1000, affinity=[0], logical_cpus=4,
            policy=qualification.ENVIRONMENT_POLICY, required=False,
        )
        self.assertTrue(record_only_unavailable["valid"])
        with self.assertRaisesRegex(
            qualification.QualificationError, "logical CPU identity"
        ):
            qualification._evaluate_environment(
                before, after, child_cpu_ms=900, wall_ms=1000,
                affinity=[0], logical_cpus=8,
                policy=qualification.ENVIRONMENT_POLICY, required=True,
            )
        malformed_frequency = copy.deepcopy(after)
        malformed_frequency["cpufreq"][0]["current_khz"] = []
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU frequency"
        ):
            qualification._evaluate_environment(
                before, malformed_frequency, child_cpu_ms=900, wall_ms=1000,
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
            qualification._evaluate_environment(
                duplicate_frequency_before, duplicate_frequency_after,
                child_cpu_ms=900, wall_ms=1000, affinity=[0], logical_cpus=4,
                policy=qualification.ENVIRONMENT_POLICY, required=True,
            )

    def test_environment_capture_is_exact_and_rejects_authority_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc_root = root / "proc"
            cpu_root = root / "cpu"
            (proc_root / "pressure").mkdir(parents=True)
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
            qualification.os, "sched_getaffinity", return_value={0, 1}
        ), mock.patch.object(
            qualification, "_capture_environment",
            side_effect=[
                copy.deepcopy(environment_payload[side])
                for _iteration in range(10)
                for side in ("before", "after")
            ],
        ) as capture, mock.patch.object(
            qualification, "_run_bounded_process", side_effect=run_process
        ) as bounded:
            run, artifacts = qualification.run_once(
                Path("/fixture/codeskeptic"), Path("/usr/bin/time"),
                prepared, 1, ROOT, Path(directory), "required",
                {
                    "cpu_affinity": [0, 1],
                    "logical_cpus": 2,
                    "host_logical_cpus": 8,
                },
            )
        self.assertEqual(bounded.call_count, 10)
        self.assertEqual(capture.call_count, 20)
        self.assertEqual(run["measurement_iterations"], 10)
        self.assertEqual(len(run["inner_runs"]), 10)
        self.assertEqual(run["metrics"]["cpu_ms"], 5000)
        self.assertTrue(run["batch_valid"])
        self.assertTrue(run["environment_valid"])
        self.assertEqual(len(artifacts), 50)

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
        current["host"]["host_logical_cpus"] = 3
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
                qualification.os, "sched_getaffinity", return_value={7, 3},
                create=True,
            ),
            mock.patch.object(
                qualification, "_cpu_uclamp_identity",
                return_value=("proc-self-sched", 1024, 1024),
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
                qualification.host_identity("test-linux-x86_64")

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
        current["host"]["cpu_affinity_source"] = "unavailable"
        current["host"]["cpu_affinity"] = []
        with self.assertRaisesRegex(
            qualification.QualificationError, "CPU affinity is not measurable"
        ):
            qualification.validate_receipt_payload(
                current, raw_manifest, baseline(manifest_sha)
            )

        current = receipt(manifest_sha)
        current["configuration"]["performance_policy"] = "record-only"
        current["host"]["cpu_affinity_source"] = "unavailable"
        current["host"]["cpu_affinity"] = []
        current["baseline"]["profile"] = None
        current["baseline"]["performance_gate"] = "not-gated"
        qualification.validate_receipt_payload(
            current, raw_manifest, baseline(manifest_sha)
        )

        malformed_baseline = baseline(manifest_sha)
        malformed_baseline["profiles"]["test-linux-x86_64"]["hardware"].update({
            "cpu_affinity_source": "unavailable",
            "cpu_affinity": [],
        })
        with self.assertRaisesRegex(
            qualification.QualificationError, "not measurable"
        ):
            qualification.validate_baseline(malformed_baseline, manifest_sha)

        malformed_calibration = calibration_receipt(manifest_sha)
        malformed_calibration["host"].update({
            "cpu_affinity_source": "unavailable",
            "cpu_affinity": [],
        })
        with self.assertRaisesRegex(
            qualification.QualificationError, "not measurable"
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
        })
        qualification._validate_rejected_payload(rejected, raw_manifest)

    def test_uclamp_identity_and_required_performance_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sched = Path(directory) / "sched"
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
                qualification._cpu_uclamp_identity(Path(directory) / "missing"),
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
            "cpu_uclamp_source": "proc-self-sched",
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
                "c_compiler", "cxx_compiler",
            },
        )
        for tool in provenance["toolchain"].values():
            self.assertRegex(tool["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(tool["version"])

    def test_build_cache_identity_is_workspace_independent_and_config_sensitive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
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
            workspace = Path(directory) / "release"
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

    def test_pinned_baseline_is_bound_to_raw_calibration_and_promotion(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        with tempfile.TemporaryDirectory() as directory:
            authority = Path(directory) / "authority"
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

    def test_manifest_and_git_tree_reject_input_identity_drift(self) -> None:
        raw_manifest = manifest()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
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
            repo = Path(directory) / "repo"
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
            repo = Path(directory) / "repo"
            source = initialize_source_repo(repo)
            source_revision = source["revision"]
            payload = calibration_receipt(
                manifest_sha, repo_root=repo,
                source_revision=source_revision, source=source,
            )
            evidence = Path(directory) / "calibration"
            qualification.write_receipt(
                evidence, payload, artifact_bytes(payload)
            )
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_bytes(qualification.canonical_json(raw_manifest))

            ignored = (
                repo / "docs" / "evidence" / "phase10" / "stress" /
                "later" / "receipt.json"
            )
            ignored.parent.mkdir(parents=True)
            ignored.write_text("later authority\n", encoding="utf-8")
            git_commit(repo, "retain ignored authority")

            qualification.verify_receipt(
                evidence, manifest_path, Path(directory) / "unused.json", repo
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
                    Path(directory) / "unused.json", repo,
                )

    def test_baseline_update_requires_exact_predecessor_and_authority_only_diff(self) -> None:
        raw_manifest = manifest()
        manifest_sha = qualification.digest_json(raw_manifest)
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
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
            root = Path(directory)
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
            root = Path(directory)
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
            root = Path(directory)
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
            root = Path(directory)
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
            root = Path(directory) / "evidence"
            artifact_bytes = {
                item["path"]: json.dumps({"forged": True}).encode()
                for item in payload["artifacts"]
            }
            for item in payload["artifacts"]:
                data = artifact_bytes[item["path"]]
                item["sha256"] = sha256(data)
                item["size"] = len(data)
            baseline_path = Path(directory) / "baseline.json"
            manifest_path = Path(directory) / "manifest.json"
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
            root = Path(directory)
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
            root = Path(directory) / "evidence"
            artifact_data = artifact_bytes(payload)
            baseline_path = Path(directory) / "baseline.json"
            manifest_path = Path(directory) / "manifest.json"
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
            outside = Path(directory) / "outside"
            report.unlink()
            try:
                os.symlink(outside, report)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(qualification.QualificationError, "regular file"):
                qualification.verify_receipt(root, manifest_path, baseline_path, None)


if __name__ == "__main__":
    unittest.main()
