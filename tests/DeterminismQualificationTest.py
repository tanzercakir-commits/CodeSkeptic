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
        "workloads": [
            {
                "id": kind,
                "kind": kind,
                "input": inputs[kind],
                "analyzer_args": [],
                "wall_timeout_seconds": 1800,
                "tu_timeout_seconds": 300,
                "tu_memory_mib": 4096,
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
        "cmake_cache_sha256": "d" * 64,
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


def artifact_bytes(payload: dict) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for workload in payload["workloads"]:
        kind = workload["kind"]
        input_value = payload["inputs"][kind]
        repo_root = qualification._root_for_marker(input_value, "$REPO")
        for run in workload["runs"]:
            paths = qualification._run_artifact_paths(kind, run["repetition"])
            result[paths[0]] = qualification.canonical_json(
                analyzer_report(kind, repo_root, input_value)
            )
            result[paths[1]] = b""
            result[paths[2]] = b""
            result[paths[3]] = time_log(run["metrics"]["wall_ms"])
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
                    "memory_bytes": 8 * 1024 * 1024 * 1024,
                },
                "workloads": {
                    kind: {
                        "semantic_sha256": semantics[kind],
                        "input_identity_sha256": inputs[kind]["identity_sha256"],
                        "translation_unit_sha256": inputs[kind]["translation_unit_sha256"],
                        "translation_unit_plan_sha256": inputs[kind]["translation_unit_plan_sha256"],
                        "statistics": {
                            "wall_ms": metric(value),
                            "cpu_ms": metric(value),
                            "peak_rss_kib": metric(value),
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
        for repetition in range(1, 11):
            paths = qualification._run_artifact_paths(kind, repetition)
            data_by_path = {
                paths[0]: qualification.canonical_json(
                    analyzer_report(kind, repo_root, inputs[kind])
                ),
                paths[1]: b"",
                paths[2]: b"",
                paths[3]: time_log(value),
            }
            artifacts.extend(
                {"path": path, "sha256": sha256(data), "size": len(data)}
                for path, data in data_by_path.items()
            )
            runs.append(
                {
                    "repetition": repetition,
                    "semantic_sha256": semantic,
                    "exit_code": 0,
                    "metrics": {
                        "wall_ms": value,
                        "cpu_ms": value,
                        "peak_rss_kib": value,
                    },
                    "artifacts": paths,
                }
            )
        workloads.append(
            {
                "id": kind,
                "kind": kind,
                "semantic_sha256": semantic,
                "runs": runs,
                "statistics": {
                    "wall_ms": metric(value),
                    "cpu_ms": metric(value),
                    "peak_rss_kib": metric(value),
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
        },
        "host": {
            "class_id": "test-linux-x86_64",
            "os": "Linux",
            "architecture": "x86_64",
            "cpu_model": "test cpu",
            "logical_cpus": 2,
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

    def test_statistics_are_integer_nearest_rank_and_complete(self) -> None:
        values = [9, 1, 7, 3, 2, 10, 6, 8, 4, 5]
        self.assertEqual(
            qualification.metric_statistics(values),
            {"count": 10, "min": 1, "median": 6, "p90": 9, "max": 10},
        )

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
                    f"{metric_name}.{statistic}" in failure
                    and "10 percent" in failure
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
                qualification.QualificationError, "checksum|raw|manifest"
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
        rejected = calibration_receipt(manifest_sha)
        rejected = {
            key: value for key, value in rejected.items()
            if key not in {"workloads"}
        }
        rejected.update({
            "schema": qualification.REJECTED_SCHEMA,
            "status": "rejected",
            "configuration": {
                **rejected["configuration"],
                "performance_policy": "required",
            },
            "inputs": {},
            "failure": "unit repetition 1 timed out",
            "artifacts": [],
        })
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
            self.assertEqual(verified["failure"], "preparation failed")
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
                "raw artifact|report|four artifacts|GNU time",
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
