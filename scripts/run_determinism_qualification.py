#!/usr/bin/env python3
"""Run and verify the Phase 10 determinism/performance qualification."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import signal
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on native Windows
    resource = None


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SCHEMA = "codeskeptic-determinism-workloads-v3"
BASELINE_SCHEMA = "codeskeptic-determinism-baseline-v7"
RECEIPT_SCHEMA = "codeskeptic-determinism-qualification-v7"
REJECTED_SCHEMA = "codeskeptic-determinism-rejected-v7"
CALIBRATION_SCHEMA = "codeskeptic-determinism-calibration-v7"
ENVIRONMENT_SCHEMA = "codeskeptic-determinism-environment-v3"
CMAKE_CACHE_IDENTITY_SCHEMA = "codeskeptic-cmake-cache-v2"
KINDS = ("unit", "real-repository", "release-candidate")
METRICS = ("wall_ms", "cpu_ms", "peak_rss_kib")
TOOLCHAIN_NAMES = (
    "analyzer", "clang", "gnu_time", "cmake", "ninja",
    "c_compiler", "cxx_compiler", "python",
)
HARDWARE_FIELDS = (
    "architecture", "cpu_model", "logical_cpus", "host_logical_cpus",
    "cpu_affinity_source", "cpu_affinity", "cpu_uclamp_source",
    "cpu_uclamp_min", "cpu_uclamp_max", "cpu_uclamp_ancestor_max",
    "system_uclamp_min_limit", "system_uclamp_max_limit",
    "controller_cpu_affinity",
    "measurement_environment", "measurement_cgroup_populated",
    "measurement_cgroup_frozen", "memory_bytes",
)
AFFINITY_SOURCE_SCHED = "sched_getaffinity"
AFFINITY_SOURCE_CGROUP = "cgroup-v2-exclusive"
AFFINITY_SOURCE_UNAVAILABLE = "unavailable"
UCLAMP_SOURCE_PROC = "proc-self-sched"
UCLAMP_SOURCE_CGROUP = "cgroup-v2"
UCLAMP_SOURCE_UNAVAILABLE = "unavailable"
MEASUREMENT_ENVIRONMENT_EXCLUSIVE = "exclusive-cgroup-v2"
MEASUREMENT_ENVIRONMENT_UNAVAILABLE = "unavailable"
SHA256 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"csf1-[0-9a-f]{16}")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}")
MAX_JSON_BYTES = 64 << 20
MAX_LOG_BYTES = 64 << 20
MAX_BUNDLE_BYTES = 512 << 20
ENVIRONMENT_POLICY = {
    "idle_seconds": 30,
    "idle_max_overshoot_ms": 2000,
    "idle_host_external_cpu_limit_basis_points": 50,
    "idle_affinity_external_cpu_limit_basis_points": 200,
    "idle_cpu_pressure_some_limit_basis_points": 200,
    "idle_memory_pressure_full_limit_basis_points": 0,
    "idle_io_pressure_full_limit_basis_points": 0,
    "runtime_affinity_external_cpu_limit_basis_points": 200,
    "batch_max_overhead_ms": 60000,
    "thermal_throttle_limit_ms": 0,
}
SOURCE_FILE_RELATIVES = (
    "CMakeLists.txt", ".gitattributes", "Dockerfile", "action.yml",
)
SOURCE_DIRECTORY_RELATIVES = (
    ".github/workflows", "src", "fuzz", "scripts", "tests", "docs",
    "profiles",
)
SOURCE_ROOTS = tuple(
    ROOT / relative
    for relative in (*SOURCE_FILE_RELATIVES, *SOURCE_DIRECTORY_RELATIVES)
)
IGNORED_SOURCE_PREFIXES = (
    "docs/evidence/",
    "docs/devlog/changelog.md",
    # The pinned performance baseline is a qualification output and is bound
    # separately by receipt.baseline.sha256. Excluding it avoids a source/hash
    # cycle while keeping every executable runner and workload byte in scope.
    "scripts/determinism_baseline.json",
)
FORBIDDEN_ANALYZER_OPTIONS = (
    "--json", "--sarif", "--html", "--build-path", "--checkpoint-dir",
    "--tu-timeout-seconds", "--tu-memory-mib", "--serve", "--worker",
    "--files", "--source",
)
EVIDENCE_FIELDS = {
    "no_inputs", "no_rules", "compile_database_failed", "tool_failed",
    "summary_load_failed", "summary_stale", "summary_save_failed",
    "baseline_load_failed", "baseline_write_failed", "baseline_recorded",
    "report_write_failed",
}


class QualificationError(RuntimeError):
    """The qualification cannot produce or accept authoritative evidence."""


FAILURE_FIELDS = {
    "type", "message", "workload", "repetition", "iteration", "metric",
    "statistic", "current", "baseline", "limit_percent",
}


def _failure_record(
    failure_type: str, message: str, *, workload: str | None = None,
    repetition: int | None = None, iteration: int | None = None,
    metric: str | None = None, statistic: str | None = None,
    current: int | None = None, baseline: int | None = None,
    limit_percent: int | None = None,
) -> dict[str, Any]:
    return {
        "type": failure_type,
        "message": message,
        "workload": workload,
        "repetition": repetition,
        "iteration": iteration,
        "metric": metric,
        "statistic": statistic,
        "current": current,
        "baseline": baseline,
        "limit_percent": limit_percent,
    }


def _validate_failure_record(value: Any, label: str) -> dict[str, Any]:
    record = _exact_dict(value, FAILURE_FIELDS, label)
    if (not isinstance(record["type"], str) or
            IDENTIFIER.fullmatch(record["type"]) is None or
            not isinstance(record["message"], str) or
            not record["message"] or "\x00" in record["message"] or
            len(record["message"].encode("utf-8")) > 8192):
        raise QualificationError(f"{label} is malformed")
    if record["workload"] is not None and record["workload"] not in KINDS:
        raise QualificationError(f"{label} workload is malformed")
    for field in ("repetition", "iteration"):
        if record[field] is not None:
            _require_int(record[field], f"{label} {field}", 1, 100)
    for field in ("current", "baseline", "limit_percent"):
        if record[field] is not None:
            _require_int(record[field], f"{label} {field}", 0, 1 << 62)
    for field in ("metric", "statistic"):
        if record[field] is not None and (
                not isinstance(record[field], str) or
                IDENTIFIER.fullmatch(record[field]) is None):
            raise QualificationError(f"{label} {field} is malformed")
    return record


class QualificationDecisionError(QualificationError):
    """A complete measurement was rejected by one or more exact gates."""

    def __init__(
        self, failures: list[dict[str, Any]], workloads: list[dict[str, Any]],
    ) -> None:
        if not failures:
            raise ValueError("qualification decision requires failures")
        super().__init__(failures[0]["message"])
        self.failures = failures
        self.workloads = workloads


class QualificationPreflightError(QualificationError):
    """The complete idle preflight rejected the measurement environment."""

    def __init__(self, violations: list[str]) -> None:
        if not violations:
            raise ValueError("qualification preflight requires violations")
        message = "idle preflight rejected the measurement environment: " + "; ".join(
            violations
        )
        super().__init__(message)
        self.violations = list(violations)


class QualificationBatchEnvironmentError(QualificationError):
    """A batch environment could not be evaluated from retained raw inputs."""

    def __init__(self, message: str, workload: str, repetition: int) -> None:
        if workload not in KINDS:
            raise ValueError("batch environment error workload is invalid")
        if isinstance(repetition, bool) or not 1 <= repetition <= 10:
            raise ValueError("batch environment error repetition is invalid")
        super().__init__(message)
        self.workload = workload
        self.repetition = repetition


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _exact_dict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise QualificationError(f"{label} fields are malformed")
    return value


def _require_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise QualificationError(f"{label} is outside the admitted range")
    return value


def _validate_os_identity(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not value.strip() or
            value != value.strip() or "\x00" in value or "\n" in value or
            len(value.encode("utf-8")) > 4096):
        raise QualificationError(f"{label} OS identity is malformed")
    return value


def _validate_cpu_affinity(
    value: Any, logical_cpus: int, source: Any, label: str,
) -> list[int]:
    if (not isinstance(source, str) or
            source not in {
                AFFINITY_SOURCE_SCHED, AFFINITY_SOURCE_CGROUP,
                AFFINITY_SOURCE_UNAVAILABLE,
            }):
        raise QualificationError(f"{label} source is malformed")
    if source == AFFINITY_SOURCE_UNAVAILABLE:
        if value != []:
            raise QualificationError(f"{label} is malformed")
        return value
    if not isinstance(value, list) or not value or len(value) != logical_cpus:
        raise QualificationError(f"{label} is malformed")
    for cpu in value:
        _require_int(cpu, label, 0, 65535)
    if value != sorted(set(value)):
        raise QualificationError(f"{label} is malformed")
    return value


def _validate_cpu_topology(value: dict[str, Any], label: str) -> None:
    source = value["cpu_affinity_source"]
    effective = _require_int(
        value["logical_cpus"], f"{label} effective logical CPU count",
        1, 65536,
    )
    host_total = _require_int(
        value["host_logical_cpus"], f"{label} host logical CPU count",
        1, 65536,
    )
    affinity = _validate_cpu_affinity(
        value["cpu_affinity"], effective, source,
        f"{label} CPU affinity",
    )
    if effective > host_total or (
            affinity and affinity[-1] >= host_total):
        raise QualificationError(f"{label} CPU topology is malformed")
    controller = value.get("controller_cpu_affinity")
    if not isinstance(controller, list):
        raise QualificationError(f"{label} controller CPU affinity is malformed")
    for cpu in controller:
        _require_int(cpu, f"{label} controller CPU affinity", 0, 65535)
    if (controller != sorted(set(controller)) or
            (controller and controller[-1] >= host_total)):
        raise QualificationError(f"{label} controller CPU affinity is malformed")
    mode = value.get("measurement_environment")
    if mode not in {
            MEASUREMENT_ENVIRONMENT_EXCLUSIVE,
            MEASUREMENT_ENVIRONMENT_UNAVAILABLE}:
        raise QualificationError(f"{label} measurement environment is malformed")
    if mode == MEASUREMENT_ENVIRONMENT_EXCLUSIVE:
        populated = _require_int(
            value.get("measurement_cgroup_populated"),
            f"{label} measurement cgroup populated", 0, 1,
        )
        frozen = _require_int(
            value.get("measurement_cgroup_frozen"),
            f"{label} measurement cgroup frozen", 0, 1,
        )
        if (not controller or source != AFFINITY_SOURCE_CGROUP or
                value.get("cpu_uclamp_source") != UCLAMP_SOURCE_CGROUP or
                set(controller) & set(affinity) or populated != 0 or
                frozen != 0):
            raise QualificationError(
                f"{label} measurement/controller CPU boundary is malformed"
            )
    elif (source == AFFINITY_SOURCE_CGROUP or
          value.get("cpu_uclamp_source") == UCLAMP_SOURCE_CGROUP or
          value.get("measurement_cgroup_populated") is not None or
          value.get("measurement_cgroup_frozen") is not None):
        raise QualificationError(
            f"{label} measurement/controller CPU boundary is malformed"
        )
    elif source == AFFINITY_SOURCE_SCHED and controller != affinity:
        raise QualificationError(
            f"{label} controller CPU affinity is malformed"
        )
    elif source == AFFINITY_SOURCE_UNAVAILABLE and controller:
        raise QualificationError(
            f"{label} controller CPU affinity is malformed"
        )


def _validate_cpu_uclamp(
    source: Any, minimum: Any, maximum: Any, label: str,
) -> None:
    if (not isinstance(source, str) or
            source not in {
                UCLAMP_SOURCE_PROC, UCLAMP_SOURCE_CGROUP,
                UCLAMP_SOURCE_UNAVAILABLE,
            }):
        raise QualificationError(f"{label} source is malformed")
    if source == UCLAMP_SOURCE_UNAVAILABLE:
        if minimum is not None or maximum is not None:
            raise QualificationError(f"{label} is malformed")
        return
    _require_int(minimum, f"{label} minimum", 0, 1024)
    _require_int(maximum, f"{label} maximum", 0, 1024)
    if minimum > maximum:
        raise QualificationError(f"{label} is malformed")


def _validate_cpu_uclamp_ancestor_max(
    source: Any, values: Any, label: str,
) -> None:
    if not isinstance(values, list):
        raise QualificationError(f"{label} is malformed")
    for value in values:
        _require_int(value, label, 0, 1024)
    if source == UCLAMP_SOURCE_CGROUP:
        if any(value != 1024 for value in values):
            raise QualificationError(f"{label} is not pinned")
    elif values:
        raise QualificationError(f"{label} is malformed")


def _validate_system_uclamp_limits(
    minimum: Any, maximum: Any, label: str, required: bool,
) -> None:
    if minimum is None or maximum is None:
        if minimum is not None or maximum is not None or required:
            raise QualificationError(f"{label} is unavailable")
        return
    minimum_value = _require_int(minimum, f"{label} minimum", 0, 1024)
    maximum_value = _require_int(maximum, f"{label} maximum", 0, 1024)
    if minimum_value > maximum_value:
        raise QualificationError(f"{label} is malformed")
    if required and (minimum_value != 1024 or maximum_value != 1024):
        raise QualificationError(f"{label} is not pinned")


def _require_stable_cpu_controls(hardware: dict[str, Any], label: str) -> None:
    if (hardware["measurement_environment"] !=
            MEASUREMENT_ENVIRONMENT_EXCLUSIVE or
            hardware["cpu_affinity_source"] != AFFINITY_SOURCE_CGROUP):
        raise QualificationError(
            f"{label} measurement cgroup is not exclusive and isolated"
        )
    if (hardware["cpu_uclamp_source"] != UCLAMP_SOURCE_CGROUP or
            hardware["cpu_uclamp_min"] != 1024 or
            hardware["cpu_uclamp_max"] != 1024 or
            any(value != 1024 for value in
                hardware["cpu_uclamp_ancestor_max"])):
        raise QualificationError(
            f"{label} CPU utilization clamp is not stable"
        )
    _validate_system_uclamp_limits(
        hardware["system_uclamp_min_limit"],
        hardware["system_uclamp_max_limit"],
        f"{label} system CPU utilization clamp", True,
    )


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise QualificationError(f"{label} is not a SHA-256 digest")
    return value


def _validate_toolchain(value: Any, label: str) -> dict[str, Any]:
    toolchain = _exact_dict(value, set(TOOLCHAIN_NAMES), label)
    for name in TOOLCHAIN_NAMES:
        tool = _exact_dict(toolchain[name], {"sha256", "version"}, f"{label} {name}")
        _require_sha(tool["sha256"], f"{label} {name}")
        if (not isinstance(tool["version"], str) or not tool["version"] or
                "\x00" in tool["version"] or len(tool["version"].encode("utf-8")) > 65536):
            raise QualificationError(f"{label} {name} version is malformed")
    return toolchain


def _relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise QualificationError(f"{label} is not a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or ".." in path.parts or "." in path.parts:
        raise QualificationError(f"{label} is not a canonical relative path")
    return value


def _regular_kind(path: Path) -> str:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except OSError as error:
        raise QualificationError(f"cannot inspect evidence path {path}: {error}") from error
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    return "non-regular"


def _read_regular(path: Path, maximum: int) -> bytes:
    if _regular_kind(path) != "regular":
        raise QualificationError(f"evidence path is not a regular file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > maximum:
                    raise QualificationError(f"evidence file exceeds size limit: {path}")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise QualificationError(f"cannot read evidence file {path}: {error}") from error


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise QualificationError(f"cannot create evidence file {path}: {error}") from error


def _load_json(path: Path, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    raw = _read_regular(path, maximum)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"malformed JSON: {path}: {error}") from error
    if not isinstance(value, dict):
        raise QualificationError(f"JSON root is not an object: {path}")
    if raw != canonical_json(value):
        raise QualificationError(f"JSON is not canonical: {path}")
    return value


def validate_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    _exact_dict(raw, {
        "schema", "repetitions", "performance_regression_limit_percent",
        "environment_policy", "workloads"
    }, "determinism manifest")
    if raw["schema"] != MANIFEST_SCHEMA:
        raise QualificationError("unsupported determinism manifest schema")
    _require_int(raw["repetitions"], "determinism repetitions", 10, 10)
    _require_int(
        raw["performance_regression_limit_percent"],
        "performance regression limit", 10, 10,
    )
    environment_policy = _exact_dict(
        raw["environment_policy"], set(ENVIRONMENT_POLICY),
        "determinism environment policy",
    )
    for field, value in environment_policy.items():
        _require_int(value, f"determinism environment policy {field}", 0, 1 << 31)
    if environment_policy["idle_seconds"] == 0:
        raise QualificationError("determinism idle duration is malformed")
    if environment_policy != ENVIRONMENT_POLICY:
        raise QualificationError("determinism environment policy is not pinned")
    workloads = raw["workloads"]
    if not isinstance(workloads, list) or len(workloads) != 3:
        raise QualificationError("workload kinds must contain exactly three entries")
    if [item.get("kind") if isinstance(item, dict) else None for item in workloads] != list(KINDS):
        raise QualificationError("workload kinds must be unit, real-repository, release-candidate")
    seen: set[str] = set()
    for item in workloads:
        _exact_dict(item, {
            "id", "kind", "input", "analyzer_args", "wall_timeout_seconds",
            "tu_timeout_seconds", "tu_memory_mib", "measurement_iterations",
            "minimum_batch_cpu_ms",
        }, "workload")
        identifier = item["id"]
        if not isinstance(identifier, str) or IDENTIFIER.fullmatch(identifier) is None or identifier in seen:
            raise QualificationError("workload id is invalid or duplicated")
        seen.add(identifier)
        _require_int(item["wall_timeout_seconds"], f"{identifier} wall timeout", 60, 21600)
        _require_int(item["tu_timeout_seconds"], f"{identifier} TU timeout", 1, 86400)
        _require_int(item["tu_memory_mib"], f"{identifier} TU memory", 64, 131072)
        _require_int(
            item["measurement_iterations"],
            f"{identifier} measurement iterations", 1, 100,
        )
        _require_int(
            item["minimum_batch_cpu_ms"],
            f"{identifier} minimum batch CPU", 0, 1 << 31,
        )
        expected_batch = (10, 5000) if item["kind"] == "unit" else (1, 0)
        if (item["measurement_iterations"], item["minimum_batch_cpu_ms"]) != expected_batch:
            raise QualificationError(
                f"{identifier} measurement batch policy is not pinned"
            )
        arguments = item["analyzer_args"]
        if (not isinstance(arguments, list) or
                any(not isinstance(token, str) or not token or "\x00" in token for token in arguments)):
            raise QualificationError(f"{identifier} analyzer_args are malformed")
        if arguments:
            admitted = (
                item["kind"] == "release-candidate" and
                arguments == [
                    "--report-paths",
                    "{release_source}/src,{release_source}/ggml/src",
                ]
            )
            if not admitted:
                raise QualificationError(
                    f"{identifier} analyzer_args override runner input authority"
                )
        source = item["input"]
        if item["kind"] == "unit":
            _exact_dict(source, {"mode", "manifest"}, "unit input")
            if source["mode"] != "thesis-corpus":
                raise QualificationError("unit input mode must be thesis-corpus")
            _relative(source["manifest"], "unit manifest")
        elif item["kind"] == "real-repository":
            _exact_dict(source, {"mode", "path", "policy"}, "repository input")
            if source["mode"] != "repository" or source["policy"] != "no-absolute-paths":
                raise QualificationError("real-repository input policy is not pinned")
            _relative(source["path"], "repository path")
        else:
            _exact_dict(source, {
                "mode", "project", "realworld_manifest", "translation_units"
            }, "release-candidate input")
            if source["mode"] != "release-candidate" or source["project"] != "llama-cpp":
                raise QualificationError("release-candidate must bind llama-cpp")
            _relative(source["realworld_manifest"], "real-world manifest")
            units = source["translation_units"]
            if (not isinstance(units, list) or not units or units != sorted(set(units)) or
                    any(_relative(unit, "release-candidate TU") != unit for unit in units)):
                raise QualificationError("release-candidate translation units are malformed")
    return raw


def load_manifest(path: Path) -> dict[str, Any]:
    return validate_manifest(_load_json(path))


def _parse_proc_stat(
    raw: bytes, affinity: list[int], clock_ticks_per_second: int,
) -> dict[str, int]:
    if (not raw or len(raw) > 1024 * 1024 or
            isinstance(clock_ticks_per_second, bool) or
            not isinstance(clock_ticks_per_second, int) or
            clock_ticks_per_second <= 0):
        raise QualificationError("CPU accounting evidence is malformed")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise QualificationError("CPU accounting evidence is malformed") from error
    wanted = {"cpu", *(f"cpu{cpu}" for cpu in affinity)}
    rows: dict[str, list[int]] = {}
    logical_labels: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        label = fields[0]
        if re.fullmatch(r"cpu[0-9]+", label):
            if label in logical_labels:
                raise QualificationError("CPU accounting evidence is malformed")
            logical_labels.add(label)
        if label not in wanted:
            continue
        if label in rows or len(fields) != 11 or any(
                re.fullmatch(r"[0-9]{1,20}", field) is None
                for field in fields[1:]):
            raise QualificationError("CPU accounting evidence is malformed")
        values = [int(field) for field in fields[1:]]
        if values[0] < values[8] or values[1] < values[9]:
            raise QualificationError("CPU accounting evidence is malformed")
        rows[label] = values
    if set(rows) != wanted:
        raise QualificationError("CPU accounting evidence is incomplete")

    def busy(values: list[int]) -> int:
        user, nice, system, _idle, _iowait, irq, softirq, steal, guest, guest_nice = values
        return user - guest + nice - guest_nice + system + irq + softirq + steal

    return {
        "clock_ticks_per_second": clock_ticks_per_second,
        "host_logical_cpus": len(logical_labels),
        "host_busy_ticks": busy(rows["cpu"]),
        "affinity_busy_ticks": sum(
            busy(rows[f"cpu{cpu}"]) for cpu in affinity
        ),
    }


def _parse_pressure(raw: bytes, label: str) -> dict[str, int]:
    if not raw or len(raw) > 64 * 1024:
        raise QualificationError(f"{label} pressure evidence is malformed")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise QualificationError(
            f"{label} pressure evidence is malformed"
        ) from error
    values: dict[str, int] = {}
    pattern = re.compile(
        r"^(some|full) avg10=[0-9]+\.[0-9]{2} "
        r"avg60=[0-9]+\.[0-9]{2} avg300=[0-9]+\.[0-9]{2} "
        r"total=([0-9]{1,20})$"
    )
    for line in text.splitlines():
        match = pattern.fullmatch(line)
        if match is None or match.group(1) in values:
            raise QualificationError(f"{label} pressure evidence is malformed")
        values[match.group(1)] = int(match.group(2))
    if set(values) != {"some", "full"}:
        raise QualificationError(f"{label} pressure evidence is incomplete")
    return {
        "some_total_us": values["some"],
        "full_total_us": values["full"],
    }


def _basis_points(value: int, capacity: int) -> int:
    if value < 0 or capacity <= 0:
        raise QualificationError("environment accounting is malformed")
    return (value * 10_000 + capacity - 1) // capacity


def _cgroup_delta(
    before: dict[str, Any], after: dict[str, Any], field: str,
) -> int:
    left = _require_int(
        before.get(field), f"measurement cgroup {field} before", 0, 1 << 62
    )
    right = _require_int(
        after.get(field), f"measurement cgroup {field} after", 0, 1 << 62
    )
    if right < left:
        raise QualificationError("measurement cgroup counter reset")
    return right - left


def _validate_v6_environment_inputs(
    before: dict[str, Any], after: dict[str, Any], wall_ms: int,
    affinity: list[int], logical_cpus: int,
) -> None:
    _require_int(wall_ms, "environment wall time", 1, 1 << 62)
    _require_int(logical_cpus, "environment logical CPU count", 1, 65536)
    if (not isinstance(affinity, list) or not affinity or
            len(affinity) > logical_cpus):
        raise QualificationError("environment affinity is malformed")
    for cpu in affinity:
        _require_int(cpu, "environment affinity", 0, 65535)
    if affinity != sorted(set(affinity)):
        raise QualificationError("environment affinity is malformed")
    fields = {
        "cpu", "global_pressure", "measurement_cgroup", "cpufreq",
        "thermal", "system_uclamp",
    }
    group_fields = {
        "mode", "cpu_usage_us", "nr_throttled", "throttled_us",
        "memory_oom", "memory_oom_kill", "memory_oom_group_kill",
        "pressure", "controller_cpu_affinity", "effective_cpu_affinity",
        "exclusive_cpu_affinity", "partition", "uclamp_min", "uclamp_max",
        "ancestor_uclamp_max", "populated", "frozen",
    }
    for snapshot, side in ((before, "before"), (after, "after")):
        exact = _exact_dict(snapshot, fields, f"environment {side}")
        group = _exact_dict(
            exact["measurement_cgroup"], group_fields,
            f"measurement cgroup {side}",
        )
        system_uclamp = _exact_dict(
            exact["system_uclamp"], {"minimum_limit", "maximum_limit"},
            f"system uclamp {side}",
        )
        _validate_system_uclamp_limits(
            system_uclamp["minimum_limit"], system_uclamp["maximum_limit"],
            f"system uclamp {side}", False,
        )
        controller = group["controller_cpu_affinity"]
        if not isinstance(controller, list):
            raise QualificationError(
                "measurement controller affinity is malformed"
            )
        for cpu in controller:
            _require_int(cpu, "measurement controller affinity", 0, 65535)
        if controller != sorted(set(controller)):
            raise QualificationError(
                "measurement controller affinity is malformed"
            )
        for field in (
                "effective_cpu_affinity", "exclusive_cpu_affinity"):
            value = group[field]
            if not isinstance(value, list):
                raise QualificationError(
                    "measurement cgroup isolation identity is malformed"
                )
            for cpu in value:
                _require_int(
                    cpu, "measurement cgroup CPU identity", 0, 65535
                )
            if value != sorted(set(value)):
                raise QualificationError(
                    "measurement cgroup isolation identity is malformed"
                )
        ancestor_max = group["ancestor_uclamp_max"]
        if not isinstance(ancestor_max, list):
            raise QualificationError(
                "measurement cgroup isolation identity is malformed"
            )
        for value in ancestor_max:
            _require_int(
                value, "measurement cgroup ancestor uclamp max", 0, 1024
            )
        if group["mode"] == MEASUREMENT_ENVIRONMENT_UNAVAILABLE:
            if (any(group[field] is not None for field in group_fields - {
                    "mode", "pressure", "controller_cpu_affinity",
                    "effective_cpu_affinity", "exclusive_cpu_affinity",
                    "ancestor_uclamp_max",
                    }) or group["pressure"] != {} or
                    group["effective_cpu_affinity"] != [] or
                    group["exclusive_cpu_affinity"] != [] or
                    group["ancestor_uclamp_max"] != []):
                raise QualificationError(
                    "unavailable measurement cgroup evidence is malformed"
                )
        elif group["mode"] != MEASUREMENT_ENVIRONMENT_EXCLUSIVE:
            raise QualificationError("measurement cgroup evidence is malformed")
        else:
            _require_int(
                group["uclamp_min"], "measurement cgroup uclamp min", 0, 1024
            )
            _require_int(
                group["uclamp_max"], "measurement cgroup uclamp max", 0, 1024
            )
            _require_int(
                group["populated"], "measurement cgroup populated", 0, 1
            )
            _require_int(
                group["frozen"], "measurement cgroup frozen", 0, 1
            )
        if group["mode"] == MEASUREMENT_ENVIRONMENT_EXCLUSIVE and (
              not controller or set(controller) & set(affinity) or
              group["effective_cpu_affinity"] != affinity or
              group["exclusive_cpu_affinity"] != affinity or
              group["partition"] != "isolated" or
              group["uclamp_min"] != 1024 or group["uclamp_max"] != 1024 or
              group["populated"] != 0 or group["frozen"] != 0 or
              any(value != 1024 for value in ancestor_max)):
            raise QualificationError(
                "measurement cgroup isolation identity is malformed"
            )


def _v6_pressure_metrics(
    before: dict[str, Any], after: dict[str, Any], wall_ms: int,
) -> dict[str, int]:
    metrics: dict[str, int] = {}
    for scope, left_root, right_root in (
        ("global", before.get("global_pressure"), after.get("global_pressure")),
        ("cgroup", before.get("measurement_cgroup", {}).get("pressure"),
         after.get("measurement_cgroup", {}).get("pressure")),
    ):
        if scope == "cgroup" and left_root == right_root == {}:
            for resource in ("cpu", "memory", "io"):
                for kind in ("some", "full"):
                    metrics[f"{scope}_{resource}_{kind}_basis_points"] = 0
            continue
        left_map = _exact_dict(
            left_root, {"cpu", "memory", "io"},
            f"{scope} pressure before",
        )
        right_map = _exact_dict(
            right_root, {"cpu", "memory", "io"},
            f"{scope} pressure after",
        )
        for resource in ("cpu", "memory", "io"):
            left = _exact_dict(
                left_map[resource], {"some_total_us", "full_total_us"},
                f"{scope} {resource} pressure before",
            )
            right = _exact_dict(
                right_map[resource], {"some_total_us", "full_total_us"},
                f"{scope} {resource} pressure after",
            )
            for kind in ("some", "full"):
                field = f"{kind}_total_us"
                lvalue = _require_int(
                    left[field], f"{scope} pressure before", 0, 1 << 62
                )
                rvalue = _require_int(
                    right[field], f"{scope} pressure after", 0, 1 << 62
                )
                if rvalue < lvalue:
                    raise QualificationError(f"{scope} pressure counter reset")
                metrics[f"{scope}_{resource}_{kind}_basis_points"] = (
                    _basis_points(rvalue - lvalue, wall_ms * 1000)
                )
    return metrics


def _v6_control_metrics(
    before: dict[str, Any], after: dict[str, Any], affinity: list[int],
    required: bool,
) -> tuple[dict[str, int], list[str]]:
    violations: list[str] = []
    before_group = before.get("measurement_cgroup")
    after_group = after.get("measurement_cgroup")
    if not isinstance(before_group, dict) or not isinstance(after_group, dict):
        raise QualificationError("measurement cgroup evidence is malformed")
    if before_group.get("mode") != after_group.get("mode"):
        raise QualificationError("measurement cgroup identity drift")
    if (before_group.get("controller_cpu_affinity") !=
            after_group.get("controller_cpu_affinity")):
        raise QualificationError("measurement controller affinity drift")
    before_system = before.get("system_uclamp")
    after_system = after.get("system_uclamp")
    if before_system != after_system:
        raise QualificationError("system CPU utilization clamp drift")
    if not isinstance(before_system, dict):
        raise QualificationError("system CPU utilization clamp is malformed")
    system_minimum = before_system.get("minimum_limit")
    system_maximum = before_system.get("maximum_limit")
    _validate_system_uclamp_limits(
        system_minimum, system_maximum,
        "system CPU utilization clamp", required,
    )
    isolation_fields = (
        "effective_cpu_affinity", "exclusive_cpu_affinity", "partition",
        "uclamp_min", "uclamp_max",
        "ancestor_uclamp_max",
        "populated", "frozen",
    )
    if any(before_group.get(field) != after_group.get(field)
           for field in isolation_fields):
        raise QualificationError("measurement cgroup isolation identity drift")
    counter_fields = (
        "nr_throttled", "throttled_us", "memory_oom", "memory_oom_kill",
        "memory_oom_group_kill",
    )
    if before_group.get("mode") == MEASUREMENT_ENVIRONMENT_EXCLUSIVE:
        deltas = {
            field: _cgroup_delta(before_group, after_group, field)
            for field in counter_fields
        }
        if required and (deltas["nr_throttled"] or deltas["throttled_us"]):
            violations.append("measurement cgroup CPU throttling occurred")
        if required and any(
                deltas[field] for field in (
                    "memory_oom", "memory_oom_kill", "memory_oom_group_kill"
                )):
            violations.append("measurement cgroup OOM activity occurred")
    elif before_group.get("mode") == MEASUREMENT_ENVIRONMENT_UNAVAILABLE:
        deltas = {field: 0 for field in counter_fields}
        if required:
            violations.append("exclusive measurement cgroup is unavailable")
    else:
        raise QualificationError("measurement cgroup evidence is malformed")

    before_frequency = before.get("cpufreq")
    after_frequency = after.get("cpufreq")
    if not isinstance(before_frequency, list) or not isinstance(after_frequency, list):
        raise QualificationError("CPU frequency evidence is malformed")
    if required and (not before_frequency or not after_frequency):
        violations.append("CPU frequency policy evidence is unavailable")
    if len(before_frequency) != len(after_frequency):
        raise QualificationError("CPU frequency evidence drift")
    frequency_fields = {
        "cpu", "driver", "governor", "minimum_khz", "maximum_khz",
        "current_khz",
    }
    for left, right in zip(before_frequency, after_frequency):
        _exact_dict(left, frequency_fields, "CPU frequency before")
        _exact_dict(right, frequency_fields, "CPU frequency after")
        for item in (left, right):
            _require_int(item["cpu"], "CPU frequency index", 0, 65535)
            for field in ("minimum_khz", "maximum_khz", "current_khz"):
                _require_int(item[field], f"CPU frequency {field}", 1, 1 << 62)
            if (not isinstance(item["driver"], str) or
                    re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", item["driver"]) is None or
                    not isinstance(item["governor"], str) or
                    re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", item["governor"]) is None or
                    item["maximum_khz"] < item["minimum_khz"]):
                raise QualificationError("CPU frequency evidence is malformed")
        if ({key: left[key] for key in frequency_fields if key != "current_khz"} !=
                {key: right[key] for key in frequency_fields if key != "current_khz"}):
            violations.append("CPU frequency policy changed during measurement")
    if before_frequency and [item["cpu"] for item in before_frequency] != affinity:
        raise QualificationError("CPU frequency identity drift")

    before_thermal = before.get("thermal")
    after_thermal = after.get("thermal")
    if not isinstance(before_thermal, list) or not isinstance(after_thermal, list):
        raise QualificationError("thermal evidence is malformed")
    if required and (not before_thermal or not after_thermal):
        violations.append("thermal throttle evidence is unavailable")
    if len(before_thermal) != len(after_thermal):
        raise QualificationError("thermal evidence drift")
    thermal_ms = 0
    thermal_count = 0
    thermal_fields = {
        "cpu", "core_count", "core_total_ms", "package_count",
        "package_total_ms",
    }
    for left, right in zip(before_thermal, after_thermal):
        _exact_dict(left, thermal_fields, "thermal evidence before")
        _exact_dict(right, thermal_fields, "thermal evidence after")
        left_cpu = _require_int(
            left["cpu"], "thermal CPU before", 0, 65535
        )
        right_cpu = _require_int(
            right["cpu"], "thermal CPU after", 0, 65535
        )
        if left_cpu != right_cpu:
            raise QualificationError("thermal CPU identity drift")
        for field in thermal_fields - {"cpu"}:
            lvalue = _require_int(left[field], f"thermal {field}", 0, 1 << 62)
            rvalue = _require_int(right[field], f"thermal {field}", 0, 1 << 62)
            if rvalue < lvalue:
                raise QualificationError("thermal counter reset")
        thermal_ms = max(
            thermal_ms,
            right["core_total_ms"] - left["core_total_ms"],
            right["package_total_ms"] - left["package_total_ms"],
        )
        thermal_count = max(
            thermal_count,
            right["core_count"] - left["core_count"],
            right["package_count"] - left["package_count"],
        )
    if before_thermal and [item["cpu"] for item in before_thermal] != affinity:
        raise QualificationError("thermal CPU identity drift")
    if required and (thermal_ms or thermal_count):
        violations.append("thermal throttle activity exceeds the pinned limit")
    return {
        **{f"cgroup_{field}_delta": value for field, value in deltas.items()},
        "system_uclamp_min_limit": system_minimum,
        "system_uclamp_max_limit": system_maximum,
        "thermal_throttle_ms": thermal_ms,
        "thermal_throttle_count": thermal_count,
    }, violations


def _v6_cpu_metrics(
    before: dict[str, Any], after: dict[str, Any], wall_ms: int,
    affinity: list[int], logical_cpus: int,
) -> dict[str, int]:
    before_cpu = _exact_dict(before.get("cpu"), {
        "clock_ticks_per_second", "host_logical_cpus", "host_busy_ticks",
        "affinity_busy_ticks",
    }, "environment CPU before")
    after_cpu = _exact_dict(after.get("cpu"), set(before_cpu), "environment CPU after")
    for field in before_cpu:
        _require_int(before_cpu[field], f"environment CPU {field}", 0, 1 << 62)
        _require_int(after_cpu[field], f"environment CPU {field}", 0, 1 << 62)
    if (before_cpu["clock_ticks_per_second"] == 0 or
            before_cpu["clock_ticks_per_second"] != after_cpu["clock_ticks_per_second"] or
            before_cpu["host_logical_cpus"] != after_cpu["host_logical_cpus"] or
            before_cpu["host_logical_cpus"] != logical_cpus):
        raise QualificationError("environment CPU topology drift")
    for field in ("host_busy_ticks", "affinity_busy_ticks"):
        if after_cpu[field] < before_cpu[field]:
            raise QualificationError("environment CPU counter reset")
    before_group = before.get("measurement_cgroup", {})
    after_group = after.get("measurement_cgroup", {})
    mode = before_group.get("mode")
    if mode != after_group.get("mode"):
        raise QualificationError("measurement cgroup identity drift")
    if mode == MEASUREMENT_ENVIRONMENT_EXCLUSIVE:
        owned_us = _cgroup_delta(before_group, after_group, "cpu_usage_us")
    elif mode == MEASUREMENT_ENVIRONMENT_UNAVAILABLE:
        if before_group.get("cpu_usage_us") is not None or after_group.get("cpu_usage_us") is not None:
            raise QualificationError("unavailable cgroup CPU evidence is malformed")
        owned_us = 0
    else:
        raise QualificationError("measurement cgroup CPU evidence is malformed")
    tick_hz = before_cpu["clock_ticks_per_second"]
    host_busy_ms = (
        (after_cpu["host_busy_ticks"] - before_cpu["host_busy_ticks"])
        * 1000 // tick_hz
    )
    affinity_busy_ms = (
        (after_cpu["affinity_busy_ticks"] - before_cpu["affinity_busy_ticks"])
        * 1000 // tick_hz
    )
    owned_ms = owned_us // 1000
    tick_ms = (1000 + tick_hz - 1) // tick_hz
    if (owned_ms > host_busy_ms + tick_ms * logical_cpus or
            owned_ms > affinity_busy_ms + tick_ms * len(affinity)):
        raise QualificationError("measurement cgroup CPU accounting drift")
    host_external_ms = max(0, host_busy_ms - owned_ms)
    affinity_external_ms = max(0, affinity_busy_ms - owned_ms)
    return {
        "host_busy_ms": host_busy_ms,
        "affinity_busy_ms": affinity_busy_ms,
        "cgroup_owned_cpu_ms": owned_ms,
        "host_external_cpu_ms": host_external_ms,
        "affinity_external_cpu_ms": affinity_external_ms,
        "host_external_cpu_basis_points": _basis_points(
            host_external_ms, wall_ms * logical_cpus
        ),
        "affinity_external_cpu_basis_points": _basis_points(
            affinity_external_ms, wall_ms * len(affinity)
        ),
    }


def _evaluate_runtime_environment(
    before: dict[str, Any], after: dict[str, Any], wall_ms: int,
    affinity: list[int], logical_cpus: int, policy: dict[str, int],
    required: bool,
) -> dict[str, Any]:
    if policy != ENVIRONMENT_POLICY:
        raise QualificationError("determinism environment policy is not pinned")
    _validate_v6_environment_inputs(
        before, after, wall_ms, affinity, logical_cpus
    )
    cpu = _v6_cpu_metrics(before, after, wall_ms, affinity, logical_cpus)
    pressure = _v6_pressure_metrics(before, after, wall_ms)
    controls, violations = _v6_control_metrics(
        before, after, affinity, required
    )
    if (required and cpu["affinity_external_cpu_basis_points"] >
            policy["runtime_affinity_external_cpu_limit_basis_points"]):
        violations.append(
            "affinity external CPU activity exceeds the pinned runtime limit"
        )
    return {
        "valid": not violations,
        "violations": violations,
        "metrics": {**cpu, **pressure, **controls},
    }


def _validate_batch_wall_evidence(
    observed_wall_ms: int, gated_wall_ms: int, measurement_iterations: int,
    policy: dict[str, int],
) -> None:
    _require_int(observed_wall_ms, "batch observed wall time", 1, 1 << 62)
    _require_int(gated_wall_ms, "batch gated wall time", 1, 1 << 62)
    _require_int(measurement_iterations, "batch measurement count", 1, 100)
    if (observed_wall_ms + measurement_iterations * 10 < gated_wall_ms or
            observed_wall_ms >
            gated_wall_ms + policy["batch_max_overhead_ms"]):
        raise QualificationError(
            "batch wall evidence differs from the measured inner window"
        )


def _evaluate_idle_environment(
    before: dict[str, Any], after: dict[str, Any], wall_ms: int,
    affinity: list[int], logical_cpus: int, policy: dict[str, int],
    required: bool,
) -> dict[str, Any]:
    if policy != ENVIRONMENT_POLICY:
        raise QualificationError("determinism environment policy is not pinned")
    _validate_v6_environment_inputs(
        before, after, wall_ms, affinity, logical_cpus
    )
    cpu = _v6_cpu_metrics(before, after, wall_ms, affinity, logical_cpus)
    pressure = _v6_pressure_metrics(before, after, wall_ms)
    controls, violations = _v6_control_metrics(
        before, after, affinity, required
    )
    idle_minimum_ms = policy["idle_seconds"] * 1000
    if not (
            idle_minimum_ms <= wall_ms <=
            idle_minimum_ms + policy["idle_max_overshoot_ms"]):
        violations.append(
            "idle preflight duration differs from the pinned window"
        )
    gates = (
        (cpu["host_external_cpu_basis_points"],
         policy["idle_host_external_cpu_limit_basis_points"],
         "host external CPU activity exceeds the pinned idle limit"),
        (cpu["affinity_external_cpu_basis_points"],
         policy["idle_affinity_external_cpu_limit_basis_points"],
         "affinity external CPU activity exceeds the pinned idle limit"),
        (pressure["global_cpu_some_basis_points"],
         policy["idle_cpu_pressure_some_limit_basis_points"],
         "global CPU pressure exceeds the pinned idle limit"),
        (pressure["global_memory_full_basis_points"],
         policy["idle_memory_pressure_full_limit_basis_points"],
         "global memory full pressure exceeds the pinned idle limit"),
        (pressure["global_io_full_basis_points"],
         policy["idle_io_pressure_full_limit_basis_points"],
         "global IO full pressure exceeds the pinned idle limit"),
    )
    if required:
        violations.extend(message for value, limit, message in gates if value > limit)
    return {
        "valid": not violations,
        "violations": violations,
        "metrics": {**cpu, **pressure, **controls},
    }


def _telemetry_bytes(path: Path, maximum: int, label: str) -> bytes:
    try:
        return _read_regular(path, maximum)
    except QualificationError as error:
        raise QualificationError(f"cannot read {label}") from error


def _telemetry_text(path: Path, label: str, maximum: int = 4096) -> str:
    raw = _telemetry_bytes(path, maximum, label)
    try:
        value = raw.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise QualificationError(f"{label} is malformed") from error
    if not value or "\x00" in value or "\n" in value:
        raise QualificationError(f"{label} is malformed")
    return value


def _telemetry_uint(path: Path, label: str) -> int:
    value = _telemetry_text(path, label)
    if re.fullmatch(r"[0-9]{1,20}", value) is None:
        raise QualificationError(f"{label} is malformed")
    return int(value)


def _system_uclamp_limits(
    proc_root: Path, allow_unavailable: bool = False,
) -> tuple[int | None, int | None]:
    kernel = proc_root / "sys" / "kernel"
    minimum_path = kernel / "sched_util_clamp_min"
    maximum_path = kernel / "sched_util_clamp_max"
    kinds = (_regular_kind(minimum_path), _regular_kind(maximum_path))
    if kinds == ("missing", "missing") and allow_unavailable:
        return None, None
    if kinds != ("regular", "regular"):
        raise QualificationError("system CPU utilization clamp is unavailable")
    minimum = _telemetry_uint(
        minimum_path, "system uclamp min"
    )
    maximum = _telemetry_uint(
        maximum_path, "system uclamp max"
    )
    _validate_system_uclamp_limits(
        minimum, maximum, "system CPU utilization clamp", False
    )
    return minimum, maximum


def _telemetry_directory(path: Path, root: Path, label: str) -> Path | None:
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise QualificationError(f"{label} is malformed") from error
    try:
        resolved.relative_to(root.resolve(strict=True))
    except (ValueError, FileNotFoundError, OSError) as error:
        raise QualificationError(f"{label} escapes its authority root") from error
    if not resolved.is_dir():
        raise QualificationError(f"{label} is malformed")
    return resolved


def _parse_named_counters(
    raw: bytes, label: str, required: set[str],
) -> dict[str, int]:
    if not raw or len(raw) > 64 * 1024:
        raise QualificationError(f"{label} is malformed")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise QualificationError(f"{label} is malformed") from error
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([a-z][a-z0-9_.-]{0,63}) ([0-9]{1,20})", line)
        if match is None or match.group(1) in values:
            raise QualificationError(f"{label} is malformed")
        values[match.group(1)] = int(match.group(2))
    if not required <= set(values):
        raise QualificationError(f"{label} is incomplete")
    return values


def _measurement_cgroup_snapshot(
    measurement_cgroup: Path | None, affinity: list[int],
    authority_root: Path = Path("/sys/fs/cgroup"),
    expected_controller_affinity: list[int] | None = None,
) -> dict[str, Any]:
    try:
        controller = sorted(os.sched_getaffinity(0))
    except AttributeError:
        controller = []
    except OSError as error:
        raise QualificationError(
            "cannot read measurement controller affinity"
        ) from error
    if (expected_controller_affinity is not None and
            controller != expected_controller_affinity):
        raise QualificationError("measurement controller affinity drift")
    if measurement_cgroup is None:
        return {
            "mode": MEASUREMENT_ENVIRONMENT_UNAVAILABLE,
            "cpu_usage_us": None,
            "nr_throttled": None,
            "throttled_us": None,
            "memory_oom": None,
            "memory_oom_kill": None,
            "memory_oom_group_kill": None,
            "pressure": {},
            "controller_cpu_affinity": controller,
            "effective_cpu_affinity": [],
            "exclusive_cpu_affinity": [],
            "partition": None,
            "uclamp_min": None,
            "uclamp_max": None,
            "ancestor_uclamp_max": [],
            "populated": None,
            "frozen": None,
        }
    identity = _measurement_cgroup_identity(
        measurement_cgroup, controller, authority_root
    )
    if identity["cpus"] != affinity:
        raise QualificationError("measurement cgroup CPU identity drift")
    root = identity["path"]
    cpu = _parse_named_counters(
        _telemetry_bytes(root / "cpu.stat", 64 * 1024, "cgroup CPU counters"),
        "cgroup CPU counters",
        {"usage_usec", "nr_throttled", "throttled_usec"},
    )
    memory = _parse_named_counters(
        _telemetry_bytes(
            root / "memory.events", 64 * 1024, "cgroup memory counters"
        ),
        "cgroup memory counters",
        {"oom", "oom_kill", "oom_group_kill"},
    )
    pressure = {
        resource: _parse_pressure(
            _telemetry_bytes(
                root / f"{resource}.pressure", 64 * 1024,
                f"cgroup {resource} pressure",
            ),
            f"cgroup {resource}",
        )
        for resource in ("cpu", "memory", "io")
    }
    return {
        "mode": MEASUREMENT_ENVIRONMENT_EXCLUSIVE,
        "cpu_usage_us": cpu["usage_usec"],
        "nr_throttled": cpu["nr_throttled"],
        "throttled_us": cpu["throttled_usec"],
        "memory_oom": memory["oom"],
        "memory_oom_kill": memory["oom_kill"],
        "memory_oom_group_kill": memory["oom_group_kill"],
        "pressure": pressure,
        "controller_cpu_affinity": controller,
        "effective_cpu_affinity": identity["cpus"],
        "exclusive_cpu_affinity": identity["exclusive_cpus"],
        "partition": identity["partition"],
        "uclamp_min": identity["uclamp_min"],
        "uclamp_max": identity["uclamp_max"],
        "ancestor_uclamp_max": identity["ancestor_uclamp_max"],
        "populated": identity["populated"],
        "frozen": identity["frozen"],
    }


def _capture_environment(
    affinity: list[int], proc_root: Path = Path("/proc"),
    cpu_root: Path = Path("/sys/devices/system/cpu"),
    measurement_cgroup: Path | None = None,
    cgroup_authority_root: Path = Path("/sys/fs/cgroup"),
    expected_controller_affinity: list[int] | None = None,
) -> dict[str, Any]:
    if not affinity or affinity != sorted(set(affinity)):
        raise QualificationError("environment affinity is malformed")
    try:
        clock_ticks = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError) as error:
        raise QualificationError("cannot read CPU accounting clock") from error
    cpu = _parse_proc_stat(
        _telemetry_bytes(proc_root / "stat", 1024 * 1024, "CPU accounting"),
        affinity, int(clock_ticks),
    )
    global_pressure = {
        resource_name: _parse_pressure(
            _telemetry_bytes(
                proc_root / "pressure" / resource_name, 64 * 1024,
                f"{resource_name} pressure",
            ),
            resource_name,
        )
        for resource_name in ("cpu", "memory", "io")
    }
    system_uclamp_minimum, system_uclamp_maximum = _system_uclamp_limits(
        proc_root, allow_unavailable=measurement_cgroup is None
    )

    frequency: list[dict[str, Any]] = []
    frequency_missing = 0
    for cpu_index in affinity:
        root = cpu_root / f"cpu{cpu_index}" / "cpufreq"
        resolved_root = _telemetry_directory(
            root, cpu_root, "CPU frequency evidence"
        )
        if resolved_root is None:
            frequency_missing += 1
            continue
        root = resolved_root
        driver = _telemetry_text(root / "scaling_driver", "CPU frequency driver")
        governor = _telemetry_text(
            root / "scaling_governor", "CPU frequency governor"
        )
        if (re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", driver) is None or
                re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", governor) is None):
            raise QualificationError("CPU frequency policy is malformed")
        minimum = _telemetry_uint(
            root / "scaling_min_freq", "CPU minimum frequency"
        )
        maximum = _telemetry_uint(
            root / "scaling_max_freq", "CPU maximum frequency"
        )
        current = _telemetry_uint(
            root / "scaling_cur_freq", "CPU current frequency"
        )
        if minimum == 0 or maximum < minimum or current == 0:
            raise QualificationError("CPU frequency policy is malformed")
        frequency.append({
            "cpu": cpu_index,
            "driver": driver,
            "governor": governor,
            "minimum_khz": minimum,
            "maximum_khz": maximum,
            "current_khz": current,
        })
    if frequency_missing not in {0, len(affinity)}:
        raise QualificationError("CPU frequency evidence is incomplete")

    thermal: list[dict[str, int]] = []
    thermal_missing = 0
    thermal_names = (
        "core_throttle_count", "core_throttle_total_time_ms",
        "package_throttle_count", "package_throttle_total_time_ms",
    )
    for cpu_index in affinity:
        root = cpu_root / f"cpu{cpu_index}" / "thermal_throttle"
        resolved_root = _telemetry_directory(
            root, cpu_root, "thermal throttle evidence"
        )
        if resolved_root is None:
            thermal_missing += 1
            continue
        root = resolved_root
        values = {
            name: _telemetry_uint(root / name, f"thermal throttle {name}")
            for name in thermal_names
        }
        thermal.append({
            "cpu": cpu_index,
            "core_count": values["core_throttle_count"],
            "core_total_ms": values["core_throttle_total_time_ms"],
            "package_count": values["package_throttle_count"],
            "package_total_ms": values["package_throttle_total_time_ms"],
        })
    if thermal_missing not in {0, len(affinity)}:
        raise QualificationError("thermal throttle evidence is incomplete")
    return {
        "cpu": cpu,
        "global_pressure": global_pressure,
        "system_uclamp": {
            "minimum_limit": system_uclamp_minimum,
            "maximum_limit": system_uclamp_maximum,
        },
        "measurement_cgroup": _measurement_cgroup_snapshot(
            measurement_cgroup, affinity, cgroup_authority_root,
            expected_controller_affinity,
        ),
        "cpufreq": frequency,
        "thermal": thermal,
    }


def metric_statistics(values: list[int]) -> dict[str, int]:
    if len(values) != 10 or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
        raise QualificationError("metric statistics require ten non-negative integer samples")
    ordered = sorted(values)
    return {
        "count": 10,
        "min": ordered[0],
        "median": (ordered[4] + ordered[5] + 1) // 2,
        "p90": ordered[8],
        "max": ordered[9],
    }


def _validate_statistics(value: Any, label: str) -> dict[str, Any]:
    stats = _exact_dict(value, {"count", "min", "median", "p90", "max"}, label)
    for field in ("count", "min", "median", "p90", "max"):
        _require_int(stats[field], f"{label}.{field}", 0, 1 << 62)
    if stats["count"] != 10 or not stats["min"] <= stats["median"] <= stats["p90"] <= stats["max"]:
        raise QualificationError(f"{label} statistics are inconsistent")
    return stats


def validate_baseline(raw: dict[str, Any], manifest_sha256: str) -> dict[str, Any]:
    _exact_dict(raw, {
        "schema", "manifest_sha256", "performance_regression_limit_percent",
        "semantic_reference", "profiles",
    }, "determinism baseline")
    if raw["schema"] != BASELINE_SCHEMA:
        raise QualificationError("unsupported determinism baseline schema")
    if raw["manifest_sha256"] != manifest_sha256:
        raise QualificationError("baseline manifest identity drift")
    _require_int(
        raw["performance_regression_limit_percent"],
        "baseline regression limit", 10, 10,
    )
    semantic_reference = raw["semantic_reference"]
    if not isinstance(semantic_reference, dict) or set(semantic_reference) != set(KINDS):
        raise QualificationError("baseline semantic reference is incomplete")
    for kind, reference in semantic_reference.items():
        _exact_dict(reference, {
            "semantic_sha256", "input_identity_sha256",
            "translation_unit_sha256", "translation_unit_plan_sha256",
        }, f"baseline semantic reference {kind}")
        for field, value in reference.items():
            _require_sha(value, f"baseline semantic reference {kind} {field}")
    profiles = raw["profiles"]
    if not isinstance(profiles, dict) or not profiles:
        raise QualificationError("baseline has no hardware profiles")
    for class_id, profile in profiles.items():
        if not isinstance(class_id, str) or IDENTIFIER.fullmatch(class_id) is None:
            raise QualificationError("baseline hardware class is invalid")
        _exact_dict(
            profile, {"os", "provenance", "hardware", "workloads"},
            f"baseline profile {class_id}",
        )
        _validate_os_identity(profile["os"], "baseline")
        provenance = _exact_dict(
            profile["provenance"], {
                "source_revision", "toolchain", "calibration", "promotion"
            },
            f"baseline provenance {class_id}",
        )
        if not isinstance(provenance["source_revision"], str) or not provenance["source_revision"]:
            raise QualificationError("baseline source revision is invalid")
        _validate_toolchain(provenance["toolchain"], "baseline toolchain")
        calibration = _exact_dict(
            provenance["calibration"], {"evidence_path", "receipt_sha256"},
            f"baseline calibration {class_id}",
        )
        evidence_path = _relative(
            calibration["evidence_path"],
            f"baseline calibration {class_id} evidence path",
        )
        if not evidence_path.startswith(
                "docs/evidence/phase10/determinism/calibrations/"):
            raise QualificationError(
                "baseline calibration evidence path is outside the retained authority"
            )
        _require_sha(
            calibration["receipt_sha256"],
            f"baseline calibration {class_id} receipt",
        )
        promotion = _exact_dict(
            provenance["promotion"], {
                "reason", "previous_baseline_sha256", "previous_profile_sha256"
            },
            f"baseline promotion {class_id}",
        )
        if (not isinstance(promotion["reason"], str) or
                not promotion["reason"].strip() or
                promotion["reason"] != promotion["reason"].strip() or
                "\x00" in promotion["reason"] or
                "\n" in promotion["reason"] or
                len(promotion["reason"].encode("utf-8")) > 4096):
            raise QualificationError("baseline promotion reason is malformed")
        for field in ("previous_baseline_sha256", "previous_profile_sha256"):
            value = promotion[field]
            if value is not None:
                _require_sha(value, f"baseline promotion {field}")
        previous_baseline = promotion["previous_baseline_sha256"]
        previous_profile = promotion["previous_profile_sha256"]
        if previous_baseline is None and previous_profile is not None:
            raise QualificationError(
                "baseline promotion profile predecessor lacks a baseline identity"
            )
        hardware = _exact_dict(
            profile["hardware"], set(HARDWARE_FIELDS),
            f"baseline hardware {class_id}",
        )
        if any(not isinstance(hardware[field], str) or not hardware[field]
               for field in ("architecture", "cpu_model")):
            raise QualificationError("baseline hardware identity is invalid")
        _validate_cpu_topology(hardware, "baseline")
        _validate_cpu_uclamp(
            hardware["cpu_uclamp_source"], hardware["cpu_uclamp_min"],
            hardware["cpu_uclamp_max"], "baseline CPU utilization clamp",
        )
        _validate_cpu_uclamp_ancestor_max(
            hardware["cpu_uclamp_source"],
            hardware["cpu_uclamp_ancestor_max"],
            "baseline CPU utilization clamp ancestor maximum",
        )
        _require_stable_cpu_controls(hardware, "baseline")
        _require_int(hardware["memory_bytes"], "baseline memory", 1, 1 << 62)
        workloads = profile["workloads"]
        if not isinstance(workloads, dict) or set(workloads) != set(KINDS):
            raise QualificationError("baseline workload set is incomplete")
        for kind, workload in workloads.items():
            _exact_dict(workload, {
                "semantic_sha256", "input_identity_sha256",
                "translation_unit_sha256", "translation_unit_plan_sha256",
                "statistics",
            }, f"baseline {kind}")
            _require_sha(workload["semantic_sha256"], f"baseline {kind} semantic")
            _require_sha(
                workload["input_identity_sha256"],
                f"baseline {kind} input identity",
            )
            _require_sha(
                workload["translation_unit_sha256"],
                f"baseline {kind} translation-unit identity",
            )
            _require_sha(
                workload["translation_unit_plan_sha256"],
                f"baseline {kind} translation-unit plan identity",
            )
            reference = semantic_reference[kind]
            for field in (
                "semantic_sha256", "input_identity_sha256",
                "translation_unit_sha256", "translation_unit_plan_sha256",
            ):
                if workload[field] != reference[field]:
                    raise QualificationError(
                        f"baseline {kind} profile differs from semantic reference"
                    )
            statistics = _exact_dict(workload["statistics"], set(METRICS), f"baseline {kind} metrics")
            for metric_name in METRICS:
                _validate_statistics(statistics[metric_name], f"baseline {kind} {metric_name}")
    return raw


def load_baseline(path: Path, manifest_sha256: str) -> dict[str, Any]:
    return validate_baseline(_load_json(path), manifest_sha256)


def performance_regressions(
    workload_id: str,
    current: dict[str, Any],
    baseline: dict[str, Any],
    limit_percent: int,
) -> list[dict[str, Any]]:
    checks = (("wall_ms", "median"), ("wall_ms", "p90"),
              ("wall_ms", "max"),
              ("cpu_ms", "median"), ("cpu_ms", "p90"),
              ("cpu_ms", "max"),
              ("peak_rss_kib", "max"))
    failures: list[dict[str, Any]] = []
    for metric_name, statistic in checks:
        current_value = current[metric_name][statistic]
        baseline_value = baseline[metric_name][statistic]
        if baseline_value == 0:
            if current_value != 0:
                message = (
                    f"{workload_id} {metric_name}.{statistic} baseline is zero"
                )
                failures.append(_failure_record(
                    "performance-regression", message,
                    workload=workload_id, metric=metric_name,
                    statistic=statistic, current=current_value,
                    baseline=baseline_value, limit_percent=limit_percent,
                ))
        elif current_value * 100 > baseline_value * (100 + limit_percent):
            message = (
                f"{workload_id} {metric_name}.{statistic} exceeds "
                f"{limit_percent} percent baseline "
                f"({current_value} > {baseline_value})"
            )
            failures.append(_failure_record(
                "performance-regression", message,
                workload=workload_id, metric=metric_name,
                statistic=statistic, current=current_value,
                baseline=baseline_value, limit_percent=limit_percent,
            ))
    return failures


def _profile_matches(
    profile: dict[str, Any] | None,
    host: dict[str, Any],
    toolchain: dict[str, Any],
) -> bool:
    if profile is None:
        return False
    hardware = {field: host[field] for field in HARDWARE_FIELDS}
    return (
        profile["os"] == host["os"] and
        profile["hardware"] == hardware and
        profile["provenance"]["toolchain"] == toolchain
    )


def _normalized_command(command: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": command["path"],
        "command_ordinal": command["command_ordinal"],
        "phase": command["phase"],
        "execution": command["normalized_execution"],
    }


def _input_identity_material(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "files": item["files"],
        "commands": [_normalized_command(command) for command in item["commands"]],
        "extra": item["extra"],
    }


def _validate_input_receipt(value: Any, kind: str) -> None:
    item = _exact_dict(value, {
        "kind", "identity_sha256", "translation_unit_sha256",
        "translation_unit_plan_sha256", "translation_units", "source_marker",
        "roots", "files", "commands", "extra",
    }, f"{kind} input receipt")
    if item["kind"] != kind:
        raise QualificationError(f"{kind} input kind drift")
    _require_sha(item["identity_sha256"], f"{kind} input identity")
    _require_sha(item["translation_unit_sha256"], f"{kind} TU identity")
    _require_sha(item["translation_unit_plan_sha256"], f"{kind} TU plan identity")
    _require_int(item["translation_units"], f"{kind} TU count", 1, 1_000_000)
    expected_marker = "$RELEASE_SOURCE" if kind == "release-candidate" else "$REPO"
    if item["source_marker"] != expected_marker:
        raise QualificationError(f"{kind} source marker is invalid")
    roots = item["roots"]
    if not isinstance(roots, list) or not roots:
        raise QualificationError(f"{kind} normalization roots are missing")
    root_pairs: list[tuple[Path, str]] = []
    root_markers: list[str] = []
    for root in roots:
        _exact_dict(root, {"marker", "path"}, f"{kind} normalization root")
        if (root["marker"] not in {"$REPO", "$BUILD", "$UNIT_BUILD",
                                   "$RELEASE_SOURCE", "$RELEASE_BUILD"} or
                not isinstance(root["path"], str) or
                not Path(root["path"]).is_absolute()):
            raise QualificationError(f"{kind} normalization root is invalid")
        root_pairs.append((Path(root["path"]), root["marker"]))
        root_markers.append(root["marker"])
    if root_markers != sorted(set(root_markers)) or expected_marker not in root_markers:
        raise QualificationError(f"{kind} normalization roots are duplicated")
    files = item["files"]
    if not isinstance(files, list) or not files:
        raise QualificationError(f"{kind} input file inventory is empty")
    file_paths: list[str] = []
    for source in files:
        _exact_dict(source, {"path", "sha256"}, f"{kind} input file")
        file_paths.append(_relative(source["path"], f"{kind} input file"))
        _require_sha(source["sha256"], f"{kind} input file")
    if file_paths != sorted(set(file_paths)) or item["translation_units"] != len(file_paths):
        raise QualificationError(f"{kind} input file inventory is inconsistent")
    commands = item["commands"]
    if not isinstance(commands, list) or not commands:
        raise QualificationError(f"{kind} translation-unit plan is empty")
    plan_keys: list[tuple[str, int]] = []
    for command in commands:
        _exact_dict(command, {
            "path", "compile_command_sha256", "command_ordinal", "phase",
            "execution", "normalized_execution",
        }, f"{kind} command")
        path = command["path"]
        if not isinstance(path, str) or not path.startswith(expected_marker + "/"):
            raise QualificationError(f"{kind} command path is outside its source root")
        relative = path[len(expected_marker) + 1:]
        if relative not in file_paths:
            raise QualificationError(f"{kind} command omits or invents an input path")
        ordinal = _require_int(command["command_ordinal"], f"{kind} command ordinal", 0, 1_000_000)
        if command["phase"] != "analysis":
            raise QualificationError(f"{kind} command phase is invalid")
        execution = _exact_dict(command["execution"], {
            "working_directory", "canonical_path", "output", "command_line",
        }, f"{kind} command execution")
        normalized = _exact_dict(command["normalized_execution"], {
            "working_directory", "canonical_path", "output", "command_line",
        }, f"{kind} normalized command execution")
        if (any(not isinstance(execution[field], str) or "\x00" in execution[field]
                for field in ("working_directory", "canonical_path", "output")) or
                not isinstance(execution["command_line"], list) or
                any(not isinstance(token, str) or "\x00" in token
                    for token in execution["command_line"])):
            raise QualificationError(f"{kind} command execution is malformed")
        expected_normalized = {
            field: _replace_root(execution[field], root_pairs)
            for field in ("working_directory", "canonical_path", "output")
        }
        expected_normalized["command_line"] = [
            _replace_root(token, root_pairs) for token in execution["command_line"]
        ]
        if normalized != expected_normalized:
            raise QualificationError(f"{kind} normalized command execution drift")
        if command["compile_command_sha256"] != _translation_unit_command_sha256(execution):
            raise QualificationError(f"{kind} compile-command identity drift")
        plan_keys.append((path, ordinal))
    if plan_keys != sorted(set(plan_keys)):
        raise QualificationError(f"{kind} translation-unit plan is not sorted and unique")
    for path in (f"{expected_marker}/{relative}" for relative in file_paths):
        ordinals = [ordinal for candidate, ordinal in plan_keys if candidate == path]
        if ordinals != list(range(len(ordinals))):
            raise QualificationError(f"{kind} command ordinals omit an input")
    normalized_plan = [_normalized_command(command) for command in commands]
    if item["translation_unit_sha256"] != digest_json(file_paths):
        raise QualificationError(f"{kind} translation-unit identity drift")
    if item["translation_unit_plan_sha256"] != digest_json(normalized_plan):
        raise QualificationError(f"{kind} translation-unit plan identity drift")
    if item["identity_sha256"] != digest_json(_input_identity_material(item)):
        raise QualificationError(f"{kind} input identity drift")
    if not isinstance(item["extra"], dict):
        raise QualificationError(f"{kind} extra input identity is malformed")
    selected_commands_sha = item["extra"].get(
        "selected_compile_commands_sha256"
    )
    _require_sha(selected_commands_sha, f"{kind} selected compile commands")
    if selected_commands_sha != _selected_commands_sha256(commands):
        raise QualificationError(f"{kind} selected compile-command identity drift")


def validate_receipt_payload(
    receipt: dict[str, Any], manifest: dict[str, Any], baseline: dict[str, Any],
    observed_rejection: bool = False,
) -> dict[str, Any]:
    validate_manifest(manifest)
    manifest_sha = digest_json(manifest)
    validate_baseline(baseline, manifest_sha)
    _exact_dict(receipt, {
        "schema", "status", "source", "configuration", "host", "toolchain",
        "inputs", "workloads", "baseline", "started_at", "finished_at",
        "duration_ms", "failures", "artifacts",
    }, "determinism receipt")
    if receipt["schema"] != RECEIPT_SCHEMA or receipt["status"] != "accepted" or receipt["failures"] != []:
        raise QualificationError("determinism receipt is not accepted")
    source = _exact_dict(receipt["source"], {
        "revision", "manifest_sha256", "file_count"
    }, "receipt source")
    if not isinstance(source["revision"], str) or not source["revision"]:
        raise QualificationError("receipt source revision is invalid")
    _require_sha(source["manifest_sha256"], "receipt source manifest")
    _require_int(source["file_count"], "receipt source file count", 1, 1_000_000)
    configuration = _exact_dict(receipt["configuration"], {
        "manifest_sha256", "repetitions", "performance_regression_limit_percent",
        "performance_policy", "environment_policy",
    }, "receipt configuration")
    _require_int(
        configuration["repetitions"], "receipt repetitions", 10, 10
    )
    _require_int(
        configuration["performance_regression_limit_percent"],
        "receipt performance regression limit", 10, 10,
    )
    if (configuration["manifest_sha256"] != manifest_sha or
            not isinstance(configuration["performance_policy"], str) or
            configuration["performance_policy"] not in {"required", "record-only"} or
            canonical_json(configuration["environment_policy"]) !=
            canonical_json(manifest["environment_policy"])):
        raise QualificationError("receipt configuration differs from manifest")
    host = _exact_dict(
        receipt["host"], {"class_id", "os", *HARDWARE_FIELDS},
        "receipt host",
    )
    if (not isinstance(host["class_id"], str) or IDENTIFIER.fullmatch(host["class_id"]) is None or
            any(not isinstance(host[field], str) or not host[field]
                for field in ("architecture", "cpu_model"))):
        raise QualificationError("receipt host identity is invalid")
    _validate_os_identity(host["os"], "receipt host")
    _validate_cpu_topology(host, "host")
    _validate_cpu_uclamp(
        host["cpu_uclamp_source"], host["cpu_uclamp_min"],
        host["cpu_uclamp_max"], "host CPU utilization clamp",
    )
    _validate_cpu_uclamp_ancestor_max(
        host["cpu_uclamp_source"], host["cpu_uclamp_ancestor_max"],
        "host CPU utilization clamp ancestor maximum",
    )
    _validate_system_uclamp_limits(
        host["system_uclamp_min_limit"], host["system_uclamp_max_limit"],
        "host system CPU utilization clamp", False,
    )
    _require_int(host["memory_bytes"], "host memory", 1, 1 << 62)
    toolchain = _validate_toolchain(receipt["toolchain"], "receipt toolchain")
    inputs = receipt["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != set(KINDS):
        raise QualificationError("receipt input set is incomplete")
    for kind in KINDS:
        _validate_input_receipt(inputs[kind], kind)
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise QualificationError("receipt artifact inventory is empty")
    artifact_paths: list[str] = []
    for item in artifacts:
        _exact_dict(item, {"path", "sha256", "size"}, "artifact inventory entry")
        artifact_paths.append(_relative(item["path"], "artifact path"))
        _require_sha(item["sha256"], "artifact checksum")
        _require_int(item["size"], "artifact size", 0, MAX_LOG_BYTES)
    if artifact_paths != sorted(set(artifact_paths)):
        raise QualificationError("artifact inventory is not sorted and unique")
    workloads = receipt["workloads"]
    if (not isinstance(workloads, list) or
            [item.get("kind") if isinstance(item, dict) else None for item in workloads] != list(KINDS)):
        raise QualificationError("receipt workload set is incomplete")
    profile_id = host["class_id"]
    profile = baseline["profiles"].get(profile_id)
    profile_matches = _profile_matches(profile, host, toolchain)
    if configuration["performance_policy"] == "required":
        _require_stable_cpu_controls(host, "required performance evidence")
    if (not observed_rejection and
            configuration["performance_policy"] == "required" and
            not profile_matches):
        if profile is None:
            raise QualificationError(f"baseline profile is unavailable for {profile_id}")
        raise QualificationError(
            f"baseline OS, hardware, or toolchain inventory drift for "
            f"{profile_id}"
        )
    used_artifacts: list[str] = [_idle_preflight_artifact_path()]
    regressions: list[str] = []
    for workload in workloads:
        _exact_dict(workload, {
            "id", "kind", "semantic_sha256", "runs", "statistics"
        }, "workload receipt")
        kind = workload["kind"]
        manifest_workload = next(item for item in manifest["workloads"] if item["kind"] == kind)
        if workload["id"] != manifest_workload["id"]:
            raise QualificationError(f"{kind} workload id drift")
        semantic = _require_sha(workload["semantic_sha256"], f"{kind} semantic")
        runs = workload["runs"]
        if not isinstance(runs, list) or len(runs) != 10:
            raise QualificationError(f"{kind} must contain ten repetitions")
        values = {metric_name: [] for metric_name in METRICS}
        for repetition, run in enumerate(runs, 1):
            _exact_dict(run, {
                "repetition", "semantic_sha256", "exit_code", "metrics",
                "measurement_iterations", "batch_valid", "environment_valid",
                "environment", "environment_artifact", "inner_runs",
                "artifacts",
            }, f"{kind} run")
            if _require_int(
                    run["repetition"], f"{kind} repetition", 1, 10
                    ) != repetition:
                raise QualificationError(f"{kind} repetition sequence is invalid")
            if run["semantic_sha256"] != semantic:
                raise QualificationError(f"{kind} semantic drift at repetition {repetition}")
            _require_int(
                run["exit_code"], f"{kind} repetition verdict", 0, 1
            )
            expected_iterations = manifest_workload["measurement_iterations"]
            if _require_int(
                    run["measurement_iterations"],
                    f"{kind} measurement iteration count", 1, 100,
                    ) != expected_iterations:
                raise QualificationError(f"{kind} measurement iteration drift")
            inner_runs = run["inner_runs"]
            if not isinstance(inner_runs, list) or len(inner_runs) != expected_iterations:
                raise QualificationError(f"{kind} inner measurement set is incomplete")
            inner_values = {metric_name: [] for metric_name in METRICS}
            for iteration, inner in enumerate(inner_runs, 1):
                _exact_dict(inner, {
                    "iteration", "semantic_sha256", "exit_code", "metrics",
                    "environment", "artifacts",
                }, f"{kind} inner measurement")
                if _require_int(
                        inner["iteration"], f"{kind} inner iteration", 1, 100
                        ) != iteration:
                    raise QualificationError(
                        f"{kind} inner measurement sequence is invalid"
                    )
                _require_int(
                    inner["exit_code"], f"{kind} inner exit code", 0, 1
                )
                if (inner["semantic_sha256"] != semantic or
                        inner["exit_code"] != run["exit_code"]):
                    raise QualificationError(
                        f"{kind} inner measurement semantic or exit drift"
                    )
                inner_metrics = _exact_dict(
                    inner["metrics"], set(METRICS),
                    f"{kind} inner measurement metrics",
                )
                for metric_name in METRICS:
                    minimum = 1 if metric_name != "cpu_ms" else 0
                    inner_values[metric_name].append(_require_int(
                        inner_metrics[metric_name],
                        f"{kind} inner {metric_name}", minimum, 1 << 62,
                    ))
                environment = _exact_dict(
                    inner["environment"], {"valid", "violations", "metrics"},
                    f"{kind} environment decision",
                )
                if (not isinstance(environment["valid"], bool) or
                        not isinstance(environment["violations"], list) or
                        any(not isinstance(value, str) or not value
                            for value in environment["violations"]) or
                        environment["valid"] != (not environment["violations"]) or
                        not isinstance(environment["metrics"], dict)):
                    raise QualificationError(
                        f"{kind} environment decision is malformed"
                    )
                expected_inner_artifacts = _iteration_artifact_paths(
                    kind, repetition, iteration
                )
                if inner["artifacts"] != expected_inner_artifacts:
                    raise QualificationError(
                        f"{kind} inner measurement artifact set is invalid"
                    )
                used_artifacts.extend(expected_inner_artifacts)
            metrics = _exact_dict(run["metrics"], set(METRICS), f"{kind} metrics")
            for metric_name in METRICS:
                minimum = 1 if metric_name != "cpu_ms" else 0
                observed = _require_int(
                    metrics[metric_name], f"{kind} {metric_name}",
                    minimum, 1 << 62,
                )
                expected_metric = (
                    max(inner_values[metric_name])
                    if metric_name == "peak_rss_kib"
                    else sum(inner_values[metric_name])
                )
                if observed != expected_metric:
                    raise QualificationError(
                        f"{kind} batch metrics differ from inner measurements"
                    )
                values[metric_name].append(observed)
            expected_batch_valid = (
                metrics["cpu_ms"] >= manifest_workload["minimum_batch_cpu_ms"]
            )
            environment = _exact_dict(
                run["environment"], {"valid", "violations", "metrics"},
                f"{kind} batch environment decision",
            )
            if (not isinstance(environment["valid"], bool) or
                    not isinstance(environment["violations"], list) or
                    any(not isinstance(value, str) or not value
                        for value in environment["violations"]) or
                    environment["valid"] != (not environment["violations"]) or
                    not isinstance(environment["metrics"], dict)):
                raise QualificationError(
                    f"{kind} batch environment decision is malformed"
                )
            expected_environment_artifact = _batch_environment_artifact_path(
                kind, repetition
            )
            if run["environment_artifact"] != expected_environment_artifact:
                raise QualificationError(
                    f"{kind} batch environment artifact is invalid"
                )
            used_artifacts.append(expected_environment_artifact)
            if (not isinstance(run["batch_valid"], bool) or
                    run["batch_valid"] != expected_batch_valid or
                    not isinstance(run["environment_valid"], bool) or
                    run["environment_valid"] != environment["valid"]):
                raise QualificationError(f"{kind} measurement validity drift")
            if not run["batch_valid"] and not observed_rejection:
                raise QualificationError(f"{kind} measurement batch CPU is too short")
            if not run["environment_valid"] and not observed_rejection:
                raise QualificationError(f"{kind} measurement environment is invalid")
            run_artifacts = run["artifacts"]
            if run_artifacts != _run_artifact_paths(
                    kind, repetition, expected_iterations):
                raise QualificationError(
                    f"{kind} run artifact set is invalid"
                )
            if any(path not in artifact_paths for path in run_artifacts):
                raise QualificationError(f"{kind} run artifact references are invalid")
        statistics = _exact_dict(workload["statistics"], set(METRICS), f"{kind} statistics")
        for metric_name in METRICS:
            _validate_statistics(statistics[metric_name], f"{kind} {metric_name}")
            if statistics[metric_name] != metric_statistics(values[metric_name]):
                raise QualificationError(f"{kind} {metric_name} statistics differ from raw runs")
        semantic_reference = baseline["semantic_reference"][kind]
        if (not observed_rejection and
                inputs[kind]["identity_sha256"] !=
                semantic_reference["input_identity_sha256"]):
            raise QualificationError(f"{kind} baseline input identity drift")
        if (not observed_rejection and
                inputs[kind]["translation_unit_sha256"] !=
                semantic_reference["translation_unit_sha256"]):
            raise QualificationError(f"{kind} baseline translation-unit identity drift")
        if (not observed_rejection and
                inputs[kind]["translation_unit_plan_sha256"] !=
                semantic_reference["translation_unit_plan_sha256"]):
            raise QualificationError(f"{kind} baseline translation-unit plan drift")
        if (not observed_rejection and
                semantic != semantic_reference["semantic_sha256"]):
            raise QualificationError(f"{kind} baseline semantic fingerprint drift")
        if profile_matches:
            baseline_workload = profile["workloads"][kind]
            regressions.extend(performance_regressions(
                workload["id"], statistics, baseline_workload["statistics"], 10
            ))
    if sorted(used_artifacts) != artifact_paths:
        raise QualificationError("artifact inventory is not bound exactly once by runs")
    baseline_record = _exact_dict(receipt["baseline"], {
        "profile", "sha256", "semantic_gate", "performance_gate", "regressions"
    }, "receipt baseline")
    _require_sha(baseline_record["sha256"], "baseline file")
    if not observed_rejection:
        expected_performance_gate = "pass" if profile_matches else "not-gated"
        expected_profile = profile_id if profile_matches else None
        if (baseline_record["profile"] != expected_profile or
                baseline_record["semantic_gate"] != "pass" or
                baseline_record["performance_gate"] != expected_performance_gate or
                baseline_record["regressions"] != []):
            raise QualificationError("receipt baseline decision is not accepted")
    if regressions and not observed_rejection:
        raise QualificationError(regressions[0]["message"])
    for field in ("started_at", "finished_at"):
        if not isinstance(receipt[field], str):
            raise QualificationError(f"receipt {field} is invalid")
        try:
            dt.datetime.fromisoformat(receipt[field])
        except ValueError as error:
            raise QualificationError(f"receipt {field} is invalid") from error
    _require_int(receipt["duration_ms"], "receipt duration", 0, 1 << 62)
    return receipt


def _calibration_payload(
    source: dict[str, Any], manifest_sha: str, host: dict[str, Any],
    toolchain: dict[str, Any], inputs: dict[str, Any],
    workloads: list[dict[str, Any]], started_at: dt.datetime,
    started_ns: int, artifacts: dict[str, bytes],
) -> dict[str, Any]:
    return {
        "schema": CALIBRATION_SCHEMA,
        "status": "calibration",
        "source": source,
        "configuration": {
            "manifest_sha256": manifest_sha,
            "repetitions": 10,
            "performance_regression_limit_percent": 10,
            "environment_policy": ENVIRONMENT_POLICY,
        },
        "host": host,
        "toolchain": toolchain,
        "inputs": inputs,
        "workloads": workloads,
        "started_at": started_at.isoformat(),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "duration_ms": max(
            0, round((time.monotonic_ns() - started_ns) / 1_000_000)
        ),
        "artifacts": sorted(
            (_artifact(path, data) for path, data in artifacts.items()),
            key=lambda item: item["path"],
        ),
    }


def _validate_calibration_payload(
    receipt: dict[str, Any], manifest: dict[str, Any]
) -> None:
    _exact_dict(receipt, {
        "schema", "status", "source", "configuration", "host", "toolchain",
        "inputs", "workloads", "started_at", "finished_at", "duration_ms",
        "artifacts",
    }, "determinism calibration receipt")
    if (receipt["schema"] != CALIBRATION_SCHEMA or
            receipt["status"] != "calibration"):
        raise QualificationError("determinism calibration classification drift")
    configuration = _exact_dict(receipt["configuration"], {
        "manifest_sha256", "repetitions",
        "performance_regression_limit_percent", "environment_policy",
    }, "calibration configuration")
    manifest_sha = digest_json(manifest)
    _require_int(
        configuration["repetitions"], "calibration repetitions", 10, 10
    )
    _require_int(
        configuration["performance_regression_limit_percent"],
        "calibration performance regression limit", 10, 10,
    )
    if (configuration["manifest_sha256"] != manifest_sha or
            canonical_json(configuration["environment_policy"]) !=
            canonical_json(manifest["environment_policy"])):
        raise QualificationError("calibration configuration differs from manifest")
    source = _exact_dict(receipt["source"], {
        "revision", "manifest_sha256", "file_count"
    }, "calibration source")
    if not isinstance(source["revision"], str) or not source["revision"]:
        raise QualificationError("calibration source revision is malformed")
    _require_sha(source["manifest_sha256"], "calibration source manifest")
    _require_int(source["file_count"], "calibration source file count", 1, 1_000_000)
    host = _exact_dict(
        receipt["host"], {"class_id", "os", *HARDWARE_FIELDS},
        "calibration host",
    )
    if (not isinstance(host["class_id"], str) or
            IDENTIFIER.fullmatch(host["class_id"]) is None or
            any(not isinstance(host[field], str) or not host[field]
                for field in ("architecture", "cpu_model"))):
        raise QualificationError("calibration host identity is malformed")
    _validate_os_identity(host["os"], "calibration host")
    _validate_cpu_topology(host, "calibration")
    _validate_cpu_uclamp(
        host["cpu_uclamp_source"], host["cpu_uclamp_min"],
        host["cpu_uclamp_max"], "calibration CPU utilization clamp",
    )
    _validate_cpu_uclamp_ancestor_max(
        host["cpu_uclamp_source"], host["cpu_uclamp_ancestor_max"],
        "calibration CPU utilization clamp ancestor maximum",
    )
    _require_stable_cpu_controls(host, "calibration")
    _require_int(host["memory_bytes"], "calibration memory", 1, 1 << 62)
    _validate_toolchain(receipt["toolchain"], "calibration toolchain")
    if (not isinstance(receipt["inputs"], dict) or
            set(receipt["inputs"]) != set(KINDS)):
        raise QualificationError("calibration input set is incomplete")
    for kind in KINDS:
        _validate_input_receipt(receipt["inputs"][kind], kind)
    if (not isinstance(receipt["workloads"], list) or
            [item.get("kind") if isinstance(item, dict) else None
             for item in receipt["workloads"]] != list(KINDS)):
        raise QualificationError("calibration workload set is incomplete")

    # Reuse the accepted-receipt validator with a self-consistent, in-memory
    # baseline. This checks every input, TU plan, run, statistic, artifact,
    # source, host, and toolchain field without creating a baseline/receipt
    # dependency cycle. Raw artifact claims are recomputed separately.
    synthetic_baseline = build_baseline(
        manifest_sha, receipt["host"], receipt["source"].get("revision", ""),
        receipt["toolchain"], receipt["workloads"], receipt["inputs"],
        "docs/evidence/phase10/determinism/calibrations/validation-placeholder",
        "0" * 64, "Calibration schema validation", None, None,
    )
    synthetic = {
        **receipt,
        "schema": RECEIPT_SCHEMA,
        "status": "accepted",
        "configuration": {
            **configuration,
            "performance_policy": "required",
        },
        "baseline": {
            "profile": receipt["host"]["class_id"],
            "sha256": "0" * 64,
            "semantic_gate": "pass",
            "performance_gate": "pass",
            "regressions": [],
        },
        "failures": [],
    }
    validate_receipt_payload(synthetic, manifest, synthetic_baseline)


def write_receipt(root: Path, payload: dict[str, Any], artifacts: dict[str, bytes]) -> None:
    if _regular_kind(root) not in {"missing", "directory"}:
        raise QualificationError("evidence root is not a directory")
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise QualificationError("evidence output must be empty")
    expected = {item["path"]: item for item in payload["artifacts"]}
    if set(artifacts) != set(expected):
        raise QualificationError("artifact bytes differ from receipt inventory")
    if sum(len(data) for data in artifacts.values()) > MAX_BUNDLE_BYTES:
        raise QualificationError("evidence bundle exceeds aggregate size limit")
    for relative in sorted(artifacts):
        _relative(relative, "artifact output path")
        data = artifacts[relative]
        descriptor = expected[relative]
        if len(data) != descriptor["size"] or sha256_bytes(data) != descriptor["sha256"]:
            raise QualificationError(f"artifact bytes do not match inventory: {relative}")
        _write_new(root / relative, data)
    receipt_bytes = canonical_json(payload)
    _write_new(root / "receipt.json", receipt_bytes)
    sidecar = f"{sha256_bytes(receipt_bytes)}  receipt.json\n".encode("utf-8")
    _write_new(root / "receipt.json.sha256", sidecar)
    manifest_entries = ["receipt.json", "receipt.json.sha256", *sorted(artifacts)]
    checksum = b"".join(
        f"{sha256_file(root / relative)}  {relative}\n".encode("utf-8")
        for relative in manifest_entries
    )
    _write_new(root / "SHA256SUMS", checksum)


def _rejected_payload(
    source: dict[str, Any], manifest_sha: str, performance_policy: str,
    host: dict[str, Any], toolchain: dict[str, Any], inputs: dict[str, Any],
    started_at: dt.datetime, started_ns: int, error: QualificationError,
    artifacts: dict[str, bytes], baseline_sha256: str | None,
    baseline_profile: str | None,
) -> dict[str, Any]:
    complete = isinstance(error, QualificationDecisionError)
    preflight_rejection = isinstance(error, QualificationPreflightError)
    if complete:
        failures = error.failures
    elif isinstance(error, QualificationBatchEnvironmentError):
        failures = [_failure_record(
            "batch-environment-error", str(error),
            workload=error.workload, repetition=error.repetition,
        )]
    else:
        failures = [_failure_record(
            "environment-preflight-invalid"
            if preflight_rejection else "qualification-error",
            str(error),
        )]
    for index, failure in enumerate(failures, 1):
        _validate_failure_record(failure, f"rejected failure {index}")
    measurement_rejection = complete and any(
        failure["type"] in {
            "measurement-batch-too-short", "environment-invalid"
        }
        for failure in failures
    )
    return {
        "schema": REJECTED_SCHEMA,
        "status": "rejected",
        "source": source,
        "configuration": {
            "manifest_sha256": manifest_sha,
            "repetitions": 10,
            "performance_regression_limit_percent": 10,
            "performance_policy": performance_policy,
            "environment_policy": ENVIRONMENT_POLICY,
        },
        "host": host,
        "toolchain": toolchain,
        "inputs": inputs,
        "baseline": {
            "sha256": baseline_sha256,
            "profile": baseline_profile,
        },
        "decision": {
            "classification": (
                "complete-measurement-rejection"
                if measurement_rejection
                else "complete-gate-rejection" if complete
                else "idle-preflight-rejection" if preflight_rejection
                else "incomplete"
            ),
            "failures": failures,
            "performance_regressions": [
                failure for failure in failures
                if failure["type"] == "performance-regression"
            ],
        },
        "observations": {
            "complete": complete,
            "workloads": error.workloads if complete else [],
        },
        "started_at": started_at.isoformat(),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "duration_ms": max(0, round((time.monotonic_ns() - started_ns) / 1_000_000)),
        "artifacts": sorted(
            (_artifact(path, data) for path, data in artifacts.items()),
            key=lambda item: item["path"],
        ),
    }


def _validate_rejected_payload(
    receipt: dict[str, Any], manifest: dict[str, Any],
    baseline: dict[str, Any] | None = None,
) -> None:
    _exact_dict(receipt, {
        "schema", "status", "source", "configuration", "host", "toolchain",
        "inputs", "baseline", "decision", "observations", "started_at",
        "finished_at", "duration_ms", "artifacts",
    }, "rejected determinism receipt")
    if receipt["schema"] != REJECTED_SCHEMA or receipt["status"] != "rejected":
        raise QualificationError("rejected determinism receipt classification drift")
    configuration = _exact_dict(receipt["configuration"], {
        "manifest_sha256", "repetitions", "performance_regression_limit_percent",
        "performance_policy", "environment_policy",
    }, "rejected configuration")
    _require_int(
        configuration["repetitions"], "rejected repetitions", 10, 10
    )
    _require_int(
        configuration["performance_regression_limit_percent"],
        "rejected performance regression limit", 10, 10,
    )
    if (configuration["manifest_sha256"] != digest_json(manifest) or
            not isinstance(configuration["performance_policy"], str) or
            configuration["performance_policy"] not in {"required", "record-only"} or
            canonical_json(configuration["environment_policy"]) !=
            canonical_json(manifest["environment_policy"])):
        raise QualificationError("rejected configuration differs from manifest")
    source = _exact_dict(receipt["source"], {
        "revision", "manifest_sha256", "file_count"
    }, "rejected source")
    if not isinstance(source["revision"], str) or not source["revision"]:
        raise QualificationError("rejected source revision is malformed")
    _require_sha(source["manifest_sha256"], "rejected source manifest")
    _require_int(source["file_count"], "rejected source file count", 1, 1_000_000)
    host = _exact_dict(
        receipt["host"], {"class_id", "os", *HARDWARE_FIELDS},
        "rejected host",
    )
    if (not isinstance(host["class_id"], str) or
            IDENTIFIER.fullmatch(host["class_id"]) is None or
            any(not isinstance(host[field], str) or not host[field]
                for field in ("architecture", "cpu_model"))):
        raise QualificationError("rejected host identity is malformed")
    _validate_os_identity(host["os"], "rejected host")
    _validate_cpu_topology(host, "rejected")
    _validate_cpu_uclamp(
        host["cpu_uclamp_source"], host["cpu_uclamp_min"],
        host["cpu_uclamp_max"], "rejected CPU utilization clamp",
    )
    _validate_cpu_uclamp_ancestor_max(
        host["cpu_uclamp_source"], host["cpu_uclamp_ancestor_max"],
        "rejected CPU utilization clamp ancestor maximum",
    )
    _validate_system_uclamp_limits(
        host["system_uclamp_min_limit"], host["system_uclamp_max_limit"],
        "rejected system CPU utilization clamp",
        configuration["performance_policy"] == "required",
    )
    _require_int(host["memory_bytes"], "rejected memory", 1, 1 << 62)
    _validate_toolchain(receipt["toolchain"], "rejected toolchain")
    if (not isinstance(receipt["inputs"], dict) or
            not set(receipt["inputs"]) <= set(KINDS)):
        raise QualificationError("rejected input set is malformed")
    for kind, input_receipt in receipt["inputs"].items():
        _validate_input_receipt(input_receipt, kind)
    baseline_record = _exact_dict(
        receipt["baseline"], {"sha256", "profile"}, "rejected baseline"
    )
    if baseline_record["sha256"] is not None:
        _require_sha(baseline_record["sha256"], "rejected baseline")
    if (baseline_record["profile"] is not None and
            (not isinstance(baseline_record["profile"], str) or
             IDENTIFIER.fullmatch(baseline_record["profile"]) is None or
             baseline_record["profile"] != host["class_id"])):
        raise QualificationError("rejected baseline profile is malformed")
    if ((baseline_record["sha256"] is None) != (baseline is None)):
        raise QualificationError("rejected baseline authority is incomplete")
    decision = _exact_dict(
        receipt["decision"], {
            "classification", "failures", "performance_regressions"
        }, "rejected decision",
    )
    failures = decision["failures"]
    if not isinstance(failures, list) or not failures:
        raise QualificationError("rejected decision has no failures")
    for index, failure in enumerate(failures, 1):
        _validate_failure_record(failure, f"rejected failure {index}")
    performance_failures = [
        failure for failure in failures
        if failure["type"] == "performance-regression"
    ]
    if decision["performance_regressions"] != performance_failures:
        raise QualificationError("rejected performance regressions are incomplete")
    observations = _exact_dict(
        receipt["observations"], {"complete", "workloads"},
        "rejected observations",
    )
    if not isinstance(observations["complete"], bool):
        raise QualificationError("rejected observation completeness is malformed")
    if observations["complete"]:
        if set(receipt["inputs"]) != set(KINDS):
            raise QualificationError("complete rejected decision is malformed")
        if baseline is not None:
            validate_baseline(baseline, digest_json(manifest))
        elif baseline_record["profile"] is not None:
            raise QualificationError("complete rejected baseline profile is malformed")
        validation_baseline = baseline or build_baseline(
            digest_json(manifest), host, source["revision"],
            receipt["toolchain"],
            [
                {
                    "kind": kind,
                    "semantic_sha256": "0" * 64,
                    "statistics": {
                        metric_name: {
                            "count": 10, "min": 0, "median": 0,
                            "p90": 0, "max": 0,
                        }
                        for metric_name in METRICS
                    },
                }
                for kind in KINDS
            ],
            receipt["inputs"],
            "docs/evidence/phase10/determinism/calibrations/validation-only",
            "0" * 64, "Validate baseline-free rejected observations",
            None, None,
        )
        synthetic = {
            **receipt,
            "schema": RECEIPT_SCHEMA,
            "status": "accepted",
            "workloads": observations["workloads"],
            "baseline": {
                "profile": baseline_record["profile"],
                "sha256": baseline_record["sha256"] or "0" * 64,
                "semantic_gate": "rejected",
                "performance_gate": "rejected",
                "regressions": performance_failures,
            },
            "failures": [],
        }
        for field in ("decision", "observations"):
            synthetic.pop(field)
        validate_receipt_payload(
            synthetic, manifest, validation_baseline, observed_rejection=True
        )
        measurement_failures = _measurement_failures(
            manifest, observations["workloads"]
        )
        expected_classification = (
            "complete-measurement-rejection"
            if measurement_failures else "complete-gate-rejection"
        )
        if decision["classification"] != expected_classification:
            raise QualificationError("complete rejected decision is malformed")
        expected_failures = measurement_failures or (
            _baseline_gate_failures(
                baseline, host, receipt["toolchain"], receipt["inputs"],
                observations["workloads"], configuration["performance_policy"],
            ) if baseline is not None else []
        )
        if failures != expected_failures:
            raise QualificationError(
                "rejected decision differs from recomputed gate failures"
            )
    else:
        preflight_rejection = (
            len(failures) == 1 and
            failures[0]["type"] == "environment-preflight-invalid"
        )
        expected_classification = (
            "idle-preflight-rejection" if preflight_rejection
            else "incomplete"
        )
        if (decision["classification"] != expected_classification or
                observations["workloads"] != [] or performance_failures):
            raise QualificationError("incomplete rejected decision is malformed")
    if not isinstance(receipt["artifacts"], list):
        raise QualificationError("rejected artifact inventory is malformed")
    rejected_artifact_paths: list[str] = []
    for item in receipt["artifacts"]:
        _exact_dict(item, {"path", "sha256", "size"}, "rejected artifact")
        rejected_artifact_paths.append(
            _relative(item["path"], "rejected artifact")
        )
        _require_sha(item["sha256"], "rejected artifact")
        _require_int(item["size"], "rejected artifact size", 0, MAX_LOG_BYTES)
    if rejected_artifact_paths != sorted(set(rejected_artifact_paths)):
        raise QualificationError(
            "rejected artifact inventory is not sorted and unique"
        )
    if (decision["classification"] == "idle-preflight-rejection" and
            rejected_artifact_paths != [_idle_preflight_artifact_path()]):
        raise QualificationError(
            "idle preflight rejection artifact inventory is not canonical"
        )
    batch_failures = [
        failure for failure in failures
        if failure["type"] == "batch-environment-error"
    ]
    if batch_failures:
        if (len(failures) != 1 or len(batch_failures) != 1 or
                observations["complete"]):
            raise QualificationError(
                "batch environment rejection classification is malformed"
            )
        batch_failure = batch_failures[0]
        kind = batch_failure["workload"]
        repetition = batch_failure["repetition"]
        if kind not in KINDS or repetition is None:
            raise QualificationError(
                "batch environment rejection identity is malformed"
            )
        definition = next(
            item for item in manifest["workloads"] if item["kind"] == kind
        )
        required_paths = {
            _idle_preflight_artifact_path(),
            _batch_environment_artifact_path(kind, repetition),
            *(
                path
                for iteration in range(
                    1, definition["measurement_iterations"] + 1
                )
                for path in _iteration_artifact_paths(
                    kind, repetition, iteration
                )
            ),
        }
        if not required_paths <= set(rejected_artifact_paths):
            raise QualificationError(
                "batch environment rejection artifact inventory is incomplete"
            )
    if not observations["complete"]:
        allowed_artifacts = {
            path
            for definition in manifest["workloads"]
            for repetition in range(1, 11)
            for iteration in range(1, definition["measurement_iterations"] + 1)
            for path in _iteration_artifact_paths(
                definition["kind"], repetition, iteration
            )
        }
        allowed_artifacts.add(_idle_preflight_artifact_path())
        allowed_artifacts.update(
            _batch_environment_artifact_path(definition["kind"], repetition)
            for definition in manifest["workloads"]
            for repetition in range(1, 11)
        )
        if any(
                item["path"] not in allowed_artifacts
                for item in receipt["artifacts"]):
            raise QualificationError(
                "incomplete rejected artifact inventory is not canonical"
            )
    for field in ("started_at", "finished_at"):
        if not isinstance(receipt[field], str):
            raise QualificationError(f"rejected {field} is malformed")
        try:
            dt.datetime.fromisoformat(receipt[field])
        except ValueError as error:
            raise QualificationError(f"rejected {field} is malformed") from error
    _require_int(receipt["duration_ms"], "rejected duration", 0, 1 << 62)


def _regular_files(root: Path) -> list[str]:
    result: list[str] = []
    for path in root.rglob("*"):
        kind = _regular_kind(path)
        if kind == "directory":
            continue
        if kind != "regular":
            raise QualificationError(f"evidence path is not a regular file: {path}")
        result.append(path.relative_to(root).as_posix())
    return sorted(result)


def _root_for_marker(input_receipt: dict[str, Any], marker: str) -> Path:
    matches = [root["path"] for root in input_receipt["roots"]
               if root["marker"] == marker]
    if len(matches) != 1:
        raise QualificationError(f"input receipt omits normalization root {marker}")
    return Path(matches[0])


def _verify_raw_claims(
    receipt: dict[str, Any], root: Path, manifest: dict[str, Any]
) -> None:
    _verify_idle_preflight_claim(receipt, root, manifest)
    _verify_workload_raw_claims(receipt, root, manifest)


def _verify_idle_preflight_claim(
    receipt: dict[str, Any], root: Path, manifest: dict[str, Any]
) -> None:
    preflight = _load_json(root / _idle_preflight_artifact_path())
    _exact_dict(
        preflight, {"schema", "scope", "wall_ms", "before", "after", "decision"},
        "idle preflight artifact",
    )
    if (preflight["schema"] != ENVIRONMENT_SCHEMA or
            preflight["scope"] != "idle-preflight"):
        raise QualificationError("idle preflight artifact schema is unsupported")
    _verify_controller_snapshot_claim(
        preflight["before"], receipt["host"], "idle preflight before"
    )
    _verify_controller_snapshot_claim(
        preflight["after"], receipt["host"], "idle preflight after"
    )
    expected_preflight = _evaluate_idle_environment(
        preflight["before"], preflight["after"], preflight["wall_ms"],
        receipt["host"]["cpu_affinity"],
        receipt["host"]["host_logical_cpus"],
        manifest["environment_policy"],
        receipt["configuration"].get("performance_policy") == "required",
    )
    if canonical_json(preflight["decision"]) != canonical_json(expected_preflight):
        raise QualificationError("idle preflight decision differs from raw artifact")
    classification = receipt.get("decision", {}).get("classification")
    is_idle_rejection = (
        receipt.get("schema") == REJECTED_SCHEMA and
        classification == "idle-preflight-rejection"
    )
    if is_idle_rejection:
        if expected_preflight["valid"]:
            raise QualificationError(
                "idle preflight rejection carries a valid raw preflight"
            )
        error = QualificationPreflightError(
            expected_preflight["violations"]
        )
        expected_failures = [
            _failure_record("environment-preflight-invalid", str(error))
        ]
        if receipt.get("decision", {}).get("failures") != expected_failures:
            raise QualificationError(
                "idle preflight rejection differs from raw violations"
            )
    elif not expected_preflight["valid"]:
        raise QualificationError(
            "accepted evidence carries an invalid idle preflight"
        )


def _verify_controller_snapshot_claim(
    snapshot: Any, host: dict[str, Any], label: str,
) -> None:
    if not isinstance(snapshot, dict) or not isinstance(
            snapshot.get("measurement_cgroup"), dict):
        raise QualificationError(f"{label} measurement identity is malformed")
    group = snapshot["measurement_cgroup"]
    expected_system = {
        "minimum_limit": host["system_uclamp_min_limit"],
        "maximum_limit": host["system_uclamp_max_limit"],
    }
    if canonical_json(snapshot.get("system_uclamp")) != canonical_json(
            expected_system):
        raise QualificationError(
            f"{label} system clamp differs from host identity"
        )
    if (group.get("controller_cpu_affinity") !=
            host["controller_cpu_affinity"]):
        raise QualificationError(
            f"{label} controller affinity differs from host identity"
        )
    if host["measurement_environment"] == MEASUREMENT_ENVIRONMENT_EXCLUSIVE:
        expected = {
            "mode": MEASUREMENT_ENVIRONMENT_EXCLUSIVE,
            "effective_cpu_affinity": host["cpu_affinity"],
            "exclusive_cpu_affinity": host["cpu_affinity"],
            "partition": "isolated",
            "uclamp_min": host["cpu_uclamp_min"],
            "uclamp_max": host["cpu_uclamp_max"],
            "ancestor_uclamp_max": host["cpu_uclamp_ancestor_max"],
            "populated": host["measurement_cgroup_populated"],
            "frozen": host["measurement_cgroup_frozen"],
        }
        if any(group.get(field) != value for field, value in expected.items()):
            raise QualificationError(
                f"{label} measurement identity differs from host identity"
            )
    elif group.get("mode") != MEASUREMENT_ENVIRONMENT_UNAVAILABLE:
        raise QualificationError(
            f"{label} measurement identity differs from host identity"
        )


def _verify_workload_raw_claims(
    receipt: dict[str, Any], root: Path, manifest: dict[str, Any]
) -> None:
    definitions = {item["kind"]: item for item in manifest["workloads"]}
    for workload in receipt["workloads"]:
        kind = workload["kind"]
        input_receipt = receipt["inputs"][kind]
        repo = _root_for_marker(input_receipt, "$REPO")
        release_source = (
            _root_for_marker(input_receipt, "$RELEASE_SOURCE")
            if kind == "release-candidate" else None
        )
        definition = definitions[kind]
        for run in workload["runs"]:
            repetition = run["repetition"]
            gated_wall_ms = 0
            for inner in run["inner_runs"]:
                iteration = inner["iteration"]
                paths = _iteration_artifact_paths(kind, repetition, iteration)
                report_raw = _read_regular(root / paths[0], MAX_JSON_BYTES)
                time_raw = _read_regular(root / paths[3], MAX_LOG_BYTES)
                environment = _load_json(root / paths[4])
                _exact_dict(
                    environment, {
                        "schema", "scope", "wall_ms", "before", "after",
                        "decision",
                    },
                    f"{kind} environment artifact",
                )
                if (environment["schema"] != ENVIRONMENT_SCHEMA or
                        environment["scope"] != "inner-record-only"):
                    raise QualificationError(
                        f"{kind} environment artifact schema is unsupported"
                    )
                _verify_controller_snapshot_claim(
                    environment["before"], receipt["host"],
                    f"{kind} inner environment before",
                )
                _verify_controller_snapshot_claim(
                    environment["after"], receipt["host"],
                    f"{kind} inner environment after",
                )
                try:
                    report = json.loads(report_raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise QualificationError(
                        f"{kind} repetition {repetition} raw report is malformed"
                    ) from error
                if not isinstance(report, dict):
                    raise QualificationError(
                        f"{kind} repetition {repetition} raw report is malformed"
                    )
                wall_ms, cpu_ms, peak_rss, time_exit = _parse_time_log(time_raw)
                gated_wall_ms += wall_ms
                if _require_int(
                        environment["wall_ms"],
                        f"{kind} inner environment wall time", 1, 1 << 62,
                        ) != wall_ms:
                    raise QualificationError(
                        f"{kind} environment wall time differs from raw artifact"
                    )
                if inner["metrics"] != {
                    "wall_ms": wall_ms,
                    "cpu_ms": cpu_ms,
                    "peak_rss_kib": peak_rss,
                }:
                    raise QualificationError(
                        f"{kind} repetition {repetition} inner metrics differ "
                        "from raw artifact"
                    )
                if (report.get("exit_code") != inner["exit_code"] or
                        time_exit != inner["exit_code"]):
                    raise QualificationError(
                        f"{kind} repetition {repetition} exit differs from raw artifact"
                    )
                projection = semantic_projection(
                    report, repo, release_source, input_receipt,
                    (definition["tu_timeout_seconds"], definition["tu_memory_mib"]),
                )
                if digest_json(projection) != inner["semantic_sha256"]:
                    raise QualificationError(
                        f"{kind} repetition {repetition} semantic differs from raw report"
                    )
                expected_decision = _evaluate_runtime_environment(
                    environment["before"], environment["after"], wall_ms,
                    receipt["host"]["cpu_affinity"],
                    receipt["host"]["host_logical_cpus"],
                    manifest["environment_policy"], False,
                )
                if (canonical_json(environment["decision"]) !=
                        canonical_json(expected_decision) or
                        canonical_json(inner["environment"]) !=
                        canonical_json(expected_decision)):
                    raise QualificationError(
                        f"{kind} repetition {repetition} environment decision "
                        "differs from raw artifact"
                    )
            batch_path = _batch_environment_artifact_path(kind, repetition)
            batch = _load_json(root / batch_path)
            _exact_dict(
                batch, {
                    "schema", "scope", "wall_ms", "gated_wall_ms",
                    "before", "after", "decision",
                },
                f"{kind} batch environment artifact",
            )
            if (batch["schema"] != ENVIRONMENT_SCHEMA or
                    batch["scope"] != "performance-batch"):
                raise QualificationError(
                    f"{kind} batch environment artifact schema is unsupported"
                )
            _verify_controller_snapshot_claim(
                batch["before"], receipt["host"],
                f"{kind} batch environment before",
            )
            _verify_controller_snapshot_claim(
                batch["after"], receipt["host"],
                f"{kind} batch environment after",
            )
            _require_int(
                batch["wall_ms"], f"{kind} batch wall time", 1, 1 << 62
            )
            if (_require_int(
                    batch["gated_wall_ms"],
                    f"{kind} batch gated wall time", 1, 1 << 62,
                    ) != gated_wall_ms or
                    run["metrics"]["wall_ms"] != gated_wall_ms):
                raise QualificationError(
                    f"{kind} batch wall evidence differs from raw artifacts"
                )
            _validate_batch_wall_evidence(
                batch["wall_ms"], gated_wall_ms,
                definition["measurement_iterations"],
                manifest["environment_policy"],
            )
            expected_batch = _evaluate_runtime_environment(
                batch["before"], batch["after"], gated_wall_ms,
                receipt["host"]["cpu_affinity"],
                receipt["host"]["host_logical_cpus"],
                manifest["environment_policy"],
                receipt["configuration"].get("performance_policy") == "required",
            )
            if (canonical_json(batch["decision"]) !=
                    canonical_json(expected_batch) or
                    canonical_json(run["environment"]) !=
                    canonical_json(expected_batch) or
                    run["environment_artifact"] != batch_path):
                raise QualificationError(
                    f"{kind} batch environment decision differs from raw artifact"
                )


def _recompute_partial_batch_wall_ms(
    root: Path, kind: str, repetition: int, measurement_iterations: int,
) -> int:
    gated_wall_ms = 0
    for iteration in range(1, measurement_iterations + 1):
        time_path = _iteration_artifact_paths(
            kind, repetition, iteration
        )[3]
        wall_ms, _cpu_ms, _peak_rss, _exit = _parse_time_log(
            _read_regular(root / time_path, MAX_LOG_BYTES)
        )
        gated_wall_ms += wall_ms
    return gated_wall_ms


def _verify_partial_normal_batch_environment_claim(
    receipt: dict[str, Any], root: Path, manifest: dict[str, Any],
    kind: str, repetition: int, batch: dict[str, Any],
) -> None:
    _exact_dict(
        batch, {
            "schema", "scope", "wall_ms", "gated_wall_ms", "before",
            "after", "decision",
        },
        f"{kind} partial batch environment artifact",
    )
    definition = next(
        item for item in manifest["workloads"] if item["kind"] == kind
    )
    _verify_controller_snapshot_claim(
        batch["before"], receipt["host"],
        f"{kind} partial batch environment before",
    )
    _verify_controller_snapshot_claim(
        batch["after"], receipt["host"],
        f"{kind} partial batch environment after",
    )
    _require_int(
        batch["wall_ms"], "partial batch wall time", 1, 1 << 62
    )
    _require_int(
        batch["gated_wall_ms"], "partial batch gated wall time", 1, 1 << 62
    )
    gated_wall_ms = _recompute_partial_batch_wall_ms(
        root, kind, repetition, definition["measurement_iterations"]
    )
    if batch["gated_wall_ms"] != gated_wall_ms:
        raise QualificationError(
            "partial batch wall evidence differs from raw artifacts"
        )
    _validate_batch_wall_evidence(
        batch["wall_ms"], gated_wall_ms,
        definition["measurement_iterations"], manifest["environment_policy"],
    )
    expected = _evaluate_runtime_environment(
        batch["before"], batch["after"], gated_wall_ms,
        receipt["host"]["cpu_affinity"],
        receipt["host"]["host_logical_cpus"],
        manifest["environment_policy"],
        receipt["configuration"]["performance_policy"] == "required",
    )
    if canonical_json(batch["decision"]) != canonical_json(expected):
        raise QualificationError(
            "partial batch environment decision differs from raw artifact"
        )


def _verify_rejected_batch_environment_claim(
    receipt: dict[str, Any], root: Path, manifest: dict[str, Any]
) -> None:
    batch_pattern = re.compile(
        r"raw/(unit|real-repository|release-candidate)/"
        r"run-(0[1-9]|10)/batch-environment\.json"
    )
    rejected_batch_paths: list[str] = []
    for artifact in receipt["artifacts"]:
        path = artifact["path"]
        match = batch_pattern.fullmatch(path)
        if match is None:
            continue
        observed = _load_json(root / path)
        if (not isinstance(observed, dict) or
                observed.get("schema") != ENVIRONMENT_SCHEMA or
                observed.get("scope") not in {
                    "performance-batch", "performance-batch-rejected"
                }):
            raise QualificationError(
                "rejected receipt batch environment scope is unsupported"
            )
        if observed["scope"] == "performance-batch-rejected":
            rejected_batch_paths.append(path)
        else:
            _verify_partial_normal_batch_environment_claim(
                receipt, root, manifest, match.group(1), int(match.group(2)),
                observed,
            )
    failures = [
        failure for failure in receipt["decision"]["failures"]
        if failure["type"] == "batch-environment-error"
    ]
    if not failures:
        if rejected_batch_paths:
            raise QualificationError(
                "rejected batch environment artifact lacks its failure claim"
            )
        return
    if len(failures) != 1:
        raise QualificationError(
            "batch environment rejection has multiple failure claims"
        )
    failure = failures[0]
    kind = failure["workload"]
    repetition = failure["repetition"]
    if kind not in KINDS or repetition is None:
        raise QualificationError(
            "batch environment rejection identity is malformed"
        )
    definition = next(
        item for item in manifest["workloads"] if item["kind"] == kind
    )
    batch_path = _batch_environment_artifact_path(kind, repetition)
    if rejected_batch_paths != [batch_path]:
        raise QualificationError(
            "batch environment rejection artifact inventory is not canonical"
        )
    batch = _load_json(root / batch_path)
    _exact_dict(
        batch, {
            "schema", "scope", "wall_ms", "gated_wall_ms", "before",
            "after", "failure",
        },
        f"{kind} rejected batch environment artifact",
    )
    if (batch["schema"] != ENVIRONMENT_SCHEMA or
            batch["scope"] != "performance-batch-rejected"):
        raise QualificationError(
            "rejected batch environment artifact schema is unsupported"
        )
    _validate_failure_record(
        batch["failure"], "rejected batch environment failure"
    )
    if canonical_json(batch["failure"]) != canonical_json(failure):
        raise QualificationError(
            "rejected batch environment failure differs from receipt"
        )
    _verify_controller_snapshot_claim(
        batch["before"], receipt["host"],
        f"{kind} rejected batch environment before",
    )
    _verify_controller_snapshot_claim(
        batch["after"], receipt["host"],
        f"{kind} rejected batch environment after",
    )
    _require_int(
        batch["wall_ms"], "rejected batch wall time", 1, 1 << 62
    )
    _require_int(
        batch["gated_wall_ms"], "rejected batch gated wall time", 1, 1 << 62
    )
    gated_wall_ms = _recompute_partial_batch_wall_ms(
        root, kind, repetition, definition["measurement_iterations"]
    )
    if batch["gated_wall_ms"] != gated_wall_ms:
        raise QualificationError(
            "rejected batch wall evidence differs from raw artifacts"
        )
    try:
        _validate_batch_wall_evidence(
            batch["wall_ms"], gated_wall_ms,
            definition["measurement_iterations"],
            manifest["environment_policy"],
        )
        _evaluate_runtime_environment(
            batch["before"], batch["after"], gated_wall_ms,
            receipt["host"]["cpu_affinity"],
            receipt["host"]["host_logical_cpus"],
            manifest["environment_policy"],
            receipt["configuration"]["performance_policy"] == "required",
        )
    except QualificationError as error:
        if str(error) != failure["message"]:
            raise QualificationError(
                "rejected batch environment failure differs from raw evidence"
            ) from error
    else:
        raise QualificationError(
            "batch environment failure was not reproduced"
        )


def verify_receipt(
    root: Path,
    manifest_path: Path,
    baseline_path: Path,
    repo_root: Path | None = ROOT,
    baseline_authority_root: Path | None = None,
) -> dict[str, Any]:
    if _regular_kind(root) != "directory":
        raise QualificationError("evidence root is missing")
    receipt_bytes = _read_regular(root / "receipt.json", MAX_JSON_BYTES)
    sidecar = _read_regular(root / "receipt.json.sha256", 1024)
    expected_sidecar = f"{sha256_bytes(receipt_bytes)}  receipt.json\n".encode("utf-8")
    if sidecar != expected_sidecar:
        raise QualificationError("receipt checksum mismatch")
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"malformed receipt JSON: {error}") from error
    if not isinstance(receipt, dict) or receipt_bytes != canonical_json(receipt):
        raise QualificationError("receipt is not canonical JSON")
    manifest = load_manifest(manifest_path)
    artifact_inventory = receipt.get("artifacts")
    if not isinstance(artifact_inventory, list):
        raise QualificationError("receipt artifact inventory is malformed")
    artifact_paths: list[str] = []
    for item in artifact_inventory:
        _exact_dict(item, {"path", "sha256", "size"}, "receipt artifact")
        artifact_paths.append(_relative(item["path"], "receipt artifact"))
        _require_sha(item["sha256"], "receipt artifact")
        _require_int(item["size"], "receipt artifact size", 0, MAX_LOG_BYTES)
    if sum(item["size"] for item in artifact_inventory) > MAX_BUNDLE_BYTES:
        raise QualificationError("receipt artifact inventory exceeds aggregate size limit")
    if artifact_paths != sorted(set(artifact_paths)):
        raise QualificationError("receipt artifact inventory is not sorted and unique")
    expected_files = sorted({
        "SHA256SUMS", "receipt.json", "receipt.json.sha256", *artifact_paths
    })
    if _regular_files(root) != expected_files:
        raise QualificationError("evidence file set differs from receipt")
    for item in receipt["artifacts"]:
        path = root / item["path"]
        data = _read_regular(path, MAX_LOG_BYTES)
        if len(data) != item["size"] or sha256_bytes(data) != item["sha256"]:
            raise QualificationError(f"artifact checksum mismatch: {item['path']}")
    checksum_lines = b"".join(
        f"{sha256_file(root / relative)}  {relative}\n".encode("utf-8")
        for relative in ["receipt.json", "receipt.json.sha256", *artifact_paths]
    )
    if _read_regular(root / "SHA256SUMS", MAX_JSON_BYTES) != checksum_lines:
        raise QualificationError("outer SHA256SUMS manifest mismatch")
    if receipt.get("schema") == REJECTED_SCHEMA:
        baseline = None
        baseline_record = receipt.get("baseline")
        if (isinstance(baseline_record, dict) and
                baseline_record.get("sha256") is not None):
            baseline = load_baseline(baseline_path, digest_json(manifest))
            if baseline_record.get("sha256") != sha256_file(baseline_path):
                raise QualificationError("rejected receipt baseline file identity drift")
            if baseline_authority_root is not None:
                authority = baseline_authority_root.resolve()
                verify_baseline_authority(
                    baseline, authority,
                    authority / "scripts" / "determinism_workloads.json",
                )
        _validate_rejected_payload(receipt, manifest, baseline)
        observations = receipt.get("observations")
        if repo_root is not None:
            _verify_source_authority(
                receipt["source"], repo_root.resolve(), "rejected receipt"
            )
        if repo_root is not None:
            _validate_manifest_inputs(
                receipt["inputs"], manifest, repo_root.resolve(),
                receipt["toolchain"], receipt["source"]["revision"],
            )
        if isinstance(observations, dict) and observations.get("complete") is True:
            observed = {
                **receipt,
                "workloads": observations["workloads"],
            }
            _verify_raw_claims(observed, root, manifest)
        elif _idle_preflight_artifact_path() in artifact_paths:
            _verify_idle_preflight_claim(receipt, root, manifest)
        _verify_rejected_batch_environment_claim(receipt, root, manifest)
        return receipt
    if receipt.get("schema") == CALIBRATION_SCHEMA:
        _validate_calibration_payload(receipt, manifest)
        if repo_root is not None:
            _verify_source_authority(
                receipt["source"], repo_root.resolve(), "calibration"
            )
        if repo_root is not None:
            _validate_manifest_inputs(
                receipt["inputs"], manifest, repo_root.resolve(),
                receipt["toolchain"], receipt["source"]["revision"],
            )
        _verify_raw_claims(receipt, root, manifest)
        return receipt
    baseline = load_baseline(baseline_path, digest_json(manifest))
    if baseline_authority_root is not None:
        authority = baseline_authority_root.resolve()
        verify_baseline_authority(
            baseline, authority,
            authority / "scripts" / "determinism_workloads.json",
        )
    if receipt.get("baseline", {}).get("sha256") != sha256_file(baseline_path):
        raise QualificationError("receipt baseline file identity drift")
    validate_receipt_payload(receipt, manifest, baseline)
    if repo_root is not None:
        _verify_source_authority(
            receipt["source"], repo_root.resolve(), "receipt"
        )
    if repo_root is not None:
        _validate_manifest_inputs(
            receipt["inputs"], manifest, repo_root.resolve(),
            receipt["toolchain"], receipt["source"]["revision"],
        )
    _verify_raw_claims(receipt, root, manifest)
    return receipt


def verify_baseline_authority(
    baseline: dict[str, Any], authority_root: Path, manifest_path: Path,
) -> None:
    authority_root = authority_root.resolve()
    if _regular_kind(authority_root) != "directory":
        raise QualificationError("baseline authority root is missing")
    manifest = load_manifest(manifest_path)
    validate_baseline(baseline, digest_json(manifest))
    for class_id, profile in baseline["profiles"].items():
        provenance = profile["provenance"]
        evidence_path = provenance["calibration"]["evidence_path"]
        evidence_root = authority_root / evidence_path
        calibration = verify_receipt(
            evidence_root, manifest_path,
            authority_root / "scripts" / "determinism_baseline.json", None,
        )
        if calibration.get("schema") != CALIBRATION_SCHEMA:
            raise QualificationError(
                f"baseline profile {class_id} evidence is not calibration evidence"
            )
        source_at_revision = source_manifest_at_revision(
            authority_root, provenance["source_revision"]
        )
        if calibration["source"] != source_at_revision:
            raise QualificationError(
                f"baseline profile {class_id} calibration source tree drift"
            )
        _validate_manifest_inputs(
            calibration["inputs"], manifest, authority_root,
            calibration["toolchain"], provenance["source_revision"],
        )
        if (sha256_file(evidence_root / "receipt.json") !=
                provenance["calibration"]["receipt_sha256"]):
            raise QualificationError(
                f"baseline profile {class_id} calibration receipt identity drift"
            )
        expected_hardware = {
            field: calibration["host"][field] for field in HARDWARE_FIELDS
        }
        if (calibration["host"]["class_id"] != class_id or
                calibration["host"]["os"] != profile["os"] or
                expected_hardware != profile["hardware"] or
                calibration["source"]["revision"] != provenance["source_revision"] or
                calibration["toolchain"] != provenance["toolchain"]):
            raise QualificationError(
                f"baseline profile {class_id} calibration provenance drift"
            )
        measured = {item["kind"]: item for item in calibration["workloads"]}
        for kind in KINDS:
            recorded = profile["workloads"][kind]
            source_input = calibration["inputs"][kind]
            expected = {
                "semantic_sha256": measured[kind]["semantic_sha256"],
                "input_identity_sha256": source_input["identity_sha256"],
                "translation_unit_sha256": source_input["translation_unit_sha256"],
                "translation_unit_plan_sha256": source_input[
                    "translation_unit_plan_sha256"
                ],
                "statistics": measured[kind]["statistics"],
            }
            if recorded != expected:
                raise QualificationError(
                    f"baseline profile {class_id} {kind} differs from raw calibration"
                )


def verify_bootstrap_promotion(
    repo: Path, base_revision: str, baseline_path: Path, manifest_path: Path,
) -> None:
    repo = repo.resolve()
    previous = subprocess.run(
        ["git", "cat-file", "-e", f"{base_revision}:scripts/determinism_baseline.json"],
        cwd=repo, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if previous.returncode == 0:
        raise QualificationError(
            "bootstrap promotion is forbidden when the base already owns a baseline"
        )
    raw_manifest = load_manifest(manifest_path)
    baseline = load_baseline(baseline_path, digest_json(raw_manifest))
    if len(baseline["profiles"]) != 1:
        raise QualificationError("initial baseline must promote exactly one profile")
    profile = next(iter(baseline["profiles"].values()))
    promotion = profile["provenance"]["promotion"]
    if (promotion["previous_baseline_sha256"] is not None or
            promotion["previous_profile_sha256"] is not None):
        raise QualificationError("initial baseline claims a nonexistent predecessor")
    infrastructure_revision = profile["provenance"]["source_revision"]
    for ancestor, descendant, label in (
        (base_revision, infrastructure_revision, "protected base"),
        (infrastructure_revision, "HEAD", "calibration source"),
    ):
        ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=repo, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if ancestry.returncode != 0:
            raise QualificationError(
                f"bootstrap {label} is not an ancestor of the candidate"
            )
    infrastructure_paths = {
        "CMakeLists.txt",
        ".github/workflows/determinism.yml",
        "docs/TODO.md",
        "scripts/determinism_workloads.json",
        "scripts/run_determinism_qualification.py",
        "scripts/run_in_measurement_cgroup.py",
        "tests/CMakeLists.txt",
        "tests/DeterminismQualificationTest.py",
        "tests/DeterminismWorkflowTest.py",
    }

    def changed_paths(start: str, end: str, label: str) -> list[str]:
        changed = subprocess.run(
            [
                "git", "diff", "--name-status", "-z", "--no-renames",
                f"{start}...{end}",
            ],
            cwd=repo, check=False, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if changed.returncode != 0:
            raise QualificationError(f"cannot inspect bootstrap {label} change set")
        tokens = changed.stdout.split(b"\x00")
        if tokens and tokens[-1] == b"":
            tokens.pop()
        if len(tokens) % 2 != 0:
            raise QualificationError(f"bootstrap {label} change set is malformed")
        result: list[str] = []
        for index in range(0, len(tokens), 2):
            try:
                status = tokens[index].decode("ascii")
                path = tokens[index + 1].decode("utf-8")
            except UnicodeDecodeError as error:
                raise QualificationError(
                    f"bootstrap {label} paths are not portable UTF-8"
                ) from error
            if status not in {"A", "M"}:
                raise QualificationError(
                    f"bootstrap {label} change set includes {status} {path}"
                )
            result.append(path)
        return result

    infrastructure_changes = changed_paths(
        base_revision, infrastructure_revision, "infrastructure"
    )
    if set(infrastructure_changes) != infrastructure_paths:
        raise QualificationError(
            "bootstrap infrastructure change set differs from the pinned allowlist"
        )
    authority_changes = changed_paths(
        infrastructure_revision, "HEAD", "authority"
    )
    if not authority_changes or any(
            path != "scripts/determinism_baseline.json" and
            path != "docs/devlog/changelog.md" and
            not path.startswith(
                "docs/evidence/phase10/determinism/calibrations/"
            ) and
            not path.startswith(
                "docs/evidence/phase10/stress/"
            )
            for path in authority_changes):
        raise QualificationError(
            "bootstrap authority change set exceeds baseline/evidence/changelog"
        )
    if ("scripts/determinism_baseline.json" not in authority_changes or
            not any(path.startswith(
                "docs/evidence/phase10/determinism/calibrations/"
            ) for path in authority_changes)):
        raise QualificationError(
            "bootstrap baseline omits its retained calibration authority"
        )
    verify_baseline_authority(baseline, repo, manifest_path)


def verify_baseline_promotion(
    repo: Path, base_revision: str, baseline_path: Path, manifest_path: Path,
) -> None:
    repo = repo.resolve()
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base_revision, "HEAD"],
        cwd=repo, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if ancestry.returncode != 0:
        raise QualificationError(
            "baseline revision is not an ancestor of the promotion candidate"
        )
    previous = subprocess.run(
        ["git", "show", f"{base_revision}:scripts/determinism_baseline.json"],
        cwd=repo, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if previous.returncode != 0:
        raise QualificationError("baseline promotion predecessor is missing")
    try:
        previous_json = json.loads(previous.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError("baseline promotion predecessor is malformed") from error
    if (not isinstance(previous_json, dict) or
            previous.stdout != canonical_json(previous_json)):
        raise QualificationError("baseline promotion predecessor is not canonical")
    changed = subprocess.run(
        [
            "git", "diff", "--name-status", "-z", "--no-renames",
            f"{base_revision}...HEAD",
        ],
        cwd=repo, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if changed.returncode != 0:
        raise QualificationError("cannot inspect baseline promotion change set")
    tokens = changed.stdout.split(b"\x00")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    if len(tokens) % 2 != 0:
        raise QualificationError("baseline promotion change set is malformed")
    paths: list[str] = []
    for index in range(0, len(tokens), 2):
        try:
            status = tokens[index].decode("ascii")
            path = tokens[index + 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise QualificationError(
                "baseline promotion paths are not portable UTF-8"
            ) from error
        allowed = (
            path == "scripts/determinism_baseline.json" or
            path == "docs/devlog/changelog.md" or
            path.startswith(
                "docs/evidence/phase10/determinism/calibrations/"
            )
        )
        if status not in {"A", "M"} or not allowed:
            raise QualificationError(
                f"baseline promotion change set includes {status} {path}"
            )
        paths.append(path)
    if "scripts/determinism_baseline.json" not in paths:
        raise QualificationError("baseline promotion does not update the baseline")
    raw_manifest = load_manifest(manifest_path)
    manifest_sha = digest_json(raw_manifest)
    old_baseline = validate_baseline(previous_json, manifest_sha)
    new_baseline = load_baseline(baseline_path, manifest_sha)
    verify_baseline_authority(new_baseline, repo, manifest_path)
    if new_baseline["semantic_reference"] != old_baseline["semantic_reference"]:
        raise QualificationError(
            "performance baseline promotion cannot change semantic authority"
        )
    if not set(old_baseline["profiles"]) <= set(new_baseline["profiles"]):
        raise QualificationError("baseline promotion removes an existing profile")
    predecessor_sha = sha256_bytes(previous.stdout)
    changed_profiles = 0
    for class_id, profile in new_baseline["profiles"].items():
        old_profile = old_baseline["profiles"].get(class_id)
        if old_profile == profile:
            continue
        changed_profiles += 1
        promotion = profile["provenance"]["promotion"]
        expected_profile_sha = (
            digest_json(old_profile) if old_profile is not None else None
        )
        if (promotion["previous_baseline_sha256"] != predecessor_sha or
                promotion["previous_profile_sha256"] != expected_profile_sha or
                profile["provenance"]["source_revision"] !=
                _git_output(repo, ["rev-parse", f"{base_revision}^{{commit}}"])):
            raise QualificationError(
                f"baseline profile {class_id} promotion lineage drift"
            )
    if changed_profiles != 1:
        raise QualificationError(
            "baseline promotion must add or replace exactly one profile"
        )


def _source_files(repo: Path) -> list[Path]:
    roots = tuple(repo / path.relative_to(ROOT) for path in SOURCE_ROOTS)
    files: set[Path] = set()
    for root in roots:
        kind = _regular_kind(root)
        if kind == "regular":
            files.add(root)
        elif kind == "directory":
            for candidate in root.rglob("*"):
                relative = candidate.relative_to(repo).as_posix()
                if ("__pycache__" in candidate.parts or
                        candidate.suffix in {".pyc", ".pyo"} or
                        any(relative.startswith(prefix)
                            for prefix in IGNORED_SOURCE_PREFIXES)):
                    continue
                candidate_kind = _regular_kind(candidate)
                if candidate_kind == "regular":
                    files.add(candidate)
                elif candidate_kind != "directory":
                    raise QualificationError(
                        f"source manifest path is not regular: {candidate}"
                    )
        else:
            raise QualificationError(f"source manifest path is missing: {root}")
    return sorted(files, key=lambda path: path.relative_to(repo).as_posix())


def source_manifest(repo: Path) -> dict[str, Any]:
    entries = [
        {"path": path.relative_to(repo).as_posix(), "sha256": sha256_file(path)}
        for path in _source_files(repo)
    ]
    return {
        "revision": _git_output(repo, ["rev-parse", "HEAD"]),
        "manifest_sha256": digest_json(entries),
        "file_count": len(entries),
    }


def _verify_source_authority(
    recorded: dict[str, Any], repo: Path, label: str,
) -> None:
    revision = recorded["revision"]
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=repo, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if ancestry.returncode != 0:
        raise QualificationError(f"{label} source revision is not an ancestor")
    if source_manifest_at_revision(repo, revision) != recorded:
        raise QualificationError(f"{label} source bytes differ from recorded revision")
    current = source_manifest(repo)
    if (
        current["manifest_sha256"] != recorded["manifest_sha256"] or
        current["file_count"] != recorded["file_count"]
    ):
        raise QualificationError(f"{label} source bytes differ from current repository")


def _git_output(repo: Path, arguments: list[str]) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=repo, check=False, capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise QualificationError(
            f"git {' '.join(arguments)} failed: {completed.stderr[-1000:].strip()}"
        )
    return completed.stdout.strip()


def _source_path_in_scope(relative: str) -> bool:
    if any(relative.startswith(prefix) for prefix in IGNORED_SOURCE_PREFIXES):
        return False
    return (
        relative in SOURCE_FILE_RELATIVES or
        any(relative.startswith(prefix + "/")
            for prefix in SOURCE_DIRECTORY_RELATIVES)
    )


def _git_blob(repo: Path, revision: str, relative: str) -> bytes:
    completed = subprocess.run(
        ["git", "show", f"{revision}:{relative}"], cwd=repo, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise QualificationError(
            f"source revision omits retained input {relative}"
        )
    return completed.stdout


def source_manifest_at_revision(repo: Path, revision: str) -> dict[str, Any]:
    resolved_revision = _git_output(repo, ["rev-parse", f"{revision}^{{commit}}"])
    completed = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", resolved_revision],
        cwd=repo, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise QualificationError("cannot enumerate calibration source revision")
    entries: list[dict[str, str]] = []
    seen_files: set[str] = set()
    for record in completed.stdout.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, _ = metadata.decode("ascii").split(" ", 2)
            relative = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise QualificationError("calibration source tree is malformed") from error
        if not _source_path_in_scope(relative):
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise QualificationError(
                f"calibration source path is not a regular file: {relative}"
            )
        entries.append({
            "path": relative,
            "sha256": sha256_bytes(_git_blob(repo, resolved_revision, relative)),
        })
        seen_files.add(relative)
    missing = set(SOURCE_FILE_RELATIVES) - seen_files
    if missing:
        raise QualificationError(
            f"calibration source revision omits required source roots: {sorted(missing)}"
        )
    entries.sort(key=lambda item: item["path"])
    return {
        "revision": resolved_revision,
        "manifest_sha256": digest_json(entries),
        "file_count": len(entries),
    }


def _command_output(command: list[str], label: str) -> bytes:
    completed = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    if completed.returncode != 0 or not completed.stdout:
        raise QualificationError(f"cannot capture {label} identity")
    return completed.stdout


def _tool_identity(path: Path, label: str) -> dict[str, str]:
    raw = _command_output([str(path), "--version"], label)
    try:
        version = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise QualificationError(f"cannot decode {label} identity") from error
    if not version or "\x00" in version or len(raw) > 65536:
        raise QualificationError(f"{label} identity is malformed")
    return {"sha256": sha256_file(path), "version": version}


def toolchain_identity(
    binary: Path, clang: Path, time_binary: Path, cmake: Path, ninja: Path,
    c_compiler: Path, cxx_compiler: Path,
) -> dict[str, dict[str, str]]:
    value = {
        "analyzer": _tool_identity(binary, "analyzer"),
        "clang": _tool_identity(clang, "Clang"),
        "gnu_time": _tool_identity(time_binary, "GNU time"),
        "cmake": _tool_identity(cmake, "CMake"),
        "ninja": _tool_identity(ninja, "Ninja"),
        "c_compiler": _tool_identity(c_compiler, "C compiler"),
        "cxx_compiler": _tool_identity(cxx_compiler, "C++ compiler"),
        "python": _tool_identity(Path(sys.executable).resolve(), "Python"),
    }
    _validate_toolchain(value, "toolchain")
    return value


def _canonical_cmake_cache_value(
    value: str, roots: list[tuple[Path, str]],
) -> list[dict[str, str]]:
    normalized = value.replace("\\", "/")
    spellings = sorted({
        (spelling.replace("\\", "/"), marker)
        for root, marker in roots
        for spelling in (str(root), str(root.resolve()))
    }, key=lambda item: len(item[0]), reverse=True)
    segments: list[dict[str, str]] = []
    literal_start = 0
    cursor = 0
    while cursor < len(normalized):
        match = next(
            ((spelling, marker) for spelling, marker in spellings
             if normalized.startswith(spelling, cursor)
             and (cursor == 0 or normalized[cursor - 1] in " \t;:=,([{\"'")
             and (cursor + len(spelling) == len(normalized)
                  or normalized[cursor + len(spelling)] in " /\t;:,)]}\"'")),
            None,
        )
        if match is None:
            cursor += 1
            continue
        if literal_start < cursor:
            segments.append({"literal": normalized[literal_start:cursor]})
        spelling, marker = match
        segments.append({"root": marker})
        cursor += len(spelling)
        literal_start = cursor
    if literal_start < len(normalized):
        segments.append({"literal": normalized[literal_start:]})
    if not segments:
        segments.append({"literal": ""})
    return segments


def _canonical_git_discovery_value(
    value: str, values: dict[str, str],
) -> list[dict[str, str]]:
    git_exe = values.get("GIT_EXE")
    git_executable = values.get("GIT_EXECUTABLE")
    if (git_exe is None or git_executable is None or
            not Path(git_exe).is_absolute() or
            not Path(git_executable).is_absolute() or
            Path(git_exe).resolve() != Path(git_executable).resolve()):
        raise QualificationError("build Git discovery identity drift")
    match = re.fullmatch(
        r"\[(.+)\]\[v([0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?)\(\)\]",
        value,
    )
    if (match is None or not Path(match.group(1)).is_absolute() or
            Path(match.group(1)).resolve() != Path(git_executable).resolve()):
        raise QualificationError("build Git discovery details are malformed")
    # CMake records the host Git version in this diagnostic-only cache field.
    # llama.cpp uses Git to derive GGML_COMMIT, whose exact value is already
    # bound by the selected compile-command plan.  Keeping the field and its
    # executable relationship while removing only the version text permits
    # equivalent native/container preparations to share an input identity.
    return [{"git-discovery": "$GIT_VERSION_RECORD_ONLY"}]


def _build_toolchain_identity(
    build: Path, source: Path, cmake: Path, ninja: Path,
    c_compiler: Path, cxx_compiler: Path,
) -> dict[str, Any]:
    cache_path = build / "CMakeCache.txt"
    if _regular_kind(cache_path) != "regular":
        raise QualificationError("build CMake cache is missing")
    raw = _read_regular(cache_path, MAX_JSON_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationError("build CMake cache is not UTF-8") from error
    entries: list[dict[str, Any]] = []
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith(("#", "//")):
            continue
        if "=" not in line:
            raise QualificationError(
                f"build CMake cache entry {line_number} has no value"
            )
        left, value = line.split("=", 1)
        if ":" not in left:
            raise QualificationError(
                f"build CMake cache entry {line_number} has no type"
            )
        key, entry_type = left.split(":", 1)
        if (not key or not entry_type or "\x00" in key or
                "\x00" in entry_type or "\x00" in value):
            raise QualificationError(
                f"build CMake cache entry {line_number} is malformed"
            )
        if key in values:
            raise QualificationError(f"build CMake cache duplicates {key}")
        values[key] = value
        entries.append({"key": key, "type": entry_type, "value": value})
    expected = {
        "CMAKE_COMMAND": cmake,
        "CMAKE_MAKE_PROGRAM": ninja,
        "CMAKE_C_COMPILER": c_compiler,
        "CMAKE_CXX_COMPILER": cxx_compiler,
    }
    for key, path in expected.items():
        recorded = values.get(key)
        if (recorded is None or not Path(recorded).is_absolute() or
                Path(recorded).resolve() != path.resolve()):
            raise QualificationError(f"build toolchain drift for {key}")
    if values.get("CMAKE_GENERATOR") != "Ninja":
        raise QualificationError("build generator is not pinned to Ninja")
    source_value = values.get("CMAKE_HOME_DIRECTORY")
    build_value = values.get("CMAKE_CACHEFILE_DIR")
    if source_value is None or build_value is None:
        raise QualificationError("build CMake cache omits source or build root")
    source_root = Path(source_value)
    recorded_build = Path(build_value)
    if (not source_root.is_absolute() or not recorded_build.is_absolute() or
            _regular_kind(source_root) != "directory" or
            source_root.resolve() != source.resolve()):
        raise QualificationError("build CMake cache source root identity drift")
    if (_regular_kind(recorded_build) != "directory" or
            recorded_build.resolve() != build.resolve()):
        raise QualificationError("build CMake cache build root identity drift")
    roots = [
        (recorded_build, "$BUILD"),
        (source_root, "$SOURCE"),
    ]
    tool_roles = {
        "CMAKE_COMMAND": "$CMAKE",
        "CMAKE_MAKE_PROGRAM": "$NINJA",
        "CMAKE_C_COMPILER": "$C_COMPILER",
        "CMAKE_CXX_COMPILER": "$CXX_COMPILER",
    }
    for entry in entries:
        if entry["key"] in tool_roles:
            entry["value"] = [{"tool": tool_roles[entry["key"]]}]
        elif entry["key"] == "FIND_PACKAGE_MESSAGE_DETAILS_Git":
            entry["value"] = _canonical_git_discovery_value(
                entry["value"], values
            )
        else:
            entry["value"] = _canonical_cmake_cache_value(entry["value"], roots)
    entries.sort(key=lambda item: (item["key"], item["type"]))
    return {
        "cmake_cache_schema": CMAKE_CACHE_IDENTITY_SCHEMA,
        "cmake_cache_canonical_sha256": digest_json(entries),
        "cmake": str(cmake.resolve()),
        "ninja": str(ninja.resolve()),
        "c_compiler": str(c_compiler.resolve()),
        "cxx_compiler": str(cxx_compiler.resolve()),
        "generator": "Ninja",
    }


def _validate_build_toolchain_identity(
    value: Any, label: str, toolchain: dict[str, Any] | None,
) -> dict[str, Any]:
    identity = _exact_dict(value, {
        "cmake_cache_schema", "cmake_cache_canonical_sha256", "cmake",
        "ninja", "c_compiler", "cxx_compiler", "generator",
    }, label)
    if identity["cmake_cache_schema"] != CMAKE_CACHE_IDENTITY_SCHEMA:
        raise QualificationError(f"{label} CMake cache schema drift")
    _require_sha(
        identity["cmake_cache_canonical_sha256"], f"{label} CMake cache"
    )
    for field in ("cmake", "ninja", "c_compiler", "cxx_compiler"):
        path = identity[field]
        if (not isinstance(path, str) or not Path(path).is_absolute() or
                "\x00" in path):
            raise QualificationError(f"{label} {field} path is malformed")
    if identity["generator"] != "Ninja":
        raise QualificationError(f"{label} generator drift")
    if toolchain is not None:
        mapping = {
            "cmake": "cmake", "ninja": "ninja",
            "c_compiler": "c_compiler", "cxx_compiler": "cxx_compiler",
        }
        for field, tool_name in mapping.items():
            path = Path(identity[field])
            if (_regular_kind(path) == "regular" and
                    sha256_file(path) != toolchain[tool_name]["sha256"]):
                raise QualificationError(f"{label} {field} binary identity drift")
    return identity


def _cpu_uclamp_identity(
    sched_path: Path = Path("/proc/self/sched"),
) -> tuple[str, int | None, int | None]:
    kind = _regular_kind(sched_path)
    if kind == "missing":
        return UCLAMP_SOURCE_UNAVAILABLE, None, None
    if kind != "regular":
        raise QualificationError("CPU utilization clamp evidence is not regular")
    try:
        with sched_path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
    except OSError as error:
        raise QualificationError(
            "cannot read effective CPU utilization clamp"
        ) from error
    if len(raw) > 1024 * 1024:
        raise QualificationError("CPU utilization clamp evidence is oversized")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise QualificationError(
            "effective CPU utilization clamp is malformed"
        ) from error
    minimum_lines = re.findall(
        r"^effective uclamp\.min.*$", text, re.MULTILINE,
    )
    maximum_lines = re.findall(
        r"^effective uclamp\.max.*$", text, re.MULTILINE,
    )
    if not minimum_lines and not maximum_lines:
        return UCLAMP_SOURCE_UNAVAILABLE, None, None
    if len(minimum_lines) != 1 or len(maximum_lines) != 1:
        raise QualificationError("effective CPU utilization clamp is malformed")
    minimum_match = re.fullmatch(
        r"effective uclamp\.min\s*:\s*([0-9]{1,4})\s*",
        minimum_lines[0],
    )
    maximum_match = re.fullmatch(
        r"effective uclamp\.max\s*:\s*([0-9]{1,4})\s*",
        maximum_lines[0],
    )
    if minimum_match is None or maximum_match is None:
        raise QualificationError("effective CPU utilization clamp is malformed")
    minimum = int(minimum_match.group(1))
    maximum = int(maximum_match.group(1))
    _validate_cpu_uclamp(
        UCLAMP_SOURCE_PROC, minimum, maximum,
        "effective CPU utilization clamp",
    )
    return UCLAMP_SOURCE_PROC, minimum, maximum


def _parse_cpu_list(value: str, label: str) -> list[int]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise QualificationError(f"{label} is malformed")
    cpus: list[int] = []
    for item in value.split(","):
        if re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", item) is None:
            raise QualificationError(f"{label} is malformed")
        bounds = [int(part) for part in item.split("-", 1)]
        start = bounds[0]
        finish = bounds[-1]
        if finish < start or finish > 65535:
            raise QualificationError(f"{label} is malformed")
        cpus.extend(range(start, finish + 1))
        if len(cpus) > 65536:
            raise QualificationError(f"{label} is malformed")
    if cpus != sorted(set(cpus)):
        raise QualificationError(f"{label} is malformed")
    return cpus


def _parse_cgroup_uclamp(
    value: str, label: str, allow_maximum_token: bool = False,
) -> int:
    if allow_maximum_token and value == "max":
        return 1024
    if re.fullmatch(r"(?:0|100)\.00", value) is None:
        raise QualificationError(f"{label} is not pinned")
    return 1024 if value == "100.00" else 0


def _measurement_environment_mode(
    performance_policy: str, measurement_cgroup: Path | None,
) -> str:
    if performance_policy not in {"required", "record-only"}:
        raise QualificationError("performance policy is malformed")
    return (
        MEASUREMENT_ENVIRONMENT_EXCLUSIVE
        if measurement_cgroup is not None
        else MEASUREMENT_ENVIRONMENT_UNAVAILABLE
    )


def _measurement_cgroup_identity(
    measurement_cgroup: Path, controller_affinity: list[int],
    authority_root: Path = Path("/sys/fs/cgroup"),
) -> dict[str, Any]:
    try:
        authority = authority_root.resolve(strict=True)
        resolved = measurement_cgroup.resolve(strict=True)
        resolved.relative_to(authority)
    except (FileNotFoundError, OSError, ValueError) as error:
        raise QualificationError("measurement cgroup is unavailable") from error
    if resolved == authority or not resolved.is_dir():
        raise QualificationError("measurement cgroup is not a dedicated child")
    effective = _parse_cpu_list(
        _telemetry_text(
            resolved / "cpuset.cpus.effective",
            "measurement effective CPU set",
        ),
        "measurement effective CPU set",
    )
    exclusive = _parse_cpu_list(
        _telemetry_text(
            resolved / "cpuset.cpus.exclusive.effective",
            "measurement exclusive CPU set",
        ),
        "measurement exclusive CPU set",
    )
    if effective != exclusive:
        raise QualificationError(
            "measurement cgroup exclusive CPU set differs from effective set"
        )
    partition = _telemetry_text(
            resolved / "cpuset.cpus.partition",
            "measurement cpuset partition",
            128,
    )
    if partition != "isolated":
        raise QualificationError(
            "measurement cgroup partition is not isolated"
        )
    controller = sorted(controller_affinity)
    if (not controller or controller != sorted(set(controller)) or
            set(controller) & set(effective)):
        raise QualificationError(
            "measurement controller affinity overlaps isolated CPUs"
        )
    membership_raw = _telemetry_bytes(
        resolved / "cgroup.procs", 64 * 1024,
        "measurement cgroup membership",
    )
    try:
        membership = membership_raw.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise QualificationError(
            "measurement cgroup membership is malformed"
        ) from error
    if membership:
        raise QualificationError("measurement cgroup is not empty")
    events = _parse_named_counters(
        _telemetry_bytes(
            resolved / "cgroup.events", 64 * 1024,
            "measurement cgroup events",
        ),
        "measurement cgroup events", {"populated", "frozen"},
    )
    if events["populated"] != 0 or events["frozen"] != 0:
        raise QualificationError(
            "measurement cgroup or descendant is populated or frozen"
        )
    uclamp_minimum = _parse_cgroup_uclamp(
        _telemetry_text(
            resolved / "cpu.uclamp.min", "measurement cgroup uclamp min",
            128,
        ),
        "measurement cgroup uclamp min", True,
    )
    uclamp_maximum = _parse_cgroup_uclamp(
        _telemetry_text(
            resolved / "cpu.uclamp.max", "measurement cgroup uclamp max",
            128,
        ),
        "measurement cgroup uclamp max", True,
    )
    if uclamp_minimum != 1024 or uclamp_maximum != 1024:
        raise QualificationError(
            "measurement cgroup CPU utilization clamp is not pinned"
        )
    ancestor_uclamp_max: list[int] = []
    ancestor = resolved.parent
    while ancestor != authority:
        try:
            ancestor.relative_to(authority)
        except ValueError as error:
            raise QualificationError(
                "measurement cgroup ancestor escapes its authority root"
            ) from error
        maximum = _parse_cgroup_uclamp(
            _telemetry_text(
                ancestor / "cpu.uclamp.max",
                "measurement cgroup ancestor uclamp max", 128,
            ),
            "measurement cgroup ancestor uclamp max", True,
        )
        if maximum != 1024:
            raise QualificationError(
                "measurement cgroup ancestor caps CPU utilization"
            )
        ancestor_uclamp_max.append(maximum)
        ancestor = ancestor.parent
    return {
        "path": resolved,
        "cpus": effective,
        "exclusive_cpus": exclusive,
        "partition": partition,
        "uclamp_min": uclamp_minimum,
        "uclamp_max": uclamp_maximum,
        "ancestor_uclamp_max": ancestor_uclamp_max,
        "populated": events["populated"],
        "frozen": events["frozen"],
    }


def _require_measurement_environment(
    performance_policy: str, measurement_cgroup: Path | None,
    controller_affinity: list[int],
) -> dict[str, Any] | None:
    mode = _measurement_environment_mode(performance_policy, measurement_cgroup)
    if mode == MEASUREMENT_ENVIRONMENT_UNAVAILABLE:
        if performance_policy == "required":
            raise QualificationError(
                "required performance evidence needs an exclusive measurement cgroup"
            )
        return None
    assert measurement_cgroup is not None
    return _measurement_cgroup_identity(
        measurement_cgroup, controller_affinity
    )


def host_identity(
    class_id: str, performance_policy: str = "record-only",
    measurement_cgroup: Path | None = None,
) -> dict[str, Any]:
    if IDENTIFIER.fullmatch(class_id) is None:
        raise QualificationError("hardware class id is invalid")
    cpu_model = platform.processor().strip()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                cpu_model = line.split(":", 1)[1].strip()
                break
    if not cpu_model:
        cpu_model = "unknown-cpu"
    memory_bytes = 0
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        match = re.search(
            r"^MemTotal:\s*(\d+)\s+kB$",
            meminfo.read_text(encoding="ascii", errors="replace"),
            re.MULTILINE,
        )
        if match:
            memory_bytes = int(match.group(1)) * 1024
    if memory_bytes <= 0:
        try:
            memory_bytes = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError):
            memory_bytes = 1
    try:
        controller_affinity = sorted(os.sched_getaffinity(0))
    except AttributeError:
        controller_affinity = []
    except OSError as error:
        raise QualificationError(
            "cannot read effective CPU affinity"
        ) from error
    if not controller_affinity and performance_policy == "required":
        raise QualificationError("effective CPU affinity is empty")
    measurement = _require_measurement_environment(
        performance_policy, measurement_cgroup, controller_affinity
    )
    system_uclamp_minimum, system_uclamp_maximum = _system_uclamp_limits(
        Path("/proc"), allow_unavailable=measurement is None
    )
    _validate_system_uclamp_limits(
        system_uclamp_minimum, system_uclamp_maximum,
        "host system CPU utilization clamp",
        performance_policy == "required",
    )
    if measurement is None:
        cpu_affinity = controller_affinity
        affinity_source = (
            AFFINITY_SOURCE_SCHED if controller_affinity
            else AFFINITY_SOURCE_UNAVAILABLE
        )
        measurement_environment = MEASUREMENT_ENVIRONMENT_UNAVAILABLE
        uclamp_source, uclamp_minimum, uclamp_maximum = _cpu_uclamp_identity()
        uclamp_ancestor_max: list[int] = []
        measurement_populated = None
        measurement_frozen = None
    else:
        cpu_affinity = measurement["cpus"]
        affinity_source = AFFINITY_SOURCE_CGROUP
        measurement_environment = MEASUREMENT_ENVIRONMENT_EXCLUSIVE
        uclamp_source = UCLAMP_SOURCE_CGROUP
        uclamp_minimum = measurement["uclamp_min"]
        uclamp_maximum = measurement["uclamp_max"]
        uclamp_ancestor_max = measurement["ancestor_uclamp_max"]
        measurement_populated = measurement["populated"]
        measurement_frozen = measurement["frozen"]
    logical_cpus = len(cpu_affinity) if cpu_affinity else (os.cpu_count() or 1)
    host_logical_cpus = os.cpu_count() or logical_cpus
    if (logical_cpus > host_logical_cpus or
            (cpu_affinity and cpu_affinity[-1] >= host_logical_cpus)):
        raise QualificationError("effective CPU topology is malformed")
    return {
        "class_id": class_id,
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine() or "unknown-architecture",
        "cpu_model": cpu_model,
        "logical_cpus": logical_cpus,
        "host_logical_cpus": host_logical_cpus,
        "cpu_affinity_source": affinity_source,
        "cpu_affinity": cpu_affinity,
        "cpu_uclamp_source": uclamp_source,
        "cpu_uclamp_min": uclamp_minimum,
        "cpu_uclamp_max": uclamp_maximum,
        "cpu_uclamp_ancestor_max": uclamp_ancestor_max,
        "system_uclamp_min_limit": system_uclamp_minimum,
        "system_uclamp_max_limit": system_uclamp_maximum,
        "controller_cpu_affinity": controller_affinity,
        "measurement_environment": measurement_environment,
        "measurement_cgroup_populated": measurement_populated,
        "measurement_cgroup_frozen": measurement_frozen,
        "memory_bytes": int(memory_bytes),
    }


def _inside(root: Path, relative: str, label: str) -> Path:
    _relative(relative, label)
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise QualificationError(f"{label} escapes its root") from error
    return candidate


def _parse_thesis_manifest(repo: Path, relative: str) -> list[Path]:
    manifest = _inside(repo, relative, "thesis manifest")
    if _regular_kind(manifest) != "regular":
        raise QualificationError("thesis corpus manifest is missing")
    sources: list[Path] = []
    for line_number, raw in enumerate(
            manifest.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[1] not in {"CLEAN", "BUG"}:
            raise QualificationError(f"invalid thesis manifest line {line_number}")
        source = _inside(manifest.parent, fields[0], "thesis source")
        if _regular_kind(source) != "regular":
            raise QualificationError(f"thesis source is missing: {fields[0]}")
        sources.append(source)
    if not sources or len(sources) != len(set(sources)):
        raise QualificationError("thesis corpus is empty or duplicated")
    return sources


def _write_unit_compile_database(sources: list[Path], build: Path, clang: Path) -> Path:
    build.mkdir(parents=True, exist_ok=False)
    entries = [
        {
            "directory": str(source.parent),
            "file": str(source),
            "arguments": [str(clang), "-std=gnu11", "-c", str(source)],
        }
        for source in sources
    ]
    path = build / "compile_commands.json"
    path.write_bytes(canonical_json(entries))
    return path


def _load_compile_database(path: Path) -> list[dict[str, Any]]:
    if _regular_kind(path) != "regular":
        raise QualificationError(f"compile database is missing: {path}")
    raw = _read_regular(path, MAX_JSON_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"malformed compile database: {error}") from error
    if not isinstance(value, list) or not value:
        raise QualificationError("compile database is empty")
    result: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict) or not {"directory", "file"} <= set(entry):
            raise QualificationError("compile database entry is malformed")
        directory = Path(entry["directory"])
        file_path = Path(entry["file"])
        if not file_path.is_absolute():
            file_path = directory / file_path
        if "arguments" in entry:
            arguments = entry["arguments"]
            if not isinstance(arguments, list) or any(not isinstance(token, str) for token in arguments):
                raise QualificationError("compile database arguments are malformed")
        elif isinstance(entry.get("command"), str):
            try:
                arguments = shlex.split(entry["command"])
            except ValueError as error:
                raise QualificationError("compile database command is malformed") from error
        else:
            raise QualificationError("compile database entry has no command")
        result.append({
            "directory": directory.resolve(),
            "file": file_path.resolve(),
            "output": entry.get("output", ""),
            "arguments": arguments,
        })
    return result


def _replace_root(value: str, roots: list[tuple[Path, str]]) -> str:
    normalized = value.replace("\\", "/")
    for root, marker in sorted(roots, key=lambda item: len(str(item[0])), reverse=True):
        spelling = str(root.resolve()).replace("\\", "/")
        normalized = normalized.replace(spelling, marker)
    return normalized


def _append_length_prefixed(output: bytearray, value: str) -> None:
    raw = value.encode("utf-8")
    output.extend(f"{len(raw)}:".encode("ascii"))
    output.extend(raw)
    output.extend(b"\n")


def _serialized_execution(execution: dict[str, Any]) -> bytes:
    output = bytearray()
    _append_length_prefixed(output, execution["working_directory"])
    _append_length_prefixed(output, execution["canonical_path"])
    _append_length_prefixed(output, execution["output"])
    output.extend(f"{len(execution['command_line'])}\n".encode("ascii"))
    for argument in execution["command_line"]:
        _append_length_prefixed(output, argument)
    return bytes(output)


def _translation_unit_command_sha256(execution: dict[str, Any]) -> str:
    return sha256_bytes(_serialized_execution(execution))


def _serialized_compile_entry(entry: dict[str, Any]) -> bytes:
    output = bytearray()
    _append_length_prefixed(output, str(entry["directory"]))
    _append_length_prefixed(output, str(entry["file"]))
    _append_length_prefixed(output, entry["output"])
    output.extend(f"{len(entry['arguments'])}\n".encode("ascii"))
    for argument in entry["arguments"]:
        _append_length_prefixed(output, argument)
    return bytes(output)


def _compile_identity(
    entries: list[dict[str, Any]],
    sources: list[Path],
    roots: list[tuple[Path, str]],
) -> str:
    selected = set(source.resolve() for source in sources)
    projection = []
    seen: set[Path] = set()
    for entry in entries:
        if entry["file"] not in selected:
            continue
        seen.add(entry["file"])
        projection.append({
            "directory": _replace_root(str(entry["directory"]), roots),
            "file": _replace_root(str(entry["file"]), roots),
            "arguments": [_replace_root(token, roots) for token in entry["arguments"]],
        })
    if seen != selected:
        missing = sorted(str(path) for path in selected - seen)
        raise QualificationError(f"compile database omits requested inputs: {missing[:3]}")
    return digest_json(projection)


def _path_manifest(paths: Iterable[Path], root: Path) -> list[dict[str, str]]:
    result = []
    for path in sorted(set(item.resolve() for item in paths),
                       key=lambda item: item.relative_to(root).as_posix()):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise QualificationError("input path escapes its source root") from error
        if _regular_kind(path) != "regular":
            raise QualificationError(f"input is not a regular file: {relative}")
        result.append({"path": relative, "sha256": sha256_file(path)})
    return result


def _selected_commands_sha256(commands: list[dict[str, Any]]) -> str:
    return digest_json([
        {
            "path": command["path"],
            "command_ordinal": command["command_ordinal"],
            "phase": command["phase"],
            "execution": command["normalized_execution"],
        }
        for command in commands
    ])


def _input_receipt(
    kind: str,
    sources: list[Path],
    source_root: Path,
    entries: list[dict[str, Any]],
    roots: list[tuple[Path, str]],
    extra_identity: dict[str, Any],
) -> dict[str, Any]:
    source_root = source_root.resolve()
    relative_paths = [path.resolve().relative_to(source_root).as_posix()
                      for path in sorted(set(sources))]
    files = _path_manifest(sources, source_root)
    marker = "$RELEASE_SOURCE" if kind == "release-candidate" else "$REPO"
    commands: list[dict[str, Any]] = []
    for source in sorted(set(path.resolve() for path in sources)):
        selected = sorted(
            (entry for entry in entries if entry["file"] == source),
            key=_serialized_compile_entry,
        )
        if not selected:
            raise QualificationError(f"compile database omits requested input: {source}")
        relative = source.relative_to(source_root).as_posix()
        for ordinal, entry in enumerate(selected):
            execution = {
                "working_directory": str(entry["directory"]),
                "canonical_path": str(source),
                "output": entry["output"],
                "command_line": entry["arguments"],
            }
            normalized = {
                field: _replace_root(execution[field], roots)
                for field in ("working_directory", "canonical_path", "output")
            }
            normalized["command_line"] = [
                _replace_root(token, roots) for token in execution["command_line"]
            ]
            commands.append({
                "path": f"{marker}/{relative}",
                "compile_command_sha256": _translation_unit_command_sha256(execution),
                "command_ordinal": ordinal,
                "phase": "analysis",
                "execution": execution,
                "normalized_execution": normalized,
            })
    commands.sort(key=lambda command: (command["path"], command["command_ordinal"]))
    roots_receipt = [
        {"marker": root_marker, "path": str(root.resolve())}
        for root, root_marker in sorted(roots, key=lambda item: item[1])
    ]
    extra_identity = dict(extra_identity)
    extra_identity["selected_compile_commands_sha256"] = (
        _selected_commands_sha256(commands)
    )
    receipt = {
        "kind": kind,
        "identity_sha256": "",
        "translation_unit_sha256": digest_json(relative_paths),
        "translation_unit_plan_sha256": digest_json(
            [_normalized_command(command) for command in commands]
        ),
        "translation_units": len(relative_paths),
        "source_marker": marker,
        "roots": roots_receipt,
        "files": files,
        "commands": commands,
        "extra": extra_identity,
    }
    receipt["identity_sha256"] = digest_json(_input_identity_material(receipt))
    _validate_input_receipt(receipt, kind)
    return receipt


def _resolve_analyzer_args(
    tokens: list[str], repo: Path, release_source: Path | None,
) -> list[str]:
    values = {"{repo}": str(repo)}
    if release_source is not None:
        values["{release_source}"] = str(release_source)
    result: list[str] = []
    for token in tokens:
        expanded = token
        for placeholder, value in values.items():
            expanded = expanded.replace(placeholder, value)
        if "{" in expanded or "}" in expanded:
            raise QualificationError(f"unknown analyzer argument placeholder: {token}")
        result.append(expanded)
    return result


def _normalization_roots(
    repo: Path, kind: str, source_root: Path, build_root: Path,
) -> list[tuple[Path, str]]:
    roots = [(repo.resolve(), "$REPO")]
    if kind == "unit":
        roots.append((build_root.resolve(), "$UNIT_BUILD"))
    elif kind == "real-repository":
        roots.append((build_root.resolve(), "$BUILD"))
    elif kind == "release-candidate":
        roots.extend([
            (source_root.resolve(), "$RELEASE_SOURCE"),
            (build_root.resolve(), "$RELEASE_BUILD"),
        ])
    else:
        raise QualificationError("unknown workload normalization kind")
    return roots


def _pin_release_command(
    command: list[str], cmake: Path, ninja: Path,
    c_compiler: Path, cxx_compiler: Path,
) -> list[str]:
    replacements = {
        "cmake": str(cmake),
        "clang-20": str(c_compiler),
        "clang++-20": str(cxx_compiler),
    }
    result: list[str] = []
    for token in command:
        if token in replacements:
            result.append(replacements[token])
        elif token == "-DCMAKE_C_COMPILER=clang-20":
            result.append(f"-DCMAKE_C_COMPILER={c_compiler}")
        elif token == "-DCMAKE_CXX_COMPILER=clang++-20":
            result.append(f"-DCMAKE_CXX_COMPILER={cxx_compiler}")
        else:
            result.append(token)
    if "Ninja" in result and not any(
            token.startswith("-DCMAKE_MAKE_PROGRAM=") for token in result):
        result.append(f"-DCMAKE_MAKE_PROGRAM={ninja}")
    return result


def _release_environment(project: dict[str, Any]) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(project.get("environment") or {})
    return environment


def prepare_release_candidate(
    repo: Path,
    workload: dict[str, Any],
    workspace: Path,
    jobs: int,
    cmake: Path,
    ninja: Path,
    c_compiler: Path,
    cxx_compiler: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    sys.path.insert(0, str(repo / "scripts"))
    try:
        import run_realworld_campaign as campaign
    except ImportError as error:
        raise QualificationError("cannot import real-world campaign authority") from error
    manifest_path = _inside(repo, workload["input"]["realworld_manifest"],
                            "real-world manifest")
    manifest = campaign.load_manifest(manifest_path)
    project = campaign.project_by_id(manifest, workload["input"]["project"])
    workspace = workspace.absolute()
    if _regular_kind(workspace) == "missing":
        workspace.mkdir(parents=True)
    if _regular_kind(workspace) != "directory":
        raise QualificationError("release workspace is not a real directory")
    workspace = workspace.resolve()
    try:
        if next(workspace.iterdir(), None) is not None:
            raise QualificationError("release workspace must be empty")
    except OSError as error:
        raise QualificationError("cannot inspect release workspace") from error
    source = workspace / project["id"]
    build = workspace / f"{project['id']}-build"
    commands = (
        ["git", "init", "--quiet", str(source)],
        ["git", "-C", str(source), "remote", "add", "origin", project["repository"]],
        ["git", "-C", str(source), "fetch", "--quiet", "--depth", "1", "origin", project["revision"]],
        ["git", "-C", str(source), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    )
    for command in commands:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        if completed.returncode != 0:
            raise QualificationError(
                f"release-candidate checkout failed: {completed.stdout[-2000:]!r}"
            )
    for operation in project["copies"]:
        source_file = _inside(repo, operation["from"], "release copy source")
        destination = _inside(source, operation["to"], "release copy destination")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, destination)
    if project["copies"] == [] and _git_output(source, ["status", "--porcelain"]):
        raise QualificationError(
            "release-candidate source is dirty before configuration"
        )
    values = {"source": str(source), "build": str(build), "jobs": str(jobs)}
    deadline = time.monotonic() + project["timeout_minutes"] * 60
    for group in ("configure", "build"):
        for raw_command in project["commands"][group]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError("release-candidate preparation timed out")
            command = _pin_release_command(
                campaign._expand(raw_command, values),
                cmake, ninja, c_compiler, cxx_compiler,
            )
            environment = _release_environment(project)
            try:
                completed = subprocess.run(
                    command, cwd=source, env=environment, check=False,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=remaining,
                )
            except subprocess.TimeoutExpired as error:
                raise QualificationError("release-candidate preparation timed out") from error
            if completed.returncode != 0:
                raise QualificationError(
                    f"release-candidate {group} failed: {completed.stdout[-4000:]!r}"
                )
    compile_database = Path(project["compile_database"].format(**values)).resolve()
    if _regular_kind(compile_database) != "regular":
        raise QualificationError("release-candidate compile database is missing")
    _build_toolchain_identity(
        build, source, cmake, ninja, c_compiler, cxx_compiler
    )
    if project["copies"] == [] and _git_output(source, ["status", "--porcelain"]):
        raise QualificationError("release-candidate checkout became dirty during preparation")
    identity = {
        "project": project["id"],
        "repository": project["repository"],
        "revision": project["revision"],
        "manifest_sha256": digest_json(manifest),
        "recipe_sha256": digest_json(campaign.project_recipe(project)),
    }
    return source, build, identity


def _release_manifest_identity(
    repo: Path, workload: dict[str, Any]
) -> dict[str, Any]:
    sys.path.insert(0, str(repo / "scripts"))
    import run_realworld_campaign as campaign
    manifest = campaign.load_manifest(
        _inside(repo, workload["input"]["realworld_manifest"], "real-world manifest")
    )
    project = campaign.project_by_id(manifest, workload["input"]["project"])
    return {
        "project": project["id"],
        "repository": project["repository"],
        "revision": project["revision"],
        "manifest_sha256": digest_json(manifest),
        "recipe_sha256": digest_json(campaign.project_recipe(project)),
    }


def _release_identity(
    repo: Path, workload: dict[str, Any], source: Path
) -> dict[str, Any]:
    identity = _release_manifest_identity(repo, workload)
    if _git_output(source, ["rev-parse", "HEAD"]) != identity["revision"]:
        raise QualificationError("release-candidate revision drift")
    return identity


def _thesis_paths_from_bytes(raw: bytes, manifest_relative: str) -> list[str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise QualificationError("thesis corpus manifest is not UTF-8") from error
    base = PurePosixPath(manifest_relative).parent
    sources: list[str] = []
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[1] not in {"CLEAN", "BUG"}:
            raise QualificationError(f"invalid thesis manifest line {line_number}")
        relative = (base / fields[0]).as_posix()
        _relative(relative, "thesis source")
        sources.append(relative)
    if not sources or len(sources) != len(set(sources)):
        raise QualificationError("thesis corpus is empty or duplicated")
    return sorted(sources)


def _validate_manifest_inputs(
    inputs: dict[str, Any], manifest: dict[str, Any], repo: Path,
    toolchain: dict[str, Any], source_revision: str,
) -> None:
    repo = repo.resolve()
    definitions = {item["kind"]: item for item in manifest["workloads"]}
    source_tree = source_manifest_at_revision(repo, source_revision)
    for kind, item in inputs.items():
        definition = definitions[kind]
        _validate_input_receipt(item, kind)
        file_paths = [entry["path"] for entry in item["files"]]
        file_hashes = {entry["path"]: entry["sha256"] for entry in item["files"]}
        extra = item["extra"]
        selected_sha = extra["selected_compile_commands_sha256"]
        if selected_sha != _selected_commands_sha256(item["commands"]):
            raise QualificationError(f"{kind} manifest compile-plan identity drift")
        if kind == "unit":
            if set(extra) != {
                "corpus_manifest_sha256", "selected_compile_commands_sha256"
            }:
                raise QualificationError("unit manifest identity fields drift")
            manifest_relative = definition["input"]["manifest"]
            raw_manifest = _git_blob(repo, source_revision, manifest_relative)
            expected_paths = _thesis_paths_from_bytes(
                raw_manifest, manifest_relative
            )
            if file_paths != expected_paths:
                raise QualificationError("unit receipt differs from workload manifest")
            if extra["corpus_manifest_sha256"] != sha256_bytes(raw_manifest):
                raise QualificationError("unit corpus manifest identity drift")
        elif kind == "real-repository":
            if set(extra) != {
                "policy", "selected_compile_commands_sha256",
                "repository_source_manifest_sha256", "build_toolchain",
            }:
                raise QualificationError("repository manifest identity fields drift")
            target = definition["input"]["path"].rstrip("/")
            if (extra["policy"] != definition["input"]["policy"] or
                    any(path != target and not path.startswith(target + "/")
                        for path in file_paths)):
                raise QualificationError(
                    "repository receipt differs from workload manifest"
                )
            if extra["repository_source_manifest_sha256"] != digest_json(
                    item["files"]):
                raise QualificationError("repository source manifest identity drift")
            _validate_build_toolchain_identity(
                extra["build_toolchain"], "repository build toolchain", toolchain
            )
        else:
            expected_paths = sorted(definition["input"]["translation_units"])
            if file_paths != expected_paths:
                raise QualificationError(
                    "release-candidate receipt differs from workload manifest"
                )
            expected_identity = _release_manifest_identity(repo, definition)
            expected_fields = {
                *expected_identity,
                "selected_compile_commands_sha256", "build_toolchain",
            }
            if set(extra) != expected_fields or any(
                    extra[field] != value
                    for field, value in expected_identity.items()):
                raise QualificationError(
                    "release-candidate manifest identity drift"
                )
            _validate_build_toolchain_identity(
                extra["build_toolchain"],
                "release-candidate build toolchain", toolchain,
            )
        if kind != "release-candidate":
            for relative, expected_sha in file_hashes.items():
                if sha256_bytes(_git_blob(repo, source_revision, relative)) != expected_sha:
                    raise QualificationError(
                        f"{kind} input file identity drift: {relative}"
                    )
        else:
            release_root = _root_for_marker(item, "$RELEASE_SOURCE")
            if _regular_kind(release_root) == "directory":
                if _git_output(release_root, ["rev-parse", "HEAD"]) != extra["revision"]:
                    raise QualificationError("release-candidate source revision drift")
                for relative, expected_sha in file_hashes.items():
                    path = _inside(release_root, relative, "release-candidate input")
                    if sha256_file(path) != expected_sha:
                        raise QualificationError(
                            f"release-candidate input file identity drift: {relative}"
                        )
        if kind in {"real-repository", "release-candidate"}:
            marker = "$BUILD" if kind == "real-repository" else "$RELEASE_BUILD"
            build_root = _root_for_marker(item, marker)
            if _regular_kind(build_root) == "directory":
                identity = extra["build_toolchain"]
                source_root = (
                    repo if kind == "real-repository"
                    else _root_for_marker(item, "$RELEASE_SOURCE")
                )
                current = _build_toolchain_identity(
                    build_root, source_root,
                    Path(identity["cmake"]), Path(identity["ninja"]),
                    Path(identity["c_compiler"]), Path(identity["cxx_compiler"]),
                )
                if current != identity:
                    raise QualificationError(f"{kind} build toolchain identity drift")
    if source_tree["revision"] != source_revision:
        raise QualificationError("input source revision resolution drift")


def prepare_workloads(
    manifest: dict[str, Any], repo: Path, build: Path, clang: Path,
    work: Path, release_source: Path, release_build: Path,
    cmake: Path, ninja: Path, c_compiler: Path, cxx_compiler: Path,
) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for workload in manifest["workloads"]:
        kind = workload["kind"]
        if kind == "unit":
            sources = _parse_thesis_manifest(repo, workload["input"]["manifest"])
            unit_build = work / "unit-build"
            compile_db = _write_unit_compile_database(sources, unit_build, clang)
            entries = _load_compile_database(compile_db)
            roots = _normalization_roots(repo, kind, repo, unit_build)
            compile_identity = _compile_identity(entries, sources, roots)
            extra = {
                "corpus_manifest_sha256": sha256_file(
                    _inside(repo, workload["input"]["manifest"], "thesis manifest")
                ),
                "selected_compile_commands_sha256": compile_identity,
            }
            source_root = repo
            build_path = unit_build
            file_list = unit_build / "files.txt"
            file_list.write_text(
                "".join(f"{path}\n" for path in sources),
                encoding="utf-8", newline="\n",
            )
            analyzer_args = ["--files", str(file_list)]
        elif kind == "real-repository":
            source_root = repo
            target = _inside(repo, workload["input"]["path"], "repository workload")
            entries = _load_compile_database(build / "compile_commands.json")
            sources = sorted({
                entry["file"] for entry in entries
                if entry["file"] == target or target in entry["file"].parents
            })
            if not sources:
                raise QualificationError("real-repository compile database has no admitted TUs")
            roots = _normalization_roots(repo, kind, repo, build)
            compile_identity = _compile_identity(entries, sources, roots)
            extra = {
                "policy": workload["input"]["policy"],
                "selected_compile_commands_sha256": compile_identity,
                "repository_source_manifest_sha256": digest_json(
                    _path_manifest(sources, repo)
                ),
                "build_toolchain": _build_toolchain_identity(
                    build, repo, cmake, ninja, c_compiler, cxx_compiler
                ),
            }
            build_path = build
            analyzer_args = [str(target), "--policy", workload["input"]["policy"]]
        else:
            source_root = release_source.resolve()
            sources = [
                _inside(source_root, relative, "release-candidate TU")
                for relative in workload["input"]["translation_units"]
            ]
            entries = _load_compile_database(release_build / "compile_commands.json")
            roots = _normalization_roots(
                repo, kind, source_root, release_build
            )
            compile_identity = _compile_identity(entries, sources, roots)
            extra = _release_identity(repo, workload, source_root)
            extra["selected_compile_commands_sha256"] = compile_identity
            extra["build_toolchain"] = _build_toolchain_identity(
                release_build, source_root,
                cmake, ninja, c_compiler, cxx_compiler
            )
            build_path = release_build
            file_list = work / "release-files.txt"
            file_list.write_text(
                "".join(f"{path}\n" for path in sources),
                encoding="utf-8", newline="\n",
            )
            analyzer_args = ["--files", str(file_list)]
        analyzer_args.extend(_resolve_analyzer_args(
            workload["analyzer_args"], repo,
            release_source if kind == "release-candidate" else None,
        ))
        analyzer_args.extend([
            "--build-path", str(build_path),
            "--tu-timeout-seconds", str(workload["tu_timeout_seconds"]),
            "--tu-memory-mib", str(workload["tu_memory_mib"]),
        ])
        prepared.append({
            "definition": workload,
            "args": analyzer_args,
            "source_root": source_root,
            "release_source": release_source,
            "input": _input_receipt(
                kind, sources, source_root, entries, roots, extra
            ),
        })
    return prepared


def _portable_report_path(
    value: Any, repo: Path, release_source: Path | None,
) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise QualificationError("report path is malformed")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise QualificationError("report path is outside the admitted root")
    candidate = candidate.resolve()
    roots = [(repo, "$REPO")]
    if release_source is not None:
        roots.append((release_source, "$RELEASE_SOURCE"))
    for root, marker in sorted(roots, key=lambda item: len(str(item[0])), reverse=True):
        try:
            relative = candidate.relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        return marker if relative == "." else f"{marker}/{relative}"
    raise QualificationError("report path is outside the admitted root")


def semantic_projection(
    report: dict[str, Any], repo: Path, release_source: Path | None,
    expected_input: dict[str, Any] | None = None,
    expected_limits: tuple[int, int] | None = None,
) -> dict[str, Any]:
    _exact_dict(report, {
        "tool", "status", "complete", "exit_code", "coverage", "evidence",
        "finding_counts", "translation_units", "total", "diagnostics",
    }, "analyzer report")
    if report["tool"] != "CodeSkeptic":
        raise QualificationError("analyzer report tool identity drift")
    if report.get("complete") is not True:
        raise QualificationError("analyzer report has no complete verdict")
    _require_int(report.get("exit_code"), "analyzer report exit code", 0, 1)
    coverage = report.get("coverage")
    coverage_fields = {
        "attempted_tus", "analyzed_tus", "broken_tus", "incomplete_functions"
    }
    if (not isinstance(coverage, dict) or set(coverage) != coverage_fields or
            any(isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in coverage.values())):
        raise QualificationError("analyzer report coverage is malformed")
    if (coverage["attempted_tus"] <= 0 or coverage["analyzed_tus"] <= 0 or
            coverage["attempted_tus"] != coverage["analyzed_tus"] or
            coverage["broken_tus"] != 0 or coverage["incomplete_functions"] != 0):
        raise QualificationError("analyzer report coverage is unavailable")
    if expected_input is not None:
        _validate_input_receipt(expected_input, expected_input.get("kind", ""))
        expected_count = len(expected_input["commands"])
        if coverage["attempted_tus"] != expected_count:
            raise QualificationError("analyzer report coverage differs from admitted plan")
    counts = report.get("finding_counts")
    if (not isinstance(counts, dict) or
            set(counts) != {"total", "blocking", "report_only"} or
            any(isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counts.values()) or
            counts["total"] != counts["blocking"] + counts["report_only"]):
        raise QualificationError("analyzer finding counts are malformed")
    diagnostics = report.get("diagnostics")
    _require_int(report["total"], "analyzer diagnostic total", 0, 1 << 62)
    if (not isinstance(diagnostics, list) or len(diagnostics) != counts["total"] or
            report["total"] != counts["total"]):
        raise QualificationError("analyzer diagnostic inventory is malformed")
    diagnostic_projection = []
    for diagnostic in diagnostics:
        _exact_dict(diagnostic, {
            "severity", "rule_id", "capability_tier", "blocks_verdict",
            "fingerprint", "file", "line", "column", "function", "message",
            "notes",
        }, "analyzer diagnostic")
        fingerprint = diagnostic.get("fingerprint")
        if not isinstance(fingerprint, str) or FINGERPRINT.fullmatch(fingerprint) is None:
            raise QualificationError("analyzer diagnostic fingerprint is malformed")
        rule = diagnostic.get("rule_id")
        if (not isinstance(rule, str) or not rule or
                not isinstance(diagnostic["severity"], str) or not diagnostic["severity"] or
                not isinstance(diagnostic["capability_tier"], str) or
                not isinstance(diagnostic["blocks_verdict"], bool) or
                isinstance(diagnostic["line"], bool) or not isinstance(diagnostic["line"], int) or
                isinstance(diagnostic["column"], bool) or not isinstance(diagnostic["column"], int) or
                diagnostic["line"] < 0 or diagnostic["column"] < 0 or
                not isinstance(diagnostic["function"], str) or
                not isinstance(diagnostic["message"], str)):
            raise QualificationError("analyzer diagnostic rule is malformed")
        if not isinstance(diagnostic["notes"], list):
            raise QualificationError("analyzer diagnostic notes are malformed")
        for note in diagnostic["notes"]:
            _exact_dict(note, {"file", "line", "column", "message"}, "diagnostic note")
            if (not isinstance(note["file"], str) or
                    isinstance(note["line"], bool) or not isinstance(note["line"], int) or
                    isinstance(note["column"], bool) or not isinstance(note["column"], int) or
                    note["line"] < 0 or note["column"] < 0 or
                    not isinstance(note["message"], str)):
                raise QualificationError("analyzer diagnostic note is malformed")
            if note["file"]:
                _portable_report_path(note["file"], repo, release_source)
        diagnostic_projection.append({
            "fingerprint": fingerprint,
            "rule_id": rule,
            "capability_tier": diagnostic.get("capability_tier"),
            "blocks_verdict": diagnostic.get("blocks_verdict"),
            "file": _portable_report_path(
                diagnostic.get("file"), repo, release_source
            ),
            "function": diagnostic.get("function") or "",
        })
    diagnostic_projection.sort(key=lambda item: (
        item["fingerprint"], item["rule_id"], item["file"], item["function"]
    ))
    translations = report.get("translation_units")
    if not isinstance(translations, list) or not translations:
        raise QualificationError("analyzer report has no translation-unit receipts")
    translation_projection = []
    observed_plan = []
    for translation in translations:
        _exact_dict(translation, {
            "path", "compile_command_sha256", "command_ordinal", "phase", "status",
            "duration_ms", "peak_memory_kib", "timeout_seconds", "memory_mib",
            "origin", "checkpoint_key_sha256", "payload_sha256",
        }, "translation-unit receipt")
        command_sha = translation["compile_command_sha256"]
        if not isinstance(command_sha, str) or SHA256.fullmatch(command_sha) is None:
            raise QualificationError("translation-unit command identity is malformed")
        if (isinstance(translation["command_ordinal"], bool) or
                not isinstance(translation["command_ordinal"], int) or
                translation["command_ordinal"] < 0 or
                translation["phase"] != "analysis" or
                translation["status"] != "completed" or
                translation["origin"] != "executed" or
                translation["checkpoint_key_sha256"] != "" or
                translation["payload_sha256"] != ""):
            raise QualificationError("translation-unit receipt is not completed")
        for field in ("duration_ms", "peak_memory_kib", "timeout_seconds", "memory_mib"):
            if (isinstance(translation[field], bool) or
                    not isinstance(translation[field], int) or translation[field] < 0):
                raise QualificationError("translation-unit telemetry is malformed")
        if expected_limits is not None and (
                translation["timeout_seconds"] != expected_limits[0] or
                translation["memory_mib"] != expected_limits[1]):
            raise QualificationError("translation-unit resource limit drift")
        portable_path = _portable_report_path(
            translation["path"], repo, release_source
        )
        observed_plan.append({
            "path": portable_path,
            "compile_command_sha256": command_sha,
            "command_ordinal": translation["command_ordinal"],
            "phase": translation["phase"],
        })
        translation_projection.append({
            "path": portable_path,
            "command_ordinal": translation["command_ordinal"],
            "phase": translation["phase"],
            "status": translation["status"],
        })
    translation_projection.sort(key=lambda item: (
        item["phase"], item["path"], item["command_ordinal"],
    ))
    observed_plan.sort(key=lambda item: (item["path"], item["command_ordinal"]))
    if expected_input is not None:
        expected_plan = [
            {
                "path": command["path"],
                "compile_command_sha256": command["compile_command_sha256"],
                "command_ordinal": command["command_ordinal"],
                "phase": command["phase"],
            }
            for command in expected_input["commands"]
        ]
        if observed_plan != expected_plan:
            raise QualificationError("analyzer report translation-unit plan drift")
    evidence = report.get("evidence")
    if (not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS or
            any(not isinstance(value, bool) for value in evidence.values()) or
            any(evidence.values())):
        raise QualificationError("analyzer report contains unavailable evidence flags")
    blocking = sum(1 for diagnostic in diagnostics if diagnostic["blocks_verdict"])
    expected_status = (
        "findings" if blocking else "report-only" if diagnostics else "clean"
    )
    if (counts["blocking"] != blocking or
            counts["report_only"] != len(diagnostics) - blocking or
            report["exit_code"] != (1 if blocking else 0) or
            report["status"] != expected_status):
        raise QualificationError("analyzer report verdict classification drift")
    return {
        "status": report.get("status"),
        "complete": True,
        "exit_code": report["exit_code"],
        "coverage": coverage,
        "finding_counts": counts,
        "diagnostics": diagnostic_projection,
        "translation_units": translation_projection,
    }


def _parse_time_log(raw: bytes) -> tuple[int, int, int, int]:
    text = raw.decode("utf-8", errors="replace")
    user_match = re.search(r"^\s*User time \(seconds\):\s*([0-9.]+)\s*$", text, re.MULTILINE)
    system_match = re.search(r"^\s*System time \(seconds\):\s*([0-9.]+)\s*$", text, re.MULTILINE)
    memory_match = re.search(
        r"^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$",
        text, re.MULTILINE,
    )
    elapsed_match = re.search(
        r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*"
        r"([0-9]+(?::[0-9]+){1,2}(?:\.[0-9]+)?)\s*$",
        text, re.MULTILINE,
    )
    exit_match = re.search(r"^\s*Exit status:\s*(-?[0-9]+)\s*$", text, re.MULTILINE)
    if not user_match or not system_match or not memory_match or not elapsed_match or not exit_match:
        raise QualificationError(
            "GNU time log is missing wall, CPU, peak RSS, or exit evidence"
        )
    try:
        cpu = (Decimal(user_match.group(1)) + Decimal(system_match.group(1))) * 1000
        cpu_ms = int(cpu.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        elapsed_fields = [Decimal(field) for field in elapsed_match.group(1).split(":")]
        if len(elapsed_fields) == 2:
            wall = elapsed_fields[0] * 60 + elapsed_fields[1]
        elif len(elapsed_fields) == 3:
            wall = elapsed_fields[0] * 3600 + elapsed_fields[1] * 60 + elapsed_fields[2]
        else:
            raise InvalidOperation
        wall_ms = int((wall * 1000).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError) as error:
        raise QualificationError("GNU time wall or CPU evidence is malformed") from error
    peak_rss = int(memory_match.group(1))
    exit_status = int(exit_match.group(1))
    if wall_ms <= 0 or cpu_ms < 0 or peak_rss <= 0 or exit_status not in (0, 1):
        raise QualificationError("GNU time evidence is outside the admitted range")
    return wall_ms, cpu_ms, peak_rss, exit_status


def _iteration_artifact_paths(
    kind: str, repetition: int, iteration: int,
) -> list[str]:
    root = (
        f"raw/{kind}/run-{repetition:02d}/"
        f"iteration-{iteration:02d}"
    )
    return [
        f"{root}/report.json",
        f"{root}/stderr.log",
        f"{root}/stdout.log",
        f"{root}/time.txt",
        f"{root}/environment.json",
    ]


def _run_artifact_paths(
    kind: str, repetition: int, measurement_iterations: int,
) -> list[str]:
    return [
        path
        for iteration in range(1, measurement_iterations + 1)
        for path in _iteration_artifact_paths(kind, repetition, iteration)
    ] + [_batch_environment_artifact_path(kind, repetition)]


def _batch_environment_artifact_path(kind: str, repetition: int) -> str:
    return f"raw/{kind}/run-{repetition:02d}/batch-environment.json"


def _batch_environment_scratch_path(
    scratch: Path, kind: str, repetition: int,
) -> Path:
    return scratch / f"{kind}-{repetition:02d}-batch.environment.json"


def _idle_preflight_artifact_path() -> str:
    return "raw/environment-idle-preflight.json"


def _artifact(path: str, data: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": sha256_bytes(data), "size": len(data)}


def _add_artifacts_bounded(
    retained: dict[str, bytes], additions: dict[str, bytes]
) -> None:
    overlap = set(retained).intersection(additions)
    if overlap:
        raise QualificationError("raw artifact path collision")
    total = sum(len(data) for data in retained.values())
    total += sum(len(data) for data in additions.values())
    if total > MAX_BUNDLE_BYTES:
        raise QualificationError("evidence bundle exceeds aggregate size limit")
    retained.update(additions)


def _process_group_exists(process_group: int) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_process_group(
    process: subprocess.Popen[Any], sig: signal.Signals
) -> PermissionError | None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return None
    except PermissionError as error:
        return error
    return None


def _wait_for_process_group_exit(
    process: subprocess.Popen[Any], timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        # Reap a finished group leader before probing the PGID. Darwin can
        # report EPERM when a zombie leader is the last visible group member.
        process.poll()
        if not _process_group_exists(process.pid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _terminate_process_group(
    process: subprocess.Popen[Any],
    failure: str = "qualification process cleanup failed",
) -> None:
    group_failure: str | None = None
    if os.name == "posix":
        term_error = _signal_process_group(process, signal.SIGTERM)
        if not _wait_for_process_group_exit(process, 0.5):
            kill_error = _signal_process_group(process, signal.SIGKILL)
            if not _wait_for_process_group_exit(process, 0.5):
                signal_error = kill_error or term_error
                detail = f": {signal_error}" if signal_error is not None else ""
                group_failure = (
                    "process-group cleanup failed: group remained after SIGKILL"
                    + detail
                )
    else:
        if process.poll() is None:
            process.terminate()
    if process.poll() is None:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired as error:
                raise QualificationError(
                    f"{failure}; direct-process cleanup incomplete"
                ) from error
    if group_failure is not None:
        raise QualificationError(f"{failure}; {group_failure}")


def _run_bounded_process(
    command: list[str], environment: dict[str, str], timeout_seconds: float,
    stdout_path: Path, stderr_path: Path, monitored_paths: list[Path],
    maximum_bytes: int = MAX_LOG_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
        child_setup = None
        if resource is not None:
            def child_setup() -> None:
                resource.setrlimit(
                    resource.RLIMIT_FSIZE, (maximum_bytes, maximum_bytes)
                )
        process = subprocess.Popen(
            command, stdout=stdout_stream, stderr=stderr_stream,
            env=environment, start_new_session=(os.name == "posix"),
            preexec_fn=child_setup,
        )
        failure: str | None = None
        while process.poll() is None:
            if time.monotonic() - started >= timeout_seconds:
                failure = "qualification process timed out"
                break
            for path in (stdout_path, stderr_path, *monitored_paths):
                try:
                    size = path.stat().st_size
                except FileNotFoundError:
                    continue
                if size >= maximum_bytes:
                    failure = f"qualification output exceeds size limit: {path.name}"
                    break
            if failure:
                break
            time.sleep(0.025)
        if failure:
            _terminate_process_group(process, failure)
        else:
            process.wait()
            if os.name == "posix" and _process_group_exists(process.pid):
                failure = "qualification process left live descendants"
                _terminate_process_group(process, failure)
    for path in (stdout_path, stderr_path, *monitored_paths):
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            continue
        if size >= maximum_bytes and failure is None:
            failure = f"qualification output exceeds size limit: {path.name}"
    if failure:
        raise QualificationError(failure)
    if (resource is not None and process.returncode == -signal.SIGXFSZ):
        raise QualificationError("qualification output exceeds size limit")
    return subprocess.CompletedProcess(
        command, process.returncode,
        _read_regular(stdout_path, maximum_bytes),
        _read_regular(stderr_path, maximum_bytes),
    )


def _read_failure_prefix(path: Path) -> bytes:
    if _regular_kind(path) != "regular":
        return b""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        return os.read(descriptor, MAX_LOG_BYTES)
    finally:
        os.close(descriptor)


def _collect_failed_run_artifacts(
    scratch: Path, kind: str, repetition: int, measurement_iterations: int,
) -> dict[str, bytes]:
    retained: dict[str, bytes] = {}
    suffixes = ("json", "stderr.log", "stdout.log", "time.txt", "environment.json")
    for iteration in range(1, measurement_iterations + 1):
        prefix = f"{kind}-{repetition:02d}-{iteration:02d}"
        canonical = _iteration_artifact_paths(kind, repetition, iteration)
        scratch_paths = [scratch / f"{prefix}.{suffix}" for suffix in suffixes]
        for relative, path in zip(canonical, scratch_paths):
            if _regular_kind(path) == "regular":
                retained[relative] = _read_failure_prefix(path)
    batch = _batch_environment_scratch_path(scratch, kind, repetition)
    if _regular_kind(batch) == "regular":
        retained[_batch_environment_artifact_path(kind, repetition)] = (
            _read_failure_prefix(batch)
        )
    return retained


def run_idle_preflight(
    host: dict[str, Any], performance_policy: str,
    measurement_cgroup: Path | None,
) -> tuple[dict[str, Any], bytes]:
    affinity = host["cpu_affinity"]
    before = _capture_environment(
        affinity, measurement_cgroup=measurement_cgroup,
        expected_controller_affinity=host["controller_cpu_affinity"],
    )
    started = time.monotonic_ns()
    time.sleep(ENVIRONMENT_POLICY["idle_seconds"])
    after = _capture_environment(
        affinity, measurement_cgroup=measurement_cgroup,
        expected_controller_affinity=host["controller_cpu_affinity"],
    )
    wall_ms = max(
        1, (time.monotonic_ns() - started + 999_999) // 1_000_000
    )
    decision = _evaluate_idle_environment(
        before, after, wall_ms, affinity, host["host_logical_cpus"],
        ENVIRONMENT_POLICY, performance_policy == "required",
    )
    raw = canonical_json({
        "schema": ENVIRONMENT_SCHEMA,
        "scope": "idle-preflight",
        "wall_ms": wall_ms,
        "before": before,
        "after": after,
        "decision": decision,
    })
    return decision, raw


def run_once(
    binary: Path,
    time_binary: Path,
    prepared: dict[str, Any],
    repetition: int,
    repo: Path,
    scratch: Path,
    performance_policy: str,
    host: dict[str, Any],
    measurement_cgroup: Path | None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    definition = prepared["definition"]
    kind = definition["kind"]
    iterations = definition["measurement_iterations"]
    artifact_data: dict[str, bytes] = {}
    inner_runs: list[dict[str, Any]] = []
    affinity = host["cpu_affinity"]
    batch_before = _capture_environment(
        affinity, measurement_cgroup=measurement_cgroup,
        expected_controller_affinity=host["controller_cpu_affinity"],
    )
    batch_started = time.monotonic_ns()
    for iteration in range(1, iterations + 1):
        prefix = f"{kind}-{repetition:02d}-{iteration:02d}"
        report_path = scratch / f"{prefix}.json"
        time_path = scratch / f"{prefix}.time.txt"
        stdout_path = scratch / f"{prefix}.stdout.log"
        stderr_path = scratch / f"{prefix}.stderr.log"
        environment_path = scratch / f"{prefix}.environment.json"
        command = [
            str(time_binary), "-v", "-o", str(time_path), "--",
            str(binary), *prepared["args"], "--json", str(report_path),
        ]
        if measurement_cgroup is not None:
            command = [
                sys.executable,
                str(ROOT / "scripts" / "run_in_measurement_cgroup.py"),
                "--cgroup", str(measurement_cgroup),
                "--cpus", ",".join(str(cpu) for cpu in affinity),
                "--", *command,
            ]
        environment = os.environ.copy()
        environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
        if (performance_policy == "required" and
                set(os.sched_getaffinity(0)) & set(affinity)):
            raise QualificationError(
                "measurement controller affinity overlaps isolated CPUs"
            )
        before = _capture_environment(
            affinity, measurement_cgroup=measurement_cgroup,
            expected_controller_affinity=host["controller_cpu_affinity"],
        )
        try:
            completed = _run_bounded_process(
                command, environment, definition["wall_timeout_seconds"],
                stdout_path, stderr_path, [report_path, time_path],
            )
        except QualificationError as error:
            raise QualificationError(
                f"{kind} repetition {repetition} iteration {iteration} {error}"
            ) from error
        if (performance_policy == "required" and
                set(os.sched_getaffinity(0)) & set(affinity)):
            raise QualificationError(
                "measurement controller affinity overlaps isolated CPUs"
            )
        after = _capture_environment(
            affinity, measurement_cgroup=measurement_cgroup,
            expected_controller_affinity=host["controller_cpu_affinity"],
        )
        if completed.returncode not in (0, 1):
            raise QualificationError(
                f"{kind} repetition {repetition} iteration {iteration} analyzer "
                f"exit {completed.returncode}: {completed.stderr[-2000:]!r}"
            )
        if _regular_kind(report_path) != "regular":
            raise QualificationError(
                f"{kind} repetition {repetition} iteration {iteration} produced "
                f"no report: {completed.stderr[-2000:]!r}"
            )
        report_raw = _read_regular(report_path, MAX_JSON_BYTES)
        try:
            report = json.loads(report_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise QualificationError(f"{kind} analyzer report is malformed") from error
        if (not isinstance(report, dict) or
                report.get("exit_code") != completed.returncode):
            raise QualificationError(
                f"{kind} process/report exit classification mismatch"
            )
        time_raw = _read_regular(time_path, MAX_LOG_BYTES)
        wall_ms, cpu_ms, peak_rss, time_exit = _parse_time_log(time_raw)
        if time_exit != completed.returncode:
            raise QualificationError(
                f"{kind} GNU time/process exit classification mismatch"
            )
        projection = semantic_projection(
            report, repo,
            prepared["release_source"] if kind == "release-candidate" else None,
            prepared["input"],
            (definition["tu_timeout_seconds"], definition["tu_memory_mib"]),
        )
        semantic_sha = digest_json(projection)
        decision = _evaluate_runtime_environment(
            before, after, wall_ms, affinity,
            host["host_logical_cpus"], ENVIRONMENT_POLICY, False,
        )
        environment_raw = canonical_json({
            "schema": ENVIRONMENT_SCHEMA,
            "scope": "inner-record-only",
            "wall_ms": wall_ms,
            "before": before,
            "after": after,
            "decision": decision,
        })
        _write_new(environment_path, environment_raw)
        paths = _iteration_artifact_paths(kind, repetition, iteration)
        values = (
            report_raw, completed.stderr, completed.stdout, time_raw,
            environment_raw,
        )
        artifact_data.update(dict(zip(paths, values)))
        inner_runs.append({
            "iteration": iteration,
            "semantic_sha256": semantic_sha,
            "exit_code": completed.returncode,
            "metrics": {
                "wall_ms": wall_ms,
                "cpu_ms": cpu_ms,
                "peak_rss_kib": peak_rss,
            },
            "environment": decision,
            "artifacts": paths,
        })
    semantics = {item["semantic_sha256"] for item in inner_runs}
    exits = {item["exit_code"] for item in inner_runs}
    if len(semantics) != 1 or len(exits) != 1:
        raise QualificationError(
            f"{kind} repetition {repetition} inner measurement drift"
        )
    batch_after = _capture_environment(
        affinity, measurement_cgroup=measurement_cgroup,
        expected_controller_affinity=host["controller_cpu_affinity"],
    )
    batch_wall_ms = max(
        1, (time.monotonic_ns() - batch_started + 999_999) // 1_000_000
    )
    gated_wall_ms = sum(
        item["metrics"]["wall_ms"] for item in inner_runs
    )
    batch_path = _batch_environment_artifact_path(kind, repetition)
    try:
        _validate_batch_wall_evidence(
            batch_wall_ms, gated_wall_ms, iterations, ENVIRONMENT_POLICY
        )
        batch_decision = _evaluate_runtime_environment(
            batch_before, batch_after, gated_wall_ms, affinity,
            host["host_logical_cpus"], ENVIRONMENT_POLICY,
            performance_policy == "required",
        )
    except QualificationError as error:
        batch_error = QualificationBatchEnvironmentError(
            str(error), kind, repetition
        )
        failure = _failure_record(
            "batch-environment-error", str(batch_error),
            workload=kind, repetition=repetition,
        )
        _write_new(
            _batch_environment_scratch_path(scratch, kind, repetition),
            canonical_json({
                "schema": ENVIRONMENT_SCHEMA,
                "scope": "performance-batch-rejected",
                "wall_ms": batch_wall_ms,
                "gated_wall_ms": gated_wall_ms,
                "before": batch_before,
                "after": batch_after,
                "failure": failure,
            }),
        )
        raise batch_error from error
    artifact_data[batch_path] = canonical_json({
        "schema": ENVIRONMENT_SCHEMA,
        "scope": "performance-batch",
        "wall_ms": batch_wall_ms,
        "gated_wall_ms": gated_wall_ms,
        "before": batch_before,
        "after": batch_after,
        "decision": batch_decision,
    })
    metrics = {
        "wall_ms": gated_wall_ms,
        "cpu_ms": sum(item["metrics"]["cpu_ms"] for item in inner_runs),
        "peak_rss_kib": max(
            item["metrics"]["peak_rss_kib"] for item in inner_runs
        ),
    }
    batch_valid = metrics["cpu_ms"] >= definition["minimum_batch_cpu_ms"]
    return {
        "repetition": repetition,
        "semantic_sha256": next(iter(semantics)),
        "exit_code": next(iter(exits)),
        "metrics": metrics,
        "measurement_iterations": iterations,
        "batch_valid": batch_valid,
        "environment_valid": batch_decision["valid"],
        "environment": batch_decision,
        "environment_artifact": batch_path,
        "inner_runs": inner_runs,
        "artifacts": _run_artifact_paths(kind, repetition, iterations),
    }, artifact_data


def build_baseline(
    manifest_sha: str,
    host: dict[str, Any],
    source_revision: str,
    toolchain: dict[str, Any],
    workloads: list[dict[str, Any]],
    inputs: dict[str, dict[str, Any]],
    calibration_evidence_path: str,
    calibration_receipt_sha256: str,
    promotion_reason: str,
    previous_baseline_sha256: str | None,
    previous_profile_sha256: str | None,
) -> dict[str, Any]:
    return {
        "schema": BASELINE_SCHEMA,
        "manifest_sha256": manifest_sha,
        "performance_regression_limit_percent": 10,
        "semantic_reference": {
            item["kind"]: {
                "semantic_sha256": item["semantic_sha256"],
                "input_identity_sha256": inputs[item["kind"]]["identity_sha256"],
                "translation_unit_sha256": inputs[item["kind"]]["translation_unit_sha256"],
                "translation_unit_plan_sha256": inputs[item["kind"]]["translation_unit_plan_sha256"],
            }
            for item in workloads
        },
        "profiles": {
            host["class_id"]: {
                "os": host["os"],
                "provenance": {
                    "source_revision": source_revision,
                    "toolchain": toolchain,
                    "calibration": {
                        "evidence_path": calibration_evidence_path,
                        "receipt_sha256": calibration_receipt_sha256,
                    },
                    "promotion": {
                        "reason": promotion_reason,
                        "previous_baseline_sha256": previous_baseline_sha256,
                        "previous_profile_sha256": previous_profile_sha256,
                    },
                },
                "hardware": {field: host[field] for field in HARDWARE_FIELDS},
                "workloads": {
                    item["kind"]: {
                        "semantic_sha256": item["semantic_sha256"],
                        "input_identity_sha256": inputs[item["kind"]]["identity_sha256"],
                        "translation_unit_sha256": inputs[item["kind"]]["translation_unit_sha256"],
                        "translation_unit_plan_sha256": inputs[item["kind"]]["translation_unit_plan_sha256"],
                        "statistics": item["statistics"],
                    }
                    for item in workloads
                },
            }
        },
    }


def _write_baseline_new(path: Path, baseline: dict[str, Any]) -> None:
    validate_baseline(baseline, baseline["manifest_sha256"])
    if _regular_kind(path) != "missing":
        raise QualificationError("baseline establishment refuses to overwrite a path")
    _write_new(path, canonical_json(baseline))


def _measurement_failures(
    manifest: dict[str, Any], workload_receipts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    definitions = {item["kind"]: item for item in manifest["workloads"]}
    for workload in workload_receipts:
        kind = workload["kind"]
        minimum_cpu = definitions[kind]["minimum_batch_cpu_ms"]
        for run in workload["runs"]:
            repetition = run["repetition"]
            if not run["batch_valid"]:
                message = (
                    f"{kind} repetition {repetition} measurement batch CPU "
                    f"is below the pinned minimum "
                    f"({run['metrics']['cpu_ms']} < {minimum_cpu})"
                )
                failures.append(_failure_record(
                    "measurement-batch-too-short", message,
                    workload=kind, repetition=repetition,
                    metric="cpu_ms", statistic="batch",
                    current=run["metrics"]["cpu_ms"], baseline=minimum_cpu,
                ))
            for message in run["environment"]["violations"]:
                failures.append(_failure_record(
                    "environment-invalid", message, workload=kind,
                    repetition=repetition,
                ))
    return failures


def _baseline_gate_failures(
    baseline: dict[str, Any], host: dict[str, Any],
    toolchain: dict[str, Any], inputs: dict[str, Any],
    workload_receipts: list[dict[str, Any]], performance_policy: str,
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    profile = baseline["profiles"].get(host["class_id"])
    profile_matches = _profile_matches(profile, host, toolchain)
    if not profile_matches and performance_policy == "required":
        failures.append(_failure_record(
            "profile-unavailable",
            f"baseline performance profile is unavailable for {host['class_id']}",
        ))
    for workload in workload_receipts:
        kind = workload["kind"]
        reference = baseline["semantic_reference"][kind]
        checks = (
            ("semantic_sha256", workload["semantic_sha256"],
             "semantic-drift", "baseline semantic fingerprint drift"),
            ("input_identity_sha256", inputs[kind]["identity_sha256"],
             "input-identity-drift", "baseline input identity drift"),
            ("translation_unit_sha256", inputs[kind]["translation_unit_sha256"],
             "translation-unit-drift", "baseline translation-unit identity drift"),
            ("translation_unit_plan_sha256",
             inputs[kind]["translation_unit_plan_sha256"],
             "translation-unit-plan-drift",
             "baseline translation-unit plan drift"),
        )
        for field, current, failure_type, message in checks:
            if current != reference[field]:
                failures.append(_failure_record(
                    failure_type, f"{kind} {message}", workload=kind,
                ))
        if profile_matches:
            failures.extend(performance_regressions(
                workload["id"], workload["statistics"],
                profile["workloads"][kind]["statistics"], 10,
            ))
    return failures


def _materialize_calibration_and_baseline(
    args: argparse.Namespace, manifest: dict[str, Any], manifest_sha: str,
    manifest_path: Path, repo: Path, source: dict[str, Any],
    host: dict[str, Any], toolchain: dict[str, Any],
    inputs: dict[str, Any], workloads: list[dict[str, Any]],
    artifacts: dict[str, bytes], started_at: dt.datetime, started_ns: int,
    baseline_output: Path, previous_baseline: dict[str, Any] | None,
    previous_baseline_path: Path | None,
) -> dict[str, Any]:
    if args.calibration_output is None:
        raise QualificationError(
            "baseline promotion requires --calibration-output"
        )
    if args.calibration_evidence_path is None:
        raise QualificationError(
            "baseline promotion requires --calibration-evidence-path"
        )
    if args.promotion_reason is None:
        raise QualificationError("baseline promotion requires --promotion-reason")
    calibration_output = args.calibration_output.resolve()
    if len({calibration_output, baseline_output.resolve(), args.output.resolve()}) != 3:
        raise QualificationError(
            "calibration, baseline, and qualification outputs must be distinct"
        )
    calibration = _calibration_payload(
        source, manifest_sha, host, toolchain, inputs, workloads,
        started_at, started_ns, artifacts,
    )
    _validate_calibration_payload(calibration, manifest)
    write_receipt(calibration_output, calibration, artifacts)
    verified = verify_receipt(
        calibration_output, manifest_path, baseline_output, repo, None,
    )
    if verified.get("schema") != CALIBRATION_SCHEMA:
        raise QualificationError("calibration evidence verification drift")
    previous_baseline_sha = None
    previous_profile_sha = None
    if previous_baseline is not None:
        if previous_baseline_path is None:
            raise QualificationError("baseline promotion predecessor path is missing")
        previous_baseline_sha = sha256_file(previous_baseline_path)
        previous_profile = previous_baseline["profiles"].get(host["class_id"])
        if previous_profile is not None:
            previous_profile_sha = digest_json(previous_profile)
    baseline = build_baseline(
        manifest_sha, host, source["revision"], toolchain, workloads, inputs,
        args.calibration_evidence_path,
        sha256_file(calibration_output / "receipt.json"),
        args.promotion_reason,
        previous_baseline_sha,
        previous_profile_sha,
    )
    if previous_baseline is not None:
        if baseline["semantic_reference"] != previous_baseline["semantic_reference"]:
            raise QualificationError(
                "performance baseline promotion cannot normalize semantic drift"
            )
        baseline["profiles"] = {
            **previous_baseline["profiles"],
            host["class_id"]: baseline["profiles"][host["class_id"]],
        }
    _write_baseline_new(baseline_output, baseline)
    return baseline


def _persist_rejection(
    output: Path, source: dict[str, Any], manifest: dict[str, Any],
    manifest_path: Path, baseline_path: Path, repo: Path,
    performance_policy: str, host: dict[str, Any], toolchain: dict[str, Any],
    inputs: dict[str, Any], started_at: dt.datetime, started_ns: int,
    artifacts: dict[str, bytes], error: QualificationError,
) -> None:
    output_kind = _regular_kind(output)
    if output_kind == "directory" and any(output.iterdir()):
        raise QualificationError(
            "rejected evidence refuses to overwrite a non-empty output"
        )
    if output_kind not in {"missing", "directory"}:
        raise QualificationError("cannot persist rejected evidence at non-directory output")
    baseline = None
    baseline_sha = None
    baseline_profile = None
    if _regular_kind(baseline_path) == "regular":
        baseline = load_baseline(baseline_path, digest_json(manifest))
        baseline_sha = sha256_file(baseline_path)
        if host["class_id"] in baseline["profiles"]:
            baseline_profile = host["class_id"]
    payload = _rejected_payload(
        source, digest_json(manifest), performance_policy, host, toolchain,
        inputs, started_at, started_ns, error, artifacts,
        baseline_sha, baseline_profile,
    )
    _validate_rejected_payload(payload, manifest, baseline)
    write_receipt(output, payload, artifacts)
    verified = verify_receipt(output, manifest_path, baseline_path, repo)
    if verified.get("status") != "rejected":
        raise QualificationError("rejected evidence verification drift")


def _finalize_qualification(
    args: argparse.Namespace, manifest: dict[str, Any], manifest_sha: str,
    manifest_path: Path, baseline_path: Path, output: Path, repo: Path,
    source: dict[str, Any], host: dict[str, Any], toolchain: dict[str, Any],
    inputs: dict[str, Any], workload_receipts: list[dict[str, Any]],
    artifacts: dict[str, bytes], started_at: dt.datetime, started_ns: int,
) -> dict[str, Any]:
    measurement_failures = _measurement_failures(manifest, workload_receipts)
    if measurement_failures:
        raise QualificationDecisionError(
            measurement_failures, workload_receipts
        )
    if args.establish_baseline:
        baseline = _materialize_calibration_and_baseline(
            args, manifest, manifest_sha, manifest_path, repo, source, host,
            toolchain, inputs, workload_receipts, artifacts, started_at,
            started_ns, baseline_path, None, None,
        )
    else:
        baseline = load_baseline(baseline_path, manifest_sha)
        if args.baseline_authority_root is None:
            raise QualificationError(
                "qualification requires --baseline-authority-root"
            )
        authority = args.baseline_authority_root.resolve()
        verify_baseline_authority(
            baseline, authority,
            authority / "scripts" / "determinism_workloads.json",
        )
    profile = baseline["profiles"].get(host["class_id"])
    profile_matches = _profile_matches(profile, host, toolchain)
    gate_failures = _baseline_gate_failures(
        baseline, host, toolchain, inputs, workload_receipts,
        args.performance_policy,
    )
    promotion_needed = bool(gate_failures) or (
        args.candidate_baseline_output is not None and not profile_matches
    )
    if args.candidate_baseline_output is not None:
        if not promotion_needed:
            raise QualificationError(
                "candidate baseline requested but the pinned baseline already passes"
            )
        if any(record["type"] not in {
                "performance-regression", "profile-unavailable"
        } for record in gate_failures):
            raise QualificationDecisionError(gate_failures, workload_receipts)
        _materialize_calibration_and_baseline(
            args, manifest, manifest_sha, manifest_path, repo, source, host,
            toolchain, inputs, workload_receipts, artifacts, started_at,
            started_ns, args.candidate_baseline_output.resolve(), baseline,
            baseline_path,
        )
        if gate_failures:
            gate_failures[0] = {
                **gate_failures[0],
                "message": (
                    f"{gate_failures[0]['message']}; review and promote the "
                    "generated candidate baseline"
                ),
            }
        else:
            gate_failures.append(_failure_record(
                "profile-unavailable",
                f"baseline performance profile is unavailable for "
                f"{host['class_id']}; review and promote the generated "
                "candidate baseline",
            ))
        raise QualificationDecisionError(gate_failures, workload_receipts)
    if gate_failures:
        raise QualificationDecisionError(gate_failures, workload_receipts)
    finished_at = dt.datetime.now(dt.timezone.utc)
    inventory = sorted(
        (_artifact(path, data) for path, data in artifacts.items()),
        key=lambda item: item["path"],
    )
    payload = {
        "schema": RECEIPT_SCHEMA,
        "status": "accepted",
        "source": source,
        "configuration": {
            "manifest_sha256": manifest_sha,
            "repetitions": 10,
            "performance_regression_limit_percent": 10,
            "performance_policy": args.performance_policy,
            "environment_policy": ENVIRONMENT_POLICY,
        },
        "host": host,
        "toolchain": toolchain,
        "inputs": inputs,
        "workloads": workload_receipts,
        "baseline": {
            "profile": host["class_id"] if profile_matches else None,
            "sha256": sha256_file(baseline_path),
            "semantic_gate": "pass",
            "performance_gate": "pass" if profile_matches else "not-gated",
            "regressions": [],
        },
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": round((time.monotonic_ns() - started_ns) / 1_000_000),
        "failures": [],
        "artifacts": inventory,
    }
    validate_receipt_payload(payload, manifest, baseline)
    write_receipt(output, payload, artifacts)
    verify_receipt(
        output, manifest_path, baseline_path, repo,
        None if args.establish_baseline else args.baseline_authority_root,
    )
    return payload


def run_qualification(args: argparse.Namespace) -> dict[str, Any]:
    repo = args.repo_root.resolve()
    build = args.build_path.resolve()
    binary = args.binary.resolve()
    clang = args.clang.resolve()
    time_binary = args.time_binary.resolve()
    cmake = args.cmake.resolve()
    ninja = args.ninja.resolve()
    c_compiler = args.c_compiler.resolve()
    cxx_compiler = args.cxx_compiler.resolve()
    output = args.output.resolve()
    manifest_path = args.manifest.resolve()
    baseline_path = args.baseline.resolve()
    for path, label in (
        (binary, "analyzer"), (clang, "Clang"), (time_binary, "GNU time"),
        (cmake, "CMake"), (ninja, "Ninja"),
        (c_compiler, "C compiler"), (cxx_compiler, "C++ compiler"),
    ):
        if _regular_kind(path) != "regular":
            raise QualificationError(f"{label} binary is missing")
    if _regular_kind(repo) != "directory" or _regular_kind(build) != "directory":
        raise QualificationError("repository or build directory is missing")
    manifest = load_manifest(manifest_path)
    if args.repetitions != manifest["repetitions"] or args.repetitions != 10:
        raise QualificationError("CLI repetitions must be exactly ten")
    source = source_manifest(repo)
    if source["revision"] != args.revision:
        raise QualificationError("requested revision differs from repository HEAD")
    if _git_output(repo, ["status", "--porcelain"]):
        raise QualificationError("tracked repository state is dirty")
    measurement_cgroup = (
        args.measurement_cgroup.resolve()
        if args.measurement_cgroup is not None else None
    )
    host = host_identity(
        args.hardware_class, args.performance_policy, measurement_cgroup
    )
    toolchain = toolchain_identity(
        binary, clang, time_binary, cmake, ninja, c_compiler, cxx_compiler
    )
    manifest_sha = digest_json(manifest)
    started_at = dt.datetime.now(dt.timezone.utc)
    started = time.monotonic_ns()
    artifacts: dict[str, bytes] = {}
    inputs: dict[str, Any] = {}
    try:
        release_workload = next(
            item for item in manifest["workloads"]
            if item["kind"] == "release-candidate"
        )
        if args.prepare_release_candidate:
            if args.release_workspace is None:
                raise QualificationError(
                    "release preparation requires --release-workspace"
                )
            release_source, release_build, _ = prepare_release_candidate(
                repo, release_workload, args.release_workspace, args.jobs,
                cmake, ninja, c_compiler, cxx_compiler,
            )
        else:
            if args.release_source is None or args.release_build is None:
                raise QualificationError(
                    "qualification requires prepared release source and build paths"
                )
            release_source = args.release_source.resolve()
            release_build = args.release_build.resolve()
        if (_regular_kind(release_source) != "directory" or
                _regular_kind(release_build) != "directory"):
            raise QualificationError("prepared release-candidate paths are missing")
        with tempfile.TemporaryDirectory(
                prefix="codeskeptic-determinism-") as directory:
            scratch = Path(directory)
            prepared = prepare_workloads(
                manifest, repo, build, clang, scratch / "inputs",
                release_source, release_build,
                cmake, ninja, c_compiler, cxx_compiler,
            )
            inputs = {
                workload["definition"]["kind"]: workload["input"]
                for workload in prepared
            }
            preflight, preflight_raw = run_idle_preflight(
                host, args.performance_policy, measurement_cgroup
            )
            _add_artifacts_bounded(
                artifacts,
                {_idle_preflight_artifact_path(): preflight_raw},
            )
            if not preflight["valid"]:
                raise QualificationPreflightError(preflight["violations"])
            runs_by_kind: dict[str, list[dict[str, Any]]] = {
                kind: [] for kind in KINDS
            }
            for repetition in range(1, 11):
                for workload in prepared:
                    kind = workload["definition"]["kind"]
                    try:
                        run, run_artifacts = run_once(
                            binary, time_binary, workload, repetition, repo,
                            scratch, args.performance_policy, host,
                            measurement_cgroup,
                        )
                    except QualificationError:
                        _add_artifacts_bounded(
                            artifacts,
                            _collect_failed_run_artifacts(
                                scratch, kind, repetition,
                                workload["definition"]["measurement_iterations"],
                            ),
                        )
                        raise
                    runs_by_kind[kind].append(run)
                    _add_artifacts_bounded(artifacts, run_artifacts)
            workload_receipts = []
            for workload in prepared:
                definition = workload["definition"]
                kind = definition["kind"]
                runs = runs_by_kind[kind]
                semantics = {run["semantic_sha256"] for run in runs}
                if len(semantics) != 1:
                    raise QualificationError(
                        f"{kind} semantic drift across ten repetitions"
                    )
                workload_receipts.append({
                    "id": definition["id"],
                    "kind": kind,
                    "semantic_sha256": next(iter(semantics)),
                    "runs": runs,
                    "statistics": {
                        metric_name: metric_statistics(
                            [run["metrics"][metric_name] for run in runs]
                        )
                        for metric_name in METRICS
                    },
                })
        return _finalize_qualification(
            args, manifest, manifest_sha, manifest_path, baseline_path, output,
            repo, source, host, toolchain, inputs, workload_receipts, artifacts,
            started_at, started,
        )
    except QualificationError as error:
        try:
            _persist_rejection(
                output, source, manifest, manifest_path, baseline_path, repo,
                args.performance_policy, host, toolchain, inputs, started_at,
                started, artifacts, error,
            )
        except QualificationError as persistence_error:
            raise QualificationError(
                f"{error}; rejected evidence persistence failed: "
                f"{persistence_error}"
            ) from error
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "scripts" / "determinism_workloads.json")
    parser.add_argument("--baseline", type=Path,
                        default=ROOT / "scripts" / "determinism_baseline.json")
    parser.add_argument("--verify-receipt", type=Path)
    parser.add_argument("--verify-baseline-authority", action="store_true")
    parser.add_argument("--verify-bootstrap-promotion", action="store_true")
    parser.add_argument("--verify-baseline-promotion", action="store_true")
    parser.add_argument("--baseline-authority-root", type=Path)
    parser.add_argument("--base-revision")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--build-path", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--hardware-class")
    parser.add_argument("--measurement-cgroup", type=Path)
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--clang", type=Path, default=Path("/usr/bin/clang-20"))
    parser.add_argument("--time-binary", type=Path, default=Path("/usr/bin/time"))
    parser.add_argument("--cmake", type=Path, default=Path("/usr/bin/cmake"))
    parser.add_argument("--ninja", type=Path, default=Path("/usr/bin/ninja"))
    parser.add_argument("--c-compiler", type=Path, default=Path("/usr/bin/clang-20"))
    parser.add_argument("--cxx-compiler", type=Path, default=Path("/usr/bin/clang++-20"))
    parser.add_argument("--prepare-release-candidate", action="store_true")
    parser.add_argument("--release-workspace", type=Path)
    parser.add_argument("--release-source", type=Path)
    parser.add_argument("--release-build", type=Path)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--establish-baseline", action="store_true")
    parser.add_argument("--candidate-baseline-output", type=Path)
    parser.add_argument("--calibration-output", type=Path)
    parser.add_argument("--calibration-evidence-path")
    parser.add_argument("--promotion-reason")
    parser.add_argument(
        "--performance-policy", choices=("required", "record-only"),
        default="required",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.verify_baseline_promotion:
            if (args.verify_receipt is not None or
                    args.verify_baseline_authority or
                    args.verify_bootstrap_promotion):
                parser.error("baseline promotion verification is an exclusive mode")
            run_only = (
                args.binary, args.build_path, args.revision, args.output,
                args.hardware_class, args.measurement_cgroup, args.repetitions,
                args.release_workspace,
                args.release_source, args.release_build,
                args.candidate_baseline_output, args.calibration_output,
                args.calibration_evidence_path, args.promotion_reason,
                args.baseline_authority_root,
            )
            if (any(value is not None for value in run_only) or
                    args.prepare_release_candidate or args.establish_baseline):
                parser.error(
                    "--verify-baseline-promotion cannot be combined with run options"
                )
            if args.repo_root is None or args.base_revision is None:
                parser.error(
                    "--verify-baseline-promotion requires --repo-root and "
                    "--base-revision"
                )
            verify_baseline_promotion(
                args.repo_root.resolve(), args.base_revision,
                args.baseline.resolve(), args.manifest.resolve(),
            )
            print("DETERMINISM_BASELINE_PROMOTION_OK")
            return 0
        if args.verify_bootstrap_promotion:
            if (args.verify_receipt is not None or
                    args.verify_baseline_authority or
                    args.verify_baseline_promotion):
                parser.error("bootstrap promotion verification is an exclusive mode")
            run_only = (
                args.binary, args.build_path, args.revision, args.output,
                args.hardware_class, args.measurement_cgroup, args.repetitions,
                args.release_workspace,
                args.release_source, args.release_build,
                args.candidate_baseline_output, args.calibration_output,
                args.calibration_evidence_path, args.promotion_reason,
                args.baseline_authority_root,
            )
            if (any(value is not None for value in run_only) or
                    args.prepare_release_candidate or args.establish_baseline):
                parser.error(
                    "--verify-bootstrap-promotion cannot be combined with run options"
                )
            if args.repo_root is None or args.base_revision is None:
                parser.error(
                    "--verify-bootstrap-promotion requires --repo-root and "
                    "--base-revision"
                )
            verify_bootstrap_promotion(
                args.repo_root.resolve(), args.base_revision,
                args.baseline.resolve(), args.manifest.resolve(),
            )
            print("DETERMINISM_BASELINE_BOOTSTRAP_OK")
            return 0
        if args.verify_baseline_authority:
            if (args.verify_receipt is not None or
                    args.verify_baseline_promotion):
                parser.error("baseline-authority and receipt verification are exclusive")
            run_only = (
                args.binary, args.repo_root, args.build_path, args.revision,
                args.output, args.hardware_class, args.measurement_cgroup,
                args.repetitions,
                args.release_workspace, args.release_source, args.release_build,
                args.candidate_baseline_output, args.calibration_output,
                args.calibration_evidence_path, args.promotion_reason,
                args.base_revision,
            )
            if any(value is not None for value in run_only) or args.prepare_release_candidate or args.establish_baseline:
                parser.error("--verify-baseline-authority cannot be combined with run options")
            if args.baseline_authority_root is None:
                parser.error(
                    "--verify-baseline-authority requires --baseline-authority-root"
                )
            raw_manifest = load_manifest(args.manifest.resolve())
            pinned = load_baseline(
                args.baseline.resolve(), digest_json(raw_manifest)
            )
            verify_baseline_authority(
                pinned, args.baseline_authority_root.resolve(),
                args.manifest.resolve(),
            )
            print(
                "DETERMINISM_BASELINE_AUTHORITY_OK "
                f"profiles={len(pinned['profiles'])}"
            )
            return 0
        if args.verify_receipt is not None:
            run_only = (
                args.binary, args.build_path, args.revision,
                args.output, args.hardware_class, args.measurement_cgroup,
                args.repetitions,
                args.release_workspace, args.release_source, args.release_build,
                args.candidate_baseline_output, args.calibration_output,
                args.calibration_evidence_path, args.promotion_reason,
                args.base_revision,
            )
            if any(value is not None for value in run_only) or args.prepare_release_candidate or args.establish_baseline:
                parser.error("--verify-receipt cannot be combined with run options")
            receipt = verify_receipt(
                args.verify_receipt.resolve(), args.manifest.resolve(),
                args.baseline.resolve(),
                args.repo_root.resolve() if args.repo_root is not None else ROOT,
                args.baseline_authority_root,
            )
            if receipt["status"] == "accepted":
                if args.baseline_authority_root is None:
                    raise QualificationError(
                        "accepted receipt verification requires "
                        "--baseline-authority-root"
                    )
                print(
                    "DETERMINISM_QUALIFICATION_OK "
                    f"mode=verify workloads={len(receipt['workloads'])} repetitions=10"
                )
            elif receipt["status"] == "calibration":
                print(
                    "DETERMINISM_CALIBRATION_OK "
                    f"mode=verify workloads={len(receipt['workloads'])} repetitions=10"
                )
            else:
                print("DETERMINISM_REJECTED_EVIDENCE_OK mode=verify")
            return 0
        required = {
            "--binary": args.binary,
            "--repo-root": args.repo_root,
            "--build-path": args.build_path,
            "--revision": args.revision,
            "--output": args.output,
            "--hardware-class": args.hardware_class,
            "--repetitions": args.repetitions,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            parser.error("run mode requires " + ", ".join(missing))
        if args.base_revision is not None:
            parser.error("--base-revision is only valid for bootstrap verification")
        if not 1 <= args.jobs <= 8:
            parser.error("--jobs must be from 1 to 8")
        promotion_mode = args.establish_baseline or args.candidate_baseline_output is not None
        promotion_fields = (
            args.calibration_output, args.calibration_evidence_path,
            args.promotion_reason,
        )
        if promotion_mode and any(value is None for value in promotion_fields):
            parser.error(
                "baseline promotion requires --calibration-output, "
                "--calibration-evidence-path, and --promotion-reason"
            )
        if not promotion_mode and any(value is not None for value in promotion_fields):
            parser.error("calibration/promotion options require a baseline promotion mode")
        if args.establish_baseline and args.candidate_baseline_output is not None:
            parser.error("initial establishment and candidate promotion are exclusive")
        if promotion_mode and args.performance_policy != "required":
            parser.error(
                "baseline establishment or promotion requires required performance policy"
            )
        if not args.establish_baseline and args.baseline_authority_root is None:
            parser.error("qualification requires --baseline-authority-root")
        receipt = run_qualification(args)
        print(
            "DETERMINISM_QUALIFICATION_OK "
            f"mode=run workloads={len(receipt['workloads'])} repetitions=10 "
            f"hardware_class={receipt['host']['class_id']}"
        )
        return 0
    except QualificationError as error:
        print(f"DETERMINISM_QUALIFICATION_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
