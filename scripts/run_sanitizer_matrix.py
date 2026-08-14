#!/usr/bin/env python3
"""Run and verify the bounded Phase 10 sanitizer runtime matrix."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
FUZZ_RUNNER_PATH = ROOT / "scripts" / "run_fuzz_campaign.py"
FUZZ_SPEC = importlib.util.spec_from_file_location(
    "codeskeptic_fuzz_runner", FUZZ_RUNNER_PATH)
if not FUZZ_SPEC or not FUZZ_SPEC.loader:
    raise RuntimeError("cannot load fuzz campaign runner")
FUZZ_RUNNER = importlib.util.module_from_spec(FUZZ_SPEC)
FUZZ_SPEC.loader.exec_module(FUZZ_RUNNER)

SCHEMA = "codeskeptic-sanitizer-receipt-v1"
FUZZ_MODE = "smoke"
# LLVM/Clang sanitizer builds are memory-heavy.  Two compile jobs keep the
# complete matrix bounded on 16 GiB developer and hosted CI machines.
BUILD_JOBS = 2
PROFILES = {
    "address": {
        "runtime_environment": {
            # LLVM's BumpPtrAllocator uses explicit ASAN poisoning in inline
            # headers.  System Clang DSOs are not ASAN-instrumented, so their
            # allocations cannot pair that poison with an inline unpoison.
            # Heap redzones, leak checks, and the runtime tripwire stay active.
            "ASAN_OPTIONS": (
                "abort_on_error=1:halt_on_error=1:"
                "allocator_may_return_null=0:strict_string_checks=1:"
                "detect_leaks=1:allow_user_poisoning=0"
            ),
            "LSAN_OPTIONS": "exitcode=23",
        },
        "tripwire_markers": (b"AddressSanitizer",),
    },
    "undefined": {
        "runtime_environment": {
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        },
        "tripwire_markers": (
            b"runtime error: signed integer overflow",
            b"UndefinedBehaviorSanitizer",
        ),
    },
}
EXPECTED_GATES = (
    "runtime_tripwire",
    "focused_serial_worker",
    "ctest_complete",
    "single_process_complete",
    "analyzer_clean",
    "analyzer_finding",
    "analyzer_invalid_input",
    "analyzer_whole_program",
    "mcp_sequential",
    "fuzz_smoke",
)
FUZZ_TARGETS = tuple(target["binary"] for target in FUZZ_RUNNER.EXPECTED_TARGETS)
SANITIZER_MARKERS = (
    b"ERROR: AddressSanitizer",
    b"AddressSanitizer:DEADLYSIGNAL",
    b"ERROR: LeakSanitizer",
    b"LeakSanitizer:",
    b"runtime error:",
    b"UndefinedBehaviorSanitizer",
    b"ThreadSanitizer",
)
SOURCE_ROOTS = (
    ROOT / "CMakeLists.txt",
    ROOT / ".gitattributes",
    ROOT / ".github" / "workflows",
    ROOT / "Dockerfile",
    ROOT / "action.yml",
    ROOT / "src",
    ROOT / "fuzz",
    ROOT / "scripts",
    ROOT / "tests",
    ROOT / "docs",
    ROOT / "profiles",
)
IGNORED_SOURCE_PARTS = {"__pycache__"}
IGNORED_SOURCE_SUFFIXES = {".pyc", ".pyo"}
IGNORED_SOURCE_PREFIXES = (
    # Evidence trees are outputs, not source. Excluding every phase prevents
    # later receipts from invalidating an otherwise exact source manifest or
    # creating a cross-matrix hash cycle.
    "docs/evidence/",
    # The human-readable entry is also an output of the matrix.
    "docs/devlog/changelog.md",
)
SANITIZER_ENVIRONMENT = {
    "ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS", "TSAN_OPTIONS",
    "MSAN_OPTIONS", "HWASAN_OPTIONS",
}


class MatrixError(RuntimeError):
    """The matrix cannot produce or verify accepted evidence."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def _regular_files(paths: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file():
            files.add(path)
        elif path.is_dir():
            for candidate in path.rglob("*"):
                if not candidate.is_file():
                    continue
                relative = candidate.relative_to(ROOT)
                if (IGNORED_SOURCE_PARTS.intersection(relative.parts) or
                        candidate.suffix in IGNORED_SOURCE_SUFFIXES or
                        any(relative.as_posix().startswith(prefix)
                            for prefix in IGNORED_SOURCE_PREFIXES)):
                    continue
                files.add(candidate)
        else:
            raise MatrixError(f"source manifest path is missing: {path}")
    return sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())


def source_manifest() -> dict[str, Any]:
    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in _regular_files(SOURCE_ROOTS)
    ]
    return {
        "algorithm": "sha256",
        "file_count": len(entries),
        "digest": sha256_bytes(canonical_json(entries)),
    }


def _inside_root(path: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise MatrixError(f"{label} must be inside the repository") from error
    if resolved == ROOT:
        raise MatrixError(f"{label} cannot be the repository root")
    return resolved


def _validated_output(path: Path, test_build: Path, fuzz_build: Path) -> Path:
    """Resolve a receipt path without overlapping either build tree."""
    output = path.resolve()
    if output == ROOT:
        raise MatrixError("receipt output cannot be the repository root")
    for build in (test_build, fuzz_build):
        if (output == build or output in build.parents or
                build in output.parents):
            raise MatrixError("receipt output overlaps a build directory")
    return output


def _read_cache(build: Path) -> dict[str, str]:
    cache_path = build / "CMakeCache.txt"
    try:
        lines = cache_path.read_text(encoding="utf-8", errors="strict").splitlines()
    except OSError as error:
        raise MatrixError(f"cannot read configured build cache: {error}") from error
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        key_type, value = line.split("=", 1)
        key = key_type.split(":", 1)[0]
        values[key] = value
    return values


def _validate_build(build: Path, profile: str, *, fuzz: bool) -> dict[str, str]:
    values = _read_cache(build)
    if values.get("CODESKEPTIC_SANITIZER") != profile:
        raise MatrixError(f"sanitizer profile mismatch in {build.name}")
    expected_tests = "OFF" if fuzz else "ON"
    expected_fuzzers = "ON" if fuzz else "OFF"
    if (values.get("CODESKEPTIC_BUILD_TESTS") != expected_tests or
            values.get("CODESKEPTIC_BUILD_FUZZERS") != expected_fuzzers):
        raise MatrixError(f"build role mismatch in {build.name}")
    compiler = values.get("CMAKE_CXX_COMPILER", "")
    if not compiler or not Path(compiler).is_file():
        raise MatrixError(f"missing configured compiler in {build.name}")
    completed = subprocess.run(
        [compiler, "--version"], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if completed.returncode != 0 or b"clang" not in completed.stdout.lower():
        raise MatrixError("sanitizer matrix requires a working Clang compiler")
    return values


def _binary(build: Path, relative: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    candidates = (
        build / f"{relative}{suffix}",
        build / Path(relative).parent / "Release" /
        f"{Path(relative).name}{suffix}",
    )
    for candidate in candidates:
        if candidate.is_file():
            resolved = candidate.resolve()
            try:
                resolved.relative_to(build)
            except ValueError as error:
                raise MatrixError("matrix binary escapes its build directory") from error
            return resolved
    raise MatrixError(f"missing matrix binary: {relative}")


def _instrumentation_evidence(build: Path, profile: str,
                              *, fuzz: bool) -> dict[str, Any]:
    compile_db = build / "compile_commands.json"
    try:
        commands = json.loads(compile_db.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot inspect compile commands: {error}") from error
    if not isinstance(commands, list):
        raise MatrixError("compile commands are not a JSON array")
    required_sources = ["src/config/Config.cpp"]
    if fuzz:
        required_sources.extend(f"fuzz/Fuzz{name}.cpp" for name in (
            "Config", "CompileDatabase", "Summary", "McpJsonRpc"))
    else:
        required_sources.append("tests/BrokenTuTest.cpp")
    flag = f"-fsanitize={profile}"
    selected: dict[str, str] = {}
    for suffix in required_sources:
        matches = [entry for entry in commands
                   if str(entry.get("file", "")).replace("\\", "/").endswith(suffix)]
        if len(matches) != 1:
            raise MatrixError(f"expected one compile command for {suffix}")
        command = matches[0].get("command")
        if not isinstance(command, str):
            arguments = matches[0].get("arguments")
            if not isinstance(arguments, list):
                raise MatrixError(f"missing compile argv for {suffix}")
            command = " ".join(str(value) for value in arguments)
        if flag not in command or "-fno-omit-frame-pointer" not in command:
            raise MatrixError(f"uninstrumented compile command for {suffix}")
        if fuzz and suffix.startswith("fuzz/") and "-fsanitize=fuzzer" not in command:
            raise MatrixError(f"fuzzer wrapper lacks libFuzzer flags: {suffix}")
        if fuzz and suffix.startswith("src/") and "-fsanitize=fuzzer-no-link" not in command:
            raise MatrixError("production parser core lacks fuzzer-no-link coverage")
        if profile == "undefined" and "-fno-sanitize-recover=undefined" not in command:
            raise MatrixError(f"UBSAN recovery is enabled for {suffix}")
        selected[suffix] = sha256_bytes(command.encode())

    graph_files = []
    ninja = build / "build.ninja"
    if ninja.is_file():
        graph_files.append(ninja)
    graph_files.extend(sorted(build.rglob("link.txt")))
    if not graph_files:
        raise MatrixError("cannot find generated link command evidence")
    graph_bytes = b"\n".join(path.read_bytes() for path in graph_files)
    if flag.encode() not in graph_bytes:
        raise MatrixError("generated link graph lacks sanitizer runtime")
    target_names = FUZZ_TARGETS if fuzz else (
        "codeskeptic", "codeskeptic_tests", "codeskeptic_sanitizer_tripwire")
    for target in target_names:
        if target.encode() not in graph_bytes:
            raise MatrixError(f"generated link graph lacks target {target}")
    return {
        "compile_commands_sha256": sha256_file(compile_db),
        "selected_compile_command_sha256": selected,
        "link_graph_sha256": sha256_bytes(graph_bytes),
        "link_graph_file_count": len(graph_files),
    }


def _normalized(command: list[str], test_build: Path, fuzz_build: Path,
                output: Path) -> list[str]:
    replacements = (
        (str(test_build), "$TEST_BUILD"),
        (str(fuzz_build), "$FUZZ_BUILD"),
        (str(output), "$OUTPUT"),
        (str(ROOT), "$ROOT"),
    )
    normalized = []
    for value in command:
        for actual, symbolic in replacements:
            if value == actual or value.startswith(actual + os.sep):
                value = symbolic + value[len(actual):]
                break
        normalized.append(value)
    return normalized


def _run_logged(command: list[str], log: Path, env: dict[str, str],
                timeout: int, *, stdin: bytes | None = None) -> tuple[int, int]:
    begin = time.monotonic()
    try:
        with log.open("wb") as stream:
            completed = subprocess.run(
                command, cwd=ROOT, env=env, input=stdin,
                stdout=stream, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
        code = completed.returncode
    except subprocess.TimeoutExpired:
        code = 124
        with log.open("ab") as stream:
            stream.write(b"\nSANITIZER MATRIX WALL TIMEOUT\n")
    return code, round((time.monotonic() - begin) * 1000)


def _append_success(log: Path, name: str) -> None:
    with log.open("ab") as stream:
        if log.stat().st_size and not log.read_bytes().endswith(b"\n"):
            stream.write(b"\n")
        stream.write(f"CODESKEPTIC_SANITIZER_GATE_OK {name}\n".encode())


def _assert_no_runtime_failure(data: bytes, name: str) -> None:
    for marker in SANITIZER_MARKERS:
        if marker in data:
            raise MatrixError(f"sanitizer diagnostic in accepted gate {name}")


def _gate(log_dir: Path, name: str, command: list[str], env: dict[str, str],
          test_build: Path, fuzz_build: Path, output: Path, timeout: int,
          *, expected_codes: set[int] = {0}, stdin: bytes | None = None,
          require: tuple[bytes, ...] = (), allow_diagnostic: bool = False,
          require_all: tuple[bytes, ...] = (),
          evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    log = log_dir / f"{name}.log"
    code, duration = _run_logged(command, log, env, timeout, stdin=stdin)
    data = log.read_bytes()
    if code not in expected_codes:
        raise MatrixError(f"gate {name} returned {code}")
    if require and not any(marker in data for marker in require):
        raise MatrixError(f"gate {name} lacks required runtime evidence")
    if require_all and not all(marker in data for marker in require_all):
        raise MatrixError(f"gate {name} lacks complete runtime evidence")
    if not allow_diagnostic:
        _assert_no_runtime_failure(data, name)
    _append_success(log, name)
    payload = {
        "name": name,
        "command": _normalized(command, test_build, fuzz_build, output),
        "exit_code": code,
        "duration_ms": duration,
        "log": log.relative_to(output).as_posix(),
        "log_sha256": sha256_file(log),
        "evidence": evidence or {},
    }
    return payload


def _prepare(log_dir: Path, name: str, command: list[str], env: dict[str, str],
             test_build: Path, fuzz_build: Path, output: Path,
             timeout: int) -> dict[str, Any]:
    return _gate(log_dir, name, command, env, test_build, fuzz_build,
                 output, timeout)


def _write_fixture(parent: Path, compiler: str) -> dict[str, Path]:
    fixture = parent / "fixture"
    clean_dir = fixture / "clean"
    whole_dir = fixture / "whole"
    invalid_dir = fixture / "invalid"
    for directory in (clean_dir, whole_dir, invalid_dir):
        directory.mkdir(parents=True)

    clean = clean_dir / "clean.cpp"
    finding = clean_dir / "finding.cpp"
    clean.write_text("int answer() { return 42; }\n", encoding="utf-8")
    finding.write_text(
        "int finding() { int* p = new int(42); delete p; return *p; }\n",
        encoding="utf-8")
    first = whole_dir / "first.cpp"
    second = whole_dir / "second.cpp"
    first.write_text("int helper(int v) { return v + 1; }\n", encoding="utf-8")
    second.write_text(
        "int helper(int); int caller() { return helper(1); }\n",
        encoding="utf-8")

    def database(directory: Path, files: list[Path]) -> None:
        payload = [
            {
                "directory": str(directory),
                "arguments": [compiler, "-std=c++17", "-c", str(path)],
                "file": str(path),
            }
            for path in files
        ]
        (directory / "compile_commands.json").write_text(
            json.dumps(payload) + "\n", encoding="utf-8", newline="\n")

    database(clean_dir, [clean, finding])
    database(whole_dir, [first, second])
    (invalid_dir / "compile_commands.json").write_text(
        '[{"directory":"unterminated', encoding="utf-8", newline="\n")
    return {
        "clean_dir": clean_dir,
        "clean": clean,
        "finding": finding,
        "whole_dir": whole_dir,
        "invalid_dir": invalid_dir,
    }


def _directory_manifest(directory: Path) -> dict[str, Any]:
    entries = [
        {
            "path": path.relative_to(directory).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in sorted(candidate for candidate in directory.rglob("*")
                           if candidate.is_file())
    ]
    return {
        "algorithm": "sha256",
        "file_count": len(entries),
        "digest": sha256_bytes(canonical_json(entries)),
        "entries": entries,
    }


def _parse_ctest_count(data: bytes) -> int:
    matches = re.findall(rb"100% tests passed, 0 tests failed out of ([0-9]+)", data)
    if len(matches) != 1:
        raise MatrixError("complete CTest log lacks an exact pass count")
    count = int(matches[0])
    if count < 1200:
        raise MatrixError(f"complete CTest unexpectedly contains only {count} tests")
    return count


def _parse_gtest_count(data: bytes) -> int:
    matches = re.findall(rb"\[  PASSED  \] ([0-9]+) tests?\.", data)
    if len(matches) != 1:
        raise MatrixError("single-process log lacks an exact pass count")
    count = int(matches[0])
    if count < 1185:
        raise MatrixError(f"single-process suite unexpectedly contains only {count} tests")
    return count


def _build_identity(build: Path, profile: str, *, fuzz: bool) -> dict[str, Any]:
    evidence = _instrumentation_evidence(build, profile, fuzz=fuzz)
    binaries = tuple(f"fuzz/{name}" for name in FUZZ_TARGETS) if fuzz else (
        "src/codeskeptic", "tests/codeskeptic_tests",
        "tests/codeskeptic_sanitizer_tripwire")
    evidence["binaries"] = {
        name: sha256_file(_binary(build, name)) for name in binaries
    }
    evidence["cmake_cache_sha256"] = sha256_file(build / "CMakeCache.txt")
    return evidence


def _write_receipt(output: Path, payload: dict[str, Any]) -> None:
    data = canonical_json(payload)
    (output / "receipt.json").write_bytes(data)
    (output / "receipt.json.sha256").write_text(
        f"{sha256_bytes(data)}  receipt.json\n", encoding="utf-8", newline="\n")


def _runtime_env(profile: str) -> tuple[dict[str, str], dict[str, str]]:
    runtime = dict(PROFILES[profile]["runtime_environment"])
    env = {key: value for key, value in os.environ.items()
           if key not in SANITIZER_ENVIRONMENT}
    env.update(runtime)
    return env, runtime


def execute(profile: str, test_build: Path, fuzz_build: Path,
            output: Path) -> dict[str, Any]:
    if profile not in PROFILES:
        raise MatrixError(f"unsupported sanitizer profile: {profile}")
    test_build = _inside_root(test_build, "test build")
    fuzz_build = _inside_root(fuzz_build, "fuzz build")
    if test_build == fuzz_build:
        raise MatrixError("test and fuzz builds must be distinct")
    test_cache = _validate_build(test_build, profile, fuzz=False)
    _validate_build(fuzz_build, profile, fuzz=True)
    output = _validated_output(output, test_build, fuzz_build)
    if output.exists() and any(output.iterdir()):
        raise MatrixError("receipt output directory is not empty")
    output.mkdir(parents=True, exist_ok=True)
    logs = output / "logs"
    logs.mkdir()
    env, runtime = _runtime_env(profile)
    compiler = test_cache["CMAKE_CXX_COMPILER"]

    started = dt.datetime.now(dt.timezone.utc)
    preparation = []
    preparation.append(_prepare(
        logs, "configure_tests", ["cmake", "-S", str(ROOT), "-B", str(test_build)],
        env, test_build, fuzz_build, output, 180))
    preparation.append(_prepare(
        logs, "configure_fuzz", ["cmake", "-S", str(ROOT), "-B", str(fuzz_build)],
        env, test_build, fuzz_build, output, 180))
    preparation.append(_prepare(
        logs, "build_tests",
        ["cmake", "--build", str(test_build), "--target", "codeskeptic",
         "codeskeptic_tests", "codeskeptic_sanitizer_tripwire",
         "--parallel", str(BUILD_JOBS)],
        env, test_build, fuzz_build, output, 1800))
    preparation.append(_prepare(
        logs, "build_fuzz", ["cmake", "--build", str(fuzz_build), "--target",
                              *FUZZ_TARGETS, "--parallel", str(BUILD_JOBS)],
        env, test_build, fuzz_build, output, 1800))

    # Re-read generated evidence after the matrix's own configure/build steps.
    _validate_build(test_build, profile, fuzz=False)
    _validate_build(fuzz_build, profile, fuzz=True)
    builds = {
        "tests": _build_identity(test_build, profile, fuzz=False),
        "fuzz": _build_identity(fuzz_build, profile, fuzz=True),
    }
    compiler_result = subprocess.run(
        [compiler, "--version"], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False)
    if compiler_result.returncode != 0:
        raise MatrixError("cannot identify sanitizer compiler")
    toolchain = {
        "path": compiler,
        "version_first_line": compiler_result.stdout.decode(
            "utf-8", errors="replace").splitlines()[0],
        "version_output_sha256": sha256_bytes(compiler_result.stdout),
    }

    tests_binary = _binary(test_build, "tests/codeskeptic_tests")
    analyzer = _binary(test_build, "src/codeskeptic")
    tripwire = _binary(test_build, "tests/codeskeptic_sanitizer_tripwire")
    gates = []
    gates.append(_gate(
        logs, "runtime_tripwire", [str(tripwire)], env,
        test_build, fuzz_build, output, 60,
        expected_codes=set(range(-64, 0)) | set(range(1, 256)),
        require=PROFILES[profile]["tripwire_markers"], allow_diagnostic=True,
        evidence={"runtime_active": True}))
    serial = _gate(
        logs, "focused_serial_worker",
        [str(tests_binary),
         "--gtest_filter=BrokenTuTest.AnalysisWorkerIsSerialAndJoinedBeforeReturn"],
        env, test_build, fuzz_build, output, 180,
        require=(b"SERIAL_WORKER_EVIDENCE callbacks=2 max_active=1 "
                 b"worker_threads=1 joined=1",),
        evidence={"max_active": 1, "worker_threads": 1, "joined": True})
    gates.append(serial)

    ctest_listing = subprocess.run(
        ["ctest", "--test-dir", str(test_build), "-N"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False)
    if ctest_listing.returncode != 0:
        raise MatrixError("cannot enumerate complete CTest suite")
    ctest_gate = _gate(
        logs, "ctest_complete",
        ["ctest", "--test-dir", str(test_build), "--output-on-failure"],
        env, test_build, fuzz_build, output, 1800)
    ctest_data = (output / ctest_gate["log"]).read_bytes()
    ctest_gate["evidence"] = {
        "test_count": _parse_ctest_count(ctest_data),
        "listing_sha256": sha256_bytes(ctest_listing.stdout),
    }
    gates.append(ctest_gate)

    direct = _gate(
        logs, "single_process_complete", [str(tests_binary)], env,
        test_build, fuzz_build, output, 1800)
    direct_data = (output / direct["log"]).read_bytes()
    direct["evidence"] = {"test_count": _parse_gtest_count(direct_data)}
    gates.append(direct)

    fixture = _write_fixture(output, compiler)
    gates.append(_gate(
        logs, "analyzer_clean",
        [str(analyzer), str(fixture["clean"]), "--build-path",
         str(fixture["clean_dir"])], env, test_build, fuzz_build,
        output, 180, require=(b"Clean!",),
        evidence={"expected_verdict_exit": 0}))
    gates.append(_gate(
        logs, "analyzer_finding",
        [str(analyzer), str(fixture["finding"]), "--build-path",
         str(fixture["clean_dir"])], env, test_build, fuzz_build,
        output, 180, expected_codes={1}, require=(b"use-after-free",),
        evidence={"expected_verdict_exit": 1}))
    gates.append(_gate(
        logs, "analyzer_invalid_input",
        [str(analyzer), str(fixture["clean"]), "--build-path",
         str(fixture["invalid_dir"])], env, test_build, fuzz_build,
        output, 180, expected_codes={2}, require=(b"compile",),
        evidence={"expected_verdict_exit": 2}))
    gates.append(_gate(
        logs, "analyzer_whole_program",
        [str(analyzer), str(fixture["whole_dir"]), "--build-path",
         str(fixture["whole_dir"]), "--whole-program"], env,
        test_build, fuzz_build, output, 240,
        require_all=(b"Whole-program pass", b"Clean!"),
        evidence={"source_files": 2, "expected_verdict_exit": 0}))

    mcp_input = _mcp_input(fixture)
    mcp = _gate(
        logs, "mcp_sequential", [str(analyzer), "--serve"], env,
        test_build, fuzz_build, output, 300, stdin=mcp_input,
        evidence={"request_ids": [1, 2], "sequential_loop": True,
                  "stdin_sha256": sha256_bytes(mcp_input)})
    mcp_data = (output / mcp["log"]).read_text(
        encoding="utf-8", errors="strict").splitlines()
    responses = []
    for line in mcp_data:
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and parsed.get("jsonrpc") == "2.0":
                responses.append(parsed)
    if [response.get("id") for response in responses] != [1, 2]:
        raise MatrixError("MCP gate did not return two ordered responses")
    if any("result" not in response for response in responses):
        raise MatrixError("MCP gate returned a protocol error")
    gates.append(mcp)

    fuzz_output = output / "fuzz-smoke"
    fuzz_command = [
        sys.executable, str(FUZZ_RUNNER_PATH), "--build-dir", str(fuzz_build),
        "--mode", FUZZ_MODE, "--output", str(fuzz_output),
    ]
    fuzz_gate = _gate(
        logs, "fuzz_smoke", fuzz_command, env, test_build, fuzz_build,
        output, 900, require=(b"fuzz campaign accepted",),
        evidence={"mode": FUZZ_MODE, "target_count": len(FUZZ_TARGETS)})
    FUZZ_RUNNER.verify_receipt(fuzz_output, fuzz_build)
    fuzz_gate["evidence"]["receipt_sha256"] = sha256_file(
        fuzz_output / "receipt.json")
    gates.append(fuzz_gate)

    if tuple(gate["name"] for gate in gates) != EXPECTED_GATES:
        raise MatrixError("sanitizer gate matrix is incomplete")
    finished = dt.datetime.now(dt.timezone.utc)
    payload = {
        "schema": SCHEMA,
        "status": "accepted",
        "profile": profile,
        "source": {
            "base_commit": FUZZ_RUNNER.git_commit(),
            "manifest": source_manifest(),
        },
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "toolchain": toolchain,
        "runtime_environment": runtime,
        "fixture": _directory_manifest(output / "fixture"),
        "builds": builds,
        "preparation": preparation,
        "gates": gates,
        "tsan": {
            "status": "not_applicable",
            "reason": "production analysis uses one joined worker at a time",
            "evidence_gate": "focused_serial_worker",
            "max_active": 1,
            "worker_threads": 1,
            "joined": True,
        },
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": round((finished - started).total_seconds() * 1000),
        "failures": [],
    }
    _write_receipt(output, payload)
    verify_receipt(output, test_build, fuzz_build)
    return payload


def _require_sha(value: Any, label: str) -> str:
    if (not isinstance(value, str) or len(value) != 64 or
            any(character not in "0123456789abcdef" for character in value)):
        raise MatrixError(f"invalid {label} SHA-256")
    return value


def _verify_log(output: Path, record: dict[str, Any], name: str,
                *, diagnostic_allowed: bool = False) -> bytes:
    expected_fields = {
        "name", "command", "exit_code", "duration_ms", "log",
        "log_sha256", "evidence",
    }
    if not isinstance(record, dict) or set(record) != expected_fields:
        raise MatrixError(f"unexpected sanitizer gate fields: {name}")
    if (not isinstance(record.get("command"), list) or
            not all(isinstance(value, str) for value in record["command"]) or
            not isinstance(record.get("exit_code"), int) or
            not isinstance(record.get("duration_ms"), int) or
            record["duration_ms"] < 0 or
            not isinstance(record.get("evidence"), dict)):
        raise MatrixError(f"invalid sanitizer gate metadata: {name}")
    if record.get("name") != name:
        raise MatrixError("sanitizer gate order/identity drift")
    relative = record.get("log")
    if relative != f"logs/{name}.log":
        raise MatrixError(f"unexpected sanitizer log path: {name}")
    path = output / relative
    if not path.is_file() or sha256_file(path) != _require_sha(
            record.get("log_sha256"), f"{name} log"):
        raise MatrixError(f"sanitizer log checksum mismatch: {name}")
    data = path.read_bytes()
    terminal = f"CODESKEPTIC_SANITIZER_GATE_OK {name}\n".encode()
    if not data.endswith(terminal) or data.count(terminal) != 1:
        raise MatrixError(f"sanitizer log lacks terminal evidence: {name}")
    if not diagnostic_allowed:
        _assert_no_runtime_failure(data, name)
    return data


def _mcp_input(fixture: dict[str, Path]) -> bytes:
    requests = []
    for request_id in (1, 2):
        requests.append(json.dumps({
            "jsonrpc": "2.0", "id": request_id,
            "method": "tools/call",
            "params": {"name": "analyze", "arguments": {
                "path": str(fixture["clean"]),
                "build_path": str(fixture["clean_dir"]),
            }},
        }, separators=(",", ":")))
    return ("\n".join(requests) + "\n").encode()


def _parse_mcp_responses(data: bytes) -> list[dict[str, Any]]:
    responses = []
    for line in data.decode("utf-8", errors="strict").splitlines():
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("jsonrpc") == "2.0":
            responses.append(parsed)
    return responses


def _expected_commands(test_build: Path, fuzz_build: Path,
                       output: Path) -> tuple[dict[str, list[str]],
                                               dict[str, list[str]]]:
    tests_binary = _binary(test_build, "tests/codeskeptic_tests")
    analyzer = _binary(test_build, "src/codeskeptic")
    tripwire = _binary(test_build, "tests/codeskeptic_sanitizer_tripwire")
    fixture = {
        "clean_dir": output / "fixture" / "clean",
        "clean": output / "fixture" / "clean" / "clean.cpp",
        "finding": output / "fixture" / "clean" / "finding.cpp",
        "whole_dir": output / "fixture" / "whole",
        "invalid_dir": output / "fixture" / "invalid",
    }
    preparation = {
        "configure_tests": ["cmake", "-S", str(ROOT), "-B", str(test_build)],
        "configure_fuzz": ["cmake", "-S", str(ROOT), "-B", str(fuzz_build)],
        "build_tests": [
            "cmake", "--build", str(test_build), "--target", "codeskeptic",
            "codeskeptic_tests", "codeskeptic_sanitizer_tripwire",
            "--parallel", str(BUILD_JOBS),
        ],
        "build_fuzz": [
            "cmake", "--build", str(fuzz_build), "--target",
            *FUZZ_TARGETS, "--parallel", str(BUILD_JOBS),
        ],
    }
    gates = {
        "runtime_tripwire": [str(tripwire)],
        "focused_serial_worker": [
            str(tests_binary),
            "--gtest_filter=BrokenTuTest.AnalysisWorkerIsSerialAndJoinedBeforeReturn",
        ],
        "ctest_complete": [
            "ctest", "--test-dir", str(test_build), "--output-on-failure"],
        "single_process_complete": [str(tests_binary)],
        "analyzer_clean": [
            str(analyzer), str(fixture["clean"]), "--build-path",
            str(fixture["clean_dir"])],
        "analyzer_finding": [
            str(analyzer), str(fixture["finding"]), "--build-path",
            str(fixture["clean_dir"])],
        "analyzer_invalid_input": [
            str(analyzer), str(fixture["clean"]), "--build-path",
            str(fixture["invalid_dir"])],
        "analyzer_whole_program": [
            str(analyzer), str(fixture["whole_dir"]), "--build-path",
            str(fixture["whole_dir"]), "--whole-program"],
        "mcp_sequential": [str(analyzer), "--serve"],
        "fuzz_smoke": [
            sys.executable, str(FUZZ_RUNNER_PATH), "--build-dir",
            str(fuzz_build), "--mode", FUZZ_MODE, "--output",
            str(output / "fuzz-smoke")],
    }
    return preparation, gates


def verify_receipt(output: Path, test_build: Path,
                   fuzz_build: Path) -> dict[str, Any]:
    output = output.resolve()
    test_build = _inside_root(test_build, "test build")
    fuzz_build = _inside_root(fuzz_build, "fuzz build")
    receipt_path = output / "receipt.json"
    checksum_path = output / "receipt.json.sha256"
    try:
        data = receipt_path.read_bytes()
        checksum = checksum_path.read_text(encoding="utf-8", errors="strict")
        receipt = json.loads(data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot read sanitizer receipt: {error}") from error
    if checksum != f"{sha256_bytes(data)}  receipt.json\n":
        raise MatrixError("sanitizer receipt checksum mismatch")
    if data != canonical_json(receipt):
        raise MatrixError("sanitizer receipt is not canonical JSON")
    expected_fields = {
        "schema", "status", "profile", "source", "host", "toolchain",
        "runtime_environment", "fixture", "builds", "preparation", "gates",
        "tsan", "started_at", "finished_at", "duration_ms", "failures",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_fields:
        raise MatrixError("unexpected sanitizer receipt fields")
    profile = receipt.get("profile")
    if (receipt.get("schema") != SCHEMA or receipt.get("status") != "accepted" or
            receipt.get("failures") != [] or profile not in PROFILES):
        raise MatrixError("sanitizer receipt is not accepted")
    _validate_build(test_build, profile, fuzz=False)
    _validate_build(fuzz_build, profile, fuzz=True)
    expected_runtime = PROFILES[profile]["runtime_environment"]
    if receipt.get("runtime_environment") != expected_runtime:
        raise MatrixError("sanitizer runtime environment drift")
    host = receipt.get("host")
    if not isinstance(host, dict) or set(host) != {
            "platform", "machine", "python"} or not all(
                isinstance(value, str) and value for value in host.values()):
        raise MatrixError("invalid sanitizer host identity")
    if not isinstance(receipt.get("duration_ms"), int) or receipt["duration_ms"] < 0:
        raise MatrixError("invalid sanitizer duration")
    try:
        started = dt.datetime.fromisoformat(receipt["started_at"])
        finished = dt.datetime.fromisoformat(receipt["finished_at"])
    except (TypeError, ValueError) as error:
        raise MatrixError("invalid sanitizer timestamps") from error
    if (started.tzinfo is None or finished.tzinfo is None or
            finished < started):
        raise MatrixError("invalid sanitizer time interval")

    source = receipt.get("source")
    if not isinstance(source, dict) or set(source) != {"base_commit", "manifest"}:
        raise MatrixError("invalid sanitizer source identity")
    base = source["base_commit"]
    if (not isinstance(base, str) or len(base) != 40 or
            not FUZZ_RUNNER.git_commit_is_ancestor(base, FUZZ_RUNNER.git_commit())):
        raise MatrixError("sanitizer source base is not current ancestry")
    if source["manifest"] != source_manifest():
        raise MatrixError("sanitizer source bytes differ from worktree")

    expected_builds = {
        "tests": _build_identity(test_build, profile, fuzz=False),
        "fuzz": _build_identity(fuzz_build, profile, fuzz=True),
    }
    if receipt.get("builds") != expected_builds:
        raise MatrixError("sanitizer build identity drift")

    fixture_dir = output / "fixture"
    fixture_manifest = _directory_manifest(fixture_dir)
    expected_fixture_paths = {
        "clean/clean.cpp", "clean/finding.cpp", "clean/compile_commands.json",
        "whole/first.cpp", "whole/second.cpp", "whole/compile_commands.json",
        "invalid/compile_commands.json",
    }
    if ({entry["path"] for entry in fixture_manifest["entries"]} !=
            expected_fixture_paths or receipt.get("fixture") != fixture_manifest):
        raise MatrixError("sanitizer fixture evidence drift")

    compiler = _read_cache(test_build)["CMAKE_CXX_COMPILER"]
    compiler_result = subprocess.run(
        [compiler, "--version"], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False)
    expected_toolchain = {
        "path": compiler,
        "version_first_line": compiler_result.stdout.decode(
            "utf-8", errors="replace").splitlines()[0]
            if compiler_result.returncode == 0 and compiler_result.stdout else "",
        "version_output_sha256": sha256_bytes(compiler_result.stdout),
    }
    if receipt.get("toolchain") != expected_toolchain:
        raise MatrixError("sanitizer toolchain identity drift")

    prep_commands, gate_commands = _expected_commands(
        test_build, fuzz_build, output)

    preparation = receipt.get("preparation")
    prep_names = ("configure_tests", "configure_fuzz", "build_tests", "build_fuzz")
    if not isinstance(preparation, list) or len(preparation) != len(prep_names):
        raise MatrixError("sanitizer preparation matrix is incomplete")
    for record, name in zip(preparation, prep_names):
        if record.get("exit_code") != 0:
            raise MatrixError(f"failed sanitizer preparation: {name}")
        if record.get("command") != _normalized(
                prep_commands[name], test_build, fuzz_build, output):
            raise MatrixError(f"sanitizer preparation command drift: {name}")
        _verify_log(output, record, name)

    gates = receipt.get("gates")
    if not isinstance(gates, list) or len(gates) != len(EXPECTED_GATES):
        raise MatrixError("sanitizer gate matrix is incomplete")
    for record, name in zip(gates, EXPECTED_GATES):
        if record.get("command") != _normalized(
                gate_commands[name], test_build, fuzz_build, output):
            raise MatrixError(f"sanitizer gate command drift: {name}")
        data = _verify_log(output, record, name,
                           diagnostic_allowed=name == "runtime_tripwire")
        code = record.get("exit_code")
        if name == "runtime_tripwire":
            if not isinstance(code, int) or code == 0 or not any(
                    marker in data for marker in PROFILES[profile]["tripwire_markers"]):
                raise MatrixError("sanitizer tripwire did not prove runtime activity")
        elif name == "analyzer_finding":
            if code != 1 or b"use-after-free" not in data:
                raise MatrixError("finding verdict gate drift")
        elif name == "analyzer_invalid_input":
            if code != 2 or b"compile" not in data.lower():
                raise MatrixError("invalid-input verdict gate drift")
        elif code != 0:
            raise MatrixError(f"accepted sanitizer gate failed: {name}")
        if name == "focused_serial_worker" and (
                b"SERIAL_WORKER_EVIDENCE callbacks=2 max_active=1 "
                b"worker_threads=1 joined=1" not in data):
            raise MatrixError("TSAN N/A serial-worker evidence drift")
        if name == "analyzer_clean" and b"Clean!" not in data:
            raise MatrixError("clean analyzer verdict evidence drift")
        if name == "analyzer_whole_program" and not all(
                marker in data for marker in (b"Whole-program pass", b"Clean!")):
            raise MatrixError("whole-program analyzer evidence drift")
        if name == "mcp_sequential":
            try:
                clean_database = json.loads(
                    (fixture_dir / "clean" / "compile_commands.json").read_text(
                        encoding="utf-8", errors="strict"))
                clean_entry = next(entry for entry in clean_database
                                   if str(entry.get("file", "")).endswith("clean.cpp"))
                fixture = {
                    "clean": Path(clean_entry["file"]),
                    "clean_dir": Path(clean_entry["directory"]),
                }
            except (OSError, UnicodeDecodeError, json.JSONDecodeError,
                    StopIteration, KeyError, TypeError) as error:
                raise MatrixError("cannot reconstruct MCP fixture input") from error
            expected_input = _mcp_input(fixture)
            if record.get("evidence") != {
                    "request_ids": [1, 2], "sequential_loop": True,
                    "stdin_sha256": sha256_bytes(expected_input)}:
                raise MatrixError("MCP input evidence drift")
            responses = _parse_mcp_responses(data)
            if ([response.get("id") for response in responses] != [1, 2] or
                    any("result" not in response for response in responses)):
                raise MatrixError("MCP ordered response evidence drift")
        if name == "ctest_complete":
            count = _parse_ctest_count(data)
            if record.get("evidence", {}).get("test_count") != count:
                raise MatrixError("CTest evidence count drift")
            listing = subprocess.run(
                ["ctest", "--test-dir", str(test_build), "-N"], cwd=ROOT,
                env={**os.environ, **expected_runtime}, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False)
            if (listing.returncode != 0 or
                    record.get("evidence", {}).get("listing_sha256") !=
                    sha256_bytes(listing.stdout)):
                raise MatrixError("CTest discovery evidence drift")
        if name == "single_process_complete":
            count = _parse_gtest_count(data)
            if record.get("evidence", {}).get("test_count") != count:
                raise MatrixError("single-process evidence count drift")

    tsan = receipt.get("tsan")
    if tsan != {
        "status": "not_applicable",
        "reason": "production analysis uses one joined worker at a time",
        "evidence_gate": "focused_serial_worker",
        "max_active": 1,
        "worker_threads": 1,
        "joined": True,
    }:
        raise MatrixError("TSAN applicability evidence drift")

    fuzz_output = output / "fuzz-smoke"
    fuzz_receipt = FUZZ_RUNNER.verify_receipt(fuzz_output, fuzz_build)
    fuzz_record = gates[-1]
    if (fuzz_receipt.get("mode") != FUZZ_MODE or
            fuzz_record.get("evidence", {}).get("receipt_sha256") !=
            sha256_file(fuzz_output / "receipt.json")):
        raise MatrixError("nested fuzz evidence drift")

    expected_root_files = {"receipt.json", "receipt.json.sha256"}
    expected_root_files.update(f"logs/{name}.log" for name in (
        *prep_names, *EXPECTED_GATES))
    expected_root_files.update(
        f"fixture/{relative}" for relative in expected_fixture_paths)
    actual_root_files = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*") if path.is_file() and
        not path.is_relative_to(fuzz_output)
    }
    if actual_root_files != expected_root_files:
        raise MatrixError("unexpected or missing sanitizer receipt files")
    return receipt


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sanitizer", choices=tuple(PROFILES))
    parser.add_argument("--test-build", type=Path, required=True)
    parser.add_argument("--fuzz-build", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-receipt", type=Path)
    args = parser.parse_args(argv)
    if args.verify_receipt is not None:
        if args.output is not None or args.sanitizer is not None:
            parser.error("verification cannot be combined with run options")
    elif args.output is None or args.sanitizer is None:
        parser.error("execution requires --sanitizer and --output")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.verify_receipt is not None:
            verify_receipt(args.verify_receipt, args.test_build,
                           args.fuzz_build)
            print(f"sanitizer receipt accepted: {args.verify_receipt}")
            return 0
        execute(args.sanitizer, args.test_build, args.fuzz_build, args.output)
        print(f"sanitizer matrix accepted: {args.sanitizer}")
        return 0
    except (MatrixError, FUZZ_RUNNER.CampaignError) as error:
        print(f"sanitizer matrix rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
