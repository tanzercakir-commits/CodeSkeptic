#!/usr/bin/env python3
"""Contract tests for the Phase 10 sanitizer runtime matrix."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "run_sanitizer_matrix.py"
STAGING_PATH = ROOT / "scripts" / "stage_stability_campaign.py"
DETERMINISM_PATH = ROOT / "scripts" / "run_determinism_qualification.py"
EVIDENCE_ROOT = (ROOT / "docs" / "evidence" / "phase10" /
                 "sanitizers" / "2026-08-15-cache-linux-x86_64")
MATERIALIZED_BUILDS = {
    "address": (
        ROOT / "build-p10-06-asan-tests",
        ROOT / "build-p10-06-asan-fuzz",
    ),
    "undefined": (
        ROOT / "build-p10-06-ubsan-tests",
        ROOT / "build-p10-06-ubsan-fuzz",
    ),
}


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "run_sanitizer_matrix", RUNNER_PATH)
    assert spec and spec.loader
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


def load_staging():
    spec = importlib.util.spec_from_file_location(
        "sanitizer_staging_contract", STAGING_PATH)
    assert spec and spec.loader
    staging = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = staging
    spec.loader.exec_module(staging)
    return staging


def load_determinism():
    spec = importlib.util.spec_from_file_location(
        "sanitizer_determinism_contract", DETERMINISM_PATH
    )
    assert spec and spec.loader
    determinism = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = determinism
    spec.loader.exec_module(determinism)
    return determinism


def cmake_compiler(environment: str, candidates: tuple[str, ...]) -> str:
    configured = os.environ.get(environment)
    if configured:
        resolved = shutil.which(configured)
        if resolved:
            return resolved
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise AssertionError(f"no {environment} compiler is available")


class SanitizerContractTest(unittest.TestCase):
    def test_googletest_dependency_is_local_checksummed_and_source_bound(
        self,
    ) -> None:
        archive = ROOT / "third_party" / "googletest-v1.14.0.tar.gz"
        self.assertTrue(archive.is_file())
        self.assertEqual(
            hashlib.sha256(archive.read_bytes()).hexdigest(),
            "8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7",
        )
        cmake = (ROOT / "tests" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("third_party/googletest-v1.14.0.tar.gz", cmake)
        self.assertIn(
            "SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7",
            cmake,
        )
        for forbidden in ("GIT_REPOSITORY", "GIT_TAG", "http://", "https://"):
            self.assertNotIn(forbidden, cmake)
        license_copy = ROOT / "third_party" / "googletest-LICENSE"
        self.assertTrue(license_copy.is_file())
        with tarfile.open(archive, "r:gz") as source_archive:
            members = source_archive.getmembers()
            self.assertTrue(members)
            self.assertEqual(
                {Path(member.name).parts[0] for member in members},
                {"googletest-1.14.0"},
            )
            self.assertTrue(
                all(member.isfile() or member.isdir() for member in members)
            )
            license_member = source_archive.extractfile(
                "googletest-1.14.0/LICENSE"
            )
            self.assertIsNotNone(license_member)
            assert license_member is not None
            self.assertEqual(license_member.read(), license_copy.read_bytes())
        runner = load_runner()
        files = {
            path.relative_to(ROOT).as_posix()
            for path in runner._regular_files(runner.SOURCE_ROOTS)
        }
        self.assertIn("third_party/googletest-v1.14.0.tar.gz", files)

    def test_cmake_exposes_one_validated_sanitizer_profile(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn('set(CODESKEPTIC_SANITIZER "none" CACHE STRING', cmake)
        self.assertIn('none address undefined thread', cmake)
        self.assertIn('CODESKEPTIC_SANITIZER_FLAGS', cmake)
        self.assertIn('-fno-omit-frame-pointer', cmake)
        self.assertIn('-fno-sanitize-recover=undefined', cmake)

    def test_invalid_sanitizer_profile_fails_before_dependency_discovery(self) -> None:
        c_compiler = cmake_compiler(
            "CC", ("clang-20", "clang", "cc", "gcc", "cl"))
        cxx_compiler = cmake_compiler(
            "CXX", ("clang++-20", "clang++", "c++", "g++", "cl"))
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    "cmake", "-S", str(ROOT), "-B", temporary,
                    f"-DCMAKE_C_COMPILER={c_compiler}",
                    f"-DCMAKE_CXX_COMPILER={cxx_compiler}",
                    "-DCODESKEPTIC_SANITIZER=not-a-runtime",
                    "-DCODESKEPTIC_BUILD_TESTS=OFF",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported CODESKEPTIC_SANITIZER", completed.stdout)

    def test_runtime_runner_and_tripwires_exist(self) -> None:
        self.assertTrue(RUNNER_PATH.is_file())
        self.assertTrue(
            (ROOT / "tests" / "sanitizer" / "AddressTripwire.cpp").is_file())
        self.assertTrue(
            (ROOT / "tests" / "sanitizer" / "UndefinedTripwire.cpp").is_file())

    def test_runner_contract_is_exact_and_bounded(self) -> None:
        runner = load_runner()
        self.assertEqual(set(runner.PROFILES), {"address", "undefined"})
        self.assertEqual(
            runner.EXPECTED_GATES,
            (
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
            ),
        )
        self.assertEqual(runner.FUZZ_MODE, "smoke")
        self.assertEqual(runner.BUILD_JOBS, 2)

    def test_sanitizer_build_cache_is_bound_to_exact_source_and_build(self) -> None:
        runner = load_runner()
        compiler = cmake_compiler(
            "CXX", ("clang++-20", "clang++", "c++")
        )
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "address-tests"
            build.mkdir()
            cache = build / "CMakeCache.txt"

            def write(source: Path, recorded_build: Path) -> None:
                cache.write_text(
                    "CODESKEPTIC_SANITIZER:STRING=address\n"
                    "CODESKEPTIC_BUILD_TESTS:BOOL=ON\n"
                    "CODESKEPTIC_BUILD_FUZZERS:BOOL=OFF\n"
                    f"CMAKE_CXX_COMPILER:FILEPATH={compiler}\n"
                    f"CMAKE_HOME_DIRECTORY:INTERNAL={source}\n"
                    f"CMAKE_CACHEFILE_DIR:INTERNAL={recorded_build}\n",
                    encoding="utf-8",
                )

            write(ROOT, build)
            runner._validate_build(build, "address", fuzz=False)
            write(ROOT.parent, build)
            with self.assertRaisesRegex(runner.MatrixError, "source root"):
                runner._validate_build(build, "address", fuzz=False)
            write(ROOT, build.parent)
            with self.assertRaisesRegex(runner.MatrixError, "build root"):
                runner._validate_build(build, "address", fuzz=False)

    def test_source_manifest_binds_all_complete_suite_inputs(self) -> None:
        runner = load_runner()
        files = {
            path.relative_to(ROOT).as_posix()
            for path in runner._regular_files(runner.SOURCE_ROOTS)
        }
        for required in (
                "tests/ConfigTest.cpp",
                "tests/StatusAutomationTest.py",
                "scripts/review_diff.sh",
                "scripts/review_report.py",
                "docs/PLAN.md",
                ".github/workflows/release.yml"):
            self.assertIn(required, files)
        self.assertFalse(any(path.startswith("docs/evidence/") for path in files))
        self.assertNotIn("docs/devlog/changelog.md", files)
        self.assertNotIn("scripts/determinism_baseline.json", files)
        self.assertFalse(any("__pycache__" in path for path in files))
        self.assertFalse(any(path.endswith((".pyc", ".pyo")) for path in files))

        first = runner.source_manifest()
        target = ROOT / "tests" / "ConfigTest.cpp"
        original_sha256_file = runner.sha256_file

        def changed_test_digest(path):
            if path == target:
                return "0" * 64
            return original_sha256_file(path)

        with mock.patch.object(
                runner, "sha256_file", side_effect=changed_test_digest):
            self.assertNotEqual(first, runner.source_manifest())

    def test_source_manifest_matches_stability_staging_scope(self) -> None:
        runner = load_runner()
        staging = load_staging()
        determinism = load_determinism()
        runner_manifest = runner.source_manifest()
        staging_manifest = staging._runtime_source_manifest(ROOT)
        determinism_manifest = determinism.source_manifest(ROOT)
        self.assertEqual(
            runner_manifest["digest"], staging_manifest,
        )
        self.assertEqual(
            determinism_manifest["manifest_sha256"], staging_manifest,
        )
        self.assertEqual(
            determinism_manifest["file_count"], runner_manifest["file_count"],
        )

        archive = ROOT / "third_party" / "googletest-v1.14.0.tar.gz"
        runner_hash = runner.sha256_file
        staging_hash = staging._sha256_regular
        determinism_hash = determinism.sha256_file

        def changed(original):
            def digest(path):
                if Path(path) == archive:
                    return "0" * 64
                return original(path)
            return digest

        with (
            mock.patch.object(runner, "sha256_file", side_effect=changed(runner_hash)),
            mock.patch.object(
                staging, "_sha256_regular", side_effect=changed(staging_hash)
            ),
            mock.patch.object(
                determinism,
                "sha256_file",
                side_effect=changed(determinism_hash),
            ),
        ):
            self.assertNotEqual(runner.source_manifest()["digest"], staging_manifest)
            self.assertNotEqual(
                staging._runtime_source_manifest(ROOT), staging_manifest
            )
            self.assertNotEqual(
                determinism.source_manifest(ROOT)["manifest_sha256"],
                staging_manifest,
            )

    def test_stability_lifecycle_lock_fails_closed_without_fcntl(self) -> None:
        staging = load_staging()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "staging"
            root.mkdir()
            with mock.patch.object(
                staging, "fcntl", None
            ), self.assertRaisesRegex(
                staging.StagingError, "requires POSIX fcntl"
            ):
                with staging._authority_lifecycle_lock(root):
                    self.fail("unsupported lifecycle lock unexpectedly opened")

    def test_runtime_environment_is_hermetic_and_receipted(self) -> None:
        runner = load_runner()
        hostile = {
            "ASAN_OPTIONS": "detect_leaks=0",
            "LSAN_OPTIONS": "exitcode=0",
            "UBSAN_OPTIONS": "halt_on_error=0",
            "TSAN_OPTIONS": "halt_on_error=0",
            "MSAN_OPTIONS": "exit_code=0",
            "HWASAN_OPTIONS": "halt_on_error=0",
        }
        with mock.patch.dict("os.environ", hostile, clear=False):
            address_env, address_receipt = runner._runtime_env("address")
            undefined_env, undefined_receipt = runner._runtime_env("undefined")
        self.assertEqual(
            {key: address_env[key] for key in runner.SANITIZER_ENVIRONMENT
             if key in address_env},
            address_receipt,
        )
        self.assertEqual(
            {key: undefined_env[key] for key in runner.SANITIZER_ENVIRONMENT
             if key in undefined_env},
            undefined_receipt,
        )
        self.assertEqual(address_receipt["LSAN_OPTIONS"], "exitcode=23")
        self.assertIn("detect_leaks=1", address_receipt["ASAN_OPTIONS"])
        self.assertIn("allow_user_poisoning=0", address_receipt["ASAN_OPTIONS"])
        self.assertEqual(
            undefined_receipt,
            {"UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"},
        )

    def test_receipt_output_cannot_overlap_either_build_tree(self) -> None:
        runner = load_runner()
        test_build = ROOT / "build-sanitizer-address-tests"
        fuzz_build = ROOT / "build-sanitizer-address-fuzz"
        for output in (
                test_build,
                test_build / "receipt",
                fuzz_build / "nested" / "receipt",
                ROOT):
            with self.subTest(output=output), self.assertRaisesRegex(
                    runner.MatrixError, "receipt output"):
                runner._validated_output(output, test_build, fuzz_build)

        external = Path(tempfile.gettempdir()) / "codeskeptic-receipt"
        self.assertEqual(
            runner._validated_output(external, test_build, fuzz_build),
            external.resolve(),
        )

    def test_ci_runs_both_profiles_and_retains_receipts(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8")
        self.assertIn("sanitizer-runtime:", workflow)
        self.assertIn("sanitizer: [address, undefined]", workflow)
        self.assertIn("python3 scripts/run_sanitizer_matrix.py", workflow)
        self.assertIn("sanitizer-${{ matrix.sanitizer }}-receipt", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertEqual(
            workflow.count("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"), 2)

    def test_checksum_bound_sanitizer_evidence_disables_conversion(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn(
            "docs/evidence/phase10/sanitizers/** -text\n", attributes)

    def test_materialized_receipts_bind_current_source_builds_and_binaries(
            self) -> None:
        runner = load_runner()
        checked = 0
        for profile in runner.PROFILES:
            receipt = EVIDENCE_ROOT / profile
            test_build, fuzz_build = MATERIALIZED_BUILDS[profile]
            if not receipt.is_dir() or not test_build.is_dir() or not fuzz_build.is_dir():
                continue
            verified = runner.verify_receipt(receipt, test_build, fuzz_build)
            self.assertEqual(verified["profile"], profile)
            checked += 1
        if checked == 0:
            self.skipTest("sanitizer evidence/builds are not materialized")

    def test_verifier_rejects_coordinated_log_append(self) -> None:
        runner = load_runner()
        retained = EVIDENCE_ROOT / "address"
        test_build, fuzz_build = MATERIALIZED_BUILDS["address"]
        if not retained.is_dir() or not test_build.is_dir() or not fuzz_build.is_dir():
            self.skipTest("ASAN evidence/builds are not materialized")
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "receipt"
            shutil.copytree(retained, copied)
            log = copied / "logs" / "analyzer_clean.log"
            log.write_bytes(log.read_bytes() + b"ERROR: AddressSanitizer\n")
            receipt_path = copied / "receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            clean = next(gate for gate in receipt["gates"]
                         if gate["name"] == "analyzer_clean")
            clean["log_sha256"] = runner.sha256_file(log)
            runner._write_receipt(copied, receipt)
            with self.assertRaisesRegex(
                    runner.MatrixError, "terminal evidence|sanitizer diagnostic"):
                runner.verify_receipt(copied, test_build, fuzz_build)

    def test_verifier_rejects_command_and_runtime_rewrites(self) -> None:
        runner = load_runner()
        retained = EVIDENCE_ROOT / "address"
        test_build, fuzz_build = MATERIALIZED_BUILDS["address"]
        if not retained.is_dir() or not test_build.is_dir() or not fuzz_build.is_dir():
            self.skipTest("ASAN evidence/builds are not materialized")
        for mutation, message in (
            (lambda receipt: receipt["gates"][0]["command"].append("--forged"),
             "command drift"),
            (lambda receipt: receipt["runtime_environment"].update(
                {"ASAN_OPTIONS": "halt_on_error=0"}),
             "runtime environment drift"),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                copied = Path(temporary) / "receipt"
                shutil.copytree(retained, copied)
                receipt = json.loads(
                    (copied / "receipt.json").read_text(encoding="utf-8"))
                mutation(receipt)
                runner._write_receipt(copied, receipt)
                with self.assertRaisesRegex(runner.MatrixError, message):
                    runner.verify_receipt(copied, test_build, fuzz_build)

    def test_external_manifest_pins_every_retained_receipt_and_log(self) -> None:
        manifest = EVIDENCE_ROOT / "SHA256SUMS"
        if not manifest.is_file():
            self.skipTest("sanitizer external manifest is not materialized")
        entries = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, separator, relative = line.partition("  ")
            self.assertTrue(separator)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(relative, entries)
            entries[relative] = digest
        expected = {
            path.relative_to(EVIDENCE_ROOT.parent).as_posix()
            for path in EVIDENCE_ROOT.rglob("*")
            if path.is_file() and (
                path.name == "receipt.json" or path.suffix == ".log")
        }
        self.assertEqual(set(entries), expected)
        runner = load_runner()
        for relative, digest in entries.items():
            self.assertEqual(
                runner.sha256_file(EVIDENCE_ROOT.parent / relative), digest)


if __name__ == "__main__":
    unittest.main()
