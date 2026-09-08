#!/usr/bin/env python3
"""Synthetic native-package and candidate-routing checks, not hosted proof."""
import os
import argparse
import contextlib
import copy
import errno
import io
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zipfile

import platform_first_scan as native

REPO = Path(__file__).resolve().parents[1]


class VersionIdentityTests(unittest.TestCase):
    def parse_version(self, identity):
        source = (REPO / "scripts/package_release.sh").read_text()
        start = re.search(r"(?m)^VERSION(?:_TEXT)?=", source).start()
        end = source.index("\nARCH=", start)
        with tempfile.TemporaryDirectory(prefix="version fixture ") as temporary:
            binary = Path(temporary) / "binary"
            binary.write_text("#!/bin/sh\nprintf '%s\\n' \"$FIXTURE_IDENTITY\"\n")
            binary.chmod(0o755)
            return subprocess.run(["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", source[start:end] + '\nprintf "%s" "$VERSION"'],
                                  env={"PATH": os.environ["PATH"], "BIN": str(binary), "FIXTURE_IDENTITY": identity, "LC_ALL": "C"},
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)

    def test_nonlinux_full_source_suffix_preserved(self):
        version = "0.4.9-dev+g0123456789ab"
        result = self.parse_version("CodeSkeptic " + version)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, version)

    def test_release_version_preserved(self):
        result = self.parse_version("CodeSkeptic 0.4.8")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "0.4.8")

    def test_windows_crlf_version_preserved(self):
        version = "0.4.9-dev+g0123456789ab"
        result = self.parse_version("CodeSkeptic " + version + "\r")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, version)

    def test_invalid_or_ambiguous_native_identity_rejected(self):
        for identity in ("other 0.4.8", "CodeSkeptic 0.4.8 trailing", "CodeSkeptic 0.4.8\nCodeSkeptic 0.4.9", "CodeSkeptic 0.4.8\r\nCodeSkeptic 0.4.9\r", "CodeSkeptic 0.4.8\r\r"):
            with self.subTest(identity=identity):
                result = self.parse_version(identity)
                self.assertNotEqual(result.returncode, 0, result.stdout)


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="platform evidence fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    @staticmethod
    def report(code=0, source="/native/güvenli_çalışma.c"):
        analyzed, skipped = (0, 1) if code == 2 else (1, 0)
        diagnostics = [{"rule_id": "null-deref", "blocks_verdict": True,
                        "capability_tier": "supported", "file": source}] if code == 1 else []
        return {"schema": "codeskeptic-report/v1", "tool": "CodeSkeptic", "tool_version": "0.4.9-dev+g0123456789ab",
                "exit_code": code, "complete": code != 2,
                "status": {0: "clean", 1: "findings", 2: "failed"}[code],
                "coverage": {"schema": "codeskeptic-source-coverage/v1", "attempted_tus": 1,
                             "analyzed_tus": analyzed, "broken_tus": skipped, "skipped_tus": skipped,
                             "failed_tus": 0, "recovery_tus": 0, "attempted_commands": 1,
                             "analyzed_commands": analyzed, "skipped_commands": skipped, "failed_commands": 0,
                             "incomplete_functions": 0, "complete": code != 2,
                             "accept_partial_coverage": False, "analyze_broken_tus": False,
                             "sources": [{"file": source, "status": "skipped" if skipped else "analyzed",
                                          "reason": "broken_translation_unit" if skipped else "analyzed",
                                          "commands": 1, "analyzed_commands": analyzed, "skipped_commands": skipped,
                                          "failed_commands": 0, "recovery_commands": 0,
                                          "prepass": {"status": "not_requested", "reason": "", "recovery_commands": 0}}]},
                "finding_counts": {"total": len(diagnostics), "blocking": len(diagnostics), "report_only": 0},
                "total": len(diagnostics), "diagnostics": diagnostics,
                "evidence": {"no_inputs": False, "no_rules": False, "tool_failed": False,
                             "summary_load_failed": False, "summary_stale": False,
                             "summary_save_failed": False, "baseline_load_failed": False,
                             "baseline_write_failed": False, "baseline_recorded": False,
                             "report_write_failed": False}}

    def test_three_verdicts_preserved(self):
        for code in (0, 1, 2):
            with self.subTest(code=code):
                result = native.validate_report(self.report(code), "0.4.9-dev+g0123456789ab", code, "c", "/native/güvenli_çalışma.c")
                self.assertEqual(result["exit_code"], code)
                self.assertEqual(result["complete"], code != 2)

    def test_identity_completeness_and_counts_reject_contradictions(self):
        mutations = [lambda r: r.update(tool_version="0.4.8"), lambda r: r.update(complete=False),
                     lambda r: r.update(exit_code=1), lambda r: r["coverage"].update(analyzed_tus=0),
                     lambda r: r["finding_counts"].update(total=7), lambda r: r.update(total=True),
                     lambda r: r.update(diagnostics={})]
        for change in mutations:
            report = self.report()
            change(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                native.validate_report(report, "0.4.9-dev+g0123456789ab", 0, "c", "/native/güvenli_çalışma.c")

    def test_supported_finding_is_required(self):
        report = self.report(1)
        report["diagnostics"][0]["rule_id"] = "experimental-only"
        with self.assertRaisesRegex(ValueError, "supported native finding"):
            native.validate_report(report, "0.4.9-dev+g0123456789ab", 1, "cpp", "/native/güvenli_çalışma.c")

    def test_native_profile_rejects_inconsistent_coverage(self):
        changes = [lambda c: c.update(complete=False), lambda c: c.update(failed_tus=1),
                   lambda c: c.update(accept_partial_coverage=True), lambda c: c.update(analyze_broken_tus=True),
                   lambda c: c.update(recovery_tus=1), lambda c: c.update(attempted_commands=2),
                   lambda c: c.update(analyzed_commands=True), lambda c: c.update(incomplete_functions=1),
                   lambda c: c["sources"][0].update(status="failed"),
                   lambda c: c["sources"][0].update(commands=2), lambda c: c["sources"][0].update(failed_commands=1),
                   lambda c: c["sources"][0]["prepass"].update(recovery_commands=1),
                   lambda c: c.update(sources=[])]
        for index, change in enumerate(changes):
            report = self.report()
            change(report["coverage"])
            with self.subTest(case=index), self.assertRaises(ValueError):
                native.validate_report(report, "0.4.9-dev+g0123456789ab", 0, "c", "/native/güvenli_çalışma.c")

    def test_nonblocking_null_diagnostic_cannot_prove_blocking(self):
        report = self.report(1)
        report["diagnostics"][0]["blocks_verdict"] = False
        with self.assertRaises(ValueError):
            native.validate_report(report, "0.4.9-dev+g0123456789ab", 1, "c", "/native/güvenli_çalışma.c")

    def test_boolean_counters_and_false_clean_evidence_rejected(self):
        for change in (lambda r: r["coverage"].update(attempted_tus=True),
                       lambda r: r["finding_counts"].update(total=False),
                       lambda r: r.update(status="incomplete"),
                       lambda r: r["evidence"].update(tool_failed=True)):
            report = self.report()
            change(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                native.validate_report(report, "0.4.9-dev+g0123456789ab", 0, "c", "/native/güvenli_çalışma.c")

    def test_report_is_bound_to_exact_unicode_source(self):
        source = self.work / "güvenli_çalışma.c"
        source.write_text("int value(void) { return 42; }\n")
        for code in (0, 1, 2):
            report = self.report(code, str(source))
            native.validate_report(report, "0.4.9-dev+g0123456789ab", code, "c", source)
            report["coverage"]["sources"][0]["file"] = str(self.work / "other.c")
            with self.assertRaisesRegex(ValueError, "source identity"):
                native.validate_report(report, "0.4.9-dev+g0123456789ab", code, "c", source)
        report = self.report(1, str(source))
        report["diagnostics"][0]["file"] = str(self.work / "other.c")
        with self.assertRaisesRegex(ValueError, "diagnostic source"):
            native.validate_report(report, "0.4.9-dev+g0123456789ab", 1, "c", source)

    def test_all_broken_profile_cannot_be_partial_incomplete(self):
        report = self.report(2)
        report["status"] = "incomplete"
        with self.assertRaisesRegex(ValueError, "verdict mismatch"):
            native.validate_report(report, "0.4.9-dev+g0123456789ab", 2, "c", "/native/güvenli_çalışma.c")

    def test_non_native_runner_rejected(self):
        with patch.object(native.platform, "system", return_value="Linux"), patch.object(native.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(ValueError, "actual native"):
                native.runner_profile()

    def test_precise_supported_runner_architectures(self):
        for system, machine, target in (("Windows", "AMD64", "windows-x86_64"), ("Darwin", "arm64", "darwin-arm64")):
            with self.subTest(system=system), patch.object(native.platform, "system", return_value=system), patch.object(native.platform, "machine", return_value=machine):
                self.assertEqual(native.runner_profile()["target"], target)
        with patch.object(native.platform, "system", return_value="Darwin"), patch.object(native.platform, "machine", return_value="x86_64"):
            with self.assertRaises(ValueError):
                native.runner_profile()

    def test_environment_does_not_forward_credentials_or_developer_overrides(self):
        with patch.dict(os.environ, {"GH_TOKEN": "fixture", "GITHUB_TOKEN": "fixture", "SDKROOT": "/fixture/sdk", "INCLUDE": "fixture", "DYLD_LIBRARY_PATH": "fixture", "LD_LIBRARY_PATH": "fixture", "VSCMD_ARG_TGT_ARCH": "fixture"}):
            result = native.child_environment(self.work / "home", self.work / "temp")
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "SDKROOT", "INCLUDE", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH", "VSCMD_ARG_TGT_ARCH"):
            self.assertNotIn(name, result)
        self.assertEqual(result["HOME"], str(self.work / "home"))

    def test_snapshot_checksum_and_input_preservation(self):
        source = self.work / "archive"
        source.write_bytes(b"synthetic archive")
        with self.assertRaisesRegex(ValueError, "checksum"):
            native.snapshot(source, "0" * 64, self.work / "bad-copy")
        self.assertEqual(source.read_bytes(), b"synthetic archive")
        native.snapshot(source, native.file_hash(source), self.work / "copy")
        self.assertEqual(source.read_bytes(), (self.work / "copy").read_bytes())

    def test_snapshot_and_document_symlinks_rejected(self):
        source = self.work / "source"
        source.write_bytes(b"fixture")
        link = self.work / "link"
        link.symlink_to(source)
        with self.assertRaisesRegex(ValueError, "regular"):
            native.read_regular(link)
        with self.assertRaisesRegex(ValueError, "regular"):
            native.snapshot(link, native.file_hash(source), self.work / "copy")

    def test_archive_paths_reject_traversal_case_collisions_and_devices(self):
        for value in ("root/../escape", "root/C:stream", "root/a\\b", "root/NUL.txt", "/root/a", "root/a.", "root/a "):
            with self.subTest(value=value), self.assertRaises(ValueError):
                native.member_path(value, "root", set())
        names = set()
        native.member_path("root/Name", "root", names)
        with self.assertRaisesRegex(ValueError, "case-colliding"):
            native.member_path("root/name", "root", names)

    def make_zip(self, entries):
        archive = self.work / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for name, data in entries:
                output.writestr(name, data)
        return archive

    def test_zip_extracts_exact_bytes_without_extractall(self):
        archive = self.make_zip([("root/bin/codeskeptic.exe", b"fixture"), ("root/LICENSE", b"notice")])
        destination = self.work / "unpacked"
        destination.mkdir()
        root = native.extract(archive, destination, "root")
        self.assertEqual((root / "bin/codeskeptic.exe").read_bytes(), b"fixture")

    def test_archive_file_directory_conflict_rejected(self):
        archive = self.make_zip([("root/parent", b"file"), ("root/parent/child", b"child")])
        with self.assertRaisesRegex(ValueError, "file/directory conflict"):
            native.extract(archive, self.work, "root")

    def test_zip_link_rejected(self):
        archive = self.work / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as output:
            item = zipfile.ZipInfo("root/link")
            item.create_system = 3
            item.external_attr = 0o120777 << 16
            output.writestr(item, "target")
        with self.assertRaisesRegex(ValueError, "special ZIP"):
            native.extract(archive, self.work, "root")

    def test_tar_exact_bytes_and_link_rejection(self):
        archive = self.work / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            item = tarfile.TarInfo("root/bin/codeskeptic")
            item.mode = 0o755
            item.size = 7
            output.addfile(item, io.BytesIO(b"fixture"))
        root = native.extract(archive, self.work, "root")
        self.assertEqual((root / "bin/codeskeptic").read_bytes(), b"fixture")
        with tarfile.open(archive, "w:gz") as output:
            item = tarfile.TarInfo("root/link")
            item.type = tarfile.SYMTYPE
            item.linkname = "target"
            output.addfile(item)
        with self.assertRaisesRegex(ValueError, "unsupported tar"):
            native.extract(archive, self.work, "root")

    def test_archive_member_and_document_bounds(self):
        archive = self.make_zip([("root/a", b"a"), ("root/b", b"b")])
        with patch.object(native, "MAX_MEMBERS", 1), self.assertRaisesRegex(ValueError, "count"):
            native.extract(archive, self.work, "root")
        document = self.work / "document"
        document.write_bytes(b"oversized")
        with self.assertRaisesRegex(ValueError, "bounded"):
            native.read_regular(document, 2)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                native.parse_json(value)

    def test_timeout_preserves_terminal_command_record(self):
        with patch.object(native.subprocess, "run", side_effect=subprocess.TimeoutExpired(["fixture"], 1)):
            with self.assertRaisesRegex(ValueError, "timed out"):
                native.execute(["fixture"], self.work, {}, self.work, "timeout", 1)
        receipt = json.loads((self.work / "timeout.command.json").read_bytes())
        self.assertTrue(receipt["timed_out"])
        self.assertIsNone(receipt["exit_code"])

    def synthetic_qualification(self, failed_case=None, os_locators=False):
        version = "0.4.9-dev+g0123456789ab"
        root = "codeskeptic-v" + version + "-windows-x86_64"
        archive = self.work / (root + ".zip")
        binary = b"synthetic executable; never run"
        with zipfile.ZipFile(archive, "w") as packed:
            for path, data in (("bin/codeskeptic.exe", binary), ("LICENSE", b"notice"),
                               ("README.md", b"readme"), ("DEPENDENCIES.txt", b"synthetic dependencies"),
                               ("lib/clang/20/include/stddef.h", b"synthetic header")):
                packed.writestr(root + "/" + path, data)
        hidden = self.work / "llvm-hidden"
        hidden.mkdir()
        source = "0123456789ab" + "0" * 28
        args = argparse.Namespace(archive=archive, archive_sha256=native.file_hash(archive), source_sha=source,
                                  version=version, source_binary_sha256=native.sha(binary),
                                  llvm_original=self.work / "llvm-original", llvm_hidden=hidden,
                                  output=self.work / "evidence", windows_os_locators=os_locators)
        def execution(argv, cwd, env, output, label, timeout=60):
            if label == "version":
                data, code = ("CodeSkeptic " + version + "\n").encode(), 0
            elif label == "capabilities":
                data, code = native.canonical({"schema_version": 2, "product": "CodeSkeptic", "version": version}), 0
            else:
                code = 0 if label.endswith("clean") else 1 if label.endswith("finding") else 2
                report = self.report(code, str(Path(argv[1]).resolve()))
                report_path = Path(argv[-1])
                report_path.write_bytes(native.canonical(report))
                data = b"synthetic command, not native execution\n"
            if label == failed_case:
                code = 7
            (output / (label + ".stdout")).write_bytes(data)
            (output / (label + ".stderr")).write_bytes(b"")
            record = {"argv": argv, "cwd": str(cwd), "exit_code": code, "timed_out": False}
            (output / (label + ".command.json")).write_bytes(native.canonical(record))
            return record
        info = {"sha": source, "version": version, "helper_sha256": native.file_hash(Path(native.__file__))}
        runner = {"system": "Windows", "machine": "AMD64", "target": "windows-x86_64"}
        with patch.object(native, "identity", return_value=info), patch.object(native, "git", return_value=Path(native.__file__).read_bytes()), \
                patch.object(native, "runner_profile", return_value=runner), patch.object(native, "execute", side_effect=execution), \
                patch.dict(os.environ, {"GITHUB_SHA": source}), contextlib.redirect_stdout(io.StringIO()):
            result = native.qualify(args)
        return result, args

    def test_synthetic_end_to_end_binds_six_cases_and_original_archive(self):
        result, args = self.synthetic_qualification()
        self.assertEqual(result["result"], "PASS")
        self.assertEqual([r["execution"]["exit_code"] for r in result["cases"]], [0, 1, 2, 0, 1, 2])
        self.assertEqual(result["artifact"]["sha256"], native.file_hash(args.output / args.archive.name))
        self.assertEqual(args.archive.read_bytes(), (args.output / args.archive.name).read_bytes())
        self.assertTrue(args.llvm_hidden.is_dir())  # helper never restores/moves the caller's tree
        self.assertFalse(args.llvm_original.exists())
        self.assertFalse((args.output / "failure.json").exists())
        self.assertEqual(len(list((args.output / "fixtures").glob("*/güvenli_çalışma.*"))), 6)
        for case in result["cases"]:
            path = args.output / "scans" / (case["name"] + "-rapor-ç.json")
            self.assertEqual(case["report_sha256"], native.file_hash(path))

    def test_synthetic_failure_retains_evidence_without_pass(self):
        with self.assertRaisesRegex(ValueError, "first-scan exit mismatch"):
            self.synthetic_qualification(failed_case="cpp-finding")
        output = self.work / "evidence"
        self.assertTrue((output / "failure.json").is_file())
        self.assertFalse((output / "result.json").exists())
        self.assertEqual(json.loads((output / "scans/cpp-finding.command.json").read_bytes())["exit_code"], 7)
        self.assertTrue(list(output.glob("*.zip")))

    def test_explicit_locator_profile_still_requires_all_six_cases(self):
        locators = {name: "C:" for name in native.WINDOWS_OS_LOCATORS}
        with patch.dict(os.environ, locators):
            result, _ = self.synthetic_qualification(os_locators=True)
        self.assertEqual(result["profile"]["windows_os_locators"], locators)
        self.assertEqual([r["execution"]["exit_code"] for r in result["cases"]], [0, 1, 2, 0, 1, 2])


class WindowsSdkDiagnosticTests(unittest.TestCase):
    setUp = NativeEvidenceTests.setUp

    def test_only_four_os_locators_added_to_existing_isolation(self):
        locators = {"ProgramFiles": r"C:\Program Files", "ProgramFiles(x86)": r"C:\Program Files (x86)",
                    "ProgramW6432": r"C:\Program Files", "SystemDrive": "C:"}
        with patch.dict(os.environ, {**locators, "INCLUDE": "forbidden", "GH_TOKEN": "forbidden",
                                     "PATH": "developer-path"}, clear=True):
            base = native.child_environment(self.work / "home", self.work / "temp")
            restored = native.windows_locator_environment(base)
        self.assertEqual(restored, {**base, **locators})
        self.assertNotIn("ProgramFiles", base)
        self.assertNotIn("GH_TOKEN", restored)
        self.assertNotIn("INCLUDE", restored)
        self.assertEqual(base["PATH"], restored["PATH"])

    def test_missing_locator_is_not_silently_invented(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "OS locator"):
            native.windows_locator_environment({"PATH": "isolated"})

    def test_arms_keep_inputs_and_capture_failure_without_qualification_pass(self):
        binary, source, database = (self.work / name for name in ("binary", "güvenli_çalışma.c", "compile_commands.json"))
        for path in (binary, source, database):
            path.write_bytes(b"fixed synthetic input")
        environments, calls = [], []
        version = "0.4.9-dev+g0123456789ab"
        def execution(argv, cwd, env, output, label, timeout=60):
            environments.append(env); calls.append((argv, cwd))
            code = 2 if label == "baseline" else 1
            report = NativeEvidenceTests.report(code, str(source))
            Path(argv[-1]).write_bytes(native.canonical(report))
            (output / (label + ".stderr")).write_bytes(b"fatal error: 'stdio.h' file not found" if code == 2 else b"")
            return {"exit_code": code, "timed_out": False}
        with patch.object(native, "windows_locator_environment", side_effect=lambda e: {**e, "SystemDrive": "C:"}), \
                patch.object(native, "execute", side_effect=execution):
            result = native.sdk_arms(binary, source, database, self.work, {"PATH": "isolated"}, self.work, version)
        self.assertEqual([arm["execution"]["exit_code"] for arm in result], [2, 1])
        self.assertEqual(calls[0][0][:-1], calls[1][0][:-1])
        self.assertEqual(calls[0][1], calls[1][1])
        self.assertEqual(environments[1], {**environments[0], "SystemDrive": "C:"})
        self.assertEqual([arm["valid_report"] for arm in result], [True, True])
        self.assertFalse((self.work / "result.json").exists())

    def test_arm_timeout_or_invalid_report_does_not_skip_other_arm(self):
        for failure in ("timeout", "malformed", "unexpected-clean"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=self.work) as folder:
                work = Path(folder)
                binary, source, database = (work / name for name in ("binary", "source.c", "compile_commands.json"))
                for path in (binary, source, database):
                    path.write_bytes(b"fixed")
                calls = []
                def execution(argv, cwd, env, output, label, timeout=60):
                    calls.append(label)
                    if label == "baseline" and failure == "timeout":
                        raise native.QualificationError("native command timed out")
                    code = 0 if label == "baseline" and failure == "unexpected-clean" else 2
                    data = b"invalid" if label == "baseline" and failure == "malformed" else native.canonical(NativeEvidenceTests.report(code, str(source)))
                    Path(argv[-1]).write_bytes(data)
                    (output / (label + ".stderr")).write_bytes(b"fatal error: 'stdio.h' file not found")
                    return {"exit_code": code, "timed_out": False}
                with patch.object(native, "windows_locator_environment", side_effect=dict), patch.object(native, "execute", side_effect=execution):
                    result = native.sdk_arms(binary, source, database, work, {}, work, "0.4.9-dev+g0123456789ab")
                self.assertEqual(calls, ["baseline", "os-locators"])
                self.assertFalse(result[0]["valid_report"])
                self.assertTrue(result[1]["valid_report"])

    def test_historical_archive_selection_and_digest_rejection(self):
        package = b"synthetic nested archive"
        archive = self.work / "artifact.zip"
        entries = [(native.SDK_PACKAGE_MEMBER, package), (native.SDK_FIXTURE_MEMBER, b"same source"),
                   (native.SDK_DATABASE_MEMBER, b"same database")]
        def select(values, *, outer_digest=None, nested_digest=None):
            with zipfile.ZipFile(archive, "w") as z:
                for name, data in values:
                    z.writestr(name, data)
            with tempfile.TemporaryDirectory(dir=self.work) as folder, \
                    patch.object(native, "SDK_ARTIFACT_SHA256", outer_digest or native.file_hash(archive)), \
                    patch.object(native, "SDK_PACKAGE_SHA256", nested_digest or native.sha(package)):
                path, source, db = native.sdk_inputs(archive, Path(folder))
                self.assertEqual(path.read_bytes(), package)
                self.assertEqual((source, db), (b"same source", b"same database"))
        select(entries)
        with self.assertRaisesRegex(ValueError, "checksum"):
            select(entries, outer_digest="0" * 64)
        with self.assertRaisesRegex(ValueError, "checksum"):
            select(entries, nested_digest="0" * 64)
        with self.assertRaisesRegex(ValueError, "missing"):
            select(entries[:-1])
        with self.assertRaisesRegex(ValueError, "case-colliding"):
            select(entries + [(native.SDK_PACKAGE_MEMBER.upper(), package)])
        with self.assertRaisesRegex(ValueError, "unsafe"):
            select(entries + [("root/../escape", b"no")])

    def synthetic_diagnostic(self, work, second_code=1, missing_stdio=True):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr(native.SDK_ROOT + "/bin/codeskeptic.exe", b"synthetic; never executed")
        archive = work / "outer.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(native.SDK_PACKAGE_MEMBER, inner.getvalue())
            z.writestr(native.SDK_FIXTURE_MEMBER, b"same archived source")
            z.writestr(native.SDK_DATABASE_MEMBER, native.canonical([{"directory": "old", "file": "old/source.c",
                        "arguments": ["clang", "-std=c11", "-c", "old/source.c"]}]))
        hidden = work / "hidden"
        hidden.mkdir()
        current_sha = "1" * 40
        args = argparse.Namespace(source_sha=current_sha, version="0.4.9-dev+g111111111111", archive=archive,
                                  archive_sha256=native.file_hash(archive), llvm_original=work / "original",
                                  llvm_hidden=hidden, output=work / "evidence")
        def execution(argv, cwd, env, output, label, timeout=60):
            if label == "version":
                (output / "version.stdout").write_text("CodeSkeptic " + native.SDK_VERSION + "\n")
                return {"exit_code": 0, "timed_out": False}
            code = 2 if label == "baseline" else second_code
            report = NativeEvidenceTests.report(code, str(Path(argv[1]).resolve()))
            report["tool_version"] = native.SDK_VERSION
            Path(argv[-1]).write_bytes(native.canonical(report))
            (output / (label + ".stderr")).write_bytes(b"'stdio.h' file not found" if missing_stdio else b"different error")
            return {"exit_code": code, "timed_out": False}
        info = {"sha": current_sha, "version": args.version}
        with patch.object(native, "identity", return_value=info), \
                patch.object(native, "git", return_value=Path(native.__file__).read_bytes()), \
                patch.object(native, "runner_profile", return_value={"system": "Windows", "target": "windows-x86_64"}), \
                patch.object(native, "SDK_ARTIFACT_SHA256", args.archive_sha256), \
                patch.object(native, "SDK_PACKAGE_SHA256", native.sha(inner.getvalue())), \
                patch.object(native, "execute", side_effect=execution), patch.object(native, "qualify") as qualify, \
                patch.dict(os.environ, {"GITHUB_SHA": current_sha, **{k: "C:" for k in native.WINDOWS_OS_LOCATORS}}), \
                contextlib.redirect_stdout(io.StringIO()):
            if second_code == 1 and missing_stdio:
                result = native.sdk_diagnostic(args)
            else:
                with self.assertRaisesRegex(ValueError, "hypothesis not established"):
                    native.sdk_diagnostic(args)
                result = json.loads((args.output / "sdk-diagnostic.json").read_bytes())
                self.assertTrue((args.output / "diagnostic-failure.json").is_file())
            qualify.assert_not_called()
        self.assertFalse((args.output / "result.json").exists())
        self.assertNotIn("result", result)
        self.assertEqual(result["schema"], "codeskeptic-windows-sdk-diagnostic/v1")
        self.assertEqual(result["diagnostic_source"]["sha"], current_sha)
        self.assertEqual(result["binary_source"], native.SDK_SOURCE)
        self.assertNotEqual(result["diagnostic_source"]["sha"], result["binary_source"])
        self.assertEqual(result["historical_database_sha256"], native.file_hash(args.output / "historical-compile_commands.json"))
        self.assertNotEqual(result["historical_database_sha256"], result["database_sha256"])
        return result

    def test_full_diagnostic_cannot_qualify_old_binary_as_current(self):
        result = self.synthetic_diagnostic(self.work)
        self.assertTrue(result["baseline_failure_then_locator_finding"])

    def test_both_failed_unexpected_clean_and_wrong_red_do_not_establish_hypothesis(self):
        for code, stdio in ((2, True), (0, True), (1, False)):
            with self.subTest(code=code, stdio=stdio), tempfile.TemporaryDirectory(dir=self.work) as folder:
                result = self.synthetic_diagnostic(Path(folder), code, stdio)
                self.assertFalse(result["baseline_failure_then_locator_finding"])


class FilesystemPrerequisiteTests(unittest.TestCase):
    def fixture_case(self, root):
        # Import declarations only. No analyzer, unittest runner or test setUp
        # is invoked by these synthetic prerequisite-boundary checks.
        with patch.object(sys, "argv", ["CompilationDatabaseCliTest.py", sys.executable]):
            module = runpy.run_path(str(REPO / "tests/CompilationDatabaseCliTest.py"), run_name="prerequisite_fixture")
        case = module["CompilationDatabaseCliTest"]()
        case.root = root
        return case

    def test_only_darwin_eilseq_is_an_explicit_unexecuted_prerequisite(self):
        with tempfile.TemporaryDirectory(prefix="byte-name-prerequisite-") as folder:
            case = self.fixture_case(Path(folder))
            for host, error, expected in (("darwin", errno.EILSEQ, unittest.SkipTest),
                                         ("linux", errno.EILSEQ, OSError), ("darwin", errno.EACCES, OSError),
                                         ("darwin", errno.ENOSPC, OSError), ("darwin", errno.EIO, OSError),
                                         ("darwin", errno.EEXIST, OSError)):
                with self.subTest(host=host, error=error), patch.object(sys, "platform", host), \
                        patch.object(os, "open", side_effect=OSError(error, "synthetic prerequisite failure")), \
                        self.assertRaises(expected):
                    case.require_non_utf8_filename_filesystem()

    def test_supported_filesystem_runs_and_only_its_owned_probe_is_removed(self):
        with tempfile.TemporaryDirectory(prefix="byte-name-prerequisite-") as folder:
            root = Path(folder)
            sentinel = root / "keep.txt"
            sentinel.write_bytes(b"unchanged")
            case = self.fixture_case(root)
            case.require_non_utf8_filename_filesystem()
            self.assertEqual(list(root.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b"unchanged")


class CheckpointTimeTests(unittest.TestCase):
    def test_native_and_wide_ticks_are_lossless(self):
        compiler = "/usr/bin/c++" if Path("/usr/bin/c++").is_file() else shutil.which("c++")
        self.assertIsNotNone(compiler, "a local C++17 compiler is required; no download is performed")
        source = r'''
#include "analyzer/CheckpointTime.h"
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
template<class T> void emit(T value) {
    std::cout << codeskeptic::checkpointTickIdentity(value) << '\n';
}
int main() {
    for (long long value = -257; value <= 257; ++value) {
        if (codeskeptic::checkpointTickIdentity(value) != std::to_string(value)) return 1;
    }
    emit(0); emit(-1); emit(42); emit(-42);
    emit(std::numeric_limits<std::int32_t>::min());
    emit(std::numeric_limits<std::int32_t>::max());
    emit(std::numeric_limits<std::int64_t>::min());
    emit(std::numeric_limits<std::int64_t>::max());
    emit(std::numeric_limits<std::uint64_t>::max());
    using Rep = std::filesystem::file_time_type::duration::rep;
    emit(Rep(0)); emit(Rep(-1));
#if defined(__SIZEOF_INT128__)
    using Wide = __int128_t;
    const Wide high = Wide(1) << 100;
    emit(high); emit(high + 42); emit(-high); emit(-high - 42);
    emit(std::numeric_limits<Wide>::min()); emit(std::numeric_limits<Wide>::max());
    emit(std::numeric_limits<__uint128_t>::max());
#else
    std::cout << "wide-representation-unavailable\n";
#endif
}
'''
        with tempfile.TemporaryDirectory(prefix="checkpoint time compiler fixture ") as temporary:
            work = Path(temporary)
            unit, binary = work / "ticks.cpp", work / "ticks"
            unit.write_text(source)
            result = subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                                     "-I", str(REPO / "src"), str(unit), "-o", str(binary)],
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)
        expected = [0, -1, 42, -42, -(1 << 31), (1 << 31) - 1, -(1 << 63), (1 << 63) - 1,
                    (1 << 64) - 1, 0, -1, 1 << 100, (1 << 100) + 42, -(1 << 100), -(1 << 100) - 42,
                    -(1 << 127), (1 << 127) - 1, (1 << 128) - 1]
        self.assertEqual(executed.stdout.splitlines(), [str(value) for value in expected],
                         "this portability regression requires a compiler with wide integer support")

    def test_both_checkpoint_paths_use_full_tick_encoder(self):
        source = (REPO / "src/analyzer/StaticAnalyzer.cpp").read_text()
        self.assertIn('#include "analyzer/CheckpointTime.h"', source)
        self.assertEqual(source.count("checkpointTickIdentity(std::filesystem::last_write_time("), 2)
        self.assertNotIn("std::to_string(std::filesystem::last_write_time(", source)


class DarwinBudgetTests(unittest.TestCase):
    def test_checked_ceiling_and_fail_closed_native_sequence(self):
        compiler = "/usr/bin/c++" if Path("/usr/bin/c++").is_file() else shutil.which("c++")
        self.assertIsNotNone(compiler, "a local C++17 compiler is required; no download is performed")
        source = r'''
#include "core/DarwinMemoryBudget.h"
#include <cassert>
#include <iostream>
#include <string>
using namespace codeskeptic::darwin_memory;
constexpr std::uint64_t M = 1024 * 1024;
constexpr auto MAX = std::numeric_limits<std::uint64_t>::max();
constexpr auto INF = MAX >> 1; // Darwin can use a sentinel below the type maximum.
struct FakeNative {
    Limits inherited{INF, INF}, installed{};
    Snapshot snapshot{392 * 1024 * M, 12, 12};
    std::string calls;
    unsigned failure = 0, reads = 0, snapshots = 0, writes = 0, mismatch = 0;
    bool readLimits(Limits& out) {
        calls += 'r'; ++reads;
        if (calls.size() == failure) return false;
        out = reads == 1 ? inherited : installed;
        if (reads == 2 && mismatch == 1) ++out.soft;
        if (reads == 2 && mismatch == 2) --out.hard;
        if (reads == 2 && mismatch == 3) out = {INF, INF};
        return true;
    }
    bool readSnapshot(Snapshot& out) {
        calls += 'q'; ++snapshots; out = snapshot;
        return calls.size() != failure;
    }
    bool writeLimits(Limits in) {
        calls += 'w'; ++writes;
        if (calls.size() == failure) return false;
        installed = in; return true;
    }
};
int main() {
    auto check = [](std::uint64_t base, std::uint64_t mb, Limits limits,
                    std::uint64_t maximum, std::uint64_t infinity,
                    Stage stage, std::uint64_t expected = 0) {
        std::uint64_t target = 17;
        assert(ceiling(base, mb, limits, maximum, infinity, target) == stage);
        assert(target == (stage == Stage::Ready ? expected : 17));
    };
    for (auto baseline : {std::uint64_t(1), 128*M, 392*1024*M}) {
        check(baseline, 128, {INF, INF}, MAX, INF, Stage::Ready, baseline+128*M);
        check(baseline, 128, {baseline+32*M, baseline+96*M}, MAX, INF, Stage::Ready, baseline+32*M);
        check(baseline, 128, {baseline+64*M, baseline+64*M}, MAX, INF, Stage::Ready, baseline+64*M);
        check(baseline, 128, {baseline, INF}, MAX, INF, Stage::Ready, baseline);
        check(baseline, 128, {baseline-1, INF}, MAX, INF, Stage::BelowSnapshot);
    }
    check(1, 0, {INF, INF}, MAX, INF, Stage::InvalidAllowance);
    check(1, MAX/M+1, {INF, INF}, MAX, INF, Stage::InvalidAllowance);
    check(0, 1, {INF, INF}, MAX, INF, Stage::InvalidSnapshot);
    check(INF, 1, {INF, INF}, MAX, INF, Stage::InvalidSnapshot);
    check(MAX, 1, {MAX, MAX}, MAX, MAX, Stage::InvalidSnapshot);
    check(1, 1, {INF, 32*M}, MAX, INF, Stage::InvalidLimits);
    check(1, 1, {40*M, 32*M}, MAX, INF, Stage::InvalidLimits);
    check(1, 1, {INF+1, INF+1}, MAX, INF, Stage::InvalidLimits);
    check(INF-M-1, 1, {INF, INF}, MAX, INF, Stage::Ready, INF-1);
    check(INF-M, 1, {INF, INF}, MAX, INF, Stage::Overflow);
    check(MAX-M+1, 1, {MAX, MAX}, MAX, MAX, Stage::Overflow);
    check(1, MAX/M, {MAX, MAX}, MAX, MAX, Stage::Ready, (MAX/M)*M+1);
    // A narrow native representation must fail before conversion; clamping
    // to inherited limits must never rescue overflow or an infinity target.
    check(2*M, 1, {INF, INF}, M, INF, Stage::InvalidSnapshot);
    check(1, 1, {INF, INF}, M-1, INF, Stage::Overflow);
    check(1, 1, {2*M, 2*M}, M, INF, Stage::InvalidLimits);
    check(INF-M, 1, {INF-M, INF}, MAX, INF, Stage::Overflow);
    FakeNative good;
    auto result = install(good, 128, MAX, INF);
    assert(result.stage == Stage::Applied && good.calls == "rqwr");
    assert(result.target == good.snapshot.bytes+128*M);
    assert(good.installed.soft == result.target && good.installed.hard == result.target);
    for (unsigned failure = 1; failure <= 4; ++failure) {
        FakeNative native; native.failure = failure;
        result = install(native, 128, MAX, INF);
        const Stage stages[] = {Stage::ReadInherited, Stage::ReadSnapshot, Stage::Install, Stage::Readback};
        assert(result.stage == stages[failure-1]);
        assert(native.calls == std::string("rqwr").substr(0, failure));
        assert(native.snapshots <= 1 && native.writes <= 1); // no retry/rebaseline
        if (failure == 4) assert(native.installed.soft == native.snapshot.bytes+128*M);
    }
    for (unsigned mismatch : {1u, 2u, 3u}) {
        FakeNative native; native.mismatch = mismatch;
        assert(install(native, 128, MAX, INF).stage == Stage::Mismatch);
        assert(native.calls == "rqwr" && native.writes == 1);
    }
    for (unsigned count : {0u, 11u, 13u}) {
        FakeNative native; native.snapshot.count = count;
        assert(install(native, 128, MAX, INF).stage == Stage::InvalidSnapshot);
        assert(native.calls == "rq" && native.writes == 0);
    }
    for (auto bytes : {std::uint64_t(0), INF, MAX}) {
        FakeNative native; native.snapshot.bytes = bytes;
        assert(install(native, 128, MAX, INF).stage == Stage::InvalidSnapshot);
        assert(native.calls == "rq" && native.writes == 0);
    }
    for (unsigned which = 0; which < 4; ++which) {
        FakeNative native;
        if (which == 0) native.snapshot.expected_count = 0;
        if (which == 1) native.inherited = {INF, 32*M};
        if (which == 2) native.inherited = {32*M, INF};
        if (which == 3) native.snapshot.bytes = INF-M;
        assert(install(native, 128, MAX, INF).stage != Stage::Applied);
        assert(native.calls == "rq" && native.writes == 0);
    }
    for (bool soft_only : {false, true}) {
        FakeNative native;
        const auto bound = native.snapshot.bytes + 32*M;
        native.inherited = {bound, soft_only ? INF : bound};
        result = install(native, 128, MAX, INF);
        assert(result.stage == Stage::Applied && result.target == bound);
        assert(native.installed.soft == bound && native.installed.hard == bound);
    }
    std::cout << "darwin-checked-ceiling-and-native-sequence PASS\n";
}
'''
        with tempfile.TemporaryDirectory(prefix="Darwin budget compiler fixture ") as temporary:
            work = Path(temporary)
            unit, binary = work / "budget.cpp", work / "budget"
            unit.write_text(source)
            compiled = subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                                       "-I", str(REPO / "src"), str(unit), "-o", str(binary)],
                                      capture_output=True, text=True, timeout=45)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertEqual(executed.stdout, "darwin-checked-ceiling-and-native-sequence PASS\n")


class RoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yaml
        class UniqueLoader(yaml.SafeLoader):
            pass
        def mapping(loader, node, deep=False):
            result = {}
            for key, value in node.value:
                name = loader.construct_object(key, deep=deep)
                if name in result:
                    raise ValueError("duplicate workflow key")
                result[name] = loader.construct_object(value, deep=deep)
            return result
        UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        cls.workflow = yaml.load((REPO / ".github/workflows/release.yml").read_text(), Loader=UniqueLoader)

    def test_only_exact_candidate_branch_and_product_paths(self):
        event = self.workflow.get("on", self.workflow.get(True))["push"]
        self.assertEqual(event["tags"], ["v*"])
        self.assertEqual(event["branches"], ["agent/cs3-ch06-s02-u002-platform-support"])
        self.assertNotIn("docs/**", event["paths"])
        self.assertIn("scripts/platform_first_scan.py", event["paths"])
        self.assertNotIn("workflow_dispatch", self.workflow.get("on", self.workflow.get(True)))

    def test_every_legacy_writer_remains_tag_only(self):
        for name in ("prepare", "linux", "macos", "windows", "publish"):
            with self.subTest(job=name):
                self.assertEqual(self.workflow["jobs"][name]["if"], "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')")

    def test_candidate_has_read_token_no_release_dependency_or_writers(self):
        job = self.workflow["jobs"]["candidate-native"]
        self.assertEqual(job["if"], "github.event_name == 'push' && github.ref == 'refs/heads/agent/cs3-ch06-s02-u002-platform-support'")
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("needs", job)
        self.assertFalse(job["strategy"]["fail-fast"])
        self.assertEqual(job["timeout-minutes"], 90)
        text = json.dumps(job)
        for forbidden in ("gh release", "git push", "git tag", "refs/status", "refs/ci-logs", "secrets."):
            self.assertNotIn(forbidden, text)
        checkout = next(step for step in job["steps"] if step.get("uses") == "actions/checkout@v4")
        self.assertFalse(checkout["with"]["persist-credentials"])

    def test_native_profiles_and_failure_retention(self):
        job = self.workflow["jobs"]["candidate-native"]
        self.assertEqual(job["strategy"]["matrix"]["include"], [
            {"runner": "windows-latest", "target": "windows-x86_64"}, {"runner": "macos-14", "target": "darwin-arm64"}])
        upload = next(step for step in job["steps"] if step.get("uses") == "actions/upload-artifact@v4")
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(upload["with"]["retention-days"], 14)
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertIn("${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}", upload["with"]["name"])
        self.assertEqual(upload["with"]["path"].splitlines(), ["${{ runner.temp }}/codeskeptic-platform/", "${{ runner.temp }}/codeskeptic-native-build/"])

    def test_retired_historical_sdk_comparison_is_not_a_release_dependency(self):
        steps = self.workflow["jobs"]["candidate-native"]["steps"]
        for step in steps:
            for retired in ("10052976442", "--sdk-diagnostic", "GH_TOKEN", "github.token", "codeskeptic-sdk-historical"):
                self.assertNotIn(retired, json.dumps(step))
        for step in steps:
            if step.get("name", "").startswith("Exact "):
                self.assertEqual("--windows-os-locators" in step["run"], "Windows" in step["name"])

    def test_candidate_checkout_preserves_blob_line_endings(self):
        environment = self.workflow["jobs"]["candidate-native"].get("env", {})
        expected = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.autocrlf", "GIT_CONFIG_VALUE_0": "false"}
        self.assertEqual(environment, expected)
        with tempfile.TemporaryDirectory(prefix="git config fixture ") as temporary:
            config = Path(temporary) / "gitconfig"
            config.write_text("[core]\n\tautocrlf = true\n")
            env = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_NOSYSTEM": "1"}
            before = subprocess.run(["git", "config", "--get", "--bool", "core.autocrlf"], cwd=temporary,
                                    env=env, capture_output=True, text=True, timeout=10)
            after = subprocess.run(["git", "config", "--get", "--bool", "core.autocrlf"], cwd=temporary,
                                   env={**env, **environment}, capture_output=True, text=True, timeout=10)
            self.assertEqual((before.returncode, before.stdout.strip()), (0, "true"))
            self.assertEqual((after.returncode, after.stdout.strip()), (0, "false"))
            self.assertEqual(config.read_text(), "[core]\n\tautocrlf = true\n")

    def test_bash_blocks_parse_and_llvm_restoration_is_explicit(self):
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if "run" in step and step.get("shell") == "bash":
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-n"], input=step["run"], text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
        steps = self.workflow["jobs"]["candidate-native"]["steps"]
        windows = next(s["run"] for s in steps if s.get("name") == "Exact Windows artifact first scans with LLVM hidden")
        macos = next(s["run"] for s in steps if s.get("name") == "Exact macOS artifact first scans with LLVM hidden")
        self.assertIn("} finally {", windows)
        self.assertIn("$LASTEXITCODE -ne 0", windows)
        self.assertIn("trap restore_llvm EXIT", macos)
        self.assertIn("pwd -P", macos)

    def test_package_outputs_preserve_clean_source_identity(self):
        steps = self.workflow["jobs"]["candidate-native"]["steps"]
        packages = [s["run"] for s in steps if s.get("name", "").startswith("Package candidate")]
        scans = [s["run"] for s in steps if s.get("name", "").startswith("Exact ")]
        self.assertEqual(len(packages), 2)
        self.assertEqual(len(scans), 2)
        for script in packages + scans:
            self.assertIn("build/native-dist", script)
        result = subprocess.run(["git", "check-ignore", "build/native-dist/fixture.zip"], cwd=REPO,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
