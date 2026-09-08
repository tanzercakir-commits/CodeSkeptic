#!/usr/bin/env python3
"""Synthetic native-package and candidate-routing checks, not hosted proof."""
import os
import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import re
import subprocess
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
    def report(code=0):
        diagnostics = [{"rule_id": "null-deref"}] if code == 1 else []
        return {"schema": "codeskeptic-report/v1", "tool": "CodeSkeptic", "tool_version": "0.4.9-dev+g0123456789ab",
                "exit_code": code, "complete": code != 2,
                "status": {0: "clean", 1: "findings", 2: "incomplete"}[code],
                "coverage": {"schema": "codeskeptic-source-coverage/v1", "attempted_tus": 1,
                             "analyzed_tus": 0 if code == 2 else 1, "broken_tus": 1 if code == 2 else 0},
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
                result = native.validate_report(self.report(code), "0.4.9-dev+g0123456789ab", code, "c")
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
                native.validate_report(report, "0.4.9-dev+g0123456789ab", 0, "c")

    def test_supported_finding_is_required(self):
        report = self.report(1)
        report["diagnostics"] = [{"rule_id": "experimental-only"}]
        with self.assertRaisesRegex(ValueError, "supported native finding"):
            native.validate_report(report, "0.4.9-dev+g0123456789ab", 1, "cpp")

    def test_boolean_counters_and_false_clean_evidence_rejected(self):
        for change in (lambda r: r["coverage"].update(attempted_tus=True),
                       lambda r: r["finding_counts"].update(total=False),
                       lambda r: r.update(status="incomplete"),
                       lambda r: r["evidence"].update(tool_failed=True)):
            report = self.report()
            change(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                native.validate_report(report, "0.4.9-dev+g0123456789ab", 0, "c")

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

    def synthetic_qualification(self, failed_case=None):
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
                                  output=self.work / "evidence")
        def execution(argv, cwd, env, output, label, timeout=60):
            if label == "version":
                data, code = ("CodeSkeptic " + version + "\n").encode(), 0
            elif label == "capabilities":
                data, code = native.canonical({"schema_version": 2, "product": "CodeSkeptic", "version": version}), 0
            else:
                code = 0 if label.endswith("clean") else 1 if label.endswith("finding") else 2
                report = self.report(code)
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
        for forbidden in ("gh release", "git push", "git tag", "refs/status", "refs/ci-logs", "GH_TOKEN", "secrets."):
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
