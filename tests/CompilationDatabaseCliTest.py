#!/usr/bin/env python3
"""Hermetic compilation-database discovery checks using the real CLI."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


if len(sys.argv) < 2:
    raise SystemExit("usage: CompilationDatabaseCliTest.py <codeskeptic-binary> [unittest options]")
BINARY = str(Path(sys.argv.pop(1)).resolve(strict=True))


class CompilationDatabaseCliTest(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="codeskeptic-compdb-")
        self.addCleanup(self.fixture.cleanup)
        # Windows temp paths may use 8.3 spelling. The reporting contract is
        # canonical identity, not the temporary-directory provider's spelling.
        self.root = Path(self.fixture.name).resolve(strict=True)
        self.source = self.root / "input.cpp"
        self.source.write_text("int safe() { return 42; }\n", encoding="utf-8")

    def run_cli(self, *args):
        return subprocess.run(
            [BINARY, *map(str, args)], cwd=self.root, text=True, encoding="utf-8",
            capture_output=True, check=False, timeout=45,
        )

    def database(self, directory, sources=None, extra=()):
        directory.mkdir(parents=True, exist_ok=True)
        sources = sources if sources is not None else [self.source]
        entries = []
        for source in sources:
            entries.append({
                "directory": str(self.root), "file": str(source),
                "arguments": ["clang" if source.suffix == ".c" else "clang++",
                              *extra, "-c", str(source)],
            })
        path = directory / "compile_commands.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        return path.resolve()

    def doctor(self, *args, expected=0):
        result = self.run_cli("--doctor", *args)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        text = result.stdout if expected == 0 else result.stderr
        self.assertIn("[CodeSkeptic] compilation doctor", text)
        fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
        self.assertEqual(fields["status"], "ready" if expected == 0 else "unavailable")
        return fields

    def scan(self, *args, expected=0, count=1):
        report = self.root / "scan-result.json"
        if report.exists():
            report.unlink()  # Only this test's previously generated report.
        result = self.run_cli(*args, "--json", report)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertTrue(report.is_file(), result.stdout + result.stderr)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["complete"], expected != 2, payload)
        if expected != 2:
            self.assertEqual(payload["coverage"]["analyzed_tus"], count, payload)
        return result, payload

    def coverage_formats(self, args, expected):
        reports = []
        for option, name in (("--json", "coverage.json"), ("--sarif", "coverage.sarif")):
            output = self.root / name
            result = self.run_cli(*args, option, output)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            if option == "--json":
                self.assertEqual(payload["exit_code"], expected)
                coverage = payload["coverage"]
            else:
                invocation = payload["runs"][0]["invocations"][0]
                self.assertEqual(invocation["properties"]["codeskeptic/exitCode"], expected)
                coverage = invocation["properties"]["codeskeptic/coverage"]
            prefix = "[CodeSkeptic] source coverage: "
            console = [json.loads(line[len(prefix):]) for line in result.stderr.splitlines()
                       if line.startswith(prefix)]
            self.assertEqual(console, [coverage], result.stderr)
            reports.append(coverage)
        self.assertEqual(reports[0], reports[1])
        return reports[0]

    def corpus_inputs(self, database, root, anchor, output, expected=0):
        producer = Path(BINARY).with_name("codeskeptic_corpus_inputs" + Path(BINARY).suffix)
        self.assertTrue(producer.is_file(), "corpus helper must be built with the CLI contract")
        result = subprocess.run([str(producer), str(database), str(root), str(anchor), str(output)],
                                text=True, encoding="utf-8", capture_output=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected:
            self.assertFalse(output.exists(), "invalid original input published a replacement")
            return None
        self.assertIn("CORPUS_INPUTS", result.stdout)
        return (json.loads((output / "compile_commands.json").read_text(encoding="utf-8")),
                json.loads((output / "provenance.json").read_text(encoding="utf-8")))

    def test_corpus_cmake_recipes_preserve_full_surface_and_partial_coverage(self):
        source = self.root / "corpus space ç-資料"
        source.mkdir()
        include = source / "include"
        include.mkdir()
        (include / "seeded.h").write_text("#define SEEDED 7\n", encoding="utf-8")
        requirements = '#include "seeded.h"\n#ifndef REQUIRED\n#error missing recipe define\n#endif\n'
        anchor = source / "configured.c"
        anchor.write_text(requirements + "int configured(void){return SEEDED + REQUIRED;}\n", encoding="utf-8")
        missing = source / "omitted.c"
        missing.write_text(requirements + "int omitted(void){int zero=0; return SEEDED/zero;}\n", encoding="utf-8")
        broken = source / "broken.c"
        broken.write_text(requirements + "int broken(void){return undeclared;}\n", encoding="utf-8")
        (source / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.16)\nproject(CorpusRecipe C)\n'
            'add_library(configured OBJECT configured.c)\n'
            'target_compile_definitions(configured PRIVATE REQUIRED=3)\n'
            'target_include_directories(configured PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")\n',
            encoding="utf-8")
        compiler = os.environ.get("CODESKEPTIC_CORPUS_COMPILER") or shutil.which("clang")
        self.assertIsNotNone(compiler, "the pinned toolchain must supply clang")
        build = self.root / "cmake corpus build"
        configured = subprocess.run(["cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                                     "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_C_COMPILER=" + compiler],
                                    text=True, encoding="utf-8", capture_output=True, timeout=45)
        self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
        original = build / "compile_commands.json"
        original_bytes = original.read_bytes()
        self.doctor(source, "--build-path", build, expected=2)
        prepared = self.root / "explicit corpus ç-資料"
        commands, evidence = self.corpus_inputs(original, source, anchor, prepared)
        self.assertEqual(original.read_bytes(), original_bytes)
        identities = {str(anchor), str(missing), str(broken)}
        self.assertEqual({command["file"] for command in commands}, identities)
        self.assertEqual({row["file"] for row in evidence["sources"]}, identities)
        self.assertEqual(len(evidence["original_commands"]), 1)
        for row in evidence["sources"]:
            self.assertEqual(row["inferred"], row["file"] != str(anchor))
            self.assertEqual(len(row["commands"]), 1)
            command = row["commands"][0]
            self.assertIn("-DREQUIRED=3", command["arguments"])
            self.assertEqual(command["directory"], str(build))
            self.assertEqual(bool(command["heuristic"]), row["inferred"])
        self.doctor(source, "--build-path", prepared)
        coverage = self.coverage_formats([source, "--build-path", prepared, "--accept-partial-coverage"], 1)
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["attempted_tus"], 3)
        self.assertEqual(coverage["analyzed_tus"], 2)
        self.assertEqual(coverage["skipped_tus"], 1)
        self.assertEqual(coverage["failed_tus"], 0)
        self.assertEqual({row["file"] for row in coverage["sources"]}, identities)

    def test_corpus_keeps_direct_variants_and_infers_one_frozen_recipe(self):
        source = self.root / "corpus"
        source.mkdir()
        anchor = source / "anchor.cpp"
        anchor.write_text("int anchor(){return FLAVOR;}\n", encoding="utf-8")
        missing = source / "missing.cpp"
        missing.write_text("int missing(){return FLAVOR;}\n", encoding="utf-8")
        database = self.database(self.root / "original", [anchor], extra=["-DFLAVOR=1"])
        originals = json.loads(database.read_text(encoding="utf-8"))
        originals.append(dict(originals[0], arguments=["clang++", "-DFLAVOR=2", "-c", str(anchor)]))
        database.write_text(json.dumps(originals), encoding="utf-8")
        original_bytes = database.read_bytes()
        prepared = self.root / "prepared"
        commands, evidence = self.corpus_inputs(database, source, anchor, prepared)
        direct = [row for row in commands if row["file"] == str(anchor)]
        self.assertEqual(database.read_bytes(), original_bytes)
        self.assertEqual(direct, evidence["original_commands"])
        self.assertEqual(len(direct), 2)
        for index, row in enumerate(direct, 1):
            self.assertEqual(row["arguments"], ["clang++", "--driver-mode=g++", "-DFLAVOR=" + str(index),
                                                "-c", str(anchor)])
        inferred = [row for row in commands if row["file"] == str(missing)]
        self.assertEqual(len(inferred), 1)
        self.assertIn("-DFLAVOR=1", inferred[0]["arguments"])
        self.assertEqual(inferred[0]["arguments"][-2:], ["--", str(missing)])
        self.assertEqual(len(evidence["original_commands"]), 2)
        coverage = self.coverage_formats([source, "--build-path", prepared], 0)
        self.assertTrue(coverage["complete"])
        self.assertEqual(coverage["analyzed_tus"], 2)
        self.assertEqual(coverage["analyzed_commands"], 3)

    def test_corpus_rejects_invalid_non_anchor_originals_before_inference(self):
        source = self.root / "corpus"
        source.mkdir()
        anchor = source / "anchor.cpp"
        anchor.write_text("int anchor(){return 1;}\n", encoding="utf-8")
        missing = source / "missing.cpp"
        missing.write_text("int missing(){return 1;}\n", encoding="utf-8")
        database = self.database(self.root / "original", [anchor])
        original = json.loads(database.read_text(encoding="utf-8"))[0]
        for index, other in enumerate((
                dict(original, file=str(missing)),
                dict(original, arguments=["clang++", "@missing.rsp", "-c", str(anchor)]),
                dict(original, arguments=["clang++", "-c", str(anchor), "--", str(missing)]),
                dict(original, arguments=["clang++", 3]),
                dict(original, directory=str(self.root / "absent-working-directory"), file=str(missing),
                     arguments=["clang++", "-c", str(missing)]))):
            with self.subTest(index=index):
                database.write_text(json.dumps([original, other]), encoding="utf-8")
                self.corpus_inputs(database, source, anchor, self.root / ("rejected-" + str(index)), expected=2)

    def test_corpus_freezes_expanded_response_before_consuming_prepared_database(self):
        source = self.root / "corpus"
        source.mkdir()
        anchor = source / "anchor.cpp"
        anchor.write_text("int anchor(){return FLAVOR;}\n", encoding="utf-8")
        missing = source / "missing.cpp"
        missing.write_text("int missing(){return FLAVOR;}\n", encoding="utf-8")
        response = self.root / "flags.rsp"
        response.write_text("-DFLAVOR=4", encoding="utf-8")
        database = self.database(self.root / "original", [anchor], extra=["@flags.rsp"])
        prepared = self.root / "prepared"
        commands, evidence = self.corpus_inputs(database, source, anchor, prepared)
        self.assertTrue(all("-DFLAVOR=4" in row["arguments"] for row in commands))
        self.assertFalse(any(arg.startswith("@") for row in commands for arg in row["arguments"]))
        response.write_text("-DFLAVOR=undefined_symbol", encoding="utf-8")
        database.write_text("{invalid later database", encoding="utf-8")
        self.scan(source, "--build-path", prepared, count=2)

    @unittest.skipUnless(os.name == "posix", "raw byte response fixture uses POSIX paths")
    def test_corpus_rejects_non_utf8_response_values_without_output(self):
        source = self.root / "corpus"
        source.mkdir()
        anchor = source / "anchor.cpp"
        anchor.write_text("int anchor(){return 1;}\n", encoding="utf-8")
        (self.root / "flags.rsp").write_bytes(b"-DFLAVOR=\xff")
        database = self.database(self.root / "original", [anchor], extra=["@flags.rsp"])
        self.corpus_inputs(database, source, anchor, self.root / "rejected", expected=2)

    def test_source_coverage_json_sarif_cli_parity_for_clean_and_findings(self):
        for finding in (False, True):
            self.source.write_text("int f(){int zero=0; return 4/zero;}\n" if finding
                                   else "int f(){return 4;}\n", encoding="utf-8")
            for whole_program in (False, True):
                with self.subTest(finding=finding, whole_program=whole_program):
                    coverage = self.coverage_formats(
                        [self.source, *(["--whole-program"] if whole_program else [])], int(finding))
                    self.assertTrue(coverage["complete"])
                    self.assertEqual(coverage["attempted_tus"], 1)
                    self.assertEqual(coverage["analyzed_tus"], 1)
                    self.assertEqual(coverage["analyzed_commands"], 1)
                    row = coverage["sources"][0]
                    self.assertEqual(row["file"], str(self.source))
                    self.assertEqual(row["status"], "analyzed")
                    self.assertEqual(row["prepass"], {"status": "analyzed" if whole_program else "not_requested",
                                                    "reason": "analyzed" if whole_program else "",
                                                    "recovery_commands": 0})

    def test_partial_and_recovery_opt_ins_never_claim_full_coverage(self):
        broken = self.root / "broken.cpp"
        broken.write_text("int broken(){ return undeclared_value; }\n", encoding="utf-8")
        build = self.root / "build"
        self.database(build, [self.source, broken])
        for whole_program in (False, True):
            for flag, expected, analyzed, skipped, recovery in (
                (None, 2, 1, 1, 0), ("--accept-partial-coverage", 0, 1, 1, 0),
                ("--analyze-broken-tus", 0, 2, 0, 1)):
                with self.subTest(flag=flag, whole_program=whole_program):
                    args = [self.root, "--build-path", build, *([flag] if flag else []),
                            *(["--whole-program"] if whole_program else [])]
                    coverage = self.coverage_formats(args, expected)
                    self.assertFalse(coverage["complete"])
                    self.assertEqual(coverage["attempted_tus"], 2)
                    self.assertEqual(coverage["analyzed_tus"], analyzed)
                    self.assertEqual(coverage["skipped_tus"], skipped)
                    self.assertEqual(coverage["failed_tus"], 0)
                    self.assertEqual(coverage["recovery_tus"], recovery)
                    row = next(row for row in coverage["sources"] if row["file"] == str(broken))
                    self.assertEqual(row["status"], "analyzed" if recovery else "skipped")
                    self.assertEqual(row["recovery_commands"], recovery)
                    if whole_program:
                        self.assertEqual(row["prepass"]["status"], row["status"])
                        self.assertEqual(row["prepass"]["recovery_commands"], recovery)
                    # Console-only mode must not label accepted partial/recovery
                    # evidence clean merely because it produced zero findings.
                    console = self.run_cli(*args)
                    self.assertEqual(console.returncode, expected)
                    self.assertNotIn("Clean!", console.stdout + console.stderr)

    def test_promoted_warning_obeys_broken_ast_policy_and_prepass(self):
        rejected = self.root / "rejected.cpp"
        rejected.write_text("#if UNDEFINED_CONTROL\nint unused;\n#endif\n"
                            "int rejected(){int zero=0; return 4/zero;}\n", encoding="utf-8")
        build = self.root / "build"
        for promoted in (False, True):
            self.database(build, [self.source, rejected],
                          extra=["-Wundef", *(["-Werror"] if promoted else [])])
            for whole_program in (False, True):
                for flag in (None, "--accept-partial-coverage", "--analyze-broken-tus"):
                    with self.subTest(promoted=promoted, whole_program=whole_program, flag=flag):
                        recover = promoted and flag == "--analyze-broken-tus"
                        skipped = int(promoted and not recover)
                        expected = 2 if promoted and flag is None else 0 if skipped else 1
                        args = [self.root, "--build-path", build, *([flag] if flag else []),
                                *(["--whole-program"] if whole_program else [])]
                        coverage = self.coverage_formats(args, expected)
                        self.assertEqual(coverage["complete"], not promoted)
                        self.assertEqual(coverage["attempted_tus"], 2)
                        self.assertEqual(coverage["analyzed_tus"], 2 - skipped)
                        self.assertEqual(coverage["skipped_tus"], skipped)
                        self.assertEqual(coverage["failed_tus"], 0)
                        self.assertEqual(coverage["recovery_tus"], int(recover))
                        row = next(s for s in coverage["sources"] if s["file"] == str(rejected))
                        self.assertEqual(row["status"], "skipped" if skipped else "analyzed")
                        self.assertEqual(row["recovery_commands"], int(recover))
                        self.assertEqual(row["prepass"]["status"],
                                         row["status"] if whole_program else "not_requested")
                        self.assertEqual(row["prepass"]["recovery_commands"],
                                         int(recover and whole_program))
                        payload = json.loads((self.root / "coverage.json").read_text())
                        # Rejected ASTs must not leak a seeded rule finding.
                        self.assertEqual(payload["total"], 0 if skipped else 1)
                        if promoted:
                            console = self.run_cli(*args)
                            self.assertEqual(console.returncode, expected)
                            self.assertNotIn("Clean!", console.stdout + console.stderr)

    def test_all_promoted_warning_sources_still_fail_partial_acceptance(self):
        self.source.write_text("#if UNDEFINED_CONTROL\nint unused;\n#endif\n"
                               "int safe(){return 42;}\n", encoding="utf-8")
        build = self.root / "build"
        self.database(build, extra=["-Werror", "-Wundef"])
        for whole_program in (False, True):
            coverage = self.coverage_formats(
                [self.source, "--build-path", build, "--accept-partial-coverage",
                 *(["--whole-program"] if whole_program else [])], 2)
            self.assertFalse(coverage["complete"])
            self.assertEqual(coverage["analyzed_tus"], 0)
            self.assertEqual(coverage["skipped_tus"], 1)
            self.assertEqual(coverage["failed_tus"], 0)

    def test_real_failed_variant_dominates_diagnostic_rejection_and_recovery(self):
        self.source.write_text("#if UNDEFINED_CONTROL\nint unused;\n#endif\n"
                               "int safe(){return 42;}\n", encoding="utf-8")
        build = self.root / "build"
        database = self.database(build, extra=["-Werror", "-Wundef"])
        rejected = json.loads(database.read_text())[0]
        valid = dict(rejected, arguments=["clang++", "-DUNDEFINED_CONTROL=0", "-c", str(self.source)])
        failed = dict(rejected, arguments=["clang++", "-target", "invalid-cs-target", "-c", str(self.source)])
        for entries in ([valid, rejected, failed], [failed, rejected, valid]):
            database.write_text(json.dumps(entries), encoding="utf-8")
            for whole_program in (False, True):
                for recover in (False, True):
                    with self.subTest(entries=entries, whole_program=whole_program, recover=recover):
                        coverage = self.coverage_formats(
                            [self.source, "--build-path", build, "--accept-partial-coverage",
                             *(["--analyze-broken-tus"] if recover else []),
                             *(["--whole-program"] if whole_program else [])], 2)
                        self.assertFalse(coverage["complete"])
                        self.assertEqual(coverage["attempted_tus"], 1)
                        self.assertEqual(coverage["failed_tus"], 1)
                        self.assertEqual(coverage["attempted_commands"], 3)
                        self.assertEqual(coverage["analyzed_commands"], 2 if recover else 1)
                        self.assertEqual(coverage["skipped_commands"], 0 if recover else 1)
                        self.assertEqual(coverage["failed_commands"], 1)
                        row = coverage["sources"][0]
                        self.assertEqual(row["status"], "failed")
                        self.assertEqual(row["reason"], "frontend_failed")
                        self.assertEqual(row["prepass"]["status"],
                                         "failed" if whole_program else "not_requested")

    def test_failed_variant_dominates_success_in_both_orders_and_prepass(self):
        build = self.root / "build"
        database = self.database(build)
        valid = json.loads(database.read_text())[0]
        failed = dict(valid, arguments=["clang++", "-target", "invalid-cs-target", "-c", str(self.source)])
        for entries in ([valid, failed], [failed, valid]):
            database.write_text(json.dumps(entries), encoding="utf-8")
            for flags in ([], ["--whole-program"], ["--accept-partial-coverage", "--analyze-broken-tus"]):
                with self.subTest(entries=entries, flags=flags):
                    coverage = self.coverage_formats([self.source, "--build-path", build, *flags], 2)
                    self.assertFalse(coverage["complete"])
                    self.assertEqual(coverage["attempted_tus"], 1)
                    self.assertEqual(coverage["analyzed_tus"], 0)
                    self.assertEqual(coverage["failed_tus"], 1)
                    self.assertEqual(coverage["attempted_commands"], 2)
                    self.assertEqual(coverage["analyzed_commands"], 1)
                    self.assertEqual(coverage["failed_commands"], 1)
                    row = coverage["sources"][0]
                    self.assertEqual(row["file"], str(self.source))
                    self.assertEqual(row["status"], "failed")
                    self.assertTrue(row["reason"])
                    self.assertEqual(row["prepass"]["status"], "failed" if "--whole-program" in flags else "not_requested")

    def test_early_input_failure_has_identical_coverage_in_all_formats(self):
        build = self.root / "build"
        build.mkdir()
        (build / "compile_commands.json").write_text("[{broken", encoding="utf-8")
        coverage = self.coverage_formats([self.source, "--build-path", build], 2)
        self.assertEqual(coverage["attempted_tus"], 1)
        self.assertEqual(coverage["failed_tus"], 1)
        self.assertEqual(coverage["sources"][0]["file"], str(self.source))
        self.assertFalse(coverage["complete"])

    def test_output_write_failure_is_reflected_in_final_console_coverage(self):
        result = self.run_cli(self.source, "--json", self.root / "missing" / "report.json")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        prefix = "[CodeSkeptic] source coverage: "
        coverage = [json.loads(line[len(prefix):]) for line in result.stderr.splitlines()
                    if line.startswith(prefix)]
        self.assertEqual(len(coverage), 1, result.stderr)
        self.assertEqual(coverage[0]["analyzed_tus"], 1)
        self.assertFalse(coverage[0]["complete"], result.stderr)

    @unittest.skipUnless(os.name == "posix", "non-UTF8 filesystem bytes require POSIX")
    def test_non_utf8_source_identity_cannot_corrupt_coverage_json(self):
        for name in (b"invalid-\xff.cpp", b"invalid-\xfe.cpp", b"parent-\xff/valid.cpp"):
            source = self.root / os.fsdecode(name)
            source.parent.mkdir(exist_ok=True)
            source.write_text("int safe(){return 0;}\n", encoding="utf-8")
            identity = "codeskeptic-bytes:" + os.fsencode(source).hex()
            for flag in (None, "--accept-partial-coverage", "--analyze-broken-tus"):
                with self.subTest(name=name, flag=flag):
                    # Also decode all stdout/stderr strictly; doctor output must
                    # not invalidate an otherwise valid JSON/CLI response.
                    coverage = self.coverage_formats([source, *([flag] if flag else [])], 2)
                    self.assertFalse(coverage["complete"])
                    self.assertEqual(coverage["attempted_tus"], 1)
                    self.assertEqual(coverage["failed_tus"], 1)
                    self.assertEqual(coverage["attempted_commands"], 0)
                    self.assertEqual(len(coverage["sources"]), 1)
                    row = coverage["sources"][0]
                    self.assertEqual(row["file"], identity)
                    self.assertEqual(row["status"], "failed")
                    self.assertEqual(row["reason"], "source_path_not_utf8")
            output = self.root / "byte-path.html"
            result = self.run_cli(source, "--html", output)
            self.assertEqual(result.returncode, 2, result.stderr)
            html = output.read_text(encoding="utf-8")
            self.assertIn(identity, html)
            self.assertIn("Full coverage: no", html)
            self.assertIn("source_path_not_utf8", html)
            self.doctor(source, expected=2)

    @unittest.skipUnless(os.name == "posix", "non-UTF8 filesystem bytes require POSIX")
    def test_mixed_source_encodings_preserve_every_requested_identity(self):
        invalid = self.root / os.fsdecode(b"invalid-\xff.cpp")
        invalid.write_text("int safe(){return 0;}\n", encoding="utf-8")
        coverage = self.coverage_formats([self.root, "--accept-partial-coverage"], 2)
        self.assertEqual(coverage["attempted_tus"], 2)
        self.assertEqual(coverage["failed_tus"], 2)
        self.assertEqual(coverage["analyzed_tus"], 0)
        identities = {row["file"]: row for row in coverage["sources"]}
        encoded = "codeskeptic-bytes:" + os.fsencode(invalid).hex()
        self.assertEqual(set(identities), {str(self.source), encoded})
        self.assertEqual(identities[encoded]["reason"], "source_path_not_utf8")
        self.assertEqual(identities[str(self.source)]["reason"], "compilation_input_unavailable")

    @unittest.skipUnless(os.name == "posix", "non-UTF8 filesystem bytes require POSIX")
    def test_non_utf8_canonical_symlink_target_is_reported_and_mcp_recovers(self):
        source = self.root / os.fsdecode(b"target-\xff.cpp")
        source.write_text("int safe(){return 0;}\n", encoding="utf-8")
        alias = self.root / "alias.cpp"
        alias.symlink_to(source)
        build = self.root / "build"
        self.database(build, [alias])
        coverage = self.coverage_formats([alias, "--build-path", build], 2)
        self.assertEqual(coverage["sources"][0]["file"],
                         "codeskeptic-bytes:" + os.fsencode(source).hex())
        self.assertEqual(coverage["sources"][0]["reason"], "source_path_not_utf8")
        clean = self.root / "clean"
        clean.mkdir()
        safe = clean / "safe.cpp"
        safe.write_text("int safe(){return 0;}\n", encoding="utf-8")
        self.database(clean, [safe])
        requests = [{"jsonrpc": "2.0", "id": index, "method": "tools/call",
                     "params": {"name": "analyze", "arguments": {
                         "path": str(path), "build_path": str(database)}}}
                    for index, (path, database) in enumerate(((alias, build), (safe, clean)), 1)]
        result = subprocess.run([BINARY, "--serve"], cwd=self.root, text=True,
            input="".join(json.dumps(request) + "\n" for request in requests),
            capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(replies), 2, result.stdout)
        payloads = [json.loads(reply["result"]["content"][0]["text"]) for reply in replies]
        self.assertEqual(payloads[0]["coverage"], coverage)
        self.assertEqual(payloads[0]["exit_code"], 2)
        self.assertEqual(payloads[1]["exit_code"], 0)
        self.assertTrue(payloads[1]["coverage"]["complete"])
        self.assertEqual(payloads[1]["coverage"]["sources"][0]["file"], str(safe))

    @unittest.skipUnless(os.name == "posix", "non-UTF8 filesystem bytes require POSIX")
    def test_unrequested_database_symlink_with_non_utf8_target_fails_without_crash(self):
        target = self.root / os.fsdecode(b"target-\xff.cpp")
        target.write_text("int safe(){return 0;}\n", encoding="utf-8")
        alias = self.root / "alias.cpp"
        alias.symlink_to(target)
        build = self.root / "build"
        self.database(build, [self.source, alias])
        # The selected source is UTF-8; database normalization itself must
        # reject the other invalid canonical entry before constructing JSON.
        coverage = self.coverage_formats([self.source, "--build-path", build], 2)
        self.assertEqual(coverage["attempted_tus"], 1)
        self.assertEqual(coverage["failed_tus"], 1)
        self.assertEqual(coverage["sources"][0]["file"], str(self.source))
        self.assertEqual(coverage["sources"][0]["reason"], "compilation_input_unavailable")

    def test_valid_unicode_source_identity_round_trips_all_coverage_formats(self):
        source = self.root / "çalışma-λ-�.cpp"
        source.write_text("int safe(){return 0;}\n", encoding="utf-8")
        coverage = self.coverage_formats([source], 0)
        self.assertTrue(coverage["complete"])
        self.assertEqual(coverage["sources"][0]["file"], str(source))

    def test_unicode_directory_and_output_paths_preserve_identity(self):
        directory = self.root / "çalışma-λ-資料"
        directory.mkdir()
        source = directory / "kaynak-測試.cpp"
        source.write_text("int safe(){return 0;}\n", encoding="utf-8")
        self.doctor(source)
        for option, filename in (("--json", "sonuç-結果.json"),
                                 ("--sarif", "sonuç-結果.sarif")):
            with self.subTest(option=option):
                output = directory / filename
                result = self.run_cli(source, option, output)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                payload = json.loads(output.read_text(encoding="utf-8"))
                coverage = (payload["coverage"] if option == "--json" else
                            payload["runs"][0]["invocations"][0]["properties"]["codeskeptic/coverage"])
                self.assertTrue(coverage["complete"])
                self.assertEqual(coverage["analyzed_tus"], 1)
                self.assertEqual(coverage["sources"][0]["file"], str(source))
                prefix = "[CodeSkeptic] source coverage: "
                console = [json.loads(line[len(prefix):]) for line in result.stderr.splitlines()
                           if line.startswith(prefix)]
                self.assertEqual(console, [coverage])

    def test_explicit_malformed_database_never_falls_back(self):
        build = self.root / "build"
        build.mkdir()
        (build / "compile_commands.json").write_text("[{broken json", encoding="utf-8")
        report = self.root / "report.json"
        result = self.run_cli(self.source, "--build-path", build, "--json", report)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        if report.exists():
            self.assertFalse(json.loads(report.read_text(encoding="utf-8"))["complete"])

    def test_unavailable_database_retains_requested_source_identities(self):
        other = self.root / "other.cpp"
        other.write_text("int other(){return 0;}\n", encoding="utf-8")
        build = self.root / "build"
        build.mkdir()
        (build / "compile_commands.json").write_text("[{broken", encoding="utf-8")
        _, payload = self.scan(self.root, "--build-path", build, expected=2)
        coverage = payload["coverage"]
        self.assertEqual(coverage["attempted_tus"], 2, coverage)
        self.assertEqual(coverage["failed_tus"], 2, coverage)
        self.assertEqual({s["file"] for s in coverage["sources"]},
                         {str(self.source), str(other)})
        self.assertTrue(all(s["status"] == "failed" and s["reason"]
                            for s in coverage["sources"]))

    def test_missing_file_list_member_has_its_own_failed_record(self):
        build = self.root / "build"
        self.database(build)
        listing = self.root / "partial.txt"
        listing.write_text(str(self.source) + "\nmissing.cpp\n", encoding="utf-8")
        _, payload = self.scan("--files", listing, "--build-path", build, expected=2)
        coverage = payload["coverage"]
        self.assertEqual(coverage["attempted_tus"], 2, coverage)
        self.assertEqual({s["file"] for s in coverage["sources"]},
                         {str(self.source), str(build / "missing.cpp")})
        self.assertEqual(coverage["failed_tus"], 2, coverage)

    def symlink_loop(self):
        loop = self.root / "loop.cpp"
        try:
            loop.symlink_to(loop.name)
        except OSError as error:
            self.skipTest(f"host cannot create the symlink-loop fixture: {error}")
        return loop

    def test_looped_build_path_does_not_erase_valid_requested_source(self):
        loop = self.symlink_loop()
        _, payload = self.scan(self.source, "--build-path", loop, expected=2)
        coverage = payload["coverage"]
        self.assertEqual(coverage["attempted_tus"], 1, coverage)
        self.assertEqual(coverage["failed_tus"], 1, coverage)
        self.assertEqual([s["file"] for s in coverage["sources"]], [str(self.source)])

    def test_looped_file_list_member_retains_every_known_identity(self):
        loop = self.symlink_loop()
        self.database(self.root / "build")
        listing = self.root / "loop-list.txt"
        listing.write_text(str(self.source) + "\n" + str(loop) + "\n", encoding="utf-8")
        _, payload = self.scan("--files", listing, "--build-path", self.root / "build", expected=2)
        coverage = payload["coverage"]
        self.assertEqual(coverage["attempted_tus"], 2, coverage)
        self.assertEqual(coverage["failed_tus"], 2, coverage)
        self.assertEqual({s["file"] for s in coverage["sources"]}, {str(self.source), str(loop)})

    def test_malformed_json_cannot_use_compile_flags(self):
        build = self.root / "build"
        build.mkdir()
        (build / "compile_flags.txt").write_text("-std=c++17\n", encoding="utf-8")
        for malformed in ("[{bad", "[]", "{}", '[{"file":"x.cpp"}]'):
            with self.subTest(malformed=malformed):
                (build / "compile_commands.json").write_text(malformed, encoding="utf-8")
                self.doctor(self.source, "--build-path", build, expected=2)
                self.scan(self.source, "--build-path", build, expected=2)

    def test_explicit_missing_path_never_uses_other_valid_database(self):
        self.database(self.root / "build")
        wrong = self.root / "missing"
        self.doctor(self.source, "--build-path", wrong, expected=2)
        self.scan(self.source, "--build-path", wrong, expected=2)

    def test_configured_build_path_is_also_explicit(self):
        self.database(self.root / "build")
        (self.root / ".codeskeptic.conf").write_text("build_path=missing\n", encoding="utf-8")
        self.doctor(self.source, expected=2)
        self.scan(self.source, expected=2)
        selected = self.doctor(self.source, "--build-path", self.root / "build")
        self.assertEqual(selected["selection"], "explicit")

    def test_empty_project_does_not_become_synthetic_analysis(self):
        empty = self.root / "empty"
        empty.mkdir()
        fields = self.doctor(empty, expected=2)
        self.assertIn("compile_commands.json", fields["next"])
        self.scan(empty, expected=2)

    def test_two_databases_are_ambiguous_until_selected(self):
        first = self.database(self.root / "build")
        second = self.database(self.root / "out" / "build")
        fields = self.doctor(self.source, expected=2)
        self.assertIn("ambiguous", fields["reason"])
        self.assertEqual([fields["candidate[0]"], fields["candidate[1]"]], sorted(map(str, [first, second])))
        self.assertNotIn("selection", fields)
        self.scan(self.source, expected=2)
        chosen = self.doctor(self.source, "--build-path", second.parent)
        self.assertEqual(chosen["database"], str(second))
        analysis, _ = self.scan(self.source, "--build-path", second.parent)
        self.assertIn("database: " + str(second), analysis.stderr)

    def test_bare_c_and_cpp_keep_explicit_synthetic_mode(self):
        for suffix, standard in ((".cpp", "c++17"), (".c", "gnu11")):
            with self.subTest(suffix=suffix):
                source = self.root / ("bare" + suffix)
                source.write_text("int safe(void) { return 42; }\n", encoding="utf-8")
                fields = self.doctor(source)
                self.assertEqual(fields["mode"], "synthetic-single-file")
                self.assertEqual(fields["standard"], standard)
                analysis, _ = self.scan(source)
                self.assertIn("mode: synthetic-single-file", analysis.stderr)

    def test_cmake_ninja_flags_and_directory_scope(self):
        cmake, ninja = shutil.which("cmake"), shutil.which("ninja")
        self.assertIsNotNone(cmake, "CMake fixture tool is required")
        self.assertIsNotNone(ninja, "Ninja fixture tool is required")
        compiler = shutil.which("clang++") or shutil.which("c++") or shutil.which("cl")
        self.assertIsNotNone(compiler, "C++ compiler for CMake fixture is required")
        include = self.root / "include"
        include.mkdir()
        (include / "required.h").write_text("#define HEADER_VALUE 42\n", encoding="utf-8")
        self.source.write_text(
            '#include "required.h"\n#ifndef REQUIRED_DEFINE\n#error missing database flag\n#endif\n'
            'int safe() { return HEADER_VALUE + REQUIRED_DEFINE; }\n', encoding="utf-8")
        (self.root / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(DoctorFixture LANGUAGES CXX)\n"
            "add_library(fixture OBJECT input.cpp)\n"
            "target_include_directories(fixture PRIVATE include)\n"
            "target_compile_definitions(fixture PRIVATE REQUIRED_DEFINE=1)\n", encoding="utf-8")
        build = self.root / "build"
        generated = subprocess.run(
            [cmake, "-S", str(self.root), "-B", str(build), "-G", "Ninja",
             "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_CXX_COMPILER=" + compiler],
            capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        fields = self.doctor(self.root)
        self.assertEqual(fields["database"], str((build / "compile_commands.json").resolve()))
        analysis, _ = self.scan(self.root)
        self.assertIn("database: " + fields["database"], analysis.stderr)
        self.assertEqual(self.doctor(".")["database"], fields["database"])
        self.scan(".")

    def test_requested_project_ignores_unrelated_cwd_database(self):
        self.database(self.root / "build")
        project = self.root / "separate"
        project.mkdir()
        (project / ".git").mkdir()
        source = project / "actual.cpp"
        source.write_text("int safe() { return 1; }\n", encoding="utf-8")
        database = self.database(project / "build", [source])
        fields = self.doctor(source)
        self.assertEqual(fields["database"], str(database))
        self.scan(source)

    def test_nested_repository_never_selects_parent_database(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
        source = nested / "nested.cpp"
        source.write_text("int safe() { return 1; }\n", encoding="utf-8")
        self.database(self.root / "build", [source])
        fields = self.doctor(source)
        self.assertEqual(fields["mode"], "synthetic-single-file")
        self.scan(source)

    def test_no_inferred_command_for_unlisted_source(self):
        other = self.root / "other.cpp"
        other.write_text("int other() { return 2; }\n", encoding="utf-8")
        self.database(self.root / "build", [other])
        fields = self.doctor(self.source, expected=2)
        self.assertIn("exact compile command", fields["reason"])
        self.scan(self.source, expected=2)

    def test_directory_cannot_silently_drop_unmapped_source(self):
        self.database(self.root / "build")
        (self.root / "unmapped.cpp").write_text("int ignored() { return 4; }\n", encoding="utf-8")
        self.doctor(self.root, expected=2)
        self.scan(self.root, expected=2)
        self.doctor(self.source)
        self.scan(self.source)

    def test_database_inside_source_directory_does_not_hide_sources(self):
        sources = self.root / "src"
        sources.mkdir()
        risky = sources / "risky.cpp"
        risky.write_text("int divide() { return 12 / 0; }\n", encoding="utf-8")
        self.database(sources, [self.source, risky])
        self.scan(self.root, "--build-path", sources, expected=1, count=2)
        fields = self.doctor(self.root, "--build-path", sources)
        self.assertEqual(fields["source-files"], "2")

    def test_database_command_cannot_substitute_another_source(self):
        other = self.root / "other.cpp"
        other.write_text("int other() { return 42; }\n", encoding="utf-8")
        self.source.write_text("int divide() { return 12 / 0; }\n", encoding="utf-8")
        path = self.database(self.root / "build", [other])
        entries = json.loads(path.read_text(encoding="utf-8"))
        entries[0]["file"] = str(self.source)
        path.write_text(json.dumps(entries), encoding="utf-8")
        self.scan(self.source, expected=2)
        self.doctor(self.source, expected=2)

    def test_file_list_resolves_build_relative_but_not_wrong_twin(self):
        build = self.root / "build"
        self.database(build)
        listing = self.root / "files.txt"
        listing.write_text("../input.cpp\n", encoding="utf-8")
        self.doctor("--files", listing, "--build-path", build)
        self.scan("--files", listing, "--build-path", build)
        twin = build / "input.cpp"
        twin.write_text("int twin() { return 3; }\n", encoding="utf-8")
        self.database(build, [twin])
        listing.write_text("input.cpp\n", encoding="utf-8")
        self.doctor("--files", listing, "--build-path", build, expected=2)
        self.scan("--files", listing, "--build-path", build, expected=2)

    def test_empty_explicit_file_list_does_not_default_to_current_directory(self):
        self.database(self.root / "build")
        listing = self.root / "empty.txt"
        listing.write_text("", encoding="utf-8")
        self.doctor("--files", listing, expected=2)

    def test_partial_file_list_cannot_be_reported_as_complete(self):
        build = self.root / "build"
        self.database(build)
        listing = self.root / "partial.txt"
        listing.write_text(str(self.source) + "\nmissing.cpp\n", encoding="utf-8")
        self.doctor("--files", listing, "--build-path", build, expected=2)
        self.scan("--files", listing, "--build-path", build, expected=2)

    def test_relative_command_directory_is_relative_to_database(self):
        build = self.root / "build"
        path = self.database(build)
        path.write_text(json.dumps([{"directory": "..", "file": "input.cpp",
                                     "arguments": ["clang++", "-c", "input.cpp"]}]), encoding="utf-8")
        self.doctor(self.source)
        self.scan(self.source)

    def test_response_file_is_expanded_without_running_a_compiler(self):
        self.source.write_text(
            "#ifndef REQUIRED\n#error response flags missing\n#endif\n"
            "int safe() { return REQUIRED; }\n", encoding="utf-8")
        response = self.root / "arguments.rsp"
        response.write_text('-DREQUIRED=42 -c "' + self.source.as_posix() + '"\n', encoding="utf-8")
        path = self.database(self.root / "build")
        entries = json.loads(path.read_text(encoding="utf-8"))
        entries[0]["arguments"] = ["clang++", "@" + response.as_posix()]
        path.write_text(json.dumps(entries), encoding="utf-8")
        self.doctor(self.source)
        self.scan(self.source)
        response.unlink()
        self.doctor(self.source, expected=2)
        self.scan(self.source, expected=2)

    def test_working_directory_cannot_substitute_a_same_named_source(self):
        self.source.write_text("int f(){return 12/0;}\n", encoding="utf-8")
        other = self.root / "other"
        other.mkdir()
        (other / "input.cpp").write_text("int f(){return 12;}\n", encoding="utf-8")
        path = self.database(self.root / "build")
        for option in (["-working-directory=other"], ["-working-directory", "other"]):
            with self.subTest(option=option):
                entry = {"directory": str(self.root), "file": str(self.source),
                         "arguments": ["clang++", *option, "-c", "input.cpp"]}
                path.write_text(json.dumps([entry]), encoding="utf-8")
                self.doctor(self.source, expected=2)
                self.scan(self.source, expected=2)

    def test_working_directory_preserves_matching_absolute_and_last_option_inputs(self):
        self.source.write_text("int f(){return 12/0;}\n", encoding="utf-8")
        other = self.root / "other"
        other.mkdir()
        path = self.database(self.root / "build")
        for options, source in ((["-working-directory=other"], self.source.as_posix()),
                                (["-working-directory=other", "-working-directory=."], "input.cpp")):
            with self.subTest(options=options):
                entry = {"directory": str(self.root), "file": str(self.source),
                         "arguments": ["clang++", *options, "-c", source]}
                path.write_text(json.dumps([entry]), encoding="utf-8")
                self.doctor(self.source)
                self.scan(self.source, expected=1)

    def test_option_values_are_not_mistaken_for_other_source_inputs(self):
        include = self.root / "included.cpp"
        include.write_text("#define INCLUDED_VALUE 42\n", encoding="utf-8")
        self.source.write_text("int safe() { return INCLUDED_VALUE; }\n", encoding="utf-8")
        self.database(self.root / "build", extra=["-include", str(include)])
        self.doctor(self.source)
        self.scan(self.source)

    def test_end_of_options_preserves_exactly_one_declared_source(self):
        other = self.root / "other.cpp"
        other.write_text("int other(){return 42;}\n", encoding="utf-8")
        path = self.database(self.root / "build")
        for before, after, expected in (
            ([], ["input.cpp"], 0),
            (["input.cpp"], [], 0),
            (["-include", "other.cpp"], ["input.cpp"], 0),
            ([], ["other.cpp"], 2),
            ([], ["input.cpp", "other.cpp"], 2),
            (["input.cpp"], ["other.cpp"], 2),
            ([], ["input.cpp", "input.cpp"], 2),
            ([], ["input.cpp", "-DNOT_AN_OPTION=1"], 2),
            ([], [], 2),
        ):
            with self.subTest(before=before, after=after):
                entry = {"directory": str(self.root), "file": str(self.source),
                         "arguments": ["clang++", "-c", *before, "--", *after]}
                path.write_text(json.dumps([entry]), encoding="utf-8")
                self.doctor(self.source, expected=expected)
                self.scan(self.source, expected=expected)

    def test_cl_mode_keeps_option_operands_and_rejects_wrong_actual_input(self):
        include = self.root / "included.cpp"
        include.write_text("#define INCLUDED_VALUE 33\n", encoding="utf-8")
        self.source.write_text("int safe() { return INCLUDED_VALUE + REQUIRED; }\n", encoding="utf-8")
        other = self.root / "other.cpp"
        other.write_text("int other() { return 42; }\n", encoding="utf-8")
        path = self.database(self.root / "build")
        for driver in (["clang-cl"], ["cl.exe"], ["clang++", "--driver-mode=cl"]):
            with self.subTest(driver=driver):
                entry = {"directory": str(self.root), "file": str(self.source),
                         "arguments": [*driver, "/DREQUIRED=9", "/FI", "included.cpp", "/c", "input.cpp"]}
                path.write_text(json.dumps([entry]), encoding="utf-8")
                self.doctor(self.source)
                self.scan(self.source)
                entry["arguments"][-1] = "other.cpp"
                path.write_text(json.dumps([entry]), encoding="utf-8")
                self.doctor(self.source, expected=2)
                self.scan(self.source, expected=2)

    def test_cl_mode_response_flags_and_wrong_or_missing_input(self):
        self.source.write_text("int safe() { return REQUIRED; }\n", encoding="utf-8")
        other = self.root / "other.cpp"
        other.write_text("int other() { return 42; }\n", encoding="utf-8")
        path = self.database(self.root / "build")
        response = self.root / "cl-arguments.rsp"
        entry = {"directory": str(self.root), "file": str(self.source),
                 "arguments": ["clang-cl", "@" + response.as_posix()]}
        path.write_text(json.dumps([entry]), encoding="utf-8")
        response.write_text('/DREQUIRED=42 /c "input.cpp"\n', encoding="utf-8")
        self.doctor(self.source)
        self.scan(self.source)
        response.write_text('/DREQUIRED=42 /c "other.cpp"\n', encoding="utf-8")
        self.doctor(self.source, expected=2)
        self.scan(self.source, expected=2)
        response.unlink()
        self.doctor(self.source, expected=2)
        self.scan(self.source, expected=2)

    def test_shell_command_database_and_paths_with_spaces(self):
        source = self.root / "source space.cpp"
        source.write_text("int safe() { return 42; }\n", encoding="utf-8")
        path = self.database(self.root / "custom build", [source])
        entries = json.loads(path.read_text(encoding="utf-8"))
        entries[0].pop("arguments")
        entries[0]["command"] = 'clang++ -c "' + source.as_posix() + '"'
        path.write_text(json.dumps(entries), encoding="utf-8")
        self.doctor(source, "--build-path", path.parent)
        self.scan(source, "--build-path", path.parent)

    def test_common_compiler_wrapper_database(self):
        path = self.database(self.root / "build")
        entries = json.loads(path.read_text(encoding="utf-8"))
        entries[0]["arguments"].insert(0, "ccache")
        path.write_text(json.dumps(entries), encoding="utf-8")
        self.doctor(self.source)
        self.scan(self.source)

    def test_symlink_alias_is_one_database(self):
        database = self.database(self.root / "build")
        try:
            (self.root / "compile_commands.json").symlink_to(database)
        except (OSError, NotImplementedError) as error:
            self.skipTest("host cannot create this symlink fixture: " + str(error))
        fields = self.doctor(self.source)
        self.assertEqual(fields["database"], str(database))

    def test_doctor_rejects_execution_mode_conflicts(self):
        for args in (("--serve",), ("--json", "report.json"), ("--summary-diff", "old", "new")):
            with self.subTest(args=args):
                result = self.run_cli("--doctor", self.source, *args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--doctor", result.stderr)


if __name__ == "__main__":
    unittest.main()
