#!/usr/bin/env python3
"""Hermetic compilation-database discovery checks using the real CLI."""

import json
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
        self.root = Path(self.fixture.name)
        self.source = self.root / "input.cpp"
        self.source.write_text("int safe() { return 42; }\n", encoding="utf-8")

    def run_cli(self, *args):
        return subprocess.run(
            [BINARY, *map(str, args)], cwd=self.root, text=True,
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

    def test_explicit_malformed_database_never_falls_back(self):
        build = self.root / "build"
        build.mkdir()
        (build / "compile_commands.json").write_text("[{broken json", encoding="utf-8")
        report = self.root / "report.json"
        result = self.run_cli(self.source, "--build-path", build, "--json", report)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        if report.exists():
            self.assertFalse(json.loads(report.read_text(encoding="utf-8"))["complete"])

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

    def test_option_values_are_not_mistaken_for_other_source_inputs(self):
        include = self.root / "included.cpp"
        include.write_text("#define INCLUDED_VALUE 42\n", encoding="utf-8")
        self.source.write_text("int safe() { return INCLUDED_VALUE; }\n", encoding="utf-8")
        self.database(self.root / "build", extra=["-include", str(include)])
        self.doctor(self.source)
        self.scan(self.source)

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
