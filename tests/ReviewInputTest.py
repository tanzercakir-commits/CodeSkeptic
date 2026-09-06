#!/usr/bin/env python3
"""Input preparation regressions; existing review verdict gates stay unchanged."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_report.py"
BINARY = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None


class ReviewInputTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-review-input-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.head = self.root / "head"
        self.base = self.root / "base"
        self.head.mkdir()
        self.base.mkdir()
        self.source = self.root / "input.json"
        self.output = self.root / "output.json"

    def remap(self, entries, protect=None, renames=None, expected=0):
        self.source.write_text(json.dumps(entries), encoding="utf-8")
        command = [sys.executable, "-B", str(SCRIPT), "remap-db", "--src", str(self.source),
                   "--from-root", str(self.head), "--to-root", str(self.base),
                   "--out", str(self.output)]
        if protect is not None:
            command += ["--protect", str(protect)]
        if renames is not None:
            path = self.root / "renames.txt"
            path.write_text(renames, encoding="utf-8")
            command += ["--renames", str(path)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected:
            self.assertFalse(self.output.exists(), "invalid input published a database")
            return None
        return json.loads(self.output.read_text(encoding="utf-8"))

    def entry(self, file="lib.c", extra=()):
        return {"directory": str(self.head), "file": str(self.head / file),
                "arguments": ["clang", *extra, "-c", str(self.head / file)]}

    def test_repository_root_is_not_a_protected_build_directory(self):
        entries = self.remap([self.entry()], protect=self.head)
        self.assertEqual(entries[0]["directory"], str(self.base))
        self.assertEqual(entries[0]["file"], str(self.base / "lib.c"))
        self.assertEqual(entries[0]["arguments"], ["clang", "-c", str(self.base / "lib.c")])

    def test_selected_and_sibling_build_paths_stay_at_head(self):
        selected = self.head / "out" / "generated"
        sibling = self.head / "build-old" / "include"
        unrelated = Path(str(self.head) + "-other") / "include"
        arguments = ["-I" + str(selected), "-I" + str(sibling), "-I" + str(unrelated)]
        entries = self.remap([self.entry(extra=arguments)], protect=selected)
        self.assertEqual(entries[0]["arguments"],
                         ["clang", *arguments, "-c", str(self.base / "lib.c")])

    def test_rename_keeps_every_compile_variant_and_flag(self):
        entries = [self.entry("new.c", ["-DFLAVOR=1"]), self.entry("new.c", ["-DFLAVOR=2"])]
        remapped = self.remap(entries, renames="old.c\tnew.c\n")
        self.assertEqual(len(remapped), 2)
        for variant, entry in enumerate(remapped, 1):
            self.assertEqual(entry["file"], str(self.base / "old.c"))
            self.assertEqual(entry["arguments"],
                             ["clang", f"-DFLAVOR={variant}", "-c", str(self.base / "old.c")])

    def test_relative_rename_target_uses_original_working_directory(self):
        entry = {"directory": str(self.head / "src"), "file": "new.c",
                 "arguments": ["clang", "-DNAME=new.c", "-c", "new.c"]}
        remapped = self.remap([entry], renames="src/old.c\tsrc/new.c\n")
        self.assertEqual(remapped[0]["directory"], str(self.base / "src"))
        self.assertEqual(remapped[0]["file"], str(self.base / "src" / "old.c"))
        self.assertEqual(remapped[0]["arguments"],
                         ["clang", "-DNAME=new.c", "-c", str(self.base / "src" / "old.c")])

    @unittest.skipUnless(os.name == "posix", "review shell command strings use POSIX quoting")
    def test_quoted_command_rename_preserves_literal_macro_value(self):
        entry = {"directory": str(self.head), "file": str(self.head / "new file.c"),
                 "command": 'clang -DNAME="new file.c" -c "' + str(self.head / "new file.c") + '"'}
        remapped = self.remap([entry], renames="old file.c\tnew file.c\n")
        import shlex
        self.assertEqual(shlex.split(remapped[0]["command"]),
                         ["clang", "-DNAME=new file.c", "-c", str(self.base / "old file.c")])

    def test_rename_does_not_repair_an_original_wrong_target(self):
        entry = self.entry("new.c")
        entry["arguments"][-1] = str(self.head / "old.c")
        self.remap([entry], renames="old.c\tnew.c\n", expected=2)

    def test_protected_build_cwd_keeps_headers_but_moves_relative_source(self):
        build = self.head / "build"
        entry = {"directory": str(build), "file": "../new.c",
                 "arguments": ["clang", "-I.", "-include", "generated.h", "-c", "../new.c"]}
        remapped = self.remap([entry], protect=build, renames="old.c\tnew.c\n")[0]
        self.assertEqual(remapped["directory"], str(build))
        self.assertEqual(remapped["file"], str(self.base / "old.c"))
        self.assertEqual(remapped["arguments"],
                         ["clang", "-I.", "-include", "generated.h", "-c", str(self.base / "old.c")])

    def test_option_operand_cannot_disguise_original_wrong_source(self):
        for old in ("old.c", str(self.head / "old.c")):
            with self.subTest(old=old):
                entry = self.entry("new.c")
                entry["arguments"] = ["clang", "-include", "new.c", "-c", old]
                self.remap([entry], renames="old.c\tnew.c\n", expected=2)

    def test_ambiguous_rename_commands_fail_without_a_replacement_database(self):
        for arguments in (["clang", "-c"], ["clang", "new.c", "new.c"],
                          ["clang", "@flags.rsp", "new.c"],
                          ["clang", "-working-directory=src", "new.c"],
                          ["clang", "--driver-mode=cl", "new.c"],
                          ["cl.exe", "/Tcnew.c"]):
            with self.subTest(arguments=arguments):
                entry = self.entry("new.c")
                entry["arguments"] = arguments
                self.remap([entry], renames="old.c\tnew.c\n", expected=2)

    def test_directory_relative_to_database_location(self):
        entry = {"directory": "head", "file": "new.c", "arguments": ["clang", "-c", "new.c"]}
        result = self.remap([entry], renames="old.c\tnew.c\n")[0]
        self.assertEqual(result["directory"], str(self.base))
        self.assertEqual(result["arguments"], ["clang", "-c", str(self.base / "old.c")])

    def test_malformed_database_is_infrastructure_failure(self):
        for entries in ({"not": "an array"}, [1], [{"file": "x.c", "directory": 3}],
                        [{"directory": str(self.head), "file": "x.c", "arguments": ["clang", 1]}]):
            with self.subTest(entries=entries):
                self.remap(entries, expected=2)

    def test_malformed_or_escaping_rename_map_is_rejected(self):
        for mapping in ("missing-tab\n", "../old.c\tnew.c\n", "old.c\t/new.c\n",
                        "a.c\tnew.c\nb.c\tnew.c\n"):
            with self.subTest(mapping=mapping):
                self.remap([self.entry("new.c")], renames=mapping, expected=2)


@unittest.skipUnless(BINARY and os.name == "posix", "actual POSIX review flow needs an analyzer binary")
class ReviewFlowInputTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-review-flow-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                        GIT_CONFIG_NOSYSTEM="1", LC_ALL="C")
        self.git("init", "-q")
        self.git("config", "user.name", "review fixture")
        self.git("config", "user.email", "review@test.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.source = self.root / "input.c"
        self.source.write_text('#include "generated.h"\n#include "sibling.h"\nint f(void) { return VALUE + SIBLING; }\n')
        self.git("add", "input.c")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.source.write_text(self.source.read_text() + "// changed source, unchanged finding semantics\n")
        self.build = self.root / "build"
        self.build.mkdir()
        self.sibling = self.root / "build-old"
        self.sibling.mkdir()
        (self.build / "generated.h").write_text("#define VALUE 3\n")
        (self.sibling / "sibling.h").write_text("#define SIBLING 4\n")
        self.database = self.build / "compile_commands.json"
        self.write_database()

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.root, env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def write_database(self, source="input.c"):
        entries = [{"directory": str(self.build), "file": "../" + source,
                    "arguments": ["clang", "-I.", "-I" + str(self.sibling),
                                  "-DFLAVOR=" + variant, "-c", "../" + source]}
                   for variant in ("1", "2")]
        self.database.write_text(json.dumps(entries), encoding="utf-8")

    def review(self, expected, *extra):
        result = subprocess.run(["bash", str(SCRIPT.with_name("review_diff.sh")), BINARY,
                                 self.base, "--build-path", str(self.build), *extra],
                                cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected == 2:
            self.assertNotIn("REVIEW_RESULT", result.stdout)
            self.assertIn("analyzer error", result.stderr)
        return result.stdout

    def test_generated_headers_and_multiple_variants_work_on_both_sides(self):
        self.assertIn("new_errors=0 new_warnings=0 fixed=0 weakened=0 gate=pass", self.review(0))

    def test_rename_preserves_build_cwd_and_generated_headers(self):
        self.git("mv", "input.c", "renamed.c")
        self.write_database("renamed.c")
        self.assertIn("new_errors=0 new_warnings=0 fixed=0 weakened=0 gate=pass", self.review(0))

    def test_missing_generated_header_is_not_clean_even_with_warn_gate(self):
        (self.build / "generated.h").unlink()
        self.review(2, "--gate", "warn")

    def test_missing_database_is_not_clean_even_with_warn_gate(self):
        self.database.unlink()
        self.review(2, "--gate", "warn")

    def test_malformed_and_wrong_input_commands_are_not_repaired(self):
        for data in ("{", "[]", json.dumps([{"directory": str(self.build), "file": "../input.c",
                     "arguments": ["clang", "-c", "../other.c"]}])):
            with self.subTest(data=data):
                self.database.write_text(data)
                self.review(2, "--gate", "warn")

    def test_added_source_has_a_real_head_command_and_no_base_counterpart(self):
        added = self.root / "added.c"
        added.write_text("int added(void) { int *p = 0; return *p; }\n")
        self.git("add", "added.c")
        entries = json.loads(self.database.read_text())
        entries.append({"directory": str(self.root), "file": str(added),
                        "arguments": ["clang", "-c", str(added)]})
        self.database.write_text(json.dumps(entries))
        output = self.review(1)
        self.assertIn("new_errors=1 new_warnings=0 fixed=0 weakened=0 gate=fail", output)
        self.assertIn("added.c", output)


if __name__ == "__main__":
    unittest.main()
