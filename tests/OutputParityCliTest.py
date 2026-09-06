#!/usr/bin/env python3
"""Bounded installed-binary output/selection contract; compile-only fixtures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


if len(sys.argv) < 2:
    raise SystemExit("usage: OutputParityCliTest.py <codeskeptic-binary>")
BINARY = Path(sys.argv.pop(1)).resolve()


class OutputParityCliTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="codeskeptic-output-parity-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_cli(self, *arguments, cwd=None):
        return subprocess.run([str(BINARY), *map(str, arguments)],
                              cwd=cwd or self.root, capture_output=True,
                              text=True, timeout=45)

    def test_malformed_options_and_config_are_deterministic(self):
        source = self.root / "valid.cpp"
        source.write_text("int f(){return 0;}\n")
        cases = [
            ("unknown-option", [source, "--no-such-option"], ""),
            ("missing-output", [source, "--json"], ""),
            ("conflicting-output", [source, "--json", "one.json", "--sarif", "two.sarif"], ""),
            ("bad-language", [source, "--lang", "unknown"], ""),
            ("unknown-rule", [source, "--disable-rule", "nonexistent-rule"], ""),
            ("bad-config-bool", [source], "analyze_broken_tus=maybe\n"),
            ("bad-config-key", [source], "not_a_setting=true\n"),
            ("bad-config-format", [source], "output_format=invalid\n"),
        ]
        for label, arguments, config in cases:
            with self.subTest(label=label):
                directory = self.root / label
                directory.mkdir()
                (directory / ".codeskeptic.conf").write_text(config)
                first = self.run_cli(*arguments, cwd=directory)
                second = self.run_cli(*arguments, cwd=directory)
                self.assertEqual(first.returncode, 2, first.stderr)
                self.assertEqual(first.stdout, "")
                self.assertEqual((first.returncode, first.stdout, first.stderr),
                                 (second.returncode, second.stdout, second.stderr))
                self.assertFalse((directory / "one.json").exists())
                self.assertFalse((directory / "two.sarif").exists())

    def test_report_paths_respect_directory_and_file_boundaries(self):
        project = self.root / "project with spaces"
        paths = ["src/keep.cpp", "src/deep/keep.cpp", "src2/neighbor.cpp", "src/keep.cpp.more.cpp"]
        for index, relative in enumerate(paths):
            path = project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"int f{index}(){{int zero=0;return 1/zero;}}\n")
        (project / "compile_commands.json").write_text(json.dumps([
            {"directory": str(project), "file": str(project / relative),
             "arguments": ["clang++", "-std=c++17", "-c", str(project / relative)]}
            for relative in paths]))
        full_coverage = None
        for label, selection, expected in (
                ("all", None, set(paths)),
                ("directory", project / "src", set(paths) - {"src2/neighbor.cpp"}),
                ("file", project / "src/keep.cpp", {"src/keep.cpp"})):
            with self.subTest(label=label):
                output = self.root / (label + ".json")
                arguments = [project, "--build-path", project, "--json", output]
                if selection is not None: arguments += ["--report-paths", selection]
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                report = json.loads(output.read_text())
                self.assertTrue(report["complete"])
                if full_coverage is None: full_coverage = report["coverage"]
                self.assertEqual(report["coverage"], full_coverage)
                actual = {Path(row["file"]).relative_to(project).as_posix()
                          for row in report["diagnostics"]}
                self.assertEqual(actual, expected)

    @unittest.skipIf(sys.platform == "win32", "Windows forbids C0 bytes in real filenames; reporter fixtures cover them")
    def test_json_preserves_control_byte_in_real_path(self):
        source = self.root / "control\x01.cpp"
        source.write_text("int f(){int zero=0;return 1/zero;}\n")
        output = self.root / "report.json"
        result = self.run_cli(source, "--json", output)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        report = json.loads(output.read_text())
        self.assertTrue(report["complete"])
        self.assertEqual(len(report["diagnostics"]), 1)
        self.assertEqual(report["diagnostics"][0]["file"], str(source))


if __name__ == "__main__":
    unittest.main()
