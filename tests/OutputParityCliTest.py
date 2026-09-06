#!/usr/bin/env python3
"""Bounded installed-binary output/selection contract; compile-only fixtures."""
import json
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import unquote_to_bytes, urlsplit


if len(sys.argv) < 2:
    raise SystemExit("usage: OutputParityCliTest.py <codeskeptic-binary>")
BINARY = Path(sys.argv.pop(1)).resolve()


class ReportHtml(HTMLParser):
    def __init__(self, content):
        super().__init__(convert_charrefs=True)
        self.snapshot = []
        self.visible = []
        self.in_snapshot = False
        self.hidden = None
        self.dependencies = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "pre" and attrs.get("id") == "codeskeptic-report":
            self.in_snapshot = True
        if tag in ("script", "style"):
            self.hidden = tag
        if (tag in ("script", "img", "iframe") and "src" in attrs) or tag == "link":
            self.dependencies.append((tag, attrs))

    def handle_endtag(self, tag):
        if tag == "pre": self.in_snapshot = False
        if tag == self.hidden: self.hidden = None

    def handle_data(self, data):
        if self.in_snapshot: self.snapshot.append(data)
        elif not self.hidden: self.visible.append(data)


def uri_path_identity(uri):
    parts = urlsplit(uri)
    if parts.query or parts.fragment:
        raise AssertionError(f"filename leaked into URI query/fragment: {uri!r}")
    path = ("//" + parts.netloc if parts.netloc else "") + parts.path
    raw = unquote_to_bytes(path)
    try:
        text = raw.decode("utf-8")
        if sys.platform == "win32":
            if len(text) > 3 and text[0] == "/" and text[2] == ":": text = text[1:]
            text = str(Path(text))
        return text if not text.startswith("codeskeptic-bytes:") else "codeskeptic-bytes:" + raw.hex()
    except UnicodeDecodeError:
        return "codeskeptic-bytes:" + raw.hex()


class OutputParityCliTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="codeskeptic-output-parity-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_cli(self, *arguments, cwd=None):
        return subprocess.run([str(BINARY), *map(str, arguments)],
                              cwd=cwd or self.root, capture_output=True,
                              text=True, timeout=45)

    def sarif_report(self, document):
        self.assertEqual(document["version"], "2.1.0")
        self.assertTrue(document["$schema"].endswith("sarif-schema-2.1.0.json"))
        self.assertEqual(len(document["runs"]), 1)
        run = document["runs"][0]
        report = dict(run["properties"]["codeskeptic/report"])
        self.assertEqual(run["tool"]["driver"]["name"], report["tool"])
        self.assertEqual(run["tool"]["driver"]["version"], report["tool_version"])
        invocation = run["invocations"][0]
        props = invocation["properties"]
        self.assertEqual(invocation["executionSuccessful"], report["complete"])
        self.assertEqual(props["codeskeptic/status"], report["status"])
        self.assertEqual(props["codeskeptic/exitCode"], report["exit_code"])
        self.assertEqual(props["codeskeptic/blockingFindings"], report["finding_counts"]["blocking"])
        self.assertEqual(props["codeskeptic/reportOnlyFindings"], report["finding_counts"]["report_only"])
        report["coverage"] = props["codeskeptic/coverage"]
        report["diagnostics"] = []
        for native in run["results"]:
            location = native["locations"][0]
            physical = location["physicalLocation"]
            props = native["properties"]
            row = {
                "rule_id": native["ruleId"],
                "severity": {"note": "info", "warning": "warning", "error": "error"}[native["level"]],
                "rule_metadata": props["codeskeptic/ruleMetadata"],
                "capability_tier": props["codeskeptic/capabilityTier"],
                "blocks_verdict": props["codeskeptic/blocksVerdict"],
                "fingerprint": native["partialFingerprints"]["codeskeptic/v1"],
                "file": uri_path_identity(physical["artifactLocation"]["uri"]),
                "line": physical["region"]["startLine"], "column": physical["region"]["startColumn"],
                "function": location.get("logicalLocations", [{"name": ""}])[0]["name"],
                "message": native["message"]["text"], "notes": [],
            }
            for note in native.get("relatedLocations", []):
                physical = note["physicalLocation"]
                row["notes"].append({"file": uri_path_identity(physical["artifactLocation"]["uri"]),
                                     "line": physical["region"]["startLine"],
                                     "column": physical["region"]["startColumn"],
                                     "message": note["message"]["text"]})
            report["diagnostics"].append(row)
        return report

    def compare_formats(self, arguments, expected_exit, expected_status, version):
        reports = {}
        visible = {}
        for format in ("json", "sarif", "html", "console"):
            output = self.root / ("parity." + format)
            result = self.run_cli(*arguments, "--lang", "en",
                                  *([] if format == "console" else ["--" + format, output]))
            self.assertEqual(result.returncode, expected_exit, result.stderr)
            self.assertEqual(result.stdout, "", "machine/human reports must not leak to stdout")
            coverage = [json.loads(line.removeprefix("[CodeSkeptic] source coverage: "))
                        for line in result.stderr.splitlines()
                        if line.startswith("[CodeSkeptic] source coverage: ")]
            self.assertEqual(len(coverage), 1, "coverage must not be duplicated")
            if format == "console":
                headers = [json.loads(line.removeprefix("[CodeSkeptic] report: "))
                           for line in result.stderr.splitlines() if line.startswith("[CodeSkeptic] report: ")]
                self.assertEqual(len(headers), 1)
                report = headers[0]
                report["coverage"] = coverage[0]
                report["diagnostics"] = [json.loads(line.removeprefix("[CodeSkeptic] finding: "))
                                         for line in result.stderr.splitlines()
                                         if line.startswith("[CodeSkeptic] finding: ")]
                visible[format] = "\n".join(line for line in result.stderr.splitlines()
                                            if not line.startswith("[CodeSkeptic]"))
            elif format == "html":
                parsed = ReportHtml(output.read_text())
                self.assertEqual(parsed.dependencies, [])
                report = json.loads("".join(parsed.snapshot))
                visible[format] = "".join(parsed.visible)
                self.assertIn("Verdict: " + expected_status, visible[format])
                self.assertIn("Exit code: " + str(expected_exit), visible[format])
                self.assertIn("Tool version: " + version, visible[format])
            else:
                report = json.loads(output.read_text())
                if format == "sarif": report = self.sarif_report(report)
            self.assertEqual(report["coverage"], coverage[0])
            self.assertEqual(report["status"], expected_status)
            self.assertEqual(report["exit_code"], result.returncode)
            self.assertEqual(report["tool_version"], version)
            self.assertEqual(report["schema"], "codeskeptic-report/v1")
            reports[format] = report
        reference = reports["json"]
        for format, report in reports.items():
            self.assertEqual(report, reference, format)
        for native in visible.values():
            if expected_status != "clean": self.assertNotIn("Clean!", native)
            for finding in reference["diagnostics"]:
                for location in [finding, *finding["notes"]]:
                    self.assertIn(f"{location['file']}:{location['line']}:{location['column']}", native)
                    self.assertIn(location["message"], native)
                for cwe in finding["rule_metadata"]["cwes"]:
                    self.assertIn(cwe["name"], native)
        return reference

    def test_four_formats_preserve_findings_versions_and_evidence(self):
        version_result = self.run_cli("--version")
        self.assertEqual(version_result.returncode, 0)
        version = version_result.stdout.strip().removeprefix("CodeSkeptic ")
        discovery = self.run_cli("--capabilities", "--json")
        self.assertEqual(discovery.returncode, 0)
        self.assertEqual(json.loads(discovery.stdout)["version"], version)
        for label, source_text, code, status in (
                ("clean", "int f(){return 0;}\n", 0, "clean"),
                ("blocking", "int f(){int zero=0;return 1/zero;}\nint g(){int *p=nullptr;return *p;}\n", 1, "findings"),
                ("report-only", "int f(){int a[2]={1,2};return a[3];}\n", 0, "report-only")):
            with self.subTest(label=label):
                source = self.root / (label + " #.cpp")
                source.write_text(source_text)
                report = self.compare_formats([source], code, status, version)
                self.assertTrue(report["complete"])
                self.assertTrue(report["coverage"]["complete"])
                if label == "blocking":
                    self.assertEqual({row["rule_id"] for row in report["diagnostics"]}, {"div-by-zero", "null-deref"})
                    self.assertTrue(any(row["notes"] for row in report["diagnostics"]))
        project = self.root / "partial"
        project.mkdir()
        for name, content in (("safe.cpp", "int f(){return 0;}\n"),
                              ("broken.cpp", "int g(){return undeclared;}\n")):
            (project / name).write_text(content)
        (project / "compile_commands.json").write_text(json.dumps([
            {"directory": str(project), "file": str(project / name),
             "arguments": ["clang++", "-c", str(project / name)]}
            for name in ("safe.cpp", "broken.cpp")]))
        for flags, code, status in (([], 2, "incomplete"),
                                     (["--accept-partial-coverage"], 0, "partial-accepted"),
                                     (["--analyze-broken-tus"], 0, "recovery-accepted")):
            with self.subTest(status=status):
                report = self.compare_formats([project, "--build-path", project, *flags], code, status, version)
                self.assertEqual(report["complete"], code == 0)
                self.assertFalse(report["coverage"]["complete"])

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
                ("trailing-separator", str(project / "src") + "/", set(paths) - {"src2/neighbor.cpp"}),
                ("project-root", project, set(paths)),
                ("file", project / "src/keep.cpp", {"src/keep.cpp"}),
                ("no-match", project / "missing", set())):
            with self.subTest(label=label):
                output = self.root / (label + ".json")
                arguments = [project, "--build-path", project, "--json", output]
                if selection is not None: arguments += ["--report-paths", selection]
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 1 if expected else 0, result.stderr)
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

    def test_sarif_preserves_reserved_bytes_in_real_path(self):
        # URI delimiters are filename bytes here, not a fragment or query.
        names = ["space # percent%.cpp"]
        if sys.platform != "win32":
            names.append("control\x01.cpp")
        for name in names:
            with self.subTest(name=name):
                source = self.root / name
                source.write_text("int f(){int zero=0;return 1/zero;}\n")
                output = self.root / "report.sarif"
                result = self.run_cli(source, "--sarif", output)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                report = json.loads(output.read_text())
                rows = report["runs"][0]["results"]
                self.assertEqual(len(rows), 1)
                uri = rows[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                self.assertEqual(uri, source.as_uri())


if __name__ == "__main__":
    unittest.main()
