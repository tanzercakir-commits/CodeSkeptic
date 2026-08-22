#!/usr/bin/env python3
"""Behavioral contract for the fail-closed real-world corpus gate."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_corpus.sh"


class CorpusWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.fixture = Path(self._temporary.name)
        self.tools = self.fixture / "tools"
        self.tools.mkdir()

        fake_cmake = self.tools / "cmake"
        fake_cmake.write_text(
            """#!/usr/bin/env python3
import json
from pathlib import Path
import sys

arguments = sys.argv[1:]
source = Path(arguments[arguments.index("-S") + 1]).resolve()
build = Path(arguments[arguments.index("-B") + 1])
build.mkdir(parents=True, exist_ok=True)
entries = []
for translation_unit in sorted(source.glob("*.c")):
    resolved = translation_unit.resolve(strict=True)
    entries.append({
        "directory": str(source),
        "command": f"cc -c {resolved}",
        "file": str(resolved),
    })
(build / "compile_commands.json").write_text(
    json.dumps(entries),
    encoding="utf-8",
)
""",
            encoding="utf-8",
            newline="\n",
        )
        fake_cmake.chmod(0o755)

        self.analyzer = self.tools / "fake-codeskeptic"
        self.analyzer.write_text(
            """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
file_list = Path(arguments[arguments.index("--files") + 1])
requested = len(file_list.read_text(encoding="utf-8").splitlines())
mode = os.environ["FAKE_ANALYZER_MODE"]
if mode == "complete":
    print(f"[CodeSkeptic] Analysis starting... ({requested} files, 12 rules)")
elif mode == "mismatch":
    print(f"[CodeSkeptic] Analysis starting... ({requested + 1} files, 12 rules)")
elif mode != "nested-only":
    raise SystemExit(f"unsupported fake mode: {mode}")
for _ in range(requested):
    print("[CodeSkeptic] Analysis starting... (1 files, 12 rules)")
""",
            encoding="utf-8",
            newline="\n",
        )
        self.analyzer.chmod(0o755)

        scripts = self.fixture / "scripts"
        scripts.mkdir()
        shutil.copy2(RUNNER, scripts / "run_corpus.sh")
        (scripts / "corpus_expected.txt").write_text(
            "cjson 0\ntinyxml2 0\n",
            encoding="utf-8",
            newline="\n",
        )

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def run_gate(self, mode: str) -> subprocess.CompletedProcess[str]:
        work = self.fixture / f"work-{mode}"
        for project, count in (("cjson", 23), ("tinyxml2", 2)):
            project_dir = work / project
            project_dir.mkdir(parents=True)
            for index in range(count):
                (project_dir / f"sample-{index:02d}.c").write_text(
                    "int sample(void) { return 0; }\n",
                    encoding="utf-8",
                    newline="\n",
                )
            (work / f"{project}.ready").touch()

        environment = os.environ.copy()
        environment["PATH"] = f"{self.tools}{os.pathsep}{environment['PATH']}"
        environment["FAKE_ANALYZER_MODE"] = mode
        return subprocess.run(
            [
                "bash",
                str(self.fixture / "scripts" / "run_corpus.sh"),
                str(self.analyzer),
                str(work),
            ],
            cwd=self.fixture,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

    def test_nested_start_lines_preserve_exact_top_level_coverage(self) -> None:
        result = self.run_gate("complete")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("syntax error", result.stderr)
        self.assertEqual(result.stdout.count("CORPUS_COVERAGE"), 2)
        self.assertIn(
            "CORPUS_COVERAGE cjson enumerated=23 broken=0 "
            "missing_compile_commands=0 analysed=23",
            result.stdout,
        )
        self.assertIn(
            "CORPUS_COVERAGE tinyxml2 enumerated=2 broken=0 "
            "missing_compile_commands=0 analysed=2",
            result.stdout,
        )

    def test_wrong_or_missing_top_level_surface_is_fail_closed(self) -> None:
        for mode in ("mismatch", "nested-only"):
            with self.subTest(mode=mode):
                result = self.run_gate(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "FAIL: incomplete compile-database coverage",
                    result.stdout,
                )


if __name__ == "__main__":
    unittest.main()
