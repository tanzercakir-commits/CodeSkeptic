#!/usr/bin/env python3
"""Regression contracts for Juliet miss classification and TU selection."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import juliet_eval  # noqa: E402


class JulietEvaluationTest(unittest.TestCase):
    def test_miss_classifier_recognizes_split_cpp_fixture_names(self) -> None:
        known_cpp = (
            "CWE401_Memory_Leak__new_char_81_bad.cpp",
            "CWE401_Memory_Leak__new_char_81_goodG2B.cpp",
            "CWE415_Double_Free__new_delete_82_bad.cpp",
            "CWE416_Use_After_Free__new_delete_83_goodB2G.cpp",
            "CWE190_Integer_Overflow__int_max_add_84_goodG2B.cpp",
            "CWE401_Memory_Leak__new_TwoIntsClass_"
            "virtual_destructor_01_good1.cpp",
            "CWE415_Double_Free__new_delete_"
            "operator_equals_01_bad.cpp",
            "CWE415_Double_Free__new_delete_"
            "operator_equals_01_good1.cpp",
        )
        for name in known_cpp:
            with self.subTest(name=name):
                self.assertEqual(juliet_eval.classify_fn(name), "cpp")

    def test_miss_classifier_preserves_existing_and_unknown_classes(self) -> None:
        expected = {
            "CWE369_Divide_by_Zero__float_zero_divide_01.c": "float",
            "CWE369_Divide_by_Zero__int_rand_divide_02.c": "opaque",
            "CWE369_Divide_by_Zero__int_zero_divide_54c.c": "multifile",
            "CWE369_Divide_by_Zero__int_zero_divide_09.c": "baseline",
            "CWE416_Use_After_Free__malloc_free_char_44.c": "flow",
            "CWE401_Memory_Leak__new_array_TwoIntsClass_72a.cpp": "cpp",
            "CWE190_truly_unknown_fixture.cpp": "other",
            "CWE190_truly_unknown_81_mystery.cpp": "other",
            "CWE190_operator_equals_01_mystery.cpp": "other",
        }
        for name, wanted in expected.items():
            with self.subTest(name=name):
                self.assertEqual(juliet_eval.classify_fn(name), wanted)

    def test_runner_excludes_only_known_main_helper_tus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            suite = temp / "suite"
            cases = (
                suite / "C" / "testcases" /
                "CWE476_NULL_Pointer_Dereference"
            )
            support = suite / "C" / "testcasesupport"
            cases.mkdir(parents=True)
            support.mkdir(parents=True)

            wanted = {
                "CWE476_NULL_Pointer_Dereference__int_01.c",
                "CWE476_NULL_Pointer_Dereference__main_01.cpp",
            }
            for name in wanted | {"main.cpp", "main_linux.cpp"}:
                (cases / name).write_text("int fixture;\n", encoding="utf-8")

            analyzer = temp / "fake-analyzer.py"
            analyzer.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import pathlib
                    import sys

                    output = pathlib.Path(sys.argv[sys.argv.index("--json") + 1])
                    output.write_text(json.dumps({"diagnostics": []}))
                    """
                ),
                encoding="utf-8",
            )
            analyzer.chmod(0o755)

            work = temp / "work"
            env = dict(os.environ, JULIET_DIR=str(suite))
            subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "run_juliet.sh"),
                    str(analyzer),
                    str(work),
                    "0",
                ],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

            selected = {
                Path(line).name
                for line in (
                    work /
                    "files_CWE476_NULL_Pointer_Dereference.txt"
                ).read_text(encoding="utf-8").splitlines()
                if line
            }
            self.assertEqual(selected, wanted)


if __name__ == "__main__":
    unittest.main()
