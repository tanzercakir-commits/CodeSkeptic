import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "action_args.py"
sys.path.insert(0, str(ROOT / "scripts"))

import action_args


class ActionArgsTest(unittest.TestCase):
    def test_expands_workspace_variables_without_losing_quoted_spaces(self):
        with mock.patch.dict(
            os.environ,
            {"PWD": "/work/repo", "GITHUB_WORKSPACE": "/work/repo"},
            clear=False,
        ):
            self.assertEqual(
                action_args.parse(
                    '--alloc-functions my_malloc '
                    '--report-paths "$GITHUB_WORKSPACE/source dir"'
                ),
                [
                    "--alloc-functions",
                    "my_malloc",
                    "--report-paths",
                    "/work/repo/source dir",
                ],
            )
            self.assertEqual(
                action_args.parse("--report-paths $PWD/src"),
                ["--report-paths", "/work/repo/src"],
            )

    def test_command_substitution_is_data_not_code(self):
        marker = Path(tempfile.gettempdir()) / "codeskeptic-action-args-pwned"
        if marker.exists():
            marker.unlink()
        value = f"--report-paths '$(touch {marker})'"

        self.assertEqual(
            action_args.parse(value),
            ["--report-paths", f"$(touch {marker})"],
        )
        self.assertFalse(marker.exists())

    def test_rejects_malformed_shell_quoting(self):
        with self.assertRaises(ValueError):
            action_args.parse("--report-paths 'unterminated")

    def test_cli_emits_nul_delimited_arguments(self):
        env = {**os.environ, "GITHUB_WORKSPACE": "/work/source dir"}
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                '--report-paths "$GITHUB_WORKSPACE" --severity warning',
            ],
            check=False,
            capture_output=True,
            env=env,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            result.stdout.split(b"\0")[:-1],
            [
                b"--report-paths",
                b"/work/source dir",
                b"--severity",
                b"warning",
            ],
        )

    def test_cli_rejects_malformed_quoting_with_exit_two(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--report-paths 'unterminated"],
            check=False,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn(b"invalid extra-args", result.stderr)


if __name__ == "__main__":
    unittest.main()
