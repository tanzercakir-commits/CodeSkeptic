#!/usr/bin/env python3
"""Regression tests for verified progress and cross-host review paths."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import progress_status  # noqa: E402
import review_report  # noqa: E402


class RepositoryFixture:
    def __init__(self, directory: Path) -> None:
        self.root = directory / "work"
        self.root.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Status Test")
        self.git("config", "user.email", "status@example.invalid")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "TODO.md").write_text(
            "# TODO\n\n<!-- cs:state-begin -->\n```\nstale\n```\n"
            "<!-- cs:state-end -->\n",
            encoding="utf-8",
            newline="\n",
        )
        (self.root / "payload.txt").write_text(
            "initial\n", encoding="utf-8", newline="\n"
        )
        self.git("add", ".")
        self.git("commit", "-m", "Phase 7: initial protected transition (#1)")
        self.main_oid = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-ref", "refs/remotes/origin/main", self.main_oid)
        self.git("checkout", "-b", "phase-status-test")

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if completed.returncode != 0:
            self_error = completed.stderr.strip() or completed.stdout.strip()
            raise AssertionError(
                f"git {' '.join(args)} failed ({completed.returncode}): "
                f"{self_error}"
            )
        return completed

    def advance_main(self, directory: Path) -> str:
        del directory  # the synthetic commit needs no checkout or worktree
        parent = self.git("rev-parse", "refs/remotes/origin/main").stdout.strip()
        tree = self.git("rev-parse", f"{parent}^{{tree}}").stdout.strip()
        oid = self.git(
            "commit-tree",
            tree,
            "-p",
            parent,
            "-m",
            "Maintenance: verified next transition (#2)",
        ).stdout.strip()
        self.git("update-ref", "refs/remotes/origin/main", oid)
        return oid


class ProgressStatusTest(unittest.TestCase):
    def test_sync_is_append_only_and_never_promotes_phase_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                first = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )
                progress_path = fixture.root / "docs" / "PROGRESS.md"
                todo_path = fixture.root / "docs" / "TODO.md"
                original = progress_path.read_text(encoding="utf-8")

                self.assertEqual(first.appended, 1)
                self.assertIn(fixture.main_oid, original)
                self.assertNotIn("phase-status-test", original)
                self.assertIn("in_flight     = phase-status-test", first.todo)
                checked = progress_status.check_repository(
                    fixture.root, "origin/main"
                )
                self.assertEqual(checked.appended, 0)

                todo_path.write_text(
                    first.todo.replace("verified_main", "stale_main", 1),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.check_repository(
                        fixture.root, "origin/main"
                    )
                repaired = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )
                self.assertEqual(repaired.appended, 0)
                self.assertEqual(
                    progress_path.read_text(encoding="utf-8"), original
                )

                next_oid = fixture.advance_main(directory)
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.check_repository(
                        fixture.root, "origin/main"
                    )
                advanced = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )
                updated = progress_path.read_text(encoding="utf-8")
                self.assertEqual(advanced.appended, 1)
                self.assertTrue(updated.startswith(original))
                self.assertIn(next_oid, updated)
                self.assertIn(
                    "verified_main = " + next_oid[:7], advanced.todo
                )
                self.assertIn(
                    "base          = " + fixture.main_oid[:7], advanced.todo
                )

    def test_manual_progress_rewrite_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                path = fixture.root / "docs" / "PROGRESS.md"
                original = path.read_text(encoding="utf-8")
                path.write_text(
                    progress_status.CURSOR_RE.sub("", original),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.check_repository(
                        fixture.root, "origin/main"
                    )

                path.write_text(
                    original.replace(
                        "initial protected transition", "rewritten transition"
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(fixture.root, "origin/main")

    def test_nonancestor_protected_main_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                tree = fixture.git(
                    "rev-parse", f"{fixture.main_oid}^{{tree}}"
                ).stdout.strip()
                unrelated = fixture.git(
                    "commit-tree", tree, "-m", "Unrelated protected history"
                ).stdout.strip()
                fixture.git(
                    "update-ref", "refs/remotes/origin/main", unrelated
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.check_repository(
                        fixture.root, "origin/main"
                    )


class ReviewPathTest(unittest.TestCase):
    def test_windows_compile_paths_remap_sources_but_preserve_builds(self) -> None:
        source = r"C:\Projects\CodeSkeptic"
        target = r"C:\tmp\base"
        selected_build = r"C:\Projects\CodeSkeptic\build-phase7"
        command = (
            r"cl -IC:\Projects\CodeSkeptic\src "
            r"-external:IC:\Projects\CodeSkeptic\build-phase4\_deps\gtest "
            r"-IC:\Projects\CodeSkeptic\build-phase7\generated "
            r"-c C:/Projects/CodeSkeptic/src/engine/CfgCache.cpp "
            r"-IC:\Projects\CodeSkepticExtra\src"
        )
        rewritten = review_report._rewrite_compile_path(
            command, source, target, selected_build
        )
        self.assertIn(r"-IC:\tmp\base\src", rewritten)
        self.assertIn(r"C:\tmp\base/src/engine/CfgCache.cpp", rewritten)
        self.assertIn(
            r"C:\Projects\CodeSkeptic\build-phase4\_deps\gtest", rewritten
        )
        self.assertIn(
            r"C:\Projects\CodeSkeptic\build-phase7\generated", rewritten
        )
        self.assertIn(r"C:\Projects\CodeSkepticExtra\src", rewritten)

    def test_relative_review_paths_always_use_git_separators(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "src" / "engine" / "CfgCache.cpp"
            path.parent.mkdir(parents=True)
            path.write_text("// fixture\n", encoding="utf-8")
            self.assertEqual(
                review_report.rel_to_root(str(path), str(root)),
                "src/engine/CfgCache.cpp",
            )


if __name__ == "__main__":
    unittest.main()
