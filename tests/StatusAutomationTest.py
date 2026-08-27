#!/usr/bin/env python3
"""Regression tests for verified progress and cross-host review paths."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import progress_status  # noqa: E402
import review_report  # noqa: E402


def bash_executable() -> str:
    """Prefer Git Bash over the WSL launcher on native Windows runners."""
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            git_root = Path(git).resolve().parent.parent
            for relative in (Path("bin/bash.exe"), Path("usr/bin/bash.exe")):
                candidate = git_root / relative
                if candidate.is_file():
                    return str(candidate)
    bash = shutil.which("bash")
    if bash:
        return bash
    raise AssertionError("a Bash implementation is required for docs guard tests")


def read_git_trace(path: Path) -> list[dict[str, object]]:
    """Return native Git subprocess starts from a Trace2 event stream."""
    calls: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        argv = event.get("argv")
        if event.get("event") != "start" or not isinstance(argv, list) or not argv:
            continue
        executable = (
            str(argv[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()
        )
        if executable in {"git", "git.exe"}:
            calls.append({"tool": "git", "args": argv[1:]})
    return calls


class RepositoryFixture:
    def __init__(self, directory: Path) -> None:
        self.root = directory / "work"
        self.root.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Status Test")
        self.git("config", "user.email", "status@example.invalid")
        # A detached `git maintenance run --auto` can outlive its parent
        # command and race TemporaryDirectory cleanup on hosted runners.
        self.git("config", "gc.auto", "0")
        self.git("config", "maintenance.auto", "false")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "TODO.md").write_text(
            "# TODO\n\n<!-- cs:state-begin -->\n```\nstale\n```\n"
            "<!-- cs:state-end -->\n",
            encoding="utf-8",
            newline="\n",
        )
        catalog = json.dumps(
            {
                "schema": 1,
                "program": "Status automation fixture",
                "items": [
                    {
                        "id": "CS-P10-01",
                        "phase": 10,
                        "title": "First generated work item",
                        "boundary": "Prove automatic queue consumption.",
                        "gates": ["focused automation contract passes"],
                        "depends_on": [],
                    },
                    {
                        "id": "CS-P10-02",
                        "phase": 10,
                        "title": "Second generated work item",
                        "boundary": "Prove dependency ordering.",
                        "gates": ["first item is merged"],
                        "depends_on": ["CS-P10-01"],
                    },
                ],
            },
            indent=2,
        )
        (self.root / "docs" / "PLAN.md").write_text(
            "# Fixed plan\n\n<!-- cs:work-items-begin -->\n"
            "```json\n"
            + catalog
            + "\n```\n<!-- cs:work-items-end -->\n",
            encoding="utf-8",
            newline="\n",
        )
        (self.root / "payload.txt").write_text(
            "initial\n", encoding="utf-8", newline="\n"
        )
        self.git("add", ".")
        self.git("commit", "-m", "Phase 7: initial protected transition (#1)")
        self.legacy_oid = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-ref", "refs/remotes/origin/main", self.legacy_oid)
        self.git("checkout", "-b", "phase-status-test")
        with mock.patch.object(
            progress_status,
            "_in_flight_branches",
            return_value=("phase-status-test",),
        ):
            progress_status.bootstrap_repository(self.root, "origin/main")
        self.git("add", "docs/TODO.md", "docs/PROGRESS.md")
        self.git("commit", "-m", "Bootstrap generated task status")
        self.main_oid = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-ref", "refs/remotes/origin/main", self.main_oid)

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

    def advance_main(
        self,
        directory: Path,
        message: str = "Maintenance: verified next transition (#2)",
    ) -> str:
        del directory  # the synthetic commit needs no checkout or worktree
        parent = self.git("rev-parse", "refs/remotes/origin/main").stdout.strip()
        tree = self.git("rev-parse", f"{parent}^{{tree}}").stdout.strip()
        oid = self.git(
            "commit-tree",
            tree,
            "-p",
            parent,
            "-m",
            message,
        ).stdout.strip()
        self.git("update-ref", "refs/remotes/origin/main", oid)
        return oid


class ProgressStatusTest(unittest.TestCase):
    def test_repository_fixture_disables_background_git_maintenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            self.assertEqual(
                fixture.git("config", "--get", "gc.auto").stdout.strip(),
                "0",
            )
            self.assertEqual(
                fixture.git("config", "--get", "maintenance.auto").stdout.strip(),
                "false",
            )

    def test_git_trace_records_native_subprocess_invocations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "git-trace.jsonl"
            environment = os.environ.copy()
            environment["GIT_ALLOW_PROTOCOL"] = "file"
            environment["GIT_TRACE2_EVENT"] = str(trace)
            completed = subprocess.run(
                ["git", "--version"],
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            blocked = subprocess.run(
                ["git", "ls-remote", "https://example.invalid/repository"],
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("transport 'https' not allowed", blocked.stderr)
            self.assertEqual(
                read_git_trace(trace),
                [
                    {"tool": "git", "args": ["--version"]},
                    {
                        "tool": "git",
                        "args": [
                            "ls-remote",
                            "https://example.invalid/repository",
                        ],
                    },
                ],
            )

    def test_windows_lifecycle_checkout_has_full_history(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "windows.yml").read_text(
            encoding="utf-8"
        )
        checkout = workflow.split("- uses: actions/checkout@v4", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertIn("fetch-depth: 0", checkout)

    def test_corpus_requires_complete_compile_database_surface(self) -> None:
        runner = (ROOT / "scripts" / "run_corpus.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("--accept-partial-coverage", runner)
        self.assertNotIn("run_one scan", runner)
        self.assertIn('requested=$(wc -l < "files-$dir.txt")', runner)
        self.assertIn(
            "missing=$(grep -cF 'Compile command not found.'",
            runner,
        )
        self.assertIn(
            "analysed=$(( ${seen:-0} - ${broke:-0} - ${missing:-0} ))",
            runner,
        )
        self.assertIn(
            '"missing_compile_commands=${missing:-0} analysed=$analysed"',
            runner,
        )
        self.assertIn('if [ "${seen:-0}" -ne "$requested" ] ||', runner)
        self.assertIn('[ "${broke:-0}" -ne 0 ] ||', runner)
        self.assertIn('[ "${missing:-0}" -ne 0 ] ||', runner)
        self.assertIn('[ "$analysed" -ne "$requested" ]; then', runner)

    def test_cross_host_control_files_are_lf_pinned(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("* text=auto eol=lf\n", attributes)
        self.assertIn("docs/PLAN.md text eol=lf\n", attributes)
        self.assertIn("docs/TODO.md text eol=lf\n", attributes)
        self.assertIn("docs/PROGRESS.md text eol=lf\n", attributes)
        self.assertIn("*.sh text eol=lf\n", attributes)

    def test_in_flight_discovery_is_offline_and_uses_local_tracking_refs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            tree = fixture.git(
                "rev-parse", f"{fixture.main_oid}^{{tree}}"
            ).stdout.strip()
            unmerged = fixture.git(
                "commit-tree",
                tree,
                "-p",
                fixture.main_oid,
                "-m",
                "Unmerged remote phase",
            ).stdout.strip()
            fixture.git(
                "update-ref", "refs/remotes/origin/phase-remote", unmerged
            )
            fixture.git(
                "update-ref",
                "refs/remotes/origin/phase-merged",
                fixture.main_oid,
            )

            real_run = subprocess.run
            observed: list[object] = []

            def observe_run(*args: object, **kwargs: object):
                command = args[0] if args else kwargs.get("args")
                if isinstance(command, (list, tuple)):
                    observed.append(tuple(str(part) for part in command))
                else:
                    observed.append(command)
                return real_run(*args, **kwargs)

            with mock.patch.object(
                progress_status.subprocess,
                "run",
                side_effect=observe_run,
            ):
                branches = progress_status._in_flight_branches(
                    fixture.root, fixture.main_oid
                )

            self.assertTrue(observed)
            for command in observed:
                self.assertIsInstance(command, tuple)
                assert isinstance(command, tuple)
                self.assertGreaterEqual(len(command), 2)
                self.assertEqual(command[0], "git")
                self.assertIn(
                    command[1], {"for-each-ref", "merge-base", "branch"}
                )
            self.assertEqual(
                branches, ("phase-remote", "phase-status-test")
            )

    def test_docs_guard_has_no_network_fetch_fallback(self) -> None:
        guard = (ROOT / "scripts" / "check_docs_sync.sh").read_text(
            encoding="utf-8"
        )
        forbidden = (
            "git fetch",
            "git ls-remote",
            "git remote update",
            "git remote prune",
            "curl ",
            "wget ",
        )
        for command in forbidden:
            with self.subTest(command=command):
                self.assertNotIn(command, guard)
        self.assertNotIn('echo "$changed" | grep', guard)
        self.assertIn("grep -qE '^src/' <<< \"$changed\"", guard)
        self.assertIn(
            "grep -qxF 'docs/devlog/changelog.md' <<< \"$changed\"",
            guard,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            trace = root / "git-trace.jsonl"
            network_log = root / "network-calls.jsonl"
            for tool in ("curl", "wget", "gh"):
                wrapper = bin_dir / tool
                wrapper.write_text(
                    "#!/usr/bin/env python3\n"
                    "import json, os, sys\n"
                    f"tool = {tool!r}\n"
                    "with open(os.environ['CS_OFFLINE_LOG'], 'a', encoding='utf-8') as f:\n"
                    "    f.write(json.dumps({'tool': tool, 'args': sys.argv[1:]}) + '\\n')\n"
                    "raise SystemExit(97)\n",
                    encoding="utf-8",
                    newline="\n",
                )
                wrapper.chmod(0o755)

            environment = os.environ.copy()
            environment["PATH"] = str(bin_dir) + os.pathsep + environment["PATH"]
            environment["CS_OFFLINE_LOG"] = str(network_log)
            environment["GIT_ALLOW_PROTOCOL"] = "file"
            environment["GIT_TERMINAL_PROMPT"] = "0"
            environment["GIT_TRACE2_EVENT"] = str(trace)
            # This test verifies the guard's offline command surface, not the
            # caller's ambient symbolic-ref state.  The production authority
            # intentionally stages a detached exact-HEAD source snapshot.
            for name in ("GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_HEAD_REF"):
                environment.pop(name, None)
            environment["GITHUB_REF_NAME"] = "main"
            completed = subprocess.run(
                [bash_executable(), "scripts/check_docs_sync.sh"],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            calls = read_git_trace(trace)
            if network_log.is_file():
                calls.extend(
                    json.loads(line)
                    for line in network_log.read_text(encoding="utf-8").splitlines()
                )
            self.assertTrue(calls)
            self.assertTrue(all(call["tool"] == "git" for call in calls))
            for call in calls:
                args = call["args"]
                self.assertFalse(
                    any(
                        arg in {"fetch", "pull", "push", "clone", "ls-remote"}
                        for arg in args
                    )
                )
                self.assertFalse(
                    "remote" in args
                    and any(arg in {"update", "prune"} for arg in args)
                )

    def test_protected_main_completion_consumes_todo_and_appends_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                initial = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )
                progress_path = fixture.root / "docs" / "PROGRESS.md"
                todo_path = fixture.root / "docs" / "TODO.md"
                original_progress = progress_path.read_text(encoding="utf-8")

                self.assertIn("CS-P10-01", initial.todo)
                self.assertIn("CS-P10-02", initial.todo)
                completion_oid = fixture.advance_main(
                    directory,
                    "Complete first generated item\n\n"
                    "Closes-CodeSkeptic-Task: CS-P10-01",
                )
                completed = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                updated_progress = progress_path.read_text(encoding="utf-8")
                updated_todo = todo_path.read_text(encoding="utf-8")
                self.assertTrue(updated_progress.startswith(original_progress))
                self.assertIn(completion_oid, updated_progress)
                self.assertIn("Completed tasks: `CS-P10-01`", updated_progress)
                self.assertNotIn("### CS-P10-01 —", updated_todo)
                self.assertIn("### CS-P10-02 —", updated_todo)
                self.assertEqual(completed.completed_work, ("CS-P10-01",))

    def test_invalid_protected_main_completion_leaves_outputs_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                tracked = (
                    fixture.root / "docs" / "TODO.md",
                    fixture.root / "docs" / "PROGRESS.md",
                )
                before = tuple(path.read_bytes() for path in tracked)

                fixture.advance_main(
                    directory,
                    "Close dependency out of order\n\n"
                    "Closes-CodeSkeptic-Task: CS-P10-02",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )
                self.assertEqual(
                    tuple(path.read_bytes() for path in tracked), before
                )

    def test_generated_todo_rejects_manual_judgment_edits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                todo_path = fixture.root / "docs" / "TODO.md"
                todo_path.write_text(
                    todo_path.read_text(encoding="utf-8")
                    + "\nmanual priority override\n",
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.check_repository(
                        fixture.root, "origin/main"
                    )

    def test_unmerged_branch_trailer_never_consumes_todo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                fixture.git(
                    "commit",
                    "--allow-empty",
                    "-m",
                    "Phase-only claim\n\n"
                    "Closes-CodeSkeptic-Task: CS-P10-01",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )
                self.assertIn("CS-P10-01", status.todo)
                self.assertEqual(status.completed_work, ())

    def test_non_trailer_example_never_consumes_todo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                example_oid = fixture.advance_main(
                    directory,
                    "Document completion syntax\n\n"
                    "Example only:\n"
                    "Closes-CodeSkeptic-Task: CS-P10-01\n\n"
                    "This is prose, not a final trailer block.",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                self.assertIn("### CS-P10-01 —", status.todo)
                self.assertEqual(status.completed_work, ())
                self.assertNotIn("Completed tasks:", status.progress)
                self.assertNotIn(example_oid, status.progress)

    def test_task_trailer_parsing_ignores_host_git_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            fixture.git("config", "trailer.separators", "=")
            fixture.git(
                "config",
                "trailer.Closes-CodeSkeptic-Task.key",
                "Host-Alias",
            )
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                closure_oid = fixture.advance_main(
                    directory,
                    "Close despite hostile local config\n\n"
                    "Closes-CodeSkeptic-Task: CS-P10-01",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                self.assertIn(closure_oid, status.progress)
                self.assertNotIn("### CS-P10-01 —", status.todo)

    def test_git_trailer_alias_cannot_manufacture_exact_task_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            fixture.git(
                "config",
                "trailer.short.key",
                "Closes-CodeSkeptic-Task",
            )
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                alias_oid = fixture.advance_main(
                    directory,
                    "Alias is not the exact raw trailer\n\nshort: CS-P10-01",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                self.assertNotIn(alias_oid, status.progress)
                self.assertIn("### CS-P10-01 —", status.todo)
                self.assertEqual(status.completed_work, ())

    def test_unicode_separator_cannot_manufacture_a_raw_trailer_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                unicode_oid = fixture.advance_main(
                    directory,
                    "Unicode separator stays in one physical line\n\n"
                    "Note: same raw line\u2028"
                    "Closes-CodeSkeptic-Task: CS-P10-01",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                self.assertNotIn(unicode_oid, status.progress)
                self.assertIn("### CS-P10-01 —", status.todo)
                self.assertEqual(status.completed_work, ())

    def test_bare_cr_cannot_manufacture_a_raw_trailer_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                cr_oid = fixture.advance_main(
                    directory,
                    "Bare CR stays in one physical line\n\n"
                    "Note: same raw line\r"
                    "Closes-CodeSkeptic-Task: CS-P10-01",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                self.assertNotIn(cr_oid, status.progress)
                self.assertIn("### CS-P10-01 —", status.todo)
                self.assertEqual(status.completed_work, ())

    def test_final_bare_cr_without_lf_is_not_a_trailer_terminator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            parent = fixture.git(
                "rev-parse", "refs/remotes/origin/main"
            ).stdout.strip()
            tree = fixture.git("rev-parse", f"{parent}^{{tree}}").stdout.strip()
            raw = (
                f"tree {tree}\n"
                f"parent {parent}\n"
                "author Status Test <status@example.invalid> 1700000000 +0000\n"
                "committer Status Test <status@example.invalid> 1700000000 +0000\n"
                "\n"
                "Final bare CR is not CRLF\n\n"
                "Closes-CodeSkeptic-Task: CS-P10-01\r"
            ).encode("utf-8")
            hashed = subprocess.run(
                ["git", "hash-object", "-t", "commit", "-w", "--stdin"],
                cwd=fixture.root,
                input=raw,
                capture_output=True,
                check=False,
            )
            self.assertEqual(hashed.returncode, 0, hashed.stderr)
            oid = hashed.stdout.decode("ascii").strip()
            fixture.git("update-ref", "refs/remotes/origin/main", oid)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                tracked = (
                    fixture.root / "docs" / "TODO.md",
                    fixture.root / "docs" / "PROGRESS.md",
                )
                before = tuple(path.read_bytes() for path in tracked)
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )
                self.assertEqual(
                    tuple(path.read_bytes() for path in tracked), before
                )

    def test_deleted_progress_cannot_be_bootstrapped_by_normal_sync(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                progress_path = fixture.root / "docs" / "PROGRESS.md"
                progress_path.unlink()

                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )
                self.assertFalse(progress_path.exists())

    def test_ci_work_ref_rejects_non_phase_branches(self) -> None:
        progress_status.validate_ci_ref("phase-status-test")
        progress_status.validate_ci_ref("main")
        with self.assertRaises(progress_status.ProgressStatusError):
            progress_status.validate_ci_ref("feature-docs-bypass")
        with self.assertRaises(progress_status.ProgressStatusError):
            progress_status.validate_ci_ref("main", pull_request=True)
        progress_status.validate_ci_ref(
            "phase-status-test", pull_request=True
        )

    def test_migration_catalog_preserves_unmerged_phase_8_and_9_work(self) -> None:
        catalog = progress_status._load_catalog(ROOT)
        by_id = {item.id: item for item in catalog.items}

        self.assertEqual(catalog.schema, progress_status.POLICY_PLAN_SCHEMA)
        self.assertIn("CS-P08-03", by_id)
        self.assertIn("CS-P08-04", by_id)
        self.assertIn("CS-P09-01", by_id)
        self.assertIn("CS-P09-01", by_id["CS-P12-08"].depends_on)

    def test_approved_policy_revision_requires_exact_bytes_and_authority(self) -> None:
        missing_plan = subprocess.CompletedProcess(
            args=["git", "show"],
            returncode=128,
            stdout=b"",
            stderr=b"protected main has no work catalog",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            plan_path = root / "docs" / "PLAN.md"
            plan_path.write_bytes((ROOT / "docs" / "PLAN.md").read_bytes())
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=missing_plan
            ), mock.patch.object(
                progress_status,
                "_resolve_commit",
                return_value=progress_status.MIGRATION_MAIN_OID,
            ), mock.patch.object(
                progress_status, "_is_ancestor", return_value=True
            ):
                progress_status._enforce_fixed_plan(root, "origin/main")

                plan_path.write_text(
                    plan_path.read_text(encoding="utf-8").replace(
                        "three independent external projects",
                        "two independent external projects",
                        1,
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._enforce_fixed_plan(root, "origin/main")

                plan_path.write_bytes((ROOT / "docs" / "PLAN.md").read_bytes())
                with mock.patch.object(
                    progress_status, "_is_ancestor", return_value=False
                ):
                    with self.assertRaises(progress_status.ProgressStatusError):
                        progress_status._enforce_fixed_plan(root, "origin/main")

    def test_pinned_legacy_catalog_remains_valid_during_policy_transition(self) -> None:
        legacy = subprocess.run(
            [
                "git",
                "show",
                f"{progress_status.PREVIOUS_POLICY_PLAN_AUTHORITY_OID}^:docs/PLAN.md",
            ],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
        self.assertEqual(
            progress_status.sha256(legacy).hexdigest(),
            progress_status.MIGRATION_PLAN_SHA256,
        )
        missing_plan = subprocess.CompletedProcess(
            args=["git", "show"],
            returncode=128,
            stdout=b"",
            stderr=b"protected main has no work catalog",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "PLAN.md").write_bytes(legacy)
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=missing_plan
            ), mock.patch.object(
                progress_status,
                "_resolve_commit",
                return_value=progress_status.MIGRATION_MAIN_OID,
            ):
                progress_status._enforce_fixed_plan(root, "origin/main")

    def test_policy_revision_accepts_exact_protected_schema_one_predecessor(self) -> None:
        legacy = subprocess.run(
            [
                "git",
                "show",
                f"{progress_status.PREVIOUS_POLICY_PLAN_AUTHORITY_OID}^:docs/PLAN.md",
            ],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
        protected = subprocess.CompletedProcess(
            args=["git", "show"],
            returncode=0,
            stdout=legacy,
            stderr=b"",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "PLAN.md").write_bytes(
                (ROOT / "docs" / "PLAN.md").read_bytes()
            )
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=protected
            ), mock.patch.object(
                progress_status, "_is_ancestor", return_value=True
            ):
                progress_status._enforce_fixed_plan(root, "origin/main")

            forged = legacy.replace(
                b"# CodeSkeptic \xe2\x80\x94 PLAN (sabit referans, t\xc3\xbcm plan)",
                b"# Forged protected PLAN narrative",
                1,
            )
            self.assertNotEqual(forged, legacy)
            with mock.patch.object(
                progress_status.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    args=["git", "show"],
                    returncode=0,
                    stdout=forged,
                    stderr=b"",
                ),
            ), mock.patch.object(
                progress_status, "_is_ancestor", return_value=True
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._enforce_fixed_plan(root, "origin/main")

    def test_scope_policy_pins_and_accepts_exact_schema_two_predecessor(self) -> None:
        previous = subprocess.run(
            [
                "git",
                "show",
                f"{progress_status.PREVIOUS_POLICY_PLAN_AUTHORITY_OID}:docs/PLAN.md",
            ],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
        previous_text = previous.decode("utf-8")
        self.assertEqual(
            progress_status.sha256(previous).hexdigest(),
            progress_status.PREVIOUS_POLICY_PLAN_SHA256,
        )
        self.assertEqual(
            progress_status.sha256(
                progress_status._catalog_payload(previous_text).encode("utf-8")
            ).hexdigest(),
            progress_status.PREVIOUS_POLICY_CATALOG_SHA256,
        )
        protected = subprocess.CompletedProcess(
            args=["git", "show"], returncode=0, stdout=previous, stderr=b""
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "PLAN.md").write_bytes(
                (ROOT / "docs" / "PLAN.md").read_bytes()
            )
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=protected
            ), mock.patch.object(
                progress_status, "_is_ancestor", return_value=True
            ):
                progress_status._enforce_fixed_plan(root, "origin/main")

    def test_first_catalog_migration_is_pinned_byte_for_byte(self) -> None:
        missing_plan = subprocess.CompletedProcess(
            args=["git", "show"],
            returncode=128,
            stdout=b"",
            stderr=b"missing legacy catalog",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            plan_path = root / "docs" / "PLAN.md"
            plan_path.write_bytes((ROOT / "docs" / "PLAN.md").read_bytes())
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=missing_plan
            ), mock.patch.object(
                progress_status,
                "_resolve_commit",
                return_value=progress_status.MIGRATION_MAIN_OID,
            ), mock.patch.object(
                progress_status, "_is_ancestor", return_value=True
            ):
                progress_status._enforce_fixed_plan(root, "origin/main")

                plan_path.write_text(
                    plan_path.read_text(encoding="utf-8").replace(
                        "Targeted-scope input validation",
                        "Silently changed migration task",
                        1,
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._enforce_fixed_plan(root, "origin/main")

                plan_path.write_bytes((ROOT / "docs" / "PLAN.md").read_bytes())
                plan_path.write_text(
                    plan_path.read_text(encoding="utf-8").replace(
                        "# CodeSkeptic — PLAN (sürüm kontrollü referans, tüm plan)",
                        "# Deleted policy plan narrative",
                        1,
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._enforce_fixed_plan(root, "origin/main")

    def test_production_ledger_cannot_be_self_consistently_reanchored(self) -> None:
        catalog = progress_status._load_catalog(ROOT)
        main_oid = progress_status.MIGRATION_MAIN_OID
        forged = (
            progress_status._progress_header(main_oid)
            + progress_status._render_receipt(
                progress_status._commit_receipt(ROOT, main_oid)
            )
            + f"\n<!-- cs:task-ledger-v2: {main_oid} -->\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "PROGRESS.md").write_text(
                forged, encoding="utf-8", newline="\n"
            )
            with mock.patch.object(
                progress_status, "_resolve_commit", return_value=main_oid
            ), mock.patch.object(
                progress_status, "_load_catalog", return_value=catalog
            ), mock.patch.object(
                progress_status, "_enforce_fixed_plan"
            ), mock.patch.object(
                progress_status, "_enforce_protected_progress_prefix"
            ), mock.patch.object(
                progress_status,
                "_render_progress",
                return_value=(forged, ()),
            ), mock.patch.object(
                progress_status, "_in_flight_branches", return_value=()
            ), mock.patch.object(
                progress_status, "_render_state_block", return_value="state"
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.derive_status(root, "origin/main")

    def test_progress_cannot_truncate_protected_main_v2_receipts(self) -> None:
        protected = (
            "legacy bytes\n"
            "<!-- cs:task-ledger-v2: "
            + progress_status.MIGRATION_MAIN_OID
            + " -->\n"
            "protected closure receipt\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "PROGRESS.md").write_text(
                protected.removesuffix("protected closure receipt\n"),
                encoding="utf-8",
                newline="\n",
            )
            shown = subprocess.CompletedProcess(
                args=["git", "show"],
                returncode=0,
                stdout=protected.encode("utf-8"),
                stderr=b"",
            )
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=shown
            ), mock.patch.object(
                progress_status,
                "_resolve_commit",
                return_value=progress_status.MIGRATION_MAIN_OID,
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._enforce_protected_progress_prefix(
                        root,
                        "origin/main",
                        (root / "docs" / "PROGRESS.md").read_bytes(),
                    )

    def test_protected_progress_newline_rewrite_is_not_byte_exact(self) -> None:
        protected = b"line1\r\nline2\r\n"
        local = b"line1\nline2\n"
        shown = subprocess.CompletedProcess(
            args=["git", "show"],
            returncode=0,
            stdout=protected,
            stderr=b"",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=shown
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._enforce_protected_progress_prefix(
                        root, "origin/main", local
                    )

    def test_fixed_plan_newline_rewrite_is_not_byte_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            local = (ROOT / "docs" / "PLAN.md").read_bytes()
            (root / "docs" / "PLAN.md").write_bytes(local)
            protected = local.replace(b"\n", b"\r\n")
            shown = subprocess.CompletedProcess(
                args=["git", "show"],
                returncode=0,
                stdout=protected,
                stderr=b"",
            )
            with mock.patch.object(
                progress_status.subprocess, "run", return_value=shown
            ), mock.patch.object(
                progress_status,
                "_resolve_commit",
                return_value=progress_status.MIGRATION_MAIN_OID,
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._enforce_fixed_plan(root, "origin/main")

    def test_explicit_bootstrap_cannot_reset_a_mature_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            fixture.advance_main(directory)
            (fixture.root / "docs" / "PROGRESS.md").unlink()
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.bootstrap_repository(
                        fixture.root, "origin/main"
                    )

    def test_bootstrap_cannot_reset_mature_repo_via_old_root_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            fixture.advance_main(directory)
            (fixture.root / "docs" / "PROGRESS.md").unlink()
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.bootstrap_repository(
                        fixture.root, fixture.legacy_oid
                    )

    def test_reconciliation_commit_is_not_an_unfinishable_ledger_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                closure_oid = fixture.advance_main(
                    directory,
                    "Close all product work\n\n"
                    "Closes-CodeSkeptic-Task: CS-P10-01\n"
                    "Closes-CodeSkeptic-Task: CS-P10-02",
                )
                reconciliation_oid = fixture.advance_main(
                    directory,
                    "Reconcile generated task status",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                self.assertIn(closure_oid, status.progress)
                self.assertNotIn(reconciliation_oid, status.progress)
                self.assertIn("No open work items.", status.todo)
                checked = progress_status.check_repository(
                    fixture.root, "origin/main"
                )
                self.assertEqual(checked.progress, status.progress)

    def test_interrupted_pair_write_fails_closed_and_rerun_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                closure_oid = fixture.advance_main(
                    directory,
                    "Close first generated item\n\n"
                    "Closes-CodeSkeptic-Task: CS-P10-01",
                )
                real_replace = progress_status.os.replace
                replacements = 0

                def fail_second_replace(source: Path, target: Path) -> None:
                    nonlocal replacements
                    replacements += 1
                    if replacements == 2:
                        raise OSError("injected TODO replace interruption")
                    real_replace(source, target)

                with mock.patch.object(
                    progress_status.os,
                    "replace",
                    side_effect=fail_second_replace,
                ):
                    with self.assertRaises(OSError):
                        progress_status.sync_repository(
                            fixture.root, "origin/main"
                        )

                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.check_repository(
                        fixture.root, "origin/main"
                    )
                recovered = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )
                self.assertIn(closure_oid, recovered.progress)
                self.assertNotIn("### CS-P10-01 —", recovered.todo)
                progress_status.check_repository(fixture.root, "origin/main")

    def test_unknown_protected_main_task_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                fixture.advance_main(
                    directory,
                    "Unknown task\n\nCloses-CodeSkeptic-Task: CS-P10-99",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )

    def test_task_cannot_close_in_two_protected_main_commits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                fixture.advance_main(
                    directory,
                    "Close once\n\nCloses-CodeSkeptic-Task: CS-P10-01",
                )
                progress_status.sync_repository(fixture.root, "origin/main")
                fixture.advance_main(
                    directory,
                    "Close twice\n\nCloses-CodeSkeptic-Task: CS-P10-01",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )

    def test_side_branch_trailer_is_not_first_parent_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            parent = fixture.git(
                "rev-parse", "refs/remotes/origin/main"
            ).stdout.strip()
            tree = fixture.git("rev-parse", f"{parent}^{{tree}}").stdout.strip()
            side = fixture.git(
                "commit-tree",
                tree,
                "-p",
                parent,
                "-m",
                "Side branch claim\n\n"
                "Closes-CodeSkeptic-Task: CS-P10-01",
            ).stdout.strip()
            mainline = fixture.git(
                "commit-tree",
                tree,
                "-p",
                parent,
                "-m",
                "Protected first-parent transition",
            ).stdout.strip()
            merged = fixture.git(
                "commit-tree",
                tree,
                "-p",
                mainline,
                "-p",
                side,
                "-m",
                "Merge side history without closure trailer",
            ).stdout.strip()
            fixture.git("update-ref", "refs/remotes/origin/main", merged)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )

                self.assertIn("### CS-P10-01 —", status.todo)
                self.assertEqual(status.completed_work, ())
                self.assertNotIn(side, status.progress)

    def test_task_anchor_must_be_on_protected_first_parent_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            anchor = fixture.git(
                "rev-parse", "refs/remotes/origin/main"
            ).stdout.strip()
            tree = fixture.git("rev-parse", f"{anchor}^{{tree}}").stdout.strip()
            unrelated = fixture.git(
                "commit-tree", tree, "-m", "Unrelated first-parent root"
            ).stdout.strip()
            reversed_merge = fixture.git(
                "commit-tree",
                tree,
                "-p",
                unrelated,
                "-p",
                anchor,
                "-m",
                "Reverse parent closure\n\n"
                "Closes-CodeSkeptic-Task: CS-P10-01",
            ).stdout.strip()
            fixture.git(
                "update-ref", "refs/remotes/origin/main", reversed_merge
            )
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                tracked = (
                    fixture.root / "docs" / "TODO.md",
                    fixture.root / "docs" / "PROGRESS.md",
                )
                before = tuple(path.read_bytes() for path in tracked)
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )
                self.assertEqual(
                    tuple(path.read_bytes() for path in tracked), before
                )

    def test_fixed_plan_change_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                plan_path = fixture.root / "docs" / "PLAN.md"
                plan_path.write_text(
                    plan_path.read_text(encoding="utf-8").replace(
                        "First generated work item",
                        "Silently rewritten work item",
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )

    def test_sync_rejects_direct_main_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RepositoryFixture(Path(temporary))
            fixture.git("checkout", "main")
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=(),
            ):
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status.sync_repository(
                        fixture.root, "origin/main"
                    )

    def test_malformed_and_duplicate_task_trailers_fail_closed(self) -> None:
        cases = (
            "Malformed\n\nCloses-CodeSkeptic-Task: phase-status-first",
            "Duplicate\n\nCloses-CodeSkeptic-Task: CS-P10-01\n"
            "Closes-CodeSkeptic-Task: CS-P10-01",
        )
        for message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                fixture = RepositoryFixture(directory)
                with mock.patch.object(
                    progress_status,
                    "_in_flight_branches",
                    return_value=("phase-status-test",),
                ):
                    progress_status.sync_repository(fixture.root, "origin/main")
                    fixture.advance_main(directory, message)
                    with self.assertRaises(progress_status.ProgressStatusError):
                        progress_status.sync_repository(
                            fixture.root, "origin/main"
                        )

    def test_multiple_task_closures_use_catalog_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = RepositoryFixture(directory)
            with mock.patch.object(
                progress_status,
                "_in_flight_branches",
                return_value=("phase-status-test",),
            ):
                progress_status.sync_repository(fixture.root, "origin/main")
                fixture.advance_main(
                    directory,
                    "Close both\n\n"
                    "Closes-CodeSkeptic-Task: CS-P10-02\n"
                    "Closes-CodeSkeptic-Task: CS-P10-01",
                )
                status = progress_status.sync_repository(
                    fixture.root, "origin/main"
                )
                self.assertEqual(
                    status.completed_work, ("CS-P10-01", "CS-P10-02")
                )
                self.assertIn(
                    "Completed tasks: `CS-P10-01`, `CS-P10-02`.",
                    status.progress,
                )
                self.assertIn("No open work items.", status.todo)

    def test_catalog_rejects_duplicate_and_forward_dependencies(self) -> None:
        replacements = (
            ('"id": "CS-P10-02"', '"id": "CS-P10-01"'),
            ('"depends_on": []', '"depends_on": ["CS-P10-02"]'),
        )
        for old, new in replacements:
            with self.subTest(replacement=new), tempfile.TemporaryDirectory() as temporary:
                fixture = RepositoryFixture(Path(temporary))
                plan_path = fixture.root / "docs" / "PLAN.md"
                plan_path.write_text(
                    plan_path.read_text(encoding="utf-8").replace(old, new, 1),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaises(progress_status.ProgressStatusError):
                    progress_status._load_catalog(fixture.root)

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

                self.assertEqual(first.appended, 0)
                self.assertIn(fixture.legacy_oid, original)
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
                self.assertEqual(advanced.appended, 0)
                self.assertTrue(updated.startswith(original))
                self.assertNotIn(next_oid, updated)
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
    def test_remap_db_wires_relative_rename_into_every_input_form(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head = root / "head"
            base = root / "base"
            for subtree in ("src", "other"):
                (head / subtree).mkdir(parents=True)
                (base / subtree).mkdir(parents=True)
            database = root / "compile_commands.json"
            database.write_text(json.dumps([
                {
                    "directory": str(head / "src"),
                    "file": "core.c",
                    "command": "clang -c core.c",
                    "arguments": ["clang", "-c", "core.c"],
                },
                {
                    "directory": str(head / "other"),
                    "file": "core.c",
                    "command": "clang -c core.c",
                    "arguments": ["clang", "-c", "core.c"],
                },
            ]), encoding="utf-8")
            renames = root / "renames.tsv"
            renames.write_text(
                "src/lib.c\tsrc/core.c\n"
                "other/old.c\tother/core.c\n",
                encoding="utf-8")
            output = root / "remapped" / "compile_commands.json"
            args = mock.Mock(
                src=str(database), from_root=str(head), to_root=str(base),
                protect=None, renames=str(renames), out=str(output))
            self.assertEqual(review_report.cmd_remap_db(args), 0)
            remapped = json.loads(output.read_text(encoding="utf-8"))
            canonical_base = Path(os.path.realpath(base))
            self.assertEqual(
                remapped[0]["directory"], str(canonical_base / "src"))
            self.assertEqual(remapped[0]["file"], "lib.c")
            self.assertEqual(remapped[0]["command"], "clang -c lib.c")
            self.assertEqual(remapped[0]["arguments"][-1], "lib.c")
            self.assertEqual(
                remapped[1]["directory"], str(canonical_base / "other"))
            self.assertEqual(remapped[1]["file"], "old.c")
            self.assertEqual(remapped[1]["command"], "clang -c old.c")
            self.assertEqual(remapped[1]["arguments"][-1], "old.c")

    def test_relative_compile_database_rename_uses_directory_context(self) -> None:
        renames = (
            ("src/lib.c", "src/core.c"),
            ("other/old.c", "other/core.c"),
        )
        source_directory = "/tmp/base/src"
        other_directory = "/tmp/base/other"
        self.assertEqual(
            review_report._rewrite_relative_renames(
                "core.c", source_directory, "/tmp/base", renames,
                command=False),
            "lib.c",
        )
        self.assertEqual(
            review_report._rewrite_relative_renames(
                "clang -c core.c", source_directory, "/tmp/base", renames),
            "clang -c lib.c",
        )
        self.assertEqual(
            review_report._rewrite_relative_renames(
                "core.c", other_directory, "/tmp/base", renames,
                command=False),
            "old.c",
        )
        self.assertEqual(
            review_report._rewrite_relative_renames(
                "../other/core.c", source_directory, "/tmp/base", renames,
                command=False),
            "../other/old.c",
        )

    def test_posix_paths_and_renames_are_case_sensitive(self) -> None:
        rewritten = review_report._rewrite_compile_paths(
            "clang -I/tmp/repo/external -c /tmp/Repo/core.c",
            ("/tmp/Repo",), "/tmp/base")
        self.assertIn("-I/tmp/repo/external", rewritten)
        self.assertIn("-c /tmp/base/core.c", rewritten)

        renamed = review_report._rewrite_compile_renames(
            "clang -I/tmp/base/Core.c -c /tmp/base/core.c",
            "/tmp/base", (("lib.c", "core.c"),))
        self.assertIn("-I/tmp/base/Core.c", renamed)
        self.assertIn("-c /tmp/base/lib.c", renamed)

    def test_posix_backslash_escape_is_not_a_path_separator(self) -> None:
        rewritten = review_report._rewrite_compile_paths(
            r"clang -I/tmp\Repo/external -c /tmp/Repo/core.c",
            ("/tmp/Repo",), "/tmp/base")
        self.assertIn(r"-I/tmp\Repo/external", rewritten)
        self.assertIn("-c /tmp/base/core.c", rewritten)

        literal = review_report._rewrite_compile_paths(
            r"/tmp/Repo\external", ("/tmp/Repo",), "/tmp/base",
            command=False)
        self.assertEqual(literal, r"/tmp/Repo\external")

        quoted = review_report._rewrite_compile_paths(
            r'''clang -I"/tmp/Repo\external" -c /tmp/Repo/core.c''',
            ("/tmp/Repo",), "/tmp/base")
        self.assertIn(r'''-I"/tmp/Repo\external"''', quoted)
        self.assertIn("-c /tmp/base/core.c", quoted)

    def test_windows_paths_remain_case_insensitive(self) -> None:
        rewritten = review_report._rewrite_compile_path(
            r"cl -Ic:\PROJECTS\codeskeptic\src C:\Projects\CodeSkeptic\x.cpp",
            r"C:\Projects\CodeSkeptic", r"C:\tmp\base")
        self.assertIn(r"-IC:\tmp\base\src", rewritten)
        self.assertIn(r"C:\tmp\base\x.cpp", rewritten)
        renamed = review_report._rewrite_relative_renames(
            r"CORE.C", r"C:\tmp\base\src", r"C:\tmp\base",
            (("src/lib.c", "src/core.c"),), command=False)
        self.assertEqual(renamed, r"lib.c")

    def test_renamed_head_compile_path_maps_to_base_path(self) -> None:
        command = (
            "clang -I/cache/-I/tmp/base/core.c "
            "-I/cache/=/tmp/base/core.c -I/cache/,/tmp/base/core.c "
            "-I\"/cache/ /tmp/base/core.c\" "
            "-c /tmp/base/core.c "
            "-I\"/tmp/base/core.c\" "
            "-o /tmp/base/core.o"
        )
        rewritten = review_report._rewrite_compile_renames(
            command, "/tmp/base", (("lib.c", "core.c"),))
        self.assertIn("-c /tmp/base/lib.c", rewritten)
        self.assertIn("-I/cache/-I/tmp/base/core.c", rewritten)
        self.assertIn("-I/cache/=/tmp/base/core.c", rewritten)
        self.assertIn("-I/cache/,/tmp/base/core.c", rewritten)
        self.assertIn('-I"/cache/ /tmp/base/core.c"', rewritten)
        self.assertIn("-I/tmp/base/lib.c", rewritten)
        # Only the renamed source token changes; similarly named outputs are
        # not inferred to be Git renames.
        self.assertIn("-o /tmp/base/core.o", rewritten)

    def test_equivalent_posix_root_spellings_remap_without_protecting_root(self) -> None:
        command = (
            "-I/cache/-I/var/work/repo/include /var/work/repo/lib.c "
            "-I/private/var/work/repo/src "
            "-isystem/var/work/repo/include "
            "--sysroot=/var/work/repo/sdk "
            "-I/cache/-isystem/var/work/repo/external "
            "-I/cache/=/var/work/repo/external "
            "-I/cache/,/var/work/repo/external "
            "-I\"/cache/ /var/work/repo/external\" "
            "-I\"/var/work/repo/quoted include\" "
            "-I/var/work/repo/build/generated"
        )
        rewritten = review_report._rewrite_compile_paths(
            command,
            ("/var/work/repo", "/private/var/work/repo"),
            "/tmp/base",
            # A build-path equal to the repository root is not a build-only
            # subtree and must not mask every source path from remapping.
            ("/var/work/repo", "/private/var/work/repo"),
        )
        self.assertIn("/tmp/base/lib.c", rewritten)
        self.assertIn("-I/cache/-I/var/work/repo/include", rewritten)
        self.assertIn("-I/tmp/base/src", rewritten)
        self.assertIn("-isystem/tmp/base/include", rewritten)
        self.assertIn("--sysroot=/tmp/base/sdk", rewritten)
        self.assertIn("-I/cache/-isystem/var/work/repo/external", rewritten)
        self.assertIn("-I/cache/=/var/work/repo/external", rewritten)
        self.assertIn("-I/cache/,/var/work/repo/external", rewritten)
        self.assertIn('-I"/cache/ /var/work/repo/external"', rewritten)
        self.assertIn("-I/tmp/base/quoted include", rewritten)
        self.assertIn("-I/var/work/repo/build/generated", rewritten)

    def test_escaped_command_and_arguments_remap_to_same_base_path(self) -> None:
        source = "/tmp/My Repo"
        target = "/tmp/base"
        command = review_report._rewrite_compile_paths(
            r"clang -I/tmp/My\ Repo/include -c /tmp/My\ Repo/core.c",
            (source,), target,
        )
        arguments = [
            review_report._rewrite_compile_paths(
                value, (source,), target, command=False)
            for value in ("clang", "-I/tmp/My Repo/include", "-c",
                          "/tmp/My Repo/core.c")
        ]
        self.assertIn("-I/tmp/base/include", command)
        self.assertIn("/tmp/base/core.c", command)
        self.assertEqual(arguments[-1], "/tmp/base/core.c")
        self.assertEqual(arguments[1], "-I/tmp/base/include")

    def test_double_quote_preserves_backslash_before_space(self) -> None:
        command = (
            r'''clang -I"/tmp/My\ Repo/external" '''
            r'''-I/tmp/My\ Repo/real'''
        )
        rewritten = review_report._rewrite_compile_paths(
            command, ("/tmp/My Repo",), "/tmp/base")
        self.assertIn(r'''-I"/tmp/My\ Repo/external"''', rewritten)
        self.assertIn("-I/tmp/base/real", rewritten)

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
