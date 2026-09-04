"""Bounded FIFO regression tests; all Git writes stay in temporary repositories."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(os.environ.get("PROJECT_QUEUE_SCRIPT", Path(__file__).resolve().parents[1] / "scripts" / "project_queue.py"))
SPEC = importlib.util.spec_from_file_location("project_queue_under_test", SCRIPT)
queue = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(queue)
HEAD = "a" * 40
STAMP = "2026-09-05T00:00:00+00:00"


def make_task(chapter, unit, depends=()):
    identity = f"CS3-{chapter}-S01-U{unit:03d}"
    return {
        "id": identity, "title": f"Deliver {identity}",
        "outcome": f"Observable outcome for {identity}",
        "acceptance": ["The narrow positive and negative regressions pass."],
        "scope": ["src/*", "tests/*"], "checks": ["focused"],
        "budget": "T1", "depends": list(depends),
    }


def make_book():
    chapters = []
    previous = []
    for chapter, count in (("CH00", 2), ("CH01", 2), ("CH02", 1)):
        entries = []
        for unit in range(1, count + 1):
            task = make_task(chapter, unit, previous[-1:])
            entries.append(task)
            previous.append(task["id"])
        chapters.append({"id": chapter, "title": f"Chapter {chapter}", "sections": [
            {"id": "S01", "title": "Atomic delivery", "tasks": entries},
        ]})
    return {"schema": "codeskeptic-book/v1", "epoch": "CWE-RESTART-20260905",
            "revision": 1, "chapters": chapters, "progress": [], "decisions": []}


def branch_for(task):
    return "agent/" + task["id"].lower() + "-regression"


def review_for(task, head=HEAD, branch=None, evidence="/tmp/fifo-evidence.log", data=b"focused PASS\n"):
    return {
        "schema": "codeskeptic-review/v1", "task_id": task["id"], "head": head,
        "branch": branch or branch_for(task), "contract_sha256": queue.digest(task),
        "implementer": "implementation-run", "verifier": "independent-review-run",
        "verdict": "PASS", "findings": [], "checks": [{
            "name": "focused", "command": "python3 -B -m unittest focused",
            "result": "PASS", "sha256": hashlib.sha256(data).hexdigest(),
            "evidence": str(evidence),
        }],
    }


def advance(book):
    task = queue.pending(book)[0]
    review = review_for(task)
    return queue.complete(book, review, HEAD, review["branch"], STAMP)


class QueueContractTests(unittest.TestCase):
    def test_01_pop_front_push_progress_and_keep_input_unchanged(self):
        old = make_book()
        before = copy.deepcopy(old)
        first = queue.pending(old)[0]
        once = advance(old)
        twice = advance(once)
        self.assertEqual(old, before)
        self.assertEqual(once["progress"][0]["task"], first)
        self.assertEqual([r["task"]["id"] for r in twice["progress"]],
                         [queue.tasks(old)[1]["id"], first["id"]])
        self.assertEqual([r["task"] for r in reversed(twice["progress"])] + queue.pending(twice), queue.tasks(old))

    def test_02_nonfront_completion_is_rejected(self):
        book = make_book()
        review = review_for(queue.pending(book)[1])
        with self.assertRaises(queue.QueueError):
            queue.complete(book, review, HEAD, review["branch"], STAMP)

    def test_03_chapter_activates_only_after_previous_chapter_is_empty(self):
        book = make_book()
        current = queue.render(book)["docs/TODO.md"]
        self.assertIn("### CS3-CH00-S01-U002", current)
        self.assertNotIn("### CS3-CH01-S01-U001", current)
        book = advance(advance(book))
        current = queue.render(book)["docs/TODO.md"]
        self.assertIn("## FRONT — CS3-CH01-S01-U001", current)
        self.assertIn("### CS3-CH01-S01-U002", current)
        self.assertNotIn("### CS3-CH00", current)
        self.assertNotIn("### CS3-CH02", current)

    def test_04_terminal_queue_is_empty_and_cannot_pop_twice(self):
        book = make_book()
        last_review = None
        while queue.pending(book):
            last_review = review_for(queue.pending(book)[0])
            book = advance(book)
        self.assertEqual(queue.pending(book), [])
        self.assertEqual(len(book["progress"]), 5)
        self.assertIn("_Queue complete._", queue.render(book)["docs/TODO.md"])
        with self.assertRaises(queue.QueueError):
            queue.complete(book, last_review, HEAD, last_review["branch"], STAMP)

    def test_05_duplicate_lost_and_unknown_completed_ids_are_rejected(self):
        duplicate = make_book()
        duplicate["chapters"][0]["sections"][0]["tasks"].append(copy.deepcopy(queue.tasks(duplicate)[0]))
        lost = advance(make_book())
        lost["chapters"][0]["sections"][0]["tasks"].pop(0)
        unknown = advance(make_book())
        unknown["progress"][0]["task"]["id"] = "CS3-CH99-S01-U999"
        for book in (duplicate, lost, unknown):
            with self.subTest(book=book), self.assertRaises(queue.QueueError):
                queue.validate_book(book)

    def test_06_progress_must_be_exact_reversed_prefix(self):
        book = advance(advance(make_book()))
        book["progress"].reverse()
        with self.assertRaises(queue.QueueError):
            queue.validate_book(book)

    def test_07_dependencies_cannot_point_to_future_or_unknown_work(self):
        for dependency in ("CS3-CH02-S01-U001", "CS3-CH99-S01-U001"):
            book = make_book()
            queue.tasks(book)[0]["depends"] = [dependency]
            with self.subTest(dependency=dependency), self.assertRaises(queue.QueueError):
                queue.validate_book(book)

    def test_08_review_is_bound_to_exact_head_contract_task_and_branch(self):
        book = make_book()
        front = queue.pending(book)[0]
        for field, value in (("head", "b" * 40), ("head", "not-a-sha"),
                             ("contract_sha256", "c" * 64), ("task_id", queue.tasks(book)[1]["id"]),
                             ("branch", "main")):
            review = review_for(front)
            review[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(queue.QueueError):
                queue.complete(book, review, HEAD, branch_for(front), STAMP)

    def test_09_self_approval_findings_and_nonpass_are_rejected(self):
        book = make_book()
        front = queue.pending(book)[0]
        for field, value in (("verifier", "implementation-run"), ("verifier", ""),
                             ("findings", ["material finding"]), ("verdict", "FAIL")):
            review = review_for(front)
            review[field] = value
            with self.subTest(field=field), self.assertRaises(queue.QueueError):
                queue.complete(book, review, HEAD, branch_for(front), STAMP)

    def test_10_required_checks_need_unique_passing_nonzero_evidence(self):
        book = make_book()
        front = queue.pending(book)[0]
        good = review_for(front)["checks"][0]
        variants = [[], [dict(good, name="unrelated")], [good, good],
                    [dict(good, result="FAIL")], [dict(good, sha256="0" * 64)],
                    [dict(good, sha256="bad")]]
        for checks in variants:
            review = review_for(front)
            review["checks"] = checks
            with self.subTest(checks=checks), self.assertRaises(queue.QueueError):
                queue.complete(book, review, HEAD, branch_for(front), STAMP)

    def test_11_future_contract_can_change_with_decision_and_prefix_preserved(self):
        book = advance(make_book())
        chapters = copy.deepcopy(book["chapters"])
        chapters[1]["sections"][0]["tasks"][0]["outcome"] = "A clarified future outcome"
        amended = queue.amend(book, chapters, "Clarify future acceptance before activation")
        self.assertEqual(amended["revision"], 2)
        self.assertEqual(amended["progress"], book["progress"])
        self.assertEqual(queue.pending(amended)[0], queue.pending(book)[0])
        self.assertEqual(amended["decisions"][-1]["previous_plan_sha256"], queue.digest(book["chapters"]))
        self.assertEqual(book["revision"], 1)

    def test_12_append_back_preserves_existing_order_and_current_front(self):
        book = make_book()
        chapters = copy.deepcopy(book["chapters"])
        chapters[-1]["sections"][0]["tasks"].append(make_task("CH02", 2, ["CS3-CH02-S01-U001"]))
        amended = queue.amend(book, chapters, "Add bounded final follow-up")
        self.assertEqual(queue.pending(amended)[:-1], queue.pending(book))
        self.assertEqual(queue.pending(amended)[-1]["id"], "CS3-CH02-S01-U002")

    def test_13_amendment_cannot_change_front_or_completed_contract(self):
        for index in (0, 1):
            book = advance(make_book())
            chapters = copy.deepcopy(book["chapters"])
            chapters[0]["sections"][0]["tasks"][index]["acceptance"] = ["Weaker acceptance"]
            with self.subTest(index=index), self.assertRaises(queue.QueueError):
                queue.amend(book, chapters, "Attempt to rewrite active history")

    def test_14_amendment_cannot_drop_reorder_or_prepend_existing_ids(self):
        for operation in ("drop", "reorder", "insert"):
            book = make_book()
            chapters = copy.deepcopy(book["chapters"])
            entries = chapters[1]["sections"][0]["tasks"]
            if operation == "drop":
                entries.pop()
            elif operation == "reorder":
                entries.reverse()
            else:
                entries.insert(0, make_task("CH01", 3))
            with self.subTest(operation=operation), self.assertRaises(queue.QueueError):
                queue.amend(book, chapters, "Invalid queue mutation")

    def test_15_closed_book_cannot_silently_reopen_and_reason_is_required(self):
        book = make_book()
        with self.assertRaises(queue.QueueError):
            queue.amend(book, book["chapters"], "  ")
        while queue.pending(book):
            book = advance(book)
        chapters = copy.deepcopy(book["chapters"])
        chapters[-1]["sections"][0]["tasks"].append(make_task("CH02", 2))
        with self.assertRaises(queue.QueueError):
            queue.amend(book, chapters, "Reopen completed program")

    def test_16_render_is_deterministic_and_contains_full_active_contracts(self):
        book = make_book()
        view = queue.render(book)
        self.assertEqual(tuple(view), queue.FILES)
        self.assertEqual(view, queue.render(copy.deepcopy(book)))
        self.assertEqual(view["docs/BOOK.json"], queue.canonical(book))
        for task in queue.tasks(book)[:2]:
            self.assertIn(task["outcome"], view["docs/TODO.md"])
            self.assertIn(task["acceptance"][0], view["docs/TODO.md"])

    def test_17_unsafe_scope_and_unknown_schema_are_rejected(self):
        for scope in ("../outside", "/tmp/outside", "src/../outside", "*", "**", "src\\outside"):
            book = make_book()
            queue.tasks(book)[0]["scope"] = [scope]
            with self.subTest(scope=scope), self.assertRaises(queue.QueueError):
                queue.validate_book(book)
        book = make_book()
        book["schema"] = "unsupported/v2"
        with self.assertRaises(queue.QueueError):
            queue.validate_book(book)

    def test_18_duplicate_json_keys_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-fifo-json-") as directory:
            path = Path(directory) / "invalid.json"
            for raw in ('{"key":1,"key":2}', '{"key":NaN}', '{"key":Infinity}'):
                path.write_text(raw, encoding="utf-8")
                with self.subTest(raw=raw), self.assertRaises(queue.QueueError):
                    queue.read_json(path)

    def test_31_amend_cannot_jump_pending_section_tasks_in_active_chapter(self):
        book = make_book()
        later_task = make_task("CH00", 1, ["CS3-CH00-S01-U002"])
        later_task["id"] = "CS3-CH00-S02-U001"
        book["chapters"][0]["sections"].append({
            "id": "S02", "title": "Already queued next section", "tasks": [later_task],
        })
        queue.validate_book(book)
        proposal = copy.deepcopy(book["chapters"])
        proposal[0]["sections"][0]["tasks"].append(make_task("CH00", 3, ["CS3-CH00-S01-U002"]))
        # Appending to S01 would insert the new task before the already-pending S02.
        with self.assertRaises(queue.QueueError):
            queue.amend(book, proposal, "Attempt to jump the active chapter FIFO")


class QueueFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-fifo-git-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "repository"
        self.root.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "FIFO Regression Fixture")
        self.git("config", "user.email", "fixture@codeskeptic.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "Fixture root")
        self.main_base = self.git("rev-parse", "HEAD")
        main_patch = mock.patch.object(queue, "MAIN_BASE", self.main_base)
        main_patch.start()
        self.addCleanup(main_patch.stop)
        self.git("switch", "-q", "-c", queue.BOOTSTRAP_BRANCH)
        self.bootstrap_book = make_book()
        self.bootstrap_book["chapters"][0]["sections"][0]["tasks"] = [queue.tasks(self.bootstrap_book)[0]]
        self.bootstrap_book["chapters"][0]["sections"][0]["tasks"][0]["scope"] = list(queue.BOOTSTRAP_SCOPE)
        self.bootstrap_book["chapters"][1]["sections"][0]["tasks"][0]["depends"] = [queue.BOOTSTRAP_TASK]
        queue.publish(self.root, self.bootstrap_book)
        self.commit("Initial governance-only fixture book")
        self.bootstrap_head = self.git("rev-parse", "HEAD")
        self.assertEqual(queue.guard(self.root, self.main_base), "bootstrap")
        self.evidence = self.directory / "focused.log"
        self.evidence.write_bytes(b"focused PASS\n")
        self.receipt = self.directory / "review.json"
        self.review = review_for(queue.pending(self.bootstrap_book)[0], self.bootstrap_head,
                                 queue.BOOTSTRAP_BRANCH, self.evidence)
        self.save_review()
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 0)
        self.commit("Verified bootstrap FIFO pop")
        self.assertEqual(queue.guard(self.root, self.bootstrap_head), "finalized")
        self.book = queue.check(self.root)
        self.branch = branch_for(queue.pending(self.book)[0])
        self.git("switch", "-q", "-c", self.branch)
        self.head = self.git("rev-parse", "HEAD")
        self.review = review_for(queue.pending(self.book)[0], self.head, self.branch, self.evidence)
        self.save_review()

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        return result.stdout.strip()

    def commit(self, message):
        self.git("add", "--all")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", message)

    def save_review(self):
        self.receipt.write_text(queue.canonical(self.review), encoding="utf-8")

    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return queue.main(["--root", str(self.root), *args])

    def snapshot(self):
        return {name: (self.root / name).read_bytes() for name in queue.FILES}

    def test_19_published_book_and_all_views_pass_check(self):
        self.assertEqual(queue.check(self.root), self.book)
        self.assertEqual(self.cli("check"), 0)
        self.assertEqual(self.cli("status"), 0)
        self.assertFalse(queue.paths(self.root)[0].exists())

    def test_20_manual_view_tampering_is_rejected(self):
        originals = self.snapshot()
        for name in queue.FILES[1:]:
            path = self.root / name
            path.write_bytes(originals[name] + b"\nManual edit\n")
            with self.subTest(name=name), self.assertRaises(queue.QueueError):
                queue.check(self.root)
            path.write_bytes(originals[name])
        self.assertEqual(queue.check(self.root), self.book)

    def test_21_cli_finalization_is_exact_pop_without_committing(self):
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 0)
        result = queue.check(self.root)
        self.assertEqual(len(result["progress"]), len(self.book["progress"]) + 1)
        self.assertEqual(queue.pending(result), queue.pending(self.book)[1:])
        self.assertEqual(result["progress"][0]["review"], self.review)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertEqual(set(self.git("diff", "--name-only").splitlines()),
                         {"docs/BOOK.json", "docs/TODO.md", "docs/PROGRESS.md"})
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)

    def test_22_dirty_implementation_and_in_repository_review_are_rejected(self):
        baseline = self.snapshot()
        dirt = self.root / "untracked.txt"
        dirt.write_text("unfinished work", encoding="utf-8")
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        dirt.unlink()
        inside = self.root / ".git" / "review.json"
        inside.write_text(queue.canonical(self.review), encoding="utf-8")
        self.assertEqual(self.cli("finalize", "--review", str(inside)), 2)
        self.assertEqual(self.snapshot(), baseline)

    def test_23_missing_changed_and_symlink_evidence_cannot_pop(self):
        baseline = self.snapshot()
        original = self.evidence.read_bytes()
        self.evidence.unlink()
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        self.evidence.write_bytes(original + b"changed")
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        target = self.directory / "target.log"
        target.write_bytes(original)
        self.evidence.unlink()
        self.evidence.symlink_to(target)
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        self.assertEqual(self.snapshot(), baseline)

    def test_24_stale_head_and_noncanonical_review_cannot_pop(self):
        baseline = self.snapshot()
        self.review["head"] = "b" * 40
        self.save_review()
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        self.review["head"] = self.head
        self.save_review()
        self.receipt.write_text(" " + self.receipt.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        self.assertEqual(self.snapshot(), baseline)

    def test_25_guard_accepts_only_front_scope_implementation(self):
        source = self.root / "src" / "fixture.cc"
        source.parent.mkdir()
        source.write_text("int fixture;\n", encoding="utf-8")
        self.commit("Scoped implementation")
        self.assertEqual(queue.guard(self.root, self.head), "implementation")
        unrelated = self.root / "unrelated.txt"
        unrelated.write_text("outside task scope\n", encoding="utf-8")
        self.commit("Out of scope fixture")
        with self.assertRaises(queue.QueueError):
            queue.guard(self.root, self.head)

    def test_26_guard_validates_exact_ledger_parent_and_rejects_skipped_prefix(self):
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 0)
        self.commit("Finalize front fixture")
        self.assertEqual(queue.guard(self.root, self.head), "finalized")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "Extra parent edge")
        with self.assertRaises(queue.QueueError):
            queue.guard(self.root, self.head)

    def test_27_caught_write_failures_restore_every_managed_byte(self):
        original_write = queue.atomic_write
        baseline = self.snapshot()
        for fail_at in range(2, 6):
            calls = 0

            def fail_once(path, data):
                nonlocal calls
                calls += 1
                if calls == fail_at:
                    raise OSError("injected managed-file write failure")
                return original_write(path, data)

            with self.subTest(fail_at=fail_at), mock.patch.object(queue, "atomic_write", side_effect=fail_once):
                with self.assertRaises(OSError):
                    queue.publish(self.root, advance(self.book))
            self.assertEqual(self.snapshot(), baseline)
            self.assertFalse(queue.paths(self.root)[0].exists())
            self.assertEqual(queue.check(self.root), self.book)

    def test_28_interrupted_rollback_blocks_check_then_recovers(self):
        baseline = self.snapshot()
        original_write = queue.atomic_write
        calls = 0

        def disk_stops(path, data):
            nonlocal calls
            calls += 1
            if calls >= 4:
                raise OSError("injected persistent write failure")
            return original_write(path, data)

        with mock.patch.object(queue, "atomic_write", side_effect=disk_stops):
            with self.assertRaises(OSError):
                queue.publish(self.root, advance(self.book))
        self.assertTrue(queue.paths(self.root)[0].exists())
        with self.assertRaises(queue.QueueError):
            queue.check(self.root)
        self.assertEqual(self.cli("recover"), 0)
        self.assertEqual(self.snapshot(), baseline)
        self.assertEqual(queue.check(self.root), self.book)
        # A real process exit cannot execute publish's exception rollback.
        proposal = self.directory / "after-interruption.json"
        proposal.write_text(queue.canonical(advance(self.book)), encoding="utf-8")
        child_code = """
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('fifo_crash_fixture', sys.argv[1])
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
original_write = q.atomic_write
calls = 0
def crash_between_files(path, data):
    global calls
    calls += 1
    if calls == 4:
        os._exit(74)
    original_write(path, data)
q.atomic_write = crash_between_files
q.publish(Path(sys.argv[2]), q.read_json(Path(sys.argv[3])))
"""
        child = subprocess.run([os.sys.executable, "-B", "-c", child_code,
                                str(SCRIPT), str(self.root), str(proposal)],
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 74, child.stderr)
        self.assertTrue(queue.paths(self.root)[0].exists())
        with self.assertRaises(queue.QueueError):
            queue.check(self.root)
        self.assertEqual(self.cli("recover"), 0)
        self.assertEqual(self.snapshot(), baseline)
        self.assertEqual(queue.check(self.root), self.book)

    def test_29_recovery_refuses_unrelated_edit_or_different_head(self):
        original_write = queue.atomic_write
        calls = 0

        def disk_stops(path, data):
            nonlocal calls
            calls += 1
            if calls >= 4:
                raise OSError("persistent fault")
            return original_write(path, data)

        with mock.patch.object(queue, "atomic_write", side_effect=disk_stops):
            with self.assertRaises(OSError):
                queue.publish(self.root, advance(self.book))
        todo = self.root / "docs/TODO.md"
        recorded_bytes = todo.read_bytes()
        todo.write_bytes(recorded_bytes + b"unrelated user edit\n")
        before = self.snapshot()
        self.assertEqual(self.cli("recover"), 2)
        self.assertEqual(self.snapshot(), before)
        todo.write_bytes(recorded_bytes)
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "Different HEAD")
        with self.assertRaises(queue.QueueError):
            queue.recover(self.root)
        self.assertTrue(queue.paths(self.root)[0].exists())

    def test_30_bootstrap_replay_and_main_mutation_are_rejected(self):
        self.git("switch", "-q", queue.BOOTSTRAP_BRANCH)
        before = self.snapshot()
        self.assertEqual(self.cli("bootstrap"), 2)
        self.git("branch", "-f", "main", "HEAD")
        self.git("switch", "-q", "main")
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        self.assertEqual(self.snapshot(), before)

    def test_32_guard_rejects_implementation_on_another_tasks_branch(self):
        source = self.root / "src" / "fixture.cc"
        source.parent.mkdir()
        source.write_text("int fixture;\n", encoding="utf-8")
        self.commit("Scoped implementation on the wrong task branch")
        self.git("branch", "-m", branch_for(queue.pending(self.book)[1]))
        with self.assertRaises(queue.QueueError):
            queue.guard(self.root, self.head)

    def test_33_bootstrap_guard_is_narrow_and_cannot_hide_product_edits(self):
        self.git("switch", "-q", "--detach", self.bootstrap_head)
        self.git("branch", "-f", queue.BOOTSTRAP_BRANCH, self.bootstrap_head)
        self.git("switch", "-q", queue.BOOTSTRAP_BRANCH)
        self.assertEqual(queue.guard(self.root, self.main_base), "bootstrap")
        source = self.root / "src" / "fixture.cc"
        source.parent.mkdir()
        source.write_text("int hidden_product_change;\n", encoding="utf-8")
        self.commit("Product code must not enter governance bootstrap")
        with self.assertRaises(queue.QueueError):
            queue.guard(self.root, self.main_base)

    def test_34_guard_cannot_shorten_base_to_hide_earlier_scope_violation(self):
        unrelated = self.root / "unrelated-contract.txt"
        unrelated.write_text("out-of-scope earlier change\n", encoding="utf-8")
        self.commit("Earlier out-of-scope implementation")
        source = self.root / "src" / "fixture.cc"
        source.parent.mkdir()
        source.write_text("int allowed_later_change;\n", encoding="utf-8")
        self.commit("Later in-scope implementation")
        before = self.snapshot()
        with self.assertRaises(queue.QueueError):
            queue.guard(self.root, "HEAD^")
        self.assertEqual(self.snapshot(), before)

    def test_35_guard_checks_each_edge_even_when_scope_violation_was_reverted(self):
        unrelated = self.root / "unrelated-contract.txt"
        unrelated.write_text("out-of-scope transient change\n", encoding="utf-8")
        self.commit("Out-of-scope historical edge")
        unrelated.unlink()
        self.commit("Revert outside path to hide it in aggregate diff")
        source = self.root / "src" / "fixture.cc"
        source.parent.mkdir()
        source.write_text("int allowed_final_change;\n", encoding="utf-8")
        self.commit("Allowed final edge")
        self.assertEqual(self.git("diff", "--name-only", self.head, "HEAD"), "src/fixture.cc")
        for base in (self.head, "HEAD^"):
            with self.subTest(base=base), self.assertRaises(queue.QueueError):
                queue.guard(self.root, base)

    def test_36_finalizer_rejects_invalid_implementation_history_despite_pass_review(self):
        unrelated = self.root / "unrelated-contract.txt"
        unrelated.write_text("out-of-scope earlier change\n", encoding="utf-8")
        self.commit("Out-of-scope implementation before claimed PASS")
        source = self.root / "src" / "fixture.cc"
        source.parent.mkdir()
        source.write_text("int allowed_final_change;\n", encoding="utf-8")
        self.commit("In-scope final edge before claimed PASS")
        exact_head = self.git("rev-parse", "HEAD")
        self.review = review_for(queue.pending(self.book)[0], exact_head, self.branch, self.evidence)
        self.save_review()
        self.assertEqual(self.git("status", "--porcelain=v1"), "")
        queue.validate_review(queue.pending(self.book)[0], self.review, exact_head, self.branch)
        before = self.snapshot()
        self.assertEqual(self.cli("finalize", "--review", str(self.receipt)), 2)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.git("rev-parse", "HEAD"), exact_head)

    def test_37_amendment_cannot_launder_earlier_scope_violation(self):
        unrelated = self.root / "unrelated-contract.txt"
        unrelated.write_text("out-of-scope implementation before amendment\n", encoding="utf-8")
        self.commit("Historical scope violation before proposed plan amendment")
        chapters = copy.deepcopy(self.book["chapters"])
        chapters[-1]["sections"][0]["tasks"][0]["outcome"] = "Refined future outcome"
        reason = "Clarify future task without changing current front"
        valid_amendment = queue.amend(self.book, chapters, reason)
        proposal = self.directory / "amendment.json"
        proposal.write_text(queue.canonical(chapters), encoding="utf-8")
        before = self.snapshot()
        self.assertEqual(self.cli("amend", "--proposal", str(proposal), "--reason", reason), 2)
        self.assertEqual(self.snapshot(), before)
        # Even a manually committed otherwise-valid amendment cannot reset the
        # implementation boundary and erase the earlier out-of-scope edge.
        queue.publish(self.root, valid_amendment)
        self.commit("Attempt to disguise invalid history with valid future amendment")
        source = self.root / "src" / "fixture.cc"
        source.parent.mkdir()
        source.write_text("int allowed_final_change;\n", encoding="utf-8")
        self.commit("In-scope final edge following laundering attempt")
        with self.assertRaises(queue.QueueError):
            queue.guard(self.root, "HEAD^")


if __name__ == "__main__":
    unittest.main()
