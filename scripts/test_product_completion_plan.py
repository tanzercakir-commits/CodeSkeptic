#!/usr/bin/env python3
"""Read-only plan tests; mutations use in-memory data or owned temp fixtures."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

import product_completion_plan as p


class ProductPlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.old, cls.approved = p.snapshots(cls.root)

    def test_01_initial_contract(self):
        p.validate_continuity(self.approved, self.old, self.approved)

    def test_02_document_has_only_new_tasks(self):
        block = p.render_contracts(self.approved)
        self.assertEqual(block.count("#### CS3-CH"), 51)
        self.assertNotIn("#### CS3-CH07", block)
        self.assertIn("**Kapsam:**", block)
        self.assertIn("**Kabul:**", block)

    def test_03_generated_block_exact(self):
        block = p.render_contracts(self.approved)
        p.validate_document("intro\n" + block + "after\n", self.approved)
        for before, after in [("**Kapsam:**", "**Scope:**"),
                              ("precision >=0.90", "precision >=0.85"),
                              ("CS3-CH14-S02-U003", "CS3-CH14-S02-U099")]:
            with self.subTest(before=before), self.assertRaises(p.q.QueueError):
                p.validate_document(block.replace(before, after), self.approved)

    def test_04_missing_duplicate_reversed_markers(self):
        block = p.render_contracts(self.approved)
        for value in ["", block + block, p.END + block + p.BEGIN,
                      block.replace(p.END, "")]:
            with self.subTest(value=value[:30]), self.assertRaises(p.q.QueueError):
                p.validate_document(value, self.approved)

    def test_05_old_contract_change_rejected(self):
        book = copy.deepcopy(self.approved)
        p.q.tasks(book)[0]["title"] += " changed"
        with self.assertRaises(p.q.QueueError):
            p.validate_continuity(book, self.old, self.approved)

    def test_06_old_receipt_change_rejected(self):
        book = copy.deepcopy(self.approved)
        book["progress"][0]["completed_at"] = "changed"
        with self.assertRaisesRegex(p.q.QueueError, "old completed"):
            p.validate_continuity(book, self.old, self.approved)

    def test_07_new_acceptance_budget_scope_and_order_rejected(self):
        for field, value in [("acceptance", ["weakened"]), ("budget", "T1"),
                             ("scope", ["README.md"]), ("checks", ["made-up"]),
                             ("outcome", "different")]:
            book = copy.deepcopy(self.approved)
            p.q.tasks(book)[46][field] = value
            with self.subTest(field=field), self.assertRaises(p.q.QueueError):
                p.validate_continuity(book, self.old, self.approved)
        book = copy.deepcopy(self.approved)
        queue = book["chapters"][8]["sections"][0]["tasks"]
        queue[0], queue[1] = queue[1], queue[0]
        with self.assertRaises(p.q.QueueError):
            p.validate_continuity(book, self.old, self.approved)

    def test_08_old_decision_rejected(self):
        book = copy.deepcopy(self.approved)
        book["decisions"][0]["reason"] += " changed"
        with self.assertRaisesRegex(p.q.QueueError, "decision prefix"):
            p.validate_continuity(book, self.old, self.approved)

    def scope_review(self):
        task = p.q.pending(self.approved)[0]
        return {"schema": "codeskeptic-scope-review/v1", "task_id": task["id"],
                "head": p.ACTIVATION, "branch": p.q.PRODUCT_RESTART_BRANCH,
                "contract_sha256": p.q.digest(task), "additions": ["docs/necessary-test.md"],
                "reason": "Necessary exact path, independently reviewed",
                "implementer": "test-primary", "verifier": "test-independent",
                "verdict": "PASS", "findings": []}

    def test_09_reviewed_scope_does_not_rewrite_approved_plan(self):
        review = self.scope_review()
        book = p.q.extend_scope(self.approved, review, review["head"], review["branch"])
        p.validate_continuity(book, self.old, self.approved)
        self.assertNotIn("docs/necessary-test.md", p.render_contracts(self.approved))
        self.assertIn("docs/necessary-test.md", p.q.pending(book)[0]["scope"])
        book["decisions"][-1]["scope_review"]["contract_sha256"] = "1" * 64
        with self.assertRaises(p.q.QueueError):
            p.validate_continuity(book, self.old, self.approved)

    def test_10_ordinary_amend_not_silent_plan_rewrite(self):
        book = copy.deepcopy(self.approved)
        book["decisions"].append({"revision": 61, "reason": "different plan",
                                  "previous_plan_sha256": p.q.digest(book["chapters"])})
        with self.assertRaisesRegex(p.q.QueueError, "only reviewed scope"):
            p.validate_continuity(book, self.old, self.approved)

    def test_11_evidence_identity_and_safety(self):
        with tempfile.TemporaryDirectory(prefix="product-plan-test-") as tmp:
            file = Path(tmp) / "log"
            file.write_bytes(b"actual evidence\n")
            row = {"evidence": str(file), "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
            p.check_evidence(row)
            file.write_bytes(b"changed\n")
            with self.assertRaisesRegex(p.q.QueueError, "evidence digest"):
                p.check_evidence(row)
            link = Path(tmp) / "link"
            link.symlink_to(file)
            row["evidence"] = str(link)
            with self.assertRaisesRegex(p.q.QueueError, "unsafe evidence"):
                p.check_evidence(row)
            row["evidence"] = "relative.log"
            with self.assertRaises(p.q.QueueError):
                p.check_evidence(row)

    def test_12_actual_repository(self):
        result = p.check(self.root)
        self.assertEqual(result["approved_new_tasks"], 51)
        self.assertEqual(result["historical_tasks_preserved"], 46)
        self.assertIsNone(result["product_quality_measured"])
        self.assertFalse(result["release_qualified"])

    def test_13_archive_bytes_not_normalized(self):
        expected = p.git_bytes(self.root, p.TERMINAL, "docs/PLAN.md")
        p.validate_archive(expected, expected)
        for corrupt in [expected.rstrip(), expected + b"\n", expected.replace(b"\n", b"\r\n")]:
            with self.subTest(size=len(corrupt)), self.assertRaises(p.q.QueueError):
                p.validate_archive(corrupt, expected)

    def test_14_no_second_unmanaged_task_or_status_queue(self):
        block = p.render_contracts(self.approved)
        for extra in ["#### CS3-CH07-S01-U002 — historical\n", "- [ ] extra task\n",
                      "- [x] completed early\n", "* [X] DONE\n"]:
            with self.subTest(extra=extra), self.assertRaisesRegex(p.q.QueueError, "unmanaged"):
                p.validate_document(block + extra, self.approved)


if __name__ == "__main__":
    unittest.main()
