#!/usr/bin/env python3
"""Read-only CH08+ contract/document and historical-evidence continuity check.

BOOK remains the sole queue. Rendering prints only an approved contract view;
this helper never edits ledgers, refreshes quality pins, or declares a release.
"""
from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import project_queue as q

TERMINAL = "4fd4a21f9b5dc381ea1ec3014daa3082a9d14e24"
ACTIVATION = "3ae794e3f552aa5040b5c12f53082ad14977e3cc"
BEGIN = "<!-- BEGIN APPROVED PRODUCT CONTRACTS -->"
END = "<!-- END APPROVED PRODUCT CONTRACTS -->"
DOCUMENT = "docs/PRODUCT_COMPLETION_PLAN.md"
ARCHIVE = "docs/archive/CWE_RESTART_PLAN_2026-09-08.md"


def git_bytes(root, revision, path):
    result = subprocess.run(["git", "show", f"{revision}:{path}"], cwd=root,
                            capture_output=True, check=False)
    q.require(result.returncode == 0, f"missing historical Git object: {revision}:{path}")
    return result.stdout


def snapshots(root):
    old = json.loads(git_bytes(root, TERMINAL, "docs/BOOK.json"))
    approved = json.loads(git_bytes(root, ACTIVATION, "docs/BOOK.json"))
    q.require(q.digest(old) == q.PRODUCT_RESTART_OLD_BOOK, "terminal snapshot digest")
    q.require(q.digest(approved) == q.PRODUCT_RESTART_NEW_BOOK, "approved snapshot digest")
    q.validate_book(old)
    q.validate_book(approved)
    return old, approved


def validate_continuity(book, old, approved):
    q.validate_book(book)
    q.require(book["chapters"][:8] == old["chapters"], "old chapter contracts changed")
    q.require(book["progress"][-46:] == old["progress"], "old completed records changed")
    prefix = approved["decisions"]
    q.require(book["decisions"][:len(prefix)] == prefix, "approved decision prefix changed")
    expected = copy.deepcopy(approved["chapters"])
    by_id = {task["id"]: task for task in q.tasks({"chapters": expected})}
    # Keep the approved human contract fixed. Only the normal separately reviewed
    # scope ledger may extend it; actual history admission remains q.guard's job.
    for decision in book["decisions"][len(prefix):]:
        q.require("scope_review" in decision, "unchanged plan admits only reviewed scope additions")
        review = decision["scope_review"]
        q.validate_scope_review(review)
        q.require(decision["previous_plan_sha256"] == q.digest(expected), "scope predecessor changed")
        task = by_id.get(review["task_id"])
        q.require(task is not None and task["id"].split("-")[1] >= "CH08", "scope outside new plan")
        q.require(review["contract_sha256"] == q.digest(task), "scope contract changed")
        q.require(all(not any(fnmatch.fnmatchcase(path, pattern) for pattern in task["scope"])
                      for path in review["additions"]), "scope path already admitted")
        task["scope"].extend(review["additions"])
    q.require(book["chapters"] == expected, "approved ID/outcome/acceptance/scope/check/budget/order changed")
    q.require(len(q.tasks(book)) == 97, "approved task count changed")


def render_contracts(approved):
    result = BEGIN + "\n\n"
    for chapter in approved["chapters"][8:]:
        result += f"## {chapter['id']} — {chapter['title']}\n\n"
        for section in chapter["sections"]:
            result += f"### {chapter['id']}-{section['id']} — {section['title']}\n\n"
            result += "".join(q.task_block(task, level=4) for task in section["tasks"])
    return result + END + "\n"


def validate_document(content, approved):
    q.require(content.count(BEGIN) == 1 and content.count(END) == 1,
              "product contract markers missing or duplicated")
    start, stop = content.index(BEGIN), content.index(END) + len(END)
    q.require(start < stop and content[start:stop] + "\n" == render_contracts(approved),
              "product document contract differs from approved BOOK")
    outside = content[:start] + content[stop:]
    q.require(not re.search(r"^#{1,6}\s+CS3-CH\d", outside, re.MULTILINE)
              and not re.search(r"^\s*[-*]\s+\[[ xX]\]", outside, re.MULTILINE),
              "unmanaged task/status list outside the approved contract block")


def validate_archive(actual, expected):
    q.require(actual == expected, "historical PLAN archive bytes changed")


def check_evidence(row):
    path = Path(row["evidence"])
    q.require(path.is_absolute() and path.is_file() and not path.is_symlink()
              and path.stat().st_size <= 10 * 1024 * 1024, "missing/unsafe evidence")
    q.require(hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"],
              f"historical evidence digest changed: {path}")


def check(root):
    old, approved = snapshots(root)
    book = q.check(root)
    validate_continuity(book, old, approved)
    q.require(q.git(root, "rev-parse", "main") == q.MAIN_BASE, "protected main changed")
    document, archive = root / DOCUMENT, root / ARCHIVE
    q.require(document.is_file() and not document.is_symlink(), "missing/unsafe product document")
    q.require(archive.is_file() and not archive.is_symlink(), "missing/unsafe historical archive")
    validate_document(document.read_text(encoding="utf-8"), approved)
    validate_archive(archive.read_bytes(), git_bytes(root, TERMINAL, "docs/PLAN.md"))
    # The generated old 46 section bytes remain an exact suffix after new POPs.
    prior_progress = git_bytes(root, TERMINAL, "docs/PROGRESS.md")
    prior_sections = prior_progress[prior_progress.index(b"## CS3-"):]
    q.require((root / "docs/PROGRESS.md").read_bytes().endswith(prior_sections),
              "historical PROGRESS section bytes changed")
    evidence = {(check["evidence"], check["sha256"]) for record in old["progress"]
                for check in record["review"]["checks"]}
    for path, sha in sorted(evidence):
        check_evidence({"evidence": path, "sha256": sha})
    return {"result": "PRODUCT_PLAN_CONTRACT_PASS", "approved_new_tasks": 51,
            "historical_tasks_preserved": 46, "historical_evidence_files": len(evidence),
            "approved_chapters_sha256": q.digest(approved["chapters"][8:]),
            "current_completed": len(book["progress"]), "product_quality_measured": None,
            "release_qualified": False,
            "boundary": "Read-only contract/evidence continuity; not product execution or release qualification."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "render"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        if args.command == "render":
            print(render_contracts(snapshots(args.root)[1]), end="")
        else:
            print(q.canonical(check(args.root)), end="")
    except (q.QueueError, OSError, ValueError) as error:
        print(f"PRODUCT_PLAN_FAIL: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
