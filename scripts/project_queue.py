#!/usr/bin/env python3
"""Local, chapter-by-chapter FIFO. No network, subprocess tests, or self-approval.

BOOK.json is the transaction state; PLAN/TODO/PROGRESS are checked readable views.
Finalization prepares a ledger-only change; the primary commits and checks it.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timezone
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

FILES = ("docs/BOOK.json", "docs/PLAN.md", "docs/TODO.md", "docs/PROGRESS.md")
TASK_RE = re.compile(r"CS3-CH\d{2}-S\d{2}-U\d{3}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
BOOTSTRAP_BRANCH = "governance/cwe-product-restart"
BOOTSTRAP_TASK = "CS3-CH00-S01-U001"
MAIN_BASE = "7dfd37596414c9512316093ff4fb6b039673f55f"
BOOTSTRAP_SCOPE = (*FILES, "AGENTS.md", "INVARIANTS.md", "MASTER_PROMPT.md",
                   "CONTRIBUTING.md", "docs/RESTART.md", "docs/QUEUE_GUIDE.md",
                   "docs/CWE_SCOPE.md", "scripts/project_queue.py", "scripts/local_test.sh",
                   "scripts/check_docs_sync.sh", "scripts/progress_status.py",
                   "tests/test_project_queue.py", "tests/StatusAutomationTest.py",
                   "tests/CMakeLists.txt", ".github/workflows/project-queue.yml")
MAX_BYTES = 2 * 1024 * 1024


class QueueError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise QueueError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path, limit=MAX_BYTES):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), f"not a regular file: {path}")
    require(path.stat().st_size <= limit, f"file exceeds bound: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(QueueError(value)))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise QueueError(f"invalid JSON: {path}: {error}") from error


def text(value):
    return isinstance(value, str) and bool(value.strip()) and not any(ord(c) < 32 for c in value)


def tasks(book):
    return [task for chapter in book["chapters"] for section in chapter["sections"] for task in section["tasks"]]


def pending(book):
    return tasks(book)[len(book["progress"]):]


def validate_book(book):
    require(isinstance(book, dict) and set(book) == {"schema", "epoch", "revision", "chapters", "progress", "decisions"}, "book fields")
    require(book["schema"] == "codeskeptic-book/v1" and book["epoch"] == "CWE-RESTART-20260905", "book schema/epoch")
    require(type(book["revision"]) is int and book["revision"] > 0, "revision")
    require(isinstance(book["chapters"], list) and 1 <= len(book["chapters"]) <= 32, "chapter count")
    ids, chapters, sections = [], [], []
    fields = {"id", "title", "outcome", "acceptance", "scope", "checks", "budget", "depends"}
    for chapter in book["chapters"]:
        require(isinstance(chapter, dict) and set(chapter) == {"id", "title", "sections"}, "chapter fields")
        require(re.fullmatch(r"CH\d{2}", chapter["id"]) and text(chapter["title"]), "chapter identity")
        chapters.append(chapter["id"])
        require(isinstance(chapter["sections"], list) and chapter["sections"], "empty sections")
        for section in chapter["sections"]:
            require(isinstance(section, dict) and set(section) == {"id", "title", "tasks"}, "section fields")
            require(re.fullmatch(r"S\d{2}", section["id"]) and text(section["title"]), "section identity")
            sections.append(chapter["id"] + "-" + section["id"])
            require(isinstance(section["tasks"], list) and section["tasks"], "empty section")
            for task in section["tasks"]:
                require(isinstance(task, dict) and set(task) == fields, "task fields")
                require(TASK_RE.fullmatch(task["id"]) and task["id"].startswith("CS3-" + chapter["id"] + "-" + section["id"] + "-"), "task hierarchy")
                require(text(task["title"]) and text(task["outcome"]), "empty task outcome/title")
                for field in ("acceptance", "scope", "checks"):
                    require(isinstance(task[field], list) and task[field] and all(text(x) for x in task[field]), f"task {field}")
                    require(len(task[field]) == len(set(task[field])), f"duplicate {field}")
                require(all(not p.startswith(("/", "-")) and ".." not in p.split("/") and "\\" not in p and p not in ("*", "**") for p in task["scope"]), "unsafe scope")
                require(task["budget"] in ("T0", "T1", "T2", "T3"), "test budget")
                require(isinstance(task["depends"], list) and all(x in ids for x in task["depends"]), "dependency not earlier")
                ids.append(task["id"])
    require(len(ids) <= 500 and len(ids) == len(set(ids)), "duplicate/too many task IDs")
    require(chapters == sorted(set(chapters)) and len(sections) == len(set(sections)), "chapter/section order or duplication")
    require(isinstance(book["progress"], list) and len(book["progress"]) <= len(ids), "progress count")
    catalog = {t["id"]: t for t in tasks(book)}
    done = []
    for record in reversed(book["progress"]):
        require(isinstance(record, dict) and set(record) == {"task", "review", "completed_at"}, "progress record")
        task = record["task"]
        require(task["id"] in catalog and task == catalog[task["id"]], "completed contract changed")
        validate_review(task, record["review"], record["review"].get("head"), record["review"].get("branch"))
        require(text(record["completed_at"]), "completion time")
        done.append(task["id"])
    require(done == ids[:len(done)], "completed work is not exact FIFO prefix")
    require(isinstance(book["decisions"], list) and all(isinstance(x, dict) and set(x) == {"revision", "reason", "previous_plan_sha256"} and type(x["revision"]) is int and text(x["reason"]) and DIGEST_RE.fullmatch(x["previous_plan_sha256"]) for x in book["decisions"]), "decision records")
    return book


def validate_review(task, review, head, branch):
    fields = {"schema", "task_id", "head", "branch", "contract_sha256", "implementer", "verifier", "verdict", "findings", "checks"}
    require(isinstance(review, dict) and set(review) == fields, "review fields")
    require(review["schema"] == "codeskeptic-review/v1", "review schema")
    require(isinstance(head, str) and SHA_RE.fullmatch(head) and review["head"] == head, "stale/invalid head")
    require(review["task_id"] == task["id"] and review["contract_sha256"] == digest(task), "task/contract mismatch")
    expected = "agent/" + task["id"].lower() + "-"
    require(isinstance(branch, str) and review["branch"] == branch and ((task["id"] == BOOTSTRAP_TASK and branch == BOOTSTRAP_BRANCH) or branch.startswith(expected)), "wrong task branch")
    require(text(review["implementer"]) and text(review["verifier"]) and review["implementer"] != review["verifier"], "independent reviewer required")
    require(review["verdict"] == "PASS" and review["findings"] == [], "review has not passed")
    require(isinstance(review["checks"], list) and 1 <= len(review["checks"]) <= 32, "check count")
    names = []
    for check in review["checks"]:
        require(isinstance(check, dict) and set(check) == {"name", "command", "result", "sha256", "evidence"}, "check fields")
        require(all(text(check[x]) for x in ("name", "command", "evidence")), "check text")
        require(check["result"] == "PASS" and isinstance(check["sha256"], str) and DIGEST_RE.fullmatch(check["sha256"]) and check["sha256"] != "0" * 64, "missing/failed evidence")
        names.append(check["name"])
    require(len(names) == len(set(names)) and set(task["checks"]) <= set(names), "required checks missing/duplicated")


def complete(book, review, head, branch, completed_at):
    validate_book(book)
    require(bool(pending(book)), "queue complete")
    validate_review(pending(book)[0], review, head, branch)
    updated = copy.deepcopy(book)
    updated["progress"].insert(0, {"task": copy.deepcopy(pending(book)[0]), "review": copy.deepcopy(review), "completed_at": completed_at})
    return validate_book(updated)


def amend(book, chapters, reason):
    validate_book(book)
    require(text(reason), "amendment reason required")
    updated = copy.deepcopy(book)
    updated["chapters"] = copy.deepcopy(chapters)
    updated["revision"] += 1
    updated["decisions"].append({"revision": updated["revision"], "reason": reason, "previous_plan_sha256": digest(book["chapters"])})
    validate_book(updated)
    old_tasks, new_tasks = tasks(book), tasks(updated)
    old_ids = [x["id"] for x in old_tasks]
    require([x["id"] for x in new_tasks if x["id"] in old_ids] == old_ids, "cannot drop/reorder existing IDs")
    if pending(book):
        require(pending(updated) and pending(updated)[0] == pending(book)[0], "active front contract is frozen until completed")
        active = pending(book)[0]["id"].split("-")[1]
        old_queue = [t["id"] for t in pending(book) if t["id"].split("-")[1] == active]
        new_queue = [t["id"] for t in pending(updated) if t["id"].split("-")[1] == active]
        require(new_queue[:len(old_queue)] == old_queue, "cannot insert ahead of active chapter queue")
    else:
        require(len(new_tasks) == len(old_tasks), "closed book cannot silently reopen")
    # Existing chapter/section queues remain in place; additions append to their back.
    for old_ch in book["chapters"]:
        matches = [c for c in chapters if c["id"] == old_ch["id"]]
        require(len(matches) == 1, "chapter removed")
        for old_sec in old_ch["sections"]:
            matches_sec = [s for s in matches[0]["sections"] if s["id"] == old_sec["id"]]
            require(len(matches_sec) == 1, "section removed")
            require([t["id"] for t in matches_sec[0]["tasks"]][:len(old_sec["tasks"])] == [t["id"] for t in old_sec["tasks"]], "new tasks must append to section back")
    return updated


def task_block(task, level=3):
    return (f"{'#' * level} {task['id']} — {task['title']}\n\n**Sonuç:** {task['outcome']}\n\n**Kabul:**\n\n" + "".join(f"- {x}\n" for x in task["acceptance"]) + f"\n**Test bütçesi:** {task['budget']}\n**Kontroller:** {', '.join(task['checks'])}\n**Kapsam:** {', '.join(task['scope'])}\n**Bağımlılıklar:** {', '.join(task['depends']) or 'Yok'}\n\n")


def render(book):
    validate_book(book)
    plan = f"# CodeSkeptic — CWE Ürün Planı\n\nSürüm: {book['revision']}. Eski planın devamı değil; main tabanlı yeni program.\n\nPLAN/TODO/PROGRESS aynı BOOK.json kaydından üretilir; elle değiştirilmez. Gelecek işler kontrollü olarak eklenebilir/güncellenebilir. Aktif işin kabulü ve tamamlanmış kayıtlar değiştirilmez.\n\n"
    for chapter in book["chapters"]:
        plan += f"## {chapter['id']} — {chapter['title']}\n\n"
        for section in chapter["sections"]:
            plan += f"### {chapter['id']}-{section['id']} — {section['title']}\n\n"
            plan += "".join(task_block(t, level=4) for t in section["tasks"])
    todo = "# CodeSkeptic — FIFO TODO\n\nTek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.\n\n"
    remaining = pending(book)
    if not remaining:
        todo += "_Queue complete._\n"
    else:
        chapter_id = remaining[0]["id"].split("-")[1]
        todo += f"## FRONT — {remaining[0]['id']}\n\n"
        todo += "".join(task_block(t) for t in remaining if t["id"].split("-")[1] == chapter_id)
        todo += "## Sonraki chapter kuyruğu — henüz yürütülemez\n\n"
        for c in book["chapters"]:
            if c["id"] > chapter_id:
                todo += f"- {c['id']} — {c['title']}\n"
    progress = "# CodeSkeptic — PROGRESS\n\nYalnız bağımsız doğrulanmış yerel tamamlamalar; GitHub yayını veya release anlamına gelmez. Eski programın kayıtları referans arşivinde korunmuştur.\n\n"
    if not book["progress"]:
        progress += "_No completed tasks._\n"
    for record in book["progress"]:
        task, review = record["task"], record["review"]
        progress += f"## {task['id']} — {task['title']}\n\n- Commit: `{review['head']}`\n- Dal: `{review['branch']}`\n- Implementer: `{review['implementer']}`\n- Bağımsız denetçi: `{review['verifier']}`\n- İnceleme SHA-256: `{digest(review)}`\n- Tarih: {record['completed_at']}\n- Sonuç: {task['outcome']}\n"
        progress += "".join(f"- {c['name']}: PASS; SHA-256 `{c['sha256']}`; `{c['command']}`\n" for c in review["checks"]) + "\n"
    return dict(zip(FILES, (canonical(book), plan.rstrip() + "\n", todo.rstrip() + "\n", progress.rstrip() + "\n")))


def git(root, *args, input=None):
    result = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.filemode=true", *args], cwd=root, input=input, capture_output=True, text=True)
    require(result.returncode == 0, f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def paths(root):
    gitdir = Path(git(root, "rev-parse", "--absolute-git-dir"))
    return gitdir / "project-queue-recovery.json", gitdir / "project-queue.lock"


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".queue-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def publish(root, book):
    contents = {name: value.encode() for name, value in render(book).items()}
    journal, _ = paths(root)
    require(not journal.exists(), "interrupted transition: recover first")
    originals = {}
    for name in FILES:
        path = root / name
        require(not path.is_symlink(), "managed file cannot be symlink")
        originals[name] = path.read_bytes() if path.exists() else None
    encode = lambda values: {k: base64.b64encode(v).decode() if v is not None else None for k, v in values.items()}
    atomic_write(journal, canonical({"head": git(root, "rev-parse", "HEAD"), "before": encode(originals), "after": encode(contents)}).encode())
    try:
        for name in (*FILES[1:], FILES[0]):
            atomic_write(root / name, contents[name])
        require(all((root / name).read_bytes() == data for name, data in contents.items()), "publication verification failed")
    except BaseException:
        errors = []
        for name, data in originals.items():
            try:
                if data is None:
                    (root / name).unlink(missing_ok=True)
                else:
                    atomic_write(root / name, data)
            except BaseException as error:
                errors.append(str(error))
        if not errors:
            journal.unlink()
        raise
    journal.unlink()


def recover(root):
    journal, _ = paths(root)
    saved = read_json(journal)
    require(set(saved) == {"head", "before", "after"} and saved["head"] == git(root, "rev-parse", "HEAD"), "recovery HEAD mismatch")
    require(set(saved["before"]) == set(FILES) and set(saved["after"]) == set(FILES), "recovery paths mismatch")
    decode = lambda value: base64.b64decode(value, validate=True) if value is not None else None
    for name in FILES:
        path = root / name
        require(not path.is_symlink(), "recovery symlink")
        current = path.read_bytes() if path.exists() else None
        require(current in (decode(saved["before"][name]), decode(saved["after"][name])), "recovery would overwrite unrelated edits")
    for name in FILES:
        data = decode(saved["before"][name])
        if data is None:
            (root / name).unlink(missing_ok=True)
        else:
            atomic_write(root / name, data)
    journal.unlink()


def check(root):
    require(not paths(root)[0].exists(), "interrupted transition: recover first")
    book = validate_book(read_json(root / FILES[0]))
    for name, value in render(book).items():
        require(not (root / name).is_symlink() and (root / name).read_bytes() == value.encode(), f"stale or manually modified view: {name}")
    return book


def clean_context(root):
    branch = git(root, "symbolic-ref", "--short", "HEAD")
    require(branch != "main", "main mutation forbidden")
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=all"), "dirty implementation")
    require(not any(line[:1] == "S" or line[:1].islower() for line in git(root, "ls-files", "-v").splitlines()), "hidden index flags")
    return git(root, "rev-parse", "HEAD"), branch


def implementation_span(root, head, book):
    """Check every implementation edge, not just the last commit or final diff.

    Amendments may refine future work but cannot launder preceding scope
    violations into a new task baseline. The prior valid POP is the boundary.
    """
    require(bool(pending(book)), "work after terminal queue")
    task = pending(book)[0]
    if task["id"] == BOOTSTRAP_TASK:
        git(root, "merge-base", "--is-ancestor", MAIN_BASE, head)
        require(not git(root, "rev-list", "--merges", MAIN_BASE + ".." + head), "bootstrap history must be linear")
        for commit in git(root, "rev-list", MAIN_BASE + ".." + head).splitlines():
            changed = git(root, "diff-tree", "--no-commit-id", "--name-only", "-r", commit).splitlines()
            require(set(changed) <= set(BOOTSTRAP_SCOPE), "bootstrap out-of-scope history")
        return
    cursor = head
    for _ in range(2000):
        parents = git(root, "rev-list", "--parents", "-n", "1", cursor).split()[1:]
        require(len(parents) == 1, "unit history needs one parent")
        parent = parents[0]
        old = validate_book(json.loads(git(root, "show", f"{parent}:{FILES[0]}"), object_pairs_hook=unique))
        changed = git(root, "diff", "--name-only", parent, cursor).splitlines()
        if old == book:
            require(all(any(fnmatch.fnmatchcase(p, pattern) for pattern in task["scope"]) for p in changed), "out-of-scope unit history")
            require(not set(changed) & set(FILES), "manual ledger history")
        elif len(book["progress"]) == len(old["progress"]) + 1:
            record = book["progress"][0]
            expected = complete(old, record["review"], parent, record["review"]["branch"], record["completed_at"])
            require(book == expected and set(changed) == {FILES[0], FILES[2], FILES[3]}, "invalid unit starting POP")
            return
        else:
            require(book["decisions"] and book == amend(old, book["chapters"], book["decisions"][-1]["reason"]), "unrecorded unit history change")
            require(set(changed) <= set(FILES), "amendment hides implementation")
            book = old
        cursor = parent
    raise QueueError("unit history exceeds bound")


def guard(root, base):
    book = check(root)
    head, branch = clean_context(root)
    base = git(root, "rev-parse", "--verify", base + "^{commit}")
    git(root, "merge-base", "--is-ancestor", base, head)
    require(not git(root, "rev-list", "--merges", base + ".." + head), "unit history must be linear")
    changed = git(root, "diff", "--name-only", base, "HEAD").splitlines()
    present = subprocess.run(["git", "cat-file", "-e", f"{base}:{FILES[0]}"], cwd=root, capture_output=True)
    if present.returncode != 0:
        require(base == MAIN_BASE and branch == BOOTSTRAP_BRANCH, "bootstrap must start from exact main")
        require(book["revision"] == 1 and not book["progress"] and not book["decisions"] and pending(book)[0]["id"] == BOOTSTRAP_TASK, "invalid bootstrap state")
        require(set(changed) <= set(BOOTSTRAP_SCOPE), "bootstrap out-of-scope diff")
        require(not git(root, "diff", "--name-only", base, "HEAD", "--", "src"), "bootstrap changed product")
        implementation_span(root, head, book)
        return "bootstrap"
    old_text = git(root, "show", f"{base}:{FILES[0]}")
    old = validate_book(json.loads(old_text, object_pairs_hook=unique))
    if book == old:
        require(bool(pending(old)), "work after terminal queue")
        task = pending(old)[0]
        require(branch.startswith("agent/" + task["id"].lower() + "-") or (task["id"] == BOOTSTRAP_TASK and branch == BOOTSTRAP_BRANCH), "wrong implementation branch")
        require(all(any(fnmatch.fnmatchcase(p, pattern) for pattern in task["scope"]) for p in changed), "out-of-scope diff")
        require(not set(changed) & set(FILES), "manual ledger edit")
        implementation_span(root, head, book)
        return "implementation"
    if len(book["progress"]) == len(old["progress"]) + 1:
        record = book["progress"][0]
        expected = complete(old, record["review"], git(root, "rev-parse", base), git(root, "symbolic-ref", "--short", "HEAD"), record["completed_at"])
        require(book == expected and set(changed) == {FILES[0], FILES[2], FILES[3]}, "not an exact ledger transition")
        require(git(root, "rev-parse", "HEAD^") == git(root, "rev-parse", base), "ledger parent mismatch")
        implementation_span(root, base, old)
        return "finalized"
    require(book["decisions"], "unrecorded plan change")
    require(book == amend(old, book["chapters"], book["decisions"][-1]["reason"]), "invalid plan amendment")
    require(set(changed) <= set(FILES), "plan amendment contains implementation")
    implementation_span(root, base, old)
    return "plan-amendment"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sub.add_parser("status")
    sub.add_parser("bootstrap")
    sub.add_parser("recover")
    review = sub.add_parser("finalize")
    review.add_argument("--review", type=Path, required=True)
    revision = sub.add_parser("amend")
    revision.add_argument("--proposal", type=Path, required=True)
    revision.add_argument("--reason", required=True)
    transition = sub.add_parser("guard")
    transition.add_argument("--base", required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        require(Path(git(root, "rev-parse", "--show-toplevel")).resolve() == root, "root must be exact repository")
        if args.command == "guard":
            print("QUEUE_GUARD_OK " + guard(root, args.base))
            return 0
        if args.command in ("check", "status"):
            book = check(root)
            print(canonical({"total": len(tasks(book)), "completed": len(book["progress"]), "remaining": len(pending(book)), "front": pending(book)[0]["id"] if pending(book) else None, "contract_sha256": digest(pending(book)[0]) if pending(book) else None}).strip())
            return 0
        journal, lock = paths(root)
        with lock.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(git(root, "symbolic-ref", "--short", "HEAD") != "main", "main mutation forbidden")
            if args.command == "recover":
                recover(root)
            elif args.command == "bootstrap":
                require(git(root, "symbolic-ref", "--short", "HEAD") == BOOTSTRAP_BRANCH, "bootstrap branch")
                candidate = validate_book(read_json(root / FILES[0]))
                require(not candidate["progress"] and candidate["revision"] == 1 and not candidate["decisions"] and pending(candidate)[0]["id"] == BOOTSTRAP_TASK, "bootstrap already finalized")
                present = subprocess.run(["git", "cat-file", "-e", f"HEAD:{FILES[0]}"], cwd=root, capture_output=True)
                if present.returncode == 0:
                    # Refresh only our unfinalized, single-child draft candidate
                    # after a review finding; the primary amends that draft.
                    require(git(root, "rev-parse", "HEAD^") == MAIN_BASE, "bootstrap already committed")
                    old = validate_book(json.loads(git(root, "show", f"HEAD:{FILES[0]}"), object_pairs_hook=unique))
                    require(not old["progress"] and pending(old)[0] == pending(candidate)[0], "bootstrap front changed")
                else:
                    require(git(root, "rev-parse", "HEAD") == MAIN_BASE, "bootstrap requires exact main")
                publish(root, candidate)
            else:
                book = check(root)
                head, branch = clean_context(root)
                implementation_span(root, head, book)
                if args.command == "amend":
                    updated = amend(book, read_json(args.proposal), args.reason)
                else:
                    require(root not in args.review.resolve().parents, "review must be outside repository")
                    receipt = read_json(args.review, 65536)
                    require(args.review.read_text(encoding="utf-8") == canonical(receipt), "review must be canonical JSON")
                    updated = complete(book, receipt, head, branch, datetime.now(timezone.utc).isoformat())
                    for evidence in receipt["checks"]:
                        path = Path(evidence["evidence"])
                        require(path.is_absolute() and path.is_file() and not path.is_symlink() and path.stat().st_size <= 10 * 1024 * 1024, "missing/unsafe evidence")
                        require(hashlib.sha256(path.read_bytes()).hexdigest() == evidence["sha256"], "evidence changed")
                require(clean_context(root) == (head, branch), "source changed during preparation")
                publish(root, updated)
            print("QUEUE_PREPARED: commit only the declared managed changes, then run guard against the parent; no publication claim")
            return 0
    except (QueueError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"QUEUE_FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
