"""Synchronize the verified-main progress ledger and generated TODO queue.

Completion authority is deliberately narrow: only commits reachable from the
selected protected-main ref are rendered as MERGED and may close fixed PLAN
work items. Phase branches remain in-flight facts and can never promote
themselves by editing generated documentation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
PROGRESS_REL = Path("docs/PROGRESS.md")
TODO_REL = Path("docs/TODO.md")
PLAN_REL = Path("docs/PLAN.md")
ANCHOR_RE = re.compile(r"<!-- cs:progress-anchor: ([0-9a-f]{40}) -->")
CURSOR_RE = re.compile(r"<!-- cs:progress-cursor: ([0-9a-f]{40}) -->")
TASK_LEDGER_RE = re.compile(r"<!-- cs:task-ledger-v2: ([0-9a-f]{40}) -->")
WORK_ITEMS_RE = re.compile(
    r"<!-- cs:work-items-begin -->\n```json\n(.*?)\n```\n"
    r"<!-- cs:work-items-end -->",
    re.DOTALL,
)
TASK_ID_RE = re.compile(r"CS-P(08|09|10|11|12)-([0-9]{2})")
TASK_TRAILER_PREFIX = "Closes-CodeSkeptic-Task:"
TASK_TRAILER_RE = re.compile(
    r"^Closes-CodeSkeptic-Task:[ \t]*(CS-P(?:08|09|10|11|12)-[0-9]{2})[ \t]*$"
)
RAW_TRAILER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*:[ \t]*.*$")
PRODUCTION_PROGRAM = "CodeSkeptic measurable v1.0 completion"
LEGACY_PROGRESS_ANCHOR = "47b03f4076f246c38a81fbc834693bed0f98ccc4"
MIGRATION_MAIN_OID = "7dfd37596414c9512316093ff4fb6b039673f55f"
LEGACY_PROGRESS_SHA256 = (
    "ad383b5215239a8324b155328f694bbba8b3f7e8a9dd90e5127b9238d7fec952"
)
MIGRATION_PLAN_SHA256 = (
    "af9f5d194103040f9396abb70a5ad38154723eab171f5db9ff3d0ba8fcabb78a"
)
MIGRATION_CATALOG_SHA256 = (
    "e99426c1790aee68ec838c851f8bc49219114f1f9e4c6abd36daa599b2357f8c"
)
MIGRATION_TASK_IDS = (
    "CS-P08-03",
    "CS-P08-04",
    "CS-P09-01",
    "CS-P10-01",
    "CS-P10-02",
    "CS-P10-03",
    "CS-P10-04",
    "CS-P10-05",
    "CS-P10-06",
    "CS-P10-07",
    "CS-P10-08",
    "CS-P10-09",
    "CS-P11-01",
    "CS-P11-02",
    "CS-P11-03",
    "CS-P11-04",
    "CS-P11-05",
    "CS-P11-06",
    "CS-P12-01",
    "CS-P12-02",
    "CS-P12-03",
    "CS-P12-04",
    "CS-P12-05",
    "CS-P12-06",
    "CS-P12-07",
    "CS-P12-08",
)


class ProgressStatusError(RuntimeError):
    """A status fact is unavailable, malformed, or inconsistent."""


@dataclass(frozen=True)
class CommitReceipt:
    oid: str
    tree: str
    committed_on: str
    subject: str
    body: str


@dataclass(frozen=True)
class WorkItem:
    id: str
    phase: int
    title: str
    boundary: str
    gates: tuple[str, ...]
    depends_on: tuple[str, ...]


@dataclass(frozen=True)
class WorkCatalog:
    program: str
    items: tuple[WorkItem, ...]


@dataclass(frozen=True)
class DerivedStatus:
    progress: str
    todo: str
    verified_main: str
    in_flight: tuple[str, ...]
    appended: int
    completed_work: tuple[str, ...]


def _run_git(
    root: Path,
    args: Sequence[str],
    *,
    allow_one: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    allowed = {0, 1} if allow_one else {0}
    if completed.returncode not in allowed:
        reason = completed.stderr.strip() or completed.stdout.strip()
        raise ProgressStatusError(
            f"git {' '.join(args)} failed ({completed.returncode}): {reason}"
        )
    return completed


def _resolve_commit(root: Path, ref: str) -> str:
    result = _run_git(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    oid = result.stdout.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", oid):
        raise ProgressStatusError(f"{ref!r} did not resolve to a full commit id")
    return oid


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    completed = _run_git(
        root,
        ["merge-base", "--is-ancestor", ancestor, descendant],
        allow_one=True,
    )
    return completed.returncode == 0


def _commit_receipt(root: Path, oid: str) -> CommitReceipt:
    completed = subprocess.run(
        ["git", "show", "-s", "--format=%H%x00%T%x00%cs%x00%s", oid],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        reason = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        ).strip()
        raise ProgressStatusError(
            f"git show metadata failed ({completed.returncode}): {reason}"
        )
    fields = completed.stdout.rstrip(b"\n").split(b"\x00", 3)
    if len(fields) != 4:
        raise ProgressStatusError(f"cannot decode commit metadata for {oid}")
    full_oid, tree, committed_on, subject = (
        field.decode("utf-8", errors="replace") for field in fields
    )
    raw_commit = subprocess.run(
        ["git", "cat-file", "commit", oid],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if raw_commit.returncode != 0:
        reason = (raw_commit.stderr or raw_commit.stdout).decode(
            "utf-8", errors="replace"
        ).strip()
        raise ProgressStatusError(
            f"git cat-file commit failed ({raw_commit.returncode}): {reason}"
        )
    raw_parts = raw_commit.stdout.split(b"\n\n", 1)
    if len(raw_parts) != 2:
        raise ProgressStatusError(f"cannot decode raw commit message for {oid}")
    body = raw_parts[1].decode("utf-8", errors="replace")
    if not re.fullmatch(r"[0-9a-f]{40}", full_oid.lower()):
        raise ProgressStatusError(f"malformed commit id returned for {oid}")
    if not re.fullmatch(r"[0-9a-f]{40}", tree.lower()):
        raise ProgressStatusError(f"malformed tree id returned for {oid}")
    subject = " ".join(subject.split())
    if not subject:
        raise ProgressStatusError(f"commit {oid} has an empty subject")
    return CommitReceipt(
        oid=full_oid.lower(),
        tree=tree.lower(),
        committed_on=committed_on,
        subject=subject,
        body=body,
    )


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProgressStatusError(f"PLAN work item {field} must be nonempty text")
    return " ".join(value.split())


def _decode_utf8_exact(content: bytes, label: str) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProgressStatusError(f"{label} is not valid UTF-8: {error}") from error


def _string_list(value: object, field: str, *, nonempty: bool) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ProgressStatusError(f"PLAN work item {field} must be a list")
    result = tuple(_nonempty_string(entry, field) for entry in value)
    if nonempty and not result:
        raise ProgressStatusError(f"PLAN work item {field} must not be empty")
    if len(set(result)) != len(result):
        raise ProgressStatusError(f"PLAN work item {field} contains duplicates")
    return result


def _load_catalog(root: Path) -> WorkCatalog:
    path = root / PLAN_REL
    if not path.is_file():
        raise ProgressStatusError(f"missing {PLAN_REL.as_posix()}")
    plan = _decode_utf8_exact(path.read_bytes(), PLAN_REL.as_posix())
    matches = WORK_ITEMS_RE.findall(plan)
    if len(matches) != 1:
        raise ProgressStatusError(
            "docs/PLAN.md must contain exactly one fixed work-item catalog"
        )
    try:
        raw = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise ProgressStatusError(f"invalid PLAN work-item JSON: {error}") from error
    if not isinstance(raw, dict) or set(raw) != {"schema", "program", "items"}:
        raise ProgressStatusError("PLAN work-item catalog has unexpected fields")
    if raw["schema"] != 1:
        raise ProgressStatusError("unsupported PLAN work-item schema")
    program = _nonempty_string(raw["program"], "program")
    raw_items = raw["items"]
    if not isinstance(raw_items, list) or not raw_items:
        raise ProgressStatusError("PLAN work-item catalog must contain items")

    required = {"id", "phase", "title", "boundary", "gates", "depends_on"}
    items: list[WorkItem] = []
    known: set[str] = set()
    previous_key: tuple[int, int] | None = None
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != required:
            raise ProgressStatusError("PLAN work item has unexpected fields")
        item_id = _nonempty_string(raw_item["id"], "id")
        match = TASK_ID_RE.fullmatch(item_id)
        if match is None:
            raise ProgressStatusError(f"invalid PLAN work-item id: {item_id}")
        phase = raw_item["phase"]
        if not isinstance(phase, int) or phase != int(match.group(1)):
            raise ProgressStatusError(f"PLAN phase disagrees with id {item_id}")
        item_key = (phase, int(match.group(2)))
        if previous_key is not None and item_key <= previous_key:
            raise ProgressStatusError("PLAN work items must use increasing ids")
        if item_id in known:
            raise ProgressStatusError(f"duplicate PLAN work-item id: {item_id}")
        dependencies = _string_list(
            raw_item["depends_on"], "depends_on", nonempty=False
        )
        unknown = [dependency for dependency in dependencies if dependency not in known]
        if unknown:
            raise ProgressStatusError(
                f"PLAN work item {item_id} has unknown or forward dependency: "
                + ", ".join(unknown)
            )
        items.append(
            WorkItem(
                id=item_id,
                phase=phase,
                title=_nonempty_string(raw_item["title"], "title"),
                boundary=_nonempty_string(raw_item["boundary"], "boundary"),
                gates=_string_list(raw_item["gates"], "gates", nonempty=True),
                depends_on=dependencies,
            )
        )
        known.add(item_id)
        previous_key = item_key
    return WorkCatalog(program=program, items=tuple(items))


def _catalog_payload(plan: str) -> str:
    matches = WORK_ITEMS_RE.findall(plan)
    if len(matches) != 1:
        raise ProgressStatusError(
            "docs/PLAN.md must contain exactly one fixed work-item catalog"
        )
    return matches[0]


def _enforce_fixed_plan(root: Path, base_ref: str) -> None:
    current_plan_bytes = (root / PLAN_REL).read_bytes()
    current_plan = _decode_utf8_exact(
        current_plan_bytes, PLAN_REL.as_posix()
    )
    current_payload = _catalog_payload(current_plan)
    completed = subprocess.run(
        ["git", "show", f"{base_ref}:{PLAN_REL.as_posix()}"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode == 0:
        _decode_utf8_exact(completed.stdout, f"{base_ref}:{PLAN_REL.as_posix()}")
    protected_has_catalog = (
        b"<!-- cs:work-items-begin -->" in completed.stdout
        or b"<!-- cs:work-items-end -->" in completed.stdout
    )
    if completed.returncode != 0 or not protected_has_catalog:
        # One-time migration from the last protected-main state without a
        # catalog. Pin both the authority commit and the exact catalog bytes;
        # otherwise a first migration branch could silently omit old work.
        base_oid = _resolve_commit(root, base_ref)
        catalog = _load_catalog(root)
        plan_digest = sha256(current_plan_bytes).hexdigest()
        digest = sha256(current_payload.encode("utf-8")).hexdigest()
        if base_oid != MIGRATION_MAIN_OID:
            raise ProgressStatusError(
                "catalog migration is allowed only from the pinned protected-main "
                f"commit {MIGRATION_MAIN_OID}"
            )
        if plan_digest != MIGRATION_PLAN_SHA256:
            raise ProgressStatusError(
                "PLAN migration differs from the pinned complete legacy plan"
            )
        if digest != MIGRATION_CATALOG_SHA256:
            raise ProgressStatusError(
                "PLAN migration catalog differs from the pinned complete catalog"
            )
        if tuple(item.id for item in catalog.items) != MIGRATION_TASK_IDS:
            raise ProgressStatusError(
                "PLAN migration catalog does not preserve every pinned task id"
            )
        return
    if current_plan_bytes != completed.stdout:
        raise ProgressStatusError(
            "docs/PLAN.md work program is fixed and differs from protected main"
        )


def _commit_range(root: Path, anchor: str, tip: str) -> list[str]:
    if not _is_ancestor(root, anchor, tip):
        raise ProgressStatusError(
            f"progress anchor {anchor} is not an ancestor of protected main {tip}"
        )
    completed = _run_git(
        root, ["rev-list", "--first-parent", "--reverse", tip]
    )
    chain = [
        line.strip().lower()
        for line in completed.stdout.splitlines()
        if line.strip()
    ]
    if anchor not in chain:
        raise ProgressStatusError(
            f"progress anchor {anchor} is not on protected main's first-parent chain"
        )
    return chain[chain.index(anchor) :]


def _progress_header(anchor: str) -> str:
    return (
        "# CodeSkeptic — Verified Progress\n\n"
        "> Generated by `python scripts/progress_status.py sync`. Do not edit\n"
        "> entries by hand. The ledger is append-only and records only commits\n"
        "> reachable from protected main; detailed rationale remains in\n"
        "> `docs/devlog/changelog.md`. History before the bootstrap anchor remains\n"
        "> in that changelog.\n\n"
        f"<!-- cs:progress-anchor: {anchor} -->\n"
    )


def _raw_final_trailer_lines(receipt: CommitReceipt) -> tuple[str, ...]:
    """Return an exact, host-config-independent final trailer paragraph.

    Only an unindented ``Token: value`` paragraph separated from the message
    body by a blank line is authority. We intentionally do not canonicalize
    aliases through ``git interpret-trailers``: repository/global Git config
    must not manufacture the exact CodeSkeptic key from different raw bytes.
    """
    # ``str.splitlines()`` treats Unicode separators (NEL, U+2028, U+2029,
    # vertical tab, form feed) as physical lines even though Git does not.
    # Split only at LF and normalize only an immediately preceding CR.
    raw_lines = receipt.body.split("\n")
    lines = [
        line[:-1]
        if index < len(raw_lines) - 1 and line.endswith("\r")
        else line
        for index, line in enumerate(raw_lines)
    ]
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return ()
    block_start = len(lines) - 1
    while block_start >= 0 and lines[block_start] != "":
        block_start -= 1
    if block_start < 0:
        return ()
    block = lines[block_start + 1 :]
    if not block or any(RAW_TRAILER_RE.fullmatch(line) is None for line in block):
        return ()
    return tuple(block)


def _task_closures(
    root: Path,
    receipts: Sequence[CommitReceipt],
    catalog: WorkCatalog,
) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...]]:
    by_id = {item.id: item for item in catalog.items}
    order = {item.id: index for index, item in enumerate(catalog.items)}
    completed: list[str] = []
    completed_set: set[str] = set()
    per_commit: dict[str, tuple[str, ...]] = {}
    for receipt in receipts:
        declared: list[str] = []
        for line in _raw_final_trailer_lines(receipt):
            if not line.startswith(TASK_TRAILER_PREFIX):
                continue
            match = TASK_TRAILER_RE.fullmatch(line)
            if match is None:
                raise ProgressStatusError(
                    f"malformed task trailer in protected-main commit {receipt.oid}"
                )
            declared.append(match.group(1))
        if len(set(declared)) != len(declared):
            raise ProgressStatusError(
                f"duplicate task trailer in protected-main commit {receipt.oid}"
            )
        unknown = [item_id for item_id in declared if item_id not in by_id]
        if unknown:
            raise ProgressStatusError(
                f"unknown task in protected-main commit {receipt.oid}: "
                + ", ".join(unknown)
            )
        ordered = tuple(sorted(declared, key=order.__getitem__))
        closing_now: set[str] = set()
        for item_id in ordered:
            if item_id in completed_set:
                raise ProgressStatusError(
                    f"task {item_id} is closed by more than one protected-main commit"
                )
            missing = [
                dependency
                for dependency in by_id[item_id].depends_on
                if dependency not in completed_set and dependency not in closing_now
            ]
            if missing:
                raise ProgressStatusError(
                    f"task {item_id} closes before dependencies: "
                    + ", ".join(missing)
                )
            closing_now.add(item_id)
            completed.append(item_id)
        completed_set.update(closing_now)
        if ordered:
            per_commit[receipt.oid] = ordered
    return per_commit, tuple(completed)


def _render_receipt(
    receipt: CommitReceipt,
    closed_here: tuple[str, ...] = (),
) -> str:
    chunks = [
        f"\n## {receipt.committed_on} — {receipt.subject} — MERGED\n\n"
        "+ Protected main contains this transition; no phase branch or prose\n"
        "  record is treated as completion authority.\n"
        f"Evidence: commit `{receipt.oid}`; tree `{receipt.tree}`.\n"
    ]
    if closed_here:
        rendered = ", ".join(f"`{item_id}`" for item_id in closed_here)
        chunks.append(f"Completed tasks: {rendered}.\n")
    chunks.append(f"\n<!-- cs:progress-cursor: {receipt.oid} -->\n")
    return "".join(chunks)


def _render_progress(
    root: Path,
    anchor: str,
    task_anchor: str,
    tip: str,
    catalog: WorkCatalog,
) -> tuple[str, tuple[str, ...]]:
    # Preserve the legacy receipt ledger byte-for-byte through task_anchor.
    # v2 then records only commits which close PLAN tasks. Ordinary
    # reconciliation commits deliberately have no receipt, making the final
    # TODO-empty reconciliation finite instead of creating an endless
    # self-recording chain.
    legacy_receipts = [
        _commit_receipt(root, oid)
        for oid in _commit_range(root, anchor, task_anchor)
    ]
    task_receipts = [
        _commit_receipt(root, oid)
        for oid in _commit_range(root, task_anchor, tip)[1:]
    ]
    closures, completed = _task_closures(root, task_receipts, catalog)
    chunks = [_progress_header(anchor)]
    chunks.extend(_render_receipt(receipt) for receipt in legacy_receipts)
    chunks.append(
        f"\n<!-- cs:task-ledger-v2: {task_anchor} -->\n\n"
        "> Task-ledger v2 records only protected-main commits with exact PLAN\n"
        "> closure trailers. Ordinary reconciliation commits are intentionally\n"
        "> omitted so the final generated TODO/PROGRESS state is finite.\n"
    )
    for receipt in task_receipts:
        closed_here = closures.get(receipt.oid, ())
        if closed_here:
            chunks.append(_render_receipt(receipt, closed_here))
    return "".join(chunks), completed


def _existing_progress_state(progress: str) -> tuple[str, str]:
    matches = ANCHOR_RE.findall(progress)
    if len(matches) != 1:
        raise ProgressStatusError(
            "docs/PROGRESS.md must contain exactly one progress anchor"
        )
    cursors = CURSOR_RE.findall(progress)
    if not cursors:
        raise ProgressStatusError("docs/PROGRESS.md has no progress cursor")
    task_anchors = TASK_LEDGER_RE.findall(progress)
    if len(task_anchors) > 1:
        raise ProgressStatusError(
            "docs/PROGRESS.md has more than one task-ledger v2 anchor"
        )
    task_anchor = task_anchors[0] if task_anchors else cursors[-1]
    if task_anchor not in cursors:
        raise ProgressStatusError(
            "docs/PROGRESS.md task-ledger v2 anchor is not a receipt cursor"
        )
    if task_anchors and progress.index(TASK_LEDGER_RE.search(progress).group(0)) < progress.index(
        f"<!-- cs:progress-cursor: {task_anchor} -->"
    ):
        raise ProgressStatusError(
            "docs/PROGRESS.md task-ledger v2 anchor precedes its receipt"
        )
    return matches[0], task_anchor


def _enforce_production_ledger_prefix(
    catalog: WorkCatalog,
    progress: bytes,
    anchor: str,
    task_anchor: str,
) -> None:
    if catalog.program != PRODUCTION_PROGRAM:
        return
    marker = (
        f"\n<!-- cs:task-ledger-v2: {MIGRATION_MAIN_OID} -->"
    ).encode("ascii")
    if anchor != LEGACY_PROGRESS_ANCHOR or task_anchor != MIGRATION_MAIN_OID:
        raise ProgressStatusError(
            "production PROGRESS anchors differ from the pinned legacy ledger"
        )
    if progress.count(marker) != 1:
        raise ProgressStatusError(
            "production PROGRESS is missing its unique pinned task-ledger marker"
        )
    legacy = progress.split(marker, 1)[0]
    digest = sha256(legacy).hexdigest()
    if digest != LEGACY_PROGRESS_SHA256:
        raise ProgressStatusError(
            "production PROGRESS legacy prefix differs from the pinned ledger"
        )


def _enforce_protected_progress_prefix(
    root: Path,
    base_ref: str,
    progress: bytes,
) -> None:
    completed = subprocess.run(
        ["git", "show", f"{base_ref}:{PROGRESS_REL.as_posix()}"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        reason = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        ).strip()
        raise ProgressStatusError(
            "cannot read the protected-main PROGRESS prefix: " + reason
        )
    if not progress.startswith(completed.stdout):
        raise ProgressStatusError(
            "docs/PROGRESS.md truncates or rewrites the protected-main ledger"
        )


def _current_branch(root: Path) -> str:
    local = _run_git(root, ["branch", "--show-current"]).stdout.strip()
    if local:
        return local
    for name in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    raise ProgressStatusError("cannot resolve the current branch name")


def _in_flight_branches(root: Path, main_oid: str) -> tuple[str, ...]:
    # Status generation is intentionally offline. CI fetches full history
    # before this command, while local runs use only already-present tracking
    # refs. A documentation refresh must never contact a remote or trigger an
    # access prompt merely to enumerate phase branches.
    completed = _run_git(
        root,
        [
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "refs/remotes/origin/phase-*",
        ],
    )
    branches: set[str] = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        if (
            len(parts) != 2
            or not parts[1].startswith("refs/remotes/origin/phase-")
        ):
            raise ProgressStatusError(
                f"malformed local phase tracking ref: {line!r}"
            )
        oid, ref = parts
        oid = oid.lower()
        if not re.fullmatch(r"[0-9a-f]{40}", oid):
            raise ProgressStatusError(
                f"malformed local phase tracking commit: {line!r}"
            )
        if not _is_ancestor(root, oid, main_oid):
            branches.add(ref.removeprefix("refs/remotes/origin/"))
    current = _current_branch(root)
    if current.startswith("phase-"):
        branches.add(current)
    return tuple(sorted(branches))


def _render_state_block(
    root: Path,
    main_oid: str,
    progress: str,
    in_flight: tuple[str, ...],
) -> str:
    merge_base = _run_git(root, ["merge-base", main_oid, "HEAD"]).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", merge_base.lower()):
        raise ProgressStatusError("cannot resolve the branch/main merge base")
    branch_text = " ".join(in_flight) if in_flight else "none"
    digest = sha256(progress.encode("utf-8")).hexdigest()
    return (
        "<!-- cs:state-begin -->\n"
        "```\n"
        f"base          = {merge_base[:7]}\n"
        f"in_flight     = {branch_text}\n"
        f"verified_main = {main_oid[:7]}\n"
        f"progress      = sha256:{digest}\n"
        "```\n"
        "<!-- cs:state-end -->"
    )


def _render_todo(
    catalog: WorkCatalog,
    completed: tuple[str, ...],
    state_block: str,
) -> str:
    completed_set = set(completed)
    open_items = [item for item in catalog.items if item.id not in completed_set]
    chunks = [
        "# CodeSkeptic — TODO (generated open work)\n\n",
        "> Generated from the fixed work-item catalog in `docs/PLAN.md` and\n",
        "> protected-main completion trailers by `progress_status.py`. Do not\n",
        "> edit this file by hand. A phase branch cannot close a work item.\n\n",
        "## Repository state\n\n",
        state_block,
        "\n\n## Open work\n",
    ]
    if not open_items:
        chunks.append("\nNo open work items.\n")
        return "".join(chunks)
    for item in open_items:
        dependencies = (
            ", ".join(f"`{dependency}`" for dependency in item.depends_on)
            if item.depends_on
            else "none"
        )
        chunks.extend(
            [
                f"\n### {item.id} — Phase {item.phase}: {item.title}\n\n",
                f"Boundary: {item.boundary}\n\n",
                f"Dependencies: {dependencies}.\n\n",
                "Acceptance gates:\n",
            ]
        )
        chunks.extend(f"- {gate}\n" for gate in item.gates)
    return "".join(chunks)


def derive_status(root: Path, base_ref: str) -> DerivedStatus:
    main_oid = _resolve_commit(root, base_ref)
    catalog = _load_catalog(root)
    _enforce_fixed_plan(root, base_ref)
    progress_path = root / PROGRESS_REL
    if not progress_path.is_file():
        raise ProgressStatusError(
            f"missing {PROGRESS_REL.as_posix()}; normal sync cannot bootstrap "
            "or replace an append-only ledger"
        )
    old_progress_bytes = progress_path.read_bytes()
    old_progress = _decode_utf8_exact(
        old_progress_bytes, PROGRESS_REL.as_posix()
    )
    anchor, task_anchor = _existing_progress_state(old_progress)
    _enforce_protected_progress_prefix(root, base_ref, old_progress_bytes)
    _enforce_production_ledger_prefix(
        catalog, old_progress_bytes, anchor, task_anchor
    )

    progress, completed_work = _render_progress(
        root, anchor, task_anchor, main_oid, catalog
    )
    if not progress.startswith(old_progress):
        # Re-rendering through the old cursor must reproduce every existing
        # byte. A mismatch is either history rewriting or manual ledger edits.
        raise ProgressStatusError(
            "docs/PROGRESS.md is not an append-only rendering of protected main"
        )
    old_cursors = CURSOR_RE.findall(old_progress)
    new_cursors = CURSOR_RE.findall(progress)
    appended = len(new_cursors) - len(old_cursors)
    in_flight = _in_flight_branches(root, main_oid)
    state_block = _render_state_block(root, main_oid, progress, in_flight)
    expected_todo = _render_todo(catalog, completed_work, state_block)
    return DerivedStatus(
        progress=progress,
        todo=expected_todo,
        verified_main=main_oid,
        in_flight=in_flight,
        appended=appended,
        completed_work=completed_work,
    )


def _write_atomic(path: Path, content: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    os.replace(temporary, path)


def sync_repository(root: Path, base_ref: str) -> DerivedStatus:
    branch = _current_branch(root)
    if not branch.startswith("phase-"):
        raise ProgressStatusError(
            "generated status may be synchronized only on a phase-* branch, "
            f"not {branch!r}"
        )
    status = derive_status(root, base_ref)
    _write_atomic(root / PROGRESS_REL, status.progress)
    _write_atomic(root / TODO_REL, status.todo)
    return status


def check_repository(root: Path, base_ref: str) -> DerivedStatus:
    status = derive_status(root, base_ref)
    progress = (root / PROGRESS_REL).read_bytes()
    todo = (root / TODO_REL).read_bytes()
    if progress != status.progress.encode("utf-8"):
        raise ProgressStatusError(
            "docs/PROGRESS.md is stale; run progress_status.py sync"
        )
    if todo != status.todo.encode("utf-8"):
        raise ProgressStatusError(
            "docs/TODO.md generated queue is stale; run progress_status.py sync"
        )
    return status


def bootstrap_repository(root: Path, base_ref: str) -> DerivedStatus:
    """Create a first ledger only for a genuinely new one-commit repository.

    This is intentionally separate from normal synchronization. In a mature
    repository, deleting PROGRESS must be unrecoverable through the generator
    unless the retained ledger is restored from version control.
    """
    branch = _current_branch(root)
    if not branch.startswith("phase-"):
        raise ProgressStatusError(
            "generated status may be bootstrapped only on a phase-* branch, "
            f"not {branch!r}"
        )
    progress_path = root / PROGRESS_REL
    if progress_path.exists():
        raise ProgressStatusError(f"{PROGRESS_REL.as_posix()} already exists")
    main_oid = _resolve_commit(root, base_ref)
    reachable = {
        line.strip().lower()
        for line in _run_git(root, ["rev-list", "--all"]).stdout.splitlines()
        if line.strip()
    }
    if reachable != {main_oid}:
        raise ProgressStatusError(
            "ledger bootstrap requires the selected root to be the only "
            "commit reachable from any repository ref"
        )
    parent_line = _run_git(
        root, ["rev-list", "--parents", "-n", "1", main_oid]
    ).stdout.split()
    if parent_line != [main_oid]:
        raise ProgressStatusError(
            "ledger bootstrap is allowed only at a repository root commit"
        )
    catalog = _load_catalog(root)
    if catalog.program == PRODUCTION_PROGRAM:
        raise ProgressStatusError(
            "the production ledger is already migrated and can never be "
            "bootstrapped by this command"
        )
    _enforce_fixed_plan(root, base_ref)
    progress, completed_work = _render_progress(
        root, main_oid, main_oid, main_oid, catalog
    )
    in_flight = _in_flight_branches(root, main_oid)
    state_block = _render_state_block(root, main_oid, progress, in_flight)
    status = DerivedStatus(
        progress=progress,
        todo=_render_todo(catalog, completed_work, state_block),
        verified_main=main_oid,
        in_flight=in_flight,
        appended=len(CURSOR_RE.findall(progress)),
        completed_work=completed_work,
    )
    _write_atomic(progress_path, status.progress)
    _write_atomic(root / TODO_REL, status.todo)
    return status


def validate_ci_ref(ref: str, *, pull_request: bool = False) -> None:
    if ref.startswith("phase-") or (ref == "main" and not pull_request):
        return
    context = "PR head" if pull_request else "work ref"
    raise ProgressStatusError(
        f"{context} {ref!r} is invalid; development and PR heads must use phase-*"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Synchronize protected-main progress and the PLAN-derived TODO."
    )
    parser.add_argument(
        "command", choices=("sync", "check", "bootstrap", "validate-ref")
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--base-ref", default="origin/main")
    parser.add_argument("--ref", default="")
    parser.add_argument("--pull-request", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    root = arguments.root.resolve()
    try:
        if arguments.command == "validate-ref":
            if not arguments.ref:
                raise ProgressStatusError("validate-ref requires --ref")
            validate_ci_ref(
                arguments.ref, pull_request=arguments.pull_request
            )
            print(f"work ref accepted: {arguments.ref}")
            return 0
        if arguments.command == "sync":
            status = sync_repository(root, arguments.base_ref)
        elif arguments.command == "bootstrap":
            status = bootstrap_repository(root, arguments.base_ref)
        else:
            status = check_repository(root, arguments.base_ref)
        branches = " ".join(status.in_flight) if status.in_flight else "none"
        print(
            "progress synchronized: "
            f"verified_main={status.verified_main[:7]} "
            f"appended={status.appended} in_flight={branches}"
        )
    except (OSError, ProgressStatusError) as error:
        print(f"progress status error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
