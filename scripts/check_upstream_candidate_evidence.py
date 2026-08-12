#!/usr/bin/env python3
"""Cross-check retained candidate receipts against frozen records and docs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DISPLAY_NAMES = {"tensorflow-lite": "TensorFlow Lite"}
RUNNER_PATH = Path(__file__).with_name("run_realworld_campaign.py")
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "retained_evidence_campaign_runner", RUNNER_PATH
)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError("cannot load campaign referee")
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot load {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: root must be an object")
    return value


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc
    return digest.hexdigest()


def evidence_path(root: Path, value: Any) -> Path:
    require(isinstance(value, str) and value, "evidence path must be non-empty")
    path = (root / value).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise EvidenceError("evidence path must stay inside the repository") from exc
    return path


def selected_batch(heads: dict[str, Any], batch_id: str) -> dict[str, Any]:
    batches = heads.get("batches")
    require(isinstance(batches, list), "candidate batches must be an array")
    matches = [item for item in batches if item.get("id") == batch_id]
    require(len(matches) == 1, f"candidate batch {batch_id!r} must exist once")
    return matches[0]


def project_from_manifest(manifest: dict[str, Any], project_id: str) -> dict[str, Any]:
    projects = manifest.get("projects")
    require(isinstance(projects, list), "retained manifest projects must be an array")
    matches = [item for item in projects if item.get("id") == project_id]
    require(len(matches) == 1, f"{project_id}: retained manifest entry must exist once")
    return matches[0]


def validate_document_summary(
    project_id: str,
    snapshot: dict[str, Any],
    repetitions: int,
    todo_text: str,
    changelog_text: str,
) -> None:
    display = DISPLAY_NAMES.get(project_id, project_id)
    coverage_token = (
        f"{snapshot.get('attempted_tus', snapshot['translation_units'])}/"
        f"{snapshot.get('analyzed_tus', snapshot['translation_units'])}"
    )
    shared_tokens = (
        coverage_token,
        "0 broken",
        "0 incomplete",
        f"{snapshot['findings']} stable findings",
    )
    for label, text, repetition_token in (
        ("TODO", todo_text, f"completed {repetitions} fresh accepted repetitions"),
        (
            "changelog",
            changelog_text,
            f"with {repetitions}/{repetitions} accepted repetitions",
        ),
    ):
        matches = [
            line
            for line in text.splitlines()
            if display in line and "current" in line and "accepted repetitions" in line
        ]
        require(
            len(matches) == 1,
            f"{project_id}: {label} must contain one current qualification summary",
        )
        require(
            repetition_token in matches[0]
            and all(token in matches[0] for token in shared_tokens)
            and re.search(rf"(?<!\d){re.escape(coverage_token)}(?!\d)", matches[0]) is not None,
            f"{project_id}: {label} summary differs from retained evidence",
        )


def validate_project(
    root: Path,
    snapshot: dict[str, Any],
    todo_text: str,
    changelog_text: str,
) -> None:
    project_id = snapshot.get("id")
    require(isinstance(project_id, str) and project_id, "candidate id is required")
    evidence = snapshot.get("receipt_evidence")
    require(isinstance(evidence, dict), f"{project_id}: receipt evidence is required")

    try:
        manifest = RUNNER.validate_manifest(
            load_json(evidence_path(root, evidence.get("manifest")))
        )
    except RUNNER.CampaignError as exc:
        raise EvidenceError(f"{project_id}: retained manifest is invalid: {exc}") from exc
    manifest_project = project_from_manifest(manifest, project_id)
    expected = manifest_project.get("expected")
    require(isinstance(expected, dict), f"{project_id}: retained expectations are missing")
    require(
        manifest_project.get("revision") == snapshot.get("head"),
        f"{project_id}: frozen revision differs from retained manifest",
    )
    for key in ("translation_units", "translation_unit_sha256", "findings", "fingerprint_sha256"):
        require(
            expected.get(key) == snapshot.get(key),
            f"{project_id}: frozen {key} differs from retained manifest",
        )
    for key in ("attempted_tus", "analyzed_tus"):
        require(
            expected.get(key) == snapshot.get(key, snapshot.get("translation_units")),
            f"{project_id}: retained {key} differs from frozen coverage",
        )
    for key in ("broken_tus", "incomplete_functions"):
        require(expected.get(key) == 0, f"{project_id}: retained {key} must be zero")

    receipt_entries = evidence.get("receipts")
    require(
        isinstance(receipt_entries, list) and len(receipt_entries) == 3,
        f"{project_id}: exactly three retained receipts are required",
    )
    receipts = []
    for repetition, entry in enumerate(receipt_entries, start=1):
        require(isinstance(entry, dict), f"{project_id}: receipt entry must be an object")
        receipt_path = evidence_path(root, entry.get("path"))
        expected_sha256 = entry.get("sha256")
        require(
            isinstance(expected_sha256, str) and SHA256_RE.fullmatch(expected_sha256),
            f"{project_id}: receipt checksum must be lowercase SHA-256",
        )
        require(
            file_digest(receipt_path) == expected_sha256,
            f"{project_id}: retained receipt {repetition} checksum differs",
        )
        receipt = load_json(receipt_path)
        receipts.append(receipt)

    campaign = evidence.get("campaign")
    require(isinstance(campaign, str) and campaign, f"{project_id}: campaign is required")
    try:
        RUNNER.validate_receipt_group(manifest, campaign, project_id, receipts)
    except RUNNER.CampaignError as exc:
        raise EvidenceError(f"{project_id}: retained receipts are invalid: {exc}") from exc
    repetitions = manifest["campaigns"][campaign]["repetitions"]
    validate_document_summary(
        project_id, snapshot, repetitions, todo_text, changelog_text
    )


def validate(
    root: Path,
    heads: dict[str, Any],
    batch_id: str,
    todo_text: str,
    changelog_text: str,
) -> int:
    batch = selected_batch(heads, batch_id)
    projects = batch.get("projects")
    require(isinstance(projects, list), "candidate projects must be an array")
    retained = [item for item in projects if isinstance(item, dict) and "receipt_evidence" in item]
    require(retained, "candidate batch must retain at least one receipt-backed qualification")
    for snapshot in retained:
        validate_project(root, snapshot, todo_text, changelog_text)
    return len(retained)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Check retained current-head candidate evidence")
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--heads", type=Path, default=root / "scripts/upstream_candidate_heads.json")
    parser.add_argument("--batch", default="2026-08-12-a")
    parser.add_argument("--todo", type=Path, default=root / "docs/TODO.md")
    parser.add_argument("--changelog", type=Path, default=root / "docs/devlog/changelog.md")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        count = validate(
            args.root.resolve(),
            load_json(args.heads),
            args.batch,
            args.todo.read_text(encoding="utf-8"),
            args.changelog.read_text(encoding="utf-8"),
        )
    except (EvidenceError, OSError) as exc:
        print(f"candidate evidence error: {exc}", file=sys.stderr)
        return 2
    print(f"UPSTREAM_CANDIDATE_EVIDENCE_OK batch={args.batch} projects={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
