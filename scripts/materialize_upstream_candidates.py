#!/usr/bin/env python3

import argparse
import copy
import json
import re
import sys
import tempfile
from datetime import date
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class MaterializeError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise MaterializeError(message)


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise MaterializeError(f"cannot load {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: root must be an object")
    return value


def select_batch(heads, batch_id):
    require(heads.get("schema") == 1, "head snapshot schema must be 1")
    batches = heads.get("batches")
    require(isinstance(batches, list) and batches, "head snapshot batches must be non-empty")
    ids = [batch.get("id") for batch in batches if isinstance(batch, dict)]
    require(len(ids) == len(set(ids)), "head snapshot batch ids must be unique")
    matches = [batch for batch in batches if batch.get("id") == batch_id]
    require(len(matches) == 1, f"head snapshot batch {batch_id!r} was not found exactly once")
    return matches[0]


def validate_batch(batch):
    checked_at = batch.get("checked_at")
    require(isinstance(checked_at, str), "batch checked_at must be a string")
    try:
        date.fromisoformat(checked_at)
    except ValueError as exc:
        raise MaterializeError("batch checked_at must be an ISO date") from exc
    projects = batch.get("projects")
    require(isinstance(projects, list) and projects, "batch projects must be non-empty")
    ids = set()
    for project in projects:
        require(isinstance(project, dict), "batch project entries must be objects")
        project_id = project.get("id")
        require(isinstance(project_id, str) and project_id, "batch project id is required")
        require(project_id not in ids, f"duplicate batch project {project_id}")
        ids.add(project_id)
        require(
            isinstance(project.get("repository"), str) and project["repository"],
            f"{project_id}: repository is required",
        )
        require(
            isinstance(project.get("default_branch"), str)
            and project["default_branch"],
            f"{project_id}: default branch is required",
        )
        require(
            isinstance(project.get("head"), str)
            and COMMIT_RE.fullmatch(project["head"]),
            f"{project_id}: head must be a full lowercase commit SHA",
        )


def materialize(base, heads, batch_id):
    require(base.get("schema") == 1, "base manifest schema must be 1")
    base_projects = base.get("projects")
    require(isinstance(base_projects, list), "base manifest projects must be an array")
    by_id = {project.get("id"): project for project in base_projects}
    require(len(by_id) == len(base_projects), "base manifest project ids must be unique")

    batch = select_batch(heads, batch_id)
    validate_batch(batch)
    selected = []
    for snapshot in batch["projects"]:
        project_id = snapshot["id"]
        require(project_id in by_id, f"{project_id}: not found in base manifest")
        project = copy.deepcopy(by_id[project_id])
        require(
            project.get("repository") == snapshot["repository"],
            f"{project_id}: repository differs from base manifest",
        )
        project["revision"] = snapshot["head"]
        selected.append(project)

    return {
        "schema": 1,
        "campaigns": {
            "upstream-candidates": {
                "window_minutes": 1440,
                "repetitions": 3,
                "projects": [project["id"] for project in selected],
            }
        },
        "projects": selected,
    }


def write_json_atomic(path, value):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(value, indent=2, sort_keys=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as stream:
        stream.write(rendered)
        temporary = Path(stream.name)
    temporary.replace(output)


def parse_args(argv=None):
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Materialize a frozen Phase 9 candidate campaign"
    )
    parser.add_argument("--base", default=str(root / "realworld_manifest.json"))
    parser.add_argument(
        "--heads", default=str(root / "upstream_candidate_heads.json")
    )
    parser.add_argument("--batch", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        value = materialize(
            load_json(args.base), load_json(args.heads), args.batch
        )
        write_json_atomic(args.output, value)
    except MaterializeError as exc:
        print(f"candidate manifest error: {exc}", file=sys.stderr)
        return 2
    print(
        f"UPSTREAM_CANDIDATES_OK batch={args.batch} "
        f"projects={len(value['projects'])} output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
