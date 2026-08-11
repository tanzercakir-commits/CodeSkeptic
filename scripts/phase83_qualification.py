#!/usr/bin/env python3
"""Observe Phase 8.3 candidates without creating accepted factory intent."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import run_realworld_campaign as campaign


SCHEMA = 1
KIND = "phase83-qualification"
CANDIDATE_IDS = ["llama-cpp", "shadps4", "tensorflow-lite"]
CMAKE_DEFINITION = re.compile(r"-D[A-Za-z0-9_]+=[A-Za-z0-9_./:+,=-]+")
CMAKE_TARGET = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:+-]*")
TENSORFLOW_SOURCE_DEFINITION = "-DTENSORFLOW_SOURCE_DIR={source}"
SUBMODULE_LINE = re.compile(r" ([0-9a-f]{40}) (.+?)(?: \([^\r\n]*\))?$")


def _load_document(path: Path | str) -> dict[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise campaign.ManifestError(f"cannot read candidate document {source}: {error}") from error
    if not isinstance(value, dict):
        raise campaign.ManifestError("candidate document root must be an object")
    return value


def _validate_cmake_command(
    tokens: Any, field: str, group: str, project_id: str
) -> list[str]:
    command = campaign._validate_tokens(
        tokens, field, command=True, command_group=group
    )
    if command[0] != "cmake":
        raise campaign.ManifestError(f"{field} must use the CMake command family")
    if group == "configure":
        if (
            len(command) < 7
            or command[1] != "-S"
            or not command[2].startswith("{source}")
            or command[3:7] != ["-B", "{build}", "-G", "Ninja"]
            or any(
                not CMAKE_DEFINITION.fullmatch(token)
                and not (
                    project_id == "tensorflow-lite"
                    and token == TENSORFLOW_SOURCE_DEFINITION
                )
                for token in command[7:]
            )
        ):
            raise campaign.ManifestError(f"{field} has an invalid configure shape")
        suffix = command[2][len("{source}") :]
        if suffix:
            campaign._require_relative(suffix.lstrip("/"), f"{field} source suffix")
        return command
    if (
        len(command) != 7
        or command[:4] != ["cmake", "--build", "{build}", "--target"]
        or not CMAKE_TARGET.fullmatch(command[4])
        or command[5:] != ["--parallel", "{jobs}"]
    ):
        raise campaign.ManifestError(f"{field} has an invalid build shape")
    return command


def _validate_project(raw: Any, index: int) -> dict[str, Any]:
    field = f"projects[{index}]"
    required = {
        "id",
        "label",
        "repository",
        "revision",
        "timeout_minutes",
        "memory_mb",
        "checkout",
        "commands",
        "compile_database",
        "sources",
        "analyzer_args",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise campaign.ManifestError(f"{field} has an invalid closed shape")
    project = copy.deepcopy(raw)
    project_id = project.get("id")
    if not isinstance(project_id, str) or not campaign.PROJECT_ID.fullmatch(project_id):
        raise campaign.ManifestError(f"{field}.id is invalid")
    if not isinstance(project.get("label"), str) or not project["label"]:
        raise campaign.ManifestError(f"project {project_id} label must be nonempty")

    repository = project.get("repository")
    parsed = urlparse(repository) if isinstance(repository, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or not parsed.path.endswith(".git")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise campaign.ManifestError(
            f"project {project_id} repository must be an exact GitHub HTTPS URL"
        )
    revision = project.get("revision")
    if not isinstance(revision, str) or not campaign.SHA40.fullmatch(revision):
        raise campaign.ManifestError(
            f"project {project_id} revision must be an immutable 40-hex commit"
        )
    campaign._require_int(
        project.get("timeout_minutes"),
        f"project {project_id} timeout_minutes",
        1,
        330,
    )
    campaign._require_int(
        project.get("memory_mb"), f"project {project_id} memory_mb", 512, 65536
    )

    checkout = project.get("checkout")
    if (
        not isinstance(checkout, dict)
        or set(checkout) != {"submodules"}
        or checkout["submodules"] not in {"none", "recursive"}
    ):
        raise campaign.ManifestError(f"project {project_id} checkout is invalid")
    if project_id != "shadps4" and checkout["submodules"] != "none":
        raise campaign.ManifestError("recursive submodules are admitted only for shadps4")
    if project_id == "shadps4" and checkout["submodules"] != "recursive":
        raise campaign.ManifestError("shadps4 requires recursive submodules")

    commands = project.get("commands")
    if not isinstance(commands, dict) or set(commands) != {"configure", "build"}:
        raise campaign.ManifestError(
            f"project {project_id} commands must contain configure and build"
        )
    for group in ("configure", "build"):
        rows = commands[group]
        if not isinstance(rows, list) or not rows:
            raise campaign.ManifestError(
                f"project {project_id} commands.{group} must be nonempty"
            )
        commands[group] = [
            _validate_cmake_command(
                row,
                f"project {project_id} commands.{group}[{row_index}]",
                group,
                project_id,
            )
            for row_index, row in enumerate(rows)
        ]
    source_bindings = sum(
        row.count(TENSORFLOW_SOURCE_DEFINITION) for row in commands["configure"]
    )
    if project_id == "tensorflow-lite" and source_bindings != 1:
        raise campaign.ManifestError(
            "tensorflow-lite must bind the pinned TensorFlow source exactly once"
        )

    if project.get("compile_database") != "{build}/compile_commands.json":
        raise campaign.ManifestError(
            f"project {project_id} compile_database must be the CMake build database"
        )
    sources = project.get("sources")
    if (
        not isinstance(sources, dict)
        or set(sources) != {"roots", "extensions", "fallback_globs"}
        or not isinstance(sources["roots"], list)
        or not sources["roots"]
    ):
        raise campaign.ManifestError(f"project {project_id} sources are invalid")
    sources["roots"] = [
        campaign._require_relative(root, f"project {project_id} source root")
        for root in sources["roots"]
    ]
    extensions = sources.get("extensions")
    if (
        not isinstance(extensions, list)
        or not extensions
        or any(
            not isinstance(extension, str)
            or not re.fullmatch(r"\.[A-Za-z0-9+]+", extension)
            for extension in extensions
        )
    ):
        raise campaign.ManifestError(f"project {project_id} extensions are invalid")
    sources["extensions"] = sorted(set(extensions))
    if sources.get("fallback_globs") != []:
        raise campaign.ManifestError(
            f"project {project_id} qualification forbids fallback globs"
        )
    project["analyzer_args"] = campaign._validate_tokens(
        project.get("analyzer_args"),
        f"project {project_id} analyzer_args",
        command=False,
    )
    return project


def validate_candidates(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema") != SCHEMA or set(raw) != {"schema", "projects"}:
        raise campaign.ManifestError("candidate document root is invalid")
    projects_raw = raw.get("projects")
    if not isinstance(projects_raw, list):
        raise campaign.ManifestError("candidate projects must be an array")
    projects = [_validate_project(project, index) for index, project in enumerate(projects_raw)]
    identities = [project["id"] for project in projects]
    if identities != CANDIDATE_IDS:
        raise campaign.ManifestError(
            "candidate identities and order must be llama-cpp, shadps4, tensorflow-lite"
        )
    return {"schema": SCHEMA, "projects": projects}


def project_by_id(document: dict[str, Any], project_id: str) -> dict[str, Any]:
    matches = [project for project in document["projects"] if project["id"] == project_id]
    if len(matches) != 1:
        raise campaign.ManifestError(f"unknown qualification candidate {project_id}")
    return matches[0]


def plan_matrix(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "include": [
            {
                "project": project["id"],
                "timeout_minutes": project["timeout_minutes"],
            }
            for project in document["projects"]
        ]
    }


def _run_logged(
    command: list[str],
    cwd: Path,
    deadline: float,
    memory_mb: int,
    log_path: Path,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    remaining = max(0.0, deadline - time.monotonic())
    if remaining <= 0:
        raise campaign.EvidenceError("qualification timed out")
    with log_path.open("a", encoding="utf-8", newline="\n") as log:
        log.write(f"COMMAND cwd={cwd.as_posix()} argv={json.dumps(command)}\n")
        log.flush()
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                check=False,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=remaining,
                preexec_fn=campaign._memory_preexec(memory_mb),
                env=env,
            )
        except subprocess.TimeoutExpired as error:
            raise campaign.EvidenceError("qualification timed out") from error
        log.write(f"EXIT {result.returncode}\n")
    return result


def _capture_git(
    command: list[str],
    cwd: Path,
    deadline: float,
    memory_mb: int,
    log_path: Path,
    env: dict[str, str],
) -> str:
    remaining = max(0.0, deadline - time.monotonic())
    if remaining <= 0:
        raise campaign.EvidenceError("qualification timed out")
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=remaining,
            preexec_fn=campaign._memory_preexec(memory_mb),
            env=env,
        )
    except subprocess.TimeoutExpired as error:
        raise campaign.EvidenceError("qualification timed out") from error
    with log_path.open("a", encoding="utf-8", newline="\n") as log:
        log.write(f"COMMAND cwd={cwd.as_posix()} argv={json.dumps(command)}\n")
        log.write(result.stdout)
        log.write(result.stderr)
        log.write(f"EXIT {result.returncode}\n")
    if result.returncode != 0:
        raise campaign.EvidenceError(
            f"checkout evidence command failed with exit {result.returncode}"
        )
    return result.stdout


def _capture_logged_command(
    command: list[str],
    cwd: Path,
    deadline: float,
    memory_mb: int,
    log_path: Path,
    evidence_name: str,
) -> str:
    remaining = max(0.0, deadline - time.monotonic())
    if remaining <= 0:
        raise campaign.EvidenceError("qualification timed out")
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=remaining,
            preexec_fn=campaign._memory_preexec(memory_mb),
        )
    except subprocess.TimeoutExpired as error:
        raise campaign.EvidenceError("qualification timed out") from error
    with log_path.open("a", encoding="utf-8", newline="\n") as log:
        log.write(f"COMMAND cwd={cwd.as_posix()} argv={json.dumps(command)}\n")
        log.write(result.stdout)
        log.write(result.stderr)
        log.write(f"EXIT {result.returncode}\n")
    if result.returncode != 0:
        raise campaign.EvidenceError(
            f"{evidence_name} command failed with exit {result.returncode}"
        )
    return result.stdout


filter_target_translation_units = campaign.filter_target_translation_units


def parse_submodule_status(output: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        match = SUBMODULE_LINE.fullmatch(line)
        if match is None:
            raise campaign.EvidenceError(
                "recursive submodule is uninitialized, drifted, conflicted, or malformed"
            )
        revision, path = match.groups()
        normalized = campaign._require_relative(path, "submodule path")
        entries.append({"path": normalized, "revision": revision})
    if not entries:
        raise campaign.EvidenceError("recursive submodule identity is empty")
    entries.sort(key=lambda entry: entry["path"])
    if len({entry["path"] for entry in entries}) != len(entries):
        raise campaign.EvidenceError("recursive submodule identity has duplicate paths")
    return entries


def _checkout(
    project: dict[str, Any],
    project_root: Path,
    deadline: float,
    log_path: Path,
) -> dict[str, Any]:
    git_env = os.environ.copy()
    git_env["GIT_ALLOW_PROTOCOL"] = "https"
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    commands = (
        ["git", "init", "--quiet"],
        ["git", "remote", "add", "origin", project["repository"]],
        ["git", "fetch", "--quiet", "--depth", "1", "origin", project["revision"]],
        ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    )
    for command in commands:
        result = _run_logged(
            command,
            project_root,
            deadline,
            project["memory_mb"],
            log_path,
            env=git_env,
        )
        if result.returncode != 0:
            raise campaign.EvidenceError(
                f"checkout command failed with exit {result.returncode}"
            )
    revision = _capture_git(
        ["git", "rev-parse", "HEAD"],
        project_root,
        deadline,
        project["memory_mb"],
        log_path,
        git_env,
    ).strip()
    if revision != project["revision"]:
        raise campaign.EvidenceError(
            f"checkout revision mismatch {revision} != {project['revision']}"
        )

    gitlinks = []
    stage = _capture_git(
        ["git", "ls-files", "--stage"],
        project_root,
        deadline,
        project["memory_mb"],
        log_path,
        git_env,
    )
    for line in stage.splitlines():
        if line.startswith("160000 "):
            gitlinks.append(line)
    mode = project["checkout"]["submodules"]
    entries: list[dict[str, str]] = []
    if mode == "none" and gitlinks:
        raise campaign.EvidenceError("candidate has undeclared gitlink submodules")
    if mode == "recursive":
        for command in (
            ["git", "-c", "protocol.file.allow=never", "submodule", "sync", "--recursive"],
            [
                "git",
                "-c",
                "protocol.file.allow=never",
                "submodule",
                "update",
                "--init",
                "--recursive",
                "--depth",
                "1",
                "--jobs",
                "2",
            ],
        ):
            result = _run_logged(
                command,
                project_root,
                deadline,
                project["memory_mb"],
                log_path,
                env=git_env,
            )
            if result.returncode != 0:
                raise campaign.EvidenceError(
                    f"recursive submodule checkout failed with exit {result.returncode}"
                )
        status = _capture_git(
            ["git", "submodule", "status", "--recursive"],
            project_root,
            deadline,
            project["memory_mb"],
            log_path,
            git_env,
        )
        entries = parse_submodule_status(status)
        clean = _capture_git(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
                "--ignore-submodules=none",
            ],
            project_root,
            deadline,
            project["memory_mb"],
            log_path,
            git_env,
        )
        if clean:
            raise campaign.EvidenceError("recursive submodule checkout is not clean")
    return {
        "mode": mode,
        "count": len(entries),
        "sha256": campaign.digest_json(entries),
        "entries": entries,
    }


def run_observation(
    document: dict[str, Any],
    project_id: str,
    analyzer: Path,
    workspace: Path,
    output: Path,
    repository_root: Path,
) -> int:
    project = project_by_id(document, project_id)
    analyzer = analyzer.resolve()
    if not analyzer.is_file():
        raise campaign.EvidenceError(f"analyzer unavailable: {analyzer}")
    analyzer_sha = campaign.file_digest(analyzer)
    started = time.monotonic()
    deadline = started + project["timeout_minutes"] * 60
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path = output.parent / "commands.log"
    if log_path.exists():
        log_path.unlink()
    workspace.mkdir(parents=True, exist_ok=True)
    project_root = campaign._inside(
        workspace, workspace / project_id, "qualification workspace"
    )
    if project_root.exists():
        shutil.rmtree(project_root)
    project_root.mkdir(parents=True)
    build = campaign._inside(
        project_root, project_root / "build-codeskeptic", "qualification build"
    )
    values = {"source": str(project_root), "build": str(build), "jobs": "2"}

    submodules = _checkout(project, project_root, deadline, log_path)
    for group in ("configure", "build"):
        for command in project["commands"][group]:
            result = _run_logged(
                campaign._expand(command, values),
                project_root,
                deadline,
                project["memory_mb"],
                log_path,
            )
            if result.returncode != 0:
                raise campaign.EvidenceError(
                    f"{group} command failed with exit {result.returncode}"
                )

    compile_database = campaign._inside(
        build,
        Path(project["compile_database"].format(**values)),
        "compile database",
    )
    files, relative_files = campaign._derive_translation_units(
        project, project_root, build, compile_database
    )
    target_commands = ""
    for command in project["commands"]["build"]:
        target_commands += _capture_logged_command(
            ["ninja", "-C", str(build), "-t", "commands", command[4]],
            project_root,
            deadline,
            project["memory_mb"],
            log_path,
            "Ninja target closure",
        )
    files, relative_files = filter_target_translation_units(
        target_commands,
        project_root,
        build,
        files,
        relative_files,
    )
    tu_sha = campaign.translation_unit_digest(relative_files)
    (output.parent / "translation-units.txt").write_text(
        "\n".join(str(path) for path in files) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (output.parent / "translation-units.relative.txt").write_text(
        "\n".join(relative_files) + "\n", encoding="utf-8", newline="\n"
    )

    report_path = output.parent / "report.json"
    analyzer_command = [
        str(analyzer),
        "--files",
        str(output.parent / "translation-units.txt"),
        "--build-path",
        str(build),
        "--json",
        str(report_path),
        *campaign._expand(project["analyzer_args"], values),
    ]
    result = _run_logged(
        analyzer_command,
        repository_root,
        deadline,
        project["memory_mb"],
        log_path,
    )
    if not report_path.is_file():
        raise campaign.EvidenceError("analyzer did not produce a qualification report")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise campaign.EvidenceError(f"qualification report is malformed: {error}") from error
    semantic = campaign._report_semantic(result.returncode, report, len(files), tu_sha)

    receipt = {
        "schema": SCHEMA,
        "kind": KIND,
        "status": "observed",
        "project": project_id,
        "label": project["label"],
        "identity": {
            "revision": project["revision"],
            "recipe_sha256": campaign.digest_json(project),
            "analyzer_sha256": analyzer_sha,
            "submodules": submodules,
        },
        "semantic": semantic,
        "failures": [],
        "execution": {
            "duration_seconds": round(time.monotonic() - started, 3),
            "jobs": 2,
        },
    }
    campaign.write_receipt(output, receipt)
    print(
        "PHASE83_QUALIFICATION_OBSERVED "
        f"project={project_id} tus={len(files)} tu_sha256={tu_sha} "
        f"findings={semantic['findings']}"
    )
    return 0


def _default_document() -> Path:
    return Path(__file__).with_name("phase83_candidates.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="validate and emit the candidate matrix")
    plan.add_argument("--document", type=Path, default=_default_document())
    run = subparsers.add_parser("run", help="observe one candidate")
    run.add_argument("--document", type=Path, default=_default_document())
    run.add_argument("--project", required=True)
    run.add_argument("--analyzer", required=True, type=Path)
    run.add_argument("--workspace", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    document: dict[str, Any] | None = None
    try:
        document = validate_candidates(_load_document(args.document))
        if args.command == "plan":
            print(json.dumps(plan_matrix(document), sort_keys=True, separators=(",", ":")))
            return 0
        return run_observation(
            document,
            args.project,
            args.analyzer,
            args.workspace,
            args.output,
            args.repository_root.resolve(),
        )
    except campaign.CampaignError as error:
        if args.command != "run":
            print(f"PHASE83_QUALIFICATION_UNAVAILABLE {error}", file=sys.stderr)
            return 2
        project = None
        if document is not None:
            try:
                project = project_by_id(document, args.project)
            except campaign.CampaignError:
                pass
        receipt = {
            "schema": SCHEMA,
            "kind": KIND,
            "status": "unavailable",
            "project": args.project,
            "label": project.get("label") if project else None,
            "identity": {
                "revision": project.get("revision") if project else None,
                "recipe_sha256": campaign.digest_json(project) if project else None,
            },
            "semantic": None,
            "failures": [str(error)],
        }
        campaign.write_receipt(args.output, receipt)
        print(f"PHASE83_QUALIFICATION_UNAVAILABLE {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
