#!/usr/bin/env python3
"""Plan, execute, and referee deterministic real-repository campaigns."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shlex
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA = 1
SHA40 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PROJECT_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
FINGERPRINT = re.compile(r"csf1-[0-9a-f]{16}")
ALLOWED_COMMANDS = {"bear", "cmake", "meson"}
ALLOWED_PLACEHOLDERS = {"source", "build", "jobs"}
MESON_OPTION = re.compile(
    r"(?:--buildtype=(?:debug|release|debugoptimized|minsize)|"
    r"-D[A-Za-z0-9_-]+=[A-Za-z0-9_.+-]+)"
)
MESON_TARGET = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:+-]*")
MAKE_ASSIGNMENT = re.compile(r"[A-Z_][A-Z0-9_]*=[A-Za-z0-9_.+-]+")
REQUIRED_EXPECTED = {
    "translation_units",
    "translation_unit_sha256",
    "attempted_tus",
    "analyzed_tus",
    "broken_tus",
    "incomplete_functions",
    "findings",
    "exit_code",
    "fingerprint_sha256",
}


class CampaignError(RuntimeError):
    """Base class for a fail-closed campaign error."""


class ManifestError(CampaignError):
    """The requested campaign input is not eligible."""


class EvidenceError(CampaignError):
    """Execution evidence cannot support a verdict."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def fingerprint_digest(fingerprints: list[str]) -> str:
    return digest_json(sorted(fingerprints))


def translation_unit_digest(paths: list[str]) -> str:
    normalized = sorted(path.replace("\\", "/") for path in paths)
    return digest_bytes(("\n".join(normalized) + "\n").encode("utf-8"))


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def load_manifest(path: Path | str) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read manifest {manifest_path}: {error}") from error
    if not isinstance(payload, dict):
        raise ManifestError("manifest root must be an object")
    return payload


def _require_int(value: Any, field: str, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{field} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        bound = f"{minimum}..{maximum}" if maximum is not None else f">={minimum}"
        raise ManifestError(f"{field} must be {bound}")
    return value


def _require_relative(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ManifestError(f"{field} must be a nonempty relative path")
    path = Path(value)
    if path.is_absolute() or value.startswith(("/", "\\")) or ".." in path.parts:
        raise ManifestError(f"{field} must stay inside its declared root")
    return value.replace("\\", "/")


def _placeholders(token: str, field: str) -> None:
    try:
        names = {
            name
            for _, name, _, _ in string.Formatter().parse(token)
            if name is not None
        }
    except ValueError as error:
        raise ManifestError(f"{field} has malformed placeholders") from error
    unknown = names - ALLOWED_PLACEHOLDERS
    if unknown:
        raise ManifestError(f"{field} has unsupported placeholder {sorted(unknown)[0]!r}")


def _validate_command_shape(tokens: list[str], field: str, group: str) -> None:
    executable = tokens[0]
    if executable == "cmake":
        return
    if executable == "meson":
        if group == "configure":
            if (
                len(tokens) < 4
                or tokens[:4] != ["meson", "setup", "{build}", "{source}"]
                or any(not MESON_OPTION.fullmatch(token) for token in tokens[4:])
            ):
                raise ManifestError(f"{field} has an invalid meson configure shape")
            return
        if (
            group != "build"
            or len(tokens) < 4
            or tokens[:4] != ["meson", "compile", "-C", "{build}"]
            or any(not MESON_TARGET.fullmatch(token) for token in tokens[4:])
        ):
            raise ManifestError(f"{field} has an invalid meson build shape")
        return
    if executable == "bear":
        prefix = [
            "bear",
            "--output",
            "{build}/compile_commands.json",
            "--",
            "make",
            "-C",
            "{source}",
        ]
        if (
            group != "build"
            or tokens[: len(prefix)] != prefix
            or len(tokens) <= len(prefix)
            or any(
                token != "-j{jobs}" and not MAKE_ASSIGNMENT.fullmatch(token)
                for token in tokens[len(prefix) :]
            )
        ):
            raise ManifestError(f"{field} has an invalid bear build shape")
        return
    raise ManifestError(f"{field} command executable {executable!r} is not admitted")


def _validate_tokens(
    tokens: Any, field: str, *, command: bool, command_group: str = ""
) -> list[str]:
    if not isinstance(tokens, list) or not tokens:
        raise ManifestError(f"{field} must be a nonempty token array")
    if any(not isinstance(token, str) or not token or "\x00" in token or "\n" in token for token in tokens):
        raise ManifestError(f"{field} contains an invalid token")
    if command and tokens[0] not in ALLOWED_COMMANDS:
        raise ManifestError(
            f"{field} command executable {tokens[0]!r} is not admitted"
        )
    for token in tokens:
        _placeholders(token, field)
    if command:
        _validate_command_shape(tokens, field, command_group)
    return list(tokens)


def _validate_project(raw: Any, index: int) -> dict[str, Any]:
    field = f"projects[{index}]"
    if not isinstance(raw, dict):
        raise ManifestError(f"{field} must be an object")
    project = copy.deepcopy(raw)
    project_id = project.get("id")
    if not isinstance(project_id, str) or not PROJECT_ID.fullmatch(project_id):
        raise ManifestError(f"{field}.id is invalid")
    if not isinstance(project.get("label"), str) or not project["label"]:
        raise ManifestError(f"project {project_id} label must be nonempty")

    repository = project.get("repository")
    if not isinstance(repository, str):
        raise ManifestError(f"project {project_id} repository must be HTTPS")
    parsed = urlparse(repository)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or not parsed.path.endswith(".git")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ManifestError(f"project {project_id} repository must be an exact GitHub HTTPS URL")
    revision = project.get("revision")
    if not isinstance(revision, str) or not SHA40.fullmatch(revision):
        raise ManifestError(f"project {project_id} revision must be an immutable 40-hex commit")

    _require_int(project.get("timeout_minutes"), f"project {project_id} timeout_minutes", 1, 330)
    _require_int(project.get("memory_mb"), f"project {project_id} memory_mb", 512, 65536)

    commands = project.get("commands")
    if not isinstance(commands, dict) or set(commands) != {"configure", "build"}:
        raise ManifestError(f"project {project_id} commands must contain configure and build")
    for group in ("configure", "build"):
        rows = commands[group]
        if not isinstance(rows, list) or not rows:
            raise ManifestError(f"project {project_id} commands.{group} must be nonempty")
        commands[group] = [
            _validate_tokens(
                row,
                f"project {project_id} commands.{group}[{row_index}]",
                command=True,
                command_group=group,
            )
            for row_index, row in enumerate(rows)
        ]

    checkout = project.get(
        "checkout",
        {
            "submodules": "none",
            "expected_count": 0,
            "expected_sha256": digest_json([]),
        },
    )
    if not isinstance(checkout, dict) or set(checkout) != {
        "submodules",
        "expected_count",
        "expected_sha256",
    }:
        raise ManifestError(f"project {project_id} checkout fields are invalid")
    if checkout["submodules"] not in ("none", "recursive"):
        raise ManifestError(f"project {project_id} checkout mode is invalid")
    _require_int(
        checkout["expected_count"],
        f"project {project_id} checkout.expected_count",
        0,
    )
    if (
        not isinstance(checkout["expected_sha256"], str)
        or not SHA256.fullmatch(checkout["expected_sha256"])
    ):
        raise ManifestError(
            f"project {project_id} checkout.expected_sha256 must be SHA-256"
        )
    if checkout["submodules"] == "none" and (
        checkout["expected_count"] != 0
        or checkout["expected_sha256"] != digest_json([])
    ):
        raise ManifestError(f"project {project_id} empty checkout identity is invalid")
    if checkout["submodules"] == "recursive" and checkout["expected_count"] < 1:
        raise ManifestError(f"project {project_id} recursive checkout identity is empty")

    copies = project.get("copies")
    if not isinstance(copies, list):
        raise ManifestError(f"project {project_id} copies must be an array")
    for copy_index, operation in enumerate(copies):
        if not isinstance(operation, dict) or set(operation) != {"from", "to"}:
            raise ManifestError(f"project {project_id} copies[{copy_index}] is invalid")
        operation["from"] = _require_relative(
            operation["from"], f"project {project_id} copies[{copy_index}].from"
        )
        operation["to"] = _require_relative(
            operation["to"], f"project {project_id} copies[{copy_index}].to"
        )

    compile_database = project.get("compile_database")
    if not isinstance(compile_database, str) or not compile_database:
        raise ManifestError(f"project {project_id} compile_database must be nonempty")
    _placeholders(compile_database, f"project {project_id} compile_database")

    sources = project.get("sources")
    if not isinstance(sources, dict) or set(sources) != {"roots", "extensions", "fallback_globs"}:
        raise ManifestError(f"project {project_id} sources has an invalid shape")
    if not isinstance(sources["roots"], list) or not sources["roots"]:
        raise ManifestError(f"project {project_id} source roots must be nonempty")
    sources["roots"] = [
        _require_relative(root, f"project {project_id} source root")
        for root in sources["roots"]
    ]
    extensions = sources["extensions"]
    if (
        not isinstance(extensions, list)
        or not extensions
        or any(not isinstance(ext, str) or not re.fullmatch(r"\.[A-Za-z0-9+]+", ext) for ext in extensions)
    ):
        raise ManifestError(f"project {project_id} extensions are invalid")
    sources["extensions"] = sorted(set(extensions))
    if not isinstance(sources["fallback_globs"], list):
        raise ManifestError(f"project {project_id} fallback_globs must be an array")
    sources["fallback_globs"] = [
        _require_relative(pattern, f"project {project_id} fallback glob")
        for pattern in sources["fallback_globs"]
    ]

    project["analyzer_args"] = _validate_tokens(
        project.get("analyzer_args"), f"project {project_id} analyzer_args", command=False
    )

    expected = project.get("expected")
    if not isinstance(expected, dict) or set(expected) != REQUIRED_EXPECTED:
        raise ManifestError(f"project {project_id} expected fields are invalid")
    for name in (
        "translation_units",
        "attempted_tus",
        "analyzed_tus",
        "broken_tus",
        "incomplete_functions",
        "findings",
    ):
        _require_int(expected.get(name), f"project {project_id} expected.{name}", 0)
    if expected["translation_units"] == 0:
        raise ManifestError(f"project {project_id} translation_units must be positive")
    for name in ("translation_unit_sha256", "fingerprint_sha256"):
        value = expected.get(name)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise ManifestError(f"project {project_id} expected.{name} must be SHA-256")
        if value.startswith("0" * 60):
            raise ManifestError(
                f"project {project_id} expected.{name} is a placeholder SHA-256"
            )
    if expected.get("exit_code") not in (0, 1):
        raise ManifestError(f"project {project_id} expected exit is an unavailable verdict")
    if (
        expected["attempted_tus"] != expected["translation_units"]
        or expected["analyzed_tus"] < expected["attempted_tus"]
        or expected["broken_tus"] != 0
        or expected["incomplete_functions"] != 0
    ):
        raise ManifestError(f"project {project_id} expected coverage is not exact")
    return project


def validate_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema") != SCHEMA:
        raise ManifestError(f"manifest schema must be {SCHEMA}")
    if set(raw) != {"schema", "campaigns", "projects"}:
        raise ManifestError("manifest root fields are invalid")
    projects_raw = raw.get("projects")
    if not isinstance(projects_raw, list) or not projects_raw:
        raise ManifestError("projects must be a nonempty array")
    projects = [_validate_project(project, index) for index, project in enumerate(projects_raw)]
    project_ids = [project["id"] for project in projects]
    duplicates = sorted({project_id for project_id in project_ids if project_ids.count(project_id) > 1})
    if duplicates:
        raise ManifestError(f"duplicate project {duplicates[0]}")

    campaigns_raw = raw.get("campaigns")
    if not isinstance(campaigns_raw, dict) or not campaigns_raw:
        raise ManifestError("campaigns must be a nonempty object")
    campaigns: dict[str, Any] = {}
    referenced: list[str] = []
    for name, campaign in campaigns_raw.items():
        if not isinstance(name, str) or not PROJECT_ID.fullmatch(name) or not isinstance(campaign, dict):
            raise ManifestError("campaign name or shape is invalid")
        if set(campaign) != {"window_minutes", "repetitions", "projects"}:
            raise ManifestError(f"campaign {name} fields are invalid")
        window = _require_int(campaign["window_minutes"], f"campaign {name} window_minutes", 1, 4320)
        repetitions = _require_int(campaign["repetitions"], f"campaign {name} repetitions", 3, 3)
        selected = campaign["projects"]
        if not isinstance(selected, list) or not selected or any(not isinstance(item, str) for item in selected):
            raise ManifestError(f"campaign {name} projects must be nonempty")
        if len(selected) != len(set(selected)):
            raise ManifestError(f"campaign {name} has duplicate project identities")
        unknown = sorted(set(selected) - set(project_ids))
        if unknown:
            raise ManifestError(f"campaign {name} references unknown project {unknown[0]}")
        if name == "nightly" and window > 720:
            raise ManifestError("nightly campaign window exceeds 12 hours")
        if name == "weekend" and not 2160 <= window <= 2880:
            raise ManifestError("weekend campaign window must be 36..48 hours")
        campaigns[name] = {
            "window_minutes": window,
            "repetitions": repetitions,
            "projects": list(selected),
        }
        referenced.extend(selected)
    unreferenced = sorted(set(project_ids) - set(referenced))
    if unreferenced:
        raise ManifestError(f"unreferenced project {unreferenced[0]}")
    return {"schema": SCHEMA, "campaigns": campaigns, "projects": projects}


def project_by_id(manifest: dict[str, Any], project_id: str) -> dict[str, Any]:
    matches = [project for project in manifest["projects"] if project["id"] == project_id]
    if len(matches) != 1:
        raise ManifestError(f"unknown project {project_id}")
    return matches[0]


def project_recipe(project: dict[str, Any]) -> dict[str, Any]:
    return {
        key: project[key]
        for key in (
            "repository",
            "revision",
            "commands",
            "copies",
            "compile_database",
            "sources",
            "analyzer_args",
            "timeout_minutes",
            "memory_mb",
        )
    }


def receipt_identity(
    manifest: dict[str, Any],
    project: dict[str, Any],
    repetition: int,
    analyzer_sha256: str,
    translation_unit_sha256: str,
    submodules: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if submodules is None:
        submodules = _expected_submodules(project)
    return {
        "manifest_sha256": digest_json(manifest),
        "project_revision": project["revision"],
        "recipe_sha256": digest_json(project_recipe(project)),
        "analyzer_sha256": analyzer_sha256,
        "translation_unit_sha256": translation_unit_sha256,
        "submodules": copy.deepcopy(submodules),
        "repetition": repetition,
    }


def plan_matrix(manifest: dict[str, Any], tier: str) -> dict[str, Any]:
    campaign = manifest["campaigns"].get(tier)
    if campaign is None:
        raise ManifestError(f"unknown campaign {tier}")
    include = []
    for project_id in campaign["projects"]:
        project = project_by_id(manifest, project_id)
        for repetition in range(1, campaign["repetitions"] + 1):
            include.append(
                {
                    "project": project_id,
                    "repetition": repetition,
                    "timeout_minutes": project["timeout_minutes"],
                }
            )
    return {"include": include}


def _sidecar(path: Path) -> Path:
    return Path(f"{path}.sha256")


def write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(encoded, encoding="utf-8", newline="\n")
    os.replace(temporary, path)
    digest = file_digest(path)
    sidecar = _sidecar(path)
    sidecar_temporary = sidecar.with_name(f".{sidecar.name}.tmp")
    sidecar_temporary.write_text(f"{digest}  {path.name}\n", encoding="ascii", newline="\n")
    os.replace(sidecar_temporary, sidecar)


def load_verified_receipt(path: Path) -> dict[str, Any]:
    sidecar = _sidecar(path)
    if not path.is_file() or not sidecar.is_file():
        raise EvidenceError(f"missing receipt or checksum: {path}")
    fields = sidecar.read_text(encoding="ascii").strip().split()
    if len(fields) != 2 or fields[1] != path.name or not SHA256.fullmatch(fields[0]):
        raise EvidenceError(f"malformed receipt checksum: {sidecar}")
    actual = file_digest(path)
    if actual != fields[0]:
        raise EvidenceError(f"receipt checksum mismatch: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"malformed receipt: {path}: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise EvidenceError(f"unsupported receipt schema: {path}")
    return payload


def checkpoint_matches(receipt: dict[str, Any], identity: dict[str, Any]) -> bool:
    return (
        receipt.get("schema") == SCHEMA
        and receipt.get("status") == "accepted"
        and receipt.get("identity") == identity
        and receipt.get("failures") == []
    )


def _report_semantic(
    process_exit: int,
    report: dict[str, Any],
    translation_units: int,
    translation_unit_sha256: str,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise EvidenceError("analyzer report root is not an object")
    if process_exit not in (0, 1) or report.get("exit_code") not in (0, 1):
        raise EvidenceError("unavailable verdict exit 2")
    if report.get("exit_code") != process_exit:
        raise EvidenceError("process/report exit classification mismatch")
    if report.get("complete") is not True:
        raise EvidenceError("report does not contain a complete verdict")
    coverage = report.get("coverage")
    if not isinstance(coverage, dict):
        raise EvidenceError("report has no coverage evidence")
    normalized_coverage: dict[str, int] = {}
    for key in ("attempted_tus", "analyzed_tus", "broken_tus", "incomplete_functions"):
        value = coverage.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EvidenceError(f"coverage field {key} is invalid")
        normalized_coverage[key] = value
    if (
        normalized_coverage["attempted_tus"] != translation_units
        or normalized_coverage["analyzed_tus"] < normalized_coverage["attempted_tus"]
        or normalized_coverage["broken_tus"] != 0
        or normalized_coverage["incomplete_functions"] != 0
    ):
        raise EvidenceError("report does not prove exact TU coverage")
    diagnostics = report.get("diagnostics")
    total = report.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0 or not isinstance(diagnostics, list):
        raise EvidenceError("report finding evidence is invalid")
    if len(diagnostics) != total:
        raise EvidenceError("report finding count does not match diagnostics")
    fingerprints: list[str] = []
    for diagnostic in diagnostics:
        fingerprint = diagnostic.get("fingerprint") if isinstance(diagnostic, dict) else None
        if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
            raise EvidenceError("report contains a malformed finding fingerprint")
        fingerprints.append(fingerprint)
    fingerprints.sort()
    return {
        "translation_units": {
            "count": translation_units,
            "sha256": translation_unit_sha256,
        },
        "coverage": normalized_coverage,
        "findings": total,
        "exit_code": process_exit,
        "fingerprints": fingerprints,
        "fingerprint_sha256": fingerprint_digest(fingerprints),
    }


def _validate_semantic(project: dict[str, Any], semantic: dict[str, Any]) -> None:
    if not isinstance(semantic, dict) or set(semantic) != {
        "translation_units",
        "coverage",
        "findings",
        "exit_code",
        "fingerprints",
        "fingerprint_sha256",
    }:
        raise EvidenceError(f"project {project['id']} semantic evidence is malformed")
    translation_units = semantic.get("translation_units")
    coverage = semantic.get("coverage")
    if (
        not isinstance(translation_units, dict)
        or set(translation_units) != {"count", "sha256"}
        or not isinstance(coverage, dict)
        or set(coverage)
        != {"attempted_tus", "analyzed_tus", "broken_tus", "incomplete_functions"}
    ):
        raise EvidenceError(f"project {project['id']} coverage evidence is malformed")
    numeric_values = [
        translation_units.get("count"),
        coverage.get("attempted_tus"),
        coverage.get("analyzed_tus"),
        coverage.get("broken_tus"),
        coverage.get("incomplete_functions"),
        semantic.get("findings"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in numeric_values):
        raise EvidenceError(f"project {project['id']} numeric evidence is malformed")
    if (
        not isinstance(translation_units.get("sha256"), str)
        or not SHA256.fullmatch(translation_units["sha256"])
        or not isinstance(semantic.get("fingerprint_sha256"), str)
        or not SHA256.fullmatch(semantic["fingerprint_sha256"])
    ):
        raise EvidenceError(f"project {project['id']} digest evidence is malformed")
    fingerprints = semantic.get("fingerprints")
    if (
        not isinstance(fingerprints, list)
        or any(not isinstance(item, str) or not FINGERPRINT.fullmatch(item) for item in fingerprints)
        or fingerprints != sorted(fingerprints)
        or len(fingerprints) != semantic["findings"]
        or fingerprint_digest(fingerprints) != semantic["fingerprint_sha256"]
    ):
        raise EvidenceError(f"project {project['id']} fingerprint evidence is inconsistent")
    exit_code = semantic.get("exit_code")
    if (
        exit_code not in (0, 1)
        or (exit_code == 0 and semantic["findings"] != 0)
        or (exit_code == 1 and semantic["findings"] == 0)
    ):
        raise EvidenceError(f"project {project['id']} verdict evidence is inconsistent")

    expected = project["expected"]
    actual = {
        "translation_units": translation_units["count"],
        "translation_unit_sha256": translation_units["sha256"],
        "attempted_tus": coverage["attempted_tus"],
        "analyzed_tus": coverage["analyzed_tus"],
        "broken_tus": coverage["broken_tus"],
        "incomplete_functions": coverage["incomplete_functions"],
        "findings": semantic["findings"],
        "exit_code": exit_code,
        "fingerprint_sha256": semantic["fingerprint_sha256"],
    }
    drift = [name for name in REQUIRED_EXPECTED if actual[name] != expected[name]]
    if drift:
        details = ", ".join(
            f"{name}={actual[name]!r} expected={expected[name]!r}" for name in sorted(drift)
        )
        raise EvidenceError(f"project {project['id']} expectation drift: {details}")


def semantic_from_report(
    project: dict[str, Any],
    process_exit: int,
    report: dict[str, Any],
    translation_units: int,
    translation_unit_sha256: str,
) -> dict[str, Any]:
    semantic = _report_semantic(
        process_exit, report, translation_units, translation_unit_sha256
    )
    _validate_semantic(project, semantic)
    return semantic


def aggregate_receipts(
    manifest: dict[str, Any], tier: str, receipt_root: Path
) -> dict[str, Any]:
    campaign = manifest["campaigns"].get(tier)
    if campaign is None:
        raise ManifestError(f"unknown campaign {tier}")
    summary: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "accepted",
        "campaign": tier,
        "manifest_sha256": digest_json(manifest),
        "projects": {},
    }
    campaign_analyzer_digests: set[str] = set()
    for project_id in campaign["projects"]:
        project = project_by_id(manifest, project_id)
        receipts: list[dict[str, Any]] = []
        for repetition in range(1, campaign["repetitions"] + 1):
            path = receipt_root / project_id / f"repeat-{repetition}" / "receipt.json"
            if not path.is_file() or not _sidecar(path).is_file():
                raise EvidenceError(f"project {project_id} missing repetition {repetition}")
            receipt = load_verified_receipt(path)
            if (
                receipt.get("status") != "accepted"
                or receipt.get("project") != project_id
                or receipt.get("repetition") != repetition
                or receipt.get("failures") != []
            ):
                raise EvidenceError(f"project {project_id} repetition {repetition} is unavailable")
            receipts.append(receipt)

        semantic_digests = {digest_json(receipt.get("semantic")) for receipt in receipts}
        if len(semantic_digests) != 1:
            raise EvidenceError(f"project {project_id} repetitions are nondeterministic")
        analyzer_digests = {
            receipt.get("identity", {}).get("analyzer_sha256") for receipt in receipts
        }
        if len(analyzer_digests) != 1 or None in analyzer_digests:
            raise EvidenceError(f"project {project_id} analyzer identity is nondeterministic")
        analyzer_digest = next(iter(analyzer_digests))
        if not isinstance(analyzer_digest, str) or not SHA256.fullmatch(analyzer_digest):
            raise EvidenceError(f"project {project_id} analyzer identity is malformed")
        campaign_analyzer_digests.add(analyzer_digest)
        if len(campaign_analyzer_digests) != 1:
            raise EvidenceError("campaign analyzer identity is nondeterministic")
        for repetition, receipt in enumerate(receipts, 1):
            identity = receipt.get("identity")
            expected_identity = receipt_identity(
                manifest,
                project,
                repetition,
                identity.get("analyzer_sha256", "") if isinstance(identity, dict) else "",
                project["expected"]["translation_unit_sha256"],
            )
            if not checkpoint_matches(receipt, expected_identity):
                raise EvidenceError(f"project {project_id} repetition {repetition} identity mismatch")
        semantic = receipts[0]["semantic"]
        _validate_semantic(project, semantic)
        summary["projects"][project_id] = {
            "repetitions": len(receipts),
            "semantic_sha256": next(iter(semantic_digests)),
            "analyzer_sha256": analyzer_digest,
            "translation_unit_sha256": semantic["translation_units"]["sha256"],
            "findings": semantic["findings"],
            "exit_code": semantic["exit_code"],
            "fingerprint_sha256": semantic["fingerprint_sha256"],
        }
    return summary


def _expand(tokens: list[str], values: dict[str, str]) -> list[str]:
    return [token.format(**values) for token in tokens]


def _inside(root: Path, candidate: Path, field: str) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise EvidenceError(f"{field} escapes {resolved_root}")
    return resolved


def _memory_preexec(memory_mb: int):
    if os.name == "nt":
        return None
    try:
        import resource
    except ImportError:
        return None

    limit = memory_mb * 1024 * 1024

    def apply_limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    return apply_limit


def _run_command(
    command: list[str],
    cwd: Path,
    deadline: float,
    memory_mb: int,
    log_path: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    remaining = max(0.0, deadline - time.monotonic())
    if remaining <= 0:
        raise EvidenceError("project shard timed out")
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
                preexec_fn=_memory_preexec(memory_mb),
                env=env,
            )
        except subprocess.TimeoutExpired as error:
            raise EvidenceError("project shard timed out") from error
        log.write(f"EXIT {result.returncode}\n")
    return result


def _expected_submodules(project: dict[str, Any]) -> dict[str, Any]:
    checkout = project.get(
        "checkout",
        {
            "submodules": "none",
            "expected_count": 0,
            "expected_sha256": digest_json([]),
        },
    )
    return {
        "mode": checkout["submodules"],
        "count": checkout["expected_count"],
        "sha256": checkout["expected_sha256"],
    }


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
        raise EvidenceError("project shard timed out")
    with log_path.open("a", encoding="utf-8", newline="\n") as log:
        log.write(f"COMMAND cwd={cwd.as_posix()} argv={json.dumps(command)}\n")
        log.flush()
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=remaining,
                preexec_fn=_memory_preexec(memory_mb),
                env=env,
            )
        except subprocess.TimeoutExpired as error:
            raise EvidenceError("project shard timed out") from error
        log.write(result.stdout)
        log.write(f"EXIT {result.returncode}\n")
    if result.returncode != 0:
        raise EvidenceError(f"git command failed with exit {result.returncode}")
    return result.stdout


def _parse_submodule_status(output: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    pattern = re.compile(r" ([0-9a-f]{40}) (.+?)(?: \([^\r\n]*\))?$")
    for line in output.splitlines():
        match = pattern.fullmatch(line)
        if match is None:
            raise EvidenceError(
                "recursive submodule is uninitialized, drifted, conflicted, or malformed"
            )
        revision, path = match.groups()
        entries.append(
            {"path": _require_relative(path, "submodule path"), "revision": revision}
        )
    entries.sort(key=lambda entry: entry["path"])
    if not entries or len({entry["path"] for entry in entries}) != len(entries):
        raise EvidenceError("recursive submodule identity is empty or duplicated")
    return entries


def _submodule_identity(
    project: dict[str, Any],
    project_root: Path,
    deadline: float,
    log_path: Path,
) -> dict[str, Any]:
    expected = _expected_submodules(project)
    mode = expected["mode"]
    git_env = os.environ.copy()
    git_env["GIT_ALLOW_PROTOCOL"] = "https"
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    stage = _capture_git(
        ["git", "ls-files", "--stage"],
        project_root,
        deadline,
        project["memory_mb"],
        log_path,
        git_env,
    )
    gitlinks = [line for line in stage.splitlines() if line.startswith("160000 ")]
    if mode == "none":
        if gitlinks:
            raise EvidenceError("project has undeclared gitlink submodules")
        return expected

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
        result = _run_command(
            command,
            project_root,
            deadline,
            project["memory_mb"],
            log_path,
            env=git_env,
        )
        if result.returncode != 0:
            raise EvidenceError(
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
    entries = _parse_submodule_status(status)

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
        raise EvidenceError("recursive submodule checkout is not clean")

    actual = {
        "mode": mode,
        "count": len(entries),
        "sha256": digest_json(entries),
    }
    if actual != expected:
        raise EvidenceError("recursive submodule identity does not match the manifest")
    return actual


def _derive_translation_units(
    project: dict[str, Any], source: Path, build: Path, compile_database: Path
) -> tuple[list[Path], list[str]]:
    try:
        database = json.loads(compile_database.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"compile database unavailable: {compile_database}: {error}") from error
    if not isinstance(database, list):
        raise EvidenceError("compile database root is not an array")
    roots = [_inside(source, source / root, "source root") for root in project["sources"]["roots"]]
    extensions = set(project["sources"]["extensions"])
    selected: dict[str, Path] = {}
    for entry in database:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise EvidenceError("compile database contains a malformed entry")
        directory = Path(entry.get("directory", build))
        file_path = Path(entry["file"])
        if not file_path.is_absolute():
            file_path = directory / file_path
        resolved = file_path.resolve()
        if resolved.suffix not in extensions or not any(
            resolved == root or root in resolved.parents for root in roots
        ):
            continue
        _inside(source, resolved, "compile database source")
        relative = resolved.relative_to(source.resolve()).as_posix()
        selected[relative] = resolved
    for pattern in project["sources"]["fallback_globs"]:
        matches = sorted(source.glob(pattern))
        if not matches:
            raise EvidenceError(f"fallback glob matched no translation unit: {pattern}")
        for file_path in matches:
            resolved = _inside(source, file_path, "fallback source")
            if not resolved.is_file() or resolved.suffix not in extensions:
                raise EvidenceError(f"fallback is not an admitted source: {file_path}")
            selected[resolved.relative_to(source.resolve()).as_posix()] = resolved
    if not selected:
        raise EvidenceError("derived translation-unit list is empty")
    relative_paths = sorted(selected)
    return [selected[path] for path in relative_paths], relative_paths


def filter_target_translation_units(
    command_output: str,
    source: Path,
    build: Path,
    files: list[Path],
    relative_files: list[str],
) -> tuple[list[Path], list[str]]:
    if len(files) != len(relative_files):
        raise EvidenceError("translation-unit identity is malformed")
    source_root = source.resolve()
    for path in files:
        resolved = path.resolve()
        if resolved != source_root and source_root not in resolved.parents:
            raise EvidenceError(
                "translation-unit identity escapes the pinned source tree"
            )
    admitted = {
        path.resolve(): (path, relative)
        for path, relative in zip(files, relative_files, strict=True)
    }
    target_sources: set[Path] = set()
    for line in command_output.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError as error:
            raise EvidenceError(
                f"Ninja target closure contains an invalid command: {error}"
            ) from error
        compile_indexes = [index for index, token in enumerate(tokens) if token == "-c"]
        if not compile_indexes:
            continue
        if len(compile_indexes) != 1:
            raise EvidenceError(
                "Ninja target closure contains an ambiguous compile command"
            )
        command_sources: set[Path] = set()
        for token in tokens:
            if token.startswith("-"):
                continue
            path = Path(token)
            if not path.is_absolute():
                path = build / path
            resolved = path.resolve()
            if resolved in admitted:
                command_sources.add(resolved)
        if len(command_sources) > 1:
            raise EvidenceError(
                "Ninja target closure contains an ambiguous compile source"
            )
        target_sources.update(command_sources)

    selected = sorted(
        (relative, path)
        for resolved, (path, relative) in admitted.items()
        if resolved in target_sources
    )
    if not selected:
        raise EvidenceError(
            "Ninja target closure selected no admitted translation units"
        )
    return [path for _, path in selected], [relative for relative, _ in selected]


def run_shard(
    manifest: dict[str, Any],
    project_id: str,
    repetition: int,
    analyzer: Path,
    workspace: Path,
    output: Path,
    checkpoint: Path | None,
    repository_root: Path,
) -> int:
    project = project_by_id(manifest, project_id)
    if repetition < 1 or repetition > 3:
        raise ManifestError("repetition identity is outside the admitted range")
    analyzer = analyzer.resolve()
    if not analyzer.is_file():
        raise EvidenceError(f"analyzer unavailable: {analyzer}")
    analyzer_sha = file_digest(analyzer)
    expected_submodules = _expected_submodules(project)
    expected_identity = receipt_identity(
        manifest,
        project,
        repetition,
        analyzer_sha,
        project["expected"]["translation_unit_sha256"],
        expected_submodules,
    )
    started = time.monotonic()
    output.parent.mkdir(parents=True, exist_ok=True)
    if checkpoint is not None and checkpoint.is_file() and _sidecar(checkpoint).is_file():
        try:
            prior = load_verified_receipt(checkpoint)
            if checkpoint_matches(prior, expected_identity):
                resumed = copy.deepcopy(prior)
                resumed["execution"] = {"duration_seconds": 0.0, "resumed": True}
                write_receipt(output, resumed)
                return 0
        except EvidenceError:
            pass

    semantic: dict[str, Any] | None = None
    actual_tu_sha = project["expected"]["translation_unit_sha256"]
    actual_submodules = expected_submodules
    failures: list[str] = []
    log_path = output.parent / "commands.log"
    if log_path.exists():
        log_path.unlink()
    deadline = started + project["timeout_minutes"] * 60
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        project_root = _inside(workspace, workspace / project_id, "project workspace")
        if project_root.exists():
            shutil.rmtree(project_root)
        project_root.mkdir(parents=True)
        build = _inside(project_root, project_root / "build-codeskeptic", "project build")
        values = {"source": str(project_root), "build": str(build), "jobs": "2"}
        for command in (
            ["git", "init", "--quiet"],
            ["git", "remote", "add", "origin", project["repository"]],
            ["git", "fetch", "--quiet", "--depth", "1", "origin", project["revision"]],
            ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        ):
            result = _run_command(command, project_root, deadline, project["memory_mb"], log_path)
            if result.returncode != 0:
                raise EvidenceError(f"checkout command failed with exit {result.returncode}")
        resolved_revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if resolved_revision != project["revision"]:
            raise EvidenceError(
                f"checkout revision mismatch {resolved_revision} != {project['revision']}"
            )
        actual_submodules = _submodule_identity(
            project,
            project_root,
            deadline,
            log_path,
        )

        for operation in project["copies"]:
            source_file = _inside(repository_root, repository_root / operation["from"], "copy source")
            destination = _inside(project_root, project_root / operation["to"], "copy destination")
            if not source_file.is_file():
                raise EvidenceError(f"copy source unavailable: {operation['from']}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, destination)
        for group in ("configure", "build"):
            for command in project["commands"][group]:
                result = _run_command(
                    _expand(command, values),
                    project_root,
                    deadline,
                    project["memory_mb"],
                    log_path,
                )
                if result.returncode != 0:
                    raise EvidenceError(f"{group} command failed with exit {result.returncode}")
        compile_database = Path(project["compile_database"].format(**values))
        files, relative_files = _derive_translation_units(
            project, project_root, build, compile_database
        )
        ninja_target = None
        for build_command in project["commands"]["build"]:
            expanded_build_command = _expand(build_command, values)
            if "--target" not in expanded_build_command:
                continue
            target_index = expanded_build_command.index("--target")
            if target_index + 1 >= len(expanded_build_command):
                raise EvidenceError("build target is missing")
            ninja_target = expanded_build_command[target_index + 1]
            break
        target_commands = ""
        if ninja_target is not None:
            target_commands = _capture_git(
                ["ninja", "-C", str(build), "-t", "commands", ninja_target],
                project_root,
                deadline,
                project["memory_mb"],
                log_path,
                None,
            )
        if target_commands:
            files, relative_files = filter_target_translation_units(
                target_commands, project_root, build, files, relative_files
            )
        actual_tu_sha = translation_unit_digest(relative_files)
        file_list = output.parent / "translation-units.txt"
        file_list.write_text(
            "\n".join(str(path) for path in files) + "\n", encoding="utf-8", newline="\n"
        )
        (output.parent / "translation-units.relative.txt").write_text(
            "\n".join(relative_files) + "\n", encoding="utf-8", newline="\n"
        )
        if target_commands:
            if (
                len(files) != project["expected"]["translation_units"]
                or actual_tu_sha != project["expected"]["translation_unit_sha256"]
            ):
                raise EvidenceError(
                    "translation-unit expectation drift: "
                    f"count={len(files)} sha256={actual_tu_sha}"
                )
        report_path = output.parent / "report.json"
        analyzer_command = [
            str(analyzer),
            "--files",
            str(file_list),
            "--build-path",
            str(build),
            "--json",
            str(report_path),
            *_expand(project["analyzer_args"], values),
        ]
        result = _run_command(
            analyzer_command,
            repository_root,
            deadline,
            project["memory_mb"],
            log_path,
        )
        if not report_path.is_file():
            raise EvidenceError(f"analyzer did not write report (exit {result.returncode})")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise EvidenceError(f"analyzer report is malformed: {error}") from error
        semantic = _report_semantic(
            result.returncode, report, len(files), actual_tu_sha
        )
        _validate_semantic(project, semantic)
    except (CampaignError, OSError, subprocess.SubprocessError) as error:
        failures.append(str(error))

    identity = receipt_identity(
        manifest,
        project,
        repetition,
        analyzer_sha,
        actual_tu_sha,
        actual_submodules,
    )
    accepted = not failures and semantic is not None
    receipt = {
        "schema": SCHEMA,
        "status": "accepted" if accepted else "unavailable",
        "project": project_id,
        "repetition": repetition,
        "identity": identity,
        "semantic": semantic,
        "execution": {
            "duration_seconds": round(time.monotonic() - started, 3),
            "resumed": False,
        },
        "failures": failures or ([] if accepted else ["missing semantic evidence"]),
    }
    write_receipt(output, receipt)
    if accepted and checkpoint is not None:
        write_receipt(checkpoint, receipt)
    return 0 if accepted else 2


def _default_manifest() -> Path:
    return Path(__file__).with_name("realworld_manifest.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="validate and print a shard matrix")
    plan.add_argument("--manifest", type=Path, default=_default_manifest())
    plan.add_argument("--tier", default="nightly")

    run = subparsers.add_parser("run", help="execute one project repetition")
    run.add_argument("--manifest", type=Path, default=_default_manifest())
    run.add_argument("--project", required=True)
    run.add_argument("--repetition", required=True, type=int)
    run.add_argument("--analyzer", required=True, type=Path)
    run.add_argument("--workspace", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--checkpoint", type=Path)
    run.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])

    aggregate = subparsers.add_parser("aggregate", help="verify all campaign receipts")
    aggregate.add_argument("--manifest", type=Path, default=_default_manifest())
    aggregate.add_argument("--tier", default="nightly")
    aggregate.add_argument("--receipts", required=True, type=Path)
    aggregate.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = validate_manifest(load_manifest(args.manifest))
        if args.command == "plan":
            print(json.dumps(plan_matrix(manifest, args.tier), sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "run":
            return run_shard(
                manifest,
                args.project,
                args.repetition,
                args.analyzer,
                args.workspace,
                args.output,
                args.checkpoint,
                args.repository_root,
            )
        summary = aggregate_receipts(manifest, args.tier, args.receipts)
        write_receipt(args.output, summary)
        print(
            f"REALWORLD_CAMPAIGN_OK campaign={args.tier} "
            f"projects={len(summary['projects'])} repetitions=3"
        )
        return 0
    except CampaignError as error:
        if args.command == "run":
            write_receipt(
                args.output,
                {
                    "schema": SCHEMA,
                    "status": "unavailable",
                    "project": args.project,
                    "repetition": args.repetition,
                    "identity": None,
                    "semantic": None,
                    "execution": {"duration_seconds": 0.0, "resumed": False},
                    "failures": [str(error)],
                },
            )
        elif args.command == "aggregate":
            write_receipt(
                args.output,
                {
                    "schema": SCHEMA,
                    "status": "unavailable",
                    "campaign": args.tier,
                    "projects": {},
                    "failures": [str(error)],
                },
            )
        print(f"REALWORLD_CAMPAIGN_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
