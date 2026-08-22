#!/usr/bin/env python3
"""Build and verify the fail-closed Phase 10 cumulative quality receipt.

The input is a normalized campaign manifest. Diagnostic true positives are
used only for precision. Addressable recall is deliberately computed from
case/file outcomes so a large diagnostic count cannot conceal missed cases.

Inner schema validation cannot establish provenance by assertion alone. The
``exact_head``/``fresh`` assertion does not prove how the run was launched.
This module does not rebuild the source or analyzer; their supplied identities
and the input hash only bind those claims.
An accepted receipt additionally requires the input's sibling
``RAW_SHA256SUMS``: its exact bytes, entry count, every retained regular file,
and every globally unique ``raw_sha256`` evidence identity are revalidated.
Callers using :func:`build_receipt` directly must provide ``artifacts_root``;
omitting it deliberately produces an unavailable/rejected receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CAPABILITY_REGISTRY = ROOT / "src" / "core" / "RuleCapabilities.def"
RAW_MANIFEST_NAME = "RAW_SHA256SUMS"
MAX_RAW_MANIFEST_BYTES = 1024 * 1024
INPUT_SCHEMA = "codeskeptic-quality-floor-input-v1"
RECEIPT_SCHEMA = "codeskeptic-quality-floor-receipt-v1"
EXPECTED_RULES = (
    "memory-leak",
    "double-free",
    "use-after-free",
    "resource-leak",
    "div-by-zero",
    "null-deref",
    "int-overflow",
)
REQUESTED_TU_KINDS = ("broken", "missing")
PER_RULE_PRECISION_PERCENT = 85
MICRO_PRECISION_PERCENT = 90
ADDRESSABLE_RECALL_PERCENT = 70
REQUIRED_CLEAN_CASES = 9

SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]*")
RAW_MANIFEST_ENTRY = re.compile(r"([0-9a-f]{64})  (.+)")
CAPABILITY_ENTRY = re.compile(
    r'^CODESKEPTIC_RULE_CAPABILITY\("([^"]+)", '
    r'(Supported|Experimental), (true|false), (true|false), '
    r'(true|false), "[^"]*"\)$'
)


class QualityFloorError(RuntimeError):
    """A receipt could not be produced or independently verified."""


class ManifestUnavailable(QualityFloorError):
    """Input evidence is malformed or incomplete and supports no verdict."""


def canonical_json(payload: Any) -> bytes:
    return (
        json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON key: {key}")
        payload[key] = value
    return payload


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _strict_json_loads(raw: bytes) -> Any:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )


def receipt_checksum_path(receipt_path: Path) -> Path:
    return receipt_path.with_name(receipt_path.name + ".sha256")


def capability_registry_identity() -> dict[str, Any]:
    """Return the exact current quality-gated default set and registry hash."""
    try:
        raw = CAPABILITY_REGISTRY.read_bytes()
        lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ManifestUnavailable(
            f"cannot read capability registry: {error}"
        ) from error
    seen: set[str] = set()
    quality_defaults: list[str] = []
    for line_no, line in enumerate(lines, 1):
        entry = line.strip()
        if not entry.startswith("CODESKEPTIC_RULE_CAPABILITY"):
            continue
        match = CAPABILITY_ENTRY.fullmatch(entry)
        if match is None:
            raise ManifestUnavailable(
                f"malformed capability registry entry at line {line_no}"
            )
        rule_id, tier, default, quality, blocking = match.groups()
        if rule_id in seen:
            raise ManifestUnavailable(
                f"duplicate capability registry rule: {rule_id}"
            )
        seen.add(rule_id)
        if tier == "Supported":
            if (default, quality, blocking) != ("true", "true", "true"):
                raise ManifestUnavailable(
                    f"supported capability is not quality-gated: {rule_id}"
                )
            quality_defaults.append(rule_id)
        elif quality != "false" or blocking != "false":
            raise ManifestUnavailable(
                f"experimental capability gates quality or verdict: {rule_id}"
            )
    if tuple(quality_defaults) != EXPECTED_RULES:
        raise ManifestUnavailable(
            "current registry is not the exact seven supported "
            "quality-gated defaults"
        )
    return {"sha256": sha256_bytes(raw), "rules": list(quality_defaults)}


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ManifestUnavailable(f"{label} fields are missing, extra, or malformed")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ManifestUnavailable(f"{label} is not an array")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ManifestUnavailable(f"{label} is not an integer >= {minimum}")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ManifestUnavailable(f"{label} is not a lowercase SHA-256")
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ManifestUnavailable(f"{label} is not a canonical identifier")
    return value


def _coverage(value: Any, label: str) -> dict[str, int]:
    payload = _object(
        value,
        {
            "attempted_tus",
            "analyzed_tus",
            "broken_tus",
            "incomplete_functions",
        },
        label,
    )
    return {
        field: _integer(payload[field], f"{label}.{field}")
        for field in (
            "attempted_tus",
            "analyzed_tus",
            "broken_tus",
            "incomplete_functions",
        )
    }


def _identity(value: Any) -> dict[str, Any]:
    payload = _object(
        value,
        {"source", "analyzer", "capabilities", "retained_artifacts"},
        "identity",
    )
    source = _object(
        payload["source"], {"revision", "manifest_sha256"}, "identity.source"
    )
    revision = source["revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ManifestUnavailable("identity.source.revision is not an exact revision")

    analyzer = _object(
        payload["analyzer"], {"version", "binary_sha256"}, "identity.analyzer"
    )
    version = analyzer["version"]
    if (
        not isinstance(version, str)
        or not version.startswith("CodeSkeptic ")
        or version.strip() != version
        or len(version) == len("CodeSkeptic ")
    ):
        raise ManifestUnavailable("identity.analyzer.version is malformed")

    capabilities = _object(
        payload["capabilities"],
        {"registry_sha256", "supported_quality_gated_default_rules"},
        "identity.capabilities",
    )
    capability_rules = _array(
        capabilities["supported_quality_gated_default_rules"],
        "identity.capabilities.supported_quality_gated_default_rules",
    )
    if any(not isinstance(item, str) for item in capability_rules):
        raise ManifestUnavailable("capability rule set contains a malformed id")
    if len(capability_rules) != len(set(capability_rules)):
        raise ManifestUnavailable("capability rule set contains a duplicate")
    if set(capability_rules) != set(EXPECTED_RULES):
        raise ManifestUnavailable(
            "capability rule set is not the exact seven supported "
            "quality-gated defaults"
        )
    current_capabilities = capability_registry_identity()
    registry_sha256 = _hash(
        capabilities["registry_sha256"],
        "identity.capabilities.registry_sha256",
    )
    if registry_sha256 != current_capabilities["sha256"]:
        raise ManifestUnavailable("capability registry hash differs from this source")

    artifacts = _object(
        payload["retained_artifacts"],
        {"manifest_path", "manifest_sha256", "file_count"},
        "identity.retained_artifacts",
    )
    if artifacts["manifest_path"] != RAW_MANIFEST_NAME:
        raise ManifestUnavailable(
            f"retained artifact manifest must be sibling {RAW_MANIFEST_NAME}"
        )
    file_count = _integer(
        artifacts["file_count"], "identity.retained_artifacts.file_count", 1
    )
    return {
        "source": {
            "revision": revision,
            "manifest_sha256": _hash(
                source["manifest_sha256"], "identity.source.manifest_sha256"
            ),
        },
        "analyzer": {
            "version": version,
            "binary_sha256": _hash(
                analyzer["binary_sha256"], "identity.analyzer.binary_sha256"
            ),
        },
        "capabilities": {
            "registry_sha256": registry_sha256,
            "supported_quality_gated_default_rules": current_capabilities["rules"],
        },
        "retained_artifacts": {
            "manifest_path": RAW_MANIFEST_NAME,
            "manifest_sha256": _hash(
                artifacts["manifest_sha256"],
                "identity.retained_artifacts.manifest_sha256",
            ),
            "file_count": file_count,
        },
    }


def _rules(value: Any) -> list[dict[str, Any]]:
    rows = _array(value, "rules")
    if len(rows) != len(EXPECTED_RULES):
        raise ManifestUnavailable("rule evidence does not contain exactly seven rows")
    normalized: dict[str, dict[str, Any]] = {}
    raw_hashes: set[str] = set()
    for index, item in enumerate(rows):
        label = f"rules[{index}]"
        row = _object(
            item,
            {
                "id",
                "corpus",
                "exact_head",
                "fresh",
                "raw_sha256",
                "diagnostics",
                "cases",
            },
            label,
        )
        rule_id = _id(row["id"], f"{label}.id")
        if rule_id in normalized:
            raise ManifestUnavailable(f"duplicate rule evidence: {rule_id}")
        if rule_id not in EXPECTED_RULES:
            raise ManifestUnavailable(f"unexpected quality-gated rule: {rule_id}")
        expected_corpus = (
            "resource-leak-mutation" if rule_id == "resource-leak" else "juliet"
        )
        if row["corpus"] != expected_corpus:
            raise ManifestUnavailable(f"{rule_id}: wrong measurement corpus")
        if row["exact_head"] is not True:
            raise ManifestUnavailable(f"{rule_id}: evidence is not exact-head")
        if row["fresh"] is not True:
            raise ManifestUnavailable(f"{rule_id}: evidence is not fresh")

        diagnostics = _object(
            row["diagnostics"],
            {"true_positives", "false_positives"},
            f"{label}.diagnostics",
        )
        true_positives = _integer(
            diagnostics["true_positives"], f"{rule_id}.true_positives"
        )
        false_positives = _integer(
            diagnostics["false_positives"], f"{rule_id}.false_positives"
        )
        if true_positives + false_positives == 0:
            raise ManifestUnavailable(
                f"{rule_id}: diagnostic precision has a zero denominator"
            )

        cases = _object(row["cases"], {"files", "misses"}, f"{label}.cases")
        files = _integer(cases["files"], f"{rule_id}.case_files", 1)
        misses = _object(
            cases["misses"],
            {"total", "addressable", "model_gap", "out_of_scope"},
            f"{label}.cases.misses",
        )
        normalized_misses = {
            key: _integer(misses[key], f"{rule_id}.misses.{key}")
            for key in ("total", "addressable", "model_gap", "out_of_scope")
        }
        classified = sum(
            normalized_misses[key]
            for key in ("addressable", "model_gap", "out_of_scope")
        )
        if classified != normalized_misses["total"]:
            raise ManifestUnavailable(f"{rule_id}: malformed miss partition")
        if normalized_misses["total"] > files:
            raise ManifestUnavailable(f"{rule_id}: misses exceed measured case files")

        raw_sha256 = _hash(row["raw_sha256"], f"{rule_id}.raw_sha256")
        if raw_sha256 in raw_hashes:
            raise ManifestUnavailable("duplicate raw rule evidence")
        raw_hashes.add(raw_sha256)
        normalized[rule_id] = {
            "id": rule_id,
            "corpus": expected_corpus,
            "exact_head": True,
            "fresh": True,
            "raw_sha256": raw_sha256,
            "diagnostics": {
                "true_positives": true_positives,
                "false_positives": false_positives,
            },
            "cases": {"files": files, "misses": normalized_misses},
        }
    if set(normalized) != set(EXPECTED_RULES):
        raise ManifestUnavailable("rule evidence set is missing a supported default")
    return [normalized[rule_id] for rule_id in EXPECTED_RULES]


def _clean_corpus(value: Any) -> list[dict[str, Any]]:
    payload = _object(value, {"cases"}, "clean_corpus")
    cases = _array(payload["cases"], "clean_corpus.cases")
    if len(cases) != REQUIRED_CLEAN_CASES:
        raise ManifestUnavailable("clean corpus is not exactly 9/9 cases")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(cases):
        label = f"clean_corpus.cases[{index}]"
        case = _object(
            item,
            {
                "id",
                "process_exit",
                "report_exit",
                "complete",
                "coverage",
                "findings",
                "raw_sha256",
            },
            label,
        )
        case_id = _id(case["id"], f"{label}.id")
        if case_id in seen:
            raise ManifestUnavailable(f"duplicate clean corpus case: {case_id}")
        seen.add(case_id)
        evidence_coverage = _coverage(case["coverage"], f"{case_id}.coverage")
        if (
            type(case["process_exit"]) is not int
            or case["process_exit"] != 0
            or type(case["report_exit"]) is not int
            or case["report_exit"] != 0
            or case["complete"] is not True
            or evidence_coverage
            != {
                "attempted_tus": 1,
                "analyzed_tus": 1,
                "broken_tus": 0,
                "incomplete_functions": 0,
            }
            or _integer(case["findings"], f"{case_id}.findings") != 0
        ):
            raise ManifestUnavailable(
                f"{case_id}: clean run is unavailable, incomplete, or non-clean"
            )
        normalized.append(
            {
                "id": case_id,
                "process_exit": 0,
                "report_exit": 0,
                "complete": True,
                "coverage": evidence_coverage,
                "findings": 0,
                "raw_sha256": _hash(
                    case["raw_sha256"], f"{case_id}.raw_sha256"
                ),
            }
        )
    return sorted(normalized, key=lambda item: item["id"])


def _requested_tu_negatives(value: Any) -> list[dict[str, Any]]:
    payload = _object(value, {"cases"}, "requested_tu_negatives")
    cases = _array(payload["cases"], "requested_tu_negatives.cases")
    if len(cases) != len(REQUESTED_TU_KINDS):
        raise ManifestUnavailable(
            "requested-TU evidence must contain broken and missing negatives"
        )
    normalized: dict[str, dict[str, Any]] = {}
    ids: set[str] = set()
    for index, item in enumerate(cases):
        label = f"requested_tu_negatives.cases[{index}]"
        case = _object(
            item,
            {
                "id",
                "kind",
                "process_exit",
                "report_exit",
                "complete",
                "verdict",
                "coverage",
                "raw_sha256",
            },
            label,
        )
        case_id = _id(case["id"], f"{label}.id")
        kind = case["kind"]
        if case_id in ids:
            raise ManifestUnavailable(f"duplicate requested-TU case: {case_id}")
        ids.add(case_id)
        if kind not in REQUESTED_TU_KINDS or kind in normalized:
            raise ManifestUnavailable("duplicate or unexpected requested-TU kind")
        if (
            type(case["process_exit"]) is not int
            or case["process_exit"] != 2
            or type(case["report_exit"]) is not int
            or case["report_exit"] != 2
            or case["complete"] is not False
            or case["verdict"] is not None
        ):
            raise ManifestUnavailable(
                f"{case_id}: requested-TU failure produced or could produce a verdict"
            )
        evidence_coverage = _coverage(case["coverage"], f"{case_id}.coverage")
        attempted = evidence_coverage["attempted_tus"]
        analyzed = evidence_coverage["analyzed_tus"]
        broken = evidence_coverage["broken_tus"]
        if attempted < 1 or analyzed > attempted or broken > attempted:
            raise ManifestUnavailable(f"{case_id}: malformed requested-TU coverage")
        if kind == "missing" and not (analyzed < attempted and broken == 0):
            raise ManifestUnavailable(
                f"{case_id}: missing requested TU is not retained as unprocessed"
            )
        if kind == "broken" and broken < 1:
            raise ManifestUnavailable(
                f"{case_id}: broken requested TU is not retained as broken"
            )
        normalized[kind] = {
            "id": case_id,
            "kind": kind,
            "process_exit": 2,
            "report_exit": 2,
            "complete": False,
            "verdict": None,
            "coverage": evidence_coverage,
            "raw_sha256": _hash(case["raw_sha256"], f"{case_id}.raw_sha256"),
        }
    if set(normalized) != set(REQUESTED_TU_KINDS):
        raise ManifestUnavailable(
            "requested-TU evidence does not cover broken and missing inputs"
        )
    return [normalized[kind] for kind in REQUESTED_TU_KINDS]


def _evidence_raw_hashes(
    rules: list[dict[str, Any]],
    clean_cases: list[dict[str, Any]],
    requested_tu_cases: list[dict[str, Any]],
) -> list[str]:
    labelled = [
        (f"rule {row['id']}", row["raw_sha256"])
        for row in rules
    ]
    labelled.extend(
        (f"clean case {case['id']}", case["raw_sha256"])
        for case in clean_cases
    )
    labelled.extend(
        (f"requested-TU case {case['id']}", case["raw_sha256"])
        for case in requested_tu_cases
    )
    seen: dict[str, str] = {}
    for label, digest in labelled:
        previous = seen.get(digest)
        if previous is not None:
            raise ManifestUnavailable(
                f"raw evidence hash is reused by {previous} and {label}"
            )
        seen[digest] = label
    return [digest for _label, digest in labelled]


def _stat_time_ns(metadata: os.stat_result, field: str) -> int:
    nanoseconds = getattr(metadata, field + "_ns", None)
    if nanoseconds is not None:
        return int(nanoseconds)
    return int(float(getattr(metadata, field)) * 1_000_000_000)


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        _stat_time_ns(metadata, "st_mtime"),
        _stat_time_ns(metadata, "st_ctime"),
    )


def _inspect_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int | None = None,
    collect: bool,
) -> tuple[str, bytes | None]:
    """Hash one no-follow regular-file snapshot from a single opened FD.

    The leaf is checked with ``lstat`` before and after the read, while the
    opened file is checked with ``fstat`` before and after it. ``O_NOFOLLOW``
    is used where the platform supplies it. Retained-path directory components
    are separately rejected when observed as symlinks. A fully pinned openat
    directory walk is intentionally not used because it is not portable to
    Windows; concurrent replacement of an already checked directory component
    is the residual namespace boundary.
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        path_before = os.lstat(path)
        if stat.S_ISLNK(path_before.st_mode):
            raise ManifestUnavailable(f"{label} is a symbolic link")
        if not stat.S_ISREG(path_before.st_mode):
            raise ManifestUnavailable(f"{label} is not a regular file")
        if path_before.st_nlink != 1:
            raise ManifestUnavailable(f"{label} has external hard links")
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            raise ManifestUnavailable(f"{label} is not a regular file")
        if opened_before.st_nlink != 1:
            raise ManifestUnavailable(f"{label} has external hard links")
        if (
            path_before.st_dev,
            path_before.st_ino,
        ) != (
            opened_before.st_dev,
            opened_before.st_ino,
        ):
            raise ManifestUnavailable(f"{label} changed while being opened")
        if max_bytes is not None and opened_before.st_size > max_bytes:
            raise ManifestUnavailable(f"{label} is too large")

        digest = hashlib.sha256()
        retained = bytearray() if collect else None
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if max_bytes is not None and total > max_bytes:
                raise ManifestUnavailable(f"{label} is too large")
            digest.update(block)
            if retained is not None:
                retained.extend(block)

        opened_after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if (
            _stat_fingerprint(opened_before)
            != _stat_fingerprint(opened_after)
            or _stat_fingerprint(opened_after)
            != _stat_fingerprint(path_after)
            or total != opened_after.st_size
        ):
            raise ManifestUnavailable(f"{label} changed while being read")
        return digest.hexdigest(), bytes(retained) if retained is not None else None
    except ManifestUnavailable:
        raise
    except OSError as error:
        raise ManifestUnavailable(f"cannot read {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _retained_file(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if (
        not relative
        or "\\" in relative
        or pure.is_absolute()
        or pure.as_posix() != relative
        or any(part in {"", ".", ".."} for part in pure.parts)
        or relative == RAW_MANIFEST_NAME
    ):
        raise ManifestUnavailable(
            f"retained artifact path is not canonical: {relative!r}"
        )
    candidate = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ManifestUnavailable(
                f"cannot inspect retained artifact path {relative}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ManifestUnavailable(
                f"retained artifact path traverses a symlink: {relative}"
            )
    return candidate


def _checked_directory(path: Path, label: str) -> Path:
    """Return an absolute directory path with no observed symlink component."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise ManifestUnavailable(f"cannot inspect {label}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ManifestUnavailable(f"{label} traverses a symbolic link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ManifestUnavailable(f"{label} is not a directory")
    return absolute


def _verify_retained_artifacts(
    identity: dict[str, Any],
    artifacts_root: Path | None,
    evidence_hashes: list[str],
) -> dict[str, Any]:
    if artifacts_root is None:
        raise ManifestUnavailable(
            "retained artifact files were not externally verified"
        )
    root = _checked_directory(artifacts_root, "retained artifact root")
    retained = identity["retained_artifacts"]
    manifest_path = root / retained["manifest_path"]
    try:
        manifest_sha256, raw = _inspect_regular_file(
            manifest_path,
            f"retained artifact manifest {RAW_MANIFEST_NAME}",
            max_bytes=MAX_RAW_MANIFEST_BYTES,
            collect=True,
        )
        assert raw is not None
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ManifestUnavailable(
            f"cannot read retained artifact manifest: {error}"
        ) from error
    if manifest_sha256 != retained["manifest_sha256"]:
        raise ManifestUnavailable("retained artifact manifest hash mismatch")
    if not raw or not raw.endswith(b"\n") or b"\r" in raw:
        raise ManifestUnavailable("retained artifact manifest is not canonical")

    entries: list[tuple[str, str]] = []
    paths: set[str] = set()
    digest_counts: dict[str, int] = {}
    for line_no, line in enumerate(text.splitlines(), 1):
        match = RAW_MANIFEST_ENTRY.fullmatch(line)
        if match is None:
            raise ManifestUnavailable(
                f"malformed retained artifact manifest line {line_no}"
            )
        expected_sha256, relative = match.groups()
        if relative in paths:
            raise ManifestUnavailable(
                f"duplicate retained artifact manifest path: {relative}"
            )
        paths.add(relative)
        path = _retained_file(root, relative)
        artifact_sha256, _unused = _inspect_regular_file(
            path,
            f"retained artifact {relative}",
            collect=False,
        )
        if artifact_sha256 != expected_sha256:
            raise ManifestUnavailable(
                f"retained artifact file hash mismatch: {relative}"
            )
        entries.append((relative, expected_sha256))
        digest_counts[expected_sha256] = digest_counts.get(expected_sha256, 0) + 1
    if [path for path, _digest in entries] != sorted(paths):
        raise ManifestUnavailable("retained artifact manifest paths are not sorted")
    if len(entries) != retained["file_count"]:
        raise ManifestUnavailable(
            "retained artifact file_count differs from manifest entries"
        )
    for digest in evidence_hashes:
        if digest_counts.get(digest) != 1:
            raise ManifestUnavailable(
                "retained artifact manifest does not bind each raw evidence hash"
            )
    return {
        "manifest_path": RAW_MANIFEST_NAME,
        "manifest_sha256": retained["manifest_sha256"],
        "file_count": len(entries),
        "evidence_file_count": len(evidence_hashes),
    }


def _metrics(
    rules: list[dict[str, Any]],
    clean_cases: list[dict[str, Any]],
    requested_tu_cases: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    gate_failures: list[str] = []
    rule_metrics: list[dict[str, Any]] = []
    total_tp = 0
    total_diagnostics = 0
    total_case_tp = 0
    total_addressable_fn = 0
    for row in rules:
        rule_id = row["id"]
        tp = row["diagnostics"]["true_positives"]
        fp = row["diagnostics"]["false_positives"]
        denominator = tp + fp
        precision_passed = (
            tp * 100 >= PER_RULE_PRECISION_PERCENT * denominator
        )
        if not precision_passed:
            gate_failures.append(
                f"{rule_id}: per-rule precision below "
                f"{PER_RULE_PRECISION_PERCENT}%"
            )
        misses = row["cases"]["misses"]
        case_tp = row["cases"]["files"] - misses["total"]
        addressable_fn = misses["addressable"]
        rule_metrics.append(
            {
                "id": rule_id,
                "diagnostic_precision": {
                    "numerator": tp,
                    "denominator": denominator,
                    "threshold_percent": PER_RULE_PRECISION_PERCENT,
                    "passed": precision_passed,
                },
                "case_recall_components": {
                    "case_true_positives": case_tp,
                    "addressable_false_negatives": addressable_fn,
                },
            }
        )
        total_tp += tp
        total_diagnostics += denominator
        total_case_tp += case_tp
        total_addressable_fn += addressable_fn

    if total_diagnostics == 0:
        raise ManifestUnavailable("micro precision has a zero denominator")
    micro_passed = total_tp * 100 >= MICRO_PRECISION_PERCENT * total_diagnostics
    if not micro_passed:
        gate_failures.append(
            f"micro precision below {MICRO_PRECISION_PERCENT}%"
        )

    recall_denominator = total_case_tp + total_addressable_fn
    if recall_denominator == 0:
        raise ManifestUnavailable("addressable recall has a zero denominator")
    recall_passed = (
        total_case_tp * 100
        >= ADDRESSABLE_RECALL_PERCENT * recall_denominator
    )
    if not recall_passed:
        gate_failures.append(
            f"case-level addressable recall below {ADDRESSABLE_RECALL_PERCENT}%"
        )
    return {
        "rules": rule_metrics,
        "micro_precision": {
            "numerator": total_tp,
            "denominator": total_diagnostics,
            "threshold_percent": MICRO_PRECISION_PERCENT,
            "passed": micro_passed,
        },
        "addressable_recall": {
            "numerator": total_case_tp,
            "denominator": recall_denominator,
            "addressable_false_negatives": total_addressable_fn,
            "threshold_percent": ADDRESSABLE_RECALL_PERCENT,
            "passed": recall_passed,
        },
        "clean_corpus": {
            "accepted_cases": len(clean_cases),
            "required_cases": REQUIRED_CLEAN_CASES,
            "passed": len(clean_cases) == REQUIRED_CLEAN_CASES,
        },
        "requested_tu_negatives": {
            "accepted_cases": len(requested_tu_cases),
            "required_kinds": list(REQUESTED_TU_KINDS),
            "passed": {case["kind"] for case in requested_tu_cases}
            == set(REQUESTED_TU_KINDS),
        },
    }, gate_failures


def build_receipt(
    manifest: Any,
    *,
    input_sha256: str,
    input_bytes: int,
    parse_error: str | None = None,
    artifacts_root: Path | None = None,
) -> dict[str, Any]:
    """Build a receipt; acceptance requires externally checked artifacts_root."""
    if SHA256.fullmatch(input_sha256) is None:
        raise QualityFloorError("input_sha256 is not a lowercase SHA-256")
    if type(input_bytes) is not int or input_bytes < 0:
        raise QualityFloorError("input_bytes is not a non-negative integer")
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "status": "rejected",
        "availability": "unavailable",
        "input": {
            "schema": manifest.get("schema") if isinstance(manifest, dict) else None,
            "sha256": input_sha256,
            "bytes": input_bytes,
        },
        "identity": None,
        "retained_artifact_verification": None,
        "metrics": None,
        "failures": [],
    }
    if parse_error is not None:
        receipt["failures"] = [f"unavailable: malformed input JSON: {parse_error}"]
        return receipt

    normalized_identity: dict[str, Any] | None = None
    try:
        payload = _object(
            manifest,
            {
                "schema",
                "identity",
                "rules",
                "clean_corpus",
                "requested_tu_negatives",
            },
            "input",
        )
        if payload["schema"] != INPUT_SCHEMA:
            raise ManifestUnavailable("unsupported quality-floor input schema")
        normalized_identity = _identity(payload["identity"])
        receipt["identity"] = normalized_identity
        rules = _rules(payload["rules"])
        clean_cases = _clean_corpus(payload["clean_corpus"])
        requested_tu_cases = _requested_tu_negatives(
            payload["requested_tu_negatives"]
        )
        evidence_hashes = _evidence_raw_hashes(
            rules, clean_cases, requested_tu_cases
        )
        artifact_verification = _verify_retained_artifacts(
            normalized_identity, artifacts_root, evidence_hashes
        )
        metrics, gate_failures = _metrics(rules, clean_cases, requested_tu_cases)
    except ManifestUnavailable as error:
        receipt["failures"] = [f"unavailable: {error}"]
        return receipt

    receipt["availability"] = "available"
    receipt["retained_artifact_verification"] = artifact_verification
    receipt["metrics"] = metrics
    receipt["failures"] = gate_failures
    if not gate_failures:
        receipt["status"] = "accepted"
    return receipt


def _read_public_regular(path: Path, label: str) -> bytes:
    _check_output_path(path, label)
    _digest, raw = _inspect_regular_file(path, label, collect=True)
    assert raw is not None
    return raw


def _read_input(input_path: Path) -> tuple[bytes, Any, str | None]:
    raw = _read_public_regular(input_path, "quality-floor input")
    try:
        payload = _strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        return raw, None, str(error)
    return raw, payload, None


def _receipt_from_input(input_path: Path) -> dict[str, Any]:
    raw, payload, parse_error = _read_input(input_path)
    return build_receipt(
        payload,
        input_sha256=sha256_bytes(raw),
        input_bytes=len(raw),
        parse_error=parse_error,
        artifacts_root=input_path.resolve().parent,
    )


def _protected_output_paths(input_path: Path) -> list[Path]:
    """Return input, manifest, and parseable retained paths for output guards."""
    root = input_path.resolve().parent
    manifest_path = root / RAW_MANIFEST_NAME
    protected = [input_path, manifest_path]
    try:
        _manifest_digest, raw = _inspect_regular_file(
            manifest_path,
            f"retained artifact manifest {RAW_MANIFEST_NAME}",
            max_bytes=MAX_RAW_MANIFEST_BYTES,
            collect=True,
        )
        assert raw is not None
        lines = raw.decode("utf-8").splitlines()
    except (ManifestUnavailable, UnicodeDecodeError):
        return protected
    for line in lines:
        match = RAW_MANIFEST_ENTRY.fullmatch(line)
        if match is None:
            continue
        try:
            protected.append(_retained_file(root, match.group(2)))
        except ManifestUnavailable:
            continue
    return protected


def _normalized_path(path: Path, *, resolve: bool) -> str:
    value = os.path.realpath(path) if resolve else os.path.abspath(path)
    return os.path.normcase(os.path.normpath(value))


def _paths_alias(first: Path, second: Path) -> bool:
    if _normalized_path(first, resolve=False) == _normalized_path(
        second, resolve=False
    ):
        return True
    if _normalized_path(first, resolve=True) == _normalized_path(
        second, resolve=True
    ):
        return True
    try:
        first_metadata = os.lstat(first)
        second_metadata = os.lstat(second)
    except OSError:
        return False
    return (
        first_metadata.st_dev,
        first_metadata.st_ino,
    ) == (
        second_metadata.st_dev,
        second_metadata.st_ino,
    )


def _check_output_path(path: Path, label: str) -> None:
    """Reject every currently observable symlink in an output path."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    remaining = absolute.parts[1:]
    for index, part in enumerate(remaining):
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise QualityFloorError(f"cannot inspect {label}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise QualityFloorError(f"{label} traverses a symbolic link")
        is_leaf = index == len(remaining) - 1
        if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
            raise QualityFloorError(f"{label} parent is not a directory")
        if is_leaf and not stat.S_ISREG(metadata.st_mode):
            raise QualityFloorError(f"{label} is not a regular file")


def _validate_output_targets(
    receipt_path: Path, protected_paths: list[Path]
) -> None:
    outputs = (
        ("receipt output", receipt_path),
        ("receipt checksum output", receipt_checksum_path(receipt_path)),
    )
    for label, output in outputs:
        _check_output_path(output, label)
        for protected in protected_paths:
            if _paths_alias(output, protected):
                raise QualityFloorError(
                    f"{label} aliases protected campaign input or evidence"
                )
    if _paths_alias(outputs[0][1], outputs[1][1]):
        raise QualityFloorError("receipt and checksum outputs alias each other")


def _atomic_temp(path: Path, data: bytes) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _fsync_directory(path: Path) -> None:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not directory_flag:
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | directory_flag | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_receipt(
    receipt_path: Path,
    receipt: dict[str, Any],
    protected_paths: list[Path],
) -> None:
    checksum_path = receipt_checksum_path(receipt_path)
    _validate_output_targets(receipt_path, protected_paths)
    try:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise QualityFloorError(
            f"cannot create receipt output directory: {error}"
        ) from error
    _validate_output_targets(receipt_path, protected_paths)

    data = canonical_json(receipt)
    checksum = f"{sha256_bytes(data)}  {receipt_path.name}\n".encode("utf-8")
    receipt_temporary: Path | None = None
    checksum_temporary: Path | None = None
    try:
        receipt_temporary = _atomic_temp(receipt_path, data)
        checksum_temporary = _atomic_temp(checksum_path, checksum)
        _validate_output_targets(receipt_path, protected_paths)
        os.replace(receipt_temporary, receipt_path)
        receipt_temporary = None
        os.replace(checksum_temporary, checksum_path)
        checksum_temporary = None
        _fsync_directory(receipt_path.parent)
    except QualityFloorError:
        raise
    except OSError as error:
        raise QualityFloorError(
            f"cannot atomically write quality-floor receipt: {error}"
        ) from error
    finally:
        if receipt_temporary is not None:
            receipt_temporary.unlink(missing_ok=True)
        if checksum_temporary is not None:
            checksum_temporary.unlink(missing_ok=True)


def generate_receipt(input_path: Path, receipt_path: Path) -> dict[str, Any]:
    _check_output_path(input_path, "quality-floor input")
    protected_paths = _protected_output_paths(input_path)
    _validate_output_targets(receipt_path, protected_paths)
    receipt = _receipt_from_input(input_path)
    protected_paths = _protected_output_paths(input_path)
    _write_receipt(receipt_path, receipt, protected_paths)
    return receipt


def verify_receipt(
    receipt_path: Path,
    input_path: Path,
    *,
    require_accepted: bool = True,
) -> dict[str, Any]:
    try:
        data = _read_public_regular(receipt_path, "quality-floor receipt")
        checksum_raw = _read_public_regular(
            receipt_checksum_path(receipt_path),
            "quality-floor receipt checksum",
        )
        checksum = checksum_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualityFloorError(
            "quality-floor receipt checksum is not UTF-8"
        ) from error
    expected_checksum = f"{sha256_bytes(data)}  {receipt_path.name}\n"
    if checksum != expected_checksum:
        raise QualityFloorError("quality-floor receipt checksum mismatch")
    try:
        receipt = _strict_json_loads(data)
    except (UnicodeDecodeError, ValueError) as error:
        raise QualityFloorError("quality-floor receipt is malformed") from error
    if not isinstance(receipt, dict):
        raise QualityFloorError("quality-floor receipt is not a JSON object")
    if data != canonical_json(receipt):
        raise QualityFloorError("quality-floor receipt is not canonical JSON")
    expected = _receipt_from_input(input_path)
    if receipt.get("status") == "accepted" and expected["status"] == "rejected":
        raise QualityFloorError(expected["failures"][0])
    if receipt != expected:
        raise QualityFloorError(
            "quality-floor receipt differs from the input-derived decision"
        )
    if require_accepted and receipt["status"] != "accepted":
        raise QualityFloorError("quality-floor receipt is rejected")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--verify-receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.output is not None:
            receipt = generate_receipt(args.input, args.output)
            if receipt["status"] != "accepted":
                print(
                    "QUALITY_FLOOR_REJECTED " + "; ".join(receipt["failures"]),
                    file=sys.stderr,
                )
                return 2
            print("QUALITY_FLOOR_ACCEPTED")
        else:
            verify_receipt(args.verify_receipt, args.input)
            print("QUALITY_FLOOR_RECEIPT_VERIFIED")
    except QualityFloorError as error:
        print(f"QUALITY_FLOOR_REJECTED {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
