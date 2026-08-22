#!/usr/bin/env python3
"""Run and verify the deterministic Phase 10 frontend/CFG stress matrix."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tests" / "stress_corpus" / "manifest.json"
SCHEMA = "codeskeptic-stress-receipt-v1"
MANIFEST_SCHEMA = "codeskeptic-stress-matrix-v1"
EXPECTED_CASES = {
    "template-instantiation": "template",
    "template-dependent-pattern": "template",
    "template-malformed": "malformed-source",
    "nested-macro-expansion": "macro",
    "high-complexity-cfg": "high-cfg",
    "malformed-source": "malformed-source",
    "mixed-clean-broken": "mixed-coverage",
    "broken-recovery-opt-in": "broken-recovery",
    "missing-requested-tu": "missing-request",
}
ALLOWED_ARGS = {"--analyze-broken-tus", "--accept-partial-coverage"}
SOURCE_ROOTS = (
    ROOT / "CMakeLists.txt",
    ROOT / ".gitattributes",
    ROOT / ".github" / "workflows",
    ROOT / "Dockerfile",
    ROOT / "action.yml",
    ROOT / "src",
    ROOT / "fuzz",
    ROOT / "scripts",
    ROOT / "tests",
    ROOT / "docs",
    ROOT / "profiles",
)
IGNORED_SOURCE_PARTS = {"__pycache__"}
IGNORED_SOURCE_SUFFIXES = {".pyc", ".pyo"}
IGNORED_SOURCE_PREFIXES = (
    "docs/evidence/",
    "docs/devlog/changelog.md",
)


class MatrixError(RuntimeError):
    """The stress matrix cannot produce accepted evidence."""


def canonical_json(payload: Any) -> bytes:
    return (
        json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON key: {key}")
        payload[key] = value
    return payload


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _strict_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise MatrixError(f"cannot load {label}: {error}") from error


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_files(paths: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file():
            files.add(path)
        elif path.is_dir():
            for candidate in path.rglob("*"):
                if not candidate.is_file():
                    continue
                relative = candidate.relative_to(ROOT)
                if (IGNORED_SOURCE_PARTS.intersection(relative.parts) or
                        candidate.suffix in IGNORED_SOURCE_SUFFIXES or
                        any(relative.as_posix().startswith(prefix)
                            for prefix in IGNORED_SOURCE_PREFIXES)):
                    continue
                files.add(candidate)
        else:
            raise MatrixError(f"source manifest path is missing: {path}")
    return sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())


def source_manifest() -> dict[str, Any]:
    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in _regular_files(SOURCE_ROOTS)
    ]
    return {
        "algorithm": "sha256",
        "file_count": len(entries),
        "digest": sha256_bytes(canonical_json(entries)),
    }


def _git_environment() -> dict[str, str]:
    admitted = {
        "COMSPEC", "LANG", "LC_ALL", "PATH", "PATHEXT", "SYSTEMROOT",
        "SystemRoot", "TEMP", "TMP", "TZ", "WINDIR",
    }
    environment = {
        key: value for key, value in os.environ.items() if key in admitted
    }
    environment.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(ROOT.resolve()),
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": os.devnull,
        "GIT_CONFIG_KEY_2": "core.fsmonitor",
        "GIT_CONFIG_VALUE_2": "false",
        "GIT_CONFIG_KEY_3": "core.commitGraph",
        "GIT_CONFIG_VALUE_3": "false",
    })
    return environment


def _manifest_path_admitted(relative: str) -> bool:
    path = Path(relative)
    if (
        IGNORED_SOURCE_PARTS.intersection(path.parts)
        or path.suffix in IGNORED_SOURCE_SUFFIXES
        or any(relative.startswith(prefix) for prefix in IGNORED_SOURCE_PREFIXES)
    ):
        return False
    roots = [path.relative_to(ROOT).as_posix() for path in SOURCE_ROOTS]
    return any(relative == root or relative.startswith(root + "/") for root in roots)


def source_manifest_at_revision(revision: str) -> dict[str, Any]:
    """Re-derive a historical stress source manifest from immutable Git blobs."""
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise MatrixError("stress source revision is malformed")
    environment = _git_environment()
    tree = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", revision],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if tree.returncode != 0:
        raise MatrixError("cannot enumerate stress source revision")
    entries: list[dict[str, str]] = []
    for record in tree.stdout.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise MatrixError("stress source tree entry is malformed") from error
        if not _manifest_path_admitted(relative):
            continue
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise MatrixError(f"stress source entry is unsafe: {relative}")
        blob = subprocess.run(
            ["git", "cat-file", "blob", oid],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        if blob.returncode != 0:
            raise MatrixError(f"cannot read stress source blob: {relative}")
        entries.append({
            "path": relative,
            "sha256": sha256_bytes(blob.stdout),
        })
    entries.sort(key=lambda item: item["path"])
    if not entries:
        raise MatrixError("stress source revision has no admitted files")
    return {
        "algorithm": "sha256",
        "file_count": len(entries),
        "digest": sha256_bytes(canonical_json(entries)),
    }


def _inside_repo(relative: str, root: Path) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise MatrixError(f"fixture escapes repository: {relative}") from error
    if Path(relative).is_absolute() or Path(relative).as_posix() != relative:
        raise MatrixError(f"fixture path is not canonical: {relative}")
    return candidate


def _validate_expected(expected: Any, case_id: str) -> None:
    required = {
        "exit_code", "status", "complete", "coverage", "required_rules",
        "required_functions", "forbidden_functions",
    }
    if not isinstance(expected, dict) or set(expected) != required:
        raise MatrixError(f"{case_id}: invalid expected outcome fields")
    if expected["exit_code"] not in {0, 1, 2}:
        raise MatrixError(f"{case_id}: invalid expected exit")
    if expected["status"] not in {"clean", "findings", "incomplete", "failed"}:
        raise MatrixError(f"{case_id}: invalid expected status")
    if not isinstance(expected["complete"], bool):
        raise MatrixError(f"{case_id}: expected complete must be boolean")
    coverage = expected["coverage"]
    coverage_keys = {
        "attempted_tus", "analyzed_tus", "broken_tus",
        "incomplete_functions",
    }
    if (not isinstance(coverage, dict) or set(coverage) != coverage_keys or
            any(not isinstance(value, int) or value < 0
                for value in coverage.values())):
        raise MatrixError(f"{case_id}: invalid expected coverage")
    for key in ("required_rules", "required_functions", "forbidden_functions"):
        values = expected[key]
        if (not isinstance(values, list) or len(values) != len(set(values)) or
                any(not isinstance(value, str) or not value for value in values)):
            raise MatrixError(f"{case_id}: invalid {key}")


def load_manifest(path: Path = MANIFEST_PATH,
                  root: Path = ROOT) -> dict[str, Any]:
    root = root.resolve()
    path = path.resolve()
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise MatrixError(f"cannot load stress manifest: {error}") from error
    payload = _strict_json(raw, "stress manifest")
    if not isinstance(payload, dict) or set(payload) != {
            "schema", "repetitions", "timeout_seconds", "cases"}:
        raise MatrixError("unexpected stress manifest fields")
    if payload["schema"] != MANIFEST_SCHEMA:
        raise MatrixError("unsupported stress manifest schema")
    if payload["repetitions"] != 2:
        raise MatrixError("stress matrix must run exactly two repetitions")
    if payload["timeout_seconds"] != 30:
        raise MatrixError("stress timeout must remain a 30-second tripwire")
    if not isinstance(payload["cases"], list):
        raise MatrixError("stress cases must be an array")

    seen: set[str] = set()
    bound_sources: set[str] = set()
    for case in payload["cases"]:
        if not isinstance(case, dict) or set(case) != {
                "id", "category", "sources", "missing_sources", "args",
                "expected"}:
            raise MatrixError("invalid stress case fields")
        case_id = case["id"]
        if (not isinstance(case_id, str) or case_id in seen or
                EXPECTED_CASES.get(case_id) != case["category"]):
            raise MatrixError(f"unexpected or duplicate stress case: {case_id}")
        seen.add(case_id)
        if not isinstance(case["sources"], list) or not case["sources"]:
            raise MatrixError(f"{case_id}: sources must be non-empty")
        names: set[str] = set()
        for source in case["sources"]:
            if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
                raise MatrixError(f"{case_id}: invalid source identity")
            relative = source["path"]
            if (not isinstance(relative, str) or
                    not relative.startswith("tests/stress_corpus/") or
                    relative in bound_sources):
                raise MatrixError(f"{case_id}: duplicate or invalid source path")
            fixture = _inside_repo(relative, root)
            if (not fixture.is_file() or fixture.is_symlink() or
                    sha256_file(fixture) != source["sha256"]):
                raise MatrixError(f"{case_id}: fixture checksum mismatch: {relative}")
            if fixture.name in names:
                raise MatrixError(f"{case_id}: duplicate fixture basename")
            names.add(fixture.name)
            bound_sources.add(relative)
        missing = case["missing_sources"]
        if (not isinstance(missing, list) or len(missing) != len(set(missing)) or
                any(not isinstance(value, str) for value in missing)):
            raise MatrixError(f"{case_id}: invalid missing_sources")
        for relative in missing:
            absent = _inside_repo(relative, root)
            if (not relative.startswith("tests/stress_corpus/") or
                    absent.exists() or absent.name in names):
                raise MatrixError(f"{case_id}: invalid missing fixture: {relative}")
            names.add(absent.name)
        args = case["args"]
        if (not isinstance(args, list) or len(args) != len(set(args)) or
                any(value not in ALLOWED_ARGS for value in args)):
            raise MatrixError(f"{case_id}: invalid analyzer args")
        _validate_expected(case["expected"], case_id)

    if seen != set(EXPECTED_CASES):
        raise MatrixError("stress case matrix differs from fixed PLAN boundary")
    actual_sources = {
        path.relative_to(root).as_posix()
        for path in (root / "tests" / "stress_corpus").glob("*.cpp")
        if path.is_file()
    }
    if actual_sources != bound_sources:
        raise MatrixError("stress corpus files and manifest identities differ")
    return payload


def _git_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_git_environment(),
    )
    commit = completed.stdout.strip()
    if completed.returncode != 0 or len(commit) != 40:
        raise MatrixError("cannot resolve source commit")
    return commit


def _git_commit_is_ancestor(base: str, head: str) -> bool:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, head], cwd=ROOT,
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=_git_environment(),
    )
    return completed.returncode == 0


def _resolve_source_manifest_revision(
    base: str,
    head: str,
    manifest: Any,
    *,
    expected_revision: str | None = None,
) -> str:
    """Resolve the committed source snapshot represented by a stress receipt."""
    if (
        re.fullmatch(r"[0-9a-f]{40}", base) is None
        or re.fullmatch(r"[0-9a-f]{40}", head) is None
        or not _git_commit_is_ancestor(base, head)
    ):
        raise MatrixError("stress source commit is not in current ancestry")
    if expected_revision is not None:
        if (
            re.fullmatch(r"[0-9a-f]{40}", expected_revision) is None
            or not _git_commit_is_ancestor(base, expected_revision)
            or not _git_commit_is_ancestor(expected_revision, head)
            or source_manifest_at_revision(expected_revision) != manifest
        ):
            raise MatrixError("stress source differs from expected campaign source")
        return expected_revision

    completed = subprocess.run(
        ["git", "rev-list", "--ancestry-path", "--reverse", f"{base}..{head}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        raise MatrixError("cannot enumerate stress source ancestry")
    candidates = [base, *completed.stdout.splitlines()]
    for revision in candidates:
        if source_manifest_at_revision(revision) == manifest:
            return revision
    raise MatrixError("stress source bytes are absent from current ancestry")


def _binary_identity(binary: Path) -> dict[str, str]:
    binary = binary.resolve()
    if not binary.is_file():
        raise MatrixError(f"missing analyzer binary: {binary}")
    completed = subprocess.run(
        [str(binary), "--version"], check=False, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
    )
    version = completed.stdout.strip()
    if completed.returncode != 0 or not version.startswith("CodeSkeptic "):
        raise MatrixError("analyzer --version tripwire failed")
    return {"sha256": sha256_file(binary), "version": version}


def _projection(report: dict[str, Any], process_exit: int) -> dict[str, Any]:
    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise MatrixError("stress report lacks diagnostics")
    projected_diagnostics = sorted([
        {
            "severity": diag.get("severity"),
            "rule_id": diag.get("rule_id"),
            "blocks_verdict": diag.get("blocks_verdict"),
            "line": diag.get("line"),
            "column": diag.get("column"),
            "function": diag.get("function"),
        }
        for diag in diagnostics
    ], key=lambda item: canonical_json(item))
    return {
        "process_exit": process_exit,
        "report_exit": report.get("exit_code"),
        "status": report.get("status"),
        "complete": report.get("complete"),
        "coverage": report.get("coverage"),
        "finding_counts": report.get("finding_counts"),
        "diagnostics": projected_diagnostics,
    }


def _assert_expected(case: dict[str, Any], projection: dict[str, Any]) -> None:
    expected = case["expected"]
    case_id = case["id"]
    if (projection["process_exit"] != expected["exit_code"] or
            projection["report_exit"] != expected["exit_code"] or
            projection["status"] != expected["status"] or
            projection["complete"] != expected["complete"] or
            projection["coverage"] != expected["coverage"]):
        raise MatrixError(f"{case_id}: observed verdict differs from manifest")
    diagnostics = projection["diagnostics"]
    rules = {diag["rule_id"] for diag in diagnostics}
    if not set(expected["required_rules"]).issubset(rules):
        raise MatrixError(f"{case_id}: required seeded rule was not reported")
    functions = [str(diag["function"]) for diag in diagnostics]
    for required in expected["required_functions"]:
        if not any(required in function for function in functions):
            raise MatrixError(f"{case_id}: seeded function was not reported")
    for forbidden in expected["forbidden_functions"]:
        if any(forbidden in function for function in functions):
            raise MatrixError(f"{case_id}: clean twin produced a finding")


def _write_case_inputs(case: dict[str, Any], work: Path) -> list[Path]:
    requested: list[Path] = []
    for source in case["sources"]:
        destination = work / Path(source["path"]).name
        shutil.copyfile(ROOT / source["path"], destination)
        requested.append(destination)
    requested.extend(work / Path(path).name for path in case["missing_sources"])
    commands = [
        {
            "directory": str(work),
            "arguments": [
                "clang++", "-std=c++17", "-fsyntax-only", str(source),
            ],
            "file": str(source),
        }
        for source in requested
    ]
    (work / "compile_commands.json").write_bytes(canonical_json(commands))
    (work / "files.txt").write_text(
        "".join(f"{source}\n" for source in requested), encoding="utf-8",
    )
    return requested


def _receipt_command(case: dict[str, Any]) -> list[str]:
    return [
        "$BINARY", "--files", "$WORK/files.txt",
        "--build-path", "$WORK", "--json", "$REPORT",
        *case["args"],
    ]


def run_matrix(binary: Path, *, output: Path,
               manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    binary = binary.resolve()
    identity = _binary_identity(binary)
    manifest = load_manifest(manifest_path)
    output = output.resolve()
    corpus_root = (ROOT / "tests" / "stress_corpus").resolve()
    if (output == ROOT or output == corpus_root or
            output in corpus_root.parents or corpus_root in output.parents):
        raise MatrixError("stress output overlaps a protected source root")
    if output.exists() and any(output.iterdir()):
        raise MatrixError("stress output directory must be absent or empty")
    (output / "logs").mkdir(parents=True, exist_ok=True)
    (output / "reports").mkdir(parents=True, exist_ok=True)

    started = dt.datetime.now(dt.timezone.utc)
    case_receipts: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="codeskeptic-stress-") as tmp:
        scratch = Path(tmp)
        for case in manifest["cases"]:
            case_runs: list[dict[str, Any]] = []
            semantic_digests: set[str] = set()
            for repetition in range(1, manifest["repetitions"] + 1):
                work = scratch / case["id"] / f"repeat-{repetition}"
                work.mkdir(parents=True)
                _write_case_inputs(case, work)
                report = output / "reports" / f"{case['id']}-{repetition}.json"
                log = output / "logs" / f"{case['id']}-{repetition}.log"
                command = [
                    str(binary), "--files", str(work / "files.txt"),
                    "--build-path", str(work), "--json", str(report),
                    *case["args"],
                ]
                env = os.environ.copy()
                env.update({"LC_ALL": "C", "LANG": "C"})
                begin = time.monotonic()
                try:
                    completed = subprocess.run(
                        command, cwd=work, env=env, check=False,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=manifest["timeout_seconds"],
                    )
                    log.write_bytes(completed.stdout)
                except subprocess.TimeoutExpired as error:
                    partial = error.stdout if isinstance(error.stdout, bytes) else b""
                    log.write_bytes(partial + b"\nTIMEOUT\n")
                    raise MatrixError(f"{case['id']}: analyzer timeout") from error
                duration_ms = round((time.monotonic() - begin) * 1000)
                try:
                    report_payload = json.loads(report.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise MatrixError(f"{case['id']}: invalid JSON report") from error
                projection = _projection(report_payload, completed.returncode)
                _assert_expected(case, projection)
                semantic_digest = sha256_bytes(canonical_json(projection))
                semantic_digests.add(semantic_digest)
                case_runs.append({
                    "repetition": repetition,
                    "duration_ms": duration_ms,
                    "command": _receipt_command(case),
                    "log": log.relative_to(output).as_posix(),
                    "log_sha256": sha256_file(log),
                    "report": report.relative_to(output).as_posix(),
                    "report_sha256": sha256_file(report),
                    "projection": projection,
                    "semantic_sha256": semantic_digest,
                })
            if len(semantic_digests) != 1:
                raise MatrixError(f"{case['id']}: repeated semantics drifted")
            case_receipts.append({
                "id": case["id"],
                "category": case["category"],
                "runs": case_runs,
                "stable_semantic_sha256": next(iter(semantic_digests)),
            })

    finished = dt.datetime.now(dt.timezone.utc)
    receipt = {
        "schema": SCHEMA,
        "status": "accepted",
        "source": {
            "base_commit": _git_commit(),
            "manifest": source_manifest(),
        },
        "matrix": {
            "path": manifest_path.resolve().relative_to(ROOT).as_posix(),
            "sha256": sha256_file(manifest_path),
        },
        "analyzer": identity,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": round((finished - started).total_seconds() * 1000),
        "summary": {
            "accepted_cases": len(case_receipts),
            "repetitions_per_case": manifest["repetitions"],
            "timeouts": 0,
            "crashes": 0,
        },
        "cases": case_receipts,
    }
    (output / "receipt.json").write_bytes(canonical_json(receipt))
    return receipt


def _safe_evidence_file(output: Path, relative: str) -> Path:
    candidate = (output / relative).resolve()
    try:
        candidate.relative_to(output)
    except ValueError as error:
        raise MatrixError(f"evidence path escapes receipt: {relative}") from error
    if not candidate.is_file() or candidate.is_symlink():
        raise MatrixError(f"missing or unsafe evidence file: {relative}")
    return candidate


def _validated_receipt_duration(receipt: dict[str, Any]) -> None:
    try:
        started = dt.datetime.fromisoformat(receipt["started_at"])
        finished = dt.datetime.fromisoformat(receipt["finished_at"])
    except (TypeError, ValueError) as error:
        raise MatrixError("invalid stress receipt timestamps") from error
    if (started.utcoffset() != dt.timedelta(0) or
            finished.utcoffset() != dt.timedelta(0) or finished < started):
        raise MatrixError("invalid stress receipt time interval")
    duration_ms = receipt["duration_ms"]
    expected_ms = round((finished - started).total_seconds() * 1000)
    if (type(duration_ms) is not int or duration_ms < 0 or
            duration_ms != expected_ms):
        raise MatrixError("invalid stress receipt duration")


def _validated_analyzer_identity(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"sha256", "version"}
        or not isinstance(value["sha256"], str)
        or len(value["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in value["sha256"])
        or not isinstance(value["version"], str)
        or not value["version"].startswith("CodeSkeptic ")
        or "\x00" in value["version"]
    ):
        raise MatrixError("invalid analyzer identity")
    return value


def verify_receipt_with_identity(
    receipt_path: Path,
    analyzer_identity: dict[str, str],
    manifest_path: Path = MANIFEST_PATH,
    *,
    expected_source_revision: str | None = None,
) -> dict[str, Any]:
    """Verify retained semantics against an externally authenticated analyzer."""
    analyzer_identity = _validated_analyzer_identity(analyzer_identity)
    receipt_path = receipt_path.resolve()
    output = receipt_path.parent
    try:
        receipt_raw = receipt_path.read_bytes()
    except OSError as error:
        raise MatrixError(f"cannot load stress receipt: {error}") from error
    receipt = _strict_json(receipt_raw, "stress receipt")
    required = {
        "schema", "status", "source", "matrix", "analyzer", "host",
        "started_at", "finished_at", "duration_ms", "summary", "cases",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise MatrixError("invalid stress receipt fields")
    if receipt_raw != canonical_json(receipt):
        raise MatrixError("stress receipt is not canonical JSON")
    if receipt["schema"] != SCHEMA or receipt["status"] != "accepted":
        raise MatrixError("stress receipt is not accepted")
    _validated_receipt_duration(receipt)
    host = receipt["host"]
    if (not isinstance(host, dict) or
            set(host) != {"platform", "machine", "python"} or
            any(not isinstance(value, str) or not value
                for value in host.values())):
        raise MatrixError("invalid stress host identity")
    manifest = load_manifest(manifest_path)
    if receipt["matrix"] != {
            "path": manifest_path.resolve().relative_to(ROOT).as_posix(),
            "sha256": sha256_file(manifest_path)}:
        raise MatrixError("stress manifest identity drift")
    source = receipt["source"]
    if not isinstance(source, dict) or set(source) != {"base_commit", "manifest"}:
        raise MatrixError("invalid stress source identity")
    current_commit = _git_commit()
    if not isinstance(source["base_commit"], str):
        raise MatrixError("stress source bytes differ from receipt")
    _resolve_source_manifest_revision(
        source["base_commit"],
        current_commit,
        source["manifest"],
        expected_revision=expected_source_revision,
    )
    if receipt["analyzer"] != analyzer_identity:
        raise MatrixError("stress analyzer identity drift")
    if receipt["summary"] != {
            "accepted_cases": len(EXPECTED_CASES),
            "repetitions_per_case": manifest["repetitions"],
            "timeouts": 0,
            "crashes": 0}:
        raise MatrixError("invalid stress receipt summary")
    cases = receipt["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_CASES):
        raise MatrixError("invalid stress receipt cases")
    manifest_by_id = {case["id"]: case for case in manifest["cases"]}
    seen: set[str] = set()
    for case_receipt in cases:
        if not isinstance(case_receipt, dict) or set(case_receipt) != {
                "id", "category", "runs", "stable_semantic_sha256"}:
            raise MatrixError("invalid retained case fields")
        case_id = case_receipt["id"]
        if case_id in seen or case_id not in manifest_by_id:
            raise MatrixError("duplicate or unknown retained stress case")
        seen.add(case_id)
        case = manifest_by_id[case_id]
        if case_receipt["category"] != case["category"]:
            raise MatrixError(f"{case_id}: retained category drift")
        runs = case_receipt["runs"]
        if not isinstance(runs, list) or len(runs) != manifest["repetitions"]:
            raise MatrixError(f"{case_id}: retained repetition count drift")
        digests: set[str] = set()
        for index, run in enumerate(runs, 1):
            required_run = {
                "repetition", "duration_ms", "command", "log", "log_sha256",
                "report", "report_sha256", "projection", "semantic_sha256",
            }
            if not isinstance(run, dict) or set(run) != required_run:
                raise MatrixError(f"{case_id}: invalid retained run fields")
            if (run["repetition"] != index or
                    type(run["duration_ms"]) is not int or
                    run["duration_ms"] < 0 or
                    run["command"] != _receipt_command(case)):
                raise MatrixError(f"{case_id}: invalid retained run metadata")
            log = _safe_evidence_file(output, run["log"])
            report = _safe_evidence_file(output, run["report"])
            if (sha256_file(log) != run["log_sha256"] or
                    sha256_file(report) != run["report_sha256"]):
                raise MatrixError(f"{case_id}: retained evidence checksum mismatch")
            try:
                report_raw = report.read_bytes()
            except OSError as error:
                raise MatrixError(f"{case_id}: retained report is invalid") from error
            report_payload = _strict_json(
                report_raw, f"{case_id} retained report"
            )
            projection = _projection(report_payload, run["projection"]["process_exit"])
            if projection != run["projection"]:
                raise MatrixError(f"{case_id}: retained projection drift")
            _assert_expected(case, projection)
            digest = sha256_bytes(canonical_json(projection))
            if digest != run["semantic_sha256"]:
                raise MatrixError(f"{case_id}: semantic checksum mismatch")
            digests.add(digest)
        if (len(digests) != 1 or
                case_receipt["stable_semantic_sha256"] not in digests):
            raise MatrixError(f"{case_id}: repeated semantics are not stable")
    if seen != set(EXPECTED_CASES):
        raise MatrixError("retained stress case set is incomplete")
    return receipt


def verify_receipt(receipt_path: Path, binary: Path,
                   manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return verify_receipt_with_identity(
        receipt_path,
        _binary_identity(binary),
        manifest_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-receipt", type=Path)
    args = parser.parse_args()
    try:
        if (args.output is None) == (args.verify_receipt is None):
            raise MatrixError("choose exactly one of --output or --verify-receipt")
        if args.verify_receipt is not None:
            verify_receipt(args.verify_receipt, args.binary)
            print("stress receipt accepted")
        else:
            run_matrix(args.binary, output=args.output)
            print("stress matrix accepted")
    except MatrixError as error:
        print(f"stress matrix rejected: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
