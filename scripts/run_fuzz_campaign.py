#!/usr/bin/env python3
"""Run the bounded parser-fuzz matrix and retain a checksummed receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_PATH = ROOT / "fuzz" / "campaign.json"
CORPUS_ROOT = ROOT / "fuzz" / "corpus"
CORPUS_CHECKSUMS = CORPUS_ROOT / "SHA256SUMS"
RECEIPT_SCHEMA = "codeskeptic-fuzz-receipt-v1"
EXPECTED_MODES = {
    "smoke": {"runs_per_target": 256, "wall_timeout_seconds": 120},
    "extended": {"runs_per_target": 10000, "wall_timeout_seconds": 900},
}
EXPECTED_TARGETS = [
    {"id": "config", "binary": "codeskeptic_fuzz_config",
     "corpus": "config", "seed": 1001},
    {"id": "compile_database",
     "binary": "codeskeptic_fuzz_compile_database",
     "corpus": "compile_database", "seed": 1002},
    {"id": "summary", "binary": "codeskeptic_fuzz_summary",
     "corpus": "summary", "seed": 1003},
    {"id": "mcp_json_rpc", "binary": "codeskeptic_fuzz_mcp_json_rpc",
     "corpus": "mcp_json_rpc", "seed": 1004},
]
SOURCE_ROOTS = (
    ROOT / "CMakeLists.txt",
    ROOT / "src",
    ROOT / "fuzz",
    ROOT / "scripts" / "run_fuzz_campaign.py",
)


class CampaignError(RuntimeError):
    """The campaign cannot produce accepted evidence."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def _regular_files(paths: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file():
            files.add(path)
        elif path.is_dir():
            files.update(candidate for candidate in path.rglob("*")
                         if candidate.is_file())
        else:
            raise CampaignError(f"source manifest path is missing: {path}")
    return sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())


def source_manifest() -> dict[str, Any]:
    entries = []
    for path in _regular_files(SOURCE_ROOTS):
        relative = path.relative_to(ROOT).as_posix()
        entries.append({"path": relative, "sha256": sha256_file(path)})
    encoded = canonical_json(entries)
    return {
        "algorithm": "sha256",
        "file_count": len(entries),
        "digest": sha256_bytes(encoded),
    }


def load_campaign() -> dict[str, Any]:
    try:
        campaign = json.loads(CAMPAIGN_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CampaignError(f"cannot load fuzz campaign: {error}") from error
    if campaign.get("schema") != "codeskeptic-fuzz-campaign-v1":
        raise CampaignError("unsupported fuzz campaign schema")
    if set(campaign) != {
        "schema", "max_input_bytes", "input_timeout_seconds", "rss_limit_mb",
        "modes", "targets",
    }:
        raise CampaignError("unexpected fuzz campaign fields")
    if not isinstance(campaign["max_input_bytes"], int) or not (
            1 <= campaign["max_input_bytes"] <= 1024 * 1024):
        raise CampaignError("invalid max_input_bytes")
    if not isinstance(campaign["input_timeout_seconds"], int) or not (
            1 <= campaign["input_timeout_seconds"] <= 60):
        raise CampaignError("invalid input_timeout_seconds")
    if campaign["rss_limit_mb"] != 2048:
        raise CampaignError("rss_limit_mb must remain exactly 2048")
    if campaign["modes"] != EXPECTED_MODES:
        raise CampaignError("fuzz campaign budgets differ from the fixed matrix")
    if campaign["targets"] != EXPECTED_TARGETS:
        raise CampaignError("fuzz target matrix differs from the PLAN boundary")
    for target in campaign["targets"]:
        if (Path(target["binary"]).name != target["binary"] or
                Path(target["corpus"]).name != target["corpus"]):
            raise CampaignError("fuzz target paths must be single components")
        corpus = CORPUS_ROOT / target["corpus"]
        if not corpus.is_dir() or not any(path.is_file()
                                          for path in corpus.iterdir()):
            raise CampaignError(f"empty or missing corpus: {target['id']}")
    return campaign


def load_corpus_checksums() -> dict[str, str]:
    try:
        lines = CORPUS_CHECKSUMS.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise CampaignError(f"cannot load corpus checksums: {error}") from error
    entries: dict[str, str] = {}
    for line in lines:
        digest, separator, relative = line.partition("  ")
        if (not separator or len(digest) != 64 or
                any(char not in "0123456789abcdef" for char in digest)):
            raise CampaignError("malformed corpus checksum line")
        if relative in entries:
            raise CampaignError(f"duplicate corpus checksum: {relative}")
        entries[relative] = digest
    actual = {
        path.relative_to(CORPUS_ROOT).as_posix()
        for path in CORPUS_ROOT.rglob("*")
        if path.is_file() and path != CORPUS_CHECKSUMS
    }
    if actual != set(entries):
        raise CampaignError("corpus files and checksum manifest differ")
    for relative, expected in entries.items():
        if sha256_file(CORPUS_ROOT / relative) != expected:
            raise CampaignError(f"corpus checksum mismatch: {relative}")
    return entries


def resolve_binary(build_dir: Path, name: str) -> Path:
    build_dir = build_dir.resolve()
    suffix = ".exe" if os.name == "nt" else ""
    candidates = (build_dir / "fuzz" / f"{name}{suffix}",
                  build_dir / "fuzz" / "Release" / f"{name}{suffix}")
    for candidate in candidates:
        if candidate.is_file():
            resolved = candidate.resolve()
            try:
                resolved.relative_to(build_dir)
            except ValueError as error:
                raise CampaignError("fuzz binary escapes the build directory") from error
            return resolved
    raise CampaignError(f"missing fuzz target in build directory: {name}")


def normalized_command(target: dict[str, Any], mode: dict[str, int]) -> list[str]:
    return [
        f"$BUILD_DIR/fuzz/{target['binary']}",
        f"-seed={target['seed']}",
        f"-runs={mode['runs_per_target']}",
        "-max_len=$MAX_INPUT_BYTES",
        "-timeout=$INPUT_TIMEOUT_SECONDS",
        "-rss_limit_mb=$RSS_LIMIT_MB",
        "-artifact_prefix=$ARTIFACT_DIR/",
        f"$MUTABLE_CORPUS/{target['corpus']}",
    ]


def actual_command(binary: Path, target: dict[str, Any], mode: dict[str, int],
                   max_input: int, input_timeout: int, rss_limit_mb: int,
                   corpus: Path, artifact_dir: Path) -> list[str]:
    return [
        str(binary),
        f"-seed={target['seed']}",
        f"-runs={mode['runs_per_target']}",
        f"-max_len={max_input}",
        f"-timeout={input_timeout}",
        f"-rss_limit_mb={rss_limit_mb}",
        f"-artifact_prefix={artifact_dir}{os.sep}",
        str(corpus),
    ]


def git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise CampaignError("cannot resolve source commit")
    commit = result.stdout.strip()
    if len(commit) != 40:
        raise CampaignError("source commit is not a full object id")
    return commit


def git_commit_is_ancestor(ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode not in (0, 1):
        raise CampaignError("cannot validate source commit ancestry")
    return result.returncode == 0


def compiler_identity(build_dir: Path) -> dict[str, str]:
    cache = build_dir / "CMakeCache.txt"
    compiler = ""
    try:
        for line in cache.read_text(encoding="utf-8", errors="strict").splitlines():
            if line.startswith("CMAKE_CXX_COMPILER:") and "=" in line:
                compiler = line.partition("=")[2]
                break
    except OSError as error:
        raise CampaignError(f"cannot read CMake cache: {error}") from error
    if not compiler or not Path(compiler).is_file():
        raise CampaignError("cannot resolve configured C++ compiler")
    result = subprocess.run(
        [compiler, "--version"], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise CampaignError("cannot read compiler identity")
    return {
        "path": compiler,
        "version_first_line": result.stdout.splitlines()[0],
        "version_output_sha256": sha256_bytes(result.stdout.encode()),
    }


def write_receipt(output: Path, payload: dict[str, Any]) -> None:
    receipt_path = output / "receipt.json"
    receipt_bytes = canonical_json(payload)
    receipt_path.write_bytes(receipt_bytes)
    receipt_digest = sha256_bytes(receipt_bytes)
    (output / "receipt.json.sha256").write_text(
        f"{receipt_digest}  receipt.json\n", encoding="utf-8", newline="\n")


def _require_sha256(value: Any, label: str) -> str:
    if (not isinstance(value, str) or len(value) != 64 or
            any(char not in "0123456789abcdef" for char in value)):
        raise CampaignError(f"invalid {label} SHA-256")
    return value


def verify_receipt(output: Path, build_dir: Path,
                   require_current_source: bool = True) -> dict[str, Any]:
    receipt_path = output / "receipt.json"
    checksum_path = output / "receipt.json.sha256"
    try:
        receipt_bytes = receipt_path.read_bytes()
        checksum_text = checksum_path.read_text(encoding="utf-8")
    except OSError as error:
        raise CampaignError(f"cannot read fuzz receipt: {error}") from error
    if checksum_text != f"{sha256_bytes(receipt_bytes)}  receipt.json\n":
        raise CampaignError("receipt checksum mismatch")
    try:
        receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignError(f"malformed fuzz receipt: {error}") from error
    if receipt_bytes != canonical_json(receipt):
        raise CampaignError("fuzz receipt is not canonical JSON")
    expected_fields = {
        "schema", "status", "mode", "source", "campaign_manifest_sha256",
        "corpus_manifest_sha256", "corpus_file_count", "toolchain", "host",
        "budget", "started_at", "finished_at", "duration_ms", "targets",
        "failures",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_fields:
        raise CampaignError("unexpected fuzz receipt fields")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise CampaignError("unsupported fuzz receipt schema")
    if receipt["status"] != "accepted" or receipt["failures"] != []:
        raise CampaignError("fuzz receipt is not accepted")

    campaign = load_campaign()
    corpus_entries = load_corpus_checksums()
    mode_name = receipt["mode"]
    if mode_name not in campaign["modes"]:
        raise CampaignError("unknown fuzz receipt mode")
    mode = campaign["modes"][mode_name]
    if receipt["budget"] != {
            "runs_per_target": mode["runs_per_target"],
            "max_input_bytes": campaign["max_input_bytes"],
            "input_timeout_seconds": campaign["input_timeout_seconds"],
            "rss_limit_mb": campaign["rss_limit_mb"],
            "wall_timeout_seconds_per_target": mode["wall_timeout_seconds"],
    }:
        raise CampaignError("fuzz receipt budget differs from campaign")
    if receipt["campaign_manifest_sha256"] != sha256_file(CAMPAIGN_PATH):
        raise CampaignError("fuzz campaign manifest drift")
    if receipt["corpus_manifest_sha256"] != sha256_file(CORPUS_CHECKSUMS):
        raise CampaignError("fuzz corpus manifest drift")
    if receipt["corpus_file_count"] != len(corpus_entries):
        raise CampaignError("fuzz corpus count drift")

    source = receipt["source"]
    if not isinstance(source, dict) or set(source) != {"commit", "manifest"}:
        raise CampaignError("invalid source identity")
    if (not isinstance(source["commit"], str) or len(source["commit"]) != 40 or
            any(char not in "0123456789abcdef" for char in source["commit"])):
        raise CampaignError("invalid source commit")
    manifest = source["manifest"]
    if (not isinstance(manifest, dict) or
            set(manifest) != {"algorithm", "file_count", "digest"} or
            manifest["algorithm"] != "sha256" or
            not isinstance(manifest["file_count"], int) or
            manifest["file_count"] < 1):
        raise CampaignError("invalid source manifest")
    _require_sha256(manifest["digest"], "source manifest")
    if require_current_source:
        current_commit = git_commit()
        if not git_commit_is_ancestor(source["commit"], current_commit):
            raise CampaignError(
                "receipt source base commit is not an ancestor of current HEAD")
        if manifest != source_manifest():
            raise CampaignError("receipt source bytes differ from worktree")

    if not isinstance(receipt["duration_ms"], int) or receipt["duration_ms"] < 0:
        raise CampaignError("invalid campaign duration")
    try:
        started = dt.datetime.fromisoformat(receipt["started_at"])
        finished = dt.datetime.fromisoformat(receipt["finished_at"])
    except (TypeError, ValueError) as error:
        raise CampaignError("invalid campaign timestamps") from error
    if started.tzinfo is None or finished.tzinfo is None or finished < started:
        raise CampaignError("invalid campaign time interval")
    if not isinstance(receipt["host"], dict) or set(receipt["host"]) != {
            "platform", "machine", "python"}:
        raise CampaignError("invalid host identity")
    if not isinstance(receipt["toolchain"], dict) or set(receipt["toolchain"]) != {
            "path", "version_first_line", "version_output_sha256"}:
        raise CampaignError("invalid toolchain identity")
    _require_sha256(receipt["toolchain"]["version_output_sha256"],
                    "toolchain output")

    targets = receipt["targets"]
    if not isinstance(targets, list) or len(targets) != len(campaign["targets"]):
        raise CampaignError("invalid target receipt count")
    expected_files = {"receipt.json", "receipt.json.sha256"}
    binaries = {
        target["id"]: resolve_binary(build_dir, target["binary"])
        for target in campaign["targets"]
    }
    for target_receipt, target in zip(targets, campaign["targets"]):
        fields = {
            "id", "binary_sha256", "command", "duration_ms", "exit_code",
            "log", "log_sha256", "artifacts",
        }
        if not isinstance(target_receipt, dict) or set(target_receipt) != fields:
            raise CampaignError("invalid target receipt fields")
        if target_receipt["id"] != target["id"]:
            raise CampaignError("fuzz target order/identity drift")
        if target_receipt["command"] != normalized_command(target, mode):
            raise CampaignError(f"fuzz command drift: {target['id']}")
        if target_receipt["exit_code"] != 0 or target_receipt["artifacts"] != []:
            raise CampaignError(f"failed fuzz target: {target['id']}")
        if (not isinstance(target_receipt["duration_ms"], int) or
                target_receipt["duration_ms"] < 0):
            raise CampaignError(f"invalid target duration: {target['id']}")
        binary_digest = _require_sha256(
            target_receipt["binary_sha256"], "binary")
        if sha256_file(binaries[target["id"]]) != binary_digest:
            raise CampaignError(f"fuzz binary checksum mismatch: {target['id']}")
        log_relative = f"logs/{target['id']}.log"
        if target_receipt["log"] != log_relative:
            raise CampaignError(f"unexpected fuzz log path: {target['id']}")
        log_path = output / log_relative
        if not log_path.is_file():
            raise CampaignError(f"missing fuzz log: {target['id']}")
        log_digest = _require_sha256(target_receipt["log_sha256"], "log")
        if sha256_file(log_path) != log_digest:
            raise CampaignError(f"fuzz log checksum mismatch: {target['id']}")
        log_bytes = log_path.read_bytes()
        runs = mode["runs_per_target"]
        done_record = re.compile(
            rb"(?m)^#" + str(runs).encode() + rb"\s+DONE\b")
        terminal_record = re.compile(
            rb"Done " + str(runs).encode() +
            rb" runs in [0-9]+ second\(s\)\n?\Z")
        if len(done_record.findall(log_bytes)) != 1 or len(
                terminal_record.findall(log_bytes)) != 1:
            raise CampaignError(
                f"fuzz log lacks exact completion evidence: {target['id']}")
        expected_files.add(log_relative)
    actual_files = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*") if path.is_file()
    }
    if actual_files != expected_files:
        raise CampaignError("unexpected or missing fuzz receipt files")
    return receipt


def execute(build_dir: Path, mode_name: str, output: Path) -> bool:
    campaign = load_campaign()
    corpus_entries = load_corpus_checksums()
    mode = campaign["modes"][mode_name]
    # Resolve every identity and executable before creating an evidence
    # directory or spending the run budget. A setup failure therefore cannot
    # leave a log-only directory that looks like an incomplete receipt.
    source = {"commit": git_commit(), "manifest": source_manifest()}
    toolchain = compiler_identity(build_dir)
    binaries = {
        target["id"]: resolve_binary(build_dir, target["binary"])
        for target in campaign["targets"]
    }
    campaign_manifest_sha256 = sha256_file(CAMPAIGN_PATH)
    corpus_manifest_sha256 = sha256_file(CORPUS_CHECKSUMS)
    if output.exists() and any(output.iterdir()):
        raise CampaignError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    logs = output / "logs"
    logs.mkdir()

    started = dt.datetime.now(dt.timezone.utc)
    failures: list[str] = []
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(
            prefix="codeskeptic-fuzz-", dir=output.parent) as temp_name:
        temp = Path(temp_name)
        mutable_corpus = temp / "corpus"
        shutil.copytree(CORPUS_ROOT, mutable_corpus)
        artifact_root = temp / "artifacts"
        artifact_root.mkdir()

        for target in campaign["targets"]:
            binary = binaries[target["id"]]
            corpus = mutable_corpus / target["corpus"]
            artifact_dir = artifact_root / target["id"]
            artifact_dir.mkdir()
            command = actual_command(
                binary, target, mode, campaign["max_input_bytes"],
                campaign["input_timeout_seconds"], campaign["rss_limit_mb"],
                corpus, artifact_dir)
            log_path = logs / f"{target['id']}.log"
            begin = time.monotonic()
            timed_out = False
            try:
                with log_path.open("wb") as log:
                    completed = subprocess.run(
                        command, cwd=ROOT, stdout=log,
                        stderr=subprocess.STDOUT, check=False,
                        timeout=mode["wall_timeout_seconds"],
                    )
                exit_code = completed.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                exit_code = 124
                with log_path.open("ab") as log:
                    log.write(b"\nCAMPAIGN WALL TIMEOUT\n")
            duration_ms = round((time.monotonic() - begin) * 1000)
            artifacts = sorted(
                path.name for path in artifact_dir.iterdir() if path.is_file())
            if exit_code != 0:
                failures.append(f"{target['id']}: exit {exit_code}")
            if timed_out:
                failures.append(f"{target['id']}: wall timeout")
            if artifacts:
                failures.append(f"{target['id']}: crash artifacts retained")
            results.append({
                "id": target["id"],
                "binary_sha256": sha256_file(binary),
                "command": normalized_command(target, mode),
                "duration_ms": duration_ms,
                "exit_code": exit_code,
                "log": log_path.relative_to(output).as_posix(),
                "log_sha256": sha256_file(log_path),
                "artifacts": artifacts,
            })

    # A campaign must never teach the canonical seed corpus in place.
    after_entries = load_corpus_checksums()
    if after_entries != corpus_entries:
        failures.append("canonical corpus changed during campaign")

    finished = dt.datetime.now(dt.timezone.utc)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "accepted" if not failures else "rejected",
        "mode": mode_name,
        "source": source,
        "campaign_manifest_sha256": campaign_manifest_sha256,
        "corpus_manifest_sha256": corpus_manifest_sha256,
        "corpus_file_count": len(corpus_entries),
        "toolchain": toolchain,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "budget": {
            "runs_per_target": mode["runs_per_target"],
            "max_input_bytes": campaign["max_input_bytes"],
            "input_timeout_seconds": campaign["input_timeout_seconds"],
            "rss_limit_mb": campaign["rss_limit_mb"],
            "wall_timeout_seconds_per_target": mode["wall_timeout_seconds"],
        },
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": round((finished - started).total_seconds() * 1000),
        "targets": results,
        "failures": failures,
    }
    write_receipt(output, receipt)
    if not failures:
        verify_receipt(output, build_dir)
    return not failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--mode", choices=("smoke", "extended"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-receipt", type=Path)
    args = parser.parse_args(argv)
    if args.verify_receipt is not None:
        if args.mode is not None or args.output is not None:
            parser.error("--verify-receipt cannot be combined with run options")
        if args.build_dir is None:
            parser.error("--verify-receipt requires --build-dir")
    elif args.build_dir is None or args.mode is None or args.output is None:
        parser.error("campaign execution requires --build-dir, --mode, and --output")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.verify_receipt is not None:
            verify_receipt(args.verify_receipt.resolve(),
                           args.build_dir.resolve())
            print(f"fuzz receipt accepted: {args.verify_receipt}")
            return 0
        accepted = execute(
            args.build_dir.resolve(), args.mode, args.output.resolve())
    except CampaignError as error:
        print(f"fuzz campaign rejected: {error}", file=sys.stderr)
        return 2
    print(f"fuzz campaign {'accepted' if accepted else 'rejected'}: "
          f"{args.output}")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
