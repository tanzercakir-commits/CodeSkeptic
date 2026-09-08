#!/usr/bin/env python3
"""Read-only reconciliation of retained actual local Action/container evidence.

Does not create scans or manufacture execution success. Independent review of
the producer, raw commands and terminal records remains mandatory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from action_container import identifier, validate_runtime
from action_local_smoke import ROOT, SCENARIOS
from action_run import require, validate


def digest(path):
    require(path.is_file() and not path.is_symlink(), "expected regular evidence file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def document(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024**2, "missing/oversized evidence")
    return json.loads(path.read_text())


def process(folder, expected):
    require(document(folder / "process.json")["exit_code"] == expected, "recorded process exit mismatch: " + str(folder))
    return document(folder / "command.json")["argv"]


def unchanged(revision, paths):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "expected exact measured Git revision")
    for path in paths:
        recorded = subprocess.check_output(["git", "show", revision + ":" + path], cwd=ROOT)
        require(recorded == (ROOT / path).read_bytes(), "measured implementation changed: " + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--container", type=Path, required=True)
    parser.add_argument("--local-head", required=True)
    parser.add_argument("--container-head", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--binary-sha256", required=True)
    args = parser.parse_args()
    require(not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT), "qualification requires clean HEAD")
    unchanged(args.local_head, ["action.yml", "scripts/action_args.py", "scripts/action_run.py",
                               "scripts/action_acquire.py", "scripts/action_local_smoke.py"])
    unchanged(args.container_head, ["Dockerfile", ".dockerignore", "scripts/action_container.py"])
    local, container = args.local.resolve(strict=True), args.container.resolve(strict=True)
    local_result, container_result = document(local / "result.json"), document(container / "result.json")
    require(local_result["schema"] == "codeskeptic-local-action-smoke/v1"
            and container_result["schema"] == "codeskeptic-artifact-container-parity/v1", "unknown evidence profile")
    for result in (local_result, container_result):
        require(result["artifact_sha256"] == args.artifact_sha256 and result["binary_sha256"] == args.binary_sha256, "qualified package identity mismatch")
        require(result["hosted_action"] is False and len(result["scenarios"]) == 6, "unsupported hosted/scenario claim")
    require(container_result["source_rebuild_qualified"] is False, "unmeasured source rebuild claim")
    version = local_result["version"]
    require(version == container_result["version"], "profile version mismatch")
    for name in ("Dockerfile", ".dockerignore"):
        require((container / "context" / name).read_bytes() == (ROOT / name).read_bytes(), "measured image recipe changed")
    require(digest(container / "context/package/bin/codeskeptic") == args.binary_sha256, "build-context binary mismatch")
    process(container / "base-inspect", 0)
    process(container / "build", 0)
    process(container / "image-inspect", 0)
    image = identifier(container_result["image"])
    require(identifier((container / "image-id").read_text()) == image, "built image ID mismatch")
    built = document(container / "image-inspect/stdout")
    require(len(built) == 1 and identifier(built[0]["Id"]) == image
            and built[0]["Config"]["User"] == "65532:65532", "built image metadata mismatch")
    for folder in ("validate", "install", "version"):
        process(local / folder, 0)
    require((local / "version/stdout").read_text().strip() == "CodeSkeptic " + version, "actual local version mismatch")
    path_entries = (local / "github-path").read_text().splitlines()
    require(len(path_entries) == 1 and digest(Path(path_entries[0]) / "codeskeptic") == args.binary_sha256, "installed binary mismatch")
    records = []
    for name, source_name, expected, extra in SCENARIOS:
        native = document(local / name / "cli.sarif")
        action = document(local / name / "action.sarif")
        case = container / name
        actual = document(case / "reports/result.sarif")
        for report in (native, action, actual):
            validate(report, expected, version)
        require(native == action == actual, name + " full SARIF parity mismatch")
        process(local / name / "cli", expected)
        process(local / name / "action", expected)
        require((local / name / "github-output").read_text() == f"exit-code={expected}\nsarif-valid=true\n", "local raw output mismatch")
        process(case / "create", 0)
        process(case / "before", 0)
        process(case / "scan", expected)
        process(case / "after", 0)
        cleanup = process(case / "cleanup", 0)
        cid = identifier((case / "create/stdout").read_text())
        for phase in ("before", "after"):
            state = document(case / phase / "stdout")
            require(len(state) == 1 and identifier(state[0]["Id"]) == cid, "runtime ID mismatch")
            validate_runtime(state[0], image, local / "fixtures", case / "reports")
            if phase == "after":
                require(state[0]["State"]["Running"] is False and not state[0]["State"]["OOMKilled"]
                        and state[0]["State"]["ExitCode"] == expected, "terminal native verdict mismatch")
        require(cleanup == ["podman", "rm", "--force", cid]
                and (case / "cleanup/stdout").read_text().strip() == cid, "exact owned cleanup mismatch")
        require((case / "scan/stdout").read_text() == args.binary_sha256 + "  /opt/codeskeptic/bin/codeskeptic\nCodeSkeptic " + version + "\n", "actual image binary identity mismatch")
        records.append({"scenario": name, "exit": expected, "sarif_sha256": digest(case / "reports/result.sarif")})
    process(local / "report-only-gate/action", 0)
    require((local / "report-only-gate/github-output").read_text() == "exit-code=1\nsarif-valid=true\n", "report-only raw verdict lost")
    require(document(local / "report-only-gate/action.sarif") == document(local / "blocking/cli.sarif"), "report-only SARIF changed")
    outer = container.with_suffix(".log").read_text()
    require(outer.endswith("OUTER_PROCESS_EXIT=0\n") and "CONTAINER_PARITY_OK scenarios=6" in outer, "outer container measurement not successful")
    require(local_result["report_only_step_exit"] == 0 and local_result["report_only_analyzer_exit"] == 1, "local summary mismatch")
    print(json.dumps({"result": "PASS", "kind": "retained-actual-evidence-reconciliation",
                      "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                      "local_result_sha256": digest(local / "result.json"), "container_result_sha256": digest(container / "result.json"),
                      "actual_scans": 19, "hosted_action": False, "source_rebuild_qualified": False,
                      "scenarios": records}, sort_keys=True))


if __name__ == "__main__":
    main()
