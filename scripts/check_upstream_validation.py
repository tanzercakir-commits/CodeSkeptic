#!/usr/bin/env python3

import argparse
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GATE_A_IDS = {"source_proof", "real_trigger", "duplicate_check", "current_head"}
OUTCOMES = {
    "accepted",
    "rejected",
    "duplicate",
    "non_triggerable",
    "false_positive",
    "stale",
    "hold",
}


class LedgerError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LedgerError(message)


def require_string(value, label):
    require(isinstance(value, str) and value.strip(), f"{label} must be a non-empty string")


def require_commit(value, label):
    require(
        isinstance(value, str) and COMMIT_RE.fullmatch(value),
        f"{label} must be a full lowercase commit SHA",
    )


def require_date(value, label):
    require_string(value, label)
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise LedgerError(f"{label} must be an ISO date") from exc


def require_timestamp(value, label):
    require_string(value, label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LedgerError(f"{label} must be an ISO timestamp") from exc
    require(parsed.tzinfo is not None, f"{label} must include a timezone")


def load_ledger(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerError(f"cannot load {path}: {exc}") from exc
    require(isinstance(value, dict), "ledger root must be an object")
    return value


def validate_gate_a(record_id, gates):
    require(
        isinstance(gates, list) and len(gates) == 4,
        f"{record_id}: gate_a must contain four proofs",
    )
    ids = set()
    for gate in gates:
        require(isinstance(gate, dict), f"{record_id}: gate_a entries must be objects")
        gate_id = gate.get("id")
        require(gate_id in GATE_A_IDS, f"{record_id}: unknown gate_a proof {gate_id!r}")
        require(gate_id not in ids, f"{record_id}: duplicate gate_a proof {gate_id}")
        require(gate.get("passed") is True, f"{record_id}: gate_a proof {gate_id} did not pass")
        require_string(gate.get("evidence"), f"{record_id}: gate_a {gate_id} evidence")
        ids.add(gate_id)
    require(ids == GATE_A_IDS, f"{record_id}: gate_a proof set is incomplete")


def validate_gate_b(record_id, gate):
    require(isinstance(gate, dict), f"{record_id}: gate_b must be an object")
    require(gate.get("passed") is True, f"{record_id}: gate_b did not pass")
    require(gate.get("maintained") is True, f"{record_id}: project is not maintained")
    require_string(gate.get("channel"), f"{record_id}: gate_b channel")
    require_string(gate.get("evidence"), f"{record_id}: gate_b evidence")


def validate_gate_c(record_id, gate):
    require(isinstance(gate, dict), f"{record_id}: gate_c must be an object")
    require(gate.get("passed") is True, f"{record_id}: gate_c did not pass")
    require_string(gate.get("report_ref"), f"{record_id}: gate_c report_ref")
    require_string(gate.get("fix_ref"), f"{record_id}: gate_c fix_ref")
    if "issue" in gate:
        require(
            isinstance(gate["issue"], int) and gate["issue"] > 0,
            f"{record_id}: gate_c issue must be positive",
        )
    if "pull_request" in gate:
        require(
            isinstance(gate["pull_request"], int) and gate["pull_request"] > 0,
            f"{record_id}: gate_c pull request must be positive",
        )
    require(
        gate.get("reproduction_first") is True,
        f"{record_id}: gate_c reproduction-first proof is missing",
    )
    require(
        gate.get("one_defect") is True,
        f"{record_id}: gate_c one-defect proof is missing",
    )
    require_string(gate.get("evidence"), f"{record_id}: gate_c evidence")


def validate_fix(record_id, observed, fix):
    require(
        isinstance(fix, dict),
        f"{record_id}: accepted record must contain fix evidence",
    )
    require(fix.get("merged") is True, f"{record_id}: fix is not merged")
    require_commit(fix.get("merge_commit"), f"{record_id}: merge_commit")
    require_timestamp(fix.get("merged_at"), f"{record_id}: merged_at")
    require(
        fix.get("verified_branch") == observed["default_branch"],
        f"{record_id}: verified branch differs from observed default branch",
    )
    require_commit(fix.get("verified_head"), f"{record_id}: verified_head")
    require(
        fix.get("ancestry") == "ancestor",
        f"{record_id}: merge commit ancestry is not proven",
    )
    require_date(fix.get("verified_at"), f"{record_id}: verified_at")


def validate_record(record):
    require(isinstance(record, dict), "records must be objects")
    record_id = record.get("id")
    require_string(record_id, "record id")
    require_string(record.get("project"), f"{record_id}: project")
    repository = record.get("repository")
    require(
        isinstance(repository, str) and REPOSITORY_RE.fullmatch(repository),
        f"{record_id}: invalid repository",
    )
    outcome = record.get("outcome")
    require(outcome in OUTCOMES, f"{record_id}: invalid outcome {outcome!r}")

    observed = record.get("observed")
    require(isinstance(observed, dict), f"{record_id}: observed must be an object")
    require_string(observed.get("default_branch"), f"{record_id}: default_branch")
    require_commit(observed.get("affected_head"), f"{record_id}: affected_head")
    require_date(observed.get("checked_at"), f"{record_id}: checked_at")

    if outcome == "accepted":
        validate_gate_a(record_id, record.get("gate_a"))
        validate_gate_b(record_id, record.get("gate_b"))
        validate_gate_c(record_id, record.get("gate_c"))
        validate_fix(record_id, observed, record.get("fix"))
    else:
        require_string(record.get("classification"), f"{record_id}: classification")


def validate_ledger(ledger):
    require(ledger.get("schema") == 1, "schema must be 1")
    targets = ledger.get("targets")
    require(
        targets == {"accepted_fixes": 10, "projects": 5},
        "targets must remain 10 fixes across 5 projects",
    )
    records = ledger.get("records")
    require(isinstance(records, list), "records must be an array")
    ids = set()
    for record in records:
        validate_record(record)
        require(record["id"] not in ids, f"duplicate record id {record['id']}")
        ids.add(record["id"])
    accepted = [record for record in records if record["outcome"] == "accepted"]
    projects = {record["repository"] for record in accepted}
    return {
        "records": len(records),
        "accepted_fixes": len(accepted),
        "projects": len(projects),
        "complete": len(accepted) >= 10 and len(projects) >= 5,
    }


def validate_append_only(previous, current):
    validate_ledger(previous)
    validate_ledger(current)
    require(
        len(current["records"]) >= len(previous["records"]),
        "append-only ledger lost records",
    )
    require(
        current["records"][: len(previous["records"])] == previous["records"],
        "append-only ledger changed or reordered existing records",
    )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Validate the Phase 9 upstream evidence ledger"
    )
    parser.add_argument(
        "--ledger",
        default=str(Path(__file__).with_name("upstream_validation_ledger.json")),
    )
    previous = parser.add_mutually_exclusive_group()
    previous.add_argument("--previous")
    previous.add_argument("--previous-if-exists")
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        ledger = load_ledger(args.ledger)
        summary = validate_ledger(ledger)
        previous_path = args.previous
        if args.previous_if_exists and Path(args.previous_if_exists).is_file():
            previous_path = args.previous_if_exists
        if previous_path:
            validate_append_only(load_ledger(previous_path), ledger)
        if args.require_complete and not summary["complete"]:
            raise LedgerError(
                f"Phase 9 incomplete: {summary['accepted_fixes']}/10 fixes "
                f"across {summary['projects']}/5 projects"
            )
    except LedgerError as exc:
        print(f"upstream ledger error: {exc}", file=sys.stderr)
        return 2
    print(
        "UPSTREAM_LEDGER_OK "
        f"records={summary['records']} accepted={summary['accepted_fixes']}/10 "
        f"projects={summary['projects']}/5 complete={int(summary['complete'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
