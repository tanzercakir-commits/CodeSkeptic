#!/usr/bin/env python3
"""Contracts for the fail-closed Phase 10.9 stability controller."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_stability_campaign as stability  # noqa: E402
import seal_hosted_exact_head as hosted_authority  # noqa: E402


POLICY_PATH = ROOT / "scripts" / "stability_manifest.json"
SESSION_ID = "1" * 64
CONTROLLER_ID = "2" * 64
BOOT_ID = "12345678-1234-1234-1234-123456789abc"
ZERO_SHA256 = "0" * 64


def canonical_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def session_material() -> dict:
    return {
        "schema": stability.SESSION_SCHEMA,
        "policy_sha256": stability.sha256_file(POLICY_PATH),
        "source_revision": "a" * 40,
        "source_tree_sha1": "6" * 40,
        "source_manifest_sha256": "b" * 64,
        "analyzer_sha256": "c" * 64,
        "runtime_config_sha256": "4" * 64,
        "runtime_launch_receipt_sha256": "5" * 64,
        "build_authority_receipt_sha256": "7" * 64,
        "realworld_manifest_sha256": stability.sha256_file(
            ROOT / "scripts" / "realworld_manifest.json"
        ),
        "realworld_mirror_authority_sha256": "3" * 64,
        "determinism_manifest_sha256": stability.sha256_file(
            ROOT / "scripts" / "determinism_workloads.json"
        ),
        "baseline_sha256": stability.sha256_file(
            ROOT / "scripts" / "determinism_baseline.json"
        ),
        "fault_injection_test_binary": {
            "path": (
                "/authority/source/build/p10-09-sanitizers/"
                "undefined-tests/tests/codeskeptic_tests"
            ),
            "sha256": "0" * 64,
            "sanitizer_profile": "undefined",
            "sanitizer_receipt_sha256": "e" * 64,
        },
        "sanitizer_receipts": {
            "address": "d" * 64,
            "undefined": "e" * 64,
        },
        "prerequisite_receipts": {
            "determinism": "8" * 64,
            "hosted_exact_head": "9" * 64,
            "quality_floor": "f" * 64,
        },
        "hardware_class": "fedora44-i5-1235u-exclusive-pcores-0-3",
        "boot_id": BOOT_ID,
    }


def runtime_config() -> dict:
    return {
        "schema": stability.RUNTIME_CONFIG_SCHEMA,
        "policy": {
            "path": "/authority/source/scripts/stability_manifest.json",
            "sha256": "1" * 64,
        },
        "source": {
            "root": "/authority/source",
            "revision": "2" * 40,
            "tree_sha1": "3" * 40,
            "manifest_sha256": "4" * 64,
        },
        "runtime": {
            "image_reference": stability.PINNED_EVIDENCE_IMAGE,
            "image_digest": stability.PINNED_EVIDENCE_IMAGE_DIGEST,
            "image_id": stability.PINNED_EVIDENCE_IMAGE_ID,
            "launch_receipt": "/launch/receipt.json",
        },
        "analyzer": {"path": "/authority/build/src/codeskeptic", "sha256": "5" * 64},
        "build_authority": {
            "root": "/authority/build-authority",
            "receipt_sha256": "6" * 64,
            "build_path": "/authority/build",
        },
        "realworld": {
            "mirror_authority": "/authority/mirrors/authority.json",
            "mirror_authority_sha256": "7" * 64,
        },
        "fault_injection": {
            "test_binary": (
                "/authority/source/build/p10-09-sanitizers/"
                "undefined-tests/tests/codeskeptic_tests"
            ),
            "test_binary_sha256": "0" * 64,
        },
        "qualification": {
            "hardware_class": "fedora44-i5-1235u-exclusive-pcores-0-3",
            "measurement_cgroup": stability.RUNTIME_MEASUREMENT_CGROUP,
            "baseline_authority_root": "/authority/source",
            "release_source": "/authority/release/source",
            "release_build": "/authority/release/build",
            "jobs": 2,
            "tools": {
                "clang": "/usr/bin/clang-20",
                "time": "/usr/bin/time",
                "cmake": "/usr/bin/cmake",
                "ninja": "/usr/bin/ninja",
                "c_compiler": "/usr/bin/clang-20",
                "cxx_compiler": "/usr/bin/clang++-20",
            },
        },
        "prerequisites": {
            "determinism": {
                "root": "/authority/prerequisites/determinism",
                "receipt_sha256": "8" * 64,
            },
            "hosted_exact_head": {
                "root": "/authority/prerequisites/hosted",
                "receipt_sha256": "9" * 64,
                "repository": "example/CodeSkeptic",
            },
            "quality_floor": {
                "root": "/authority/prerequisites/quality",
                "receipt_sha256": "a" * 64,
            },
        },
        "sanitizers": {
            "address": {
                "root": "/authority/sanitizers/address",
                "receipt_sha256": "b" * 64,
                "test_build": (
                    "/authority/source/build/p10-09-sanitizers/address-tests"
                ),
                "fuzz_build": (
                    "/authority/source/build/p10-09-sanitizers/address-fuzz"
                ),
            },
            "undefined": {
                "root": "/authority/sanitizers/undefined",
                "receipt_sha256": "c" * 64,
                "test_build": (
                    "/authority/source/build/p10-09-sanitizers/undefined-tests"
                ),
                "fuzz_build": (
                    "/authority/source/build/p10-09-sanitizers/undefined-fuzz"
                ),
            },
        },
    }


def write_canonical_pair(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = stability.canonical_document(value)
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    Path(f"{path}.sha256").write_text(
        f"{digest}  {path.name}\n", encoding="ascii"
    )
    return digest


def _event_material(
    seq: int,
    previous: str,
    event_type: str,
    monotonic_ns: int,
    payload: dict,
    *,
    boottime_ns: int | None = None,
    boot_id: str = BOOT_ID,
    controller_id: str = CONTROLLER_ID,
    session_id: str = SESSION_ID,
    utc: str = "2026-08-23T00:00:00Z",
) -> dict:
    return {
        "schema": stability.EVENT_SCHEMA,
        "seq": seq,
        "previous_event_sha256": previous,
        "event_type": event_type,
        "session_id": session_id,
        "controller_id": controller_id,
        "boot_id": boot_id,
        "monotonic_ns": monotonic_ns,
        "boottime_ns": monotonic_ns if boottime_ns is None else boottime_ns,
        "utc": utc,
        "payload": payload,
    }


def append_event(
    events: list[dict],
    event_type: str,
    monotonic_ns: int,
    payload: dict,
    **overrides: object,
) -> None:
    previous = events[-1]["event_sha256"] if events else ZERO_SHA256
    material = _event_material(
        len(events), previous, event_type, monotonic_ns, payload, **overrides
    )
    events.append({**material, "event_sha256": stability.digest_json(material)})


def resign(events: list[dict]) -> list[dict]:
    result: list[dict] = []
    previous = ZERO_SHA256
    for seq, source in enumerate(events):
        material = {
            key: copy.deepcopy(value)
            for key, value in source.items()
            if key != "event_sha256"
        }
        material["seq"] = seq
        material["previous_event_sha256"] = previous
        sealed = {**material, "event_sha256": stability.digest_json(material)}
        result.append(sealed)
        previous = sealed["event_sha256"]
    return result


def terminal_action_receipt_path(
    root: Path, cycle_ordinal: int, action: dict,
) -> Path:
    return (
        root / "cycles" / f"{cycle_ordinal:06d}" / "actions"
        / f"{action['ordinal']:02d}-{action['kind']}" / "receipt.json"
    )


def write_terminal_action_receipts(
    root: Path,
    policy: dict,
    schedule: dict,
    session_id: str,
) -> dict[tuple[int, int], str]:
    result: dict[tuple[int, int], str] = {}
    for cycle_ordinal in (1, 2):
        plan = stability.build_cycle_plan(
            policy, schedule, session_id, cycle_ordinal
        )
        for action in plan["actions"]:
            path = terminal_action_receipt_path(root, cycle_ordinal, action)
            digest = write_document(path, {
                "schema": stability.ACTION_RECEIPT_SCHEMA,
                "status": "accepted",
                "failures": [],
                "identity": {
                    "action_id": action["id"],
                    "cycle_id": plan["id"],
                    "cycle_ordinal": cycle_ordinal,
                    "action_ordinal": action["ordinal"],
                    "kind": action["kind"],
                    "plan_sha256": plan["plan_sha256"],
                },
                "command": {},
                "inner": {},
            })
            result[(cycle_ordinal, action["ordinal"])] = digest
    return result


def accepted_journal(
    duration_seconds: int = 259200,
    *,
    session_id: str = SESSION_ID,
    controller_id: str = CONTROLLER_ID,
    boot_id: str = BOOT_ID,
    cycle_events: list[dict] | None = None,
    action_receipt_hashes: dict[tuple[int, int], str] | None = None,
) -> list[dict]:
    duration_ns = duration_seconds * 1_000_000_000
    policy = stability.validate_policy(canonical_policy(), ROOT)
    schedule = stability.build_schedule(policy, ROOT)
    policy_sha = stability.sha256_file(POLICY_PATH)
    events: list[dict] = []
    append_event(
        events,
        "session-start",
        0,
        {"policy_sha256": policy_sha, "status": "running"},
        session_id=session_id,
        controller_id=controller_id,
        boot_id=boot_id,
    )
    plans = [
        stability.build_cycle_plan(policy, schedule, session_id, ordinal)
        for ordinal in (1, 2)
    ]
    cycle_events = cycle_events or [
        {
            "cycle_id": plan["id"],
            "receipt_sha256": ("b" if plan["ordinal"] == 1 else "d") * 64,
        }
        for plan in plans
    ]
    actions = [
        (plan, action)
        for plan in plans
        for action in plan["actions"]
    ]
    timeout_ns = [
        action["timeout_seconds"] * 1_000_000_000
        for _plan, action in actions
    ]
    total_capacity = sum(timeout_ns)
    if duration_ns > total_capacity:
        raise AssertionError("fixture duration exceeds the exact action plan")
    durations = [
        duration_ns * capacity // total_capacity
        for capacity in timeout_ns
    ]
    remainder = duration_ns - sum(durations)
    for index in range(remainder):
        durations[index] += 1

    elapsed_ns = 0
    duration_index = 0
    for cycle_ordinal in (1, 2):
        plan = plans[cycle_ordinal - 1]
        for action in plan["actions"]:
            start_ns = elapsed_ns
            finish_ns = start_ns + durations[duration_index]
            duration_index += 1
            child_pid = 1200 + cycle_ordinal * 100 + action["ordinal"]
            append_event(
                events,
                "action-start",
                start_ns,
                {
                    "action_id": action["id"],
                    "kind": action["kind"],
                    "cycle_ordinal": cycle_ordinal,
                    "action_ordinal": action["ordinal"],
                    "timeout_seconds": action["timeout_seconds"],
                    "child_pid": child_pid,
                },
                session_id=session_id,
                controller_id=controller_id,
                boot_id=boot_id,
            )
            heartbeat_ns = start_ns + 90 * 1_000_000_000
            while heartbeat_ns < finish_ns:
                append_event(
                    events,
                    "heartbeat",
                    heartbeat_ns,
                    {
                        "stage": action["kind"],
                        "child_pid": child_pid,
                        "action_id": action["id"],
                        "cycle_ordinal": cycle_ordinal,
                        "action_ordinal": action["ordinal"],
                    },
                    session_id=session_id,
                    controller_id=controller_id,
                    boot_id=boot_id,
                )
                heartbeat_ns += 90 * 1_000_000_000
            receipt_sha = (
                action_receipt_hashes.get(
                    (cycle_ordinal, action["ordinal"])
                )
                if action_receipt_hashes is not None
                else stability.digest_json({
                    "action_id": action["id"],
                    "fixture": "terminal-action-receipt",
                })
            )
            if receipt_sha is None:
                raise AssertionError("fixture action receipt hash is missing")
            append_event(
                events,
                "action-finish",
                finish_ns,
                {
                    "accepted": True,
                    "exit_code": 0,
                    "kind": action["kind"],
                    "action_id": action["id"],
                    "outcome": "normal",
                    "receipt_sha256": receipt_sha,
                    "child_pid": child_pid,
                    "cycle_ordinal": cycle_ordinal,
                    "action_ordinal": action["ordinal"],
                },
                session_id=session_id,
                controller_id=controller_id,
                boot_id=boot_id,
            )
            elapsed_ns = finish_ns
        append_event(
            events,
            "cycle-finish",
            elapsed_ns,
            {
                "accepted": True,
                "mode": "cold" if cycle_ordinal == 1 else "warm",
                "ordinal": cycle_ordinal,
                "slot_count": 9,
                **cycle_events[cycle_ordinal - 1],
            },
            session_id=session_id,
            controller_id=controller_id,
            boot_id=boot_id,
        )
    append_event(
        events,
        "session-finish",
        elapsed_ns,
        {"status": "accepted"},
        session_id=session_id,
        controller_id=controller_id,
        boot_id=boot_id,
    )
    return events


def write_document(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(data)
    return stability.sha256_file(path)


def session_record() -> dict:
    identity = session_material()
    return {
        "id": stability.build_session_identity(identity),
        "controller_id": CONTROLLER_ID,
        "identity": identity,
    }


def session_record_for_config(config: dict) -> dict:
    """Build the exact live session link used by cycle-level fixtures."""

    session = session_record()
    identity = session["identity"]
    identity["source_revision"] = config["source"]["revision"]
    identity["source_manifest_sha256"] = config["source"][
        "manifest_sha256"
    ]
    identity["analyzer_sha256"] = config["analyzer"]["sha256"]
    identity["sanitizer_receipts"]["undefined"] = config["sanitizers"][
        "undefined"
    ]["receipt_sha256"]
    identity["fault_injection_test_binary"] = {
        "path": config["fault_injection"]["test_binary"],
        "sha256": config["fault_injection"]["test_binary_sha256"],
        "sanitizer_profile": "undefined",
        "sanitizer_receipt_sha256": config["sanitizers"]["undefined"][
            "receipt_sha256"
        ],
    }
    identity["hardware_class"] = config["qualification"]["hardware_class"]
    session["id"] = stability.build_session_identity(identity)
    return session


def cycle_document(
    root: Path,
    session: dict,
    schedule: dict,
    ordinal: int,
    mode: str,
) -> dict:
    prefix = Path("cycles") / f"{ordinal:06d}"
    aggregate_path = prefix / "realworld" / "aggregate.json"
    aggregate_sha = write_document(
        root / aggregate_path,
        {"fixture": "realworld", "ordinal": ordinal, "status": "accepted"},
    )
    pre_qualification_path = (
        Path("cycles") / "000001" / "qualification" / "pre" / "receipt.json"
    )
    if ordinal == 1:
        pre_qualification_sha = write_document(
            root / pre_qualification_path,
            {"fixture": "qualification", "ordinal": 0, "status": "accepted"},
        )
        qualification = None
    else:
        pre_qualification_sha = stability.sha256_file(
            root / pre_qualification_path
        )
        qualification_path = (
            prefix / "qualification" / "post" / "receipt.json"
        )
        qualification_sha = write_document(
            root / qualification_path,
            {
                "fixture": "qualification",
                "ordinal": ordinal,
                "status": "accepted",
            },
        )
        qualification = {
            "receipt_path": qualification_path.as_posix(),
            "receipt_sha256": qualification_sha,
            "status": "accepted",
            "performance_policy": "required",
            "performance_gate": "pass",
            "semantic_sha256": "6" * 64,
            "source_revision": session["identity"]["source_revision"],
            "analyzer_sha256": session["identity"]["analyzer_sha256"],
            "hardware_class": session["identity"]["hardware_class"],
        }
    fault_path = (
        Path("cycles") / "000001" / "fault-injection" / "receipt.json"
    )
    if ordinal == 1:
        fault_sha = write_document(
            root / fault_path,
            {
                "schema": "fixture-fault-injection-projection-v1",
                "status": "accepted",
                "test_binary_sha256": session["identity"][
                    "fault_injection_test_binary"
                ]["sha256"],
            },
        )
    else:
        fault_sha = stability.sha256_file(root / fault_path)
    identity = session["identity"]
    cycle_id = stability.cycle_identity(
        session["id"], ordinal, schedule["schedule_sha256"]
    )
    return {
        "schema": stability.CYCLE_SCHEMA,
        "status": "accepted",
        "failures": [],
        "identity": {
            "id": cycle_id,
            "session_id": session["id"],
            "ordinal": ordinal,
            "schedule_sha256": schedule["schedule_sha256"],
        },
        "mode": mode,
        "source_revision": identity["source_revision"],
        "analyzer_sha256": identity["analyzer_sha256"],
        "realworld": {
            "aggregate_path": aggregate_path.as_posix(),
            "aggregate_sha256": aggregate_sha,
            "slot_count": 9,
            "requested_tus": 900,
            "completed_tus": 900,
            "broken_tus": 0,
            "missing_tus": 0,
            "executed_tus": 900 if mode == "cold" else 0,
            "checkpoint_tus": 0 if mode == "cold" else 900,
            "semantic_sha256": "4" * 64,
            "translation_unit_plan_sha256": "5" * 64,
            "duration_ms": 9000,
            "maximum_peak_memory_kib": 1024,
            "resource_observations_sha256": "7" * 64,
        },
        "fault_injection": {
            "receipt_path": fault_path.as_posix(),
            "receipt_sha256": fault_sha,
            "status": "accepted",
            "source_revision": identity["source_revision"],
            "test_binary_path": identity["fault_injection_test_binary"]["path"],
            "test_binary_sha256": identity["fault_injection_test_binary"]["sha256"],
            "test_count": 6,
            "tests": list(stability.fault_injection.CANONICAL_TESTS),
        },
        "pre_qualification": {
            "receipt_path": pre_qualification_path.as_posix(),
            "receipt_sha256": pre_qualification_sha,
            "status": "accepted",
            "performance_policy": "required",
            "performance_gate": "pass",
            "semantic_sha256": "6" * 64,
            "source_revision": identity["source_revision"],
            "analyzer_sha256": identity["analyzer_sha256"],
            "hardware_class": identity["hardware_class"],
        },
        "qualification": qualification,
    }


def realworld_cycle_evidence(
    root: Path, mode: str,
) -> tuple[Path, Path, Path, str]:
    manifest_path = root / "manifest.json"
    raw_manifest = json.loads(
        (ROOT / "scripts" / "realworld_manifest.json").read_text(encoding="utf-8")
    )
    for project in raw_manifest["projects"]:
        if project["id"] in {"llama-cpp", "tensorflow-lite", "shadps4"}:
            project["expected"]["findings"] = 0
            project["expected"]["exit_code"] = 0
            project["expected"]["fingerprint_sha256"] = (
                stability.realworld.fingerprint_digest([])
            )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(raw_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = stability.realworld.validate_manifest(
        stability.realworld.load_manifest(manifest_path)
    )
    receipt_root = root / "realworld"
    analyzer_sha = "c" * 64
    for project_index, project_id in enumerate(
        manifest["campaigns"]["release-candidate"]["projects"]
    ):
        project = stability.realworld.project_by_id(manifest, project_id)
        expected = project["expected"]
        phases = 2 if "--whole-program" in project["analyzer_args"] else 1
        for repetition in (1, 2, 3):
            shard_root = receipt_root / project_id / f"repeat-{repetition}"
            requested_paths = [
                (
                    root / "fixture-workspaces" / project_id
                    / f"repeat-{repetition}" / f"unit-{index}.cpp"
                ).absolute()
                for index in range(expected["translation_units"])
            ]
            unit_receipts = []
            for phase in (
                ["summary-harvest", "analysis"]
                if phases == 2 else ["analysis"]
            ):
                for index in range(expected["analyzed_tus"]):
                    path_index = index % len(requested_paths)
                    origin = "executed" if mode == "cold" else "checkpoint"
                    unit_receipts.append({
                        "path": requested_paths[path_index].as_posix(),
                        "compile_command_sha256": f"{index + 1:064x}",
                        "command_ordinal": index // len(requested_paths),
                        "phase": phase,
                        "status": "completed",
                        "duration_ms": 10,
                        "peak_memory_kib": 1024,
                        "timeout_seconds": stability.TU_TIMEOUT_SECONDS,
                        "memory_mib": 4096,
                        "origin": origin,
                        "checkpoint_key_sha256": (
                            f"{index + 1000:064x}" if mode == "warm" else ""
                        ),
                        "payload_sha256": (
                            f"{index + 2000:064x}" if mode == "warm" else ""
                        ),
                    })
            report = {
                "complete": True,
                "exit_code": expected["exit_code"],
                "total": expected["findings"],
                "coverage": {
                    "attempted_tus": expected["attempted_tus"],
                    "analyzed_tus": expected["analyzed_tus"],
                    "broken_tus": expected["broken_tus"],
                    "incomplete_functions": expected["incomplete_functions"],
                },
                "diagnostics": [],
                "translation_units": unit_receipts,
            }
            shard_root.mkdir(parents=True, exist_ok=True)
            (shard_root / "report.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (shard_root / "translation-units.txt").write_text(
                "\n".join(path.as_posix() for path in requested_paths) + "\n",
                encoding="utf-8",
            )
            plan = stability.realworld.translation_unit_plan(
                report,
                len(requested_paths),
                expected["analyzed_tus"],
                requested_paths,
                whole_program=phases == 2,
            )
            identity = stability.realworld.receipt_identity(
                manifest,
                project,
                repetition,
                analyzer_sha,
                expected["translation_unit_sha256"],
            )
            receipt = {
                "schema": stability.realworld.SCHEMA,
                "status": "accepted",
                "project": project_id,
                "repetition": repetition,
                "identity": identity,
                "semantic": {
                    "translation_units": {
                        "count": expected["translation_units"],
                        "sha256": expected["translation_unit_sha256"],
                    },
                    "coverage": {
                        "attempted_tus": expected["attempted_tus"],
                        "analyzed_tus": expected["analyzed_tus"],
                        "broken_tus": expected["broken_tus"],
                        "incomplete_functions": expected["incomplete_functions"],
                    },
                    "findings": expected["findings"],
                    "exit_code": expected["exit_code"],
                    "fingerprints": [],
                    "fingerprint_sha256": expected["fingerprint_sha256"],
                },
                "execution": {
                    "duration_seconds": 1.0,
                    "resumed": mode == "warm",
                    "translation_unit_plan": plan,
                },
                "failures": [],
            }
            stability.realworld.write_receipt(
                shard_root / "receipt.json",
                receipt,
            )
    aggregate = stability.realworld.aggregate_receipts(
        manifest, "release-candidate", receipt_root
    )
    aggregate_path = root / "aggregate" / "receipt.json"
    stability.realworld.write_receipt(aggregate_path, aggregate)
    return manifest_path, receipt_root, aggregate_path, analyzer_sha


def build_evidence_bundle(root: Path) -> dict:
    policy = stability.validate_policy(canonical_policy(), ROOT)
    schedule = stability.build_schedule(policy, ROOT)
    authority_records: dict[str, dict[str, str]] = {}
    authority_paths = {
        "build_authority": Path("authorities") / "build" / "receipt.json",
        "determinism": Path("authorities") / "prerequisites" / "determinism.json",
        "hosted_exact_head": (
            Path("authorities") / "prerequisites" / "hosted-exact-head.json"
        ),
        "quality_floor": Path("authorities") / "prerequisites" / "quality-floor.json",
    }
    for authority, relative in authority_paths.items():
        digest = write_document(
            root / relative,
            {"authority": authority, "fixture": True, "status": "accepted"},
        )
        authority_records[authority] = {
            "path": relative.as_posix(),
            "sha256": digest,
        }
    diagnostic_records: dict[str, dict[str, str]] = {}
    for profile in ("address", "undefined"):
        relative = Path("diagnostics") / profile / "receipt.json"
        digest = write_document(
            root / relative,
            {"fixture": "sanitizer", "profile": profile, "status": "accepted"},
        )
        diagnostic_records[profile] = {
            "path": relative.as_posix(),
            "sha256": digest,
        }
    identity = session_material()
    identity["build_authority_receipt_sha256"] = authority_records[
        "build_authority"
    ]["sha256"]
    identity["prerequisite_receipts"] = {
        prerequisite: authority_records[prerequisite]["sha256"]
        for prerequisite in ("determinism", "hosted_exact_head", "quality_floor")
    }
    identity["sanitizer_receipts"] = {
        profile: record["sha256"]
        for profile, record in diagnostic_records.items()
    }
    identity["fault_injection_test_binary"]["sanitizer_receipt_sha256"] = (
        identity["sanitizer_receipts"]["undefined"]
    )
    session = {
        "id": stability.build_session_identity(identity),
        "controller_id": CONTROLLER_ID,
        "identity": identity,
    }
    cycles = [
        cycle_document(root, session, schedule, 1, "cold"),
        cycle_document(root, session, schedule, 2, "warm"),
    ]
    cycle_records = []
    for ordinal, cycle in enumerate(cycles, 1):
        relative = Path("cycles") / f"{ordinal:06d}" / "cycle.json"
        digest = write_document(root / relative, cycle)
        cycle_records.append({"path": relative.as_posix(), "sha256": digest})

    journal_path = root / "journal.jsonl"
    action_receipt_hashes = write_terminal_action_receipts(
        root, policy, schedule, session["id"]
    )
    events = accepted_journal(
        session_id=session["id"],
        cycle_events=[
            {
                "cycle_id": cycle["identity"]["id"],
                "receipt_sha256": record["sha256"],
            }
            for cycle, record in zip(cycles, cycle_records, strict=True)
        ],
        action_receipt_hashes=action_receipt_hashes,
    )
    journal_path.write_bytes(b"".join(
        stability.canonical_json(event) + b"\n" for event in events
    ))
    timeline = stability.verify_journal(
        events,
        policy,
        expected_session_id=session["id"],
        expected_controller_id=CONTROLLER_ID,
        expected_boot_id=BOOT_ID,
        expected_schedule=schedule,
        evidence_root=root,
    )
    cycle_summary = stability.validate_cycle_documents(
        cycles, root, session, schedule, policy
    )
    establishment_path = Path("establishment") / "receipt.json"
    establishment_sha = write_document(
        root / establishment_path,
        {
            "fixture": True,
            "schema": "codeskeptic-stability-establishment-v1",
            "status": "accepted",
        },
    )
    base_receipt = {
        "schema": stability.RECEIPT_SCHEMA,
        "status": "accepted",
        "policy": {
            "path": "scripts/stability_manifest.json",
            "sha256": stability.sha256_file(POLICY_PATH),
        },
        "session": session,
        "schedule": schedule,
        "timeline": timeline,
        "cycles": cycle_records,
        "cycle_summary": cycle_summary,
        "establishment": {
            "path": establishment_path.as_posix(),
            "sha256": establishment_sha,
        },
        "authorities": authority_records,
        "diagnostics": diagnostic_records,
        "gates": {
            "scope": "pass",
            "crash_hang": "pass",
            "semantic": "pass",
            "performance": "pass",
            "performance_scope": stability.PERFORMANCE_SCOPE,
            "coverage": "pass",
            "restart": "pass",
            "sanitizer": "pass",
            "fault_injection": "pass",
            "resources": "pass",
            "orphan_free": "pass",
        },
        "failures": [],
    }
    return stability.finalize_evidence(root, base_receipt)


def reseal_outer(root: Path, receipt: dict) -> None:
    receipt_path = root / "receipt.json"
    data = stability.canonical_document(receipt)
    receipt_path.write_bytes(data)
    sidecar = root / "receipt.json.sha256"
    sidecar.write_text(
        f"{stability.sha256_file(receipt_path)}  receipt.json\n",
        encoding="utf-8",
    )
    manifest_paths = [
        "receipt.json",
        "receipt.json.sha256",
        *[item["path"] for item in receipt["artifacts"]],
    ]
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{stability.sha256_file(root / relative)}  {relative}\n"
            for relative in manifest_paths
        ),
        encoding="utf-8",
    )


class FakeClock:
    def __init__(self) -> None:
        self.monotonic = 0
        self.boottime = 0
        self.current_boot_id = BOOT_ID
        self.utc = dt.datetime(2026, 8, 23, tzinfo=dt.timezone.utc)

    def monotonic_ns(self) -> int:
        return self.monotonic

    def boottime_ns(self) -> int:
        return self.boottime

    def utc_now(self) -> dt.datetime:
        return self.utc

    def boot_id(self) -> str:
        return self.current_boot_id

    def sleep(self, seconds: float) -> None:
        self.advance(seconds)

    def advance(self, seconds: float, *, suspend_seconds: float = 0) -> None:
        delta = int(seconds * 1_000_000_000)
        self.monotonic += delta
        self.boottime += delta + int(suspend_seconds * 1_000_000_000)
        self.utc += dt.timedelta(seconds=seconds + suspend_seconds)


class FakeCommandHandle:
    def __init__(
        self,
        clock: FakeClock,
        *,
        finish_after_seconds: float | None,
        exit_code: int,
        terminate_exits: bool = True,
        on_natural_finish: object | None = None,
        wait_error: BaseException | None = None,
    ) -> None:
        self.clock = clock
        self.pid = 4321
        self.remaining = finish_after_seconds
        self.exit_code = exit_code
        self.terminate_exits = terminate_exits
        self.on_natural_finish = on_natural_finish
        self.wait_error = wait_error
        self.finished = False
        self.group_live = True
        self.wait_calls: list[float] = []
        self.terminate_calls = 0
        self.kill_calls = 0
        self.unexpected: list[int] = []

    def wait(self, timeout_seconds: float) -> int | None:
        if timeout_seconds <= 0:
            raise AssertionError("wait timeout must be positive")
        self.wait_calls.append(timeout_seconds)
        if self.wait_error is not None:
            error = self.wait_error
            self.wait_error = None
            raise error
        if self.finished:
            return self.exit_code
        if self.remaining is None:
            self.clock.advance(timeout_seconds)
            return None
        if self.remaining <= timeout_seconds:
            self.clock.advance(self.remaining)
            self.remaining = 0
            self.finished = True
            self.group_live = False
            if self.on_natural_finish is not None:
                callback = self.on_natural_finish
                self.on_natural_finish = None
                callback()
            return self.exit_code
        self.remaining -= timeout_seconds
        self.clock.advance(timeout_seconds)
        return None

    def terminate_group(self) -> None:
        self.terminate_calls += 1
        if self.terminate_exits:
            self.finished = True
            self.group_live = False
            self.exit_code = -15

    def kill_group(self) -> None:
        self.kill_calls += 1
        self.finished = True
        self.group_live = False
        self.exit_code = -9

    def group_alive(self) -> bool:
        return self.group_live

    def wait_group(self, timeout_seconds: float) -> bool:
        del timeout_seconds
        return not self.group_live

    def unexpected_pids(self) -> list[int]:
        return list(self.unexpected)

    def terminate_unexpected(self) -> None:
        self.unexpected.clear()

    def kill_unexpected(self) -> None:
        self.unexpected.clear()

    def wait_unexpected(self, timeout_seconds: float) -> bool:
        del timeout_seconds
        return not self.unexpected


class FakeCommandRunner:
    def __init__(self, handle: FakeCommandHandle) -> None:
        self.handle = handle
        self.calls: list[dict] = []

    def start(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        stdout_path: Path,
        stderr_path: Path,
    ) -> FakeCommandHandle:
        self.calls.append({
            "argv": list(argv),
            "cwd": cwd,
            "env": dict(env),
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
        })
        return self.handle


class ScriptedCycleExecutor:
    def __init__(
        self,
        writer: stability.JournalWriter,
        root: Path,
        cycle_durations_seconds: list[int],
    ) -> None:
        self.writer = writer
        self.root = root
        self.cycle_durations_seconds = cycle_durations_seconds
        self.calls: list[int] = []

    def __call__(self, plan: dict) -> dict:
        cycle_ordinal = plan["ordinal"]
        self.calls.append(cycle_ordinal)
        total_seconds = self.cycle_durations_seconds[cycle_ordinal - 1]
        actions = plan["actions"]
        remaining_total = total_seconds
        durations = []
        for action in actions:
            duration = min(remaining_total, action["timeout_seconds"])
            durations.append(duration)
            remaining_total -= duration
        if remaining_total:
            raise AssertionError("fixture duration exceeds planned action capacity")
        for action, duration in zip(actions, durations, strict=True):
            child_pid = 5000 + cycle_ordinal * 100 + action["ordinal"]
            self.writer.append("action-start", {
                "action_id": action["id"],
                "kind": action["kind"],
                "cycle_ordinal": cycle_ordinal,
                "action_ordinal": action["ordinal"],
                "timeout_seconds": action["timeout_seconds"],
                "child_pid": child_pid,
            })
            remaining = duration
            gap = self.writer.policy["heartbeat"]["maximum_gap_seconds"]
            while remaining > gap:
                self.writer.clock.advance(gap)
                remaining -= gap
                self.writer.append("heartbeat", {
                    "stage": action["kind"],
                    "child_pid": child_pid,
                    "action_id": action["id"],
                    "cycle_ordinal": cycle_ordinal,
                    "action_ordinal": action["ordinal"],
                })
            self.writer.clock.advance(remaining)
            action_path = (
                self.root / "cycles" / f"{cycle_ordinal:06d}" / "actions"
                / f"{action['ordinal']:02d}.json"
            )
            action_sha = write_document(action_path, {
                "action_id": action["id"],
                "schema": "fixture-stability-action-v1",
                "status": "accepted",
            })
            self.writer.append("action-finish", {
                "accepted": True,
                "exit_code": 0,
                "kind": action["kind"],
                "action_id": action["id"],
                "outcome": "normal",
                "receipt_sha256": action_sha,
                "child_pid": child_pid,
                "cycle_ordinal": cycle_ordinal,
                "action_ordinal": action["ordinal"],
            })
        cycle_path = (
            self.root / "cycles" / f"{cycle_ordinal:06d}" / "cycle.json"
        )
        cycle_sha = write_document(cycle_path, {
            "cycle_id": plan["id"],
            "mode": plan["mode"],
            "schema": "fixture-stability-cycle-v1",
            "status": "accepted",
        })
        return {
            "cycle_id": plan["id"],
            "mode": plan["mode"],
            "receipt_path": cycle_path,
            "receipt_sha256": cycle_sha,
            "slot_count": 9,
        }


class ManifestContractTest(unittest.TestCase):
    def test_canonical_policy_binds_the_exact_cold_warm_scope(self) -> None:
        raw = canonical_policy()
        normalized = stability.validate_policy(raw, ROOT)
        self.assertEqual(normalized, raw)
        self.assertEqual(normalized["completion"], {
            "basis": "exact-cold-warm-matrix",
            "required_cold_rounds": 1,
            "required_complete_rounds": 2,
            "required_realworld_shards": 18,
            "required_warm_rounds": 1,
        })
        self.assertEqual(normalized["matrix"], {
            "manifest": "scripts/realworld_manifest.json",
            "minimum_complete_rounds": 2,
            "tier": "release-candidate",
        })
        self.assertEqual(
            normalized["diagnostics"]["required_sanitizer_profiles"],
            ["address", "undefined"],
        )
        self.assertEqual(normalized["resources"], {
            "maximum_open_fds": 4096,
            "rss_budget": "per-translation-unit-required",
            "time_budget": "per-translation-unit-required",
            "tu_memory_mib": 4096,
            "tu_timeout_seconds": 300,
        })
        self.assertEqual(normalized["fault_injection"], {
            "mode": "cold-only",
            "required_test_count": 6,
            "required_tests": list(stability.fault_injection.CANONICAL_TESTS),
            "timeout_seconds": stability.fault_injection.TIMEOUT_SECONDS,
        })

    def test_policy_rejects_weakened_scope_unknown_fields_and_boolean_numbers(self) -> None:
        mutations = []
        short = canonical_policy()
        short["completion"]["required_realworld_shards"] -= 1
        mutations.append(short)
        unknown = canonical_policy()
        unknown["shortcut"] = True
        mutations.append(unknown)
        boolean = canonical_policy()
        boolean["heartbeat"]["maximum_gap_seconds"] = True
        mutations.append(boolean)
        fd_drift = canonical_policy()
        fd_drift["resources"]["maximum_open_fds"] -= 1
        mutations.append(fd_drift)
        timeout_drift = canonical_policy()
        timeout_drift["resources"]["tu_timeout_seconds"] = 86_400
        mutations.append(timeout_drift)
        memory_drift = canonical_policy()
        memory_drift["resources"]["tu_memory_mib"] = 131_072
        mutations.append(memory_drift)
        fault_drift = canonical_policy()
        fault_drift["fault_injection"]["required_tests"] = fault_drift[
            "fault_injection"
        ]["required_tests"][:-1]
        mutations.append(fault_drift)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(stability.StabilityError):
                    stability.validate_policy(mutation, ROOT)

    def test_policy_rejects_absolute_traversal_and_wrong_authority_inputs(self) -> None:
        for path in ("/tmp/manifest.json", "../manifest.json"):
            mutation = canonical_policy()
            mutation["matrix"]["manifest"] = path
            with self.subTest(path=path):
                with self.assertRaises(stability.StabilityError):
                    stability.validate_policy(mutation, ROOT)
        wrong_tier = canonical_policy()
        wrong_tier["matrix"]["tier"] = "weekend"
        with self.assertRaises(stability.StabilityError):
            stability.validate_policy(wrong_tier, ROOT)
        record_only = canonical_policy()
        record_only["qualification"]["performance_policy"] = "record-only"
        with self.assertRaises(stability.StabilityError):
            stability.validate_policy(record_only, ROOT)

    def test_runtime_fd_limit_must_equal_the_fixed_hard_budget(self) -> None:
        policy = stability.validate_policy(canonical_policy(), ROOT)
        available = mock.Mock(RLIMIT_NOFILE=7)
        available.getrlimit.return_value = (4096, 4096)
        with mock.patch.object(stability, "resource", available):
            limits = stability.verify_runtime_resource_limits(policy)
        self.assertEqual(limits["maximum_open_fds"], 4096)
        available.getrlimit.return_value = (4096, 8192)
        with mock.patch.object(stability, "resource", available):
            with self.assertRaisesRegex(stability.StabilityError, "FD limit"):
                stability.verify_runtime_resource_limits(policy)
        with mock.patch.object(stability, "resource", None):
            with self.assertRaisesRegex(stability.StabilityError, "unavailable"):
                stability.verify_runtime_resource_limits(policy)

    def test_release_candidate_window_is_bounded_scheduling_metadata(
        self,
    ) -> None:
        manifest = json.loads(
            (ROOT / "scripts" / "realworld_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "realworld-manifest.json"
            manifest["campaigns"]["release-candidate"]["window_minutes"] = 60
            path.write_text(json.dumps(manifest), encoding="utf-8")
            stability._validate_matrix_authority(path, "release-candidate")

            for invalid in (
                0,
                stability.MAX_MATRIX_SCHEDULING_WINDOW_MINUTES + 1,
                True,
            ):
                with self.subTest(invalid=invalid):
                    manifest["campaigns"]["release-candidate"][
                        "window_minutes"
                    ] = invalid
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                    with self.assertRaisesRegex(
                        stability.StabilityError,
                        "window|matrix authority",
                    ):
                        stability._validate_matrix_authority(
                            path, "release-candidate"
                        )


class RuntimeConfigContractTest(unittest.TestCase):
    def test_exact_pinned_runtime_config_is_accepted_without_ambient_fields(self) -> None:
        config = runtime_config()
        self.assertEqual(stability.validate_runtime_config(config), config)

    def test_runtime_config_rejects_image_path_tool_and_schema_drift(self) -> None:
        mutations: list[tuple[str, dict]] = []
        unknown = runtime_config()
        unknown["ambient"] = True
        mutations.append(("unknown", unknown))
        image = runtime_config()
        image["runtime"]["image_id"] = "sha256:" + "0" * 64
        mutations.append(("image", image))
        escape = runtime_config()
        escape["analyzer"]["path"] = "/tmp/codeskeptic"
        mutations.append(("escape", escape))
        relative = runtime_config()
        relative["prerequisites"]["quality_floor"]["root"] = "authority/quality"
        mutations.append(("relative", relative))
        jobs = runtime_config()
        jobs["qualification"]["jobs"] = 4
        mutations.append(("jobs", jobs))
        tool = runtime_config()
        tool["qualification"]["tools"]["cmake"] = "/usr/local/bin/cmake"
        mutations.append(("tool", tool))
        fault_path = runtime_config()
        fault_path["fault_injection"]["test_binary"] = (
            "/authority/build/codeskeptic_tests"
        )
        mutations.append(("fault-path", fault_path))
        fault_sha = runtime_config()
        fault_sha["fault_injection"]["test_binary_sha256"] = "0" * 63
        mutations.append(("fault-sha", fault_sha))
        cgroup = runtime_config()
        cgroup["qualification"]["measurement_cgroup"] = (
            "/sys/fs/cgroup/system.slice/codeskeptic-stability.service/measurement"
        )
        mutations.append(("measurement-cgroup", cgroup))
        build_layout = runtime_config()
        build_layout["build_authority"]["build_path"] = (
            "/authority/alternate-build"
        )
        mutations.append(("build-layout", build_layout))
        sanitizer_layout = runtime_config()
        sanitizer_layout["sanitizers"]["address"]["test_build"] = (
            "/authority/sanitizer-builds/address-tests"
        )
        mutations.append(("sanitizer-layout", sanitizer_layout))
        release_layout = runtime_config()
        release_layout["qualification"]["release_build"] = (
            "/authority/release/alternate-build"
        )
        mutations.append(("release-layout", release_layout))
        for name, mutation in mutations:
            with self.subTest(name=name):
                with self.assertRaises(stability.StabilityError):
                    stability.validate_runtime_config(mutation)

    def test_canonical_config_and_launch_receipt_round_trip_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "runtime.json"
            config = runtime_config()
            config_sha = write_canonical_pair(config_path, config)
            self.assertEqual(
                stability.load_runtime_config_file(config_path), config
            )

            launch = stability.build_runtime_launch_receipt(config_sha, BOOT_ID)
            self.assertEqual(
                launch["container"]["cgroup_parent"],
                stability.RUNTIME_CGROUP_PARENT,
            )
            launch_path = root / "launch" / "receipt.json"
            write_canonical_pair(launch_path, launch)
            self.assertEqual(
                stability.load_runtime_launch_receipt(
                    launch_path,
                    config,
                    runtime_config_sha256=config_sha,
                    boot_id=BOOT_ID,
                ),
                launch,
            )

    def test_config_and_launch_reject_noncanonical_checksum_and_topology_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = runtime_config()
            config_path = root / "runtime.json"
            config_sha = write_canonical_pair(config_path, config)
            pretty = json.loads(config_path.read_text(encoding="utf-8"))
            config_path.write_text(json.dumps(pretty), encoding="utf-8")
            with self.assertRaisesRegex(stability.StabilityError, "canonical"):
                stability.load_runtime_config_file(config_path)

            write_canonical_pair(config_path, config)
            Path(f"{config_path}.sha256").write_text(
                f"{'0' * 64}  runtime.json\n", encoding="ascii"
            )
            with self.assertRaisesRegex(stability.StabilityError, "checksum"):
                stability.load_runtime_config_file(config_path)

            launch = stability.build_runtime_launch_receipt(config_sha, BOOT_ID)
            launch["container"]["network"] = "host"
            with self.assertRaisesRegex(stability.StabilityError, "topology"):
                stability.validate_runtime_launch_receipt(
                    launch,
                    config,
                    runtime_config_sha256=config_sha,
                    boot_id=BOOT_ID,
                )
            launch = stability.build_runtime_launch_receipt(config_sha, BOOT_ID)
            launch["container"]["cgroup_parent"] = "codeskeptic-p10-09"
            with self.assertRaisesRegex(stability.StabilityError, "topology"):
                stability.validate_runtime_launch_receipt(
                    launch,
                    config,
                    runtime_config_sha256=config_sha,
                    boot_id=BOOT_ID,
                )

    def test_live_fault_binary_must_match_the_runtime_config(self) -> None:
        import run_determinism_qualification as determinism

        config = runtime_config()
        paths = {
            Path(config["policy"]["path"]): config["policy"]["sha256"],
            Path(config["analyzer"]["path"]): config["analyzer"]["sha256"],
        }

        def digest(path: Path) -> str:
            return paths[path]

        tree = mock.Mock(
            returncode=0,
            stdout=(config["source"]["tree_sha1"] + "\n").encode("ascii"),
        )
        source_identity = {
            "revision": config["source"]["revision"],
            "manifest_sha256": config["source"]["manifest_sha256"],
        }
        with (
            mock.patch.object(stability, "sha256_file", side_effect=digest),
            mock.patch.object(
                stability.fault_injection,
                "sha256_binary",
                return_value="f" * 64,
            ),
            mock.patch.object(stability, "_load_json", return_value=canonical_policy()),
            mock.patch.object(
                stability, "validate_policy", return_value=canonical_policy()
            ),
            mock.patch.object(determinism, "source_manifest", return_value=source_identity),
            mock.patch.object(
                determinism, "_git_authority_environment", return_value={}
            ),
            mock.patch.object(stability.subprocess, "run", return_value=tree),
        ):
            with self.assertRaisesRegex(
                stability.StabilityError, "fault-injection test binary"
            ):
                stability.verify_runtime_source_and_policy(config)

    def test_launch_sealer_is_canonical_verified_and_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "runtime.json"
            write_canonical_pair(config_path, runtime_config())
            launch_root = root / "launch"
            launch_root.mkdir()
            receipt = stability.seal_runtime_launch_receipt(
                config_path, launch_root, BOOT_ID
            )
            self.assertEqual(receipt["boot_id"], BOOT_ID)
            self.assertEqual(
                stability.verify_runtime_launch_files(
                    config_path, launch_root / "receipt.json", BOOT_ID
                ),
                receipt,
            )
            with self.assertRaises(stability.StabilityError):
                stability.seal_runtime_launch_receipt(
                    config_path, launch_root, BOOT_ID
                )


class SessionIdentityContractTest(unittest.TestCase):
    def test_exact_authorities_derive_the_session_identity(self) -> None:
        material = session_material()
        self.assertEqual(
            stability.build_session_identity(material),
            stability.digest_json(material),
        )

    def test_identity_rejects_unknown_malformed_and_missing_diagnostics(self) -> None:
        unknown = session_material()
        unknown["ambient"] = "not-authority"
        malformed = session_material()
        malformed["source_revision"] = "a" * 39
        missing = session_material()
        del missing["sanitizer_receipts"]["undefined"]
        missing_prerequisite = session_material()
        del missing_prerequisite["prerequisite_receipts"]["hosted_exact_head"]
        missing_mirror = session_material()
        del missing_mirror["realworld_mirror_authority_sha256"]
        missing_fault = session_material()
        del missing_fault["fault_injection_test_binary"]
        unlinked_fault = session_material()
        unlinked_fault["fault_injection_test_binary"][
            "sanitizer_receipt_sha256"
        ] = "f" * 64
        for name, value in (
            ("unknown", unknown),
            ("malformed", malformed),
            ("missing", missing),
            ("missing-prerequisite", missing_prerequisite),
            ("missing-mirror", missing_mirror),
            ("missing-fault", missing_fault),
            ("unlinked-fault", unlinked_fault),
        ):
            with self.subTest(name=name):
                with self.assertRaises(stability.StabilityError):
                    stability.build_session_identity(value)

    def test_runtime_session_record_binds_config_launch_and_fixed_manifests(self) -> None:
        config = runtime_config()
        record = stability.build_runtime_session_record(
            config,
            runtime_config_sha256="4" * 64,
            runtime_launch_receipt_sha256="5" * 64,
            boot_id=BOOT_ID,
            controller_id=CONTROLLER_ID,
            repository_root=ROOT,
        )
        self.assertEqual(record["controller_id"], CONTROLLER_ID)
        self.assertEqual(record["identity"]["boot_id"], BOOT_ID)
        self.assertEqual(
            record["identity"]["fault_injection_test_binary"],
            {
                "path": config["fault_injection"]["test_binary"],
                "sha256": config["fault_injection"]["test_binary_sha256"],
                "sanitizer_profile": "undefined",
                "sanitizer_receipt_sha256": config["sanitizers"]["undefined"][
                    "receipt_sha256"
                ],
            },
        )
        self.assertEqual(
            record["identity"]["realworld_manifest_sha256"],
            stability.sha256_file(ROOT / "scripts" / "realworld_manifest.json"),
        )
        self.assertEqual(
            record["id"],
            stability.build_session_identity(record["identity"]),
        )


class ScheduleIdentityContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = stability.validate_policy(canonical_policy(), ROOT)

    def test_schedule_reuses_the_exact_realworld_release_candidate_plan(self) -> None:
        schedule = stability.build_schedule(self.policy, ROOT)
        self.assertEqual(schedule["tier"], "release-candidate")
        self.assertEqual(schedule["slot_count"], 9)
        self.assertEqual(
            [(slot["project"], slot["repetition"]) for slot in schedule["slots"]],
            [
                (project, repetition)
                for project in ("llama-cpp", "tensorflow-lite", "shadps4")
                for repetition in (1, 2, 3)
            ],
        )
        self.assertEqual(
            schedule["schedule_sha256"],
            stability.digest_json(schedule["slots"]),
        )

    def test_cycle_and_action_identities_bind_every_ordinal_and_parameter(self) -> None:
        schedule = stability.build_schedule(self.policy, ROOT)
        cycle = stability.cycle_identity(
            SESSION_ID, 1, schedule["schedule_sha256"]
        )
        action = stability.action_identity(
            cycle,
            0,
            "realworld",
            {"project": "llama-cpp", "repetition": 1},
        )
        self.assertRegex(cycle, r"^[0-9a-f]{64}$")
        self.assertRegex(action, r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            cycle,
            stability.cycle_identity(
                SESSION_ID, 2, schedule["schedule_sha256"]
            ),
        )
        self.assertNotEqual(
            action,
            stability.action_identity(
                cycle,
                0,
                "realworld",
                {"project": "llama-cpp", "repetition": 2},
            ),
        )


class ActionSpecContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = runtime_config()
        policy = stability.validate_policy(canonical_policy(), ROOT)
        schedule = stability.build_schedule(policy, ROOT)
        self.plan = stability.build_cycle_plan(policy, schedule, SESSION_ID, 1)

    def test_fixed_actions_use_pinned_paths_environment_and_isolated_outputs(self) -> None:
        qualification = stability.build_action_spec(
            self.config, self.plan, self.plan["actions"][0]
        )
        self.assertEqual(qualification["cwd"], Path("/authority/source"))
        self.assertEqual(
            qualification["receipt_path"],
            Path("/evidence/cycles/000001/qualification/pre/receipt.json"),
        )
        self.assertEqual(
            qualification["env"],
            {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/runtime/home",
                "TMPDIR": "/runtime/tmp",
                "LC_ALL": "C.UTF-8",
                "LANG": "C.UTF-8",
                "TZ": "UTC",
                "PYTHONDONTWRITEBYTECODE": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
        )
        self.assertEqual(
            qualification["argv"][qualification["argv"].index("--output") + 1],
            "/evidence/cycles/000001/qualification/pre",
        )
        wrapper = stability.build_action_wrapper_spec(
            self.config,
            self.plan,
            self.plan["actions"][0],
            config_path=Path("/config/runtime.json"),
            plan_path=Path("/evidence/cycles/000001/plan.json"),
        )
        self.assertEqual(
            wrapper["argv"],
            [
                "/usr/bin/python3",
                "-B",
                "/authority/source/scripts/run_stability_campaign.py",
                "_action",
                "--config",
                "/config/runtime.json",
                "--plan",
                "/evidence/cycles/000001/plan.json",
                "--action-ordinal",
                "0",
                "--evidence",
                "/evidence",
                "--runtime",
                "/runtime",
            ],
        )
        self.assertEqual(
            wrapper["receipt_path"],
            Path("/evidence/cycles/000001/actions/00-qualification/receipt.json"),
        )
        self.assertNotIn("--prepare-release-candidate", qualification["argv"])
        self.assertEqual(
            qualification["argv"][
                qualification["argv"].index("--release-source") + 1
            ],
            "/authority/release/source",
        )

        realworld_action = next(
            action for action in self.plan["actions"]
            if action["kind"] == "realworld"
        )
        realworld_spec = stability.build_action_spec(
            self.config, self.plan, realworld_action
        )
        self.assertEqual(
            realworld_spec["argv"][realworld_spec["argv"].index("--workspace") + 1],
            "/runtime/realworld/workspaces/llama-cpp",
        )
        self.assertEqual(
            realworld_spec["argv"][realworld_spec["argv"].index("--checkpoint") + 1],
            "/runtime/realworld/checkpoints/llama-cpp/repeat-1/receipt.json",
        )
        self.assertEqual(
            realworld_spec["argv"][
                realworld_spec["argv"].index("--tu-timeout-seconds") + 1
            ],
            "300",
        )
        self.assertEqual(
            realworld_spec["argv"][
                realworld_spec["argv"].index("--tu-memory-mib") + 1
            ],
            "4096",
        )
        self.assertEqual(
            realworld_spec["receipt_path"],
            Path(
                "/evidence/cycles/000001/realworld/llama-cpp/"
                "repeat-1/receipt.json"
            ),
        )

        aggregate_action = next(
            action for action in self.plan["actions"]
            if action["kind"] == "aggregate"
        )
        aggregate_spec = stability.build_action_spec(
            self.config, self.plan, aggregate_action
        )
        self.assertEqual(
            aggregate_spec["receipt_path"],
            Path("/evidence/cycles/000001/realworld/aggregate/receipt.json"),
        )
        self.assertEqual(
            aggregate_spec["argv"][aggregate_spec["argv"].index("--receipts") + 1],
            "/evidence/cycles/000001/realworld",
        )

        fault_action = next(
            action for action in self.plan["actions"]
            if action["kind"] == "fault-injection"
        )
        fault_spec = stability.build_action_spec(
            self.config, self.plan, fault_action
        )
        self.assertEqual(
            fault_spec["receipt_path"],
            Path("/evidence/cycles/000001/fault-injection/receipt.json"),
        )
        self.assertEqual(
            fault_spec["argv"],
            [
                "/usr/bin/python3", "-B",
                "/authority/source/scripts/run_stability_fault_injection.py",
                "run", "--source-revision", self.config["source"]["revision"],
                "--binary", self.config["fault_injection"]["test_binary"],
                "--binary-sha256",
                self.config["fault_injection"]["test_binary_sha256"],
                "--output", "/evidence/cycles/000001/fault-injection",
            ],
        )

    def test_cold_and_warm_actions_reuse_project_workspace_only(self) -> None:
        policy = stability.validate_policy(canonical_policy(), ROOT)
        schedule = stability.build_schedule(policy, ROOT)
        plans = [
            stability.build_cycle_plan(policy, schedule, SESSION_ID, ordinal)
            for ordinal in (1, 2)
        ]
        workspaces: dict[str, set[str]] = {}
        checkpoints: dict[str, set[str]] = {}
        for plan in plans:
            for action in plan["actions"]:
                if action["kind"] != "realworld":
                    continue
                spec = stability.build_action_spec(self.config, plan, action)
                argv = spec["argv"]
                project = action["parameters"]["project"]
                workspaces.setdefault(project, set()).add(
                    argv[argv.index("--workspace") + 1]
                )
                checkpoints.setdefault(project, set()).add(
                    argv[argv.index("--checkpoint") + 1]
                )
        self.assertEqual(set(workspaces), set(stability.REQUIRED_MATRIX_PROJECTS))
        for project in stability.REQUIRED_MATRIX_PROJECTS:
            self.assertEqual(
                workspaces[project],
                {f"/runtime/realworld/workspaces/{project}"},
            )
            self.assertEqual(
                checkpoints[project],
                {
                    f"/runtime/realworld/checkpoints/{project}/"
                    f"repeat-{repetition}/receipt.json"
                    for repetition in (1, 2, 3)
                },
            )

    def test_action_spec_rejects_plan_and_action_identity_drift(self) -> None:
        unknown_plan = copy.deepcopy(self.plan)
        unknown_plan["ambient"] = True
        bad_hash = copy.deepcopy(self.plan)
        bad_hash["plan_sha256"] = "0" * 64
        bad_action = copy.deepcopy(self.plan["actions"][1])
        bad_action["parameters"]["repetition"] = 2
        for name, plan, action in (
            ("unknown-plan", unknown_plan, unknown_plan["actions"][0]),
            ("plan-hash", bad_hash, bad_hash["actions"][0]),
            ("action", self.plan, bad_action),
        ):
            with self.subTest(name=name):
                with self.assertRaises(stability.StabilityError):
                    stability.build_action_spec(self.config, plan, action)


class FaultInjectionActionContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = runtime_config()
        policy = stability.validate_policy(canonical_policy(), ROOT)
        schedule = stability.build_schedule(policy, ROOT)
        self.plan = stability.build_cycle_plan(policy, schedule, SESSION_ID, 1)
        self.action = next(
            action for action in self.plan["actions"]
            if action["kind"] == "fault-injection"
        )
        self.spec = stability.build_action_spec(
            self.config,
            self.plan,
            self.action,
            evidence_root=self.root,
            runtime_root=self.root / "runtime",
        )
        self.spec["receipt_path"].parent.mkdir(parents=True)
        self.spec["receipt_path"].write_bytes(stability.canonical_document({
            "fixture": "fault-injection",
            "status": "accepted",
        }))
        self.projection = {
            "schema": stability.FAULT_INJECTION_PROJECTION_SCHEMA,
            "status": "pass",
            "source_revision": self.config["source"]["revision"],
            "test_binary_path": self.config["fault_injection"]["test_binary"],
            "test_binary_sha256": self.config["fault_injection"][
                "test_binary_sha256"
            ],
            "receipt_sha256": stability.sha256_file(self.spec["receipt_path"]),
            "test_count": len(stability.fault_injection.CANONICAL_TESTS),
            "tests": list(stability.fault_injection.CANONICAL_TESTS),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_projection_is_exact_and_rederived_from_standalone_verifier(self) -> None:
        standalone = {
            "schema": stability.fault_injection.SCHEMA,
            "status": "accepted",
            "failures": [],
            "source_revision": self.config["source"]["revision"],
            "binary": {
                "path": self.config["fault_injection"]["test_binary"],
                "sha256": self.config["fault_injection"]["test_binary_sha256"],
            },
            "command": {
                "filter": ":".join(stability.fault_injection.REQUIRED_TESTS),
                "timeout_seconds": stability.fault_injection.TIMEOUT_SECONDS,
            },
            "results": {
                "test_count": len(stability.fault_injection.CANONICAL_TESTS),
                "tests": list(stability.fault_injection.CANONICAL_TESTS),
                "failures": 0,
                "disabled": 0,
                "errors": 0,
            },
            "artifacts": {},
        }
        with mock.patch.object(
            stability.fault_injection,
            "verify_evidence",
            return_value=standalone,
        ) as verifier:
            projection = stability.verify_planned_action_projection(
                self.config, self.plan, self.action, self.spec
            )
        self.assertEqual(projection, self.projection)
        verifier.assert_called_once_with(
            self.spec["receipt_root"],
            source_revision=self.config["source"]["revision"],
            binary=Path(self.config["fault_injection"]["test_binary"]),
            binary_sha256=self.config["fault_injection"]["test_binary_sha256"],
        )

    def test_projection_rejects_status_inventory_identity_and_receipt_tamper(self) -> None:
        mutations = []
        status = copy.deepcopy(self.projection)
        status["status"] = "fail"
        mutations.append(status)
        tests = copy.deepcopy(self.projection)
        tests["tests"] = tests["tests"][:-1]
        mutations.append(tests)
        binary = copy.deepcopy(self.projection)
        binary["test_binary_sha256"] = "f" * 64
        mutations.append(binary)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(stability.StabilityError):
                    stability._validate_action_projection(
                        mutation, self.config, self.action
                    )
        receipt = copy.deepcopy(self.projection)
        receipt["receipt_sha256"] = "f" * 64
        with self.assertRaisesRegex(stability.StabilityError, "checksum"):
            stability.build_action_receipt(
                self.config,
                self.plan,
                self.action,
                receipt,
                evidence_root=self.root,
                runtime_root=self.root / "runtime",
            )


class ActionReceiptContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = runtime_config()
        policy = stability.validate_policy(canonical_policy(), ROOT)
        schedule = stability.build_schedule(policy, ROOT)
        self.plan = stability.build_cycle_plan(
            policy, schedule, SESSION_ID, 1
        )
        self.action = self.plan["actions"][0]
        self.spec = stability.build_action_spec(
            self.config,
            self.plan,
            self.action,
            evidence_root=self.root,
            runtime_root=self.root / "runtime",
        )
        self.spec["receipt_path"].parent.mkdir(parents=True)
        self.spec["receipt_path"].write_bytes(stability.canonical_document({
            "schema": "fixture-inner-v1",
            "status": "accepted",
        }))
        self.projection = {
            "schema": stability.DETERMINISM_PROJECTION_SCHEMA,
            "source_revision": self.config["source"]["revision"],
            "source_manifest_sha256": self.config["source"][
                "manifest_sha256"
            ],
            "analyzer_sha256": self.config["analyzer"]["sha256"],
            "hardware_class": self.config["qualification"]["hardware_class"],
            "manifest_sha256": stability.sha256_file(
                ROOT / "scripts" / "determinism_workloads.json"
            ),
            "baseline_sha256": stability.sha256_file(
                ROOT / "scripts" / "determinism_baseline.json"
            ),
            "performance_gate": "pass",
            "semantic_gate": "pass",
            "workload_count": 3,
            "workloads": [
                {
                    "kind": kind,
                    "semantic_sha256": f"{index:064x}",
                    "input_identity_sha256": f"{index + 3:064x}",
                    "translation_unit_sha256": f"{index + 6:064x}",
                    "translation_unit_plan_sha256": f"{index + 9:064x}",
                }
                for index, kind in enumerate(
                    ["unit", "real-repository", "release-candidate"], 1
                )
            ],
            "semantic_sha256": "d" * 64,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_action_receipt_binds_plan_command_inner_receipt_and_projection(self) -> None:
        receipt = stability.build_action_receipt(
            self.config,
            self.plan,
            self.action,
            self.projection,
            evidence_root=self.root,
            runtime_root=self.root / "runtime",
        )
        action_path = self.spec["action_receipt_path"]
        action_path.parent.mkdir(parents=True, exist_ok=True)
        action_path.write_bytes(stability.canonical_document(receipt))
        self.assertEqual(
            stability.verify_action_receipt(
                action_path,
                self.config,
                self.plan,
                self.action,
                evidence_root=self.root,
                runtime_root=self.root / "runtime",
            ),
            stability.sha256_file(action_path),
        )
        self.assertEqual(
            receipt["inner"]["receipt_sha256"],
            stability.sha256_file(self.spec["receipt_path"]),
        )

    def test_action_receipt_rejects_plan_projection_and_inner_receipt_drift(self) -> None:
        receipt = stability.build_action_receipt(
            self.config,
            self.plan,
            self.action,
            self.projection,
            evidence_root=self.root,
            runtime_root=self.root / "runtime",
        )
        action_path = self.spec["action_receipt_path"]
        action_path.parent.mkdir(parents=True, exist_ok=True)
        mutations: list[tuple[str, dict]] = []
        plan_drift = copy.deepcopy(receipt)
        plan_drift["identity"]["plan_sha256"] = "0" * 64
        mutations.append(("plan", plan_drift))
        projection_drift = copy.deepcopy(receipt)
        projection_drift["inner"]["projection"]["performance_gate"] = "fail"
        mutations.append(("projection", projection_drift))
        for name, mutation in mutations:
            with self.subTest(name=name):
                action_path.write_bytes(stability.canonical_document(mutation))
                with self.assertRaises(stability.StabilityError):
                    stability.verify_action_receipt(
                        action_path,
                        self.config,
                        self.plan,
                        self.action,
                        evidence_root=self.root,
                        runtime_root=self.root / "runtime",
                    )
        action_path.write_bytes(stability.canonical_document(receipt))
        self.spec["receipt_path"].write_bytes(b"tampered\n")
        with self.assertRaisesRegex(stability.StabilityError, "inner"):
            stability.verify_action_receipt(
                action_path,
                self.config,
                self.plan,
                self.action,
                evidence_root=self.root,
                runtime_root=self.root / "runtime",
            )


class PlannedActionExecutionContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runtime_root = self.root / "runtime"
        self.config = runtime_config()
        policy = stability.validate_policy(canonical_policy(), ROOT)
        schedule = stability.build_schedule(policy, ROOT)
        self.plan = stability.build_cycle_plan(
            policy, schedule, SESSION_ID, 1
        )
        self.action = self.plan["actions"][0]
        self.spec = stability.build_action_spec(
            self.config,
            self.plan,
            self.action,
            evidence_root=self.root,
            runtime_root=self.runtime_root,
        )
        self.projection = {
            "schema": stability.DETERMINISM_PROJECTION_SCHEMA,
            "source_revision": self.config["source"]["revision"],
            "source_manifest_sha256": self.config["source"][
                "manifest_sha256"
            ],
            "analyzer_sha256": self.config["analyzer"]["sha256"],
            "hardware_class": self.config["qualification"]["hardware_class"],
            "manifest_sha256": "b" * 64,
            "baseline_sha256": "c" * 64,
            "performance_gate": "pass",
            "semantic_gate": "pass",
            "workload_count": 3,
            "workloads": [
                {
                    "kind": kind,
                    "semantic_sha256": f"{index:064x}",
                    "input_identity_sha256": f"{index + 3:064x}",
                    "translation_unit_sha256": f"{index + 6:064x}",
                    "translation_unit_plan_sha256": f"{index + 9:064x}",
                }
                for index, kind in enumerate(
                    ["unit", "real-repository", "release-candidate"], 1
                )
            ],
            "semantic_sha256": "d" * 64,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_wrapper_runs_inner_command_verifies_then_seals_action_receipt(self) -> None:
        calls: list[dict] = []

        def execute(argv: list[str], cwd: Path, env: dict[str, str]) -> int:
            calls.append({"argv": argv, "cwd": cwd, "env": env})
            self.spec["receipt_path"].parent.mkdir(parents=True)
            self.spec["receipt_path"].write_bytes(
                stability.canonical_document({
                    "schema": "fixture-inner-v1",
                    "status": "accepted",
                })
            )
            return 0

        def verify(*args: object, **kwargs: object) -> dict:
            self.assertTrue(self.spec["receipt_path"].is_file())
            return copy.deepcopy(self.projection)

        action_path = stability.execute_planned_action(
            self.config,
            self.plan,
            self.action,
            evidence_root=self.root,
            runtime_root=self.runtime_root,
            command_executor=execute,
            projection_verifier=verify,
        )
        self.assertEqual(action_path, self.spec["action_receipt_path"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["argv"], self.spec["argv"])
        self.assertEqual(
            stability.verify_action_receipt(
                action_path,
                self.config,
                self.plan,
                self.action,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
            ),
            stability.sha256_file(action_path),
        )

    def test_wrapper_rejects_preexisting_inner_and_nonzero_without_sealing(self) -> None:
        self.spec["receipt_path"].parent.mkdir(parents=True)
        self.spec["receipt_path"].write_text("stale\n", encoding="utf-8")
        called = False

        def should_not_run(*args: object) -> int:
            nonlocal called
            called = True
            return 0

        with self.assertRaisesRegex(stability.StabilityError, "already exists"):
            stability.execute_planned_action(
                self.config,
                self.plan,
                self.action,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
                command_executor=should_not_run,
                projection_verifier=lambda *args: self.projection,
            )
        self.assertFalse(called)
        self.spec["receipt_path"].unlink()
        with self.assertRaisesRegex(stability.StabilityError, "exit code 2"):
            stability.execute_planned_action(
                self.config,
                self.plan,
                self.action,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
                command_executor=lambda *args: 2,
                projection_verifier=lambda *args: self.projection,
            )
        self.assertFalse(self.spec["action_receipt_path"].exists())


class CycleSealerContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runtime_root = self.root / "runtime"
        self.config = runtime_config()
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.schedule = stability.build_schedule(self.policy, ROOT)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def qualification_projection(self) -> dict:
        return {
            "schema": stability.DETERMINISM_PROJECTION_SCHEMA,
            "source_revision": self.config["source"]["revision"],
            "source_manifest_sha256": self.config["source"][
                "manifest_sha256"
            ],
            "analyzer_sha256": self.config["analyzer"]["sha256"],
            "hardware_class": self.config["qualification"]["hardware_class"],
            "manifest_sha256": "b" * 64,
            "baseline_sha256": "c" * 64,
            "performance_gate": "pass",
            "semantic_gate": "pass",
            "workload_count": 3,
            "workloads": [
                {
                    "kind": kind,
                    "semantic_sha256": f"{index:064x}",
                    "input_identity_sha256": f"{index + 3:064x}",
                    "translation_unit_sha256": f"{index + 6:064x}",
                    "translation_unit_plan_sha256": f"{index + 9:064x}",
                }
                for index, kind in enumerate(
                    ["unit", "real-repository", "release-candidate"], 1
                )
            ],
            "semantic_sha256": "d" * 64,
        }

    def resource_projection(self, requested: int) -> dict:
        return {
            "schema": "codeskeptic-realworld-tu-resources-v1",
            "translation_units": requested,
            "total_duration_ms": requested * 10,
            "maximum_duration_ms": 10,
            "maximum_peak_memory_kib": 1024,
            "timeout_seconds": stability.TU_TIMEOUT_SECONDS,
            "memory_mib": stability.TU_MEMORY_MIB,
            "duration_budget_violations": 0,
            "memory_budget_violations": 0,
            "observations_sha256": "a" * 64,
        }

    def fault_projection(self, receipt_path: Path) -> dict:
        return {
            "schema": stability.FAULT_INJECTION_PROJECTION_SCHEMA,
            "status": "pass",
            "source_revision": self.config["source"]["revision"],
            "test_binary_path": self.config["fault_injection"]["test_binary"],
            "test_binary_sha256": self.config["fault_injection"][
                "test_binary_sha256"
            ],
            "receipt_sha256": stability.sha256_file(receipt_path),
            "test_count": len(stability.fault_injection.CANONICAL_TESTS),
            "tests": list(stability.fault_injection.CANONICAL_TESTS),
        }

    def seal_action_receipts(self, plan: dict) -> None:
        shard_records: list[dict] = []
        shard_projections: dict[int, dict] = {}
        for action in plan["actions"]:
            if action["kind"] == "aggregate":
                continue
            spec = stability.build_action_spec(
                self.config,
                plan,
                action,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
            )
            spec["receipt_path"].parent.mkdir(parents=True, exist_ok=True)
            spec["receipt_path"].write_bytes(stability.canonical_document({
                "action": action["id"],
                "schema": "fixture-inner-v1",
                "status": "accepted",
            }))
            if action["kind"] == "qualification":
                projection = self.qualification_projection()
            elif action["kind"] == "fault-injection":
                projection = self.fault_projection(spec["receipt_path"])
            else:
                parameters = action["parameters"]
                checkpoint = 0 if plan["mode"] == "cold" else 10
                projection = {
                    "schema": stability.REALWORLD_SHARD_PROJECTION_SCHEMA,
                    "mode": plan["mode"],
                    "project": parameters["project"],
                    "repetition": parameters["repetition"],
                    "analyzer_sha256": self.config["analyzer"]["sha256"],
                    "semantic_sha256": "e" * 64,
                    "requested_tus": 10,
                    "executed_tus": 10 - checkpoint,
                    "checkpoint_tus": checkpoint,
                    "resumed": plan["mode"] == "warm",
                    "translation_unit_plan_sha256": "f" * 64,
                    "receipt_sha256": stability.sha256_file(
                        spec["receipt_path"]
                    ),
                    "duration_ms": 1000,
                    "resources": self.resource_projection(10),
                }
                shard_projections[action["ordinal"]] = projection
                shard_records.append({
                    "project": parameters["project"],
                    "repetition": parameters["repetition"],
                    "path": spec["receipt_path"].as_posix(),
                    "sha256": projection["receipt_sha256"],
                    "requested_tus": 10,
                    "executed_tus": 10 - checkpoint,
                    "checkpoint_tus": checkpoint,
                    "duration_ms": 1000,
                    "resources": self.resource_projection(10),
                })
            receipt = stability.build_action_receipt(
                self.config,
                plan,
                action,
                projection,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
            )
            spec["action_receipt_path"].parent.mkdir(parents=True, exist_ok=True)
            spec["action_receipt_path"].write_bytes(
                stability.canonical_document(receipt)
            )

        aggregate_action = next(
            action for action in plan["actions"]
            if action["kind"] == "aggregate"
        )
        aggregate_spec = stability.build_action_spec(
            self.config,
            plan,
            aggregate_action,
            evidence_root=self.root,
            runtime_root=self.runtime_root,
        )
        aggregate_spec["receipt_path"].parent.mkdir(parents=True, exist_ok=True)
        aggregate_spec["receipt_path"].write_bytes(stability.canonical_document({
            "schema": "fixture-aggregate-v1",
            "status": "accepted",
        }))
        checkpoint_total = 0 if plan["mode"] == "cold" else 90
        aggregate_projection = {
            "schema": stability.REALWORLD_PROJECTION_SCHEMA,
            "mode": plan["mode"],
            "slot_count": 9,
            "manifest_file_sha256": "1" * 64,
            "manifest_identity_sha256": "2" * 64,
            "aggregate_sha256": stability.sha256_file(
                aggregate_spec["receipt_path"]
            ),
            "analyzer_sha256": self.config["analyzer"]["sha256"],
            "requested_tus": 90,
            "completed_tus": 90,
            "executed_tus": 90 - checkpoint_total,
            "checkpoint_tus": checkpoint_total,
            "broken_tus": 0,
            "missing_tus": 0,
            "semantic_sha256": "3" * 64,
            "translation_unit_plan_sha256": "4" * 64,
            "duration_ms": 9000,
            "maximum_peak_memory_kib": 1024,
            "resource_observations_sha256": "5" * 64,
            "shards": shard_records,
        }
        aggregate_receipt = stability.build_action_receipt(
            self.config,
            plan,
            aggregate_action,
            aggregate_projection,
            evidence_root=self.root,
            runtime_root=self.runtime_root,
        )
        aggregate_spec["action_receipt_path"].parent.mkdir(
            parents=True, exist_ok=True
        )
        aggregate_spec["action_receipt_path"].write_bytes(
            stability.canonical_document(aggregate_receipt)
        )

    def test_cycle_sealer_builds_exact_cold_warm_documents_and_contiguous_bracket(self) -> None:
        session = session_record_for_config(self.config)
        documents = []
        for ordinal in (1, 2):
            plan = stability.build_cycle_plan(
                self.policy, self.schedule, session["id"], ordinal
            )
            plan_path = self.root / "cycles" / f"{ordinal:06d}" / "plan.json"
            plan_path.parent.mkdir(parents=True, exist_ok=True)
            plan_path.write_bytes(stability.canonical_document(plan))
            self.seal_action_receipts(plan)
            cycle_path = stability.seal_cycle_receipt(
                self.config,
                plan,
                session,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
            )
            documents.append(
                json.loads(cycle_path.read_text(encoding="utf-8"))
            )
        self.assertEqual(documents[0]["mode"], "cold")
        self.assertEqual(documents[1]["mode"], "warm")
        self.assertIsNone(documents[0]["qualification"])
        self.assertEqual(
            documents[1]["pre_qualification"],
            documents[0]["pre_qualification"],
        )
        summary = stability.validate_cycle_documents(
            documents, self.root, session, self.schedule, self.policy
        )
        self.assertEqual(summary["cycles"], 2)
        self.assertEqual(summary["slot_count"], 18)
        self.assertEqual(summary["fault_injection_test_count"], 6)
        self.assertEqual(
            documents[1]["fault_injection"],
            documents[0]["fault_injection"],
        )

        rederived_kinds: list[str] = []

        def rederive(
            config: dict, plan: dict, action: dict, spec: dict
        ) -> dict:
            del config, plan
            rederived_kinds.append(action["kind"])
            retained = json.loads(
                spec["action_receipt_path"].read_text(encoding="utf-8")
            )
            return retained["inner"]["projection"]

        strict = stability.verify_cycle_action_authorities(
            self.config,
            session,
            self.policy,
            self.schedule,
            evidence_root=self.root,
            runtime_root=self.runtime_root,
            projection_verifier=rederive,
        )
        self.assertEqual(strict, summary)
        self.assertEqual(rederived_kinds.count("fault-injection"), 1)

    def test_warm_sealer_rejects_malformed_previous_identity_as_stability_error(self) -> None:
        session = session_record_for_config(self.config)
        cold = stability.build_cycle_plan(
            self.policy, self.schedule, session["id"], 1
        )
        cold_plan = self.root / "cycles" / "000001" / "plan.json"
        cold_plan.parent.mkdir(parents=True)
        cold_plan.write_bytes(stability.canonical_document(cold))
        self.seal_action_receipts(cold)
        cold_path = stability.seal_cycle_receipt(
            self.config,
            cold,
            session,
            evidence_root=self.root,
            runtime_root=self.runtime_root,
        )
        malformed = json.loads(cold_path.read_text(encoding="utf-8"))
        malformed["identity"] = "not-an-identity"
        cold_path.write_bytes(stability.canonical_document(malformed))

        warm = stability.build_cycle_plan(
            self.policy, self.schedule, session["id"], 2
        )
        warm_plan = self.root / "cycles" / "000002" / "plan.json"
        warm_plan.parent.mkdir(parents=True)
        warm_plan.write_bytes(stability.canonical_document(warm))
        self.seal_action_receipts(warm)
        with self.assertRaisesRegex(
            stability.StabilityError, "previous cycle receipt"
        ):
            stability.seal_cycle_receipt(
                self.config,
                warm,
                session,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
            )

    def test_cold_sealer_rejects_an_intermediate_post_qualification_action(self) -> None:
        session = session_record_for_config(self.config)
        plan = stability.build_cycle_plan(
            self.policy, self.schedule, session["id"], 1
        )
        parameters = {"phase": "post"}
        ordinal = len(plan["actions"])
        plan["actions"].append({
            "schema": stability.ACTION_PLAN_SCHEMA,
            "id": stability.action_identity(
                plan["id"], ordinal, "qualification", parameters
            ),
            "ordinal": ordinal,
            "kind": "qualification",
            "parameters": parameters,
            "timeout_seconds": (
                self.policy["qualification"]["outer_timeout_seconds"]
                + stability.ACTION_SUPERVISION_GRACE_SECONDS
            ),
        })
        plan["action_count"] = len(plan["actions"])
        plan["plan_sha256"] = stability.digest_json(plan["actions"])
        plan_path = self.root / "cycles" / "000001" / "plan.json"
        plan_path.parent.mkdir(parents=True)
        plan_path.write_bytes(stability.canonical_document(plan))
        self.seal_action_receipts(plan)
        with self.assertRaisesRegex(
            stability.StabilityError, "qualification bracket action count"
        ):
            stability.seal_cycle_receipt(
                self.config,
                plan,
                session,
                evidence_root=self.root,
                runtime_root=self.runtime_root,
            )

    def test_production_cycle_executor_supervises_the_exact_wrapper_plan(self) -> None:
        session = session_record_for_config(self.config)
        plan = stability.build_cycle_plan(
            self.policy, self.schedule, session["id"], 1
        )
        clock = FakeClock()
        writer = stability.JournalWriter(
            self.root / "journal.jsonl",
            self.policy,
            session["id"],
            session["controller_id"],
            stability.sha256_file(POLICY_PATH),
            clock,
        )
        calls: list[dict] = []

        def supervise(writer_arg: object, runner_arg: object, **kwargs: object) -> dict:
            del runner_arg
            self.assertIs(writer_arg, writer)
            if not calls:
                self.seal_action_receipts(plan)
            action = plan["actions"][kwargs["action_ordinal"]]
            calls.append(dict(kwargs))
            writer.append("action-start", {
                "action_id": action["id"],
                "kind": action["kind"],
                "cycle_ordinal": 1,
                "action_ordinal": action["ordinal"],
                "timeout_seconds": action["timeout_seconds"],
                "child_pid": 6000 + action["ordinal"],
            })
            clock.advance(1)
            receipt_path = kwargs["receipt_path"]
            receipt_sha = kwargs["verify_receipt"](receipt_path)
            writer.append("action-finish", {
                "accepted": True,
                "exit_code": 0,
                "kind": action["kind"],
                "action_id": action["id"],
                "outcome": "normal",
                "receipt_sha256": receipt_sha,
                "child_pid": 6000 + action["ordinal"],
                "cycle_ordinal": 1,
                "action_ordinal": action["ordinal"],
            })
            return {
                "action_id": action["id"],
                "exit_code": 0,
                "kind": action["kind"],
                "receipt_sha256": receipt_sha,
            }

        try:
            result = stability.execute_production_cycle(
                writer,
                self.config,
                session,
                plan,
                config_path=Path("/config/runtime.json"),
                evidence_root=self.root,
                runtime_root=self.runtime_root,
                runner=object(),
                supervisor=supervise,
            )
        finally:
            writer.close()
        self.assertEqual(len(calls), plan["action_count"])
        self.assertEqual(result["cycle_id"], plan["id"])
        self.assertEqual(result["slot_count"], 9)
        for action, call in zip(plan["actions"], calls, strict=True):
            self.assertEqual(call["action_id"], action["id"])
            self.assertEqual(call["kind"], action["kind"])
            self.assertEqual(call["argv"][3], "_action")
            self.assertEqual(call["argv"][-1], self.runtime_root.as_posix())

    def test_owned_production_runner_is_closed_when_cycle_execution_raises(self) -> None:
        session = session_record_for_config(self.config)
        plan = stability.build_cycle_plan(
            self.policy, self.schedule, session["id"], 1
        )
        runner = mock.Mock()
        writer = mock.Mock()
        with (
            mock.patch.object(
                stability, "SubprocessCommandRunner", return_value=runner
            ) as constructor,
            mock.patch.object(
                stability,
                "_execute_production_cycle_actions",
                side_effect=stability.StabilityError("fixture failure"),
            ),
            self.assertRaisesRegex(stability.StabilityError, "fixture failure"),
        ):
            stability.execute_production_cycle(
                writer,
                self.config,
                session,
                plan,
                config_path=Path("/config/runtime.json"),
                evidence_root=self.root,
                runtime_root=self.runtime_root,
            )
        constructor.assert_called_once_with(
            evidence_root=self.root,
            runtime_root=self.runtime_root,
        )
        runner.close.assert_called_once_with()


class CampaignControllerContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.schedule = stability.build_schedule(self.policy, ROOT)
        self.clock = FakeClock()
        self.writer = stability.JournalWriter(
            self.root / "journal.jsonl",
            self.policy,
            SESSION_ID,
            CONTROLLER_ID,
            stability.sha256_file(POLICY_PATH),
            self.clock,
        )

    def tearDown(self) -> None:
        self.writer.close()
        self.temporary.cleanup()

    def test_cycle_plan_is_exact_deterministic_and_cold_then_warm(self) -> None:
        cold = stability.build_cycle_plan(
            self.policy, self.schedule, SESSION_ID, 1
        )
        warm = stability.build_cycle_plan(
            self.policy, self.schedule, SESSION_ID, 2
        )
        self.assertEqual(cold, stability.build_cycle_plan(
            self.policy, self.schedule, SESSION_ID, 1
        ))
        self.assertEqual(cold["mode"], "cold")
        self.assertEqual(warm["mode"], "warm")
        self.assertEqual(cold["action_count"], 12)
        self.assertEqual(warm["action_count"], 11)
        self.assertEqual(cold["actions"][0]["parameters"], {"phase": "pre"})
        fault_actions = [
            action for action in cold["actions"]
            if action["kind"] == "fault-injection"
        ]
        self.assertEqual(len(fault_actions), 1)
        self.assertEqual(fault_actions[0]["ordinal"], 1)
        self.assertEqual(
            fault_actions[0]["parameters"],
            {"test_count": len(stability.fault_injection.REQUIRED_TESTS)},
        )
        self.assertEqual(
            fault_actions[0]["timeout_seconds"],
            stability.fault_injection.TIMEOUT_SECONDS
            + stability.ACTION_SUPERVISION_GRACE_SECONDS,
        )
        self.assertFalse(any(
            action["kind"] == "fault-injection" for action in warm["actions"]
        ))
        self.assertFalse(any(
            action["kind"] == "qualification"
            and action["parameters"] == {"phase": "post"}
            for action in cold["actions"]
        ))
        self.assertEqual(warm["actions"][-1]["parameters"], {"phase": "post"})
        self.assertEqual(
            cold["actions"][0]["timeout_seconds"],
            self.policy["qualification"]["outer_timeout_seconds"]
            + stability.ACTION_SUPERVISION_GRACE_SECONDS,
        )
        for action in (
            item for item in cold["actions"] if item["kind"] == "realworld"
        ):
            self.assertEqual(
                action["timeout_seconds"],
                action["parameters"]["timeout_minutes"] * 60
                + stability.ACTION_SUPERVISION_GRACE_SECONDS,
            )
        self.assertEqual(
            [action["kind"] for action in cold["actions"]].count("realworld"),
            9,
        )
        self.assertEqual(
            [action["parameters"]["checkpoint_mode"] for action in cold["actions"]
             if action["kind"] == "realworld"],
            ["cold"] * 9,
        )
        self.assertEqual(
            [action["parameters"]["checkpoint_mode"] for action in warm["actions"]
             if action["kind"] == "realworld"],
            ["warm"] * 9,
        )
        action_ids = [
            action["id"] for plan in (cold, warm) for action in plan["actions"]
        ]
        self.assertEqual(len(action_ids), len(set(action_ids)))

    def test_scope_campaign_finishes_after_exact_cold_and_warm_cycles(self) -> None:
        executor = ScriptedCycleExecutor(
            self.writer, self.root, [120, 180]
        )
        result = stability.run_campaign(
            self.writer,
            self.policy,
            self.schedule,
            executor,
        )
        self.assertEqual(executor.calls, [1, 2])
        self.assertEqual(result["timeline"]["active_duration_seconds"], 300)
        self.assertEqual(result["timeline"]["cycles"], 2)
        self.assertEqual(result["timeline"]["action_count"], 23)
        self.assertEqual(len(result["cycles"]), 2)
        self.assertEqual(self.writer.events[-1]["event_type"], "session-finish")

    def test_elapsed_time_never_adds_an_unplanned_third_cycle(self) -> None:
        executor = ScriptedCycleExecutor(
            self.writer, self.root, [100000, 100000, 100000]
        )
        result = stability.run_campaign(
            self.writer,
            self.policy,
            self.schedule,
            executor,
        )
        self.assertEqual(executor.calls, [1, 2])
        self.assertEqual(result["timeline"]["cycles"], 2)
        self.assertEqual(result["timeline"]["active_duration_seconds"], 200000)

    def test_cycle_callback_failure_never_writes_an_accepted_terminal_event(self) -> None:
        def failed_executor(plan: dict) -> dict:
            raise stability.StabilityError(f"fixture cycle {plan['ordinal']} failed")

        with self.assertRaisesRegex(stability.StabilityError, "fixture cycle"):
            stability.run_campaign(
                self.writer,
                self.policy,
                self.schedule,
                failed_executor,
            )
        self.assertEqual(self.writer.events[-1]["event_type"], "session-finish")
        self.assertEqual(
            self.writer.events[-1]["payload"]["status"], "rejected"
        )


class InnerAuthorityProjectionContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_realworld_projection_recomputes_all_nine_shards_and_aggregate(self) -> None:
        manifest_path, cold_root, cold_aggregate, analyzer_sha = realworld_cycle_evidence(
            self.root / "cold", "cold"
        )
        cold = stability.verify_realworld_cycle(
            manifest_path,
            "release-candidate",
            cold_root,
            cold_aggregate,
            expected_analyzer_sha256=analyzer_sha,
            mode="cold",
        )
        self.assertEqual(cold["slot_count"], 9)
        self.assertEqual(cold["checkpoint_tus"], 0)
        self.assertEqual(cold["executed_tus"], cold["requested_tus"])
        self.assertEqual(len(cold["shards"]), 9)

        warm_manifest, warm_root, warm_aggregate, _ = realworld_cycle_evidence(
            self.root / "warm", "warm"
        )
        warm = stability.verify_realworld_cycle(
            warm_manifest,
            "release-candidate",
            warm_root,
            warm_aggregate,
            expected_analyzer_sha256=analyzer_sha,
            mode="warm",
        )
        self.assertEqual(warm["checkpoint_tus"], warm["requested_tus"])
        self.assertEqual(warm["executed_tus"], 0)
        self.assertEqual(
            cold["translation_unit_plan_sha256"],
            warm["translation_unit_plan_sha256"],
        )
        self.assertEqual(cold["semantic_sha256"], warm["semantic_sha256"])

    def test_realworld_projection_rejects_aggregate_or_restart_drift(self) -> None:
        manifest_path, receipt_root, aggregate_path, analyzer_sha = realworld_cycle_evidence(
            self.root, "cold"
        )
        aggregate = stability.realworld.load_verified_receipt(aggregate_path)
        aggregate["campaign"] = "tampered"
        stability.realworld.write_receipt(aggregate_path, aggregate)
        with self.assertRaisesRegex(stability.StabilityError, "aggregate"):
            stability.verify_realworld_cycle(
                manifest_path,
                "release-candidate",
                receipt_root,
                aggregate_path,
                expected_analyzer_sha256=analyzer_sha,
                mode="cold",
            )

        warm_manifest, warm_root, warm_aggregate, _ = realworld_cycle_evidence(
            self.root / "mislabeled", "cold"
        )
        with self.assertRaisesRegex(stability.StabilityError, "warm"):
            stability.verify_realworld_cycle(
                warm_manifest,
                "release-candidate",
                warm_root,
                warm_aggregate,
                expected_analyzer_sha256=analyzer_sha,
                mode="warm",
            )

    def test_realworld_shard_projection_binds_identity_and_restart_mode(self) -> None:
        manifest_path, receipt_root, _, analyzer_sha = realworld_cycle_evidence(
            self.root / "cold-shard", "cold"
        )
        receipt_path = receipt_root / "llama-cpp" / "repeat-1" / "receipt.json"
        cold = stability.verify_realworld_shard(
            manifest_path,
            receipt_path,
            project_id="llama-cpp",
            repetition=1,
            expected_analyzer_sha256=analyzer_sha,
            mode="cold",
        )
        self.assertEqual(cold["checkpoint_tus"], 0)
        self.assertFalse(cold["resumed"])
        self.assertEqual(cold["receipt_sha256"], stability.sha256_file(receipt_path))
        self.assertEqual(cold["resources"]["duration_budget_violations"], 0)
        self.assertEqual(cold["resources"]["memory_budget_violations"], 0)
        self.assertEqual(cold["resources"]["translation_units"], 200)

        report_path = receipt_path.parent / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["translation_units"][0]["duration_ms"] = 300_001
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(stability.StabilityError, "duration budget"):
            stability.verify_realworld_shard(
                manifest_path,
                receipt_path,
                project_id="llama-cpp",
                repetition=1,
                expected_analyzer_sha256=analyzer_sha,
                mode="cold",
            )
        report["translation_units"][0]["duration_ms"] = 10
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        warm_manifest, warm_root, _, _ = realworld_cycle_evidence(
            self.root / "warm-shard", "warm"
        )
        warm_path = warm_root / "llama-cpp" / "repeat-1" / "receipt.json"
        warm = stability.verify_realworld_shard(
            warm_manifest,
            warm_path,
            project_id="llama-cpp",
            repetition=1,
            expected_analyzer_sha256=analyzer_sha,
            mode="warm",
        )
        self.assertEqual(warm["checkpoint_tus"], warm["requested_tus"])
        self.assertEqual(warm["executed_tus"], 0)
        self.assertTrue(warm["resumed"])
        with self.assertRaisesRegex(stability.StabilityError, "warm"):
            stability.verify_realworld_shard(
                manifest_path,
                receipt_path,
                project_id="llama-cpp",
                repetition=1,
                expected_analyzer_sha256=analyzer_sha,
                mode="warm",
            )

    def test_determinism_projection_binds_all_three_workload_inputs_and_gates(self) -> None:
        receipt_path = (
            ROOT / "docs" / "evidence" / "phase10" / "determinism"
            / "confirmations"
            / "2026-08-22-fedora44-i5-1235u-exclusive-pcores-kernel-6-19-10"
            / "qualification" / "confirmation" / "receipt.json"
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        expected = {
            "source_revision": receipt["source"]["revision"],
            "source_manifest_sha256": receipt["source"]["manifest_sha256"],
            "analyzer_sha256": receipt["toolchain"]["analyzer"]["sha256"],
            "hardware_class": receipt["host"]["class_id"],
            "manifest_sha256": receipt["configuration"]["manifest_sha256"],
            "baseline_sha256": receipt["baseline"]["sha256"],
        }
        projection = stability.project_determinism_receipt(receipt, expected)
        self.assertEqual(projection["workload_count"], 3)
        self.assertEqual(
            [item["kind"] for item in projection["workloads"]],
            ["unit", "real-repository", "release-candidate"],
        )
        self.assertRegex(projection["semantic_sha256"], r"^[0-9a-f]{64}$")

        rejected = copy.deepcopy(receipt)
        rejected["baseline"]["performance_gate"] = "fail"
        with self.assertRaisesRegex(stability.StabilityError, "performance"):
            stability.project_determinism_receipt(rejected, expected)

        retained_root = self.root / "qualification"
        retained_root.mkdir()
        retained_path = retained_root / "receipt.json"
        retained_path.write_bytes(stability.canonical_document(receipt))
        verified = stability.verify_determinism_evidence(
            retained_root,
            ROOT / "scripts" / "determinism_workloads.json",
            ROOT / "scripts" / "determinism_baseline.json",
            ROOT,
            ROOT,
            expected,
            verifier=lambda *args: copy.deepcopy(receipt),
        )
        self.assertEqual(
            verified["receipt_sha256"], stability.sha256_file(retained_path)
        )
        self.assertEqual(verified["projection"], projection)

        def mutating_verifier(*args: object) -> dict:
            retained_path.write_bytes(stability.canonical_document({"tampered": True}))
            return copy.deepcopy(receipt)

        with self.assertRaisesRegex(stability.StabilityError, "changed"):
            stability.verify_determinism_evidence(
                retained_root,
                ROOT / "scripts" / "determinism_workloads.json",
                ROOT / "scripts" / "determinism_baseline.json",
                ROOT,
                ROOT,
                expected,
                verifier=mutating_verifier,
            )

    def test_static_prerequisite_projections_bind_exact_source_and_gates(self) -> None:
        quality_root = (
            ROOT / "docs" / "evidence" / "phase10" / "quality"
            / "2026-08-22-linux-x86_64"
        )
        quality = json.loads(
            (quality_root / "receipt.json").read_text(encoding="utf-8")
        )
        build = json.loads(
            (quality_root / "raw" / "build-authority" / "receipt.json")
            .read_text(encoding="utf-8")
        )
        expected = {
            "source_revision": build["source"]["revision"],
            "source_manifest_sha256": build["source"]["manifest_sha256"],
            "analyzer_sha256": build["analyzer"]["sha256"],
        }
        build_projection = stability.project_build_authority_receipt(
            build, expected
        )
        self.assertEqual(
            build_projection["build_identity_sha256"],
            build["build_identity_sha256"],
        )
        quality_projection = stability.project_quality_floor_receipt(
            quality, expected
        )
        self.assertRegex(quality_projection["metrics_sha256"], r"^[0-9a-f]{64}$")

        failed_quality = copy.deepcopy(quality)
        failed_quality["metrics"]["clean_corpus"]["passed"] = False
        with self.assertRaisesRegex(stability.StabilityError, "clean corpus"):
            stability.project_quality_floor_receipt(failed_quality, expected)
        stale_build = copy.deepcopy(build)
        stale_build["source"]["revision"] = "0" * 40
        with self.assertRaisesRegex(stability.StabilityError, "identity drift"):
            stability.project_build_authority_receipt(stale_build, expected)

        sanitizer_path = (
            ROOT / "docs" / "evidence" / "phase10" / "sanitizers"
            / "2026-08-15-cache-linux-x86_64" / "address" / "receipt.json"
        )
        sanitizer = json.loads(sanitizer_path.read_text(encoding="utf-8"))
        sanitizer_expected = {
            "profile": "address",
            "source_revision": sanitizer["source"]["base_commit"],
            "source_manifest_sha256": sanitizer["source"]["manifest"]["digest"],
        }
        sanitizer_projection = stability.project_sanitizer_receipt(
            sanitizer, sanitizer_expected
        )
        self.assertEqual(sanitizer_projection["profile"], "address")
        self.assertEqual(
            sanitizer_projection["test_binary_sha256"],
            sanitizer["builds"]["tests"]["binaries"][
                "tests/codeskeptic_tests"
            ],
        )
        failed_sanitizer = copy.deepcopy(sanitizer)
        failed_sanitizer["gates"][-1]["exit_code"] = 2
        with self.assertRaisesRegex(stability.StabilityError, "gate matrix"):
            stability.project_sanitizer_receipt(
                failed_sanitizer, sanitizer_expected
            )

        missing_binary = copy.deepcopy(sanitizer)
        del missing_binary["builds"]["tests"]["binaries"][
            "tests/codeskeptic_tests"
        ]
        with self.assertRaisesRegex(
            stability.StabilityError, "codeskeptic_tests binary"
        ):
            stability.project_sanitizer_receipt(
                missing_binary, sanitizer_expected
            )

    def test_fault_binary_is_exactly_linked_to_undefined_sanitizer_authority(self) -> None:
        config = runtime_config()
        projection = {
            "test_binary_sha256": config["fault_injection"][
                "test_binary_sha256"
            ],
            "builds_sha256": "1" * 64,
        }
        sanitizers = {
            "address": {},
            "undefined": {
                "receipt_sha256": config["sanitizers"]["undefined"][
                    "receipt_sha256"
                ],
                "projection": projection,
            },
        }
        with mock.patch.object(
            stability.fault_injection,
            "sha256_binary",
            return_value=config["fault_injection"]["test_binary_sha256"],
        ):
            authority = stability.verify_fault_injection_test_binary_authority(
                config, sanitizers
            )
        self.assertEqual(authority, {
            "schema": (
                "codeskeptic-stability-fault-injection-"
                "binary-authority-v1"
            ),
            "path": config["fault_injection"]["test_binary"],
            "sha256": config["fault_injection"]["test_binary_sha256"],
            "sanitizer_profile": "undefined",
            "sanitizer_receipt_sha256": config["sanitizers"]["undefined"][
                "receipt_sha256"
            ],
            "sanitizer_builds_sha256": "1" * 64,
        })

        mutations: list[tuple[str, dict, dict, str]] = []
        forged_config = copy.deepcopy(config)
        forged_config["fault_injection"]["test_binary_sha256"] = "f" * 64
        mutations.append(("configured-sha", forged_config, sanitizers, "0" * 64))
        receipt_binary_drift = copy.deepcopy(sanitizers)
        receipt_binary_drift["undefined"]["projection"][
            "test_binary_sha256"
        ] = "f" * 64
        mutations.append((
            "receipt-binary",
            config,
            receipt_binary_drift,
            config["fault_injection"]["test_binary_sha256"],
        ))
        receipt_identity_drift = copy.deepcopy(sanitizers)
        receipt_identity_drift["undefined"]["receipt_sha256"] = "f" * 64
        mutations.append((
            "receipt-identity",
            config,
            receipt_identity_drift,
            config["fault_injection"]["test_binary_sha256"],
        ))
        for name, candidate_config, candidate_sanitizers, live_sha in mutations:
            with self.subTest(name=name), mock.patch.object(
                stability.fault_injection,
                "sha256_binary",
                return_value=live_sha,
            ):
                with self.assertRaisesRegex(
                    stability.StabilityError, "undefined sanitizer authority"
                ):
                    stability.verify_fault_injection_test_binary_authority(
                        candidate_config, candidate_sanitizers
                    )

    def test_hosted_projection_requires_ten_exact_head_successes_and_logs(self) -> None:
        revision = "a" * 40
        repository = "example/CodeSkeptic"
        runs = []
        gates = []
        logs = []
        for index, gate_id in enumerate(stability.REQUIRED_HOSTED_GATES, 1):
            run_id = 1000 + index
            runs.append({
                "workflow_path": ".github/workflows/ci.yml",
                "workflow_file_sha256": f"{index:064x}",
                "run_id": run_id,
                "run_attempt": 1,
                "event": "push",
                "head_sha": revision,
                "conclusion": "success",
                "url": f"https://github.com/{repository}/actions/runs/{run_id}",
            })
            gates.append({
                "gate_id": gate_id,
                "provider_name": "github-actions",
                "check_run_id": 2000 + index,
                "conclusion": "success",
                "url": f"https://github.com/{repository}/runs/{2000 + index}",
                "workflow_run_id": run_id,
                "status_ref": f"refs/status/{revision}/{gate_id}/success",
                "status_ref_target": revision,
            })
            logs.append({
                "run_id": run_id,
                "path": f"raw/logs/{run_id}.zip",
                "sha256": f"{3000 + index:064x}",
                "size": 1,
            })
        receipt = {
            "schema": stability.HOSTED_EXACT_HEAD_SCHEMA,
            "status": "accepted",
            "failures": [],
            "source": {
                "repository": repository,
                "revision": revision,
                "tree_sha1": "b" * 40,
            },
            "required_gates": list(stability.REQUIRED_HOSTED_GATES),
            "gates": gates,
            "runs": runs,
            "logs": logs,
            "artifacts": [],
            "snapshots": [{
                "path": "raw/github-api.json",
                "sha256": "f" * 64,
                "size": 1,
            }],
        }
        projection = stability.project_hosted_exact_head_receipt(
            receipt, repository=repository, revision=revision
        )
        self.assertEqual(projection["gate_count"], 10)
        self.assertEqual(projection["workflow_run_count"], 10)

        stale = copy.deepcopy(receipt)
        stale["gates"][0]["status_ref_target"] = "b" * 40
        with self.assertRaisesRegex(stability.StabilityError, "exact-head"):
            stability.project_hosted_exact_head_receipt(
                stale, repository=repository, revision=revision
            )
        missing_log = copy.deepcopy(receipt)
        missing_log["logs"].pop()
        with self.assertRaisesRegex(stability.StabilityError, "cover"):
            stability.project_hosted_exact_head_receipt(
                missing_log, repository=repository, revision=revision
            )

        hosted_root = self.root / "hosted"
        sealed = copy.deepcopy(receipt)
        for record in sealed["logs"]:
            path = hosted_root / record["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = f"run={record['run_id']}\n".encode("ascii")
            path.write_bytes(payload)
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size"] = len(payload)
        snapshot = sealed["snapshots"][0]
        snapshot_path = hosted_root / snapshot["path"]
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_payload = b"{}\n"
        snapshot_path.write_bytes(snapshot_payload)
        snapshot["sha256"] = hashlib.sha256(snapshot_payload).hexdigest()
        snapshot["size"] = len(snapshot_payload)
        write_document(hosted_root / "receipt.json", sealed)
        receipt_data = (hosted_root / "receipt.json").read_bytes()
        (hosted_root / "receipt.json.sha256").write_text(
            f"{hashlib.sha256(receipt_data).hexdigest()}  receipt.json\n",
            encoding="ascii",
        )
        retained_paths = sorted(
            [record["path"] for record in sealed["logs"]]
            + [record["path"] for record in sealed["snapshots"]]
        )
        manifest_paths = ["receipt.json", "receipt.json.sha256", *retained_paths]
        (hosted_root / "SHA256SUMS").write_bytes(b"".join(
            f"{stability.sha256_file(hosted_root / path)}  {path}\n".encode("utf-8")
            for path in manifest_paths
        ))
        verified = stability.verify_hosted_exact_head_evidence(
            hosted_root, repository=repository, revision=revision
        )
        self.assertEqual(verified["projection"]["gate_count"], 10)
        (hosted_root / sealed["logs"][0]["path"]).write_bytes(b"tampered\n")
        with self.assertRaisesRegex(stability.StabilityError, "checksum"):
            stability.verify_hosted_exact_head_evidence(
                hosted_root, repository=repository, revision=revision
            )

    def test_full_hosted_authority_adapter_binds_repository_to_git_source(self) -> None:
        root = self.root / "hosted-adapter"
        source_root = self.root / "source-adapter"
        receipt = {"schema": "fixture-hosted-receipt"}
        write_document(root / "receipt.json", receipt)
        identity = {"schema": "fixture-directory-identity"}
        structural = {"bundle": identity, "projection": {}}
        source = object()
        with (
            mock.patch.object(
                stability, "directory_identity", return_value=identity
            ),
            mock.patch.object(
                stability,
                "verify_hosted_exact_head_evidence",
                return_value=structural,
            ),
            mock.patch.object(
                hosted_authority, "GitSourceAuthority", return_value=source
            ) as constructor,
            mock.patch.object(
                hosted_authority, "verify_evidence", return_value=receipt
            ) as verifier,
        ):
            result = stability.verify_hosted_exact_head_authority(
                root,
                source_root,
                repository="example/CodeSkeptic",
                revision="a" * 40,
            )
        constructor.assert_called_once_with(
            source_root, repository="example/CodeSkeptic"
        )
        verifier.assert_called_once_with(
            root,
            repository="example/CodeSkeptic",
            revision="a" * 40,
            source=source,
        )
        self.assertEqual(result, structural)

    def test_realworld_mirror_adapter_binds_the_exact_matrix_scope(self) -> None:
        authority = self.root / "mirrors" / "authority.json"
        manifest_path = self.root / "realworld-manifest.json"
        identity = {
            "schema": "fixture-directory-identity",
            "file_count": 4,
        }
        manifest = {
            "campaigns": {
                "release-candidate": {
                    "projects": list(stability.REQUIRED_MATRIX_PROJECTS),
                    "repetitions": 3,
                }
            }
        }
        calls: list[tuple[str, list[str] | None]] = []

        def load(
            path: Path,
            retained_manifest: dict,
            project_id: str,
            *,
            expected_project_ids: list[str] | None = None,
        ) -> tuple[dict, Path]:
            self.assertEqual(path, authority)
            self.assertIs(retained_manifest, manifest)
            calls.append((project_id, expected_project_ids))
            return {"id": project_id}, authority.parent.absolute()

        with (
            mock.patch.object(
                stability, "directory_identity", return_value=identity
            ),
            mock.patch.object(
                stability.realworld, "load_manifest", return_value=manifest
            ),
            mock.patch.object(
                stability.realworld, "validate_manifest", return_value=manifest
            ),
            mock.patch.object(
                stability.realworld,
                "load_mirror_authority",
                side_effect=load,
            ),
            mock.patch.object(
                stability, "sha256_file", return_value="a" * 64
            ),
        ):
            result = stability.verify_realworld_mirror_authority(
                authority, manifest_path
            )
        self.assertEqual(
            calls,
            [
                (project_id, stability.REQUIRED_MATRIX_PROJECTS)
                for project_id in stability.REQUIRED_MATRIX_PROJECTS
            ],
        )
        self.assertEqual(result["bundle"], identity)

    def test_prerequisite_wrappers_reverify_semantics_and_stable_bundles(self) -> None:
        quality_source = (
            ROOT / "docs" / "evidence" / "phase10" / "quality"
            / "2026-08-22-linux-x86_64"
        )
        quality = json.loads(
            (quality_source / "receipt.json").read_text(encoding="utf-8")
        )
        build = json.loads(
            (quality_source / "raw" / "build-authority" / "receipt.json")
            .read_text(encoding="utf-8")
        )
        expected = {
            "source_revision": build["source"]["revision"],
            "source_manifest_sha256": build["source"]["manifest_sha256"],
            "analyzer_sha256": build["analyzer"]["sha256"],
            "build_identity_sha256": build["build_identity_sha256"],
        }
        build_root = self.root / "build-authority"
        write_document(build_root / "receipt.json", build)
        build_result = stability.verify_build_authority_evidence(
            build_root, expected, verifier=lambda root: copy.deepcopy(build)
        )
        self.assertEqual(
            build_result["projection"]["build_identity_sha256"],
            expected["build_identity_sha256"],
        )

        package = self.root / "quality"
        write_document(package / "receipt.json", quality)
        write_document(
            package / "raw" / "build-authority" / "receipt.json", build
        )
        quality_result = stability.verify_quality_floor_evidence(
            package,
            ROOT,
            expected,
            verifier=lambda *args, **kwargs: copy.deepcopy(quality),
        )
        self.assertEqual(
            quality_result["build_authority_projection"]["build_identity_sha256"],
            expected["build_identity_sha256"],
        )

        sanitizer_source = (
            ROOT / "docs" / "evidence" / "phase10" / "sanitizers"
            / "2026-08-15-cache-linux-x86_64" / "address" / "receipt.json"
        )
        sanitizer = json.loads(sanitizer_source.read_text(encoding="utf-8"))
        sanitizer_root = self.root / "sanitizer"
        write_document(sanitizer_root / "receipt.json", sanitizer)
        sanitizer_expected = {
            "profile": "address",
            "source_revision": sanitizer["source"]["base_commit"],
            "source_manifest_sha256": sanitizer["source"]["manifest"]["digest"],
        }
        sanitizer_result = stability.verify_sanitizer_evidence(
            sanitizer_root,
            self.root,
            self.root,
            sanitizer_expected,
            verifier=lambda *args: copy.deepcopy(sanitizer),
        )
        self.assertEqual(sanitizer_result["projection"]["profile"], "address")

        mutating_root = self.root / "mutating-build-authority"
        write_document(mutating_root / "receipt.json", build)

        def mutating_verifier(root: Path) -> dict:
            (root / "ambient.txt").write_text("changed\n", encoding="utf-8")
            return copy.deepcopy(build)

        with self.assertRaisesRegex(stability.StabilityError, "changed"):
            stability.verify_build_authority_evidence(
                mutating_root, expected, verifier=mutating_verifier
            )


class CycleEvidenceContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.schedule = stability.build_schedule(self.policy, ROOT)
        self.session = session_record()
        self.cycles = [
            cycle_document(self.root, self.session, self.schedule, 1, "cold"),
            cycle_document(self.root, self.session, self.schedule, 2, "warm"),
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify(self, cycles: list[dict] | None = None) -> dict:
        return stability.validate_cycle_documents(
            self.cycles if cycles is None else cycles,
            self.root,
            self.session,
            self.schedule,
            self.policy,
        )

    def test_exact_cold_and_warm_cycles_pass(self) -> None:
        summary = self.verify()
        self.assertEqual(summary["cycles"], 2)
        self.assertEqual(summary["slot_count"], 18)
        self.assertEqual(summary["requested_tus"], 1800)
        self.assertEqual(summary["completed_tus"], 1800)
        self.assertEqual(summary["checkpoint_tus"], 900)
        self.assertEqual(summary["performance_gate"], "pass")
        self.assertEqual(
            summary["performance_scope"],
            "p10-07-representative-pre-post",
        )

    def test_realworld_elapsed_drift_is_retained_not_self_baselined(self) -> None:
        drift = copy.deepcopy(self.cycles)
        drift[1]["realworld"]["duration_ms"] *= 100
        summary = self.verify(drift)
        self.assertEqual(
            summary["realworld_durations"],
            [
                {"mode": "cold", "duration_ms": 9000},
                {"mode": "warm", "duration_ms": 900000},
            ],
        )
        self.assertEqual(summary["performance_gate"], "pass")
        self.assertEqual(
            summary["performance_scope"],
            stability.PERFORMANCE_SCOPE,
        )

    def test_pre_and_post_qualification_bracket_is_contiguous(self) -> None:
        self.assertIsNone(self.cycles[0]["qualification"])
        self.assertEqual(
            self.cycles[1]["pre_qualification"],
            self.cycles[0]["pre_qualification"],
        )
        summary = self.verify()
        self.assertEqual(summary["qualification_semantic_sha256"], "6" * 64)

        drift = copy.deepcopy(self.cycles)
        drift[1]["pre_qualification"] = copy.deepcopy(
            drift[1]["qualification"]
        )
        with self.assertRaisesRegex(stability.StabilityError, "bracket"):
            self.verify(drift)

        intermediate = copy.deepcopy(self.cycles)
        intermediate[0]["qualification"] = copy.deepcopy(
            intermediate[1]["qualification"]
        )
        with self.assertRaisesRegex(
            stability.StabilityError, "intermediate post-qualification"
        ):
            self.verify(intermediate)

    def test_semantic_plan_analyzer_and_coverage_drift_are_rejected(self) -> None:
        mutations: list[tuple[str, list[dict], str]] = []
        semantic = copy.deepcopy(self.cycles)
        semantic[1]["realworld"]["semantic_sha256"] = "7" * 64
        mutations.append(("semantic", semantic, "semantic"))
        plan = copy.deepcopy(self.cycles)
        plan[1]["realworld"]["translation_unit_plan_sha256"] = "8" * 64
        mutations.append(("plan", plan, "plan"))
        analyzer = copy.deepcopy(self.cycles)
        analyzer[1]["analyzer_sha256"] = "9" * 64
        mutations.append(("analyzer", analyzer, "analyzer"))
        omitted = copy.deepcopy(self.cycles)
        omitted[1]["realworld"]["completed_tus"] -= 1
        mutations.append(("coverage", omitted, "coverage"))
        broken = copy.deepcopy(self.cycles)
        broken[1]["realworld"]["broken_tus"] = 1
        mutations.append(("broken", broken, "coverage"))
        for name, cycles, message in mutations:
            with self.subTest(name=name):
                with self.assertRaisesRegex(stability.StabilityError, message):
                    self.verify(cycles)

    def test_warm_checkpoint_and_required_performance_are_fail_closed(self) -> None:
        no_checkpoint = copy.deepcopy(self.cycles)
        no_checkpoint[1]["realworld"]["checkpoint_tus"] = 0
        no_checkpoint[1]["realworld"]["executed_tus"] = 900
        partial_checkpoint = copy.deepcopy(self.cycles)
        partial_checkpoint[1]["realworld"]["checkpoint_tus"] = 899
        partial_checkpoint[1]["realworld"]["executed_tus"] = 1
        record_only = copy.deepcopy(self.cycles)
        record_only[1]["qualification"]["performance_policy"] = "record-only"
        regression = copy.deepcopy(self.cycles)
        regression[1]["qualification"]["performance_gate"] = "fail"
        for name, cycles, message in (
            ("checkpoint", no_checkpoint, "checkpoint"),
            ("partial-checkpoint", partial_checkpoint, "checkpoint"),
            ("record-only", record_only, "performance"),
            ("regression", regression, "performance"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(stability.StabilityError, message):
                    self.verify(cycles)

    def test_fault_injection_identity_reuse_and_retained_receipt_are_fail_closed(self) -> None:
        drift = copy.deepcopy(self.cycles)
        drift[1]["fault_injection"]["test_binary_sha256"] = "f" * 64
        with self.assertRaisesRegex(stability.StabilityError, "fault-injection"):
            self.verify(drift)

        target = self.root / self.cycles[0]["fault_injection"]["receipt_path"]
        target.unlink()
        with self.assertRaisesRegex(stability.StabilityError, "regular"):
            self.verify()

    def test_inner_receipt_hash_missing_file_and_cycle_identity_are_rejected(self) -> None:
        wrong_hash = copy.deepcopy(self.cycles)
        wrong_hash[0]["realworld"]["aggregate_sha256"] = "f" * 64
        wrong_identity = copy.deepcopy(self.cycles)
        wrong_identity[1]["identity"]["id"] = "f" * 64
        with self.assertRaisesRegex(stability.StabilityError, "checksum"):
            self.verify(wrong_hash)
        with self.assertRaisesRegex(stability.StabilityError, "identity"):
            self.verify(wrong_identity)
        target = self.root / self.cycles[1]["qualification"]["receipt_path"]
        target.unlink()
        with self.assertRaisesRegex(stability.StabilityError, "regular"):
            self.verify()


class RuntimeEstablishmentContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.evidence = self.root / "evidence"
        self.sources.mkdir()
        self.evidence.mkdir()
        self.session = session_record()
        self.source_identity = {
            "revision": "a" * 40,
            "manifest_sha256": "b" * 64,
            "file_count": 2,
        }
        self.static = {
            "fixture": True,
            "authority_sha256": "c" * 64,
        }
        self.runtime_resources = {
            "schema": "codeskeptic-stability-runtime-resources-v1",
            "maximum_open_fds": 4096,
            "soft_open_fds": 4096,
            "hard_open_fds": 4096,
            "rss_budget": "per-translation-unit-required",
            "time_budget": "per-translation-unit-required",
            "tu_timeout_seconds": stability.TU_TIMEOUT_SECONDS,
            "tu_memory_mib": stability.TU_MEMORY_MIB,
        }
        self.records: dict[str, tuple[Path, str]] = {}
        staged: dict[str, dict] = {}
        for index, name in enumerate(("alpha", "beta"), 1):
            source = self.sources / f"{name}.json"
            source.write_text(f"{{\"fixture\":{index}}}\n", encoding="utf-8")
            relative = f"authorities/{name}.json"
            destination = self.evidence / "establishment" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            self.records[name] = (source, relative)
            staged[name] = {
                "path": f"establishment/{relative}",
                "sha256": stability.sha256_file(source),
                "size": source.stat().st_size,
            }
        receipt = {
            "schema": "codeskeptic-stability-establishment-v1",
            "status": "accepted",
            "failures": [],
            "session": self.session,
            "source": self.source_identity,
            "static_authorities": self.static,
            "runtime_resources": self.runtime_resources,
            "staged": staged,
        }
        (self.evidence / "establishment" / "receipt.json").write_bytes(
            stability.canonical_document(receipt)
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify(self) -> dict:
        return stability.verify_runtime_establishment(
            self.evidence,
            self.sources / "runtime.json",
            {},
            self.session,
            self.source_identity,
            self.static,
            self.runtime_resources,
            source_records=self.records,
        )

    def test_every_staged_file_is_read_only_and_bound_to_its_live_source(self) -> None:
        before = {
            path.relative_to(self.root).as_posix(): (
                path.stat().st_size, path.stat().st_mtime_ns
            )
            for path in self.root.rglob("*") if path.is_file()
        }
        verified = self.verify()
        after = {
            path.relative_to(self.root).as_posix(): (
                path.stat().st_size, path.stat().st_mtime_ns
            )
            for path in self.root.rglob("*") if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(set(verified["staged"]), {"alpha", "beta"})

        self.records["alpha"][0].write_text(
            "{\"fixture\":999}\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(stability.StabilityError, "source"):
            self.verify()


class EvidenceBundleContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.receipt = build_evidence_bundle(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify(self) -> dict:
        return stability.verify_evidence_structure(
            self.root, POLICY_PATH, ROOT
        )

    def snapshot(self) -> dict[str, tuple[int, int]]:
        return {
            path.relative_to(self.root).as_posix(): (
                path.stat().st_size,
                path.stat().st_mtime_ns,
            )
            for path in sorted(self.root.rglob("*"))
            if path.is_file()
        }

    def test_exact_bundle_verifies_without_writing(self) -> None:
        before = self.snapshot()
        verified = self.verify()
        after = self.snapshot()
        self.assertEqual(verified, self.receipt)
        self.assertEqual(after, before)

    def test_artifact_tamper_extra_file_and_symlink_are_rejected(self) -> None:
        journal = self.root / "journal.jsonl"
        journal.write_bytes(journal.read_bytes() + b"{}\n")
        with self.assertRaisesRegex(stability.StabilityError, "checksum"):
            self.verify()

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.receipt = build_evidence_bundle(self.root)
        (self.root / "ambient.txt").write_text("ambient\n", encoding="utf-8")
        with self.assertRaisesRegex(stability.StabilityError, "file set"):
            self.verify()

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.receipt = build_evidence_bundle(self.root)
        target = self.root / self.receipt["diagnostics"]["address"]["path"]
        contents = target.read_bytes()
        target.unlink()
        backing = self.root / "address-backing.json"
        backing.write_bytes(contents)
        target.symlink_to(backing)
        with self.assertRaisesRegex(stability.StabilityError, "regular"):
            self.verify()

    def test_resealed_failed_gate_and_timeline_claim_are_rejected(self) -> None:
        failed_gate = copy.deepcopy(self.receipt)
        failed_gate["gates"]["fault_injection"] = "fail"
        reseal_outer(self.root, failed_gate)
        with self.assertRaisesRegex(stability.StabilityError, "gate"):
            self.verify()

        failed_scope = copy.deepcopy(self.receipt)
        failed_scope["gates"]["performance_scope"] = "all-realworld-shards"
        reseal_outer(self.root, failed_scope)
        with self.assertRaisesRegex(stability.StabilityError, "gate"):
            self.verify()

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.receipt = build_evidence_bundle(self.root)
        false_timeline = copy.deepcopy(self.receipt)
        false_timeline["timeline"]["active_duration_seconds"] += 1
        reseal_outer(self.root, false_timeline)
        with self.assertRaisesRegex(stability.StabilityError, "timeline"):
            self.verify()

    def test_diagnostic_hash_must_match_the_session_identity(self) -> None:
        mutation = copy.deepcopy(self.receipt)
        mutation["session"]["identity"]["sanitizer_receipts"]["address"] = "f" * 64
        mutation["session"]["id"] = stability.build_session_identity(
            mutation["session"]["identity"]
        )
        reseal_outer(self.root, mutation)
        with self.assertRaisesRegex(stability.StabilityError, "sanitizer"):
            self.verify()

    def test_authority_hashes_must_match_the_session_identity(self) -> None:
        mutation = copy.deepcopy(self.receipt)
        mutation["session"]["identity"]["prerequisite_receipts"][
            "hosted_exact_head"
        ] = "0" * 64
        mutation["session"]["id"] = stability.build_session_identity(
            mutation["session"]["identity"]
        )
        reseal_outer(self.root, mutation)
        with self.assertRaisesRegex(stability.StabilityError, "prerequisite"):
            self.verify()


class ProductionEvidenceIntegrationContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.receipt = build_evidence_bundle(self.root)
        self.config = runtime_config()
        self.config_path = self.root / "runtime.json"
        self.config_path.write_bytes(stability.canonical_document(self.config))
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.schedule = stability.build_schedule(self.policy, ROOT)
        self.source_identity = {
            "revision": self.config["source"]["revision"],
            "manifest_sha256": self.config["source"]["manifest_sha256"],
            "file_count": 386,
        }
        self.static_authorities = {"fixture": "strict-live-authorities"}
        self.runtime_resources = {
            "schema": "codeskeptic-stability-runtime-resources-v1",
            "maximum_open_fds": 4096,
            "soft_open_fds": 4096,
            "hard_open_fds": 4096,
            "rss_budget": "per-translation-unit-required",
            "time_budget": "per-translation-unit-required",
            "tu_timeout_seconds": stability.TU_TIMEOUT_SECONDS,
            "tu_memory_mib": stability.TU_MEMORY_MIB,
        }
        staged: dict[str, dict] = {}
        for name, record in self.receipt["authorities"].items():
            staged[name] = {**copy.deepcopy(record), "size": 1}
        for profile, record in self.receipt["diagnostics"].items():
            staged[f"sanitizer_{profile}"] = {
                **copy.deepcopy(record),
                "size": 1,
            }
        self.establishment = {
            **copy.deepcopy(self.receipt["establishment"]),
            "staged": staged,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify_production(self) -> dict:
        original_sha256_file = stability.sha256_file
        session = self.receipt["session"]

        def live_sha256(path: Path) -> str:
            candidate = Path(path)
            if candidate == self.config_path:
                return session["identity"]["runtime_config_sha256"]
            if candidate == Path(self.config["runtime"]["launch_receipt"]):
                return session["identity"]["runtime_launch_receipt_sha256"]
            return original_sha256_file(candidate)

        def source_authority(
            config: dict,
        ) -> tuple[dict, dict, dict]:
            self.assertIs(config, self.config)
            return self.policy, self.schedule, self.source_identity

        def static_authority(config: dict, policy: dict) -> dict:
            self.assertIs(config, self.config)
            self.assertEqual(policy, self.policy)
            return self.static_authorities

        def strict_cycles(
            config: dict,
            retained_session: dict,
            policy: dict,
            schedule: dict,
            **kwargs: object,
        ) -> dict:
            self.assertIs(config, self.config)
            self.assertEqual(retained_session, session)
            self.assertEqual(policy, self.policy)
            self.assertEqual(schedule, self.schedule)
            self.assertEqual(kwargs["evidence_root"], self.root)
            fault_path = (
                self.root / self.receipt["cycles"][0]["path"]
            ).parent / "fault-injection" / "receipt.json"
            projection = json.loads(fault_path.read_text(encoding="utf-8"))
            if projection.get("test_binary_sha256") != session["identity"][
                "fault_injection_test_binary"
            ]["sha256"]:
                raise stability.StabilityError(
                    "strict retained fault projection tamper"
                )
            return copy.deepcopy(self.receipt["cycle_summary"])

        with (
            mock.patch.object(
                stability, "load_runtime_config_file", return_value=self.config
            ),
            mock.patch.object(
                stability,
                "verify_evidence_structure",
                return_value=self.receipt,
            ),
            mock.patch.object(stability, "load_runtime_launch_receipt"),
            mock.patch.object(
                stability,
                "build_runtime_session_record",
                return_value=session,
            ),
            mock.patch.object(
                stability,
                "verify_runtime_resource_limits",
                return_value=self.runtime_resources,
            ),
            mock.patch.object(
                stability,
                "verify_runtime_establishment",
                return_value=self.establishment,
            ),
            mock.patch.object(
                stability, "verify_runtime_static_authority_identities"
            ),
            mock.patch.object(
                stability, "sha256_file", side_effect=live_sha256
            ),
        ):
            return stability.verify_production_evidence(
                self.config_path,
                self.root,
                source_policy_verifier=source_authority,
                static_authority_verifier=static_authority,
                cycle_authority_verifier=strict_cycles,
            )

    def test_strict_terminal_routes_fault_projection_and_rejects_tamper(self) -> None:
        self.assertEqual(self.verify_production(), self.receipt)
        fault_path = (
            self.root / self.receipt["cycles"][0]["path"]
        ).parent / "fault-injection" / "receipt.json"
        projection = json.loads(fault_path.read_text(encoding="utf-8"))
        projection["test_binary_sha256"] = "f" * 64
        fault_path.write_bytes(stability.canonical_document(projection))
        with self.assertRaisesRegex(
            stability.StabilityError, "strict retained fault projection tamper"
        ):
            self.verify_production()


class JournalContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.schedule = stability.build_schedule(self.policy, ROOT)

    def verify(self, events: list[dict]) -> dict:
        return stability.verify_journal(
            events,
            self.policy,
            expected_session_id=SESSION_ID,
            expected_controller_id=CONTROLLER_ID,
            expected_boot_id=BOOT_ID,
            expected_schedule=self.schedule,
        )

    def test_exact_two_rounds_and_cold_to_warm_pass(self) -> None:
        result = self.verify(accepted_journal())
        self.assertEqual(result["active_duration_seconds"], 259200)
        self.assertEqual(result["cycles"], 2)
        self.assertEqual(result["cold_cycles"], 1)
        self.assertEqual(result["warm_cycles"], 1)
        self.assertLessEqual(result["maximum_gap_seconds"], 90)
        self.assertEqual(result["maximum_suspend_delta_seconds"], 0)

    def test_terminal_journal_requires_every_exact_planned_action(self) -> None:
        events = accepted_journal()
        starts = [
            index for index, event in enumerate(events)
            if event["event_type"] == "action-start"
        ]
        self.assertEqual(len(starts), 23)
        self.assertEqual(
            [
                sum(
                    event["event_type"] == "action-start"
                    and event["payload"]["cycle_ordinal"] == ordinal
                    for event in events
                )
                for ordinal in (1, 2)
            ],
            [12, 11],
        )

        missing = copy.deepcopy(events)
        first_start = starts[0]
        first_finish = next(
            index for index in range(first_start + 1, len(missing))
            if missing[index]["event_type"] == "action-finish"
        )
        del missing[first_start:first_finish + 1]

        reordered = copy.deepcopy(events)
        first = starts[0]
        second = starts[1]
        reordered[first]["payload"]["action_id"], reordered[second]["payload"][
            "action_id"
        ] = (
            reordered[second]["payload"]["action_id"],
            reordered[first]["payload"]["action_id"],
        )

        timeout = copy.deepcopy(events)
        timeout[starts[0]]["payload"]["timeout_seconds"] += 1

        for name, candidate in (
            ("missing", missing),
            ("reordered", reordered),
            ("timeout", timeout),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    stability.StabilityError,
                    "fixed plan|planned action|heartbeat gap",
                ):
                    self.verify(resign(candidate))

    def test_terminal_journal_binds_finish_to_retained_receipt_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt_hashes = write_terminal_action_receipts(
                root, self.policy, self.schedule, SESSION_ID
            )
            events = accepted_journal(action_receipt_hashes=receipt_hashes)
            result = stability.verify_journal(
                events,
                self.policy,
                expected_session_id=SESSION_ID,
                expected_controller_id=CONTROLLER_ID,
                expected_boot_id=BOOT_ID,
                expected_schedule=self.schedule,
                evidence_root=root,
            )
            self.assertEqual(result["action_count"], 23)

            first_finish = next(
                event for event in events
                if event["event_type"] == "action-finish"
            )
            first_finish["payload"]["receipt_sha256"] = "f" * 64
            with self.assertRaisesRegex(
                stability.StabilityError, "receipt"
            ):
                stability.verify_journal(
                    resign(events),
                    self.policy,
                    expected_session_id=SESSION_ID,
                    expected_controller_id=CONTROLLER_ID,
                    expected_boot_id=BOOT_ID,
                    expected_schedule=self.schedule,
                    evidence_root=root,
                )

            first_plan = stability.build_cycle_plan(
                self.policy, self.schedule, SESSION_ID, 1
            )
            first_receipt = terminal_action_receipt_path(
                root, 1, first_plan["actions"][0]
            )
            retained = json.loads(first_receipt.read_text(encoding="utf-8"))
            retained["identity"]["action_id"] = "f" * 64
            first_receipt.write_bytes(stability.canonical_document(retained))
            with self.assertRaisesRegex(
                stability.StabilityError, "receipt"
            ):
                stability.verify_journal(
                    accepted_journal(action_receipt_hashes=receipt_hashes),
                    self.policy,
                    expected_session_id=SESSION_ID,
                    expected_controller_id=CONTROLLER_ID,
                    expected_boot_id=BOOT_ID,
                    expected_schedule=self.schedule,
                    evidence_root=root,
                )

    def test_short_elapsed_time_is_metadata_not_a_completion_gate(self) -> None:
        result = self.verify(accepted_journal(duration_seconds=120))
        self.assertEqual(result["active_duration_seconds"], 120)
        self.assertEqual(result["cycles"], 2)

    def test_heartbeat_gap_is_rejected(self) -> None:
        events = accepted_journal()
        events = [event for event in events if event["event_type"] != "heartbeat"]
        with self.assertRaisesRegex(stability.StabilityError, "heartbeat gap"):
            self.verify(resign(events))

    def test_suspend_boot_and_controller_changes_are_rejected(self) -> None:
        base = accepted_journal()
        heartbeat = next(
            index for index, event in enumerate(base)
            if event["event_type"] == "heartbeat"
        )
        cases: list[tuple[str, list[dict], str]] = []
        suspended = copy.deepcopy(base)
        suspended[heartbeat]["boottime_ns"] += 3_000_000_000
        cases.append(("suspend", resign(suspended), "suspend"))
        rebooted = copy.deepcopy(base)
        rebooted[heartbeat]["boot_id"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        cases.append(("boot", resign(rebooted), "boot"))
        restarted = copy.deepcopy(base)
        restarted[heartbeat]["controller_id"] = "3" * 64
        cases.append(("controller", resign(restarted), "controller"))
        for name, events, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(stability.StabilityError, message):
                    self.verify(events)

    def test_hash_tamper_and_monotonic_rollback_are_rejected(self) -> None:
        tampered = accepted_journal()
        tampered[3]["payload"]["stage"] = "tampered"
        with self.assertRaisesRegex(stability.StabilityError, "hash"):
            self.verify(tampered)
        rollback = accepted_journal()
        rollback[4]["monotonic_ns"] = rollback[3]["monotonic_ns"] - 1
        with self.assertRaisesRegex(stability.StabilityError, "monotonic"):
            self.verify(resign(rollback))

    def test_utc_jump_does_not_change_duration_authority(self) -> None:
        events = accepted_journal()
        events[len(events) // 2]["utc"] = "1999-01-01T00:00:00Z"
        result = self.verify(resign(events))
        self.assertEqual(result["active_duration_seconds"], 259200)

    def test_missing_warm_round_duplicate_round_and_failed_action_are_rejected(self) -> None:
        no_warm = [
            event for event in accepted_journal()
            if not (
                event["event_type"] == "cycle-finish"
                and event["payload"]["mode"] == "warm"
            )
        ]
        duplicate = accepted_journal()
        second_cycle = [
            index for index, event in enumerate(duplicate)
            if event["event_type"] == "cycle-finish"
        ][1]
        duplicate[second_cycle]["payload"]["ordinal"] = 1
        failed = accepted_journal()
        append_at = 2
        material = _event_material(
            append_at,
            failed[append_at - 1]["event_sha256"],
            "action-finish",
            1_000_000_000,
            {
                "accepted": False,
                "exit_code": 2,
                "kind": "realworld",
                "outcome": "nonzero-exit",
                "action_id": "f" * 64,
                "action_ordinal": 4,
                "child_pid": 4321,
                "cycle_ordinal": 2,
                "receipt_sha256": None,
            },
        )
        failed.insert(
            append_at,
            {**material, "event_sha256": stability.digest_json(material)},
        )
        cases = (
            ("warm", resign(no_warm), "cycle"),
            ("duplicate", resign(duplicate), "cycle"),
            ("failed", resign(failed), "action"),
        )
        for name, events, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(stability.StabilityError, message):
                    self.verify(events)

    def test_action_state_rejects_orphan_nested_and_mismatched_events(self) -> None:
        orphan = accepted_journal()
        first_start = next(
            index for index, event in enumerate(orphan)
            if event["event_type"] == "action-start"
        )
        del orphan[first_start]

        nested = accepted_journal()
        first_start = next(
            index for index, event in enumerate(nested)
            if event["event_type"] == "action-start"
        )
        nested.insert(first_start + 1, copy.deepcopy(nested[first_start]))

        mismatch = accepted_journal()
        first_heartbeat = next(
            index for index, event in enumerate(mismatch)
            if event["event_type"] == "heartbeat"
        )
        mismatch[first_heartbeat]["payload"]["child_pid"] += 1

        cases = (
            ("orphan", resign(orphan), "active action"),
            ("nested", resign(nested), "nested"),
            ("mismatch", resign(mismatch), "does not match"),
        )
        for name, events, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(stability.StabilityError, message):
                    self.verify(events)

    def test_action_identity_timeout_and_transition_gaps_are_rejected(self) -> None:
        duplicate_id = accepted_journal()
        starts = [
            index for index, event in enumerate(duplicate_id)
            if event["event_type"] == "action-start"
        ]
        duplicate_id[starts[1]]["payload"]["action_id"] = duplicate_id[
            starts[0]
        ]["payload"]["action_id"]
        second_action_id = duplicate_id[starts[1]]["payload"]["action_id"]
        for event in duplicate_id[starts[1] + 1:]:
            if event["event_type"] in {"heartbeat", "action-finish"}:
                if event["payload"]["cycle_ordinal"] == 2:
                    event["payload"]["action_id"] = second_action_id

        expired = accepted_journal()
        first_start = next(
            event for event in expired if event["event_type"] == "action-start"
        )
        first_start["payload"]["timeout_seconds"] = 1

        transition = accepted_journal()
        first_cycle = next(
            index for index, event in enumerate(transition)
            if event["event_type"] == "cycle-finish"
        )
        for event in transition[first_cycle:]:
            event["monotonic_ns"] += 61_000_000_000
            event["boottime_ns"] += 61_000_000_000

        cases = (
            ("duplicate", resign(duplicate_id), "duplicate action"),
            ("timeout", resign(expired), "fixed plan|declared timeout"),
            ("transition", resign(transition), "transition"),
        )
        for name, events, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(stability.StabilityError, message):
                    self.verify(events)


class JournalWriterContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "journal.jsonl"
        self.clock = FakeClock()
        self.policy = stability.validate_policy(canonical_policy(), ROOT)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def writer(self) -> stability.JournalWriter:
        return stability.JournalWriter(
            self.path,
            self.policy,
            SESSION_ID,
            CONTROLLER_ID,
            stability.sha256_file(POLICY_PATH),
            self.clock,
        )

    def test_writer_creates_canonical_fsynced_chain_and_terminal_state(self) -> None:
        writer = self.writer()
        self.clock.advance(30)
        writer.append(
            "heartbeat",
            {
                "stage": "qualification",
                "child_pid": 1234,
                "action_id": "a" * 64,
                "cycle_ordinal": 1,
                "action_ordinal": 0,
            },
        )
        self.clock.advance(30)
        writer.append("session-finish", {"status": "accepted"})
        writer.close()
        events = stability.load_journal(self.path)
        self.assertEqual([event["seq"] for event in events], [0, 1, 2])
        self.assertEqual(events[-1]["event_type"], "session-finish")
        with self.assertRaisesRegex(stability.StabilityError, "terminal"):
            writer.append("session-finish", {"status": "accepted"})

    def test_existing_journal_is_never_resumed_or_replaced(self) -> None:
        self.path.write_text("existing\n", encoding="utf-8")
        with self.assertRaisesRegex(stability.StabilityError, "existing"):
            self.writer()
        self.assertEqual(self.path.read_text(encoding="utf-8"), "existing\n")

    def test_writer_rejects_boot_change_and_suspend_immediately(self) -> None:
        writer = self.writer()
        self.clock.current_boot_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with self.assertRaisesRegex(stability.StabilityError, "boot"):
            writer.append(
                "heartbeat",
                {
                    "stage": "campaign",
                    "child_pid": 1234,
                    "action_id": "a" * 64,
                    "cycle_ordinal": 1,
                    "action_ordinal": 0,
                },
            )
        writer.close()

        other_path = self.root / "suspend.jsonl"
        self.path = other_path
        self.clock = FakeClock()
        writer = self.writer()
        self.clock.advance(30, suspend_seconds=3)
        with self.assertRaisesRegex(stability.StabilityError, "suspend"):
            writer.append(
                "heartbeat",
                {
                    "stage": "campaign",
                    "child_pid": 1234,
                    "action_id": "a" * 64,
                    "cycle_ordinal": 1,
                    "action_ordinal": 0,
                },
            )
        writer.close()

    def test_rejected_terminal_state_is_persisted_but_never_accepted(self) -> None:
        writer = self.writer()
        self.clock.advance(1)
        writer.append("session-finish", {"status": "rejected"})
        self.assertEqual(writer.events[-1]["payload"]["status"], "rejected")
        with self.assertRaisesRegex(stability.StabilityError, "terminal"):
            writer.append("session-finish", {"status": "accepted"})
        writer.close()


class ActionSupervisorContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.clock = FakeClock()
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.writer = stability.JournalWriter(
            self.root / "journal.jsonl",
            self.policy,
            SESSION_ID,
            CONTROLLER_ID,
            stability.sha256_file(POLICY_PATH),
            self.clock,
        )
        self.action_id = "a" * 64
        self.receipt_path = self.root / "action-receipt.json"

    def write_receipt(self) -> None:
        self.receipt_path.write_bytes(stability.canonical_document({
            "schema": "fixture-action-v1",
            "status": "accepted",
        }))

    def tearDown(self) -> None:
        self.writer.close()
        self.temporary.cleanup()

    def supervise(
        self,
        handle: FakeCommandHandle,
        *,
        timeout_seconds: int = 120,
    ) -> dict:
        runner = FakeCommandRunner(handle)
        result = stability.supervise_action(
            self.writer,
            runner,
            action_id=self.action_id,
            kind="qualification",
            cycle_ordinal=1,
            action_ordinal=0,
            timeout_seconds=timeout_seconds,
            argv=["fixture-runner", "--receipt", str(self.receipt_path)],
            cwd=self.root,
            env={"LC_ALL": "C"},
            stdout_path=self.root / "stdout.log",
            stderr_path=self.root / "stderr.log",
            receipt_path=self.receipt_path,
            verify_receipt=lambda path: stability.sha256_file(path),
        )
        self.assertEqual(len(runner.calls), 1)
        return result

    def test_success_emits_30_second_heartbeats_and_binds_receipt(self) -> None:
        handle = FakeCommandHandle(
            self.clock,
            finish_after_seconds=65,
            exit_code=0,
            on_natural_finish=self.write_receipt,
        )
        result = self.supervise(handle)
        expected_sha = stability.sha256_file(self.receipt_path)
        self.assertEqual(result, {
            "action_id": self.action_id,
            "exit_code": 0,
            "kind": "qualification",
            "receipt_sha256": expected_sha,
        })
        events = self.writer.events
        self.assertEqual(
            [event["event_type"] for event in events],
            [
                "session-start", "action-start", "heartbeat", "heartbeat",
                "action-finish",
            ],
        )
        self.assertEqual(
            [
                event["monotonic_ns"]
                for event in events if event["event_type"] == "heartbeat"
            ],
            [30_000_000_000, 60_000_000_000],
        )
        self.assertTrue(events[-1]["payload"]["accepted"])
        self.assertEqual(events[-1]["payload"]["outcome"], "normal")
        self.assertEqual(events[1]["payload"]["child_pid"], 4321)
        for event in events[1:]:
            if event["event_type"] in {
                "action-start", "heartbeat", "action-finish"
            }:
                self.assertEqual(event["payload"]["child_pid"], 4321)
                self.assertEqual(event["payload"]["cycle_ordinal"], 1)
                self.assertEqual(event["payload"]["action_ordinal"], 0)
        self.assertEqual(events[-1]["payload"]["receipt_sha256"], expected_sha)
        self.assertEqual(handle.terminate_calls, 0)
        self.assertEqual(handle.kill_calls, 0)

    def test_nonzero_exit_is_sealed_and_rejected(self) -> None:
        handle = FakeCommandHandle(
            self.clock, finish_after_seconds=1, exit_code=2
        )
        with self.assertRaisesRegex(stability.StabilityError, "exit code 2"):
            self.supervise(handle)
        failure = self.writer.events[-1]
        self.assertEqual(failure["event_type"], "action-finish")
        self.assertEqual(failure["payload"], {
            "accepted": False,
            "action_id": self.action_id,
            "exit_code": 2,
            "kind": "qualification",
            "outcome": "nonzero-exit",
            "action_ordinal": 0,
            "child_pid": 4321,
            "cycle_ordinal": 1,
            "receipt_sha256": None,
        })

    def test_outer_timeout_terminates_then_kills_the_process_group(self) -> None:
        handle = FakeCommandHandle(
            self.clock,
            finish_after_seconds=None,
            exit_code=0,
            terminate_exits=False,
        )
        with self.assertRaisesRegex(stability.StabilityError, "outer timeout"):
            self.supervise(handle, timeout_seconds=65)
        self.assertEqual(handle.terminate_calls, 1)
        self.assertEqual(handle.kill_calls, 1)
        failure = self.writer.events[-1]
        self.assertEqual(failure["event_type"], "action-finish")
        self.assertFalse(failure["payload"]["accepted"])
        self.assertEqual(failure["payload"]["exit_code"], 124)
        self.assertEqual(failure["payload"]["outcome"], "outer-timeout")
        self.assertIsNone(failure["payload"]["receipt_sha256"])

    def test_receipt_verifier_must_bind_the_unchanged_regular_file(self) -> None:
        handle = FakeCommandHandle(
            self.clock,
            finish_after_seconds=1,
            exit_code=0,
            on_natural_finish=self.write_receipt,
        )

        def invalid_verifier(path: Path) -> str:
            path.write_bytes(stability.canonical_document({"tampered": True}))
            return "f" * 64

        runner = FakeCommandRunner(handle)
        with self.assertRaisesRegex(stability.StabilityError, "receipt"):
            stability.supervise_action(
                self.writer,
                runner,
                action_id=self.action_id,
                kind="qualification",
                cycle_ordinal=1,
                action_ordinal=0,
                timeout_seconds=120,
                argv=["fixture-runner"],
                cwd=self.root,
                env={},
                stdout_path=self.root / "stdout.log",
                stderr_path=self.root / "stderr.log",
                receipt_path=self.receipt_path,
                verify_receipt=invalid_verifier,
            )
        failure = self.writer.events[-1]
        self.assertEqual(failure["event_type"], "action-finish")
        self.assertFalse(failure["payload"]["accepted"])
        self.assertEqual(failure["payload"]["outcome"], "receipt-rejected")
        self.assertEqual(
            failure["payload"]["receipt_sha256"],
            stability.sha256_file(self.receipt_path),
        )

    def test_nonzero_exit_records_a_fresh_diagnostic_receipt_hash(self) -> None:
        handle = FakeCommandHandle(
            self.clock,
            finish_after_seconds=1,
            exit_code=7,
            on_natural_finish=self.write_receipt,
        )
        with self.assertRaisesRegex(stability.StabilityError, "exit code 7"):
            self.supervise(handle)
        self.assertEqual(
            self.writer.events[-1]["payload"]["receipt_sha256"],
            stability.sha256_file(self.receipt_path),
        )

    def test_preexisting_receipt_is_rejected_before_the_child_launches(self) -> None:
        self.write_receipt()
        handle = FakeCommandHandle(
            self.clock, finish_after_seconds=1, exit_code=0
        )
        runner = FakeCommandRunner(handle)
        with self.assertRaisesRegex(stability.StabilityError, "already exists"):
            stability.supervise_action(
                self.writer,
                runner,
                action_id=self.action_id,
                kind="qualification",
                cycle_ordinal=1,
                action_ordinal=0,
                timeout_seconds=120,
                argv=["fixture-runner"],
                cwd=self.root,
                env={},
                stdout_path=self.root / "stdout.log",
                stderr_path=self.root / "stderr.log",
                receipt_path=self.receipt_path,
                verify_receipt=lambda path: stability.sha256_file(path),
            )
        self.assertEqual(runner.calls, [])

    def test_keyboard_interrupt_cleans_the_group_and_seals_supervision_failure(self) -> None:
        handle = FakeCommandHandle(
            self.clock,
            finish_after_seconds=None,
            exit_code=0,
            wait_error=KeyboardInterrupt(),
        )
        with self.assertRaises(KeyboardInterrupt):
            self.supervise(handle)
        self.assertFalse(handle.group_alive())
        self.assertEqual(handle.terminate_calls, 1)
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "supervision-error"
        )


@unittest.skipUnless(
    sys.platform.startswith("linux") and Path("/proc/self/stat").is_file(),
    "Linux subreaper containment unavailable",
)
class SubprocessRunnerContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "evidence"
        self.runtime = self.root / "runtime"
        self.evidence.mkdir()
        self.runtime.mkdir()
        self.reserve_patch = mock.patch.object(
            stability, "FILESYSTEM_EMERGENCY_RESERVE_BYTES", 4 * 1024 * 1024
        )
        self.reserve_patch.start()
        self.recovery_patch = mock.patch.object(
            stability, "MINIMUM_FILESYSTEM_RECOVERY_BYTES", 1024 * 1024
        )
        self.recovery_patch.start()
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.clock = stability.LinuxClock()
        self.writer = stability.JournalWriter(
            self.root / "journal.jsonl",
            self.policy,
            SESSION_ID,
            CONTROLLER_ID,
            stability.sha256_file(POLICY_PATH),
            self.clock,
        )
        self.runner = stability.SubprocessCommandRunner(
            evidence_root=self.evidence,
            runtime_root=self.runtime,
        )

    def tearDown(self) -> None:
        handle = getattr(self.runner, "last_handle", None)
        if handle is not None and (
            handle.group_alive() or handle.unexpected_pids()
        ):
            handle.kill_group()
            handle.kill_unexpected()
            handle.wait_group(2.0)
            handle.wait_unexpected(2.0)
        self.runner.close()
        self.writer.close()
        self.recovery_patch.stop()
        self.reserve_patch.stop()
        self.temporary.cleanup()

    def supervise(self, argv: list[str], receipt_path: Path, timeout: int) -> dict:
        return stability.supervise_action(
            self.writer,
            self.runner,
            action_id="b" * 64,
            kind="qualification",
            cycle_ordinal=1,
            action_ordinal=0,
            timeout_seconds=timeout,
            argv=argv,
            cwd=self.root,
            env=dict(os.environ, LC_ALL="C"),
            stdout_path=self.evidence / "stdout.log",
            stderr_path=self.evidence / "stderr.log",
            receipt_path=receipt_path,
            verify_receipt=lambda path: stability.sha256_file(path),
        )

    def assert_owned_identity_absent(self, identity_path: Path) -> None:
        pid_text, start_text = identity_path.read_text(
            encoding="ascii"
        ).split(":")
        pid = int(pid_text)
        start_time = int(start_text)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            record = stability._action_process_table().get(pid)
            if record is None or record[2] != start_time:
                break
            time.sleep(0.02)
        record = stability._action_process_table().get(pid)
        self.assertTrue(
            record is None or record[2] != start_time,
            f"owned action identity {pid}:{start_time} survived",
        )

    @staticmethod
    def detached_setup_command(identity_path: Path) -> list[str]:
        code = (
            "import os,pathlib,subprocess,sys;"
            "sink=open(os.devnull,'wb');"
            "child=subprocess.Popen([sys.executable,'-c',"
            "'import time;time.sleep(60)'],start_new_session=True,"
            "stdin=subprocess.DEVNULL,stdout=sink,stderr=sink,close_fds=True);"
            "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
            "encoding='ascii').rsplit(')',1)[1].strip().split();"
            "open(sys.argv[1],'w',encoding='ascii').write("
            "str(child.pid)+':'+fields[19])"
        )
        return [sys.executable, "-c", code, str(identity_path)]

    @staticmethod
    def detached_pthread_exit_command(identity_path: Path) -> list[str]:
        child = """
import ctypes
import os
import pathlib
import sys
import threading
import time

ready = threading.Event()
def worker():
    fields = (pathlib.Path('/proc') / str(os.getpid()) / 'stat').read_text(
        encoding='ascii'
    ).rsplit(')', 1)[1].strip().split()
    pathlib.Path(sys.argv[1]).write_text(
        str(os.getpid()) + ':' + fields[19], encoding='ascii'
    )
    ready.set()
    time.sleep(60)

threading.Thread(target=worker).start()
ready.wait(2)
ctypes.CDLL(None).pthread_exit(None)
"""
        parent = (
            "import os,subprocess,sys;"
            "sink=open(os.devnull,'wb');"
            f"subprocess.Popen([sys.executable,'-c',{child!r},sys.argv[1]],"
            "start_new_session=True,stdin=subprocess.DEVNULL,"
            "stdout=sink,stderr=sink,close_fds=True)"
        )
        return [sys.executable, "-c", parent, str(identity_path)]

    @staticmethod
    def assert_log_descriptors_closed(*paths: Path) -> None:
        targets = {path.as_posix() for path in paths}
        open_targets: set[str] = set()
        for name in os.listdir("/proc/self/fd"):
            if not name.isascii() or not name.isdigit():
                continue
            try:
                open_targets.add(os.readlink(f"/proc/self/fd/{name}"))
            except FileNotFoundError:
                continue
        if targets & open_targets:
            raise AssertionError(
                f"action log descriptors remained open: {targets & open_targets}"
            )

    def assert_controller_echild(self) -> None:
        self.assertEqual(stability._direct_action_children(os.getpid()), {})
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def _run_thread_start_failure(self, failure_ordinal: int) -> None:
        identity_path = self.root / f"thread-{failure_ordinal}.identity"
        stdout_path = self.evidence / f"thread-{failure_ordinal}.stdout.log"
        stderr_path = self.evidence / f"thread-{failure_ordinal}.stderr.log"
        real_popen = stability.subprocess.Popen
        real_start = stability.threading.Thread.start
        starts = 0

        def wait_for_detached_child(*args: object, **kwargs: object) -> object:
            process = real_popen(*args, **kwargs)
            deadline = time.monotonic() + 2.0
            while not identity_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            return process

        def fail_selected_start(thread: object) -> None:
            nonlocal starts
            starts += 1
            if starts == failure_ordinal:
                raise RuntimeError(
                    f"fixture output thread {failure_ordinal} start failure"
                )
            real_start(thread)

        try:
            with (
                mock.patch.object(
                    stability.subprocess,
                    "Popen",
                    side_effect=wait_for_detached_child,
                ),
                mock.patch.object(
                    stability.threading.Thread,
                    "start",
                    new=fail_selected_start,
                ),
                self.assertRaisesRegex(
                    stability.StabilityError,
                    f"output thread {failure_ordinal} start failure",
                ),
            ):
                self.runner.start(
                    self.detached_setup_command(identity_path),
                    cwd=self.root,
                    env=dict(os.environ, LC_ALL="C"),
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                )
            self.assert_owned_identity_absent(identity_path)
            self.assert_controller_echild()
            self.assert_log_descriptors_closed(stdout_path, stderr_path)
            self.assertFalse(self.runner._reserve.released)
        finally:
            handle = self.runner.last_handle
            if handle is not None and (
                handle.group_alive() or handle.unexpected_pids()
            ):
                stability._stop_process_group(handle, release_reserve=False)

    def test_real_child_creates_fresh_receipt_and_is_reaped(self) -> None:
        receipt_path = self.evidence / "receipt.json"
        code = (
            "import json,sys;"
            "open(sys.argv[1],'w',encoding='utf-8').write("
            "json.dumps({'schema':'fixture-v1','status':'accepted'},"
            "indent=2,sort_keys=True)+'\\n')"
        )
        result = self.supervise(
            [sys.executable, "-c", code, str(receipt_path)],
            receipt_path,
            5,
        )
        self.assertEqual(result["receipt_sha256"], stability.sha256_file(receipt_path))
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertTrue((self.evidence / "stdout.log").is_file())
        self.assertTrue((self.evidence / "stderr.log").is_file())

    def test_identity_lookup_failure_cleans_adopted_tree_and_keeps_runner(
        self,
    ) -> None:
        identity_path = self.root / "identity-lookup-child.identity"
        stdout_path = self.evidence / "identity-lookup.stdout.log"
        stderr_path = self.evidence / "identity-lookup.stderr.log"
        retry_stdout = self.evidence / "identity-retry.stdout.log"
        retry_stderr = self.evidence / "identity-retry.stderr.log"
        real_popen = stability.subprocess.Popen
        real_record = stability._action_process_record
        leader_pid: int | None = None
        failed = False

        def wait_for_detached_child(*args: object, **kwargs: object) -> object:
            nonlocal leader_pid
            process = real_popen(*args, **kwargs)
            leader_pid = process.pid
            deadline = time.monotonic() + 2.0
            while not identity_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            return process

        def fail_exact_leader_lookup(
            pid: int,
        ) -> tuple[int, int, int, str] | None:
            nonlocal failed
            if pid == leader_pid and not failed:
                failed = True
                raise OSError("fixture leader identity lookup failure")
            return real_record(pid)

        try:
            with (
                mock.patch.object(
                    stability.subprocess,
                    "Popen",
                    side_effect=wait_for_detached_child,
                ),
                mock.patch.object(
                    stability,
                    "_action_process_record",
                    side_effect=fail_exact_leader_lookup,
                ),
                self.assertRaisesRegex(
                    stability.StabilityError,
                    "leader identity lookup failure",
                ),
            ):
                self.runner.start(
                    self.detached_setup_command(identity_path),
                    cwd=self.root,
                    env=dict(os.environ, LC_ALL="C"),
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                )
            self.assertTrue(failed)
            self.assert_owned_identity_absent(identity_path)
            self.assert_controller_echild()
            self.assert_log_descriptors_closed(stdout_path, stderr_path)
            self.assertFalse(self.runner._reserve.released)

            retry = self.runner.start(
                [sys.executable, "-c", "raise SystemExit(0)"],
                cwd=self.root,
                env=dict(os.environ, LC_ALL="C"),
                stdout_path=retry_stdout,
                stderr_path=retry_stderr,
            )
            self.assertEqual(retry.wait(5.0), 0)
            self.assertTrue(stability._action_process_tree_clean(retry))
        finally:
            if self.runner.last_handle is None:
                try:
                    stability._cleanup_adopted_action_children(os.getpid())
                except stability.StabilityError:
                    pass

    def test_first_output_thread_start_failure_cleans_exact_tree(self) -> None:
        self._run_thread_start_failure(1)

    def test_second_output_thread_start_failure_cleans_exact_tree(self) -> None:
        self._run_thread_start_failure(2)

    def test_real_pthread_exit_descendant_is_killed_and_reaped(self) -> None:
        identity_path = self.root / "pthread-exit.identity"
        handle = self.runner.start(
            self.detached_pthread_exit_command(identity_path),
            cwd=self.root,
            env=dict(os.environ, LC_ALL="C"),
            stdout_path=self.evidence / "pthread-exit.stdout.log",
            stderr_path=self.evidence / "pthread-exit.stderr.log",
        )
        self.assertEqual(handle.wait(5.0), 0)
        deadline = time.monotonic() + 2.0
        while not identity_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(identity_path.is_file())
        pid_text, start_text = identity_path.read_text(
            encoding="ascii"
        ).split(":")
        pid = int(pid_text)
        start_time = int(start_text)
        record = stability._action_process_record(pid)
        self.assertIsNotNone(record)
        self.assertEqual(record[2], start_time)
        self.assertEqual(record[3], "Z")
        self.assertIn(pid, handle.unexpected_pids())

        handle.kill_unexpected()
        self.assertTrue(handle.wait_unexpected(2.0))
        self.assert_owned_identity_absent(identity_path)

    def test_no_handle_cleanup_reaps_real_pthread_exit_descendant(self) -> None:
        identity_path = self.root / "pthread-exit-no-handle.identity"
        stability._enable_action_subreaper()
        process = subprocess.Popen(
            self.detached_pthread_exit_command(identity_path),
            cwd=self.root,
            env=dict(os.environ, LC_ALL="C"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        process.wait(timeout=2.0)
        deadline = time.monotonic() + 2.0
        while not identity_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(identity_path.is_file())

        stability._cleanup_adopted_action_children(os.getpid())
        self.assert_owned_identity_absent(identity_path)
        self.assert_controller_echild()

    def test_runner_close_retains_reserve_while_action_writer_survives(
        self,
    ) -> None:
        stdout_path = self.evidence / "close-survivor.stdout.log"
        stderr_path = self.evidence / "close-survivor.stderr.log"
        handle = self.runner.start(
            [sys.executable, "-c", "import time;time.sleep(60)"],
            cwd=self.root,
            env=dict(os.environ, LC_ALL="C"),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        descriptor = self.runner._reserve._descriptors[0]

        with self.assertRaisesRegex(
            stability.StabilityError, "active action owner"
        ):
            self.runner.close()

        self.assertFalse(self.runner._closed)
        self.assertFalse(self.runner._reserve.released)
        self.assertGreaterEqual(os.fstat(descriptor).st_blocks, 1)
        self.assertTrue(handle.group_alive())

        stability._stop_process_group(handle, release_reserve=False)
        self.assertTrue(stability._action_process_tree_clean(handle))

    def test_failed_stop_proof_retains_reserve_until_later_clean_close(
        self,
    ) -> None:
        stdout_path = self.evidence / "stop-proof.stdout.log"
        stderr_path = self.evidence / "stop-proof.stderr.log"
        handle = self.runner.start(
            [sys.executable, "-c", "import time;time.sleep(60)"],
            cwd=self.root,
            env=dict(os.environ, LC_ALL="C"),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        descriptor = self.runner._reserve._descriptors[0]
        real_wait_group = handle.wait_group

        with (
            mock.patch.object(handle, "wait_group", return_value=False),
            self.assertRaisesRegex(
                stability.StabilityError, "survived SIGKILL"
            ),
        ):
            stability._stop_process_group(handle)

        self.assertFalse(self.runner._reserve.released)
        self.assertGreaterEqual(os.fstat(descriptor).st_blocks, 1)
        self.assertTrue(real_wait_group(2.0))
        self.assertTrue(handle.wait_unexpected(2.0))

    def test_real_timeout_kills_and_reaps_the_process_group(self) -> None:
        receipt_path = self.evidence / "timeout-receipt.json"
        with self.assertRaisesRegex(stability.StabilityError, "outer timeout"):
            self.supervise(
                [sys.executable, "-c", "import time;time.sleep(60)"],
                receipt_path,
                1,
            )
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "outer-timeout"
        )

    def test_successful_parent_with_live_descendant_is_rejected_and_cleaned(self) -> None:
        receipt_path = self.evidence / "descendant-receipt.json"
        code = (
            "import json,subprocess,sys;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            "open(sys.argv[1],'w',encoding='utf-8').write("
            "json.dumps({'schema':'fixture-v1','status':'accepted'},"
            "indent=2,sort_keys=True)+'\\n')"
        )
        with self.assertRaisesRegex(
            stability.StabilityError,
            "^action left a live process-group or PID-namespace descendant$",
        ):
            self.supervise(
                [sys.executable, "-c", code, str(receipt_path)],
                receipt_path,
                5,
            )
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "supervision-error"
        )

    def test_descendant_cannot_escape_cleanup_with_a_new_session(self) -> None:
        receipt_path = self.evidence / "escaped-receipt.json"
        pid_path = self.root / "escaped.pid"
        code = (
            "import json,pathlib,subprocess,sys;"
            "child=subprocess.Popen([sys.executable,'-c',"
            "'import time;time.sleep(60)'],start_new_session=True);"
            "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
            "encoding='ascii').rsplit(')',1)[1].strip().split();"
            "open(sys.argv[2],'w',encoding='ascii').write("
            "str(child.pid)+':'+fields[19]);"
            "open(sys.argv[1],'w',encoding='utf-8').write("
            "json.dumps({'schema':'fixture-v1','status':'accepted'},"
            "indent=2,sort_keys=True)+'\\n')"
        )
        with self.assertRaisesRegex(stability.StabilityError, "descendant"):
            self.supervise(
                [
                    sys.executable, "-c", code,
                    str(receipt_path), str(pid_path),
                ],
                receipt_path,
                5,
            )
        self.assert_owned_identity_absent(pid_path)
        self.assertEqual(self.runner.last_handle.unexpected_pids(), [])
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "supervision-error"
        )

    def test_immediate_leader_exit_cannot_hide_closed_pipe_detached_child(
        self,
    ) -> None:
        receipt_path = self.evidence / "closed-pipe-receipt.json"
        identity_path = self.root / "closed-pipe-child.identity"
        code = (
            "import json,os,pathlib,subprocess,sys;"
            "sink=open(os.devnull,'wb');"
            "child=subprocess.Popen([sys.executable,'-c',"
            "'import time;time.sleep(60)'],start_new_session=True,"
            "stdin=subprocess.DEVNULL,stdout=sink,stderr=sink,close_fds=True);"
            "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
            "encoding='ascii').rsplit(')',1)[1].strip().split();"
            "open(sys.argv[2],'w',encoding='ascii').write("
            "str(child.pid)+':'+fields[19]);"
            "open(sys.argv[1],'w',encoding='utf-8').write("
            "json.dumps({'schema':'fixture-v1','status':'accepted'},"
            "indent=2,sort_keys=True)+'\\n')"
        )
        with self.assertRaisesRegex(stability.StabilityError, "descendant"):
            self.supervise(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(receipt_path),
                    str(identity_path),
                ],
                receipt_path,
                5,
            )
        self.assert_owned_identity_absent(identity_path)
        self.assertEqual(self.runner.last_handle.unexpected_pids(), [])
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "supervision-error"
        )

    def test_action_cleanup_converges_during_detached_final_forks(self) -> None:
        receipt_path = self.evidence / "fork-race-receipt.json"
        children_path = self.root / "fork-race-children.identities"
        forker_path = self.root / "fork-race-parent.identity"
        forker = f"""import os,signal,time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    pid = os.fork()
    if pid == 0:
        os.setsid()
        fields = open('/proc/self/stat', encoding='ascii').read().rsplit(')', 1)[1].strip().split()
        descriptor = os.open({str(children_path)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.write(descriptor, (str(os.getpid()) + ':' + fields[19] + '\\n').encode('ascii'))
        os.fsync(descriptor)
        os.close(descriptor)
        time.sleep(60)
        os._exit(0)
    time.sleep(0.01)
"""
        code = (
            "import json,os,pathlib,subprocess,sys;"
            "forker=subprocess.Popen([sys.executable,'-c',sys.argv[3]],"
            "start_new_session=True,stdin=subprocess.DEVNULL,"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True);"
            "fields=(pathlib.Path('/proc')/str(forker.pid)/'stat').read_text("
            "encoding='ascii').rsplit(')',1)[1].strip().split();"
            "open(sys.argv[2],'w',encoding='ascii').write("
            "str(forker.pid)+':'+fields[19]);"
            "open(sys.argv[1],'w',encoding='utf-8').write("
            "json.dumps({'schema':'fixture-v1','status':'accepted'},"
            "indent=2,sort_keys=True)+'\\n')"
        )
        observed: list[tuple[int, int]] = []
        real_signal = stability.SubprocessCommandHandle._signal_exact
        stop_calls: dict[int, int] = {}

        def delayed_second_stop(
            pid: int, start_time: int, signal_number: int,
        ) -> None:
            if signal_number == stability.signal.SIGSTOP and forker_path.exists():
                forker_pid = int(
                    forker_path.read_text(encoding="ascii").split(":", 1)[0]
                )
                if pid == forker_pid:
                    stop_calls[pid] = stop_calls.get(pid, 0) + 1
                    if stop_calls[pid] == 1:
                        return
                    if stop_calls[pid] == 2:
                        # Force children after the first cleanup observation.
                        # A fixed snapshot cleanup leaves these sessions alive.
                        time.sleep(0.10)
            real_signal(pid, start_time, signal_number)

        try:
            with (
                mock.patch.object(
                    stability.SubprocessCommandHandle,
                    "_signal_exact",
                    new=staticmethod(delayed_second_stop),
                ),
                self.assertRaisesRegex(stability.StabilityError, "descendant"),
            ):
                self.supervise(
                    [
                        sys.executable,
                        "-c",
                        code,
                        str(receipt_path),
                        str(forker_path),
                        forker,
                    ],
                    receipt_path,
                    5,
                )
            observed = [
                tuple(map(int, line.split(":")))
                for line in children_path.read_text(encoding="ascii").splitlines()
            ]
            self.assertGreaterEqual(len(observed), 10)
            for pid, start_time in observed:
                record = stability._action_process_table().get(pid)
                self.assertTrue(record is None or record[2] != start_time)
            self.assert_owned_identity_absent(forker_path)
            self.assertEqual(self.runner.last_handle.unexpected_pids(), [])
        finally:
            for pid, start_time in observed:
                real_signal(pid, start_time, stability.signal.SIGKILL)
            if forker_path.exists():
                pid_text, start_text = forker_path.read_text(
                    encoding="ascii"
                ).split(":")
                real_signal(
                    int(pid_text), int(start_text), stability.signal.SIGKILL
                )

    def test_action_stdout_flood_is_stopped_at_the_live_log_limit(self) -> None:
        receipt_path = self.evidence / "flood-receipt.json"
        code = (
            "import os;"
            "block=b'x'*65536;"
            "[(os.write(1,block)) for _ in range(1024)]"
        )
        with (
            mock.patch.object(stability, "MAX_ACTION_LOG_BYTES", 4096),
            self.assertRaisesRegex(stability.StabilityError, "output|size limit"),
        ):
            self.supervise(
                [sys.executable, "-c", code], receipt_path, 5
            )
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertLessEqual((self.evidence / "stdout.log").stat().st_size, 4096)

    def test_preexisting_unrelated_child_is_never_claimed_or_signalled(self) -> None:
        receipt_path = self.evidence / "unrelated-receipt.json"
        unrelated = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        try:
            with self.assertRaisesRegex(
                stability.StabilityError, "already owns a child"
            ):
                self.supervise(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    receipt_path,
                    5,
                )
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2.0)

    def test_multithreaded_controller_fails_before_spawning_an_action(self) -> None:
        receipt_path = self.evidence / "threaded-receipt.json"
        release = threading.Event()
        started = threading.Event()

        def hold_thread() -> None:
            started.set()
            release.wait(5.0)

        thread = threading.Thread(target=hold_thread)
        thread.start()
        started.wait(2.0)
        try:
            with self.assertRaisesRegex(
                stability.StabilityError, "dedicated single thread"
            ):
                self.supervise(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    receipt_path,
                    5,
                )
        finally:
            release.set()
            thread.join(2.0)
        self.assertFalse(thread.is_alive())


class ActionSignalIdentityContractTest(unittest.TestCase):
    @staticmethod
    def fixture_handle() -> object:
        handle = object.__new__(stability.SubprocessCommandHandle)
        handle.pid = 10_001
        handle._controller_pid = os.getpid()
        handle._leader_start_time = 77
        return handle

    def test_quiescence_requires_every_thread_stopped_on_two_scans(
        self,
    ) -> None:
        handle = self.fixture_handle()
        leader = (os.getpid(), handle.pid, handle._leader_start_time, "T")
        with (
            mock.patch.object(handle, "_owned_records", return_value={}),
            mock.patch.object(handle, "_leader_record", return_value=leader),
            mock.patch.object(handle, "_signal_exact"),
            mock.patch.object(
                stability,
                "_action_task_states",
                return_value={handle.pid: "T", handle.pid + 1: "D"},
                create=True,
            ) as task_states,
            mock.patch.object(
                stability.time, "monotonic", side_effect=[0.0, 6.0]
            ),
            self.assertRaisesRegex(
                stability.StabilityError, "writers did not quiesce"
            ),
        ):
            handle.quiesce_owned()
        self.assertGreaterEqual(task_states.call_count, 1)

        with (
            mock.patch.object(handle, "_owned_records", return_value={}),
            mock.patch.object(handle, "_leader_record", return_value=leader),
            mock.patch.object(handle, "_signal_exact"),
            mock.patch.object(
                stability,
                "_action_task_states",
                return_value={handle.pid: "T", handle.pid + 1: "T"},
                create=True,
            ) as task_states,
        ):
            handle.quiesce_owned()
        self.assertEqual(task_states.call_count, 2)

    def test_zombie_leader_with_live_worker_is_alive_and_killed_exactly(
        self,
    ) -> None:
        handle = self.fixture_handle()
        leader = (os.getpid(), handle.pid, handle._leader_start_time, "Z")
        descendant_pid = handle.pid + 10
        descendant_start = 88
        descendant = (
            handle.pid,
            handle.pid,
            descendant_start,
            "Z",
        )

        with (
            mock.patch.object(handle, "_leader_record", return_value=leader),
            mock.patch.object(handle, "_owned_records", return_value={}),
            mock.patch.object(
                stability,
                "_action_task_states",
                return_value={handle.pid: "Z", handle.pid + 1: "S"},
                create=True,
            ),
        ):
            self.assertTrue(handle.group_alive())

        with (
            mock.patch.object(
                handle,
                "_owned_records",
                side_effect=[{descendant_pid: descendant},
                             {descendant_pid: descendant}, {}],
            ),
            mock.patch.object(
                stability,
                "_action_task_states",
                side_effect=[
                    {descendant_pid: "Z", descendant_pid + 1: "S"},
                    {descendant_pid: "Z", descendant_pid + 1: "T"},
                ],
                create=True,
            ),
            mock.patch.object(handle, "_signal_exact") as exact_signal,
        ):
            handle.kill_unexpected()
        self.assertIn(
            mock.call(descendant_pid, descendant_start, stability.signal.SIGSTOP),
            exact_signal.call_args_list,
        )
        self.assertIn(
            mock.call(descendant_pid, descendant_start, stability.signal.SIGKILL),
            exact_signal.call_args_list,
        )

        with (
            mock.patch.object(
                handle,
                "_owned_records",
                side_effect=[{descendant_pid: descendant}, {}],
            ),
            mock.patch.object(
                stability,
                "_action_task_states",
                side_effect=stability._ActionTaskInventoryUnavailable(
                    "fixture hidden task directory"
                ),
            ),
            mock.patch.object(handle, "_signal_exact") as exact_signal,
        ):
            handle.kill_unexpected()
        exact_signal.assert_called_once_with(
            descendant_pid, descendant_start, stability.signal.SIGKILL
        )

    def test_exact_signal_revalidation_is_linear_not_namespace_quadratic(
        self,
    ) -> None:
        count = 1000
        start_time = 456
        with (
            mock.patch.object(
                stability,
                "_action_process_record",
                return_value=(1, 123, start_time, "T"),
            ) as record,
            mock.patch.object(
                stability,
                "_action_process_table",
                side_effect=AssertionError("must not rescan the namespace"),
            ),
            mock.patch.object(stability.os, "kill") as kill,
        ):
            for index in range(count):
                stability.SubprocessCommandHandle._signal_exact(
                    10_000 + index, start_time, stability.signal.SIGSTOP
                )
        self.assertEqual(record.call_count, count)
        self.assertEqual(kill.call_count, count)


class ArtifactTraversalBoundContractTest(unittest.TestCase):
    def test_oversize_artifact_is_rejected_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized = root / "oversized.bin"
            with oversized.open("wb") as stream:
                stream.truncate(stability.MAX_ARTIFACT_FILE_BYTES + 1)
            with (
                mock.patch.object(
                    stability,
                    "sha256_file",
                    side_effect=AssertionError("oversize file must not be hashed"),
                ),
                self.assertRaisesRegex(stability.StabilityError, "size limit"),
            ):
                stability._artifact_entry(root, oversized.name)

    def test_traversal_stops_at_the_file_count_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(3):
                (root / f"{index}.txt").write_text("x", encoding="ascii")
            with (
                mock.patch.object(stability, "MAX_ARTIFACTS", 2),
                self.assertRaisesRegex(stability.StabilityError, "file count"),
            ):
                stability._regular_files(root)

    def test_traversal_stops_at_the_aggregate_byte_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(3):
                (root / f"{index}.txt").write_text("x", encoding="ascii")
            with (
                mock.patch.object(stability, "MAX_ARTIFACT_BYTES", 2),
                self.assertRaisesRegex(stability.StabilityError, "byte count"),
            ):
                stability._regular_files(root)


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "posix_fallocate"),
    "POSIX filesystem reservation unavailable",
)
class FilesystemEmergencyReserveContractTest(unittest.TestCase):
    def test_reserve_is_hidden_allocated_and_released_normally(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                stability, "FILESYSTEM_EMERGENCY_RESERVE_BYTES", 4 * 1024 * 1024
            ):
                reserve = stability._FilesystemEmergencyReserve([root])
                self.assertFalse(reserve.released)
                self.assertGreaterEqual(
                    sum(os.fstat(fd).st_blocks * 512 for fd in reserve._descriptors),
                    stability.FILESYSTEM_EMERGENCY_RESERVE_BYTES,
                )
                self.assertEqual(list(root.iterdir()), [])
                reserve.release()
                self.assertTrue(reserve.released)
                self.assertEqual(list(root.iterdir()), [])

    def test_reserve_allocation_failure_leaves_no_visible_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch.object(
                    stability, "FILESYSTEM_EMERGENCY_RESERVE_BYTES", 4096
                ),
                mock.patch.object(
                    stability.os,
                    "posix_fallocate",
                    side_effect=OSError(28, "fixture ENOSPC"),
                ),
                self.assertRaisesRegex(
                    stability.StabilityError,
                    "cannot allocate filesystem emergency reserve",
                ),
            ):
                stability._FilesystemEmergencyReserve([root])
            self.assertEqual(list(root.iterdir()), [])

    def test_reserve_close_failure_is_not_silently_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                stability, "FILESYSTEM_EMERGENCY_RESERVE_BYTES", 4096
            ):
                reserve = stability._FilesystemEmergencyReserve([root])
            descriptor = reserve._descriptors[0]
            real_close = os.close

            def close(candidate: int) -> None:
                if candidate == descriptor:
                    raise OSError(5, "fixture close failure")
                real_close(candidate)

            try:
                with (
                    mock.patch.object(stability.os, "close", side_effect=close),
                    self.assertRaisesRegex(
                        stability.StabilityError,
                        "cannot release filesystem emergency reserve",
                    ),
                ):
                    reserve.release()
            finally:
                real_close(descriptor)


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "posix_fallocate"),
    "POSIX live disk monitoring unavailable",
)
class LiveActionDiskProtectionContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "evidence"
        self.runtime = self.root / "runtime"
        self.evidence.mkdir()
        self.runtime.mkdir()
        self.reserve_patch = mock.patch.object(
            stability, "FILESYSTEM_EMERGENCY_RESERVE_BYTES", 4 * 1024 * 1024
        )
        self.reserve_patch.start()
        self.recovery_patch = mock.patch.object(
            stability, "MINIMUM_FILESYSTEM_RECOVERY_BYTES", 1024 * 1024
        )
        self.recovery_patch.start()
        self.policy = stability.validate_policy(canonical_policy(), ROOT)
        self.clock = stability.LinuxClock()
        self.writer = stability.JournalWriter(
            self.root / "journal.jsonl",
            self.policy,
            SESSION_ID,
            CONTROLLER_ID,
            stability.sha256_file(POLICY_PATH),
            self.clock,
        )

    def tearDown(self) -> None:
        runner = getattr(self, "runner", None)
        handle = getattr(runner, "last_handle", None)
        if handle is not None and (
            handle.group_alive() or handle.unexpected_pids()
        ):
            handle.kill_group()
            handle.kill_unexpected()
            handle.wait_group(2.0)
            handle.wait_unexpected(2.0)
        if runner is not None:
            runner.close()
        self.writer.close()
        self.recovery_patch.stop()
        self.reserve_patch.stop()
        self.temporary.cleanup()

    def supervise(
        self,
        code: str,
        *arguments: Path,
        filesystem_probe: object | None = None,
    ) -> None:
        self.runner = stability.SubprocessCommandRunner(
            evidence_root=self.evidence,
            runtime_root=self.runtime,
            filesystem_probe=filesystem_probe,
        )
        receipt = self.evidence / "receipt.json"
        stability.supervise_action(
            self.writer,
            self.runner,
            action_id="c" * 64,
            kind="qualification",
            cycle_ordinal=1,
            action_ordinal=0,
            timeout_seconds=5,
            argv=[sys.executable, "-c", code, *map(os.fspath, arguments)],
            cwd=self.root,
            env=dict(os.environ, LC_ALL="C"),
            stdout_path=self.evidence / "stdout.log",
            stderr_path=self.evidence / "stderr.log",
            receipt_path=receipt,
            verify_receipt=lambda path: stability.sha256_file(path),
        )

    def test_direct_evidence_file_flood_is_killed_live(self) -> None:
        target = self.evidence / "direct-flood.bin"
        code = (
            "import os,subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
            "start_new_session=True,stdin=subprocess.DEVNULL,"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True);"
            "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
            "os.posix_fallocate(fd,0,2*1024*1024);os.close(fd);time.sleep(60)"
        )
        with (
            mock.patch.object(stability, "MAX_ARTIFACT_BYTES", 1024 * 1024),
            mock.patch.object(stability, "ACTION_TREE_SCAN_SECONDS", 0.05),
            self.assertRaisesRegex(
                stability.StabilityError, "evidence.*byte|disk"
            ),
        ):
            self.supervise(code, target, filesystem_probe=None)
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertEqual(self.runner.last_handle.unexpected_pids(), [])
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "supervision-error"
        )

    def test_observed_runtime_breach_stops_writer_before_reserve_release(
        self,
    ) -> None:
        release_marker = self.root / "reserve-released"
        post_release_write = self.runtime / "post-release.bin"
        writer_ready = self.root / "writer-ready"

        def probe(path: Path) -> object:
            del path
            available = (
                stability.MINIMUM_FILESYSTEM_FREE_BYTES - 1
                if writer_ready.exists()
                else stability.MINIMUM_FILESYSTEM_FREE_BYTES + 1024 * 1024 * 1024
            )
            runner = getattr(self, "runner", None)
            reserve = getattr(runner, "_reserve", None)
            if reserve is not None and reserve.released:
                available += stability.FILESYSTEM_EMERGENCY_RESERVE_BYTES
            return mock.Mock(
                f_bavail=available,
                f_frsize=1,
                f_favail=stability.MINIMUM_FILESYSTEM_FREE_INODES + 1000,
                f_files=0,
            )

        code = (
            "import os,pathlib,sys,time;"
            "pathlib.Path(sys.argv[1]).write_text('ready',encoding='ascii');"
            "marker=pathlib.Path(sys.argv[2]);"
            "\nwhile not marker.exists(): time.sleep(0.001)"
            "\nfd=os.open(sys.argv[3],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)"
            "\nos.posix_fallocate(fd,0,1024*1024);os.close(fd);time.sleep(60)"
        )
        real_release = stability._FilesystemEmergencyReserve.release

        def expose_release_to_writer(
            reserve: object, *, best_effort: bool = False,
        ) -> None:
            was_released = reserve.released
            real_release(reserve, best_effort=best_effort)
            if not was_released:
                release_marker.write_text("released", encoding="ascii")
                # Old release-before-STOP ordering deterministically lets the
                # armed child consume the just-recovered extent in this gap.
                time.sleep(0.20)

        with (
            mock.patch.object(
                stability._FilesystemEmergencyReserve,
                "release",
                new=expose_release_to_writer,
            ),
            self.assertRaisesRegex(
                stability.StabilityError, "free-space reserve"
            ),
        ):
            self.supervise(
                code,
                writer_ready,
                release_marker,
                post_release_write,
                filesystem_probe=probe,
            )
        self.assertTrue(writer_ready.is_file())
        self.assertTrue(release_marker.is_file())
        self.assertFalse(post_release_write.exists())
        self.assertTrue(self.runner._reserve.released)
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertEqual(self.runner.last_handle.unexpected_pids(), [])
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "supervision-error"
        )

    def test_runtime_allocation_drop_is_bound_to_campaign_baseline(self) -> None:
        target = self.runtime / "allocation.bin"
        baseline = stability.MINIMUM_FILESYSTEM_FREE_BYTES + 16 * 1024 * 1024

        def probe(path: Path) -> object:
            del path
            available = (
                baseline - 2 * 1024 * 1024
                if target.exists() and target.stat().st_size
                else baseline
            )
            runner = getattr(self, "runner", None)
            reserve = getattr(runner, "_reserve", None)
            if reserve is not None and reserve.released:
                available += stability.FILESYSTEM_EMERGENCY_RESERVE_BYTES
            return mock.Mock(
                f_bavail=available,
                f_frsize=1,
                f_favail=0,
                f_files=0,
            )

        code = (
            "import os,sys,time;"
            "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
            "os.posix_fallocate(fd,0,1024*1024);os.close(fd);time.sleep(60)"
        )
        with (
            mock.patch.object(
                stability, "MAX_FILESYSTEM_CONSUMPTION_BYTES", 1024 * 1024
            ),
            self.assertRaisesRegex(stability.StabilityError, "allocation budget"),
        ):
            self.supervise(code, target, filesystem_probe=probe)
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertEqual(self.runner.last_handle.unexpected_pids(), [])
        self.assertEqual(
            self.writer.events[-1]["payload"]["outcome"], "supervision-error"
        )

    def test_runtime_fallocate_cannot_cross_the_inherited_hard_limit(self) -> None:
        target = self.runtime / "hard-limit.bin"
        code = (
            "import errno,os,sys,time;"
            "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
            "\ntry: os.posix_fallocate(fd,0,2*1024*1024)"
            "\nexcept OSError as error: sys.exit(73 if error.errno == errno.EFBIG else 74)"
            "\nos.close(fd);time.sleep(60)"
        )
        with (
            mock.patch.object(stability, "MAX_ACTION_FILE_BYTES", 1024 * 1024),
            self.assertRaisesRegex(stability.StabilityError, "exit code 73"),
        ):
            self.supervise(code, target)
        self.assertLessEqual(target.stat().st_size, 1024 * 1024)
        self.assertFalse(self.runner.last_handle.group_alive())
        self.assertEqual(self.runner.last_handle.unexpected_pids(), [])

class JournalFileContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "journal.jsonl"
        self.events = accepted_journal()
        self.path.write_bytes(b"".join(
            stability.canonical_json(event) + b"\n" for event in self.events
        ))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_canonical_journal_load_is_read_only(self) -> None:
        before = (self.path.stat().st_size, self.path.stat().st_mtime_ns)
        loaded = stability.load_journal(self.path)
        after = (self.path.stat().st_size, self.path.stat().st_mtime_ns)
        self.assertEqual(loaded, self.events)
        self.assertEqual(after, before)

    def test_pretty_partial_blank_and_non_utf8_journals_are_rejected(self) -> None:
        cases = {
            "pretty": json.dumps(self.events[0], indent=2).encode("utf-8") + b"\n",
            "partial": stability.canonical_json(self.events[0]),
            "blank": stability.canonical_json(self.events[0]) + b"\n\n",
            "non-utf8": b"\xff\n",
        }
        for name, contents in cases.items():
            with self.subTest(name=name):
                self.path.write_bytes(contents)
                with self.assertRaises(stability.StabilityError):
                    stability.load_journal(self.path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_symlinked_journal_is_rejected(self) -> None:
        target = self.root / "target.jsonl"
        target.write_bytes(self.path.read_bytes())
        self.path.unlink()
        self.path.symlink_to(target)
        with self.assertRaisesRegex(stability.StabilityError, "regular"):
            stability.load_journal(self.path)


if __name__ == "__main__":
    unittest.main()
