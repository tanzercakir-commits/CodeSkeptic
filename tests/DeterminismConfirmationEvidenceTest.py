#!/usr/bin/env python3
"""Contracts for the accepted Phase 10.7 Fedora confirmation evidence."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    ROOT
    / "docs/evidence/phase10/determinism/confirmations"
    / "2026-08-22-fedora44-i5-1235u-exclusive-pcores-kernel-6-19-10"
)
QUALIFICATION = EVIDENCE / "qualification"
CONFIRMATION = QUALIFICATION / "confirmation"
ATTEMPT23 = EVIDENCE / "host/attempt23"
ATTEMPT24 = EVIDENCE / "host/attempt24-erratum"
SHA256_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def key_values(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise AssertionError(f"invalid key/value receipt line: {line!r}")
        result[key] = value
    return result


class DeterminismConfirmationEvidenceTest(unittest.TestCase):
    maxDiff = None

    def verify_manifest(
        self,
        root: Path,
        manifest: Path,
        *,
        expected_entries: int | None = None,
        exact_coverage: bool = False,
    ) -> dict[str, str]:
        entries: dict[str, str] = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = SHA256_LINE.fullmatch(line)
            self.assertIsNotNone(match, line)
            assert match is not None
            expected, raw_name = match.groups()
            name = raw_name.removeprefix("./")
            relative = Path(name)
            self.assertFalse(relative.is_absolute(), name)
            self.assertNotIn("..", relative.parts, name)
            self.assertNotIn(name, entries, name)
            candidate = root / relative
            self.assertTrue(candidate.is_file(), name)
            self.assertFalse(candidate.is_symlink(), name)
            self.assertEqual(sha256(candidate), expected, name)
            entries[name] = expected

        if expected_entries is not None:
            self.assertEqual(len(entries), expected_entries)
        if exact_coverage:
            actual = {
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file() and path != manifest
            }
            self.assertEqual(set(entries), actual)
        return entries

    def test_top_level_manifest_binds_the_complete_symlink_free_bundle(self) -> None:
        self.assertTrue(EVIDENCE.is_dir())
        self.assertEqual(
            [path.relative_to(EVIDENCE).as_posix()
             for path in EVIDENCE.rglob("*") if path.is_symlink()],
            [],
        )
        entries = self.verify_manifest(
            EVIDENCE,
            EVIDENCE / "SHA256SUMS",
            exact_coverage=True,
        )
        self.assertIn("assessment.json", entries)
        self.assertIn("qualification/confirmation/receipt.json", entries)
        self.assertIn("host/attempt23/terminal-receipt.txt", entries)
        self.assertIn("host/attempt24-erratum/guided-headless-confirmation.sh", entries)

    def test_nested_manifests_and_receipt_bind_all_measured_bytes(self) -> None:
        self.verify_manifest(
            QUALIFICATION,
            QUALIFICATION / "SHA256SUMS",
            expected_entries=636,
        )
        self.verify_manifest(
            CONFIRMATION,
            CONFIRMATION / "SHA256SUMS",
            expected_entries=633,
            exact_coverage=True,
        )
        self.verify_manifest(
            ATTEMPT24,
            ATTEMPT24 / "SHA256SUMS",
            expected_entries=9,
        )

        receipt_path = CONFIRMATION / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(
            sha256(receipt_path),
            "a7d8409199a22a2896d8486e2e7d95674ba254bdb9c6df84da9746f2a3c096f9",
        )
        self.assertEqual(receipt["schema"], "codeskeptic-determinism-qualification-v7")
        self.assertEqual(receipt["status"], "accepted")
        self.assertEqual(receipt["failures"], [])
        self.assertEqual(receipt["configuration"]["repetitions"], 10)
        self.assertEqual(receipt["configuration"]["performance_policy"], "required")
        self.assertEqual(receipt["baseline"]["semantic_gate"], "pass")
        self.assertEqual(receipt["baseline"]["performance_gate"], "pass")
        self.assertEqual(receipt["baseline"]["regressions"], [])
        self.assertEqual(receipt["duration_ms"], 2_670_421)
        self.assertEqual(len(receipt["artifacts"]), 631)
        self.assertEqual(
            len({artifact["path"] for artifact in receipt["artifacts"]}),
            631,
        )
        for artifact in receipt["artifacts"]:
            path = CONFIRMATION / artifact["path"]
            self.assertEqual(path.stat().st_size, artifact["size"], artifact["path"])
            self.assertEqual(sha256(path), artifact["sha256"], artifact["path"])

        self.assertEqual(
            receipt["source"],
            {
                "file_count": 386,
                "manifest_sha256": (
                    "b8c4b7235c1c8704304dd5fe4de90728e6cd0b4ab020526b76f1e4731b3e0d9b"
                ),
                "revision": "88e369b21675e64e0a92842b0ce22f0c8148745e",
            },
        )
        expected_semantics = {
            "unit": "383bef6a2b61b9745692eb9e696d40f4c719a508e292fd7faf1dcc13640d6c54",
            "real-repository": (
                "22b4b6d506cff038ee753d13a11a89319931e03b4c15406636752428451f8a6e"
            ),
            "release-candidate": (
                "ae2e427b1c6bce48d62d03c4eda0235413f13330f1c40d6ed05bc6fb6476e862"
            ),
        }
        self.assertEqual(
            {workload["id"]: workload["semantic_sha256"]
             for workload in receipt["workloads"]},
            expected_semantics,
        )
        self.assertEqual(
            [len(workload["runs"]) for workload in receipt["workloads"]],
            [10, 10, 10],
        )
        self.assertEqual(
            [[len(run["inner_runs"]) for run in workload["runs"]]
             for workload in receipt["workloads"]],
            [[10] * 10, [1] * 10, [1] * 10],
        )

    def test_accepted_payload_is_distinct_from_the_guided_false_negative(self) -> None:
        guided = key_values(ATTEMPT23 / "guided-result.txt")
        terminal = key_values(ATTEMPT23 / "terminal-receipt.txt")
        self.assertEqual(guided["CODESKEPTIC_GUIDED_PAYLOAD_EXIT"], "2")
        self.assertEqual(guided["CODESKEPTIC_GUIDED_TRANSACTION_SAFE"], "1")
        self.assertEqual(guided["CODESKEPTIC_GUIDED_GRAPHICAL_RESTORE_EXIT"], "0")
        self.assertEqual(terminal["CODESKEPTIC_HEADLESS_PAYLOAD_EXIT"], "0")
        self.assertEqual(terminal["CODESKEPTIC_HEADLESS_RESTORATION_FAILED"], "0")
        self.assertEqual(
            terminal["CODESKEPTIC_HEADLESS_JOURNAL_SHA256"],
            sha256(ATTEMPT23 / "transaction-journal.txt"),
        )

        log = (ATTEMPT23 / "headless.log").read_text(encoding="utf-8")
        self.assertIn(
            "CODESKEPTIC_HEADLESS_DRKONQI_COUNTER_TRANSITION "
            "previous=160 current=160",
            log,
        )
        self.assertIn("DETERMINISM_QUALIFICATION_OK mode=run workloads=3 repetitions=10", log)
        self.assertIn("DETERMINISM_QUALIFICATION_OK mode=verify workloads=3 repetitions=10", log)
        self.assertIn("CODESKEPTIC_HEADLESS_CONTROLLER_CLEANUP_FAILED=0", log)
        self.assertIn("CODESKEPTIC_HEADLESS_CONTROLLER_EXIT=0", log)

        old_wrapper = (ATTEMPT23 / "guided-headless-confirmation.sh").read_text(
            encoding="utf-8"
        )
        fixed_wrapper = (ATTEMPT24 / "guided-headless-confirmation.sh").read_text(
            encoding="utf-8"
        )
        old_transition = old_wrapper.split(
            "transition_graphical_counter_after_receipt() {", 1
        )[1].split("restoration_surface_clean() {", 1)[0]
        fixed_transition = fixed_wrapper.split(
            "transition_graphical_counter_after_receipt() {", 1
        )[1].split("restoration_surface_clean() {", 1)[0]
        self.assertIn("$accepted == 0", old_transition)
        self.assertIn("drkonqi_accepted_before_isolate=0", old_transition)
        self.assertNotIn('$accepted == "$journal_accepted" || $accepted == 0', old_transition)
        self.assertIn(
            '( $accepted == "$journal_accepted" || $accepted == 0 )',
            fixed_transition,
        )
        self.assertIn("drkonqi_accepted_before_isolate=$accepted", fixed_transition)
        regression = (ATTEMPT24 / "test-confirmation-operator.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "test_guided_counter_transition_accepts_preserved_or_reset_counter",
            regression,
        )

        assessment = json.loads((EVIDENCE / "assessment.json").read_text(encoding="utf-8"))
        self.assertEqual(
            assessment["classification"],
            "qualification-accepted-guided-wrapper-false-negative",
        )
        self.assertEqual(assessment["qualification"]["status"], "accepted")
        self.assertEqual(assessment["qualification"]["failures"], [])
        self.assertEqual(assessment["guided_result"]["payload_exit"], 2)
        self.assertEqual(assessment["headless_terminal"]["payload_exit"], 0)
        self.assertFalse(assessment["orchestration_erratum"]["physical_rerun_required"])
        self.assertEqual(
            assessment["orchestration_erratum"]["corrected_operator_tests"],
            {"passed": 65, "total": 65},
        )


if __name__ == "__main__":
    unittest.main()
