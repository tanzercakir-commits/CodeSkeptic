#!/usr/bin/env python3
"""Contracts for Phase 2 measurement schemas, deltas, and fingerprints."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compare_measurements  # noqa: E402
import juliet_eval  # noqa: E402
import render_quality_dashboard  # noqa: E402
import run_measurement_lab  # noqa: E402


def corpus(kind: str, findings: int = 0, caught: int = 0) -> dict:
    return {
        "kind": kind,
        "cases": 1,
        "caught_cases": caught,
        "floor_violations": 0,
        "findings": findings,
        "blocking_findings": findings,
        "report_only_findings": 0,
        "rules": {"null-deref": findings} if findings else {},
        "fingerprints": {"csf1-0000000000000001": findings} if findings else {},
        "coverage": {
            "attempted_tus": 1,
            "analyzed_tus": 1,
            "broken_tus": 0,
            "incomplete_functions": 0,
        },
        "performance": {"elapsed_ms": 100, "peak_rss_kb": 1000},
        "unavailable_runs": 0,
        "case_results": [],
    }


def receipt(revision: str) -> dict:
    return {
        "schema_version": 1,
        "revision": revision,
        "corpora": {
            "clean": corpus("clean"),
            "defective": corpus("defective", findings=1, caught=1),
            "real_repo": corpus("real-repository"),
        },
    }


class MeasurementLabTest(unittest.TestCase):
    def test_fingerprint_is_root_line_and_format_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "checkout-a" / "project" / "src" / "sample.cpp"
            second = root / "checkout-b" / "project" / "src" / "sample.cpp"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.write_text("int f(int* p) {\n  return *p;\n}\n", encoding="utf-8")
            second.write_text("// shift\n\nint f(int* p) {\n\treturn  * p;\n}\n", encoding="utf-8")
            left = {
                "rule_id": "null-deref", "severity": "warning",
                "file": str(first), "line": 2, "function": "f",
                "message": "Possible null dereference",
            }
            right = dict(left, file=str(second), line=4, severity="error",
                         message="Definite dereference of a null pointer")
            oracle = run_measurement_lab.FingerprintOracle()
            self.assertEqual(oracle.fingerprint(left), oracle.fingerprint(right))

    def test_compare_renders_all_four_delta_axes(self) -> None:
        base = receipt("base")
        head = receipt("head")
        base["corpora"]["defective"]["coverage"]["broken_tus"] = 2
        head["corpora"]["defective"]["performance"]["elapsed_ms"] = 110
        head["corpora"]["defective"]["performance"]["peak_rss_kb"] = 1050
        comparison, failures = compare_measurements.compare(base, head)
        self.assertEqual(failures, [])
        markdown = compare_measurements.render(comparison)
        self.assertIn("Findings", markdown)
        self.assertIn("Analyzed / broken TUs", markdown)
        self.assertIn("Elapsed", markdown)
        self.assertIn("Peak RSS", markdown)
        self.assertIn("Fingerprints", markdown)
        self.assertIn("1/2 → 1/0", markdown)
        self.assertIn("Measurement gate: PASS", markdown)

    def test_compare_fails_closed_on_quality_or_coverage_loss(self) -> None:
        base = receipt("base")
        head = receipt("head")
        head["corpora"]["clean"]["findings"] = 1
        head["corpora"]["defective"]["caught_cases"] = 0
        head["corpora"]["real_repo"]["coverage"]["analyzed_tus"] = 0
        comparison, failures = compare_measurements.compare(base, head)
        self.assertEqual(comparison["gate"], "fail")
        self.assertTrue(any("false-positive" in item for item in failures))
        self.assertTrue(any("recall dropped" in item for item in failures))
        self.assertTrue(any("coverage dropped" in item for item in failures))

    def test_juliet_baseline_and_three_way_miss_partition(self) -> None:
        baseline = json.loads(
            (ROOT / "scripts" / "measurement_baseline.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(baseline["juliet"]), set(render_quality_dashboard.RULES))
        detailed = {"float", "opaque", "multifile", "baseline", "flow", "cpp", "other"}
        classified = {bucket for values in juliet_eval.MISS_CLASSES.values() for bucket in values}
        self.assertEqual(classified, detailed)
        for row in baseline["juliet"].values():
            misses = row["misses"]
            self.assertEqual(
                misses["total"],
                misses["addressable"] + misses["model_gap"] + misses["out_of_scope"],
            )

    def test_quality_dashboard_parses_machine_rows(self) -> None:
        baseline = json.loads(
            (ROOT / "scripts" / "measurement_baseline.json").read_text(encoding="utf-8")
        )
        lines = []
        for cwe, row in baseline["juliet"].items():
            lines.append(
                f"JULIET_RESULT {cwe} files={row['files']} tp={row['rtp']} fp={row['rfp']} "
                f"precision={row['precision']:.3f} hitrate={row['recall']:.3f} "
                f"rtp={row['rtp']} rfp={row['rfp']} rprecision={row['precision']:.3f} "
                f"rhitrate={row['recall']:.3f} rcaseprec=1.000 rf1={row['case_f1']:.3f} eprecision=1.000"
            )
            misses = row["misses"]
            lines.append(
                f"JULIET_MISS_CLASS {cwe} total={misses['total']} "
                f"addressable={misses['addressable']} model_gap={misses['model_gap']} "
                f"out_of_scope={misses['out_of_scope']}"
            )
        lines.append("[juliet] OK — see the JULIET_RESULT lines for a summary")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "juliet.txt"
            output.write_text("\n".join(lines), encoding="utf-8")
            parsed = render_quality_dashboard.parse_output(output)
        self.assertEqual(set(parsed), set(render_quality_dashboard.RULES))
        markdown = render_quality_dashboard.render(parsed, baseline, None)
        self.assertIn("Rule quality dashboard", markdown)
        self.assertIn("addressable", markdown)


if __name__ == "__main__":
    unittest.main()
