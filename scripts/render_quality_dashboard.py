#!/usr/bin/env python3
"""Render a per-rule Juliet quality and miss-class delta dashboard."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


RESULT = re.compile(r"^JULIET_RESULT\s+(\S+)\s+(.*)$")
MISSES = re.compile(r"^JULIET_MISS_CLASS\s+(\S+)\s+(.*)$")
KEY_VALUE = re.compile(r"([a-z0-9_]+)=([^\s]+)")
RULES = {
    "CWE476_NULL_Pointer_Dereference": "null-deref",
    "CWE401_Memory_Leak": "memory-leak",
    "CWE415_Double_Free": "double-free",
    "CWE416_Use_After_Free": "use-after-free",
    "CWE369_Divide_by_Zero": "div-by-zero",
    "CWE190_Integer_Overflow": "int-overflow",
}


def fail(message: str) -> None:
    print(f"QUALITY_DASHBOARD_FAIL {message}", file=sys.stderr)
    raise SystemExit(1)


def fields(text: str) -> dict[str, str]:
    return dict(KEY_VALUE.findall(text))


def parse_output(path: Path) -> dict[str, dict]:
    results: dict[str, dict] = {}
    miss_rows: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = RESULT.search(line)
        if match:
            cwe, raw = match.groups()
            if cwe in results:
                fail(f"duplicate JULIET_RESULT for {cwe}")
            values = fields(raw)
            try:
                results[cwe] = {
                    "rule": RULES[cwe],
                    "files": int(values["files"]),
                    "rtp": int(values["rtp"]),
                    "rfp": int(values["rfp"]),
                    "precision": float(values["rprecision"]),
                    "recall": float(values["rhitrate"]),
                    "case_f1": float(values["rf1"]),
                }
            except (KeyError, ValueError) as error:
                fail(f"malformed JULIET_RESULT for {cwe}: {error}")
        match = MISSES.search(line)
        if match:
            cwe, raw = match.groups()
            if cwe in miss_rows:
                fail(f"duplicate JULIET_MISS_CLASS for {cwe}")
            values = fields(raw)
            try:
                miss_rows[cwe] = {
                    key: int(values[key])
                    for key in ("total", "addressable", "model_gap", "out_of_scope")
                }
            except (KeyError, ValueError) as error:
                fail(f"malformed JULIET_MISS_CLASS for {cwe}: {error}")

    if set(results) != set(RULES):
        fail(f"result set expected={sorted(RULES)} got={sorted(results)}")
    if set(miss_rows) != set(RULES):
        fail(f"miss set expected={sorted(RULES)} got={sorted(miss_rows)}")
    for cwe, misses in miss_rows.items():
        classified = sum(
            misses[key] for key in ("addressable", "model_gap", "out_of_scope")
        )
        if classified != misses["total"]:
            fail(f"miss partition for {cwe}: classified={classified} total={misses['total']}")
        results[cwe]["misses"] = misses
    return results


def parse_time(path: Path | None) -> dict[str, int | float] | None:
    if path is None or not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
    elapsed = re.search(
        r"Elapsed \(wall clock\) time .*:\s*((?:\d+:)?\d+:\d+(?:\.\d+)?)",
        text,
    )
    if not rss or not elapsed:
        return None
    parts = [float(part) for part in elapsed.group(1).split(":")]
    seconds = 0.0
    for part in parts:
        seconds = seconds * 60 + part
    return {"elapsed_seconds": round(seconds, 3), "peak_rss_kb": int(rss.group(1))}


def signed(value: float) -> str:
    return f"{value:+.3f}"


def render(current: dict[str, dict], baseline: dict, performance: dict | None) -> str:
    lines = [
        "## Rule quality dashboard",
        "",
        "Reference: analyzer tree `%(analyzer_tree)s`, workflow run `%(workflow_run)s`." % baseline["reference"],
        "",
        "| Rule | Precision (base → head, Δ) | Recall (base → head, Δ) | F1 (base → head, Δ) | TP / FP | Misses A / M / O |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for cwe in RULES:
        head = current[cwe]
        base = baseline["juliet"][cwe]
        misses = head["misses"]
        lines.append(
            "| `%(rule)s` | %(bp).3f → %(hp).3f (%(dp)s) | "
            "%(br).3f → %(hr).3f (%(dr)s) | %(bf).3f → %(hf).3f (%(df)s) | "
            "%(tp)d / %(fp)d | %(a)d / %(m)d / %(o)d |" % {
                "rule": head["rule"],
                "bp": base["precision"], "hp": head["precision"],
                "dp": signed(head["precision"] - base["precision"]),
                "br": base["recall"], "hr": head["recall"],
                "dr": signed(head["recall"] - base["recall"]),
                "bf": base["case_f1"], "hf": head["case_f1"],
                "df": signed(head["case_f1"] - base["case_f1"]),
                "tp": head["rtp"], "fp": head["rfp"],
                "a": misses["addressable"], "m": misses["model_gap"],
                "o": misses["out_of_scope"],
            }
        )
    lines.extend([
        "",
        "Miss classes: **A** addressable, **M** engine/model gap, **O** intentionally out of scope.",
    ])
    if performance:
        lines.extend([
            "",
            f"Benchmark runtime: {performance['elapsed_seconds']:.3f}s; "
            f"peak RSS: {performance['peak_rss_kb']} KiB.",
        ])
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--juliet-output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--time-output", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    if baseline.get("schema_version") != 1 or set(baseline.get("juliet", {})) != set(RULES):
        fail("invalid measurement baseline schema or CWE set")
    current = parse_output(args.juliet_output)
    performance = parse_time(args.time_output)
    payload = {
        "schema_version": 1,
        "reference": baseline["reference"],
        "juliet": current,
        "performance": performance,
    }
    args.json_output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.markdown_output.write_text(
        render(current, baseline, performance), encoding="utf-8"
    )
    print("QUALITY_DASHBOARD_OK rules=6 miss_partition=complete")


if __name__ == "__main__":
    main()
