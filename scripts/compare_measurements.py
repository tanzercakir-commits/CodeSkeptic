#!/usr/bin/env python3
"""Compare base/head measurement-lab receipts and render the PR delta."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


CORPORA = ("clean", "defective", "real_repo")


def fail(message: str) -> None:
    print(f"MEASUREMENT_COMPARE_FAIL {message}", file=sys.stderr)
    raise SystemExit(2)


def delta(value: int) -> str:
    return f"{value:+d}"


def percent(base: int | None, head: int | None) -> str:
    if base in (None, 0) or head is None:
        return "n/a"
    return f"{((head - base) * 100 / base):+.1f}%"


def fingerprint_delta(base: dict, head: dict) -> tuple[Counter, Counter]:
    old = Counter({key: int(value) for key, value in base.items()})
    new = Counter({key: int(value) for key, value in head.items()})
    return new - old, old - new


def compare(base: dict, head: dict) -> tuple[dict, list[str]]:
    for name, payload in (("base", base), ("head", head)):
        if payload.get("schema_version") != 1:
            fail(f"{name} schema_version={payload.get('schema_version')!r}")
        if set(payload.get("corpora", {})) != set(CORPORA):
            fail(f"{name} corpus set differs")

    failures: list[str] = []
    rows: dict[str, dict] = {}
    rule_deltas: dict[str, dict[str, int]] = {}
    for corpus_name in CORPORA:
        old = base["corpora"][corpus_name]
        new = head["corpora"][corpus_name]
        added, removed = fingerprint_delta(
            old.get("fingerprints", {}), new.get("fingerprints", {})
        )
        rows[corpus_name] = {
            "kind": new["kind"],
            "base_cases": old["cases"],
            "head_cases": new["cases"],
            "base_findings": old["findings"],
            "head_findings": new["findings"],
            "finding_delta": new["findings"] - old["findings"],
            "base_analyzed_tus": old["coverage"]["analyzed_tus"],
            "head_analyzed_tus": new["coverage"]["analyzed_tus"],
            "base_broken_tus": old["coverage"]["broken_tus"],
            "head_broken_tus": new["coverage"]["broken_tus"],
            "base_elapsed_ms": old["performance"]["elapsed_ms"],
            "head_elapsed_ms": new["performance"]["elapsed_ms"],
            "elapsed_delta_percent": percent(
                old["performance"]["elapsed_ms"],
                new["performance"]["elapsed_ms"],
            ),
            "base_peak_rss_kb": old["performance"].get("peak_rss_kb"),
            "head_peak_rss_kb": new["performance"].get("peak_rss_kb"),
            "rss_delta_percent": percent(
                old["performance"].get("peak_rss_kb"),
                new["performance"].get("peak_rss_kb"),
            ),
            "fingerprints_added": dict(sorted(added.items())),
            "fingerprints_removed": dict(sorted(removed.items())),
        }
        if new.get("unavailable_runs", 0) != 0:
            failures.append(f"{corpus_name}: unavailable analysis run")
        if new["coverage"]["broken_tus"] != 0:
            failures.append(f"{corpus_name}: broken translation units")
        if new["coverage"]["analyzed_tus"] < old["coverage"]["analyzed_tus"]:
            failures.append(f"{corpus_name}: analyzed TU coverage dropped")
        if corpus_name == "clean" and new["findings"] > old["findings"]:
            failures.append(f"clean: new false-positive findings")
        if corpus_name == "defective":
            if new["caught_cases"] < old["caught_cases"]:
                failures.append("defective: caught-case recall dropped")
            if new.get("floor_violations", 0) != 0:
                failures.append("defective: adjudicated finding floor violated")

        rules = set(old.get("rules", {})) | set(new.get("rules", {}))
        for rule in rules:
            rule_deltas.setdefault(rule, {})[corpus_name] = (
                int(new.get("rules", {}).get(rule, 0))
                - int(old.get("rules", {}).get(rule, 0))
            )

    return {
        "schema_version": 1,
        "base_revision": base.get("revision"),
        "head_revision": head.get("revision"),
        "gate": "fail" if failures else "pass",
        "failures": failures,
        "corpora": rows,
        "rule_finding_deltas": dict(sorted(rule_deltas.items())),
    }, failures


def render(comparison: dict) -> str:
    lines = [
        "## Base → head measurement delta",
        "",
        f"Base `{comparison['base_revision']}` → head `{comparison['head_revision']}`.",
        "",
        "| Corpus | Role | Findings (base → head, Δ) | Analyzed / broken TUs | Elapsed (base → head, Δ) | Peak RSS (base → head, Δ) | Fingerprints + / - |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for name in CORPORA:
        row = comparison["corpora"][name]
        lines.append(
            "| `%(name)s` | %(kind)s | %(bf)d → %(hf)d (%(fd)s) | "
            "%(ba)d/%(bb)d → %(ha)d/%(hb)d | %(be)dms → %(he)dms (%(ep)s) | "
            "%(br)s → %(hr)s KiB (%(rp)s) | +%(added)d / -%(removed)d |" % {
                "name": name, "kind": row["kind"],
                "bf": row["base_findings"], "hf": row["head_findings"],
                "fd": delta(row["finding_delta"]),
                "ba": row["base_analyzed_tus"], "ha": row["head_analyzed_tus"],
                "bb": row["base_broken_tus"],
                "hb": row["head_broken_tus"],
                "be": row["base_elapsed_ms"], "he": row["head_elapsed_ms"],
                "ep": row["elapsed_delta_percent"],
                "br": row["base_peak_rss_kb"] or "n/a",
                "hr": row["head_peak_rss_kb"] or "n/a",
                "rp": row["rss_delta_percent"],
                "added": sum(row["fingerprints_added"].values()),
                "removed": sum(row["fingerprints_removed"].values()),
            }
        )
    lines.extend(["", "### Per-rule finding deltas", ""])
    if comparison["rule_finding_deltas"]:
        lines.extend([
            "| Rule | Clean | Defective | Real repository |",
            "|---|---:|---:|---:|",
        ])
        for rule, values in comparison["rule_finding_deltas"].items():
            lines.append(
                f"| `{rule}` | {delta(values.get('clean', 0))} | "
                f"{delta(values.get('defective', 0))} | "
                f"{delta(values.get('real_repo', 0))} |"
            )
    else:
        lines.append("No rule-level finding changes.")
    lines.extend(["", f"**Measurement gate: {comparison['gate'].upper()}**"])
    for failure in comparison["failures"]:
        lines.append(f"- {failure}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--head", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()

    base = json.loads(args.base.read_text(encoding="utf-8"))
    head = json.loads(args.head.read_text(encoding="utf-8"))
    comparison, failures = compare(base, head)
    args.json_output.write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.markdown_output.write_text(render(comparison), encoding="utf-8")
    print(
        f"MEASUREMENT_COMPARE_OK gate={comparison['gate']} "
        f"corpora={len(CORPORA)} rules={len(comparison['rule_finding_deltas'])}"
    )
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
