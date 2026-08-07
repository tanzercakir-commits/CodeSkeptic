#!/usr/bin/env python3
"""Fail-closed validator for the canonical real-world replay ledger."""

from __future__ import annotations

import re
import sys
from pathlib import Path


EXPECTED_PROJECTS = {"libgit2", "rtp2httpd"}
SHA40 = re.compile(r"[0-9a-f]{40}")
PROJECT = re.compile(r"[a-z0-9][a-z0-9-]*")


def fail(message: str) -> None:
    print(f"REALWORLD_LEDGER_FAIL {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_nonnegative(value: str, field: str, line_no: int) -> int:
    if not value.isascii() or not value.isdigit():
        fail(f"line={line_no} field={field} expected=nonnegative-int got={value!r}")
    return int(value)


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).with_name(
        "realworld_expected.txt"
    )
    if len(sys.argv) > 2:
        fail("usage: check_realworld_ledger.py [ledger-path]")
    if not path.is_file():
        fail(f"missing={path}")

    seen: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 8:
            fail(f"line={line_no} expected_fields=8 got={len(fields)}")
        project, revision, label, tus_s, findings_s, exit_s, actionable_s, fp_s = fields
        if not PROJECT.fullmatch(project):
            fail(f"line={line_no} invalid_project={project!r}")
        if project in seen:
            fail(f"line={line_no} duplicate_project={project}")
        seen.add(project)
        if not SHA40.fullmatch(revision):
            fail(f"line={line_no} project={project} invalid_revision={revision!r}")
        if not label or any(ch.isspace() for ch in label):
            fail(f"line={line_no} project={project} invalid_label={label!r}")

        tus = parse_nonnegative(tus_s, "tus", line_no)
        findings = parse_nonnegative(findings_s, "findings", line_no)
        exit_code = parse_nonnegative(exit_s, "exit", line_no)
        if tus == 0:
            fail(f"line={line_no} project={project} tus_must_be_positive")
        if exit_code not in (0, 1):
            fail(f"line={line_no} project={project} unavailable_verdict_exit={exit_code}")
        if (findings == 0) != (exit_code == 0):
            fail(
                f"line={line_no} project={project} findings={findings} "
                f"contradict_exit={exit_code}"
            )

        if (actionable_s == "-") != (fp_s == "-"):
            fail(f"line={line_no} project={project} partial_triage_partition")
        if actionable_s != "-":
            actionable = parse_nonnegative(actionable_s, "actionable", line_no)
            context_fp = parse_nonnegative(fp_s, "context_fp", line_no)
            if actionable + context_fp != findings:
                fail(
                    f"line={line_no} project={project} triage_total="
                    f"{actionable + context_fp} findings={findings}"
                )

    if seen != EXPECTED_PROJECTS:
        fail(
            "project_set expected="
            f"{','.join(sorted(EXPECTED_PROJECTS))} got={','.join(sorted(seen))}"
        )
    print(f"REALWORLD_LEDGER_OK projects={len(seen)} path={path.as_posix()}")


if __name__ == "__main__":
    main()
