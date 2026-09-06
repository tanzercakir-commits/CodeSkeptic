#!/usr/bin/env python3
"""Bounded, offline frontend/CFG qualification, not a product worker system.

Each case uses the real CLI and one exact compile command in a fresh directory.
Exit 0 means the *qualification* expectations passed, not that every analyzed
input was clean or complete. Expected compiler-limit rejection stays incomplete
in the report. Unexpected timeout/crash/missing evidence always fails the matrix.
POSIX timeouts kill/reap the owned process group; on Windows only the direct
analyzer is managed. Portable product worker/resource policy belongs to CH04.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

CORPUS = Path(__file__).resolve().parents[1] / "tests" / "stress_corpus"
REPORT_LIMIT = 4 * 1024 * 1024
LOG_LIMIT = 64 * 1024
EVIDENCE_FLAGS = ("no_inputs", "no_rules", "tool_failed", "summary_load_failed",
                  "summary_stale", "summary_save_failed", "baseline_load_failed",
                  "baseline_write_failed", "baseline_recorded", "report_write_failed")


def cases():
    result = []
    for stem, rule, function in (("templates", "null-deref", "template_stress"),
                                 ("macros", "div-by-zero", "macro_stress"),
                                 ("high_cfg", "null-deref", "cfg_stress")):
        for bug in (False, True):
            result.append({"id": stem + ("-seeded" if bug else "-safe"),
                           "source": str(CORPUS / (stem + ".cpp")),
                           "flags": ["-std=c++17", "-DSTRESS_BUG=" + str(int(bug))],
                           "expected_exit": int(bug),
                           "expected_diagnostics": [[rule, function]] if bug else []})
    result.append({"id": "template-depth-limit", "source": str(CORPUS / "templates.cpp"),
                   "flags": ["-std=c++17", "-DSTRESS_BUG=0", "-ftemplate-depth=16"],
                   "expected_exit": 2, "expected_reason": "broken_translation_unit", "expected_diagnostics": [],
                   "expected_source_status": "skipped",
                   "stderr_contains": "recursive template instantiation exceeded maximum depth"})
    return result


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def exact(value, expected):
    return type(value) is type(expected) and value == expected


def pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("non-finite JSON constant: " + value)


def finite_float(value):
    number = float(value)
    require(math.isfinite(number), "non-finite JSON number")
    return number


def validate_report(report, source, exit_code):
    """Validate the exact single-command profile; never infer clean from exit 0."""
    require(isinstance(report, dict) and report.get("tool") == "CodeSkeptic", "wrong report tool")
    require(type(report.get("exit_code")) is int and report["exit_code"] == exit_code,
            "process/report exit mismatch")
    require(exit_code in (0, 1, 2), "unexpected process exit")
    complete = exit_code != 2
    require(exact(report.get("complete"), complete), "top-level completeness mismatch")
    coverage = report.get("coverage")
    require(isinstance(coverage, dict) and coverage.get("schema") == "codeskeptic-source-coverage/v1",
            "missing coverage schema")
    require(exact(coverage.get("complete"), complete), "coverage completeness mismatch")
    for flag in ("accept_partial_coverage", "analyze_broken_tus"):
        require(exact(coverage.get(flag), False), "unexpected coverage opt-in")
    sources = coverage.get("sources")
    require(isinstance(sources, list) and len(sources) == 1 and isinstance(sources[0], dict),
            "expected one requested source")
    row = sources[0]
    require(row.get("file") == str(source), "wrong source identity")
    status = row.get("status")
    require(status in ("analyzed", "skipped", "failed"), "invalid source status")
    require(isinstance(row.get("reason"), str) and bool(row["reason"]), "missing source reason")
    require(row.get("prepass") == {"status": "not_requested", "reason": "", "recovery_commands": 0}
            and type(row["prepass"].get("recovery_commands")) is int, "unexpected prepass")
    expected_counts = {"attempted_tus": 1, "analyzed_tus": int(status == "analyzed"),
                       "skipped_tus": int(status == "skipped"), "broken_tus": int(status == "skipped"),
                       "failed_tus": int(status == "failed"), "recovery_tus": 0,
                       "attempted_commands": 1, "analyzed_commands": int(status == "analyzed"),
                       "skipped_commands": int(status == "skipped"), "failed_commands": int(status == "failed"),
                       "incomplete_functions": 0}
    for name, value in expected_counts.items():
        require(exact(coverage.get(name), value), "coverage counter mismatch: " + name)
    for name, value in {"commands": 1, "analyzed_commands": int(status == "analyzed"),
                        "skipped_commands": int(status == "skipped"),
                        "failed_commands": int(status == "failed"), "recovery_commands": 0}.items():
        require(exact(row.get(name), value), "source counter mismatch: " + name)
    require((status == "analyzed") == complete, "source completeness mismatch")
    if complete:
        require(row["reason"] == "analyzed", "unexpected complete source reason")
    flags = report.get("evidence")
    require(isinstance(flags, dict) and all(type(flags.get(f)) is bool for f in EVIDENCE_FLAGS),
            "invalid evidence flags")
    require(not any(flags.values()), "unexpected evidence failure")
    diagnostics = report.get("diagnostics")
    require(isinstance(diagnostics, list) and exact(report.get("total"), len(diagnostics)),
            "diagnostic count mismatch")
    for diag in diagnostics:
        require(isinstance(diag, dict) and diag.get("file") == str(source)
                and isinstance(diag.get("rule_id"), str) and isinstance(diag.get("function"), str)
                and type(diag.get("blocks_verdict")) is bool, "invalid diagnostic identity")
    blocking = sum(d["blocks_verdict"] for d in diagnostics)
    counts = report.get("finding_counts")
    require(isinstance(counts, dict) and all(exact(counts.get(k), v) for k, v in
            {"total": len(diagnostics), "blocking": blocking, "report_only": len(diagnostics) - blocking}.items()),
            "finding counts mismatch")
    if complete:
        require(exit_code == int(blocking > 0), "blocking verdict mismatch")
        expected_status = "findings" if blocking else "report-only" if diagnostics else "clean"
        require(report.get("status") == expected_status, "complete status mismatch")
    else:
        require(report.get("status") == "failed", "single skipped/failed TU cannot yield a verdict")
    return coverage


def run_process(command, cwd, timeout):
    """Wait finitely, retaining bounded log excerpts and the real return code."""
    require(math.isfinite(timeout) and 0 < timeout <= 60, "timeout must be finite and in (0, 60]")
    result = {"returncode": None, "reason": "", "stdout": "", "stderr": ""}
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr,
                                       start_new_session=(os.name == "posix"))
        except OSError as error:
            result.update(reason="launch_error", stderr=str(error))
        else:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result["reason"] = "timeout"
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
            result["returncode"] = process.returncode
            if process.returncode < 0 and not result["reason"]:
                result["reason"] = "signal"
            for label, stream in (("stdout", stdout), ("stderr", stderr)):
                size = stream.seek(0, os.SEEK_END)
                stream.seek(max(0, size - LOG_LIMIT))
                result[label] = stream.read(LOG_LIMIT).decode("utf-8", errors="replace")
                result[label + "_truncated"] = size > LOG_LIMIT
    result["elapsed_seconds"] = round(time.monotonic() - started, 6)
    return result


def run_case(binary, case, timeout=10):
    source = Path(case["source"]).resolve(strict=True)
    result = {"id": case["id"], "source": str(source),
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "timeout_seconds": timeout, "expectation": case,
              "qualification_passed": False, "coverage_complete": False}
    with tempfile.TemporaryDirectory(prefix="codeskeptic-stress-") as temporary:
        directory = Path(temporary)
        report_path = directory / "report.json"
        entry = {"directory": str(source.parent), "file": str(source),
                 "arguments": ["clang++", *case["flags"], "-c", str(source)]}
        (directory / "compile_commands.json").write_text(json.dumps([entry]), encoding="utf-8")
        command = [str(binary), "--source", str(source), "--build-path", temporary,
                   "--json", str(report_path), "--lang", "en"]
        result.update(command=command, compile_command=entry)
        result.update(run_process(command, temporary, timeout))
        if result["reason"]:
            return result
        try:
            require(report_path.is_file(), "missing analyzer report")
            require(report_path.stat().st_size <= REPORT_LIMIT, "oversized analyzer report")
            raw = report_path.read_bytes()
            result["report_sha256"] = hashlib.sha256(raw).hexdigest()
            report = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_no_duplicates,
                                parse_constant=invalid_constant, parse_float=finite_float)
            result["analyzer_report"] = report
            coverage = validate_report(report, source, result["returncode"])
            result["coverage_complete"] = coverage["complete"]
            result["reason"] = "analyzed" if coverage["complete"] else coverage["sources"][0]["reason"]
            require(result["returncode"] == case["expected_exit"], "unexpected case exit")
            actual = sorted([d["rule_id"], d["function"]] for d in report["diagnostics"])
            require(actual == sorted(case["expected_diagnostics"]), "unexpected fixture diagnostics")
            if case["expected_exit"] == 2:
                require(coverage["sources"][0]["status"] == case["expected_source_status"],
                        "unexpected incomplete source classification")
                require(result["reason"] == case["expected_reason"], "unexpected incomplete reason")
                require(case["stderr_contains"] in result["stderr"], "expected compiler diagnostic missing")
            result["qualification_passed"] = True
        except (OSError, ValueError, RecursionError) as error:
            # Preserve source reasons/raw analyzer coverage separately; validation
            # failure must never leave an apparently trustworthy complete row.
            result["reason"] = "invalid_or_unexpected_evidence"
            result["detail"] = str(error)
            result["coverage_complete"] = False
    return result


def run_matrix(binary, selected, timeout=10):
    binary = Path(binary).resolve(strict=True)
    with binary.open("rb") as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    rows = [run_case(binary, case, timeout) for case in selected]
    return {"schema": "codeskeptic-stress-matrix/v1", "binary": str(binary), "binary_sha256": digest,
            "qualification_passed": bool(rows) and all(row["qualification_passed"] for row in rows),
            "coverage_complete": bool(rows) and all(row["coverage_complete"] for row in rows), "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    try:
        require(math.isfinite(args.timeout) and 0 < args.timeout <= 60, "invalid timeout")
        result = run_matrix(args.binary, cases(), args.timeout)
        text = json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
        if args.out:
            # Evidence is append-only by filename: refuse to replace a prior run.
            with args.out.open("x", encoding="utf-8") as stream:
                stream.write(text)
        for row in result["cases"]:
            print(f"{row['id']}: {'PASS' if row['qualification_passed'] else 'FAIL'} "
                  f"exit={row['returncode']} coverage_complete={row['coverage_complete']} "
                  f"reason={row['reason']} {row.get('detail', '')}")
        if not args.out:
            print(text)
        return 0 if result["qualification_passed"] else 1
    except (OSError, ValueError) as error:
        print(f"stress matrix input/output error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
