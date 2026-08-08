#!/usr/bin/env python3
"""Run the clean, defective, and real-repository measurement corpora."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path


ASCII_SPACE = " \t\r\n\v\f"
FINGERPRINT = re.compile(r"csf1-[0-9a-f]{16}")


def fail(message: str) -> None:
    print(f"MEASUREMENT_LAB_FAIL {message}", file=sys.stderr)
    raise SystemExit(1)


def portable_path_tail(path: str) -> str:
    components = [part for part in path.replace("\\", "/").split("/") if part]
    return "/".join(components[-3:])


def source_statement(value: str) -> str:
    result: list[str] = []
    in_single = in_double = escaped = False
    for character in value:
        if not in_single and not in_double and character in ASCII_SPACE:
            continue
        result.append(character)
        if escaped:
            escaped = False
            continue
        if (in_single or in_double) and character == "\\":
            escaped = True
            continue
        if not in_double and character == "'":
            in_single = not in_single
        elif not in_single and character == '"':
            in_double = not in_double
    return "".join(result)


def fnv1a64(value: str) -> str:
    fingerprint = 0xCBF29CE484222325
    for byte in value.encode("utf-8"):
        fingerprint ^= byte
        fingerprint = (fingerprint * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{fingerprint:016x}"


class FingerprintOracle:
    def __init__(self) -> None:
        self.lines: dict[str, list[str]] = {}

    def source_line(self, path: str, line: int) -> str:
        if path not in self.lines:
            try:
                self.lines[path] = Path(path).read_text(
                    encoding="utf-8", errors="surrogateescape"
                ).splitlines()
            except OSError:
                self.lines[path] = []
        lines = self.lines[path]
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def fingerprint(self, diagnostic: dict) -> str:
        payload = "\n".join(
            (
                "csf1",
                diagnostic.get("rule_id") or diagnostic.get("rule") or "",
                portable_path_tail(diagnostic.get("file", "")),
                diagnostic.get("function", ""),
                source_statement(
                    self.source_line(
                        diagnostic.get("file", ""), int(diagnostic.get("line", 0))
                    )
                ),
            )
        )
        return "csf1-" + fnv1a64(payload)


def parse_time_file(path: Path) -> int | None:
    if not path.is_file():
        return None
    match = re.search(
        r"Maximum resident set size \(kbytes\):\s*(\d+)",
        path.read_text(encoding="utf-8", errors="replace"),
    )
    return int(match.group(1)) if match else None


def run_analyzer(binary: Path, arguments: list[str], report: Path) -> tuple[dict, int, int | None]:
    command = [str(binary), *arguments, "--json", str(report)]
    time_file = report.with_suffix(".time.txt")
    if Path("/usr/bin/time").is_file():
        command = [
            "/usr/bin/time", "-v", "-o", str(time_file), "--", *command
        ]
    started = time.perf_counter_ns()
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    elapsed_ms = round((time.perf_counter_ns() - started) / 1_000_000)
    if result.returncode not in (0, 1):
        fail(
            f"analyzer exit={result.returncode} command={arguments!r} "
            f"stderr_tail={result.stderr[-2000:]!r}"
        )
    if not report.is_file():
        fail(f"analyzer produced no JSON report: {report}")
    payload = json.loads(report.read_text(encoding="utf-8"))
    if payload.get("exit_code") != result.returncode:
        fail(
            f"process/report exit mismatch process={result.returncode} "
            f"report={payload.get('exit_code')}"
        )
    return payload, elapsed_ms, parse_time_file(time_file)


def new_corpus(kind: str) -> dict:
    return {
        "kind": kind,
        "cases": 0,
        "caught_cases": 0,
        "floor_violations": 0,
        "findings": 0,
        "blocking_findings": 0,
        "report_only_findings": 0,
        "rules": Counter(),
        "fingerprints": Counter(),
        "coverage": {
            "attempted_tus": 0,
            "analyzed_tus": 0,
            "broken_tus": 0,
            "incomplete_functions": 0,
        },
        "performance": {"elapsed_ms": 0, "peak_rss_kb": None},
        "unavailable_runs": 0,
        "case_results": [],
    }


def add_report(
    corpus: dict,
    payload: dict,
    elapsed_ms: int,
    peak_rss_kb: int | None,
    case_name: str,
    floor: int,
    oracle: FingerprintOracle,
) -> None:
    corpus["cases"] += 1
    diagnostics = payload.get("diagnostics", [])
    finding_count = len(diagnostics)
    corpus["findings"] += finding_count
    if finding_count > 0:
        corpus["caught_cases"] += 1
    if finding_count < floor:
        corpus["floor_violations"] += 1
    if not payload.get("complete", False):
        corpus["unavailable_runs"] += 1

    counts = payload.get("finding_counts", {})
    corpus["blocking_findings"] += int(counts.get("blocking", 0))
    corpus["report_only_findings"] += int(counts.get("report_only", 0))
    for key in corpus["coverage"]:
        corpus["coverage"][key] += int(payload.get("coverage", {}).get(key, 0))
    corpus["performance"]["elapsed_ms"] += elapsed_ms
    if peak_rss_kb is not None:
        previous = corpus["performance"]["peak_rss_kb"] or 0
        corpus["performance"]["peak_rss_kb"] = max(previous, peak_rss_kb)

    case_fingerprints: list[str] = []
    for diagnostic in diagnostics:
        rule = diagnostic.get("rule_id") or diagnostic.get("rule") or "?"
        corpus["rules"][rule] += 1
        computed = oracle.fingerprint(diagnostic)
        emitted = diagnostic.get("fingerprint")
        if emitted is not None:
            if not FINGERPRINT.fullmatch(emitted):
                fail(f"malformed fingerprint {emitted!r} in {case_name}")
            if emitted != computed:
                fail(
                    f"fingerprint parity mismatch in {case_name}: "
                    f"emitted={emitted} computed={computed}"
                )
        corpus["fingerprints"][computed] += 1
        case_fingerprints.append(computed)
    corpus["case_results"].append(
        {
            "case": case_name,
            "floor": floor,
            "findings": finding_count,
            "complete": bool(payload.get("complete", False)),
            "fingerprints": sorted(case_fingerprints),
        }
    )


def finalize(corpus: dict) -> dict:
    corpus["rules"] = dict(sorted(corpus["rules"].items()))
    corpus["fingerprints"] = dict(sorted(corpus["fingerprints"].items()))
    corpus["case_results"].sort(key=lambda item: item["case"])
    return corpus


def write_compile_database(paths: list[Path], output: Path) -> None:
    entries = [
        {
            "directory": str(path.parent),
            "file": str(path),
            "command": f"clang-20 -std=gnu11 -c {path}",
        }
        for path in paths
    ]
    output.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--build-path", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    binary = args.binary.resolve()
    repo = args.repo_root.resolve()
    build = args.build_path.resolve()
    if not binary.is_file() or not repo.is_dir() or not build.is_dir():
        fail("binary, repo root, or build path is missing")

    manifest = repo / "tests" / "thesis_corpus" / "thesis_expected.txt"
    cases: list[tuple[Path, str, int]] = []
    for line_no, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3 or parts[1] not in {"CLEAN", "BUG"}:
            fail(f"invalid thesis manifest line {line_no}: {raw!r}")
        source = (manifest.parent / parts[0]).resolve()
        if not source.is_file():
            fail(f"missing thesis source: {source}")
        cases.append((source, parts[1], int(parts[2])))

    clean = new_corpus("clean")
    defective = new_corpus("defective")
    real_repo = new_corpus("real-repository")
    oracle = FingerprintOracle()
    with tempfile.TemporaryDirectory(prefix="codeskeptic-measure-") as temporary:
        temp = Path(temporary)
        write_compile_database([source for source, _, _ in cases], temp / "compile_commands.json")
        for index, (source, role, floor) in enumerate(cases):
            report = temp / f"thesis-{index}.json"
            payload, elapsed, peak = run_analyzer(
                binary,
                [str(source), "--build-path", str(temp)],
                report,
            )
            add_report(
                clean if role == "CLEAN" else defective,
                payload,
                elapsed,
                peak,
                source.name,
                floor,
                oracle,
            )

        report = temp / "real-repository.json"
        payload, elapsed, peak = run_analyzer(
            binary,
            [
                str(repo / "src"),
                "--build-path", str(build),
                "--policy", "no-absolute-paths",
            ],
            report,
        )
        add_report(
            real_repo, payload, elapsed, peak, "codeskeptic/src", 0, oracle
        )

    version = subprocess.run(
        [str(binary), "--version"], check=False, capture_output=True, text=True
    ).stdout.strip()
    corpora = {
        "clean": finalize(clean),
        "defective": finalize(defective),
        "real_repo": finalize(real_repo),
    }
    payload = {
        "schema_version": 1,
        "revision": args.revision,
        "analyzer_version": version,
        "corpora": corpora,
        "totals": {
            "elapsed_ms": sum(
                corpus["performance"]["elapsed_ms"] for corpus in corpora.values()
            ),
            "peak_rss_kb": max(
                (corpus["performance"]["peak_rss_kb"] or 0)
                for corpus in corpora.values()
            ) or None,
            "attempted_tus": sum(
                corpus["coverage"]["attempted_tus"] for corpus in corpora.values()
            ),
            "analyzed_tus": sum(
                corpus["coverage"]["analyzed_tus"] for corpus in corpora.values()
            ),
            "broken_tus": sum(
                corpus["coverage"]["broken_tus"] for corpus in corpora.values()
            ),
            "findings": sum(corpus["findings"] for corpus in corpora.values()),
        },
    }
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        "MEASUREMENT_LAB_OK "
        f"clean={clean['cases']} defective={defective['cases']} "
        f"real_repo={real_repo['cases']} attempted={payload['totals']['attempted_tus']} "
        f"analyzed={payload['totals']['analyzed_tus']} broken={payload['totals']['broken_tus']}"
    )


if __name__ == "__main__":
    main()
