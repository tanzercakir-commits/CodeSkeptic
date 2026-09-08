#!/usr/bin/env python3
"""Execute one scan and publish only a fresh, process-consistent SARIF artifact.

No download/upload occurs here. The trusted analyzer receives a minimal process
environment; native execution is not an OS sandbox. Container isolation is a
separate execution profile. Findings may be report-only; invalid evidence may not.
"""
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

from action_args import parse


class ActionError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ActionError(message)


def number(value):
    require(type(value) is int and value >= 0, "invalid nonnegative integer")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def finite_number(text):
    value = float(text)
    require(math.isfinite(value), "non-finite JSON number")
    return value


def invalid_constant(text):
    raise ActionError("invalid JSON constant: " + text)


def object_value(value):
    require(type(value) is dict, "expected JSON object")
    return value


def array_value(value):
    require(type(value) is list, "expected JSON array")
    return value


def validate(document, code, version):
    require(code in (0, 1, 2), "analyzer did not return a supported process verdict")
    object_value(document)
    require(document["version"] == "2.1.0" and len(array_value(document["runs"])) == 1, "invalid SARIF run")
    run = object_value(document["runs"][0])
    report = object_value(object_value(run["properties"])["codeskeptic/report"])
    require(report["schema"] == "codeskeptic-report/v1" and report["tool"] == "CodeSkeptic", "unsupported report schema/tool")
    require(run["tool"]["driver"]["name"] == "CodeSkeptic"
            and run["tool"]["driver"]["version"] == report["tool_version"] == version, "tool version mismatch")
    require(number(report["exit_code"]) == code, "process/report exit mismatch")
    require(report["complete"] is (code != 2), "process/report completeness mismatch")
    require(len(array_value(run["invocations"])) == 1, "missing or ambiguous invocation")
    invocation = object_value(run["invocations"][0])
    properties = object_value(invocation["properties"])
    require(invocation["executionSuccessful"] is report["complete"], "invocation completeness mismatch")
    require(number(properties["codeskeptic/exitCode"]) == code
            and properties["codeskeptic/status"] == report["status"], "invocation verdict mismatch")
    counts = object_value(report["finding_counts"])
    results = array_value(run["results"])
    total, blocking, report_only = (number(counts[key]) for key in ("total", "blocking", "report_only"))
    require(total == blocking + report_only == number(report["total"]) == len(results), "finding count mismatch")
    actual_blocking = 0
    for finding in results:
        object_value(finding)
        require(type(finding["ruleId"]) is str and bool(finding["ruleId"]), "invalid finding rule")
        require(type(object_value(finding["message"])["text"]) is str, "invalid finding message")
        require(finding["level"] in ("none", "note", "warning", "error"), "invalid finding level")
        blocks = object_value(finding["properties"])["codeskeptic/blocksVerdict"]
        require(type(blocks) is bool, "invalid finding verdict")
        actual_blocking += blocks
    require(actual_blocking == blocking, "native finding verdict count mismatch")
    require(number(properties["codeskeptic/blockingFindings"]) == blocking
            and number(properties["codeskeptic/reportOnlyFindings"]) == report_only, "invocation counts mismatch")
    coverage = object_value(properties["codeskeptic/coverage"])
    require(coverage["schema"] == "codeskeptic-source-coverage/v1", "unsupported coverage schema")
    for flag in ("complete", "accept_partial_coverage", "analyze_broken_tus"):
        require(type(coverage[flag]) is bool, "invalid coverage flag")
    attempted, analyzed, broken, failed = (number(coverage[key]) for key in
                                          ("attempted_tus", "analyzed_tus", "broken_tus", "failed_tus"))
    rows = array_value(coverage["sources"])
    require(attempted == analyzed + broken + failed == len(rows), "coverage counts mismatch")
    command_fields = ("commands", "analyzed_commands", "skipped_commands", "failed_commands")
    sums = dict.fromkeys(command_fields, 0)
    observed_recovery = 0
    for row in rows:
        object_value(row)
        require(type(row["file"]) is str and bool(row["file"]) and type(row["reason"]) is str, "invalid coverage source identity/reason")
        for key in command_fields:
            sums[key] += number(row[key])
        require(row["commands"] == row["analyzed_commands"] + row["skipped_commands"] + row["failed_commands"], "source command partition mismatch")
        require(number(row["recovery_commands"]) <= row["analyzed_commands"], "source recovery count mismatch")
        prepass = object_value(row["prepass"])
        require(prepass["status"] in ("not_requested", "analyzed", "skipped", "failed")
                and type(prepass["reason"]) is str, "invalid prepass status/reason")
        require(number(prepass["recovery_commands"]) <= row["commands"], "prepass recovery count mismatch")
        require(prepass["status"] != "not_requested" or (not prepass["reason"] and prepass["recovery_commands"] == 0), "unrequested prepass has evidence")
        recovered = bool(row["recovery_commands"] or prepass["recovery_commands"])
        require(not recovered or coverage["analyze_broken_tus"], "recovery requires explicit opt-in")
        observed_recovery += recovered
        # The summary prepass can promote status without changing second-pass
        # command counters (StaticAnalyzer.cpp). Early failures have no commands.
        expected_source_status = ("failed" if row["commands"] == 0 or row["failed_commands"] or prepass["status"] == "failed" else
                                  "skipped" if row["skipped_commands"] or prepass["status"] == "skipped" else "analyzed")
        require(row["status"] == expected_source_status, "source status/command evidence mismatch")
    for key, value in sums.items():
        aggregate_key = "attempted_commands" if key == "commands" else key
        require(number(coverage[aggregate_key]) == value, "aggregate command count mismatch")
    require(len({row["file"] for row in rows}) == attempted, "duplicate coverage source")
    for status, count in (("analyzed", analyzed), ("skipped", broken), ("failed", failed)):
        require(sum(row["status"] == status for row in rows) == count, "coverage source status mismatch")
    require(all(row["status"] in ("analyzed", "skipped", "failed") for row in rows), "unknown coverage source status")
    evidence = object_value(report["evidence"])
    flags = ("no_inputs", "no_rules", "tool_failed", "summary_load_failed", "summary_stale",
             "summary_save_failed", "baseline_load_failed", "baseline_write_failed",
             "baseline_recorded", "report_write_failed")
    require(all(type(evidence[flag]) is bool for flag in flags), "invalid evidence flag")
    recovery = number(coverage["recovery_tus"])
    incomplete_functions = number(coverage["incomplete_functions"])
    require(number(coverage["skipped_tus"]) == broken and recovery == observed_recovery, "coverage alias/count mismatch")
    for key, value in (("attemptedTUs", attempted), ("analyzedTUs", analyzed),
                       ("brokenTUs", broken), ("incompleteFunctions", incomplete_functions)):
        require(number(properties["codeskeptic/" + key]) == value, "invocation coverage counter mismatch")
    # Keep the precedence of the authored AnalysisResult.h process contract,
    # including explicit partial/recovery and baseline-recorded exceptions.
    hard_failure = (failed > 0 or (attempted > 0 and analyzed == 0 and not coverage["analyze_broken_tus"])
                    or any(evidence[key] for key in ("no_inputs", "no_rules", "tool_failed", "summary_save_failed",
                                                     "baseline_load_failed", "baseline_write_failed", "report_write_failed")))
    incomplete = (bool(broken and not coverage["analyze_broken_tus"] and not coverage["accept_partial_coverage"])
                  or incomplete_functions > 0 or evidence["summary_load_failed"] or evidence["summary_stale"])
    complete = not hard_failure and not incomplete
    require(report["complete"] is complete, "evidence/completeness mismatch")
    require(coverage["complete"] is (complete and attempted > 0 and analyzed == attempted
                                      and broken == 0 and failed == 0 and recovery == 0), "coverage completeness mismatch")
    expected_status = ("failed" if hard_failure else "incomplete" if incomplete else
                       "partial-accepted" if broken else "recovery-accepted" if recovery else
                       "recorded" if evidence["baseline_recorded"] else "findings" if blocking else
                       "report-only" if total else "clean")
    expected_code = 2 if not complete else 0 if evidence["baseline_recorded"] else int(blocking > 0)
    require(report["status"] == expected_status and code == expected_code, "evidence/verdict mismatch")
    return report


def child_environment(temporary):
    allowed = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    result.update(HOME=str(temporary), TMPDIR=str(temporary))
    return result


def execute(arguments, environment, timeout, capture=False):
    process = subprocess.Popen(arguments, env=environment, start_new_session=True,
                               stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.PIPE if capture else None, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        raise ActionError("analyzer timed out")
    if capture:
        require(process.returncode == 0, "analyzer version query failed")
    return process.returncode, stdout, stderr


def github_output(code, valid):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, "a") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "GITHUB_OUTPUT must be a regular file")
        stream.write(f"exit-code={code}\nsarif-valid={'true' if valid else 'false'}\n")


def main():
    code = 2
    valid = False
    try:
        gate = os.environ.get("INPUT_GATE", "report-only")
        require(gate in ("report-only", "error"), "invalid gate")
        source = os.environ.get("INPUT_PATH", ".")
        require(bool(source) and not source.startswith("-"), "invalid source path")
        target_value = os.environ.get("INPUT_SARIF_PATH", "codeskeptic.sarif")
        require(bool(target_value), "empty SARIF path")
        target = Path(target_value).absolute()
        require(not os.path.lexists(target), "SARIF destination exists; choose a new report path")
        require(target.parent.is_dir(), "SARIF parent directory is missing")
        binary = shutil.which("codeskeptic")
        require(binary is not None, "codeskeptic is not installed")
        extra = parse(os.environ.get("INPUT_EXTRA_ARGS", ""))
        reserved = {"--source", "--build-path", "--sarif", "--json", "--html", "--version", "--help", "--capabilities", "--doctor"}
        require(not any(argument.split("=", 1)[0] in reserved for argument in extra), "extra-args may not override source, report or execution mode")
        timeout = int(os.environ.get("INPUT_TIMEOUT", "300"))
        require(1 <= timeout <= 3600, "timeout must be between 1 and 3600 seconds")
        with tempfile.TemporaryDirectory(prefix=".codeskeptic-action-", dir=target.parent) as temporary:
            temporary = Path(temporary)
            environment = child_environment(temporary)
            _, identity, _ = execute([binary, "--version"], environment, 15, capture=True)
            match = re.fullmatch(r"CodeSkeptic ([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*)\n?", identity)
            require(match is not None, "invalid analyzer identity")
            artifact = temporary / "report.sarif"
            arguments = [binary, source, "--sarif", str(artifact)]
            build = os.environ.get("INPUT_BUILD_PATH", "")
            if build:
                arguments.extend(["--build-path", build])
            code, _, _ = execute([*arguments, *extra], environment, timeout)
            require(artifact.is_file() and not artifact.is_symlink(), "missing fresh regular SARIF")
            require(0 < artifact.stat().st_size <= 64 * 1024 * 1024, "SARIF size outside 1..64 MiB bound")
            document = json.loads(artifact.read_text(), object_pairs_hook=unique_object,
                                  parse_constant=invalid_constant, parse_float=finite_number)
            validate(document, code, match[1])
            os.link(artifact, target)  # exclusive, byte preserving publication
            valid = True
        github_output(code, valid)
        if code == 1 and gate == "report-only":
            print("::notice::CodeSkeptic findings retained; report-only gate")
            return 0
        return code
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError, subprocess.SubprocessError) as error:
        try:
            github_output(code, valid)
        except (OSError, ValueError):
            pass
        print("::error::CodeSkeptic action failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
