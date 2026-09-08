#!/usr/bin/env python3
"""Actual CLI vs checked-in local composite shell steps, without network/upload.

This is explicitly NOT a hosted GitHub Actions run or a container qualification.
Use a trusted artifact. The normal native-process trust boundary still applies.
Every invocation writes new evidence and refuses an existing output directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess

from action_acquire import digest_value
from action_run import child_environment, require, validate


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (("clean", "clean", 0, []), ("blocking", "blocking", 1, []),
             ("report-only", "report-only", 0, []), ("incomplete", "incomplete", 2, []),
             ("partial-accepted", "incomplete", 0, ["--accept-partial-coverage"]),
             ("recovery-accepted", "incomplete", 0, ["--analyze-broken-tus"]))


def write_json(path, value):
    with path.open("x") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")


def step_script(name):
    text = (ROOT / "action.yml").read_text()
    marker = "    - name: " + name + "\n"
    require(text.count(marker) == 1, "missing/ambiguous composite step")
    block = text.split(marker, 1)[1].split("    - name:", 1)[0]
    lines = block.split("      run: |\n", 1)[1].splitlines()
    require(all(not line.strip() or line.startswith("        ") for line in lines), "unexpected step layout")
    return "\n".join(line[8:] for line in lines) + "\n"


def run(arguments, folder, environment, cwd):
    folder.mkdir()
    write_json(folder / "command.json", {"argv": arguments, "cwd": str(cwd)})
    with (folder / "stdout").open("x") as stdout, (folder / "stderr").open("x") as stderr:
        process = subprocess.Popen(arguments, cwd=cwd, env=environment, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            raise RuntimeError("bounded smoke timed out")
    write_json(folder / "process.json", {"exit_code": code})
    return code


def fixtures(root):
    root.mkdir()
    cases = {
        "clean": {"answer.c": "#include <stddef.h>\nsize_t answer_c(void) { return sizeof(int); }\n",
                  "answer.cpp": "#include <stddef.h>\nsize_t answer_cpp() { return sizeof(long); }\n"},
        "blocking": {"answer.c": "#include <stddef.h>\nint answer_c(void) { int *p = 0; return *p; }\n",
                     "answer.cpp": "#include <stddef.h>\nint answer_cpp() { int zero = 0; return 1 / zero; }\n"},
        "report-only": {"bounds.cpp": "int bounds() { int a[2] = {1,2}; return a[3]; }\n"},
        "incomplete": {"safe.cpp": "int f() { return 1; }\n", "broken.cpp": "int g() { return undeclared; }\n"},
    }
    for scenario, files in cases.items():
        folder = root / scenario
        folder.mkdir()
        commands = []
        for name, content in files.items():
            path = folder / name
            with path.open("x") as output:
                output.write(content)
            commands.append({"directory": str(folder), "file": str(path),
                             "arguments": ["clang-20" if name.endswith(".c") else "clang++-20", "-c", str(path)]})
        write_json(folder / "compile_commands.json", commands)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    digest = digest_value(args.sha256)
    output = args.out.absolute()
    output.mkdir()
    runner = output / "runner"
    runner.mkdir()
    fixtures(output / "fixtures")
    environment = child_environment(runner)
    environment.update(GITHUB_ACTION_PATH=str(ROOT), RUNNER_TEMP=str(runner),
                       GITHUB_PATH=str(output / "github-path"), INPUT_ARTIFACT_PATH=str(args.artifact.absolute()),
                       INPUT_ARTIFACT_SHA256=digest, INPUT_VERSION="", INPUT_GATE="error", INPUT_UPLOAD_SARIF="false",
                       INPUT_SARIF_PATH=str(output / "unused.sarif"))
    shell = ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c"]
    for name, folder in (("Validate action inputs", "validate"), ("Install local CodeSkeptic artifact", "install")):
        require(run([*shell, step_script(name)], output / folder, environment, output) == 0, name + " failed")
    paths = (output / "github-path").read_text().splitlines()
    require(len(paths) == 1, "expected one installed binary directory")
    binary = Path(paths[0]) / "codeskeptic"
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    environment["PATH"] = str(binary.parent) + os.pathsep + environment["PATH"]
    require(run([str(binary), "--version"], output / "version", environment, output) == 0, "binary version failed")
    version = (output / "version/stdout").read_text().strip().removeprefix("CodeSkeptic ")
    records = []
    for name, source_name, expected, extra in SCENARIOS:
        folder = output / name
        folder.mkdir()
        source = output / "fixtures" / source_name
        native = folder / "cli.sarif"
        report = folder / "action.sarif"
        common = [str(source), "--build-path", str(source), "--lang", "en", *extra]
        native_code = run([str(binary), *common, "--sarif", str(native)], folder / "cli", child_environment(runner), output)
        action_environment = dict(environment, INPUT_PATH=str(source), INPUT_BUILD_PATH=str(source), INPUT_SARIF_PATH=str(report),
                                  INPUT_EXTRA_ARGS=shlex.join(["--lang", "en", *extra]), INPUT_TIMEOUT="60",
                                  GITHUB_OUTPUT=str(folder / "github-output"))
        action_code = run([*shell, step_script("Analyze")], folder / "action", action_environment, output)
        require(native_code == action_code == expected, name + " process parity failed")
        native_document, action_document = json.loads(native.read_text()), json.loads(report.read_text())
        validate(native_document, native_code, version)
        validate(action_document, action_code, version)
        require(native_document == action_document, name + " full SARIF parity failed")
        require((folder / "github-output").read_text() == f"exit-code={expected}\nsarif-valid=true\n", "Action outputs mismatch")
        records.append({"scenario": name, "cli_exit": native_code, "action_exit": action_code,
                        "sarif_equal": True, "sarif_sha256": hashlib.sha256(report.read_bytes()).hexdigest()})
    # Literal gate=error parity above; separately measure report-only mapping.
    folder = output / "report-only-gate"
    folder.mkdir()
    source = output / "fixtures/blocking"
    gate_environment = dict(environment, INPUT_PATH=str(source), INPUT_BUILD_PATH=str(source), INPUT_GATE="report-only",
                            INPUT_SARIF_PATH=str(folder / "action.sarif"), INPUT_EXTRA_ARGS="--lang en", INPUT_TIMEOUT="60",
                            GITHUB_OUTPUT=str(folder / "github-output"))
    require(run([*shell, step_script("Analyze")], folder / "action", gate_environment, output) == 0, "report-only gate failed")
    require((folder / "github-output").read_text() == "exit-code=1\nsarif-valid=true\n", "raw findings verdict was lost")
    require(json.loads((folder / "action.sarif").read_text()) == json.loads((output / "blocking/cli.sarif").read_text()), "report-only gate altered SARIF")
    write_json(output / "result.json", {"schema": "codeskeptic-local-action-smoke/v1", "profile": "local-composite-shell-steps",
                                       "hosted_action": False, "container_qualified": False, "artifact_sha256": digest,
                                       "binary_sha256": binary_hash, "version": version, "scenarios": records,
                                       "report_only_step_exit": 0, "report_only_analyzer_exit": 1})
    print("LOCAL_ACTION_SMOKE_OK scenarios=6 scans=13 full_SARIF_parity=true hosted=false container=false")


if __name__ == "__main__":
    main()
