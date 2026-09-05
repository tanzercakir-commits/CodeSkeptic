#!/usr/bin/env python3
"""Explicit push checkpoint orchestration. No installs, implicit fetches or resume."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import compare_measurements as measurement
import run_realworld_campaign as campaign
import verify_regression_checkpoint as verify

ROOT = Path(__file__).resolve().parents[1]
REQUEST = "ci/regression-checkpoint.json"
ADJUDICATIONS = "ci/regression-adjudications.json"


def git(repo, *arguments):
    return subprocess.run(["git", "-C", str(repo), *arguments], check=True,
                          capture_output=True, text=True).stdout.strip()


def clean_revision(repo, revision):
    verify.require(git(repo, "rev-parse", "HEAD") == revision, "checkout SHA differs")
    verify.require(not git(repo, "status", "--porcelain", "--untracked-files=normal"), "input/source checkout is dirty")


def write_json(path, value):
    path = Path(path)
    verify.require(not path.exists() and not path.is_symlink(), f"refusing stale output: {path}")
    with path.open("xb") as stream:
        stream.write(verify.canonical(value))


def fresh_dir(path):
    path = Path(path).absolute()
    verify.require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink output/workspace")
    path.mkdir()  # Existing directory (including a broad root) is never deleted or reused.
    return path


def environment_context(lane):
    return verify.validate_context({"head_sha": os.environ.get("GITHUB_SHA"),
                                    "workflow_sha": os.environ.get("CHECKPOINT_WORKFLOW_SHA"),
                                    "run_id": os.environ.get("GITHUB_RUN_ID"),
                                    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                                    "repository": os.environ.get("GITHUB_REPOSITORY"),
                                    "ref": os.environ.get("GITHUB_REF"), "lane": lane})


def request_at_head(repo, config, context):
    clean_revision(repo, context["head_sha"])
    git(repo, "merge-base", "--is-ancestor", config["base_sha"], context["head_sha"])
    parent = git(repo, "rev-parse", "HEAD^")
    old = subprocess.run(["git", "-C", str(repo), "show", f"{parent}:{REQUEST}"],
                         capture_output=True, text=True)
    if old.returncode != 0:
        # A first introduction is eligible, but a missing parent/object is not.
        git(repo, "cat-file", "-e", f"{parent}^{{commit}}")
        return True
    prior = json.loads(old.stdout, object_pairs_hook=verify._object, parse_constant=verify._constant)
    # Ordinary ledger/new-branch pushes inherit the request unchanged. Require a
    # new request id in the FINAL candidate commit, not merely a broad push diff.
    return config != prior and config["request_id"] != prior.get("request_id")


def collect_inputs(repo, config):
    clean_revision(repo, config["inputs_sha"])
    verify.require(not git(repo, "ls-files", "--others", "--ignored", "--exclude-standard"),
                   "ignored extra files in immutable input checkout")
    manifest_path = Path(repo) / "scripts/realworld_manifest.json"
    manifest = campaign.validate_manifest(verify.load_json(manifest_path))
    verify.require(campaign.digest_json(manifest) == config["manifest_sha256"], "pinned manifest differs")
    verify.full_matrix(manifest)
    # Bind the whole common checkout, including root configuration and copied
    # profiles. Git status alone can be blinded by index ignore flags.
    tree = git(repo, "ls-tree", "-r", "-z", "--full-tree", config["inputs_sha"])
    objects = {}
    for entry in tree.split("\0"):
        if not entry:
            continue
        metadata, path = entry.split("\t", 1)
        mode, kind, oid = metadata.split()
        verify.require(kind == "blob" and mode in ("100644", "100755"), "nonregular committed input")
        objects[path] = oid
    paths = list(objects)
    verify.require(paths and len(paths) == len(set(paths)), "missing input catalog")
    files = {path: verify.file_digest(Path(repo) / path) for path in paths}
    observed = git(repo, "hash-object", "--no-filters", "--", *paths).splitlines()
    verify.require(observed == list(objects.values()), "input bytes differ from pinned Git objects")
    copies = {operation["from"] for project in manifest["projects"] for operation in project["copies"]}
    verify.require(copies <= set(files), "copied project profile is not a bound input")
    identity = {"source_sha": config["inputs_sha"], "tree_sha256": verify.json_digest(files),
                "manifest_sha256": campaign.digest_json(manifest),
                "manifest_file_sha256": verify.file_digest(manifest_path),
                "thesis_manifest_sha256": verify.file_digest(Path(repo) / "tests/thesis_corpus/thesis_expected.txt"),
                "copied_profiles": {path: files[path] for path in sorted(copies)}}
    return identity, manifest


def thesis_cases(repo):
    result = {"clean": {}, "defective": {}, "real_repo": {"codeskeptic/src": 0}}
    manifest = verify.regular(Path(repo) / "tests/thesis_corpus/thesis_expected.txt")
    seen = set()
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        verify.require(len(parts) == 3 and parts[1] in ("CLEAN", "BUG") and parts[2].isdigit(), "invalid thesis manifest")
        name, role, floor = parts[0], parts[1], int(parts[2])
        verify.require(Path(name).name == name and name.endswith(".c") and name not in seen,
                       "unsafe/duplicate thesis case")
        seen.add(name)
        verify.regular(manifest.parent / name)
        verify.require(role != "CLEAN" or floor == 0, "clean floor differs")
        result["clean" if role == "CLEAN" else "defective"][name] = floor
    verify.require(result["clean"] and result["defective"], "missing thesis cases")
    return result


def prepare_inputs(repo, workspace, config):
    inputs = workspace / "inputs"
    git(repo, "worktree", "add", "--detach", str(inputs), config["inputs_sha"])
    identity, manifest = collect_inputs(inputs, config)
    # New checkpoint orchestration cannot silently substitute altered control pins.
    verify.require(verify.file_digest(Path(repo) / "scripts/realworld_manifest.json") == identity["manifest_file_sha256"],
                   "control and input manifests differ")
    return inputs, identity, manifest


def build_analyzer(source, revision, build, llvm_prefix):
    clean_revision(source, revision)
    subprocess.run(["cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                    "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_PREFIX_PATH={llvm_prefix}",
                    "-DCODESKEPTIC_BUILD_TESTS=OFF"], check=True)
    subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True)
    clean_revision(source, revision)
    binary = build / "src/codeskeptic"
    return binary, {"source_sha": revision, "binary_sha256": verify.file_digest(binary)}


def seal_artifact(output, config, context, inputs, kind, details):
    envelope = {"schema": "codeskeptic-checkpoint-artifact/v1", "context": context,
                "config_sha256": verify.json_digest(config), "inputs": inputs, "kind": kind,
                "details": details, "files": verify.artifact_files(output)}
    write_json(Path(output) / "envelope.json", envelope)
    return envelope


def measure_pair(base_binary, head_binary, repo, build, base_sha, head_sha, output):
    """Both versions use precisely the same fixture/source root and compile DB."""
    cases = thesis_cases(repo)
    before = verify.file_digest(build / "compile_commands.json")
    bindings = {}
    for side, binary, revision in (("base", base_binary, base_sha), ("head", head_binary, head_sha)):
        binary_digest = verify.file_digest(binary)
        bindings[side] = {"source_sha": revision, "binary_sha256": binary_digest}
        subprocess.run([sys.executable, "-B", str(ROOT / "scripts/run_measurement_lab.py"),
                        "--binary", str(binary), "--repo-root", str(repo), "--build-path", str(build),
                        "--revision", revision, "--output", str(output / f"measurement-{side}.json")], check=True)
        verify.validate_measurement(verify.load_json(output / f"measurement-{side}.json"), revision, cases)
        verify.require(verify.file_digest(binary) == binary_digest, "analyzer changed during measurement")
    verify.require(verify.file_digest(build / "compile_commands.json") == before, "compile DB changed during measurement")
    base, head = (verify.load_json(output / f"measurement-{side}.json") for side in ("base", "head"))
    comparison, failures = measurement.compare(base, head)
    write_json(output / "measurement-delta.json", comparison)
    (output / "measurement-delta.md").write_text(measurement.render(comparison), encoding="utf-8")
    verify.require(not failures, "measurement quality regression: " + "; ".join(failures))
    write_json(output / "builds.json", bindings)
    shutil.copyfile(build / "compile_commands.json", output / "compile_commands.json")
    return {"base_binary_sha256": bindings["base"]["binary_sha256"],
            "head_binary_sha256": bindings["head"]["binary_sha256"], "compile_database_sha256": before}


def execute(args):
    repo = ROOT
    config = verify.validate_config(verify.load_json(repo / REQUEST))
    adjudications = verify.load_adjudications(config, repo / ADJUDICATIONS
                                             if config["schema"].endswith("/v2") else None)
    context = environment_context(args.lane)
    selected = verify.request_selected(config, request_at_head(repo, config, context))
    if args.command == "plan":
        manifest = campaign.validate_manifest(verify.load_json(repo / "scripts/realworld_manifest.json"))
        verify.require(campaign.digest_json(manifest) == config["manifest_sha256"], "request manifest mismatch")
        verify.derive_expectations(config, manifest, adjudications)
        rows = verify.full_matrix(manifest)
        outputs = {"selected": "true" if selected else "false", "base_sha": config["base_sha"],
                   "matrix": json.dumps({"include": rows}, separators=(",", ":"))}
        if args.github_output:
            with Path(args.github_output).open("a", encoding="utf-8") as stream:
                for key, value in outputs.items():
                    stream.write(f"{key}={value}\n")
        print(json.dumps(outputs, sort_keys=True))
        return
    verify.require(selected, "no fresh enabled checkpoint at event head")
    workspace, output = fresh_dir(args.workspace), fresh_dir(args.output)
    inputs, input_identity, manifest = prepare_inputs(repo, workspace, config)
    manifests, _ = verify.derive_expectations(config, manifest, adjudications)
    if args.command == "build":
        verify.require(args.lane == "realworld", "wrong build lane")
        source = inputs if args.side == "base" else repo
        revision = config["base_sha"] if args.side == "base" else context["head_sha"]
        binary, binding = build_analyzer(source, revision, workspace / "build", args.llvm_prefix)
        shutil.copyfile(binary, output / "codeskeptic")
        details = {"side": args.side, **binding}
        kind = "binary"
    elif args.command == "measure":
        verify.require(args.lane == "measurement", "wrong measurement lane")
        base, _ = build_analyzer(inputs, config["base_sha"], workspace / "base-build", args.llvm_prefix)
        head, _ = build_analyzer(repo, context["head_sha"], workspace / "head-build", args.llvm_prefix)
        details = measure_pair(base, head, inputs, workspace / "base-build", config["base_sha"], context["head_sha"], output)
        kind = "measurement"
    elif args.command == "shard":
        verify.require(args.lane == "realworld", "wrong shard lane")
        artifact = verify.load_artifact(args.binary_artifact, config, context, input_identity, "binary")
        binary = Path(args.binary_artifact) / "codeskeptic"
        binary_sha = verify.file_digest(binary)
        revision = config["base_sha"] if args.side == "base" else context["head_sha"]
        verify.require(artifact["details"] == {"side": args.side, "source_sha": revision, "binary_sha256": binary_sha} and
                       artifact["files"] == {"codeskeptic": binary_sha}, "wrong shared analyzer artifact")
        binary.chmod(0o755)  # upload-artifact does not retain executable permission.
        code = campaign.run_shard(manifests[args.side], args.project, args.repetition, binary, workspace / "campaign",
                                  output / "receipt.json", None, inputs)
        verify.require(code == 0, "real-world shard unavailable; raw diagnostic receipt retained")
        verify.require(verify.file_digest(binary) == binary_sha, "analyzer changed during shard")
        verify.verify_raw_shard(output, manifests[args.side], args.project, args.repetition, binary_sha)
        details = {"side": args.side, "project": args.project, "repetition": args.repetition, "binary_sha256": binary_sha}
        kind = "shard"
    elif args.command == "aggregate":
        needs = verify.load_json(args.needs)
        result = verify.verify_realworld_bundle(args.artifacts, config, context, input_identity, manifest, needs,
                                               adjudications=adjudications)
        write_json(output / "result.json", result)
        details, kind = {"validated_shards": 48}, "aggregate"
    else:
        raise verify.CheckpointError("unknown execution mode")
    verify.require(collect_inputs(inputs, config)[0] == input_identity, "common input tree changed during execution")
    clean_revision(repo, context["head_sha"])
    seal_artifact(output, config, context, input_identity, kind, details)
    if kind == "measurement":
        verify.verify_measurement_bundle(output, config, context, input_identity, thesis_cases(inputs))
    print(f"CHECKPOINT_ARTIFACT_OK kind={kind} head={context['head_sha']} (not hosted completion)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build", "measure", "shard", "aggregate"))
    parser.add_argument("--lane", choices=("measurement", "realworld"), required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--side", choices=("base", "head"))
    parser.add_argument("--project")
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3))
    parser.add_argument("--binary-artifact", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--needs", type=Path)
    parser.add_argument("--llvm-prefix", default="/usr/lib/llvm-20")
    args = parser.parse_args()
    if args.command != "plan" and (args.workspace is None or args.output is None):
        parser.error("execution needs --workspace and --output")
    if args.command in ("build", "shard") and args.side is None:
        parser.error("build/shard needs --side")
    if args.command == "shard" and (args.project is None or args.repetition is None or args.binary_artifact is None):
        parser.error("shard needs --project, --repetition and --binary-artifact")
    if args.command == "aggregate" and (args.artifacts is None or args.needs is None):
        parser.error("aggregate needs --artifacts and --needs")
    try:
        execute(args)
    except (verify.CheckpointError, campaign.CampaignError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"CHECKPOINT_FAIL {error}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
